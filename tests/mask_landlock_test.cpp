// mask_landlock_test -- a mask must hold on a host with NO mount namespace.
//
// The regression this exists for: on such a host (Ubuntu 24.04's AppArmor
// default denies unprivileged user namespaces), a mask under a granted
// directory became an FsAuthority deny that landlock cannot express. compile()
// skipped it and still reported filesystem.read `strong`, and a masked .env
// read back in full. Measured, not hypothetical.
//
// Two layers, because they fail differently:
//
//   1. PLAN, every host. Model the host as having no namespaces and inspect
//      the compiled landlock rules: no rule may cover the masked path, the
//      masked path's directory must not keep read-file, siblings must be
//      granted with nofollow, and the mechanism must say "per-entry".
//
//   2. LIVE, only when this process genuinely cannot create a user namespace
//      (CI runs it under `bwrap --unshare-user --disable-userns`). Spawn real
//      attackers and try every way an agent has been seen to reach a file it
//      was denied: plain read, rename, hard link, symlink, /proc/self/root,
//      a pre-existing sibling symlink, and a fresh copy of the directory.
//      Siblings must stay readable and the workspace writable -- a mask that
//      breaks the build is a mask someone turns off.

#include "harness.hpp"

#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#if defined(__linux__)
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "claybin/plan/compile.hpp"
#include "claybin/plan/spawn.hpp"
#include "claybin/policy/profiles.hpp"

using namespace clay;
using namespace clay::test;

#if defined(__linux__)

namespace {

// ---- attacker side: re-exec of this binary as `attack <name> <ws> <secret_dir>` ----
// 0 means the escape SUCCEEDED (the secret's bytes were read).

bool read_canary(const std::string& p) {
    const int fd = ::open(p.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    char buf[64]{};
    const ssize_t n = ::read(fd, buf, sizeof buf - 1);
    ::close(fd);
    return n > 0 && std::strstr(buf, "CANARY") != nullptr;
}

int run_attack(const char* name, const std::string& ws, const std::string& outside) {
    const std::string env = ws + "/.env";
    const std::string nested = ws + "/sub/deep/.env";
    if (!std::strcmp(name, "read")) return read_canary(env) ? 0 : 1;
    if (!std::strcmp(name, "overwrite_then_read")) {
        // with write kept on the masked file's directory, the guest can
        // replace the file's CONTENT -- but what it reads back is only what it
        // wrote, never the original secret. append, so the original bytes are
        // still in front of anything it adds.
        const int fd = ::open(env.c_str(), O_WRONLY | O_APPEND | O_CLOEXEC);
        if (fd >= 0) {
            (void)!::write(fd, "x", 1);
            ::close(fd);
        }
        return read_canary(env) ? 0 : 1;
    }
    if (!std::strcmp(name, "read_nested")) return read_canary(nested) ? 0 : 1;
    if (!std::strcmp(name, "proc_root")) return read_canary("/proc/self/root" + env) ? 0 : 1;
    if (!std::strcmp(name, "rename_same_dir")) {
        // a rename within the directory keeps the inode; the new name must be
        // just as unreadable.
        if (::rename(env.c_str(), (ws + "/renamed").c_str()) != 0) return 1;
        const bool got = read_canary(ws + "/renamed");
        ::rename((ws + "/renamed").c_str(), env.c_str());
        return got ? 0 : 1;
    }
    if (!std::strcmp(name, "rename_to_sibling")) {
        // reparenting into a readable sibling directory is the move that
        // would actually escape. REFER must refuse it.
        if (::rename(env.c_str(), (ws + "/src/stolen").c_str()) != 0) return 1;
        const bool got = read_canary(ws + "/src/stolen");
        ::rename((ws + "/src/stolen").c_str(), env.c_str());
        return got ? 0 : 1;
    }
    if (!std::strcmp(name, "rename_parent_dir")) {
        // move a whole directory that CONTAINS a mask under a readable
        // sibling. the moved tree would inherit src's read-file; REFER must
        // refuse the reparent.
        if (::rename((ws + "/sub").c_str(), (ws + "/src/sub_moved").c_str()) != 0) return 1;
        const bool got = read_canary(ws + "/src/sub_moved/deep/.env");
        ::rename((ws + "/src/sub_moved").c_str(), (ws + "/sub").c_str());
        return got ? 0 : 1;
    }
    if (!std::strcmp(name, "hardlink")) {
        if (::link(env.c_str(), (ws + "/src/hl").c_str()) != 0) return 1;
        const bool got = read_canary(ws + "/src/hl");
        ::unlink((ws + "/src/hl").c_str());
        return got ? 0 : 1;
    }
    if (!std::strcmp(name, "symlink")) {
        // a fresh symlink resolves to the same inode, so the same rule.
        if (::symlink(env.c_str(), (ws + "/src/sl").c_str()) != 0) return 1;
        const bool got = read_canary(ws + "/src/sl");
        ::unlink((ws + "/src/sl").c_str());
        return got ? 0 : 1;
    }
    if (!std::strcmp(name, "presymlinked_sibling")) {
        // a sibling that was ALREADY a symlink to a secret directory outside
        // the workspace when the plan compiled. granting it with follow would
        // have granted the target; nofollow keeps the rule on the link.
        return read_canary(ws + "/link_out/key") ? 0 : 1;
    }
    if (!std::strcmp(name, "outside_direct")) return read_canary(outside + "/key") ? 0 : 1;
    // attacks on read-only paths inside the writable workspace.
    if (!std::strcmp(name, "write_ro_file")) {
        // a read-only bind inside the writable workspace (the trust-handoff
        // shape: .vscode/tasks.json). appending must fail.
        const int fd = ::open((ws + "/ro.json").c_str(), O_WRONLY | O_APPEND | O_CLOEXEC);
        if (fd < 0) return 1;
        const bool ok = ::write(fd, "PWNED", 5) == 5;
        ::close(fd);
        return ok ? 0 : 1;
    }
    if (!std::strcmp(name, "write_ro_dir")) {
        // a read-only directory (.git/hooks): creating a hook in it must fail.
        const int fd = ::open((ws + "/hooks/post-merge").c_str(),
                              O_WRONLY | O_CREAT | O_CLOEXEC, 0755);
        if (fd < 0) return 1;
        ::close(fd);
        ::unlink((ws + "/hooks/post-merge").c_str());
        return 0;
    }
    // controls: must SUCCEED, or the walls are too broad to live with.
    if (!std::strcmp(name, "ok_read_ro")) return read_canary(ws + "/ro.json") ? 42 : 1;
    if (!std::strcmp(name, "ok_sibling_read")) return read_canary(ws + "/ok.txt") ? 42 : 1;
    if (!std::strcmp(name, "ok_nested_read")) return read_canary(ws + "/src/a.c") ? 42 : 1;
    if (!std::strcmp(name, "ok_write")) {
        const std::string p = ws + "/src/new.txt";
        const int fd = ::open(p.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        if (fd < 0) return 1;
        const bool ok = ::write(fd, "CANARY", 6) == 6;
        ::close(fd);
        const bool back = read_canary(p);
        ::unlink(p.c_str());
        return ok && back ? 42 : 1;
    }
    return 3;
}

void write_file(const std::string& p, const char* s) {
    const int fd = ::open(p.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) return;
    (void)!::write(fd, s, std::strlen(s));
    ::close(fd);
}

struct Fixture {
    std::string ws, outside;
};

Fixture make_fixture() {
    char tmpl[] = "/tmp/clay_mask_XXXXXX";
    char* base = ::mkdtemp(tmpl);
    Fixture f{std::string{base} + "/ws", std::string{base} + "/secrets"};
    ::mkdir(f.ws.c_str(), 0755);
    ::mkdir((f.ws + "/src").c_str(), 0755);
    ::mkdir((f.ws + "/sub").c_str(), 0755);
    ::mkdir((f.ws + "/sub/deep").c_str(), 0755);
    ::mkdir(f.outside.c_str(), 0755);
    write_file(f.ws + "/.env", "CANARY=env\n");
    write_file(f.ws + "/sub/deep/.env", "CANARY=nested\n");
    write_file(f.ws + "/ok.txt", "CANARY=fine\n");
    write_file(f.ws + "/src/a.c", "CANARY=code\n");
    write_file(f.outside + "/key", "CANARY=key\n");
    write_file(f.ws + "/ro.json", "CANARY=tasks\n");
    ::mkdir((f.ws + "/hooks").c_str(), 0755);
    (void)!::symlink(f.outside.c_str(), (f.ws + "/link_out").c_str());
    return f;
}

HostCapabilities no_namespaces(HostCapabilities h) {
    h.user_namespaces = h.mount_namespaces = h.pid_namespaces = h.net_namespaces =
        h.uts_namespaces = h.ipc_namespaces = h.cgroup_namespaces = false;
    return h;
}

Policy<Sealed> make_policy(const Fixture& f, const std::string& self_dir) {
    auto d = Policy<Draft>{};
    d = std::move(d).ro_bind("/usr", "/usr");
    for (const char* p : {"/lib", "/lib64", "/bin", "/etc/ld.so.cache"})
        d = std::move(d).bind_try(p, p);
    // the attacker is this binary, so its directory must be executable.
    if (!self_dir.empty()) d = std::move(d).ro_bind(self_dir, self_dir);
    d = std::move(d).bind(f.ws, f.ws);
    d = std::move(d).mask(f.ws + "/.env");
    d = std::move(d).mask(f.ws + "/sub/deep/.env");
    d = std::move(d).bind_try(f.ws + "/ro.json", f.ws + "/ro.json", /*ro=*/true);
    d = std::move(d).bind_try(f.ws + "/hooks", f.ws + "/hooks", /*ro=*/true);
    d = std::move(d).syscall_profile(profiles::compiler());
    return std::move(d).seal();
}

int attack(const Compiled& c, const char* self, const char* name, const Fixture& f) {
    const char* argv[] = {self, "attack", name, f.ws.c_str(), f.outside.c_str(), nullptr};
    const char* envp[] = {nullptr};
    Command cmd{self, argv, envp};
    auto sp = spawn(c.plan, cmd);
    if (!sp) {
        std::fprintf(stderr, "  spawn %s: %.*s errno=%d\n", name,
                     int(sp.error().mechanism.size()), sp.error().mechanism.data(),
                     sp.error().sys_errno);
        return -1;
    }
    int st = 0;
    ::waitpid(sp->pid, &st, 0);
    if (sp->pidfd >= 0) ::close(sp->pidfd);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}

}  // namespace

#endif

int main(int argc, char** argv) {
#if defined(__linux__)
    if (argc >= 5 && !std::strcmp(argv[1], "attack")) return run_attack(argv[2], argv[3], argv[4]);

    const auto real = probe_host();
    if (real.landlock_abi == 0) return skip("mask_landlock_test", "no landlock");
    const Fixture f = make_fixture();
    char self[4096]{};
    const ssize_t n = ::readlink("/proc/self/exe", self, sizeof self - 1);
    if (n <= 0) return skip("mask_landlock_test", "no /proc/self/exe");
    std::string self_dir{self};
    self_dir.resize(self_dir.rfind('/'));

    // ---- 1. the plan, on every host ---------------------------------------
    {
        auto c = compile(make_policy(f, self_dir), no_namespaces(real));
        CHECK(c.has_value());
        if (c) {
            CHECK(c->guarantees.strength(CapId::fs_read) == Enforcement::strong);
            CHECK(std::string_view{c->guarantees.mechanism(CapId::fs_read)}
                  == "landlock (per-entry masks)");
            CHECK(c->fidelity == Fidelity::approximate);
            bool env_ruled = false, ws_reads_files = false, sibling_nofollow = false;
            c->plan.for_each([&](OpCode code, std::span<const std::byte> payload) {
                if (code != OpCode::landlock_rule && code != OpCode::landlock_rule_nofollow)
                    return true;
                LandlockRuleOp op{};
                Plan::decode(payload, op);
                const std::string p = c->plan.cstr(op.path);
                if (p == f.ws + "/.env" || p == f.ws + "/sub/deep/.env") env_ruled = true;
                if (p == f.ws && (op.allowed & (1ull << 2) /* READ_FILE */)) ws_reads_files = true;
                if (p == f.ws + "/link_out" && code == OpCode::landlock_rule_nofollow)
                    sibling_nofollow = true;
                return true;
            });
            CHECK(!env_ruled);          // no rule may name the mask
            CHECK(!ws_reads_files);     // the mask's directory keeps no read-file
            CHECK(sibling_nofollow);    // a symlinked sibling is ruled ON the link
        }
    }

    // ---- 2. live, only where namespaces are genuinely unavailable ----------
    if (real.user_namespaces) {
        std::fprintf(stderr, "  (live attacks skipped: this host has user namespaces; "
                             "run under bwrap --unshare-user --disable-userns)\n");
        return finish("mask_landlock_test");
    }
    auto c = compile(make_policy(f, self_dir), real);
    CHECK(c.has_value());
    if (!c) return finish("mask_landlock_test");

    for (const char* a : {"read", "read_nested", "proc_root", "rename_same_dir",
                          "rename_to_sibling", "hardlink", "symlink",
                          "presymlinked_sibling", "outside_direct",
                          "overwrite_then_read", "rename_parent_dir",
                          "write_ro_file", "write_ro_dir"}) {
        const int rc = attack(*c, self, a, f);
        if (rc == 0) std::fprintf(stderr, "  ESCAPED: %s\n", a);
        CHECK(rc > 0 && rc != 42);
    }
    for (const char* ok : {"ok_sibling_read", "ok_nested_read", "ok_write", "ok_read_ro"}) {
        const int rc = attack(*c, self, ok, f);
        if (rc != 42) std::fprintf(stderr, "  control failed: %s (rc=%d)\n", ok, rc);
        CHECK(rc == 42);
    }
#else
    (void)argc;
    (void)argv;
#endif
    return finish("mask_landlock_test");
}
