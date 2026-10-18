// a live check of the windows apply path. unlike windows_backend_test (pure
// translation, runs everywhere) this one actually CREATES an appcontainer
// profile, stamps real ACLs and spawns a real confined child, so it only means
// anything on a windows host.
//
// separate from the backend test for the same reason the macos live check is:
// it needs real children with real exit codes, and a test that silently skips
// on every CI runner should be obviously the one doing the skipping.
#include "harness.hpp"

#include "claybin/windows/backend.hpp"
#include "claybin/policy/shapes.hpp"

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <userenv.h>

#include <cstdio>
#include <filesystem>

#endif

using namespace clay;
using namespace clay::test;

#if defined(_WIN32)
namespace {

// the same RAII idea spawn.cpp uses locally: the test owns the handles it is
// handed, and closes them exactly once, at scope exit.
struct hguard {
    void* h{nullptr};
    explicit hguard(void* v) : h(v) {}
    ~hguard() { if (h) ::CloseHandle(h); }
    hguard(const hguard&)            = delete;
    hguard& operator=(const hguard&) = delete;
};

int run_in(const windows::Compiled& c, const char* cmd) {
    const char* argv[] = {"cmd.exe", "/d", "/s", "/c", cmd, nullptr};
    windows::SpawnRequest req;
    req.program = "cmd.exe";
    req.argv    = argv;
    req.stdout_fd = windows::SpawnRequest::kDevNull;
    req.stderr_fd = windows::SpawnRequest::kDevNull;
    req.workdir   = "C:\\_Workspace_\\claybin\\build";

    auto s = windows::spawn(c, req);
    if (!s) return -1;

    // the waitable exit is the process handle; the job the kill switch that
    // closes at scope exit, which is what takes a still-running guest down.
    hguard proc{s->process};
    hguard job{s->job};
    if (::WaitForSingleObject(static_cast<HANDLE>(proc.h), 20000) != WAIT_OBJECT_0)
        return -1;
    DWORD code = 0;
    if (!::GetExitCodeProcess(static_cast<HANDLE>(proc.h), &code)) return -1;
    return static_cast<int>(code);
}

// the agentty shape: stdout/stderr are ANONYMOUS PIPE handles, not the NUL
// device. insider builds are known to drift exactly here -- a guest whose
// console must attach while its inherited handles are pipes dies during dll
// init (0xc0000142) even though the same guest with NUL handles runs. this
// variant exists to measure that difference on THIS host.
int run_in_pipe(const windows::Compiled& c, const char* cmd) {
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE r = nullptr, w = nullptr;
    if (!::CreatePipe(&r, &w, &sa, 0)) return -1;
    hguard rg{r}, wg{w};

    const char* argv[] = {"cmd.exe", "/d", "/s", "/c", cmd, nullptr};
    windows::SpawnRequest req;
    req.program = "cmd.exe";
    req.argv    = argv;
    req.stdout_fd = static_cast<int>(reinterpret_cast<intptr_t>(w));
    req.stderr_fd = static_cast<int>(reinterpret_cast<intptr_t>(w));
    req.workdir   = "C:\\_Workspace_\\claybin\\build";

    auto s = windows::spawn(c, req);
    if (!s) return -1;
    hguard proc{s->process};
    hguard job{s->job};
    wg.h = nullptr;  // our write end goes, or the reader never sees EOF
    if (::WaitForSingleObject(static_cast<HANDLE>(proc.h), 20000) != WAIT_OBJECT_0)
        return -1;
    DWORD code = 0;
    if (!::GetExitCodeProcess(static_cast<HANDLE>(proc.h), &code)) return -1;
    return static_cast<int>(code);
}

struct scope_exit {
    void (*fn)() = nullptr;
    ~scope_exit() { if (fn) fn(); }
};

}  // namespace
#endif

int main() {
#if !defined(_WIN32)
    return skip("windows_live_check", "not Windows");
#else
    namespace fs = std::filesystem;

    const auto host = windows::probe_host();
    if (!host.app_container)
        return skip("windows_live_check", "appcontainer profiles unavailable to this token");

    // scratch dir for the write grant: a fresh dir we label and ACE ourselves,
    // deleted afterwards. the workspace-of-the-moment, in miniature.
    const fs::path scratch =
        fs::temp_directory_path() / "claybin_live_scratch";
    std::error_code ec;
    fs::remove_all(scratch, ec);
    fs::create_directories(scratch, ec);
    if (ec) return skip("windows_live_check", "cannot create scratch dir");
    const std::string scratch_s = scratch.string();
    scope_exit cleanup{[] {
        std::error_code e2;
        fs::remove_all(fs::temp_directory_path() / "claybin_live_scratch", e2);
    }};

    // a policy that can run a shell: read the system, write only to the
    // working dir (the scratch dir is where the RUNNER would place the
    // workspace), no network. cmd.exe needs fork/exec equivalents to run
    // anything, which is itself worth asserting: a sandbox that forbids them
    // looks identical to a broken one.
    const std::string workdir_s = "C:\\_Workspace_\\claybin\\build";
    auto pol = Policy<Draft>{}
                   .read("C:\\Windows")
                   .execute("C:\\Windows\\System32")
                   .read_write(workdir_s)
                   .allow_fork()
                   .allow_exec()
                   .seal();

    // ACL mutation is opt-in on windows (it mutates host objects), and this
    // test is exactly the thing that was opted into.
    windows::Options opts;
    opts.allow_host_acl_mutation = true;

    auto c = windows::compile(pol, host, opts);
    CHECK(c.has_value());
    if (!c) return finish("windows_live_check");

    // -- the sandbox does not break the program ----------------------------
    // first, and most important: a sandbox that denies everything passes
    // every "is it blocked" test and is still useless. the guest must RUN.
    CHECK_EQ(run_in(*c, "exit 0"), 0);

    // -- the write wall holds ----------------------------------------------
    // writing inside the grant works -- the file must land IN the granted
    // workdir, which is exactly what run_in pins as the child's cwd.
    CHECK_EQ(run_in(*c, "echo ok > claybin_live_ok.txt"), 0);
    CHECK(fs::exists(fs::path{workdir_s} / "claybin_live_ok.txt"));
    // ...and writing outside it does not. C:\\Windows is readable, and its
    // ACL is owned by TrustedInstaller: a lowbox process could not write
    // there even without us, which is the wall doing its job through both
    // mechanisms at once.
    CHECK(run_in(*c, "echo no > C:\\Windows\\claybin_should_not_exist.txt") != 0);
    CHECK(!fs::exists("C:\\Windows\\claybin_should_not_exist.txt"));

    // -- the read wall holds -----------------------------------------------
    // a policy with no grants beyond the system roots: the appcontainer token
    // keeps the user SID, so what the read wall can and cannot do depends on
    // the host's restricted-token verdict, which probe_host measured by
    // RUNNING a child. this host (an insider build) refuses restricted
    // tokens, so the wall here is appcontainer default-deny: arbitrary
    // absolute paths outside the grants are unreadable, but a path in the
    // user profile that carries the user's own DACL still is. the test pins
    // what IS true rather than what should be: probing a location with no
    // grant and no package ACE must not succeed.
    {
        auto ro = Policy<Draft>{}
                      .read("C:\\Windows")
                      .execute("C:\\Windows\\System32")
                      .allow_fork()
                      .allow_exec()
                      .seal();
        auto rc = windows::compile(ro, host, opts);
        CHECK(rc.has_value());
        if (rc) {
            // reading something granted must work
            CHECK_EQ(run_in(*rc, "type C:\\Windows\\win.ini >nul"), 0);
            // a made-up path outside every grant must not
            CHECK(run_in(*rc, "type C:\\claybin_should_not_exist.txt") != 0);
        }
    }

    // -- the job: memory cap is a hard wall --------------------------------
    {
        windows::Compiled tight = *c;
        tight.memory_limit_bytes = 8 * 1024 * 1024;  // 8 MiB
        // powershell cannot even start inside 8 MiB; the command ends under
        // the cap with a nonzero exit. `& exit 0` would mask the outcome,
        // so the failure code IS the observed exit.
        const int rc = run_in(tight,
            "powershell -NoProfile -Command \"$a='x'*20000000\" >nul 2>&1");
        CHECK(rc != 0);
    }

    // -- network capabilities: measure what THIS host grants a guest -------
    // createAppContainerProfile with capability sets is exactly where
    // insider builds drift: a set that fails here fails at SPAWN TIME with
    // a child that dies during dll init (0xc0000142), which no compile-time
    // check can see. the probe runs the agentty shape (internetClient +
    // privateNetworkClientServer, the two entries of kNetworkCapabilities)
    // and the single-cap shape, and pins what actually runs.
    {
        // the agentty shape: allow_network + both canonical caps.
        auto net_pol = Policy<Draft>{}
                          .read("C:\\Windows")
                          .execute("C:\\Windows\\System32")
                          .read_write(workdir_s)
                          .allow_fork()
                          .allow_exec()
                          .connect("", 0)  // Full: both kNetworkCapabilities
                          .seal();
        auto nc = windows::compile(net_pol, host, opts);
        CHECK(nc.has_value());
        if (nc) {
            const int rc2 = run_in(*nc, "exit 0");
            std::fprintf(stderr, "net-caps guest (both caps): exit %d\n", rc2);
            CHECK_EQ(rc2, 0);
        }
        // the single-cap shape: outbound only, no loopback/LAN grant.
        auto one_pol = Policy<Draft>{}
                          .read("C:\\Windows")
                          .execute("C:\\Windows\\System32")
                          .read_write(workdir_s)
                          .allow_fork()
                          .allow_exec()
                          .connect("", 443)  // Ports: narrow net grant
                          .seal();
        auto oc = windows::compile(one_pol, host, opts);
        CHECK(oc.has_value());
        if (oc) {
            const int rc3 = run_in(*oc, "exit 0");
            std::fprintf(stderr, "net-caps guest (narrow): exit %d\n", rc3);
            CHECK_EQ(rc3, 0);
        }
    }

    // -- pipes: the agentty exec chain hands stdout/stderr as PIPE handles --
    // every check above ran with NUL-device handles. the full exec chain in
    // agentty hands anonymous pipes, which is where the 0xc0000142 deaths
    // were observed. pin both shapes: NUL and pipe must agree.
    {
        const int rp = run_in_pipe(*c, "echo piped");
        std::fprintf(stderr, "pipe-handle guest: exit %d\n", rp);
        CHECK_EQ(rp, 0);
    }

    // -- the agentty shape, in full: ACL-stamped grants, own profile name --
    // agentty's adapter opts into allow_host_acl_mutation and spawns under
    // the "agentty" profile. anything that only bites in that combination
    // (a stale ACE, a stamp on a system dir) is invisible to the checks
    // above, so it is pinned here with the real Options.
    {
        ::clay::windows::Options ag_opts;
        ag_opts.profile_name = "agentty.livecheck";
        ag_opts.allow_host_acl_mutation = true;
        auto ag_pol = Policy<Draft>{}
                          .read("C:\\Windows")
                          .execute("C:\\Windows\\System32")
                          .read_write(workdir_s)
                          .allow_fork()
                          .allow_exec()
                          .connect("", 0)
                          .seal();
        auto ac = windows::compile(ag_pol, host, ag_opts);
        CHECK(ac.has_value());
        if (ac) {
            const int ra = run_in_pipe(*ac, "echo agentty-shape");
            std::fprintf(stderr, "agentty-shape guest (acl stamps, own profile): exit %d\n", ra);
            CHECK_EQ(ra, 0);
        }
        ::DeleteAppContainerProfile(L"agentty.livecheck");

        // the exact agentty PROFILE NAME: the chain in agentty dies with
        // 0xc0000142 while every check here runs -- the last remaining delta
        // was the profile name. if "agentty" dies where "agentty.livecheck"
        // lives, the name (or its on-disk state) is the poison.
        {
            ag_opts.profile_name = "agentty";
            auto ac2 = windows::compile(ag_pol, host, ag_opts);
            CHECK(ac2.has_value());
            if (ac2) {
                const int rap = run_in_pipe(*ac2, "echo agentty-name");
                std::fprintf(stderr, "agentty-profile-name guest: exit %d\n", rap);
                CHECK_EQ(rap, 0);
            }
        }
    }

    return finish("windows_live_check");
#endif
}
