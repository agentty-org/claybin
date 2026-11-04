// cgroup limits are the easiest thing in a sandbox to claim and not deliver: the
// write succeeds, the report says `strong`, and nobody notices until a guest
// eats all the memory. so this test does not check that we wrote the file -- it
// checks that a guest which TRIES to exceed the limit actually gets stopped.

#include "harness.hpp"

#include <cstring>
#include <string>

#if defined(__linux__)
#include <cerrno>
#include <cstdlib>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "claybin/linux/cgroup.hpp"
#include "claybin/plan/compile.hpp"
#include "claybin/plan/spawn.hpp"
#include "claybin/policy/shapes.hpp"

using namespace clay;
using namespace clay::test;
using namespace clay::literals;

#if defined(__linux__)
namespace {

// the guest side: try to consume more than we were allowed.
int hog_memory(std::size_t target_mb) {
    // touch every page, so this is resident memory and not just address space.
    // RLIMIT_AS would stop the mmap; only a cgroup stops the touching.
    const std::size_t chunk = 8u << 20;
    std::size_t total = 0;
    while (total < target_mb << 20) {
        auto* p = static_cast<volatile char*>(std::malloc(chunk));
        if (!p) return 1;  // allocation refused: the limit held
        for (std::size_t i = 0; i < chunk; i += 4096) p[i] = 1;
        total += chunk;
    }
    return 0;  // we got all of it: the limit did NOT hold
}

int fork_bomb(int target) {
    int made = 0;
    for (int i = 0; i < target; ++i) {
        pid_t p = ::fork();
        if (p < 0) return 1;  // refused: the limit held
        if (p == 0) {
            ::pause();
            ::_exit(0);
        }
        ++made;
    }
    // clean up before reporting success
    for (int i = 0; i < made; ++i) ::kill(-1, SIGKILL);
    return 0;  // we made them all: the limit did NOT hold
}

// first line of a cgroup interface file, newline stripped. empty on failure.
std::string read_line(const std::string& path) {
    char buf[64] = "";
    std::FILE* f = std::fopen(path.c_str(), "r");
    if (!f) return {};
    if (!std::fgets(buf, sizeof buf, f)) buf[0] = '\0';
    std::fclose(f);
    buf[std::strcspn(buf, "\n")] = '\0';
    return buf;
}

}  // namespace
#endif

int main(int argc, char** argv) {
#if defined(__linux__)
    if (argc >= 3 && std::strcmp(argv[1], "hog") == 0)
        return hog_memory(static_cast<std::size_t>(std::atoi(argv[2])));
    if (argc >= 3 && std::strcmp(argv[1], "bomb") == 0)
        return fork_bomb(std::atoi(argv[2]));

    auto probe = cgroup::probe();
    std::fprintf(stderr, "cgroup: %s\n", cgroup::to_string(probe.availability));
    if (probe.availability != cgroup::Availability::delegated) {
        std::fprintf(stderr, "skip cgroup_test: %s\n", probe.reason);
        return 0;
    }

    static char self[4096];
    ssize_t n = ::readlink("/proc/self/exe", self, sizeof self - 1);
    if (n <= 0) return 1;
    self[n] = '\0';
    static char dir[4096];
    std::snprintf(dir, sizeof dir, "%s", self);
    if (char* s = std::strrchr(dir, '/')) *s = '\0';

    auto host = probe_host();

    // -- create() never adopts a cgroup that is already there --------------
    //
    // names are clay-<hint>-<pid>, so a second create() from the same process
    // -- a supervisor with two sandboxes -- used to hit EEXIST, shrug, and hand
    // back the SAME cgroup: one pool for both guests, the second policy's limits
    // over the first's. a leftover from a dead process with our pid was adopted
    // the same way, limits and tenants included.
    {
        const std::string& parent =
            probe.delegating_path.empty() ? probe.own_path : probe.delegating_path;
        char squat[64];
        std::snprintf(squat, sizeof squat, "/clay-adopt-%d", static_cast<int>(::getpid()));
        const std::string squatted = parent + squat;
        // stands in for the cgroup a dead process with our pid left behind.
        // EEXIST is fine -- that IS such a leftover, from a run that died here
        // -- but only a directory this run made is ours to remove.
        const bool made = ::mkdir(squatted.c_str(), 0755) == 0;
        CHECK(made || errno == EEXIST);

        ResourceLimits mem;
        mem.memory = 64_MB;
        ResourceLimits pids_only;
        pids_only.pids = Count{8};
        {
            auto a = cgroup::create(probe, mem, "adopt");
            auto b = cgroup::create(probe, pids_only, "adopt");
            CHECK(a.has_value());
            CHECK(b.has_value());
            if (a && b) {
                CHECK(a->path() != squatted);
                CHECK(b->path() != squatted);
                CHECK(a->path() != b->path());
                if (probe.memory) {
                    CHECK(read_line(a->path() + "/memory.max") == "67108864");
                    // b asked for no memory cap, so it must not be wearing a's
                    CHECK(read_line(b->path() + "/memory.max") == "max");
                }
            }
        }
        if (made) ::rmdir(squatted.c_str());
    }

    // -- the report must only claim strong when we really got a cgroup -----
    {
        auto pol = shapes::system_ro()
                       .bind_try(dir, dir)
                       .memory(64_MB)
                       .processes(16)
                       .syscall_profile(profiles::compiler())
                       .seal();
        auto c = compile(pol, host);
        CHECK(c.has_value());
        if (c) {
            CHECK(c->cgroup.valid());
            CHECK(c->guarantees.strength(CapId::mem_limit) == Enforcement::strong);
            CHECK(c->guarantees.strength(CapId::pid_limit) == Enforcement::strong);
            // and the claim is backed by a real cgroup directory
            CHECK(!c->cgroup.path().empty());
        }
    }

    // -- a memory hog must be STOPPED, not merely reported -----------------
    {
        auto pol = shapes::system_ro()
                       .bind_try(dir, dir)
                       .memory(64_MB)
                       .syscall_profile(profiles::compiler())
                       .seal();
        auto c = compile(pol, host);
        CHECK(c.has_value());
        if (c && c->cgroup.valid()) {
            const char* argvv[] = {self, "hog", "512", nullptr};
            Command cmd{self, argvv, nullptr};
            auto sp = spawn_in(c->plan, cmd, c->cgroup);
            if (!sp)
                std::fprintf(stderr, "  hog did not start: %.*s errno=%d\n",
                             static_cast<int>(sp.error().mechanism.size()),
                             sp.error().mechanism.data(), sp.error().sys_errno);
            CHECK(sp.has_value());
            if (sp) {
                int st = 0;
                ::waitpid(sp->pid, &st, 0);
                if (sp->pidfd >= 0) ::close(sp->pidfd);
                int code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
                // asked for 512 MB with a 64 MB cap. either malloc failed (1)
                // or the kernel OOM-killed it. code 0 would mean it got all
                // 512 MB, i.e. the limit was decorative.
                bool stopped = WIFSIGNALED(st) || code == 1 || code == 137 ||
                               (code > 128 && code < 160);
                if (!stopped)
                    std::fprintf(stderr, "  MEMORY LIMIT NOT ENFORCED: exit=%d\n", code);
                CHECK(stopped);
            }
        }
    }

    // -- a fork bomb must hit pids.max -------------------------------------
    {
        auto pol = shapes::system_ro()
                       .bind_try(dir, dir)
                       .processes(8)
                       .syscall_profile(profiles::compiler())
                       .seal();
        auto c = compile(pol, host);
        CHECK(c.has_value());
        if (c && c->cgroup.valid()) {
            const char* argvv[] = {self, "bomb", "200", nullptr};
            Command cmd{self, argvv, nullptr};
            auto sp = spawn_in(c->plan, cmd, c->cgroup);
            CHECK(sp.has_value());
            if (sp) {
                int st = 0;
                ::waitpid(sp->pid, &st, 0);
                if (sp->pidfd >= 0) ::close(sp->pidfd);
                int code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
                bool stopped = WIFSIGNALED(st) || code != 0;
                if (!stopped) std::fprintf(stderr, "  PID LIMIT NOT ENFORCED\n");
                CHECK(stopped);
            }
        }
    }

    // -- a cap above the inherited hard limit still spawns ------------------
    // a pi had nproc hard=3335 and agentty asks for 4096. raising a hard limit
    // is EPERM, so every spawn died. the host's lower limit should just win.
    {
        pid_t kid = ::fork();
        if (kid == 0) {
            struct rlimit cur{};
            ::getrlimit(RLIMIT_NPROC, &cur);
            // nproc counts every process of this user, so leave headroom
            // above what is running, but stay under the 4096 we ask for.
            struct rlimit low{4000, 4000};
            if (cur.rlim_max != RLIM_INFINITY && cur.rlim_max < 4000) low = cur;
            if (::setrlimit(RLIMIT_NPROC, &low) != 0) ::_exit(0);  // can't set up, skip
            auto pol = shapes::system_ro().processes(4096)
                           .syscall_profile(profiles::compiler()).seal();
            auto c = compile(pol, host);
            if (!c) ::_exit(2);
            const char* argvv[] = {"/bin/true", nullptr};
            Command cmd{"/bin/true", argvv, nullptr};
            auto sp = c->cgroup.valid() ? spawn_in(c->plan, cmd, c->cgroup) : spawn(c->plan, cmd);
            if (!sp) {
                std::fprintf(stderr, "  spawn: %.*s errno=%d\n",
                             static_cast<int>(sp.error().mechanism.size()),
                             sp.error().mechanism.data(), sp.error().sys_errno);
                ::_exit(3);
            }
            int st = 0;
            ::waitpid(sp->pid, &st, 0);
            ::_exit(WIFEXITED(st) && WEXITSTATUS(st) == 0 ? 0 : 4);
        }
        int st = 0;
        ::waitpid(kid, &st, 0);
        if (!(WIFEXITED(st) && WEXITSTATUS(st) == 0))
            std::fprintf(stderr, "  RLIMIT ABOVE HARD FAILS SPAWN: %d\n", WEXITSTATUS(st));
        CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0);
    }

    // -- the cgroup is cleaned up ------------------------------------------
    {
        std::string path;
        {
            auto pol = shapes::system_ro().memory(64_MB)
                           .syscall_profile(profiles::compiler()).seal();
            auto c = compile(pol, host);
            if (c && c->cgroup.valid()) path = c->cgroup.path();
            // c goes out of scope here; the Group destructor should rmdir
        }
        if (!path.empty()) {
            CHECK(::access(path.c_str(), F_OK) != 0);
        }
    }

#else
    (void)argc;
    (void)argv;
    std::fprintf(stderr, "skip cgroup_test: linux only\n");
#endif
    return finish("cgroup_test");
}
