// claybin: a minimal spawn, for tests and for callers with no event loop.
//
// deliberately small. it forks, applies the plan, and execs. it does NOT
// supervise: no timeout, no output pumping, no reaping strategy. that is the
// loop's job (see docs/jaal.md), and claybin refuses to grow one.
//
// the one thing it does own is the fork/exec boundary itself, because that is
// where the async-signal-safety rules live and they are easy to get wrong.
#pragma once

#include <span>
#include <string_view>

#include "claybin/core/error.hpp"
#include "claybin/linux/cgroup.hpp"
#include "claybin/plan/plan.hpp"

namespace clay {

struct Command {
    const char* program{nullptr};
    // nullptr-terminated, exactly as execve wants them. no std::string here:
    // the child side of a fork cannot safely allocate.
    const char* const* argv{nullptr};
    const char* const* envp{nullptr};

    // ---- descriptors to carry into the child ----------------------------
    //
    // spawn() closes every descriptor it did not create, which is the right
    // default -- an inherited fd is authority the sandbox cannot see or revoke,
    // and bubblewrap leaks one here. but a caller that wants the guest's output
    // needs a pipe to survive that, so it has to be declared rather than
    // assumed.
    //
    // this is libminijail's minijail_preserve_fd(j, parent_fd, child_fd), and
    // the shape is worth copying rather than inventing: the CALLER owns the
    // descriptor and says where it should land, so the ordering hazard of
    // dup2-ing onto a number that is still in use is handled in one place
    // instead of at every call site. it is also the piece that lets an embedder
    // keep its own supervise loop -- poll the read end, reap the pid -- which is
    // the difference between a library and a subprocess.
    //
    // a pair is applied as dup2(parent_fd, child_fd) in the child, after the
    // plan's fd phase and before exec. child_fd is exempt from the close sweep.
    // to send stdout and stderr to one pipe, pass the same parent_fd twice with
    // child_fd 1 and 2.
    struct FdMap {
        int parent_fd{-1};
        int child_fd{-1};
    };
    // a fixed array, not a vector: this is read on the child side of a fork,
    // where allocation is not safe. eight covers stdio plus a status pipe or
    // two, which is every case an embedder has needed so far.
    static constexpr int kMaxFdMaps = 8;
    FdMap fds[kMaxFdMaps]{};
    int fd_count{0};

    // stdio convenience. the common case is "stdin from /dev/null, stdout and
    // stderr to this pipe", and spelling that as three FdMaps at every call
    // site is noise.
    //
    // -1 means "leave it alone", which for stdin is inherit and for stdout and
    // stderr is whatever the plan's fd phase left. use kDevNull for stdin to get
    // an explicit empty input rather than the caller's terminal.
    static constexpr int kDevNull = -2;
    int stdin_fd{-1};
    int stdout_fd{-1};
    int stderr_fd{-1};
};

struct Spawned {
    int pid{-1};
    int pidfd{-1};  // -1 if the kernel is too old for CLONE_PIDFD
    // the seccomp listener, when the policy brokers syscalls. the CALLER owns
    // it: wrap it in a broker::Listener and answer every notification, or the
    // guest blocks forever on its first brokered call.
    int notify_fd{-1};
    // the guest-side loopback listener, when the policy asked for one
    // (proxied_netns). the CALLER owns it: accept on it and decide what each
    // connection may reach. `proxy_port` is where it is bound inside the
    // guest's namespace, which is what the guest's proxy env vars must name.
    int proxy_listen_fd{-1};
    std::uint16_t proxy_port{0};
    // the netns inode that listener is bound in. the guest's own netns must
    // match, or the proxy is listening where nothing can reach it.
    std::uint64_t proxy_netns_ino{0};
};

// fork, apply the plan in the child, exec. returns in the parent only.
//
// on any failure inside the child the child _exit()s with a distinctive code
// rather than returning, because a child that survived a failed sandbox setup
// is unconfined and must not run the target program.
Result<Spawned> spawn(const Plan& plan, const Command& cmd);

// same, but also move the child into `cg` before it execs.
//
// the cgroup write happens in the PARENT, between fork and exec: writing to
// sysfs is not async-signal-safe, and after a pivot_root the child cannot even
// see /sys/fs/cgroup any more. the child waits on a pipe until we say go, so
// the limits are guaranteed to be in force before the target program's first
// instruction.
Result<Spawned> spawn_in(const Plan& plan, const Command& cmd, const cgroup::Group& cg);

// exit codes the child uses to report setup failure. chosen high to avoid
// colliding with ordinary program exits.
inline constexpr int kExitPlanFailed = 126;
inline constexpr int kExitExecFailed = 127;

}  // namespace clay
