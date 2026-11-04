#include "claybin/plan/spawn.hpp"

#if defined(__linux__)

#include <string_view>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <utility>
#include <fcntl.h>
#include <sched.h>
#include <poll.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_getfd
#define SYS_pidfd_getfd 438
#endif
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

namespace clay {

Result<Spawned> spawn(const Plan& plan, const Command& cmd) {
    return spawn_in(plan, cmd, cgroup::Group{});
}

namespace {

// Error::mechanism is a string_view onto a static string. A failure reported
// by the child arrives as bytes in a buffer, so map it back to the literal it
// was made from (every mechanism claybin names is one). Unknown bytes give a
// generic name rather than a view into a buffer that is about to go away.
std::string_view static_mechanism(const char* got) noexcept {
    static constexpr std::string_view kNames[] = {
        "bind_target",
        "bind_target: mkdir",
        "bind_target: mkdir (confined)",
        "bind_target: touch",
        "broker: NOTIF_ADDFD",
        "broker: NOTIF_RECV",
        "broker: NOTIF_SEND",
        "broker: linux only",
        "broker: no fd",
        "broker: no fd to inject",
        "broker: notification expired",
        "cgroup: attach",
        "cgroup: kill",
        "cgroup: mkdir",
        "cgroup: no cgroup.kill",
        "cgroup: no group",
        "cgroup: open",
        "cgroup: open dir",
        "cgroup: open procs",
        "cgroup: write",
        "cgroups are linux-only",
        "chdir",
        "close_range",
        "die_with_parent",
        "drop_caps",
        "dup2",
        "fork",
        "hardened: landlock",
        "hardened: seccomp",
        "hardened: user namespaces",
        "id_map",
        "landlock",
        "landlock: no ruleset",
        "landlock: rule before enforce",
        "landlock_add_rule",
        "landlock_net",
        "landlock_net: no ruleset",
        "landlock_net_rule",
        "landlock_restrict_self",
        "macos-spawn",
        "microvm backend not implemented",
        "mkdir",
        "mkdir (confined)",
        "mount",
        "no_new_privs",
        "pipe2 gate",
        "pipe2 relay",
        "pivot2",
        "pivot2: chdir /",
        "pivot2: chdir newroot",
        "pivot2: fchdir",
        "pivot2: open /",
        "pivot2: pivot_root",
        "pivot2: umount oldroot",
        "pivot_root",
        "pivot_root: chdir",
        "pivot_root: chdir /",
        "plan::apply: linux only",
        "remount_rec",
        "seccomp",
        "seccomp: arg rule too large",
        "seccomp: empty program",
        "seccomp: new_listener",
        "seccomp: program too large",
        "seccomp: unknown audit arch",
        "setgid",
        "sethostname",
        "setids",
        "setrlimit",
        "setuid",
        "socketpair",
        "spawn: linux only",
        "spawn: no program",
        "spawn: plan not well ordered",
        "symlink",
        "symlink (confined)",
        "touch",
        "umount",
        "unknown opcode",
        "unshare",
        "write_fd",
        "write_fd: bind",
        "write_fd: bind target",
        "write_fd: open dest",
        "write_fd: open dest (confined)",
        "write_fd: read",
        "write_fd: remount ro",
        "write_fd: root",
        "write_fd: touch",
        "write_fd: write",
        "write_file",
    };
    const std::string_view g{got};
    for (auto n : kNames)
        if (n == g) return n;
    return "child setup";
}

}  // namespace

Result<Spawned> spawn_in(const Plan& plan, const Command& cmd, const cgroup::Group& cg) {
    if (!cmd.program || !cmd.argv)
        return std::unexpected(Error{Errc::invalid_policy, "spawn: no program"});
    if (!plan.well_ordered())
        return std::unexpected(Error{Errc::invalid_policy, "spawn: plan not well ordered"});

    // does this plan broker syscalls? if so the listener fd has to make a
    // three-hop journey (guest -> shepherd -> supervisor) for reasons the
    // shepherd branch explains, and that needs an extra pipe.
    bool brokering = false;
    plan.for_each([&](OpCode code, std::span<const std::byte> pl) {
        if (code == OpCode::seccomp_install) {
            SeccompInstallOp o{};
            if (Plan::decode(pl, o) && (o.flags & 1u)) brokering = true;
            return false;
        }
        return true;
    });

    int relay[2] = {-1, -1};
    if (brokering && ::pipe2(relay, O_CLOEXEC) < 0)
        return std::unexpected(Error{Errc::spawn_failed, "pipe2 relay", errno});
    // every early return below must give these back. they used to leak on
    // each failure path after this point -- a supervisor that retries a
    // failing spawn burned two descriptors per attempt until EMFILE.
    auto close_relay = [&] {
        if (relay[0] >= 0) ::close(relay[0]);
        if (relay[1] >= 0) ::close(relay[1]);
    };

    // a CLOEXEC socketpair, not a pipe: the child may need to send the seccomp
    // listener fd back, and SCM_RIGHTS needs a socket. on a successful exec the
    // write end closes and the parent reads EOF, exactly as with a pipe.
    int report[2] = {-1, -1};
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, report) < 0) {
        const int err = errno;
        close_relay();
        return std::unexpected(Error{Errc::spawn_failed, "socketpair", err});
    }

    // a second pipe, the other direction: the child blocks on it until the
    // parent has put it in the cgroup. without this gate the child could exec
    // and start allocating before its memory limit exists, which would make the
    // limit advisory rather than enforced.
    int gate[2] = {-1, -1};
    const bool use_cgroup = cg.valid();
    if (use_cgroup && ::pipe2(gate, O_CLOEXEC) < 0) {
        const int err = errno;
        ::close(report[0]);
        ::close(report[1]);
        close_relay();
        return std::unexpected(Error{Errc::spawn_failed, "pipe2 gate", err});
    }

    // CLONE_PIDFD gives us a race-free handle on the child. without it, a pid
    // can be reused between exit and wait, and we would be signalling a
    // stranger. fall back only if the kernel refuses.
    int pidfd = -1;
    // where this process's argv strings live. the in-namespace shepherd is a
    // fork of us that never execs, so the guest could read the supervisor's
    // command line from /proc/1/cmdline; the shepherd blanks this range. read
    // here, before the fork, where allocating is still allowed.
    std::uintptr_t arg_start = 0, arg_end = 0;
    if (FILE* sf = std::fopen("/proc/self/stat", "re")) {
        char buf[2048];
        const std::size_t n = std::fread(buf, 1, sizeof buf - 1, sf);
        std::fclose(sf);
        buf[n] = '\0';
        // fields 48/49; count from the ')' that ends comm, which may hold spaces
        if (char* p = std::strrchr(buf, ')')) {
            int field = 2;
            char* save = nullptr;
            // the kernel prints these as unsigned decimals; on a 32-bit host
            // anything above UINTPTR_MAX is a parse we can't trust, so leave
            // the range empty (no blanking) rather than truncate the address.
            auto parse_addr = [](const char* s) -> std::uintptr_t {
                char* end = nullptr;
                errno = 0;
                const unsigned long long v = std::strtoull(s, &end, 10);
                if (errno != 0 || end == s || v > UINTPTR_MAX) return 0;
                return static_cast<std::uintptr_t>(v);
            };
            for (char* tok = ::strtok_r(p + 1, " ", &save); tok; tok = ::strtok_r(nullptr, " ", &save)) {
                ++field;
                if (field == 48) arg_start = parse_addr(tok);
                if (field == 49) { arg_end = parse_addr(tok); break; }
            }
        }
    }
    struct clone_args {
        std::uint64_t flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls;
        std::uint64_t set_tid, set_tid_size, cgroup;
    } args{};
    args.flags = 0x00001000ull;  // CLONE_PIDFD
    args.pidfd = reinterpret_cast<std::uint64_t>(&pidfd);
    args.exit_signal = SIGCHLD;

    long pid = ::syscall(SYS_clone3, &args, sizeof args);
    if (pid < 0) {
        pidfd = -1;
        pid = ::fork();
        if (pid < 0) {
            const int err = errno;
            ::close(report[0]);
            ::close(report[1]);
            if (use_cgroup) {
                ::close(gate[0]);
                ::close(gate[1]);
            }
            close_relay();
            return std::unexpected(Error{Errc::spawn_failed, "fork", err});
        }
    }

    if (pid == 0) {
        // ---- child. from here on: no allocation, no stdio, no returning. ----
        //
        // every path out of this block is an _exit(). returning would unwind
        // into the caller's stack frame with a half-built sandbox in place,
        // which is the one outcome worse than failing to start.

        // FIRST: drop every signal handler the caller installed.
        //
        // fork copies them, and the shepherd below never execs -- it becomes
        // pid 1 of the new pid namespace and sits in waitpid() for the
        // guest's lifetime. So without this it runs the EMBEDDER's handlers:
        // agentty installs a crash handler that writes a report, and a test
        // binary installs one that prints "test case CRASHED". Both then fire
        // from inside the sandbox, on a process the embedder does not know
        // exists, and the report names the wrong process.
        //
        // It is worse than noise for pid 1 of a namespace. The kernel skips
        // default-action signals for pid 1 but DELIVERS ones that have a
        // handler, so an inherited handler turns "SIGTERM kills the shepherd"
        // into "SIGTERM runs someone else's code and the shepherd survives".
        // Found as an intermittent SIGTERM apparently crashing a test that
        // had already passed.
        //
        // Async-signal-safe: raw rt_sigaction/rt_sigprocmask, NOT glibc's
        // sigaction. Since glibc 2.41 sigaction(SIGABRT) takes glibc's abort
        // lock, and posix_spawn/fork on another thread hold it for reading.
        // We came here through a raw clone3, so if one was mid-spawn at that
        // instant the child's copy of the lock is held forever and the first
        // sigaction(SIGABRT) waits on it. Seen as spawns stuck in futex_wait
        // until the 30s setup timeout.
        {
            // all-zero kernel sigaction == SIG_DFL, no flags, empty mask.
            const std::uint64_t dfl[4] = {0, 0, 0, 0};
            constexpr long kSigsetBytes = 8;   // _NSIG / 8 on Linux
            for (int s = 1; s < 65; ++s) {
                if (s == SIGKILL || s == SIGSTOP) continue;   // cannot be set
                ::syscall(SYS_rt_sigaction, s, dfl, nullptr, kSigsetBytes);
            }
            const std::uint64_t none = 0;
            ::syscall(SYS_rt_sigprocmask, SIG_SETMASK, &none, nullptr, kSigsetBytes);   // unblock
        }

        ::close(report[0]);
        if (use_cgroup) ::close(gate[1]);

        // tell the plan which fds to spare when it closes inherited descriptors.
        // without this the close takes our own failure channel with it, and every
        // later error reaches the parent as a bare exit code.
        ApplyFds afds;
        afds.report = static_cast<std::uint32_t>(report[1]);
        // and the broker relay, which the guest writes its listener fd number to
        // AFTER the privdrop phase that does the closing.
        if (brokering) afds.relay  = static_cast<std::uint32_t>(relay[1]);
        if (brokering) afds.relay2 = static_cast<std::uint32_t>(relay[0]);
        // and the caller's own descriptors -- the pipe an embedder is polling,
        // typically. these are registered as the PARENT-side numbers, because
        // that is what exists right now; the dup2 onto the child-side numbers
        // happens after the plan, just before exec.
        {
            unsigned slot = 0;
            auto reserve = [&](int fd) {
                if (fd < 0 || slot >= kMaxPreservedFds) return;
                afds.preserved[slot++] = static_cast<std::uint32_t>(fd);
            };
            reserve(cmd.stdin_fd);
            reserve(cmd.stdout_fd);
            reserve(cmd.stderr_fd);
            for (int i = 0; i < cmd.fd_count && i < Command::kMaxFdMaps; ++i)
                reserve(cmd.fds[i].parent_fd);
        }

        struct Failure {
            int stage;  // 0 = plan, 1 = exec
            int code;
            int sys_errno;
            char mech[32];
        } f{};

        // wait for the parent to put us in our cgroup. a single byte, or EOF if
        // the parent gave up. this must happen BEFORE any of the sandbox setup
        // that allocates, so the memory cap covers everything we do.
        if (use_cgroup) {
            char go = 0;
            ssize_t got = ::read(gate[0], &go, 1);
            ::close(gate[0]);
            if (got != 1) ::_exit(kExitPlanFailed);
        }

        // the pid namespace needs a fork to ENTER: unshare(CLONE_NEWPID) puts
        // our children inside it and leaves us outside, and mounting procfs
        // requires membership. the plan's own unshare op already created the
        // namespace (along with user/mount/net), so here we only need to step
        // into it before the mount phase runs.
        //
        // apply_until() runs the namespace phase, we fork, then the grandchild
        // runs the rest -- mounts included -- as a real member of the new pid
        // namespace. it is pid 1 there, and forks once more below so the guest
        // is not (see the shepherd).
        auto st = plan.apply_until(Phase::mounts, afds);

        // PROXY LISTENER HANDOFF, before the fork into the pid namespace.
        //
        // The listener was opened by the namespace phase, in THIS process. It
        // has to reach the supervisor from here: the forks below lead to the
        // guest, whose copy closes on exec, and the supervisor cannot make one
        // itself (setns into the guest's netns is EPERM).
        //
        // Unlike the seccomp listener this is an ordinary socket and nnp is
        // not set yet, so one SCM_RIGHTS sendmsg is enough.
        if (st && afds.proxy_listen_fd >= 0) {
            const int pfd = std::exchange(afds.proxy_listen_fd, -1);
            struct iovec iov{};
            const std::uint16_t port = afds.proxy_port;
            char payload[11] = {'P', static_cast<char>(port & 0xff),
                                static_cast<char>((port >> 8) & 0xff)};
            {
                std::uint64_t ino = afds.proxy_netns_ino;
                for (int k = 0; k < 8; ++k)
                    payload[3 + k] = static_cast<char>((ino >> (8 * k)) & 0xff);
            }
            iov.iov_base = payload;
            iov.iov_len = sizeof payload;
            union {
                char buf[CMSG_SPACE(sizeof(int))];
                struct cmsghdr align;
            } u{};
            struct msghdr msg{};
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = u.buf;
            msg.msg_controllen = sizeof u.buf;
            struct cmsghdr* cm = CMSG_FIRSTHDR(&msg);
            cm->cmsg_level = SOL_SOCKET;
            cm->cmsg_type = SCM_RIGHTS;
            cm->cmsg_len = CMSG_LEN(sizeof(int));
            std::memcpy(CMSG_DATA(cm), &pfd, sizeof pfd);
            ssize_t sent;
            do sent = ::sendmsg(report[1], &msg, 0);
            while (sent < 0 && errno == EINTR);
            // NOT closed here, and that is the whole trick. A socket's bind
            // belongs to the network namespace, and the namespace lives only
            // as long as a process in it holds something open. Closing our
            // copy would leave the supervisor holding the only reference --
            // from OUTSIDE -- and the guest would find nothing listening on
            // its own loopback. Left open, it is inherited by the shepherd
            // (pid 1 of the namespace), which outlives the guest, so the bind
            // stands for the box's whole life and goes away with it.
            if (sent != sizeof payload) {
                f.stage = 0;
                f.code = static_cast<int>(Errc::io_error);
                f.sys_errno = errno;
                for (int k = 0; k < 11; ++k) f.mech[k] = "proxy: send"[k];
                ::close(pfd);
                ssize_t ig = ::write(report[1], &f, sizeof f);
                (void)ig;
                ::_exit(kExitPlanFailed);
            }
        }
        if (st) {
            // a raw clone, NOT glibc's fork(). we got here through a raw
            // clone3 of a threaded process, which skips glibc's fork handling,
            // so glibc's internal locks are in whatever state other threads
            // had them at that instant. fork() takes several of them (the
            // abort lock since 2.41, malloc's arenas) and can wait forever.
            struct clone_args_fork {
                std::uint64_t flags, pidfd, child_tid, parent_tid, exit_signal, stack,
                    stack_size, tls, set_tid, set_tid_size, cgroup;
            } fa{};
            fa.exit_signal = SIGCHLD;
            pid_t inner = static_cast<pid_t>(::syscall(SYS_clone3, &fa, sizeof fa));
            if (inner < 0) {
                f.stage = 0;
                f.sys_errno = errno;
                for (int k = 0; k < 8; ++k) f.mech[k] = "pid-fork"[k];
                ssize_t ig = ::write(report[1], &f, sizeof f);
                (void)ig;
                ::_exit(kExitPlanFailed);
            }
            if (inner > 0) {
                // the outer child is outside the new pid namespace (unshare only
                // moves our CHILDREN in), so it just mirrors the exit status.
                ::close(report[1]);
                int wst = 0;
                while (::waitpid(inner, &wst, 0) < 0 && errno == EINTR) {
                }
                if (WIFSIGNALED(wst)) ::_exit(128 + WTERMSIG(wst));
                ::_exit(WIFEXITED(wst) ? WEXITSTATUS(wst) : 1);
            }
            // `inner` is the first process in the namespace, so it is pid 1.
            // pid 1 ignores every signal it has no handler for, including
            // SIGKILL from inside the namespace, so a guest running here could
            // not `kill $$` or be killed by its own children, and a script that
            // signals itself reported success. one more fork keeps pid 1 for a
            // shepherd that only waits, and the guest runs as pid 2 with normal
            // signal semantics. `kill -9 $$` then dies with 137, as on the host.
            // a policy that asked for as_pid_1 skips this and keeps pid 1.
            //
            // the shepherd stays in the setup child's fd table only until the
            // fork, then closes the report socket so the parent's EOF still
            // means "guest exec'd". signals from outside (the runner's SIGTERM
            // and SIGKILL) reach pid 1, and when pid 1 dies the kernel kills
            // everything else in the namespace, so stop/timeout still work.
            if (!plan.guest_is_pid_1()) {
                pid_t guest = static_cast<pid_t>(::syscall(SYS_clone3, &fa, sizeof fa));
                if (guest < 0) {
                    f.stage = 0;
                    f.sys_errno = errno;
                    for (int k = 0; k < 8; ++k) f.mech[k] = "pid-fork"[k];
                    ssize_t ig = ::write(report[1], &f, sizeof f);
                    (void)ig;
                    ::_exit(kExitPlanFailed);
                }
                if (guest > 0) {
                    ::close(report[1]);
                    // blank the argv we inherited, so /proc/1/cmdline inside the
                    // sandbox reads empty instead of the supervisor's command
                    // line. plain stores, no libc: we are post-fork.
                    if (arg_start != 0 && arg_end > arg_start && arg_end - arg_start < (1u << 20)) {
                        auto* p = reinterpret_cast<volatile char*>(arg_start);
                        for (std::uintptr_t k = 0; k < arg_end - arg_start; ++k) p[k] = 0;
                    }
                    ::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);   // and no ptrace into it
                    // when the outer process dies (the runner's SIGKILL on a
                    // timeout), die too: pid 1 going takes the whole namespace
                    // with it, so nothing the guest started can outlive the
                    // stop. without this the guest's setsid() put it outside the
                    // group the runner signals, and a timed-out command's
                    // children kept running.
                    ::prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
                    // pass on what the runner sends pid 1, so a graceful SIGTERM
                    // still reaches the guest instead of being ignored. like
                    // tini: block the stop signals and collect them while we
                    // wait, so no handler (and no sigaction restorer) is needed.
                    // the guest unblocks them below, before it execs.
                    constexpr long kSigsetBytes = 8;
                    std::uint64_t stop_set = 0;
                    for (int sig : {SIGTERM, SIGINT, SIGHUP, SIGQUIT, SIGCHLD})
                        stop_set |= 1ull << (sig - 1);
                    ::syscall(SYS_rt_sigprocmask, SIG_BLOCK, &stop_set, nullptr, kSigsetBytes);
                    for (;;) {
                        int wst = 0;
                        const pid_t r = ::waitpid(guest, &wst, WNOHANG);
                        if (r == guest) {
                            if (WIFSIGNALED(wst)) ::_exit(128 + WTERMSIG(wst));
                            ::_exit(WIFEXITED(wst) ? WEXITSTATUS(wst) : 1);
                        }
                        if (r < 0 && errno != EINTR) ::_exit(1);
                        struct timespec tick{0, 200'000'000};
                        const long sig = ::syscall(SYS_rt_sigtimedwait, &stop_set, nullptr,
                                                   &tick, kSigsetBytes);
                        if (sig > 0 && sig != SIGCHLD) ::syscall(SYS_kill, guest, sig);
                    }
                }
            }
            // grandchild: finish the plan.
            //
            // NOTE ON BROKERING. the seccomp listener fd cannot be handed to the
            // supervisor with SCM_RIGHTS. once no_new_privs is set -- which it
            // must be, before both landlock and seccomp -- the kernel refuses to
            // pass a notify fd over a unix socket, because that would let an
            // unprivileged process give another process the ability to answer
            // (and therefore bypass) its filter. sendmsg returns EPERM, and no
            // amount of reordering helps: the fd does not exist until seccomp is
            // installed, and seccomp cannot be installed before nnp.
            //
            // so the supervisor fetches it the other way round, with
            // pidfd_getfd(), which is the interface the kernel provides for
            // exactly this and which requires PTRACE_MODE_ATTACH on the target --
            // i.e. the supervisor's existing authority over its own child, rather
            // than a new capability crossing a boundary. spawn() therefore
            // reports the fd NUMBER, and the parent pulls the descriptor across.
            st = plan.apply_range(Phase::mounts, Phase::seccomp, afds);

            // BROKER HANDOFF, following the approach crun landed after hitting
            // this exact deadlock (scrivano.org/posts/2022-09-05-seccomp-listener).
            //
            // the problem: the listener fd only exists AFTER the filter is
            // installed, but by then sendmsg may itself be filtered -- and the
            // kernel refuses SCM_RIGHTS on a notify fd once no_new_privs is set.
            // so the process that installs the filter cannot be the one that
            // hands the descriptor over.
            //
            // the fix: fork a helper with CLONE_FILES *before* installing the
            // filter. it SHARES our descriptor table, so when we install the
            // filter and get fd N, the helper already has fd N -- no transfer is
            // needed at all. and the helper is outside the filter, so its
            // sendmsg is not intercepted.
            //
            // the helper learns N through a pipe write, which is the one syscall
            // we must keep allowed (compile() ensures that).
            pid_t helper = -1;
            if (st && brokering) {
                struct clone_args_inner {
                    std::uint64_t flags, pidfd, child_tid, parent_tid, exit_signal, stack,
                        stack_size, tls, set_tid, set_tid_size, cgroup;
                } ca{};
                ca.flags = 0x00000400ull;  // CLONE_FILES
                ca.exit_signal = SIGCHLD;
                long hp = ::syscall(SYS_clone3, &ca, sizeof ca);
                if (hp == 0) {
                    // helper: share the fd table, wait for the number, send it.
                    ::prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
                    int nfd = -1;
                    while (::read(relay[0], &nfd, sizeof nfd) < 0 && errno == EINTR) {
                    }
                    if (nfd >= 0) {
                        struct iovec iov{};
                        char tag = 'L';
                        iov.iov_base = &tag;
                        iov.iov_len = 1;
                        union {
                            char buf[CMSG_SPACE(sizeof(int))];
                            struct cmsghdr align;
                        } u{};
                        struct msghdr msg{};
                        msg.msg_iov = &iov;
                        msg.msg_iovlen = 1;
                        msg.msg_control = u.buf;
                        msg.msg_controllen = sizeof u.buf;
                        struct cmsghdr* cm = CMSG_FIRSTHDR(&msg);
                        cm->cmsg_level = SOL_SOCKET;
                        cm->cmsg_type = SCM_RIGHTS;
                        cm->cmsg_len = CMSG_LEN(sizeof(int));
                        std::memcpy(CMSG_DATA(cm), &nfd, sizeof nfd);
                        ssize_t sent = ::sendmsg(report[1], &msg, 0);
                        (void)sent;
                    }
                    ::_exit(0);
                }
                helper = static_cast<pid_t>(hp);
            }

            // NOW install the filter. the helper is already running and shares
            // our fd table, so whatever number we get is a number it can use.
            if (st) st = plan.apply_from(Phase::seccomp, afds);

            if (brokering && helper > 0) {
                int nfd = std::exchange(afds.notify_fd, -1);
                ssize_t w = ::write(relay[1], &nfd, sizeof nfd);
                (void)w;
                // wait for the helper to finish sending, so the descriptor is in
                // the supervisor's hands before we exec (exec would close it).
                int hst = 0;
                ::waitpid(helper, &hst, 0);
            }

            // report the listener fd NUMBER so the parent can fetch it with
            // pidfd_getfd. the descriptor itself cannot cross the boundary (see
            // the note above), but its number is just an integer.
            if (st) {
                int nfd = std::exchange(afds.notify_fd, -1);
                if (nfd >= 0) {
                    struct Handshake {
                        int stage;
                        int code;
                        int sys_errno;
                        char mech[32];
                    } hs{};
                    hs.stage = 2;  // 2 = broker handshake, not a failure
                    hs.code = nfd;
                    // our own pid, so the parent can open a pidfd on US rather
                    // than on the shepherd -- the listener lives in this process.
                    hs.sys_errno = static_cast<int>(::getpid());
                    ssize_t w = ::write(relay[1], &hs, sizeof hs);
                    (void)w;
                    // do NOT close nfd: the parent needs it to still exist in our
                    // descriptor table when it calls pidfd_getfd, and it stays
                    // valid across the exec because the kernel keeps the listener
                    // alive as long as the filter is.
                }
            }
        }

        if (!st) {
            f.stage = 0;
            f.code = static_cast<int>(st.error().code);
            f.sys_errno = st.error().sys_errno;
            auto m = st.error().mechanism;
            std::size_t n = m.size() < sizeof(f.mech) - 1 ? m.size() : sizeof(f.mech) - 1;
            for (std::size_t i = 0; i < n; ++i) f.mech[i] = m[i];
            ssize_t ignored = ::write(report[1], &f, sizeof f);
            (void)ignored;
            ::_exit(kExitPlanFailed);
        }

        // ---- descriptors, last thing before exec --------------------------
        //
        // after the plan (so the fd phase's close sweep has already run) and
        // before execve, because these are the only descriptors the guest is
        // meant to keep.
        //
        // the ordering hazard is real: dup2(a, b) where some later pair still
        // needs the OLD b silently reads the wrong file. minijail solves it by
        // moving every source out of the target range first, and so do we --
        // each parent_fd is relocated above the highest child_fd before any
        // dup2 lands, so no assignment can clobber a source that has not been
        // consumed yet.
        {
            Command::FdMap maps[Command::kMaxFdMaps];
            int n = 0;
            // stdio shorthand expands first, so an explicit fds[] entry for the
            // same child_fd wins by being applied later.
            auto add = [&](int parent, int child) {
                if (parent == -1 || n >= Command::kMaxFdMaps) return;
                maps[n].parent_fd = parent;
                maps[n].child_fd = child;
                ++n;
            };
            int devnull = -1;
            auto resolve = [&](int v) {
                if (v != Command::kDevNull) return v;
                if (devnull < 0) devnull = ::open("/dev/null", O_RDWR | O_CLOEXEC);
                return devnull;
            };
            add(resolve(cmd.stdin_fd), 0);
            add(resolve(cmd.stdout_fd), 1);
            add(resolve(cmd.stderr_fd), 2);
            for (int i = 0; i < cmd.fd_count && i < Command::kMaxFdMaps; ++i)
                add(cmd.fds[i].parent_fd, cmd.fds[i].child_fd);

            int highest = 2;
            for (int i = 0; i < n; ++i)
                if (maps[i].child_fd > highest) highest = maps[i].child_fd;

            // phase 1: lift every source clear of the destination range.
            for (int i = 0; i < n; ++i) {
                if (maps[i].parent_fd > highest) continue;
                int moved = ::fcntl(maps[i].parent_fd, F_DUPFD_CLOEXEC, highest + 1);
                if (moved >= 0) maps[i].parent_fd = moved;
            }
            // phase 2: place them, and clear CLOEXEC so they survive execve.
            bool fd_ok = true;
            for (int i = 0; i < n; ++i) {
                if (::dup2(maps[i].parent_fd, maps[i].child_fd) < 0) {
                    fd_ok = false;
                    break;
                }
                ::fcntl(maps[i].child_fd, F_SETFD, 0);
            }
            if (!fd_ok) {
                f.stage = 2;
                f.sys_errno = errno;
                ssize_t ignored = ::write(report[1], &f, sizeof f);
                (void)ignored;
                ::_exit(kExitPlanFailed);
            }
        }

        ::execve(cmd.program, const_cast<char* const*>(cmd.argv),
                 const_cast<char* const*>(cmd.envp ? cmd.envp : environ));

        f.stage = 1;
        f.sys_errno = errno;
        ssize_t ignored = ::write(report[1], &f, sizeof f);
        (void)ignored;
        ::_exit(kExitExecFailed);
    }

    // ---- parent ----
    ::close(report[1]);
    if (brokering) {
        ::close(relay[0]);
        ::close(relay[1]);
    }

    // put the child in its cgroup, then release it. doing this here rather than
    // in the child is what keeps the post-fork path free of sysfs work.
    if (use_cgroup) {
        ::close(gate[0]);
        auto att = cg.attach(static_cast<int>(pid));
        if (!att) {
            // could not enforce the limits we promised. kill the child rather
            // than run it unlimited: it has not exec'd yet, so nothing of the
            // caller's program has run.
            ::close(gate[1]);
            ::kill(static_cast<pid_t>(pid), SIGKILL);
            int st = 0;
            ::waitpid(static_cast<pid_t>(pid), &st, 0);
            ::close(report[0]);
            if (pidfd >= 0) ::close(pidfd);
            return std::unexpected(att.error());
        }
        char go = 1;
        ssize_t w = ::write(gate[1], &go, 1);
        (void)w;
        ::close(gate[1]);
    }

    struct Failure {
        int stage, code, sys_errno;
        char mech[32];
    } f{};

    // recvmsg, because the shepherd may relay the seccomp listener as ancillary
    // data. a plain failure report arrives the same way.
    //
    // bounded: setup takes well under a second, but a guest that blocks in it
    // (a bind or stat on a dead FUSE/NFS mount) would otherwise hold this
    // call forever, and the caller's timeouts only start once we return.
    {
        constexpr int kSetupTimeoutMs = 30'000;
        struct pollfd pfd{report[0], POLLIN, 0};
        int pr;
        do pr = ::poll(&pfd, 1, kSetupTimeoutMs); while (pr < 0 && errno == EINTR);
        if (pr == 0) {
            // the in-namespace shepherd is pid 1 there, so killing the outer
            // child (whose death it tracks) takes the rest; the cgroup covers a
            // host with no pidns.
            if (use_cgroup && cg.kill_supported()) (void)cg.kill();
            ::kill(static_cast<pid_t>(pid), SIGKILL);
            int st = 0;
            ::waitpid(static_cast<pid_t>(pid), &st, 0);
            ::close(report[0]);
            if (pidfd >= 0) ::close(pidfd);
            return std::unexpected(Error{Errc::spawn_failed, "setup timed out", ETIMEDOUT});
        }
    }
    int received_fd = -1;
    int proxy_fd = -1;
    std::uint16_t proxy_port = 0;
    std::uint64_t proxy_netns_ino = 0;
    ssize_t n;
    // the proxy listener, when the plan opened one, is sent FIRST and tagged
    // 'P' so it cannot be confused with the broker handoff or a failure
    // report. MSG_PEEK: if the first message is not ours, leave it for the
    // read below untouched.
    if (plan.has(OpCode::loopback_up)) {
        char tag[11] = {};
        struct iovec piov{};
        piov.iov_base = tag;
        piov.iov_len = sizeof tag;
        union {
            char buf[CMSG_SPACE(sizeof(int))];
            struct cmsghdr align;
        } pu{};
        struct msghdr pmsg{};
        pmsg.msg_iov = &piov;
        pmsg.msg_iovlen = 1;
        pmsg.msg_control = pu.buf;
        pmsg.msg_controllen = sizeof pu.buf;
        ssize_t pn;
        do pn = ::recvmsg(report[0], &pmsg, MSG_PEEK);
        while (pn < 0 && errno == EINTR);
        if (pn == sizeof tag && tag[0] == 'P') {
            // ours: take it for real this time.
            pmsg.msg_controllen = sizeof pu.buf;
            pmsg.msg_flags = 0;
            do pn = ::recvmsg(report[0], &pmsg, 0);
            while (pn < 0 && errno == EINTR);
            if (pn == sizeof tag && !(pmsg.msg_flags & MSG_CTRUNC))
                if (struct cmsghdr* cm = CMSG_FIRSTHDR(&pmsg);
                    cm && cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS &&
                    cm->cmsg_len == CMSG_LEN(sizeof proxy_fd)) {
                    std::memcpy(&proxy_fd, CMSG_DATA(cm), sizeof proxy_fd);
                    proxy_port = static_cast<std::uint16_t>(
                        (static_cast<unsigned char>(tag[1])) |
                        (static_cast<unsigned char>(tag[2]) << 8));
                    for (int k = 0; k < 8; ++k)
                        proxy_netns_ino |= static_cast<std::uint64_t>(
                                               static_cast<unsigned char>(tag[3 + k]))
                                           << (8 * k);
                }
        }
    }
    {
        struct iovec iov{};
        iov.iov_base = &f;
        iov.iov_len = sizeof f;
        union {
            char buf[CMSG_SPACE(sizeof(int))];
            struct cmsghdr align;
        } u{};
        struct msghdr msg{};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = u.buf;
        msg.msg_controllen = sizeof u.buf;
        do n = ::recvmsg(report[0], &msg, 0); while (n < 0 && errno == EINTR);
        // the shepherd sends exactly one SCM_RIGHTS message carrying one fd,
        // so read that header and check it fully instead of walking a list.
        // a truncated control buffer means the fd was dropped: treat as none.
        if (n > 0 && !(msg.msg_flags & MSG_CTRUNC))
            if (struct cmsghdr* cm = CMSG_FIRSTHDR(&msg);
                cm && cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS &&
                cm->cmsg_len == CMSG_LEN(sizeof received_fd))
                std::memcpy(&received_fd, CMSG_DATA(cm), sizeof received_fd);
    }
    ::close(report[0]);

    // the CLONE_FILES helper sent the listener as ancillary data, so a one-byte
    // message with a descriptor attached IS the handoff -- not a failure report.
    // the helper shares the guest's fd table, which is why no pidfd_getfd dance
    // is needed: the number the guest got is already valid in the helper.

    if (received_fd >= 0 && n == 1)
        return Spawned{static_cast<int>(pid), pidfd, received_fd, proxy_fd, proxy_port,
                       proxy_netns_ino};

    if (n == static_cast<ssize_t>(sizeof f)) {
        // the child told us why. reap it so we do not leave a zombie, then
        // report the real reason rather than a generic spawn failure.
        int status = 0;
        ::waitpid(static_cast<pid_t>(pid), &status, 0);
        if (pidfd >= 0) ::close(pidfd);
        if (proxy_fd >= 0) ::close(proxy_fd);
        f.mech[sizeof(f.mech) - 1] = '\0';
        return std::unexpected(Error{f.stage == 0 ? static_cast<Errc>(f.code) : Errc::spawn_failed,
                                     f.stage == 0 ? static_mechanism(f.mech) : "execve",
                                     f.sys_errno});
    }

    return Spawned{static_cast<int>(pid), pidfd, -1, proxy_fd, proxy_port, proxy_netns_ino};
}

}  // namespace clay

#else

namespace clay {
Result<Spawned> spawn(const Plan&, const Command&) {
    return std::unexpected(Error{Errc::unsupported, "spawn: linux only"});
}
}  // namespace clay

#endif
