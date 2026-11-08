// claybin: ready-made syscall profiles.
//
// hand-writing an allow-list is how people get this wrong: miss one syscall the
// libc startup path needs and the child dies before main(), usually with a
// confusing SIGSYS. these profiles are the tested baselines to build on.
//
// x86_64 numbers. other arches get their own table; the policy layer is
// arch-independent, only these constants are not.
#pragma once

#include "claybin/policy/syscalls.hpp"

// the namespace is overridable for the same reason the arch is: a test that
// wants both tables in one binary needs them to be DIFFERENT symbols. these are
// inline functions, so two translation units defining `clay::profiles::base()`
// differently is an ODR violation the linker resolves by silently picking one --
// which is not a diagnostic, it is a wrong answer.
#if !defined(CLAY_PROFILES_NAMESPACE)
#define CLAY_PROFILES_NAMESPACE profiles
#endif

namespace clay::CLAY_PROFILES_NAMESPACE {

// which arch's syscall table to compile. normally the one we are building for,
// but overridable so the tables can be TESTED on a different host: an untested
// syscall table is a list of guesses, and cross-compiling the whole library
// just to check 130 numbers is a poor trade.
//
// CLAY_PROFILE_ARCH_AARCH64 selects the aarch64 block regardless of host. it
// only changes which numbers the tables contain -- it cannot make a filter for
// the wrong arch get INSTALLED, because bpf::compile() guards on the real
// audit arch from native_arch() and that is not overridable.
#if defined(CLAY_PROFILE_ARCH_AARCH64)
#define CLAY_PROFILES_AARCH64 1
#elif defined(CLAY_PROFILE_ARCH_X86_64)
#define CLAY_PROFILES_X86_64 1
#elif defined(__x86_64__)
#define CLAY_PROFILES_X86_64 1
#elif defined(__aarch64__)
#define CLAY_PROFILES_AARCH64 1
#endif

// prctl options a guest may use: each acts only on the caller's own process.
// the values are the same on every arch (linux/prctl.h).
inline constexpr std::uint32_t kPrctlAllowed[] = {
    1, 2,        // PR_SET/GET_PDEATHSIG
    3, 4,        // PR_GET/SET_DUMPABLE (can only lower it once nnp is set)
    15, 16,      // PR_SET/GET_NAME
    21,          // PR_GET_SECCOMP
    23,          // PR_CAPBSET_READ
    27,          // PR_GET_SECUREBITS
    29, 30,      // PR_SET/GET_TIMERSLACK
    36, 37,      // PR_SET/GET_CHILD_SUBREAPER
    38, 39,      // PR_SET/GET_NO_NEW_PRIVS (setting it only narrows)
    40,          // PR_GET_TID_ADDRESS
    41, 42,      // PR_SET/GET_THP_DISABLE
    0x53564d41,  // PR_SET_VMA (anon mapping names; glibc 2.40+ calls it)
};
// personality(0xffffffff) only reads the current value; 0 is PER_LINUX.
inline constexpr std::uint32_t kPersonalityAllowed[] = {0u, 0xffffffffu};

// A tracer (linuxity, an emulator) stacks its own filter to choose which
// calls it traps; without one it stops on every syscall, about ten times
// slower. Stacking can't widen anything, since the kernel runs every filter
// and keeps the strictest answer, and a notify listener only sees the
// installer's own descendants, all inside the sandbox. Only the ops that
// install or query a filter. And since the strictest answer wins, a call
// this policy kills would kill a guest the tracer meant to answer: under a
// tracer those become EPERM, which refuses them just as firmly.
inline void allow_stacked_filter(SyscallPolicy& p, SysNr seccomp_nr) {
    static constexpr std::uint32_t kOps[] = {1 /* SET_MODE_FILTER */, 2 /* GET_ACTION_AVAIL */,
                                             3 /* GET_NOTIF_SIZES */};
    p.allow(seccomp_nr);
    p.allow_arg32_only(seccomp_nr, 0, kOps);
    std::vector<SysNr> killed;
    for (const auto& r : p.rules())
        if (r.action == SysAction::kill_process) killed.push_back(r.nr);
    for (SysNr nr : killed) p.deny(nr, 1 /* EPERM */);
}

#if defined(CLAY_PROFILES_X86_64)

// the bare minimum for a dynamically linked program to start, run, and exit.
// anything that cannot be justified as "libc needs this before main" belongs in
// a more specific profile, not here.
//
// NOTE: there is deliberately no execve here. that means a policy using bare
// base() cannot be handed to spawn(), because spawn's own execve would be the
// first thing the filter denies -- you get EPERM from execve and it looks like
// the sandbox is broken. use with_processes() or compiler() when the sandboxed
// program is launched by exec, which is almost always. base() is for a process
// that sandboxes ITSELF after it is already running.
inline SyscallPolicy base() {
    SyscallPolicy p;
    p.set_default(SysAction::errno_, 1 /* EPERM */);

    static constexpr SysNr kAllowed[] = {
        0,    // read
        1,    // write
        3,    // close
        5,    // fstat
        8,    // lseek
        9,    // mmap
        10,   // mprotect
        11,   // munmap
        12,   // brk
        25,   // mremap
        //   mremap belongs with the other four, not with anything optional.
        //   glibc's realloc() grows a block past the mmap threshold by
        //   remapping it, so denying mremap makes realloc return NULL on a
        //   perfectly reasonable request -- and a caller that checks its
        //   allocations then reports out of memory on a machine with free
        //   RAM. curl does exactly that: it failed with CURLE_OUT_OF_MEMORY
        //   (27) talking to a raw IP, which reads like a network denial and
        //   is not one. A filter whose failures lie about their cause is
        //   worse than a looser one, and mremap grants no authority the
        //   other four don't already: it moves the caller's own mapping.
        13,   // rt_sigaction
        14,   // rt_sigprocmask
        15,   // rt_sigreturn
        16,   // ioctl  (isatty; narrowed by landlock's ioctl_dev on abi>=5)
        17,   // pread64
        18,   // pwrite64
        19,   // readv
        20,   // writev
        24,   // sched_yield
        28,   // madvise
        39,   // getpid
        60,   // exit
        63,   // uname
        72,   // fcntl
        79,   // getcwd
        // the working directory is per-process state, and landlock and the
        // mount tree still decide what a path reaches. without these `cd`
        // fails EPERM, which breaks every shell script and `git -C`.
        80,   // chdir
        81,   // fchdir
        89,   // readlink
        96,   // gettimeofday
        97,   // getrlimit
        98,   // getrusage
        102,  // getuid
        104,  // getgid
        107,  // geteuid
        108,  // getegid
        110,  // getppid
        // capget READS the caller's capability sets. it grants nothing -- capSET
        // is the one that changes them, and that stays denied.
        //
        // WHY IT IS HERE: node calls capget 15 times during startup, and
        // without it V8 died before running a line of script with
        // `Check failed: 12 == errno` -- an assertion that the call it just
        // made should have set ENOMEM. a syscall handing back EPERM where the
        // caller expected a different errno is exactly that shape, and the
        // symptom (a fatal error naming no file and no line) points nowhere
        // near the cause. found by strace-counting node's startup on the host
        // and diffing against the profile.
        125,  // capget
        158,  // arch_prctl
        186,  // gettid
        201,  // time
        202,  // futex
        204,  // sched_getaffinity
        218,  // set_tid_address
        228,  // clock_gettime
        230,  // clock_nanosleep
        231,  // exit_group
        234,  // tgkill    (abort/assert)
        257,  // openat
        262,  // newfstatat
        273,  // set_robust_list
        302,  // prlimit64
        318,  // getrandom
        334,  // rseq
    };
    p.allow(std::span<const SysNr>{kAllowed});

    // clone3 is deliberately NOT allowed, and the errno is ENOSYS rather than
    // EPERM on purpose.
    //
    // clone3 takes a POINTER to struct clone_args, so its flags live in memory
    // and seccomp cannot see them -- and filtering them by dereferencing the
    // pointer is unsound, because the guest can rewrite it between the check and
    // the syscall. that makes clone3 a hole straight through the clone flag
    // rules below: deny unshare and mask off CLONE_NEWUSER on clone, and
    // clone3(CLONE_NEWUSER) still gets you a namespace.
    //
    // ENOSYS is what makes this safe rather than merely strict: glibc probes
    // clone3 and falls back to clone when the kernel says "no such syscall",
    // which is exactly the path we can filter. EPERM here would make
    // pthread_create fail instead of fall back.
    p.deny(435 /* clone3 */, 38 /* ENOSYS */);

    // prctl, but only options that act on the caller's own process. without
    // it Chromium, Electron and Python multiprocessing fail at startup
    // (PR_SET_NAME, PR_SET_PDEATHSIG). PR_SET_SECCOMP, PR_SET_MM,
    // PR_SET_PTRACER, PR_CAP_AMBIENT and PR_SET_KEEPCAPS aren't listed, so
    // they get EPERM.
    p.allow(157 /* prctl */);
    p.allow_arg32_only(157, 0 /* option */, std::span<const std::uint32_t>{kPrctlAllowed},
                       SysAction::errno_, 1 /* EPERM */);

    // personality: query (0xffffffff) and PER_LINUX only. ADDR_NO_RANDOMIZE
    // (`setarch -R`) and READ_IMPLIES_EXEC would weaken the guest's own
    // hardening.
    p.allow(135 /* personality */);
    p.allow_arg32_only(135, 0, std::span<const std::uint32_t>{kPersonalityAllowed},
                       SysAction::errno_, 1);

    // process-group and session calls. these are NOT privileges -- they only
    // touch the caller's own group -- but every shell calls them during startup
    // and a missing one produces the baffling
    // "initialize_job_control: getpgrp failed: Success", which cost an
    // afternoon the first time. a sandbox that cannot run /bin/sh is not much
    // of a sandbox.
    static constexpr SysNr kJobControl[] = {
        39,   // getpid (already above, harmless to repeat)
        109,  // setpgid
        110,  // getppid
        111,  // getpgrp
        112,  // setsid
        121,  // getpgid
        124,  // getsid
        // NOT 122 or 123. those are setfsuid and setfsgid, and 122 was in this
        // list labelled "getsid" -- which is 124. a mislabelled number in an
        // allow-list is the worst kind of typo: nothing breaks to tell you it is
        // there, and reading the list does not catch it, twice.
        //
        // being straight about the severity: setfsuid needs CAP_SETUID, and the
        // sandbox drops the whole bounding set before seccomp, so this was not
        // exploitable -- measured, the fsuid does not budge inside claybin.
        // it was defence-in-depth that had quietly stopped being defence. the
        // real fix is not this line, it is syscall_table_test, which resolves
        // every name through the kernel's own headers so the next mislabelled
        // number fails a test instead of sitting here.
        14,   // rt_sigprocmask (already above)
        13,   // rt_sigaction (already above)
    };
    p.allow(std::span<const SysNr>{kJobControl});

    // Calls ordinary programs make that grant NO authority.
    //
    // This group is here because leaving it out did not produce "the sandbox
    // is strict", it produced "the sandbox is broken": curl died with
    // CURLE_OUT_OF_MEMORY (27) on a machine with gigabytes free, while
    // python3 fetched the same URL fine. Error 27 sends you to memory caps
    // and network rules, and the cause was neither -- it took dumping the
    // profile table to find it. A filter whose failures lie about their cause
    // is worse than a looser one, because nobody can act on the lie.
    //
    // The bar for each of these is AUTHORITY, not convenience: does it let
    // the guest reach something it could not already reach? For every entry
    // below the answer is no, and the note says why. mlockall is deliberately
    // NOT here -- see after the list.
    static constexpr SysNr kOrdinary[] = {
        // openssl mlocks the pages holding key material so they cannot be
        // swapped to disk. bounded by RLIMIT_MEMLOCK, which the sandbox sets,
        // and it pins only the caller's OWN pages -- no new reach. denying it
        // is what broke curl: openssl treats the failure as an allocation
        // failure and reports OOM.
        149,  // mlock
        150,  // munlock
        // no authority at all: these read a clock or yield. sleep() and every
        // retry/backoff loop needs nanosleep, and a tool that cannot sleep
        // looks hung rather than denied.
        35,   // nanosleep
        229,  // clock_getres
        // glibc and rseq use membarrier for lock-free fast paths. it
        // synchronises the caller's own threads and nothing else.
        324,  // membarrier
        // topology probes. they leak which CPU we are on, which is not a
        // capability -- /proc/cpuinfo says more and is already readable.
        309,  // getcpu
        // new DESCRIPTORS, no new reach. an eventfd/timerfd is a private
        // notification object; every event loop (libuv, glib, tokio) opens
        // one at startup.
        290,  // eventfd2
        283,  // timerfd_create
        // POSIX interval timers. SAME authority as timerfd_create above --
        // the timer is per-process, fires a signal at the caller, and
        // reaches nothing outside it -- but denying them breaks something
        // that LOOKS like it worked, which is worse than an honest EPERM.
        //
        // coreutils `timeout` arms a timer, prints
        //     timeout: warning: timer_create: Operation not permitted
        // to stderr, and then runs the command WITHOUT A TIMEOUT, exiting 0.
        // A caller that greps for a non-zero exit sees success. So a hung
        // command inside the sandbox is never killed, and anything relying
        // on `timeout` for its own watchdog silently has none. Python's
        // signal.setitimer and every SIGALRM-based watchdog fail the same
        // way.
        //
        // Allowing these does not weaken the wall-clock cap: that is
        // enforced by the RUNNER (subprocess.cpp's deadline + SIGTERM/
        // SIGKILL) from outside the sandbox, where the guest cannot reach
        // it. These let a guest time ITSELF, which it can already do with
        // timerfd + poll.
        222,  // timer_create
        223,  // timer_settime
        224,  // timer_gettime
        225,  // timer_getoverrun
        226,  // timer_delete
        38,   // setitimer
        36,   // getitimer
        37,   // alarm       (the oldest spelling of the same thing)
        // Reads the caller's own supplementary group list. No authority at
        // all -- the ids are already in /proc/self/status, which is
        // readable. Denying it only makes `id` print an error.
        115,  // getgroups
        // AF_UNIX only, and both ends belong to the caller -- it cannot be
        // used to reach a socket outside the sandbox. git and ssh use it to
        // talk to their own helper processes. the network namespace still
        // governs anything routable.
        53,   // socketpair
        // anonymous memory with a file descriptor. the descriptor refers to
        // memory, not to anything in the filesystem, so it grants no path
        // access. NOTE: a memfd can be mapped executable, so this interacts
        // with the W^X rule below -- that rule still applies to the mapping,
        // which is where the protection actually lives.
        319,  // memfd_create
    };
    p.allow(std::span<const SysNr>{kOrdinary});

    // mlockall stays DENIED, and the asymmetry with mlock is the point.
    //
    // mlock pins a named range the caller already owns. mlockall pins
    // EVERYTHING, current and future, which under a cgroup memory cap is a
    // denial-of-service lever rather than a convenience. Nothing in the
    // toolchains this profile targets needs it; gnupg and some JVMs do, and
    // they can run under a profile that says so.
    p.deny(151 /* mlockall */, 1 /* EPERM */);

    // the modern variants glibc actually calls. the older numbers are not
    // enough on their own: libc prefers pipe2/dup3/openat and only falls back
    // to pipe/dup2/open on ancient kernels, so a list with just the classic
    // numbers produces "pipe error: Operation not permitted" from any shell
    // running a pipeline.
    static constexpr SysNr kModern[] = {
        22,   // pipe
        32,   // dup
        33,   // dup2
        292,  // dup3
        293,  // pipe2
        213,  // epoll_create
        291,  // epoll_create1
        232,  // epoll_wait
        281,  // epoll_pwait
        233,  // epoll_ctl
        23,   // select
        7,    // poll
        271,  // ppoll
        270,  // pselect6
        302,  // prlimit64
        99,   // sysinfo
        137,  // statfs
        138,  // fstatfs
    };
    p.allow(std::span<const SysNr>{kModern});

    // explicitly kill rather than errno for the classic escape attempts. a
    // denied-with-EPERM ptrace looks like a permissions hiccup; a killed one is
    // an unmistakable signal in an audit log.
    for (SysNr nr : {101u /* ptrace */, 165u /* mount */, 166u /* umount2 */,
                     155u /* pivot_root */, 161u /* chroot */, 272u /* unshare */,
                     308u /* setns */, 321u /* bpf */, 298u /* perf_event_open */,
                     175u /* init_module */, 176u /* delete_module */,
                     313u /* finit_module */, 246u /* kexec_load */,
                     320u /* kexec_file_load */, 169u /* reboot */,
                     // the new mount API. each is as much an escape primitive
                     // as mount(2), and aarch64 already killed finit_module.
                     428u /* open_tree */, 429u /* move_mount */, 430u /* fsopen */,
                     431u /* fsconfig */, 432u /* fsmount */, 433u /* fspick */,
                     442u /* mount_setattr */})
        p.kill(nr);

    // ---- ioctl, restricted by ARGUMENT to an allow-list -------------------
    //
    // ioctl has to stay allowed: isatty() calls it, and so does every program
    // that checks whether stdout is a terminal. but it is the widest syscall in
    // the kernel -- thousands of requests, and any loaded driver adds more -- so
    // a deny-list is a list of the escapes somebody already thought of. this is
    // an allow-list instead: everything is EPERM except the requests a normal
    // program genuinely needs.
    //
    // that closes the ones a deny-list would have to name one at a time, most
    // importantly TIOCSTI. TIOCSTI pushes a byte into a terminal's input queue,
    // so a guest sharing a controlling terminal with an interactive shell can
    // TYPE INTO THAT SHELL and have it run outside the sandbox. modern kernels
    // gate it behind dev.tty.legacy_tiocsti, but a sandbox that relies on a host
    // sysctl is not a sandbox. TIOCLINUX does the same thing via its subcommand
    // TIOCL_SETSEL, TIOCCONS redirects console output, and TIOCSCTTY steals a
    // controlling terminal -- none of which are on this list, so none need
    // naming.
    //
    // these are 32-BIT comparisons. ioctl's cmd is `unsigned int` and the kernel
    // truncates the register before using it, so a rule that also requires the
    // high half to be zero is bypassed by ioctl(fd, 0xdeadbeef00005412), which
    // runs as TIOCSTI. that is measured, not theoretical.
    //
    // values from asm-generic/ioctls.h.
    static constexpr std::uint32_t kIoctlAllowed[] = {
        // terminal attributes. isatty() is TCGETS, and every shell and libc
        // startup path touches these.
        0x5401,  // TCGETS
        0x5402,  // TCSETS
        0x5403,  // TCSETSW
        0x5404,  // TCSETSF
        0x5405,  // TCGETA
        0x5409,  // TCSBRK
        0x540A,  // TCXONC
        0x540B,  // TCFLSH
        // window size. anything that formats output for a terminal asks.
        0x5413,  // TIOCGWINSZ
        0x5414,  // TIOCSWINSZ
        // process group and session. job control, and read-only queries.
        0x540F,  // TIOCGPGRP
        0x5410,  // TIOCSPGRP
        0x5429,  // TIOCGSID
        // descriptor state. these act on the fd, not on any device.
        0x541B,  // FIONREAD
        0x5421,  // FIONBIO
        0x5450,  // FIONCLEX
        0x5451,  // FIOCLEX
        0x5411,  // TIOCOUTQ
    };
    p.allow_arg32_only(16 /* ioctl */, 1 /* request */,
                       std::span<const std::uint32_t>{kIoctlAllowed}, SysAction::errno_,
                       1 /* EPERM */);

    // W^X: no mapping may be writable and executable at the same time.
    //
    // this does not stop a determined attacker -- they can mmap writable, write
    // their code, then mprotect it executable -- but it does break the whole
    // class of exploits that rely on a single RWX mapping, and it costs nothing
    // for ordinary programs, which never ask for one. JITs do, which is why this
    // lives here and not in a profile a JIT would use.
    //
    // not_all is the right comparison: PROT_WRITE|PROT_EXEC is forbidden as a
    // COMBINATION, while either alone is fine. an equality test on the pair
    // would miss PROT_READ|PROT_WRITE|PROT_EXEC, which is what a real exploit
    // actually asks for.
    static constexpr std::uint64_t kProtWriteExec = 0x2 | 0x4;
    p.deny_arg_all(9 /* mmap */, 2 /* prot */, kProtWriteExec, SysAction::errno_, 1);
    p.deny_arg_all(10 /* mprotect */, 2 /* prot */, kProtWriteExec, SysAction::errno_, 1);

    return p;
}

// every CLONE_NEW* flag. a new namespace of any kind is the first move in most
// container escapes: a user namespace hands back capabilities, a mount namespace
// is a step towards remounting something writable, and a pid namespace hides
// processes from a supervisor watching from outside.
//
// masking these off clone is what makes threads work while namespaces do not --
// pthread_create sets CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD,
// none of which are here.
//
// these values are from linux/sched.h and are NOT guessable. CLONE_VM is
// 0x00000100 and CLONE_NEWNS is 0x00020000; getting that pair backwards puts
// CLONE_VM in this mask and denies every pthread_create in the sandbox.
inline constexpr std::uint64_t kCloneNewNamespaces =
    0x00020000ull |  // CLONE_NEWNS      -- mount
    0x02000000ull |  // CLONE_NEWCGROUP
    0x04000000ull |  // CLONE_NEWUTS     -- hostname
    0x08000000ull |  // CLONE_NEWIPC
    0x10000000ull |  // CLONE_NEWUSER    -- the dangerous one
    0x20000000ull |  // CLONE_NEWPID
    0x40000000ull;   // CLONE_NEWNET
                     // 0x80000000 is CLONE_IO, not a namespace. leave it alone.

// grant subprocesses and threads on top of an existing profile, WITH the clone
// flag mask that makes it safe.
//
// this is a mutating helper rather than a composition because composition of
// sealed authority is meet -- intersection -- and intersecting two profiles
// would deny everything either one denies, which is the opposite of "add exec
// to a filesystem profile". granting is only ever explicit, so it looks like a
// function call that takes a policy apart and puts more in.
inline SyscallPolicy& add_processes(SyscallPolicy& p) {
    for (SysNr nr : {56u /* clone */, 57u /* fork */, 58u /* vfork */, 59u /* execve */,
                     61u /* wait4 */, 62u /* kill */, 322u /* execveat */})
        p.allow(nr);

    // clone is allowed, but not for making namespaces. base() already denies
    // unshare and clone3 outright; this closes the third door.
    //
    // any_set, not equality: the guest picks the other flags, so the only sound
    // question is "is any namespace bit present".
    p.deny_arg_any(56 /* clone */, 0 /* flags */, kCloneNewNamespaces, SysAction::errno_,
                   1 /* EPERM */);
    return p;
}

// base plus threads and subprocesses. this is the smallest profile that works
// with spawn(), because it is the first one that allows execve.
inline SyscallPolicy with_processes() {
    SyscallPolicy p = base();
    add_processes(p);
    return p;
}

// base plus the filesystem calls a compiler or build tool needs.
//
// like base(), this has no execve: it is for a process restricting itself. if
// you are going to spawn() into it, use compiler() instead.
inline SyscallPolicy with_filesystem() {
    SyscallPolicy p = base();
    for (SysNr nr : {2u /* open */, 4u /* stat */, 6u /* lstat */, 21u /* access */,
                     22u /* pipe */, 32u /* dup */, 33u /* dup2 */, 77u /* ftruncate */,
                     78u /* getdents */, 82u /* rename */, 83u /* mkdir */, 84u /* rmdir */,
                     87u /* unlink */, 88u /* symlink */, 90u /* chmod */, 91u /* fchmod */,
                     133u /* mknod */, 217u /* getdents64 */, 260u /* fchownat */,
                     263u /* unlinkat */, 264u /* renameat */, 265u /* linkat */,
                     266u /* symlinkat */, 269u /* faccessat */, 280u /* utimensat */,
                     285u /* fallocate */, 316u /* renameat2 */, 332u /* statx */,
                     439u /* faccessat2 */})
        p.allow(nr);
    // read-only xattrs. coreutils `ls` and `cp -a` probe them per file
    // (security.selinux, system.posix_acl_access) and print an error on
    // EPERM. reading metadata grants nothing the mount tree and landlock
    // don't already decide; the set*/remove* calls stay denied.
    for (SysNr nr : {191u /* getxattr */, 192u /* lgetxattr */, 193u /* fgetxattr */,
                     194u /* listxattr */, 195u /* llistxattr */, 196u /* flistxattr */})
        p.allow(nr);
    return p;
}

// a build/compile sandbox: files plus subprocesses, no network.
inline SyscallPolicy compiler() {
    SyscallPolicy p = with_filesystem();
    add_processes(p);
    return p;
}

// compiler() plus ptrace, for a tracer that supervises its own children
// (linuxity, gdb, strace). Safe for the same reasons the other walls hold:
// the sandbox has its own pid namespace, so a tracee can only be another
// sandboxed process, and since 4.8 seccomp checks a syscall again after a
// tracer rewrites it, so tracing can't step around this filter.
// process_vm_readv/writev are a tracer's memory window; they follow the
// same ptrace access check.
inline SyscallPolicy supervisor() {
    SyscallPolicy p = compiler();
    for (SysNr nr : {101u /* ptrace */, 310u /* process_vm_readv */, 311u /* process_vm_writev */,
                     // kill and tgkill are allowed already; these reach the
                     // same targets. A tracer's child stops itself with one
                     // before its first exec.
                     200u /* tkill */, 129u /* rt_sigqueueinfo */, 297u /* rt_tgsigqueueinfo */,
                     // a tracer emulates these for its guest (linuxity's root
                     // chowns and setgroups). Allowing them grants nothing:
                     // with the bounding set empty and no_new_privs, the
                     // kernel's own credential checks refuse any real change.
                     92u /* chown */, 93u /* fchown */, 94u /* lchown */, 116u /* setgroups */,
                     105u /* setuid */, 106u /* setgid */, 113u /* setreuid */, 114u /* setregid */,
                     117u /* setresuid */, 119u /* setresgid */, 122u /* setfsuid */,
                     123u /* setfsgid */, 126u /* capset */, 118u /* getresuid */, 120u /* getresgid */})
        p.allow(nr);
    allow_stacked_filter(p, 317 /* seccomp */);
    return p;
}

// base plus TCP client sockets.
//
// pair this with a per-port `connect()` grant: landlock (abi 4+) then mediates
// which ports are reachable, so "this program may talk to exactly 443" is
// enforced by the kernel rather than merely described. seccomp alone can only
// say "sockets yes or no" -- the port granularity comes from landlock, and the
// two together are what a netns cannot give you.
//
// like with_filesystem(), this has NO execve: it is for a process restricting
// itself. use compiler_with_network() when spawn() has to exec into it.
inline SyscallPolicy with_network() {
    SyscallPolicy p = with_filesystem();
    for (SysNr nr : {41u /* socket */, 42u /* connect */, 43u /* accept */,
                     44u /* sendto */, 45u /* recvfrom */, 46u /* sendmsg */,
                     47u /* recvmsg */, 48u /* shutdown */, 49u /* bind */,
                     50u /* listen */, 51u /* getsockname */, 52u /* getpeername */,
                     54u /* setsockopt */, 55u /* getsockopt */, 288u /* accept4 */,
                     299u /* recvmmsg */, 307u /* sendmmsg */})
        p.allow(nr);
    return p;
}

// the shape an agent-run build wants: files, subprocesses, and brokered network.
inline SyscallPolicy compiler_with_network() {
    SyscallPolicy p = with_network();
    add_processes(p);
    return p;
}

#elif defined(CLAY_PROFILES_AARCH64)

// ---------------------------------------------------------------------------
// aarch64.
//
// a second table rather than a mapping layer, because a syscall number IS the
// arch-specific thing -- there is no portable name a filter can act on, and a
// translation table would just be this list with an extra chance to be wrong.
//
// every number here came out of <asm-generic/unistd.h>, which is the table
// aarch64 uses. NOT from memory: the x86_64 list above shipped with 122
// labelled "getsid" (it is setfsuid, getsid is 124), which is exactly the
// mistake a hand-written table invites. syscall_table_test resolves names
// through the kernel's own headers so the next one fails a test.
//
// the shape differs from x86_64 in one structural way worth knowing: aarch64
// has NO legacy non-`at` calls. no open, no stat, no fork, no pipe, no dup2,
// no getpgrp. libc uses openat, fstatat, clone, pipe2, dup3 and getpgid, so
// their absence is correct rather than an omission -- there is no number to
// allow.
// ---------------------------------------------------------------------------

inline SyscallPolicy base() {
    SyscallPolicy p;
    p.set_default(SysAction::errno_, 1 /* EPERM */);

    static constexpr SysNr kAllowed[] = {
        // what libc needs before main
        63,   // read
        64,   // write
        57,   // close
        80,   // fstat
        62,   // lseek
        222,  // mmap
        226,  // mprotect
        215,  // munmap
        214,  // brk
        216,  // mremap  -- see the x86_64 table: realloc needs it
        134,  // rt_sigaction
        135,  // rt_sigprocmask
        139,  // rt_sigreturn
        29,   // ioctl
        67,   // pread64
        68,   // pwrite64
        65,   // readv
        66,   // writev
        124,  // sched_yield
        233,  // madvise
        172,  // getpid
        93,   // exit
        160,  // uname
        25,   // fcntl
        17,   // getcwd
        49,   // chdir   -- see the x86_64 table
        50,   // fchdir
        169,  // gettimeofday
        165,  // getrusage
        174,  // getuid
        176,  // getgid
        175,  // geteuid
        177,  // getegid
        173,  // getppid
        90,   // capget -- reads only; see the x86_64 table for why node needs it
        178,  // gettid
        98,   // futex
        123,  // sched_getaffinity
        96,   // set_tid_address
        113,  // clock_gettime
        115,  // clock_nanosleep
        94,   // exit_group
        131,  // tgkill
        56,   // openat      (there is no `open`)
        79,   // fstatat     (there is no `stat`/`lstat`/`newfstatat`)
        78,   // readlinkat  (there is no `readlink`)
        99,   // set_robust_list
        261,  // prlimit64
        278,  // getrandom
        293,  // rseq

        // job control. note getpgrp does not exist here; glibc's getpgrp()
        // calls getpgid(0).
        154,  // setpgid
        155,  // getpgid
        157,  // setsid
        156,  // getsid   -- and NOT 151/152, which are setfsuid/setfsgid

        // descriptors and polling
        59,   // pipe2   (there is no `pipe`)
        23,   // dup
        24,   // dup3    (there is no `dup2`)
        20,   // epoll_create1
        21,   // epoll_ctl
        22,   // epoll_pwait
        73,   // ppoll     (there is no `poll`)
        72,   // pselect6  (there is no `select`)
        179,  // sysinfo
        43,   // statfs
        44,   // fstatfs
    };
    p.allow(std::span<const SysNr>{kAllowed});

    // The same no-authority group as x86_64 -- see the long note there for why
    // each one is safe and why mlockall is not in it. Numbers verified against
    // the kernel's asm-generic/unistd.h (which is aarch64's table), NOT
    // translated by hand from the x86_64 list: hand-translating a syscall
    // number is exactly how 122/124 got mislabelled the first time.
    static constexpr SysNr kOrdinary[] = {
        228,  // mlock
        229,  // munlock
        101,  // nanosleep
        114,  // clock_getres
        283,  // membarrier
        168,  // getcpu
        19,   // eventfd2
        85,   // timerfd_create
        // POSIX interval timers -- see the long note on the x86_64 list for
        // why these are no-authority and why denying them is worse than an
        // honest refusal (`timeout` warns, then runs with NO timeout and
        // exits 0). Numbers from asm-generic/unistd.h, same as the rest of
        // this table. aarch64 has no `alarm`: glibc implements it on
        // setitimer there, so the x86_64 entry 37 has no counterpart.
        107,  // timer_create
        110,  // timer_settime
        108,  // timer_gettime
        109,  // timer_getoverrun
        111,  // timer_delete
        103,  // setitimer
        102,  // getitimer
        158,  // getgroups
        199,  // socketpair
        279,  // memfd_create
    };
    p.allow(std::span<const SysNr>{kOrdinary});

    // mlockall denied here too: it pins ALL memory, current and future, which
    // is a DoS lever under a cgroup cap rather than a convenience.
    p.deny(230 /* mlockall */, 1 /* EPERM */);

    // clone3: denied with ENOSYS, for the same reason as on x86_64. its flags
    // live behind a pointer that seccomp cannot read, so it is a hole straight
    // through the clone flag rules; ENOSYS makes glibc fall back to clone, which
    // we CAN filter, where EPERM would break pthread_create.
    p.deny(435 /* clone3 */, 38 /* ENOSYS */);

    // same prctl and personality rules as x86_64; see there.
    p.allow(167 /* prctl */);
    p.allow_arg32_only(167, 0, std::span<const std::uint32_t>{kPrctlAllowed},
                       SysAction::errno_, 1);
    p.allow(92 /* personality */);
    p.allow_arg32_only(92, 0, std::span<const std::uint32_t>{kPersonalityAllowed},
                       SysAction::errno_, 1);

    // outright denials, killed rather than errno'd: nothing legitimate calls
    // these inside a sandbox, so a kill is an unmistakable audit signal.
    for (SysNr nr : {117u /* ptrace */, 40u /* mount */, 39u /* umount2 */,
                     41u /* pivot_root */, 51u /* chroot */, 97u /* unshare */,
                     268u /* setns */, 280u /* bpf */, 241u /* perf_event_open */,
                     105u /* init_module */, 106u /* delete_module */,
                     273u /* finit_module */, 104u /* kexec_load */, 142u /* reboot */,
                     294u /* kexec_file_load */,
                     428u /* open_tree */, 429u /* move_mount */, 430u /* fsopen */,
                     431u /* fsconfig */, 432u /* fsmount */, 433u /* fspick */,
                     442u /* mount_setattr */})
        p.kill(nr);

    // ioctl by allow-list, not deny-list -- see the x86_64 block for why. the
    // request numbers are ARCH-INDEPENDENT (they encode a type/nr/size, not a
    // syscall number), so this is the same table, and it is 32-bit for the same
    // reason: the kernel truncates ioctl's cmd to `unsigned int`.
    static constexpr std::uint32_t kIoctlAllowed[] = {
        0x5401,  // TCGETS
        0x5402,  // TCSETS
        0x5403,  // TCSETSW
        0x5404,  // TCSETSF
        0x5405,  // TCGETA
        0x5409,  // TCSBRK
        0x540A,  // TCXONC
        0x540B,  // TCFLSH
        0x5413,  // TIOCGWINSZ
        0x5414,  // TIOCSWINSZ
        0x540F,  // TIOCGPGRP
        0x5410,  // TIOCSPGRP
        0x5429,  // TIOCGSID
        0x541B,  // FIONREAD
        0x5421,  // FIONBIO
        0x5450,  // FIONCLEX
        0x5451,  // FIOCLEX
        0x5411,  // TIOCOUTQ
    };
    p.allow_arg32_only(29 /* ioctl */, 1 /* request */,
                       std::span<const std::uint32_t>{kIoctlAllowed}, SysAction::errno_, 1);

    // W^X, same as x86_64. PROT_* values are arch-independent.
    static constexpr std::uint64_t kProtWriteExec = 0x2 | 0x4;
    p.deny_arg_all(222 /* mmap */, 2 /* prot */, kProtWriteExec, SysAction::errno_, 1);
    p.deny_arg_all(226 /* mprotect */, 2 /* prot */, kProtWriteExec, SysAction::errno_, 1);

    return p;
}

// CLONE_NEW* are arch-independent (they are kernel flag bits, not syscall
// numbers), so this is the same constant as x86_64 uses.
inline constexpr std::uint64_t kCloneNewNamespaces =
    0x00020000ull |  // CLONE_NEWNS
    0x02000000ull |  // CLONE_NEWCGROUP
    0x04000000ull |  // CLONE_NEWUTS
    0x08000000ull |  // CLONE_NEWIPC
    0x10000000ull |  // CLONE_NEWUSER
    0x20000000ull |  // CLONE_NEWPID
    0x40000000ull;   // CLONE_NEWNET

inline SyscallPolicy& add_processes(SyscallPolicy& p) {
    // no fork or vfork on aarch64: both are clone underneath, and clone is the
    // only number there is.
    for (SysNr nr : {220u /* clone */, 221u /* execve */, 260u /* wait4 */, 129u /* kill */,
                     281u /* execveat */})
        p.allow(nr);
    p.deny_arg_any(220 /* clone */, 0 /* flags */, kCloneNewNamespaces, SysAction::errno_, 1);
    return p;
}

inline SyscallPolicy with_processes() {
    SyscallPolicy p = base();
    add_processes(p);
    return p;
}

// the filesystem set, named once. it was briefly written out twice -- here and
// in compiler_with_network -- which is precisely how a table drifts: one copy
// gets a new syscall and the other silently does not.
inline constexpr SysNr kFsSyscalls[] = {
    46,   // ftruncate
    61,   // getdents64  (there is no `getdents`)
    34,   // mkdirat     (there is no `mkdir`)
    33,   // mknodat     (there is no `mknod`)
    52,   // fchmod
    53,   // fchmodat    (there is no `chmod`)
    54,   // fchownat
    35,   // unlinkat    (no `unlink`, and no `rmdir`)
    38,   // renameat    (there is no `rename`)
    37,   // linkat
    36,   // symlinkat   (there is no `symlink`)
    48,   // faccessat   (there is no `access`)
    88,   // utimensat
    47,   // fallocate
    276,  // renameat2
    291,  // statx
    439,  // faccessat2
    // read-only xattrs (see x86_64)
    8,    // getxattr
    9,    // lgetxattr
    10,   // fgetxattr
    11,   // listxattr
    12,   // llistxattr
    13,   // flistxattr
};

inline SyscallPolicy with_filesystem() {
    SyscallPolicy p = base();
    p.allow(std::span<const SysNr>{kFsSyscalls});
    return p;
}

inline SyscallPolicy compiler() {
    SyscallPolicy p = with_filesystem();
    add_processes(p);
    return p;
}

// see the x86-64 supervisor()
inline SyscallPolicy supervisor() {
    SyscallPolicy p = compiler();
    for (SysNr nr : {117u /* ptrace */, 270u /* process_vm_readv */, 271u /* process_vm_writev */,
                     130u /* tkill */, 138u /* rt_sigqueueinfo */, 240u /* rt_tgsigqueueinfo */,
                     55u /* fchown */, 159u /* setgroups */, 146u /* setuid */, 144u /* setgid */,
                     145u /* setreuid */, 143u /* setregid */, 147u /* setresuid */,
                     149u /* setresgid */, 151u /* setfsuid */, 152u /* setfsgid */, 91u /* capset */,
                     148u /* getresuid */, 150u /* getresgid */})
        p.allow(nr);
    allow_stacked_filter(p, 277 /* seccomp */);
    return p;
}

inline SyscallPolicy with_network() {
    SyscallPolicy p = base();
    static constexpr SysNr kNet[] = {
        198,  // socket
        203,  // connect
        202,  // accept
        206,  // sendto
        207,  // recvfrom
        211,  // sendmsg
        212,  // recvmsg
        210,  // shutdown
        200,  // bind
        201,  // listen
        204,  // getsockname
        205,  // getpeername
        208,  // setsockopt
        209,  // getsockopt
        242,  // accept4
        243,  // recvmmsg
        269,  // sendmmsg
    };
    p.allow(std::span<const SysNr>{kNet});
    return p;
}

inline SyscallPolicy compiler_with_network() {
    SyscallPolicy p = with_network();
    p.allow(std::span<const SysNr>{kFsSyscalls});
    add_processes(p);
    return p;
}

#else

// the profiles are syscall-number tables, so they are arch-specific by nature.
// refuse rather than hand back a table for the wrong architecture.
inline SyscallPolicy base() { return SyscallPolicy::nothing(); }
inline SyscallPolicy with_processes() { return SyscallPolicy::nothing(); }
inline SyscallPolicy with_filesystem() { return SyscallPolicy::nothing(); }
inline SyscallPolicy compiler() { return SyscallPolicy::nothing(); }
inline SyscallPolicy supervisor() { return SyscallPolicy::nothing(); }
inline SyscallPolicy with_network() { return SyscallPolicy::nothing(); }
inline SyscallPolicy compiler_with_network() { return SyscallPolicy::nothing(); }

#endif

}  // namespace clay::CLAY_PROFILES_NAMESPACE

// these are per-inclusion decisions, not global state. leaving them defined
// would mean a second include with a different CLAY_PROFILE_ARCH_* silently kept
// the first one's tables -- the include guard already makes that a trap, and a
// stale macro would make it a confusing one.
#undef CLAY_PROFILES_X86_64
#undef CLAY_PROFILES_AARCH64
#undef CLAY_PROFILES_NAMESPACE
