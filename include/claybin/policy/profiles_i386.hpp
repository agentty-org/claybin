// claybin: syscall profiles for 32-bit (i386) programs on an x86_64 host.
//
// the x86_64 kernel runs i386 programs through a second syscall table, with
// different numbers for the same calls: 37 is kill here and getpid there. a
// filter written for one table is wrong for the other, so the seccomp program
// dispatches on the audit arch and applies THIS policy to i386 calls
// (bpf::compile(native, i386)).
//
// the rule for this file: allow what the x86_64 profile allows, by NAME, and
// nothing else. numbers come from asm/unistd_32.h. tests/x86_audit.sh resolves
// every entry through the kernel headers and fails when the two ABIs disagree,
// so the reasons live in profiles.hpp and are only summarised here; the few
// calls that differ on purpose are listed there and here.
//
// x32 (the third x86 ABI) is never allowed: bpf::compile kills it outright.
#pragma once

#include "claybin/policy/profiles.hpp"   // kPrctlAllowed, kPersonalityAllowed
#include "claybin/policy/syscalls.hpp"

namespace clay::profiles_i386 {

// the bare minimum for a dynamically linked program to start, run and exit.
// same contract as profiles::base(): no execve, so not for spawn().
inline SyscallPolicy base() {
    SyscallPolicy p;
    p.set_default(SysAction::errno_, 1 /* EPERM */);

    static constexpr SysNr kAllowed[] = {
        // memory and descriptors, as in profiles::base()
        3,    // read
        4,    // write
        6,    // close
        108,  // fstat
        197,  // fstat64
        19,   // lseek
        140,  // _llseek
        192,  // mmap2   (prot is checked below; old mmap is not allowed)
        125,  // mprotect
        91,   // munmap
        45,   // brk
        163,  // mremap
        180,  // pread64
        181,  // pwrite64
        145,  // readv
        146,  // writev
        221,  // fcntl64
        55,   // fcntl
        // signals. i386 has the rt_ calls and the old ones; libc uses rt_.
        174,  // rt_sigaction
        175,  // rt_sigprocmask
        173,  // rt_sigreturn
        119,  // sigreturn
        176,  // rt_sigpending
        177,  // rt_sigtimedwait
        421,  // rt_sigtimedwait_time64
        179,  // rt_sigsuspend
        186,  // sigaltstack
        // the caller's own process: ids, limits, scheduling, time
        20,   // getpid
        64,   // getppid
        224,  // gettid
        24,   // getuid
        47,   // getgid
        49,   // geteuid
        50,   // getegid
        199,  // getuid32
        200,  // getgid32
        201,  // geteuid32
        202,  // getegid32
        80,   // getgroups
        205,  // getgroups32
        209,  // getresuid32
        211,  // getresgid32
        184,  // capget
        122,  // uname
        183,  // getcwd
        12,   // chdir
        133,  // fchdir
        85,   // readlink
        76,   // getrlimit
        191,  // ugetrlimit
        340,  // prlimit64
        77,   // getrusage
        43,   // times
        116,  // sysinfo
        158,  // sched_yield
        155,  // sched_getparam
        157,  // sched_getscheduler
        242,  // sched_getaffinity
        318,  // getcpu
        13,   // time
        78,   // gettimeofday
        265,  // clock_gettime
        403,  // clock_gettime64
        266,  // clock_getres
        406,  // clock_getres_time64
        267,  // clock_nanosleep
        407,  // clock_nanosleep_time64
        162,  // nanosleep
        // timers and alarms on the caller's own process
        259,  // timer_create
        260,  // timer_settime
        409,  // timer_settime64
        261,  // timer_gettime
        408,  // timer_gettime64
        262,  // timer_getoverrun
        263,  // timer_delete
        104,  // setitimer
        105,  // getitimer
        27,   // alarm
        29,   // pause
        // process groups and sessions: every shell's job control
        57,   // setpgid
        65,   // getpgrp
        66,   // setsid
        132,  // getpgid
        147,  // getsid
        // threads and TLS. i386 sets its thread pointer with set_thread_area
        // where x86_64 uses arch_prctl.
        240,  // futex
        422,  // futex_time64
        243,  // set_thread_area
        244,  // get_thread_area
        258,  // set_tid_address
        311,  // set_robust_list
        312,  // get_robust_list
        386,  // rseq
        375,  // membarrier
        252,  // exit_group
        1,    // exit
        0,    // restart_syscall
        270,  // tgkill   (abort/assert signal their own thread)
        // waiting for descriptors
        42,   // pipe
        331,  // pipe2
        41,   // dup
        63,   // dup2
        330,  // dup3
        254,  // epoll_create
        329,  // epoll_create1
        255,  // epoll_ctl
        256,  // epoll_wait
        319,  // epoll_pwait
        441,  // epoll_pwait2
        168,  // poll
        309,  // ppoll
        414,  // ppoll_time64
        142,  // _newselect
        82,   // select   (the old pointer-argument form; reads only fd sets)
        308,  // pselect6
        413,  // pselect6_time64
        // private notification objects and memory, as in profiles::base()
        323,  // eventfd
        328,  // eventfd2
        322,  // timerfd_create
        325,  // timerfd_settime
        411,  // timerfd_settime64
        326,  // timerfd_gettime
        410,  // timerfd_gettime64
        356,  // memfd_create
        150,  // mlock
        151,  // munlock
        219,  // madvise
        355,  // getrandom
        436,  // close_range
        // the caller's file creation mask
        60,   // umask
        // AF_UNIX pairs only; the family is checked in add_socket_families()
        360,  // socketpair
        // file watching, signal descriptors, niceness: as profiles::base()
        291,  // inotify_init
        332,  // inotify_init1
        292,  // inotify_add_watch
        293,  // inotify_rm_watch
        321,  // signalfd
        327,  // signalfd4
        96,   // getpriority
    };
    p.allow(std::span<const SysNr>{kAllowed});

    // setpriority on the caller only, as profiles::base()
    static constexpr std::uint32_t kZero[] = {0};
    p.allow(97 /* setpriority */);
    p.allow_arg32_only(97, 0 /* which */, std::span<const std::uint32_t>{kZero},
                       SysAction::errno_, 1);
    p.allow_arg32_only(97, 1 /* who */, std::span<const std::uint32_t>{kZero},
                       SysAction::errno_, 1);

    // the old mmap takes its six arguments through a pointer, so seccomp
    // can't see prot and W^X couldn't hold. ENOSYS: libc uses mmap2.
    p.deny(90 /* mmap */, 38 /* ENOSYS */);
    // clone3 takes a struct pointer, so its flags can't be checked. ENOSYS
    // makes glibc fall back to clone, whose flags we can.
    p.deny(435 /* clone3 */, 38 /* ENOSYS */);

    p.allow(172 /* prctl */);
    p.allow_arg32_only(172, 0, std::span<const std::uint32_t>{profiles::kPrctlAllowed},
                       SysAction::errno_, 1);
    p.allow(136 /* personality */);
    p.allow_arg32_only(136, 0, std::span<const std::uint32_t>{profiles::kPersonalityAllowed},
                       SysAction::errno_, 1);

    // ioctl: the same terminal and descriptor requests as profiles::base().
    // the request is compared as 32 bits, so 0xdeadbeef00005412 can't pass as
    // TIOCSTI either.
    static constexpr std::uint32_t kIoctlAllowed[] = {
        0x5401, 0x5402, 0x5403, 0x5404, 0x5405,   // TCGETS .. TCGETA
        0x5409, 0x540A, 0x540B,                   // TCSBRK, TCXONC, TCFLSH
        0x5413, 0x5414,                           // TIOCGWINSZ, TIOCSWINSZ
        0x540F, 0x5410, 0x5429,                   // TIOCGPGRP, TIOCSPGRP, TIOCGSID
        0x541B, 0x5421, 0x5450, 0x5451, 0x5411,   // FIONREAD .. TIOCOUTQ
    };
    p.allow(54 /* ioctl */);
    p.allow_arg32_only(54 /* ioctl */, 1, std::span<const std::uint32_t>{kIoctlAllowed},
                       SysAction::errno_, 1);

    // W^X, as in profiles::base(): no mapping writable and executable at once.
    for (SysNr nr : {192u /* mmap2 */, 125u /* mprotect */})
        p.deny_arg_all(nr, 2 /* prot */, 0x2u | 0x4u /* PROT_WRITE|PROT_EXEC */,
                       SysAction::errno_, 1);

    // the escape and kernel-interface calls are KILLED, not refused: the same
    // set profiles::base() kills, by name (x86_audit checks). umount is the
    // old i386 spelling of umount2. everything else unlisted is EPERM.
    for (SysNr nr : {26u /* ptrace */, 21u /* mount */, 22u /* umount */, 52u /* umount2 */,
                     217u /* pivot_root */, 61u /* chroot */, 310u /* unshare */,
                     346u /* setns */, 357u /* bpf */, 336u /* perf_event_open */,
                     128u /* init_module */, 129u /* delete_module */,
                     350u /* finit_module */, 283u /* kexec_load */, 88u /* reboot */,
                     428u /* open_tree */, 429u /* move_mount */, 430u /* fsopen */,
                     431u /* fsconfig */, 432u /* fsmount */, 433u /* fspick */,
                     442u /* mount_setattr */})
        p.kill(nr);
    return p;
}

// profiles::with_filesystem(): paths, metadata, durability. landlock and the
// mount tree decide what a path reaches; these only let a program use it.
inline SyscallPolicy with_filesystem() {
    SyscallPolicy p = base();
    static constexpr SysNr kAllowed[] = {
        5,    // open
        295,  // openat
        8,    // creat
        33,   // access
        307,  // faccessat
        439,  // faccessat2
        106,  // stat
        107,  // lstat
        195,  // stat64
        196,  // lstat64
        300,  // fstatat64
        383,  // statx
        99,   // statfs
        100,  // fstatfs
        268,  // statfs64
        269,  // fstatfs64
        141,  // getdents
        220,  // getdents64
        305,  // readlinkat
        92,   // truncate
        193,  // truncate64
        93,   // ftruncate
        194,  // ftruncate64
        38,   // rename
        302,  // renameat
        353,  // renameat2
        39,   // mkdir
        296,  // mkdirat
        40,   // rmdir
        10,   // unlink
        301,  // unlinkat
        9,    // link
        303,  // linkat
        83,   // symlink
        304,  // symlinkat
        14,   // mknod
        297,  // mknodat
        15,   // chmod
        94,   // fchmod
        306,  // fchmodat
        452,  // fchmodat2
        16,   // lchown
        95,   // fchown
        182,  // chown
        212,  // chown32
        207,  // fchown32
        198,  // lchown32
        298,  // fchownat
        30,   // utime
        271,  // utimes
        299,  // futimesat
        320,  // utimensat
        412,  // utimensat_time64
        324,  // fallocate
        118,  // fsync
        148,  // fdatasync
        314,  // sync_file_range
        143,  // flock
        250,  // fadvise64
        272,  // fadvise64_64
        377,  // copy_file_range
        187,  // sendfile
        239,  // sendfile64
        313,  // splice
        315,  // tee
        333,  // preadv
        334,  // pwritev
        378,  // preadv2
        379,  // pwritev2
        144,  // msync
        // read-only xattrs: ls and cp -a probe them per file
        229,  // getxattr
        230,  // lgetxattr
        231,  // fgetxattr
        232,  // listxattr
        233,  // llistxattr
        234,  // flistxattr
    };
    p.allow(std::span<const SysNr>{kAllowed});
    // xattr writes: ENOTSUP, so cp -a and tar treat them as unsupported.
    for (SysNr nr : {226u /* setxattr */, 227u /* lsetxattr */, 228u /* fsetxattr */,
                     235u /* removexattr */, 236u /* lremovexattr */,
                     237u /* fremovexattr */})
        p.deny(nr, 95 /* ENOTSUP */);
    return p;
}

// profiles::add_processes(): subprocesses and threads, but no namespaces.
inline SyscallPolicy& add_processes(SyscallPolicy& p) {
    for (SysNr nr : {120u /* clone */, 2u /* fork */, 190u /* vfork */, 11u /* execve */,
                     358u /* execveat */, 114u /* wait4 */, 7u /* waitpid */,
                     284u /* waitid */, 37u /* kill */})
        p.allow(nr);
    // clone's flags are arg 0 on i386 too. the namespace bits, from
    // linux/sched.h, as profiles::kCloneNewNamespaces.
    constexpr std::uint64_t kNewNamespaces = 0x00020000ull | 0x02000000ull | 0x04000000ull |
                                             0x08000000ull | 0x10000000ull | 0x20000000ull |
                                             0x40000000ull;
    p.deny_arg_any(120 /* clone */, 0 /* flags */, kNewNamespaces, SysAction::errno_, 1);
    return p;
}

// a build/compile sandbox: files plus subprocesses, no network.
inline SyscallPolicy compiler() {
    SyscallPolicy p = with_filesystem();
    add_processes(p);
    return p;
}

// the direct i386 socket calls. socketcall, the old multiplexer, takes its
// arguments through a pointer, so the address family couldn't be checked;
// ENOSYS sends libc to the direct calls.
inline SyscallPolicy& add_network(SyscallPolicy& p) {
    p.deny(102 /* socketcall */, 38 /* ENOSYS */);
    for (SysNr nr : {359u /* socket */, 362u /* connect */, 364u /* accept4 */,
                     369u /* sendto */, 371u /* recvfrom */, 370u /* sendmsg */,
                     372u /* recvmsg */, 373u /* shutdown */, 361u /* bind */,
                     363u /* listen */, 367u /* getsockname */, 368u /* getpeername */,
                     366u /* setsockopt */, 365u /* getsockopt */, 337u /* recvmmsg */,
                     417u /* recvmmsg_time64 */, 345u /* sendmmsg */})
        p.allow(nr);
    return p;
}

inline SyscallPolicy compiler_with_network() {
    SyscallPolicy p = compiler();
    add_network(p);
    return p;
}

// socket()/socketpair() only for the families real tools use, as the host's
// native rule. agentty applies this; a bare policy leaves it to the caller.
inline SyscallPolicy& add_socket_families(SyscallPolicy& p) {
    static constexpr std::uint32_t kFamilies[] = {1 /* AF_UNIX */, 2 /* AF_INET */,
                                                  10 /* AF_INET6 */};
    for (SysNr nr : {359u /* socket */, 360u /* socketpair */})
        p.allow_arg32_only(nr, 0 /* family */, std::span<const std::uint32_t>{kFamilies},
                           SysAction::errno_, 97 /* EAFNOSUPPORT */);
    return p;
}

}  // namespace clay::profiles_i386
