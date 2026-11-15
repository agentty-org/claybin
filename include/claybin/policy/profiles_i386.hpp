// Native Linux i386 syscall profiles. Numbers from Linux asm/unistd_32.h.
// Deliberately independent of the build host and of the x86_64 syscall table.
#pragma once
#include "claybin/policy/syscalls.hpp"

namespace clay::profiles_i386 {
inline SyscallPolicy base() {
    SyscallPolicy p;
    p.set_default(SysAction::errno_, 1);
    static constexpr SysNr calls[] = {
        0, 1, // restart_syscall,exit
        3, 4, 6, // read, write, close
        19, 140, // lseek, _llseek
        20, 24, 47, 49, 50, 64, // pid/uid/gid/euid/egid/ppid
        199, 200, 201, 202, // 32-bit uid/gid variants
        33,  // access
        43,  // times
        45,  // brk
        54, 55, 221, // ioctl, fcntl, fcntl64
        77, 78, // getrusage,gettimeofday
        91, 125, 163, 192, 218, 219, // munmap,mprotect,mremap,mmap2,mincore,madvise
        106, 107, 108, 195, 196, 197, // stat/lstat/fstat and stat64 variants
        119, 173, 174, 175, 176, 177, 179, 186, // signal handling
        122,  // uname
        158, 162, // sched_yield,nanosleep
        180, 181, 183, // pread64,pwrite64,getcwd
        184, // capget
        191, // ugetrlimit
        224, 240, 242, 243, 244, // gettid,futex,affinity,set/get_thread_area
        252, 258, // exit_group,set_tid_address
        265, 266, 267, // clock_gettime/getres/nanosleep
        311, 312, // set/get_robust_list
        42,41,63,330,331, // pipe,dup,dup2,dup3,pipe2
        254,329,256,319,255, // epoll_create/create1/wait/pwait/ctl
        142,168,309,308, // _newselect,poll,ppoll,pselect6
        340,116,99,100, // prlimit64,sysinfo,statfs,fstatfs
        414,413, // ppoll_time64,pselect6_time64
        355,  // getrandom
        375, 380, 381, 382, // membarrier,pkey_mprotect/alloc/free
        386, // rseq
        403, 406, 407, 422, // clock_gettime64/getres64/nanosleep64,futex_time64
        436, // close_range
    };
    p.allow(std::span<const SysNr>{calls});
    // The old mmap takes a pointer: seccomp cannot inspect its prot field.
    p.deny(90, 38);
    p.deny(435, 38); // clone3: force inspectable clone fallback
    for (SysNr nr : {192u, 125u, 380u})
        p.deny_arg_all(nr, 2, 6, SysAction::errno_, 1);
    static constexpr std::uint32_t prctl[] = {
        1,2,3,4,15,16,21,23,27,29,30,36,37,38,39,40,41,42,0x53564d41};
    p.allow(172);
    p.allow_arg32_only(172, 0, std::span<const std::uint32_t>{prctl}, SysAction::errno_, 1);
    static constexpr std::uint32_t personality[] = {0, 0xffffffffu};
    p.allow(136);
    p.allow_arg32_only(136, 0, std::span<const std::uint32_t>{personality}, SysAction::errno_, 1);
    static constexpr std::uint32_t ioctl[] = {
        0x5401,0x5402,0x5403,0x5404,0x5405,0x5409,0x540a,0x540b,
        0x5413,0x5414,0x540f,0x5410,0x541b,0x5421,0x5450,0x5451,0x5411};
    p.allow_arg32_only(54, 1, std::span<const std::uint32_t>{ioctl}, SysAction::errno_, 1);
    for (SysNr nr : {26u /* ptrace */, 21u /* mount */, 52u /* umount2 */,
                     217u /* pivot_root */, 61u /* chroot */, 310u /* unshare */,
                     346u /* setns */, 357u /* bpf */, 336u /* perf_event_open */,
                     128u,129u,350u /* modules */, 283u, /* kexec_load */
                     101u,110u, /* ioperm,iopl */ 286u,287u,288u, /* keyring */
                     374u /* userfaultfd */, 425u,426u,427u /* io_uring */,
                     428u,429u,430u,431u,432u,433u,442u /* mount APIs */})
        p.kill(nr);
    return p;
}

inline SyscallPolicy compiler() {
    auto p = base();
    static constexpr SysNr calls[] = {
        2, 11, 114, 120, 190, 284, // fork,execve,wait4,clone,vfork,waitid
        5,8,9,10,12,14,15,16,38,39,40,41,42,60,63,83,85,92,93,94,95,
        118,133,141,145,146,148,193,194,220,229,230,231,232,233,234,
        239,250,254,255,256,268,269,271,272,295,296,297,298,299,300,
        301,302,303,304,305,306,307,308,309,319,324,328,329,330,331,
        333,334,340,353,358,378,379,383,439,
        116,99,100,168,142, // sysinfo,statfs,fstatfs,poll,_newselect
        187, // sendfile
        414,413, // ppoll_time64,pselect6_time64
    };
    p.allow(std::span<const SysNr>{calls});
    // No process profile grants keyring access.
    p.deny_arg_any(120, 0, 0x00020000ull | 0x02000000ull | 0x04000000ull |
                  0x08000000ull | 0x10000000ull | 0x20000000ull | 0x40000000ull,
                  SysAction::errno_, 1);
    // kill/tkill/pidfd_send_signal remain EPERM; no compatibility notify broker.
    return p;
}

inline SyscallPolicy compiler_with_network() {
    auto p = compiler();
    // socketcall multiplexes only socket operations. Network authority remains
    // enforced by the same namespace/Landlock boundaries as the native profile.
    p.allow(102);
    static constexpr SysNr calls[] = {
        345,337, // sendmmsg,recvmmsg
        359,360,361,362,363,364,365,366,367,368,369,370,371,372,373,
        417, // recvmmsg_time64
    };
    p.allow(std::span<const SysNr>{calls});
    return p;
}
} // namespace clay::profiles_i386
