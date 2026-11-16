// Keep asm/unistd_32.h isolated from syscall_table_test's native SYS_* macros.
#pragma once
#include "harness.hpp"
#include "claybin/policy/profiles_i386.hpp"

#if defined(__linux__) && defined(__x86_64__) && __has_include(<asm/unistd_32.h>)
#include <asm/unistd_32.h>
namespace clay::test {
inline void check_i386_table() {
    struct Entry { SysNr nr; SysNr kernel; };
#define I386(name, nr) Entry{nr, __NR_##name}
    // Independent names resolve through the host kernel's real i386 table.
    // Includes every syscall literal in all three profiles, including denies
    // and argument rules. The coverage walk below rejects unreviewed additions.
    const Entry expected[] = {
        I386(restart_syscall,0), I386(exit,1), I386(fork,2), I386(read,3),
        I386(write,4), I386(open,5), I386(close,6), I386(creat,8), I386(link,9),
        I386(unlink,10), I386(execve,11), I386(chdir,12), I386(time,13),
        I386(mknod,14), I386(chmod,15), I386(lchown,16), I386(lseek,19),
        I386(getpid,20), I386(mount,21), I386(getuid,24), I386(ptrace,26),
        I386(alarm,27), I386(pause,29), I386(access,33), I386(rename,38),
        I386(mkdir,39), I386(rmdir,40), I386(dup,41), I386(pipe,42),
        I386(times,43), I386(brk,45), I386(getgid,47), I386(geteuid,49),
        I386(getegid,50), I386(umount2,52), I386(ioctl,54), I386(fcntl,55),
        I386(setpgid,57), I386(umask,60), I386(chroot,61), I386(dup2,63),
        I386(getppid,64), I386(getpgrp,65), I386(setsid,66),
        I386(getrusage,77), I386(gettimeofday,78), I386(symlink,83),
        I386(readlink,85), I386(mmap,90), I386(munmap,91), I386(truncate,92),
        I386(ftruncate,93), I386(fchmod,94), I386(fchown,95),
        I386(statfs,99), I386(fstatfs,100), I386(ioperm,101), I386(socketcall,102),
        I386(setitimer,104), I386(getitimer,105), I386(stat,106),
        I386(lstat,107), I386(fstat,108), I386(iopl,110), I386(wait4,114),
        I386(sysinfo,116), I386(fsync,118), I386(sigreturn,119), I386(clone,120),
        I386(uname,122), I386(mprotect,125), I386(init_module,128),
        I386(delete_module,129), I386(getpgid,132), I386(fchdir,133),
        I386(personality,136), I386(_llseek,140), I386(getdents,141),
        I386(_newselect,142), I386(readv,145), I386(writev,146), I386(getsid,147),
        I386(fdatasync,148), I386(sched_yield,158), I386(nanosleep,162),
        I386(mremap,163), I386(poll,168), I386(prctl,172), I386(rt_sigreturn,173),
        I386(rt_sigaction,174), I386(rt_sigprocmask,175), I386(rt_sigpending,176),
        I386(rt_sigtimedwait,177), I386(rt_sigsuspend,179), I386(capget,184),
        I386(pread64,180), I386(pwrite64,181), I386(getcwd,183),
        I386(sigaltstack,186), I386(sendfile,187), I386(vfork,190),
        I386(ugetrlimit,191), I386(mmap2,192), I386(truncate64,193),
        I386(ftruncate64,194), I386(stat64,195), I386(lstat64,196), I386(fstat64,197),
        I386(getuid32,199), I386(getgid32,200), I386(geteuid32,201),
        I386(getegid32,202), I386(pivot_root,217), I386(mincore,218),
        I386(madvise,219), I386(getdents64,220), I386(fcntl64,221), I386(gettid,224),
        I386(getxattr,229), I386(lgetxattr,230), I386(fgetxattr,231),
        I386(listxattr,232), I386(llistxattr,233), I386(flistxattr,234),
        I386(sendfile64,239), I386(futex,240), I386(sched_getaffinity,242),
        I386(set_thread_area,243), I386(get_thread_area,244), I386(fadvise64,250),
        I386(exit_group,252), I386(epoll_create,254), I386(epoll_ctl,255),
        I386(epoll_wait,256), I386(set_tid_address,258), I386(clock_gettime,265),
        I386(clock_getres,266), I386(clock_nanosleep,267), I386(statfs64,268),
        I386(fstatfs64,269), I386(utimes,271), I386(fadvise64_64,272),
        I386(kexec_load,283), I386(waitid,284), I386(add_key,286),
        I386(request_key,287), I386(keyctl,288), I386(openat,295),
        I386(mkdirat,296), I386(mknodat,297), I386(fchownat,298),
        I386(futimesat,299), I386(fstatat64,300), I386(unlinkat,301),
        I386(renameat,302), I386(linkat,303), I386(symlinkat,304),
        I386(readlinkat,305), I386(fchmodat,306), I386(faccessat,307),
        I386(pselect6,308), I386(ppoll,309), I386(unshare,310),
        I386(set_robust_list,311), I386(get_robust_list,312), I386(epoll_pwait,319),
        I386(fallocate,324), I386(eventfd2,328), I386(epoll_create1,329),
        I386(dup3,330), I386(pipe2,331), I386(preadv,333), I386(pwritev,334),
        I386(perf_event_open,336), I386(recvmmsg,337), I386(prlimit64,340),
        I386(sendmmsg,345), I386(setns,346), I386(finit_module,350),
        I386(renameat2,353), I386(getrandom,355), I386(bpf,357), I386(execveat,358),
        I386(socket,359), I386(socketpair,360), I386(bind,361), I386(connect,362),
        I386(listen,363), I386(accept4,364), I386(getsockopt,365),
        I386(setsockopt,366), I386(getsockname,367), I386(getpeername,368),
        I386(sendto,369), I386(sendmsg,370), I386(recvfrom,371), I386(recvmsg,372),
        I386(shutdown,373), I386(userfaultfd,374), I386(membarrier,375),
        I386(preadv2,378), I386(pwritev2,379), I386(pkey_mprotect,380),
        I386(pkey_alloc,381), I386(pkey_free,382), I386(statx,383), I386(rseq,386),
        I386(clock_gettime64,403), I386(clock_getres_time64,406),
        I386(clock_nanosleep_time64,407), I386(pselect6_time64,413),
        I386(ppoll_time64,414), I386(recvmmsg_time64,417), I386(futex_time64,422),
        I386(io_uring_setup,425), I386(io_uring_enter,426), I386(io_uring_register,427),
        I386(open_tree,428), I386(move_mount,429), I386(fsopen,430),
        I386(fsconfig,431), I386(fsmount,432), I386(fspick,433), I386(clone3,435),
        I386(close_range,436), I386(faccessat2,439), I386(mount_setattr,442),
    };
#undef I386
    for (auto e : expected) CHECK_EQ(e.nr, e.kernel);
    const auto reviewed = [&](SysNr nr) {
        for (auto e : expected) if (e.nr == nr) return true;
        std::fprintf(stderr, "unreviewed i386 syscall number: %u\n", nr);
        return false;
    };
    for (const auto& p : {profiles_i386::base(), profiles_i386::compiler(),
                          profiles_i386::compiler_with_network()}) {
        for (const auto& r : p.rules()) CHECK(reviewed(r.nr));
        for (const auto& r : p.arg_rules()) CHECK(reviewed(r.nr));
        for (const auto& r : p.arg_allow_sets()) CHECK(reviewed(r.nr));
    }
}
} // namespace clay::test
#else
namespace clay::test {
inline void check_i386_table() {
    std::fprintf(stderr, "skip i386 kernel table: asm/unistd_32.h unavailable\n");
}
}
#endif
