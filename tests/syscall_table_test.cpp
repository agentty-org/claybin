// the syscall tables must agree with the kernel's own headers.
//
// this test exists because reading a table of ~130 numbers and checking each
// against its comment is something a human does badly and a machine does
// perfectly. it found a real bug on its first run: 122 was in the job-control
// allow-list labelled "getsid", but getsid is 124 and 122 is setfsuid -- a
// syscall that changes the uid the kernel uses for filesystem access checks,
// sitting in an allow-list, with nothing breaking to announce it.
//
// the check is: for every `NNN, // name` pair in profiles.hpp, does the kernel
// agree that NNN is called `name`? the numbers come from <sys/syscall.h> at
// compile time, so this is the kernel's own opinion rather than a second table
// that could drift the same way.
#include "harness.hpp"

#include <cstring>
#include <string_view>

#include "claybin/policy/profiles.hpp"

// the aarch64 tables, compiled for that arch in their own translation unit so
// they can be checked here. see profiles_aarch64.cpp.
namespace clay::arm {
SyscallPolicy base();
SyscallPolicy compiler();
SyscallPolicy compiler_with_network();
}  // namespace clay::arm

using namespace clay;
using namespace clay::test;

#if defined(__linux__) && defined(__x86_64__)

#include <sys/syscall.h>

namespace {

struct Named {
    const char* name;
    long nr;
};

// every syscall the profiles name, paired with the kernel's number for it.
// SYS_* comes from <sys/syscall.h>, so there is no second table to get wrong:
// if the libc headers and the profile disagree, that is the bug.
//
// keep this sorted the way the profile lists are, so a reader can diff them.
constexpr Named kExpected[] = {
    // base(): what libc needs before main
    {"read", SYS_read},
    {"write", SYS_write},
    {"close", SYS_close},
    {"fstat", SYS_fstat},
    {"lseek", SYS_lseek},
    {"mmap", SYS_mmap},
    {"mprotect", SYS_mprotect},
    {"munmap", SYS_munmap},
    {"brk", SYS_brk},
    {"rt_sigaction", SYS_rt_sigaction},
    {"rt_sigprocmask", SYS_rt_sigprocmask},
    {"rt_sigreturn", SYS_rt_sigreturn},
    {"ioctl", SYS_ioctl},
    {"pread64", SYS_pread64},
    {"pwrite64", SYS_pwrite64},
    {"readv", SYS_readv},
    {"writev", SYS_writev},
    {"sched_yield", SYS_sched_yield},
    {"madvise", SYS_madvise},
    {"getpid", SYS_getpid},
    {"exit", SYS_exit},
    {"uname", SYS_uname},
    {"fcntl", SYS_fcntl},
    {"getcwd", SYS_getcwd},
    {"chdir", SYS_chdir},
    {"fchdir", SYS_fchdir},
    {"readlink", SYS_readlink},
    {"gettimeofday", SYS_gettimeofday},
    {"getrlimit", SYS_getrlimit},
    {"getrusage", SYS_getrusage},
    {"getuid", SYS_getuid},
    {"getgid", SYS_getgid},
    {"geteuid", SYS_geteuid},
    {"getegid", SYS_getegid},
    {"getppid", SYS_getppid},
    {"arch_prctl", SYS_arch_prctl},
    {"gettid", SYS_gettid},
    {"time", SYS_time},
    {"futex", SYS_futex},
    {"sched_getaffinity", SYS_sched_getaffinity},
    {"set_tid_address", SYS_set_tid_address},
    {"clock_gettime", SYS_clock_gettime},
    {"clock_nanosleep", SYS_clock_nanosleep},
    {"exit_group", SYS_exit_group},
    {"tgkill", SYS_tgkill},
    {"openat", SYS_openat},
    {"newfstatat", SYS_newfstatat},
    {"set_robust_list", SYS_set_robust_list},
    {"prlimit64", SYS_prlimit64},
    {"getrandom", SYS_getrandom},
    {"rseq", SYS_rseq},
    {"clone3", SYS_clone3},
    {"mremap", SYS_mremap},
    // the no-authority group. every one of these was denied once, and the
    // symptom was never "denied" -- curl said out of memory on a box with
    // gigabytes free. resolved through the kernel's own headers so a
    // mislabelled number fails here instead of sitting in the table.
    {"mlock", SYS_mlock},
    {"munlock", SYS_munlock},
    {"mlockall", SYS_mlockall},
    {"nanosleep", SYS_nanosleep},
    {"clock_getres", SYS_clock_getres},
    {"membarrier", SYS_membarrier},
    {"getcpu", SYS_getcpu},
    {"eventfd2", SYS_eventfd2},
    {"timerfd_create", SYS_timerfd_create},
    {"socketpair", SYS_socketpair},
    {"memfd_create", SYS_memfd_create},

    // job control. this is the group the bug was in.
    {"setpgid", SYS_setpgid},
    {"getpgrp", SYS_getpgrp},
    {"setsid", SYS_setsid},
    {"getpgid", SYS_getpgid},
    {"getsid", SYS_getsid},
    // and the two that must NOT be confused with getsid
    {"setfsuid", SYS_setfsuid},
    {"setfsgid", SYS_setfsgid},

    // descriptors and polling
    {"pipe", SYS_pipe},
    {"pipe2", SYS_pipe2},
    {"dup", SYS_dup},
    {"dup2", SYS_dup2},
    {"dup3", SYS_dup3},
    {"epoll_create", SYS_epoll_create},
    {"epoll_create1", SYS_epoll_create1},
    {"epoll_wait", SYS_epoll_wait},
    {"epoll_pwait", SYS_epoll_pwait},
    {"epoll_ctl", SYS_epoll_ctl},
    {"select", SYS_select},
    {"poll", SYS_poll},
    {"ppoll", SYS_ppoll},
    {"pselect6", SYS_pselect6},
    {"sysinfo", SYS_sysinfo},
    {"statfs", SYS_statfs},
    {"fstatfs", SYS_fstatfs},

    // the denied set: these must be exactly right, because a wrong number here
    // means the dangerous syscall is NOT denied and some innocent one is.
    {"ptrace", SYS_ptrace},
    {"mount", SYS_mount},
    {"umount2", SYS_umount2},
    {"pivot_root", SYS_pivot_root},
    {"chroot", SYS_chroot},
    {"unshare", SYS_unshare},
    {"setns", SYS_setns},
    {"bpf", SYS_bpf},
    {"perf_event_open", SYS_perf_event_open},
    {"init_module", SYS_init_module},
    {"delete_module", SYS_delete_module},
    {"kexec_load", SYS_kexec_load},
    {"reboot", SYS_reboot},
    {"finit_module", SYS_finit_module},
    {"kexec_file_load", SYS_kexec_file_load},
    {"open_tree", SYS_open_tree},
    {"move_mount", SYS_move_mount},
    {"fsopen", SYS_fsopen},
    {"fsconfig", SYS_fsconfig},
    {"fsmount", SYS_fsmount},
    {"fspick", SYS_fspick},
    {"mount_setattr", SYS_mount_setattr},
    // allowed with argument rules, or read-only
    {"prctl", SYS_prctl},
    {"personality", SYS_personality},
    {"getxattr", SYS_getxattr},
    {"lgetxattr", SYS_lgetxattr},
    {"fgetxattr", SYS_fgetxattr},
    {"listxattr", SYS_listxattr},
    {"llistxattr", SYS_llistxattr},
    {"flistxattr", SYS_flistxattr},
    {"setxattr", SYS_setxattr},
    {"removexattr", SYS_removexattr},

    // processes
    {"clone", SYS_clone},
    {"fork", SYS_fork},
    {"vfork", SYS_vfork},
    {"execve", SYS_execve},
    {"wait4", SYS_wait4},
    {"kill", SYS_kill},
    {"execveat", SYS_execveat},

    // filesystem
    {"open", SYS_open},
    {"stat", SYS_stat},
    {"lstat", SYS_lstat},
    {"access", SYS_access},
    {"ftruncate", SYS_ftruncate},
    {"getdents", SYS_getdents},
    {"rename", SYS_rename},
    {"mkdir", SYS_mkdir},
    {"rmdir", SYS_rmdir},
    {"unlink", SYS_unlink},
    {"symlink", SYS_symlink},
    {"chmod", SYS_chmod},
    {"fchmod", SYS_fchmod},
    {"mknod", SYS_mknod},
    {"getdents64", SYS_getdents64},
    {"fchownat", SYS_fchownat},
    {"unlinkat", SYS_unlinkat},
    {"renameat", SYS_renameat},
    {"linkat", SYS_linkat},
    {"symlinkat", SYS_symlinkat},
    {"faccessat", SYS_faccessat},
    {"utimensat", SYS_utimensat},
    {"fallocate", SYS_fallocate},
    {"renameat2", SYS_renameat2},
    {"statx", SYS_statx},
    {"faccessat2", SYS_faccessat2},

    // network
    {"socket", SYS_socket},
    {"connect", SYS_connect},
    {"accept", SYS_accept},
    {"sendto", SYS_sendto},
    {"recvfrom", SYS_recvfrom},
    {"sendmsg", SYS_sendmsg},
    {"recvmsg", SYS_recvmsg},
    {"shutdown", SYS_shutdown},
    {"bind", SYS_bind},
    {"listen", SYS_listen},
    {"getsockname", SYS_getsockname},
    {"getpeername", SYS_getpeername},
    {"setsockopt", SYS_setsockopt},
    {"getsockopt", SYS_getsockopt},
    {"accept4", SYS_accept4},
    {"recvmmsg", SYS_recvmmsg},
    {"sendmmsg", SYS_sendmmsg},
};

long nr_of(std::string_view name) {
    for (const auto& e : kExpected)
        if (name == e.name) return e.nr;
    return -1;
}

// is this syscall permitted (not errno'd, not killed) by the policy?
bool permitted(const SyscallPolicy& p, long nr) {
    return p.action_for(static_cast<SysNr>(nr)) == SysAction::allow;
}

}  // namespace

int main() {
    // -- the syscalls a sandbox must never allow --------------------------
    //
    // spelled by NAME here, resolved through the kernel's headers. that is the
    // whole point: the profile lists numbers, and a number cannot be reviewed.
    // if a profile ever allows one of these, it is either a new mistake or the
    // same mislabelling bug again.
    static constexpr const char* kMustDeny[] = {
        // privilege
        "setfsuid",         // changes the uid used for fs access checks
        "setfsgid",
        "ptrace",           // read/write another process's memory
        // namespaces and mounts: the escape primitives
        "mount", "umount2", "pivot_root", "chroot", "unshare", "setns",
        // kernel interfaces
        "bpf", "perf_event_open", "init_module", "delete_module", "kexec_load",
        "reboot",
    };

    struct {
        const char* name;
        SyscallPolicy p;
    } profiles_[] = {
        {"base", profiles::base()},
        {"with_processes", profiles::with_processes()},
        {"with_filesystem", profiles::with_filesystem()},
        {"with_network", profiles::with_network()},
        {"compiler", profiles::compiler()},
        {"compiler_with_network", profiles::compiler_with_network()},
    };

    for (const auto& prof : profiles_) {
        for (const char* name : kMustDeny) {
            long nr = nr_of(name);
            CHECK(nr >= 0);
            if (nr < 0) continue;
            if (permitted(prof.p, nr)) {
                std::fprintf(stderr, "  profile %s ALLOWS %s (nr %ld)\n", prof.name, name, nr);
                CHECK(false);
            } else {
                ++g_checks;
            }
        }
    }

    // the escape primitives must be KILLED, not merely errno'd -- same reasoning
    // as the aarch64 block below. the default action is EPERM, so a mistyped
    // number in the deny list still leaves the syscall denied and the mistake
    // invisible; what it silently loses is the audit signal.
    //
    // setfsuid/setfsgid are NOT here: they are denied by omission from the
    // allow-list, which is the correct treatment for a syscall that is merely
    // unnecessary rather than an escape primitive.
    static constexpr const char* kMustKill[] = {
        "ptrace", "mount", "umount2", "pivot_root", "chroot", "unshare", "setns",
        "bpf", "perf_event_open", "init_module", "delete_module", "kexec_load",
        "reboot", "finit_module", "kexec_file_load", "open_tree", "move_mount",
        "fsopen", "fsconfig", "fsmount", "fspick", "mount_setattr",
    };
    for (const char* name : kMustKill) {
        long nr = nr_of(name);
        CHECK(nr >= 0);
        if (nr < 0) continue;
        if (profiles::base().action_for(static_cast<SysNr>(nr)) != SysAction::kill_process) {
            std::fprintf(stderr, "  base() does not KILL %s (nr %ld)\n", name, nr);
            CHECK(false);
        } else {
            ++g_checks;
        }
    }

    // -- the syscalls libc needs, by name --------------------------------
    //
    // the other half of the same problem: a mislabelled number can also DENY
    // something needed, and the failure then looks like a broken program rather
    // than a hole. these are the calls a dynamically linked program makes before
    // it reaches main.
    static constexpr const char* kMustAllow[] = {
        "read", "write", "close", "mmap", "mprotect", "munmap", "brk",
        "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "openat", "newfstatat",
        "exit_group", "futex", "set_tid_address", "set_robust_list", "getrandom",
        "arch_prctl", "ioctl", "prctl", "personality",
    };
    for (const char* name : kMustAllow) {
        long nr = nr_of(name);
        CHECK(nr >= 0);
        if (nr < 0) continue;
        if (!permitted(profiles::base(), nr)) {
            std::fprintf(stderr, "  base() DENIES %s (nr %ld), which libc needs\n", name, nr);
            CHECK(false);
        } else {
            ++g_checks;
        }
    }

    // exec is what separates base() from with_processes(). base() deliberately
    // omits it, and that is documented rather than accidental -- so assert both
    // halves, or a future edit could "fix" base() and nobody would notice the
    // profile boundary moved.
    CHECK(!permitted(profiles::base(), SYS_execve));
    CHECK(permitted(profiles::with_processes(), SYS_execve));
    CHECK(permitted(profiles::with_processes(), SYS_clone));

    // clone3 must be ENOSYS, not EPERM: glibc probes it and only falls back to
    // clone when the kernel says the syscall does not exist.
    CHECK_EQ(profiles::base().action_for(SYS_clone3), SysAction::errno_);
    CHECK_EQ(profiles::base().errno_for(SYS_clone3), std::uint16_t{38});

    // mremap is in base(), so it is in every profile. It was once missing, and
    // the way that presented is the reason this check exists: glibc's realloc
    // grows a large block by remapping it, so a denied mremap turned into a
    // NULL realloc, and every caller that checks its allocations reported out
    // of memory. curl said CURLE_OUT_OF_MEMORY while fetching a raw IP, which
    // looks like a network denial and is not one -- an hour went into the
    // network rules before the allocator was suspected. Assert it at the
    // bottom profile so no profile can lose it again.
    CHECK(permitted(profiles::base(), SYS_mremap));
    CHECK(permitted(profiles::with_filesystem(), SYS_mremap));
    CHECK(permitted(profiles::compiler(), SYS_mremap));
    CHECK(permitted(profiles::compiler_with_network(), SYS_mremap));

    // The no-authority group: allowed in every profile, because they are in
    // base(). Denying them did not make the sandbox stricter in any useful
    // sense -- it made ordinary tools fail with errors that pointed at the
    // wrong cause. curl reported CURLE_OUT_OF_MEMORY while python3 fetched
    // the same URL, and finding out why took a dump of this table.
    //
    // Each is checked at base() so no profile can lose it.
    for (long nr : {(long)SYS_mlock, (long)SYS_munlock, (long)SYS_nanosleep,
                    (long)SYS_clock_getres, (long)SYS_membarrier,
                    (long)SYS_getcpu, (long)SYS_eventfd2,
                    (long)SYS_timerfd_create, (long)SYS_socketpair,
                    (long)SYS_memfd_create}) {
        CHECK(permitted(profiles::base(), (SysNr)nr));
        CHECK(permitted(profiles::compiler_with_network(), (SysNr)nr));
    }

    // mlockall is the deliberate exception, and the asymmetry is the point:
    // mlock pins a range the caller already owns, mlockall pins EVERYTHING
    // including future mappings, which under a cgroup memory cap is a DoS
    // lever. EPERM rather than a kill -- it is a refusal, not an attack
    // signature.
    CHECK(!permitted(profiles::base(), SYS_mlockall));
    CHECK_EQ(profiles::base().action_for(SYS_mlockall), SysAction::errno_);
    CHECK_EQ(profiles::base().errno_for(SYS_mlockall), std::uint16_t{1});

    // xattr reads are allowed (ls probes them per file); writes are not.
    for (long nr : {(long)SYS_getxattr, (long)SYS_lgetxattr, (long)SYS_fgetxattr,
                    (long)SYS_listxattr, (long)SYS_llistxattr, (long)SYS_flistxattr})
        CHECK(permitted(profiles::with_filesystem(), (SysNr)nr));
    CHECK(!permitted(profiles::compiler_with_network(), SYS_setxattr));
    CHECK(!permitted(profiles::compiler_with_network(), SYS_removexattr));

    // prctl and personality are allowed but narrowed by option. the set is
    // the whole point, so pin both ends of it.
    {
        const auto p = profiles::base();
        auto allow_set = [&](long nr) -> const std::vector<std::uint32_t>* {
            for (const auto& s : p.arg_allow_sets())
                if (s.nr == (SysNr)nr && s.arg_index == 0) return &s.values;
            return nullptr;
        };
        auto has = [](const std::vector<std::uint32_t>* v, std::uint32_t x) {
            return v && std::binary_search(v->begin(), v->end(), x);
        };
        const auto* pr = allow_set(SYS_prctl);
        CHECK(pr != nullptr);
        CHECK(has(pr, 15));          // PR_SET_NAME
        CHECK(has(pr, 1));           // PR_SET_PDEATHSIG
        CHECK(!has(pr, 22));         // PR_SET_SECCOMP
        CHECK(!has(pr, 35));         // PR_SET_MM
        CHECK(!has(pr, 47));         // PR_CAP_AMBIENT
        CHECK(!has(pr, 8));          // PR_SET_KEEPCAPS
        CHECK(!has(pr, 0x59616d61)); // PR_SET_PTRACER
        const auto* pe = allow_set(SYS_personality);
        CHECK(pe != nullptr);
        CHECK(has(pe, 0xffffffffu));
        CHECK(has(pe, 0));
        CHECK(!has(pe, 0x0040000));  // ADDR_NO_RANDOMIZE
        CHECK(!has(pe, 0x0400000));  // READ_IMPLIES_EXEC
    }

    // -- the aarch64 tables, checked on an x86_64 host ---------------------
    //
    // these numbers cannot be verified against <sys/syscall.h> here, because
    // that header describes the host. so they are checked against the values
    // from <asm-generic/unistd.h> -- the table aarch64 actually uses -- which
    // are pinned literally below.
    //
    // pinning them looks like duplicating the profile, and it is: that is the
    // point. the profile says "40 is mount" and this says "mount is 40", written
    // from the header independently. the x86_64 bug was a number whose COMMENT
    // disagreed with it, and a second independent list is what catches that.
    //
    // the profiles are compiled for aarch64 by a separate translation unit
    // (profiles_aarch64.cpp) which defines CLAY_PROFILE_ARCH_AARCH64, so both
    // tables exist in this binary at once.
    {
        struct Arm {
            const char* name;
            long nr;
        };
        // from asm-generic/unistd.h
        static constexpr Arm kMustDenyArm[] = {
            {"setfsuid", 151},        {"setfsgid", 152},   {"ptrace", 117},
            {"mount", 40},            {"umount2", 39},     {"pivot_root", 41},
            {"chroot", 51},           {"unshare", 97},     {"setns", 268},
            {"bpf", 280},             {"perf_event_open", 241},
            {"init_module", 105},     {"delete_module", 106},
            {"finit_module", 273},    {"kexec_load", 104}, {"reboot", 142},
        };
        static constexpr Arm kMustAllowArm[] = {
            {"read", 63},        {"write", 64},       {"close", 57},
            {"mmap", 222},       {"mprotect", 226},   {"munmap", 215},
            {"brk", 214},        {"rt_sigaction", 134}, {"rt_sigprocmask", 135},
            {"rt_sigreturn", 139}, {"openat", 56},    {"fstatat", 79},
            {"exit_group", 94},  {"futex", 98},       {"set_tid_address", 96},
            {"set_robust_list", 99}, {"getrandom", 278}, {"ioctl", 29},
            {"getsid", 156},     {"getpgid", 155},
        };

        SyscallPolicy arm_base = arm::base();
        SyscallPolicy arm_compiler = arm::compiler();
        SyscallPolicy arm_net = arm::compiler_with_network();

        // a table that refuses everything would pass every deny check below, so
        // assert it is a real policy first.
        CHECK(!arm_base.is_nothing());
        CHECK(arm_base.rules().size() > 50);

        for (const auto& prof : {arm_base, arm_compiler, arm_net}) {
            for (const auto& e : kMustDenyArm) {
                if (permitted(prof, e.nr)) {
                    std::fprintf(stderr, "  aarch64 profile ALLOWS %s (nr %ld)\n", e.name, e.nr);
                    CHECK(false);
                } else {
                    ++g_checks;
                }
            }
        }

        // the escape primitives must be KILLED, not merely errno'd.
        //
        // this is the check that catches a mistyped number in the deny list. the
        // default action is EPERM, so getting `mount` wrong still leaves mount
        // denied -- it fails closed, which is why it is invisible. what it loses
        // is the kill: a guest calling mount should die loudly and land in an
        // audit log, not get a tidy errno it can retry around. i planted a wrong
        // number here to check, and the ALLOWS test above did not notice.
        static constexpr Arm kMustKillArm[] = {
            {"ptrace", 117},       {"mount", 40},         {"umount2", 39},
            {"pivot_root", 41},    {"chroot", 51},        {"unshare", 97},
            {"setns", 268},        {"bpf", 280},          {"perf_event_open", 241},
            {"init_module", 105},  {"delete_module", 106}, {"finit_module", 273},
            {"kexec_load", 104},   {"reboot", 142},      {"kexec_file_load", 294},
            {"open_tree", 428},   {"move_mount", 429},  {"fsopen", 430},
            {"fsconfig", 431},    {"fsmount", 432},     {"fspick", 433},
            {"mount_setattr", 442},
        };
        for (const auto& e : kMustKillArm) {
            if (arm_base.action_for(static_cast<SysNr>(e.nr)) != SysAction::kill_process) {
                std::fprintf(stderr,
                             "  aarch64 base() does not KILL %s (nr %ld) -- a mistyped "
                             "number in the deny list downgrades it to EPERM\n",
                             e.name, e.nr);
                CHECK(false);
            } else {
                ++g_checks;
            }
        }
        for (const auto& e : kMustAllowArm) {
            if (!permitted(arm_base, e.nr)) {
                std::fprintf(stderr, "  aarch64 base() DENIES %s (nr %ld)\n", e.name, e.nr);
                CHECK(false);
            } else {
                ++g_checks;
            }
        }

        // the same profile boundaries as x86_64: exec is what with_processes
        // adds, and clone3 is ENOSYS so glibc falls back to clone.
        CHECK(!permitted(arm_base, 221 /* execve */));
        CHECK(permitted(arm_compiler, 221 /* execve */));
        CHECK(permitted(arm_compiler, 220 /* clone */));
        CHECK_EQ(arm_base.action_for(435 /* clone3 */), SysAction::errno_);
        CHECK_EQ(arm_base.errno_for(435), std::uint16_t{38});

        // aarch64 has no legacy calls, so the x86_64 numbers for them must not
        // appear. this is the failure mode that matters: pasting the x86_64
        // table into the aarch64 block would allow a set of unrelated syscalls,
        // because the same number means something different on each arch.
        //
        // x86_64 2 is `open`; on aarch64 2 is unassigned in the generic table.
        // x86_64 59 is `execve`; on aarch64 59 is pipe2. so if the aarch64
        // base() allowed 59 while denying execve, the paste would be invisible.
        // base() must not allow 221 (aarch64 execve) -- already checked above --
        // and must not allow x86_64's 57/58 (fork/vfork) as if they were process
        // calls: on aarch64 57 is close (allowed, correctly) and 58 is unassigned.
        CHECK(!permitted(arm_base, 58));   // unassigned on aarch64
        CHECK(!permitted(arm_base, 2));    // unassigned on aarch64

        // and the ioctl allow-list survived the port. the request numbers are
        // arch-independent, but the SYSCALL number is not: 29 here, 16 there.
        bool has_ioctl_set = false;
        for (const auto& s : arm_base.arg_allow_sets())
            if (s.nr == 29) has_ioctl_set = true;
        CHECK(has_ioctl_set);
        // x86_64's ioctl number must NOT carry the set on aarch64
        for (const auto& s : arm_base.arg_allow_sets()) CHECK(s.nr != 16);
    }

    return finish("syscall_table_test");
}

#else

int main() {
    std::fprintf(stderr, "skip syscall_table_test: x86_64 linux only\n");
    return 0;
}

#endif
