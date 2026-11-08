// claybin: kernel capability probe.
//
// split from compile.cpp on purpose: compile() is pure and testable against a
// described kernel, this file is the only place that asks the real one.
#include "claybin/plan/compile.hpp"

#include "claybin/linux/cgroup.hpp"

#if defined(__linux__)
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace clay {

#if defined(__linux__)
namespace {

bool path_exists(const char* p) {
    struct stat st {};
    return ::stat(p, &st) == 0;
}

// read a small proc file into a buffer. returns false on any short read, so a
// missing knob is never mistaken for a permissive value.
bool read_small(const char* path, char* buf, std::size_t cap) {
    int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    ssize_t n = ::read(fd, buf, cap - 1);
    ::close(fd);
    if (n <= 0) return false;
    buf[n] = '\0';
    return true;
}

std::uint32_t probe_landlock_abi() {
    // LANDLOCK_CREATE_RULESET_VERSION == 1. returns the abi version, or -1 with
    // ENOSYS/EOPNOTSUPP when landlock is absent or disabled.
    long rc = ::syscall(444 /* landlock_create_ruleset */, nullptr, 0ul, 1u);
    if (rc <= 0) return 0;
    // a version number is a claim, not a wall. an emulating kernel (linuxity
    // on android) answers it and then enforces nothing, so restrict a child
    // for real: a ruleset that handles READ_DIR with no rules must refuse "/".
    const pid_t pid = ::fork();
    if (pid < 0) return 0;
    if (pid == 0) {
        std::uint64_t handled = 1u << 3;   // LANDLOCK_ACCESS_FS_READ_DIR
        const long fd = ::syscall(444, &handled, sizeof handled, 0u);
        if (fd < 0) ::_exit(1);
        if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) ::_exit(2);
        if (::syscall(446 /* landlock_restrict_self */, fd, 0u) != 0) ::_exit(3);
        const int d = ::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (d >= 0) ::_exit(4);
        ::_exit(errno == EACCES ? 0 : 5);
    }
    int status = 0;
    if (::waitpid(pid, &status, 0) < 0) return 0;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return 0;
    return static_cast<std::uint32_t>(rc);
}

bool probe_seccomp() {
    // SECCOMP_GET_ACTION_AVAIL(2) with a null arg: EFAULT means seccomp is
    // there and validated our pointer, ENOSYS means it is not.
    long rc = ::syscall(SYS_seccomp, 2u, 0u, nullptr);
    if (rc == 0) return true;
    return errno == EFAULT || errno == EINVAL;
}

bool probe_user_notif() {
    std::uint32_t action = 0x7fc00000u;  // SECCOMP_RET_USER_NOTIF
    long rc = ::syscall(SYS_seccomp, 2u /* GET_ACTION_AVAIL */, 0u, &action);
    return rc == 0;
}

bool probe_userns() {
    char buf[32];
    // an explicit 0 here means the admin turned unprivileged userns off.
    if (read_small("/proc/sys/kernel/unprivileged_userns_clone", buf, sizeof buf))
        if (buf[0] == '0') return false;
    if (read_small("/proc/sys/user/max_user_namespaces", buf, sizeof buf))
        if (buf[0] == '0') return false;
    if (!path_exists("/proc/self/ns/user")) return false;

    // the sysctls and the path are necessary but NOT sufficient, and trusting
    // them was a real bug: on a GitHub Actions runner all three say yes, the
    // unshare succeeds, and writing uid_map then fails with EACCES -- so claybin
    // reported `user ns yes`, claimed process isolation, and every spawn died at
    // setup with a bare errno=13.
    //
    // the only honest test is to DO it: fork, unshare, and try the uid_map write
    // that a real sandbox depends on. a probe that asks "is the feature
    // compiled in" instead of "can I use it" will keep being wrong in exactly
    // this way, because the interesting failures are policy, not absence --
    // containers, seccomp filters and LSMs all block the map while leaving the
    // sysctls untouched.
    //
    // the cost is one fork per probe, which is nothing next to the mount work
    // that follows.
    //
    // read the uid BEFORE unsharing. after unshare(CLONE_NEWUSER) and before the
    // map is written, getuid() returns the OVERFLOW uid (65534), so a map line
    // built from it names a uid we do not own and the write is EPERM -- which
    // this function would then report as "user namespaces unavailable" on a host
    // where they work perfectly. i made this exact mistake twice today, once
    // here and once in mount_test, and both times it looked like a genuine
    // capability failure rather than a bug in the probe.
    const uid_t real_uid = ::getuid();
    pid_t pid = ::fork();
    if (pid < 0) return false;  // cannot tell; assume not available
    if (pid == 0) {
        if (::unshare(CLONE_NEWUSER) != 0) ::_exit(1);
        // deny setgroups first or gid_map is refused; ignore its failure, since
        // uid_map is the one that decides.
        int f = ::open("/proc/self/setgroups", O_WRONLY | O_CLOEXEC);
        if (f >= 0) {
            ssize_t w = ::write(f, "deny", 4);
            (void)w;
            ::close(f);
        }
        char line[64];
        int n = std::snprintf(line, sizeof line, "0 %u 1\n", real_uid);
        f = ::open("/proc/self/uid_map", O_WRONLY | O_CLOEXEC);
        if (f < 0) ::_exit(2);
        bool ok = ::write(f, line, static_cast<std::size_t>(n)) == n;
        ::close(f);
        ::_exit(ok ? 0 : 3);
    }
    int status = 0;
    if (::waitpid(pid, &status, 0) < 0) return false;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

// can we make a mount nobody else sees, and does read-only on it hold? the
// old check was "/proc/self/ns/mnt exists and userns works", which an
// emulator that accepts mount(2) as a no-op passes while every bind and
// read-only remount does nothing. so do it: in a child, mount a tmpfs over a
// scratch dir, write a file, remount read-only, expect EROFS. then the
// parent must see the dir still empty.
bool probe_mount_ns() {
    char dir[] = "/tmp/.clay-probe-XXXXXX";
    // no scratch dir means claybin could not stage a root here either
    if (!::mkdtemp(dir)) return false;
    char a[sizeof dir + 2], b[sizeof dir + 2];
    std::snprintf(a, sizeof a, "%s/a", dir);
    std::snprintf(b, sizeof b, "%s/b", dir);

    const uid_t real_uid = ::getuid();   // before unshare, see probe_userns
    const gid_t real_gid = ::getgid();
    const bool as_root = ::geteuid() == 0;
    const pid_t pid = ::fork();
    if (pid == 0) {
        if (::unshare(as_root ? CLONE_NEWNS : (CLONE_NEWUSER | CLONE_NEWNS)) != 0) ::_exit(1);
        if (!as_root) {
            int f = ::open("/proc/self/setgroups", O_WRONLY | O_CLOEXEC);
            if (f >= 0) {
                ssize_t w = ::write(f, "deny", 4);
                (void)w;
                ::close(f);
            }
            // both maps: a file created with an unmapped gid is EOVERFLOW
            const struct { const char* path; unsigned id; } maps[] = {
                {"/proc/self/uid_map", real_uid}, {"/proc/self/gid_map", real_gid}};
            for (const auto& m : maps) {
                char line[64];
                const int n = std::snprintf(line, sizeof line, "0 %u 1\n", m.id);
                f = ::open(m.path, O_WRONLY | O_CLOEXEC);
                if (f < 0 || ::write(f, line, static_cast<std::size_t>(n)) != n) ::_exit(2);
                ::close(f);
            }
        }
        if (::mount("none", "/", nullptr, MS_REC | MS_PRIVATE, nullptr) != 0) ::_exit(3);
        if (::mount("tmpfs", dir, "tmpfs", 0, nullptr) != 0) ::_exit(4);
        int f = ::open(a, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
        if (f < 0) ::_exit(5);
        ::close(f);
        if (::mount(nullptr, dir, nullptr, MS_REMOUNT | MS_BIND | MS_RDONLY, nullptr) != 0) ::_exit(6);
        f = ::open(b, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
        if (f >= 0) ::_exit(7);
        ::_exit(errno == EROFS ? 0 : 8);
    }
    int status = 0;
    const bool ran = pid > 0 && ::waitpid(pid, &status, 0) == pid &&
                     WIFEXITED(status) && WEXITSTATUS(status) == 0;
    // the file the child wrote must not be here: the tmpfs was private
    struct stat st {};
    const bool leaked = ::lstat(a, &st) == 0 || ::lstat(b, &st) == 0;
    ::unlink(a);
    ::unlink(b);
    ::rmdir(dir);
    return ran && !leaked;
}

bool probe_cgroup2() {
    struct stat st {};
    return ::stat("/sys/fs/cgroup/cgroup.controllers", &st) == 0;
}
bool probe_no_new_privs() {
    // reading the current value is harmless and tells us the knob exists.
    return ::prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) >= 0;
}

bool probe_kvm() {
    // OPEN it, do not stat it. /dev/kvm exists on hosts where the module is
    // loaded but the device is root-only, which is the common case on desktop
    // distributions -- and a capability that reads as present and fails on use
    // is the failure mode this whole probe file exists to avoid (see
    // probe_userns: the sysctls said yes and the uid_map write said no).
    //
    // O_RDWR because that is what a VMM needs; read-only access to /dev/kvm is
    // not enough to create a VM.
    const int fd = ::open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (fd < 0) return false;
    ::close(fd);
    return true;
}

}  // namespace

HostCapabilities probe_host() {
    HostCapabilities h;
    h.user_namespaces = probe_userns();

    // the OTHER namespaces are reported as "can i create one", not "does this
    // kernel know the concept". path_exists("/proc/self/ns/mnt") answers the
    // second question and is true on literally every linux, including the ones
    // that refuse the unshare -- which is how a denied-userns host ended up
    // with a plan full of namespace flags it could not use.
    //
    // none of these is unprivileged by itself. with a user namespace available
    // they come for free, because the kernel grants them inside the new userns.
    // without one they need CAP_SYS_ADMIN, so the honest answer for an
    // unprivileged process is no.
    const bool ns_creatable = h.user_namespaces || ::geteuid() == 0;
    h.mount_namespaces = ns_creatable && path_exists("/proc/self/ns/mnt") && probe_mount_ns();
    h.pid_namespaces = ns_creatable && path_exists("/proc/self/ns/pid");
    h.net_namespaces = ns_creatable && path_exists("/proc/self/ns/net");
    h.uts_namespaces = ns_creatable && path_exists("/proc/self/ns/uts");
    h.ipc_namespaces = ns_creatable && path_exists("/proc/self/ns/ipc");
    h.cgroup_namespaces = ns_creatable && path_exists("/proc/self/ns/cgroup");
    h.seccomp = probe_seccomp();
    h.seccomp_user_notif = h.seccomp && probe_user_notif();
    h.kvm = probe_kvm();

    // cgroups need the full delegation probe, not a stat: whether we can
    // actually create a limited cgroup depends on how our caller was launched.
    if (probe_cgroup2()) {
        auto cg = cgroup::probe();
        h.cgroups = cg.availability;
        h.cgroup_memory = cg.memory;
        h.cgroup_pids = cg.pids;
        h.cgroup_cpu = cg.cpu;
    }

    h.landlock_abi = probe_landlock_abi();
    h.no_new_privs = probe_no_new_privs();
    return h;
}

#else

HostCapabilities probe_host() { return HostCapabilities::none(); }

#endif

}  // namespace clay
