// the escape corpus.
//
// one binary, many attacks. each one is a specific, named thing an attacker
// would actually try, and the harness records what happened rather than just
// asserting "blocked". the point is not to reach a number -- it is that every
// entry here is a claim about the sandbox that a reader can check.
//
// each attack returns:
//   0  = THE ESCAPE SUCCEEDED   (test failure)
//   1  = blocked                (test pass)
//   2  = not applicable here    (skipped, not counted as a pass)
#pragma once

#include <cstdio>
#include <cstring>

#if defined(__linux__)
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace clay::attacks {

#if defined(__linux__)

constexpr int kEscaped = 0;
constexpr int kBlocked = 1;
constexpr int kNotApplicable = 2;

// ---------------------------------------------------------------------------
// filesystem: reach something outside the granted tree
// ---------------------------------------------------------------------------

inline int read_path(const char* p) {
    int fd = ::open(p, O_RDONLY);
    if (fd < 0) return kBlocked;
    char b[1];
    ssize_t n = ::read(fd, b, 1);
    ::close(fd);
    return n > 0 ? kEscaped : kBlocked;
}

inline int write_path(const char* p) {
    int fd = ::open(p, O_WRONLY | O_CREAT, 0600);
    if (fd < 0) return kBlocked;
    ::close(fd);
    ::unlink(p);
    return kEscaped;
}

inline int stat_path(const char* p) {
    struct stat st{};
    return ::stat(p, &st) == 0 ? kEscaped : kBlocked;
}

// climb out with .. -- the oldest trick, and the reason path normalization has
// to be component-aware rather than a string prefix.
inline int dotdot_climb() {
    return read_path("../../../../../../../../etc/passwd");
}

// a symlink we create ourselves, pointing outside. landlock resolves symlinks,
// so this must fail even though the symlink itself is inside the sandbox.
inline int symlink_escape() {
    if (::symlink("/etc/passwd", "/tmp/clay_esc_link") != 0) return kBlocked;
    int r = read_path("/tmp/clay_esc_link");
    ::unlink("/tmp/clay_esc_link");
    return r;
}

// walk /proc/*/root, which is a magic symlink to another process's root. if the
// pid namespace works there is nobody else to look at; if it does not, this
// reaches the host filesystem.
inline int proc_root_escape() {
    DIR* d = ::opendir("/proc");
    if (!d) return kBlocked;
    int result = kBlocked;
    while (struct dirent* e = ::readdir(d)) {
        if (e->d_name[0] < '1' || e->d_name[0] > '9') continue;
        // sized so the format CANNOT truncate: d_name is up to 255 bytes and
        // the literals add 22, so char[256] was provably too small. a silently
        // truncated path would stat the wrong thing and report kBlocked -- an
        // escape probe that passes because it stopped probing.
        char path[sizeof(e->d_name) + 32];
        std::snprintf(path, sizeof path, "/proc/%s/root/etc/passwd", e->d_name);
        if (read_path(path) == kEscaped) {
            result = kEscaped;
            break;
        }
    }
    ::closedir(d);
    return result;
}

// /proc/self/cwd and /proc/self/exe are magic symlinks too.
inline int proc_cwd_escape() { return read_path("/proc/self/cwd/../../../etc/passwd"); }

// openat with a dirfd we got before the sandbox closed things down. tests that
// inherited descriptors really are gone.
inline int inherited_fd_escape() {
    // fd 7 is what the harness leaks on purpose when testing this.
    char buf[1];
    ssize_t n = ::read(7, buf, 1);
    if (n >= 0) return kEscaped;
    return kBlocked;
}

// ---------------------------------------------------------------------------
// process: touch something outside our own tree
// ---------------------------------------------------------------------------

inline int ptrace_attach() {
    // pid 1 of the host, if we can see it
    long r = ::syscall(SYS_ptrace, PTRACE_ATTACH, 1, 0, 0);
    return r == 0 ? kEscaped : kBlocked;
}

inline int kill_host_init() {
    // signal pid 1. inside a pid namespace this is our own init, which is fine;
    // outside one it is the host's, which is not.
    return ::kill(1, 0) == 0 && ::getpid() != 1 ? kEscaped : kBlocked;
}

inline int fork_bomb() {
    int made = 0;
    for (int i = 0; i < 4096; ++i) {
        pid_t p = ::fork();
        if (p < 0) break;
        if (p == 0) {
            ::pause();
            ::_exit(0);
        }
        ++made;
    }
    for (int i = 0; i < made; ++i) ::wait(nullptr);
    // if we got thousands of processes the pid limit is not working
    return made > 2000 ? kEscaped : kBlocked;
}

inline int setuid_escape() {
    // becoming uid 0 OUTSIDE a user namespace would be an escape. inside one it
    // is meaningless, which is the point of userns.
    if (::setuid(0) != 0) return kBlocked;
    // we are uid 0 -- but can we actually do anything with it?
    return read_path("/etc/shadow") == kEscaped ? kEscaped : kBlocked;
}

inline int clone_userns() {
    // the sibling of unshare, and the one that gets forgotten. a filter that
    // denies unshare but allows clone with unrestricted flags has not closed
    // anything: clone(CLONE_NEWUSER) is the same escape with a different entry
    // point, and it hands back a namespace where we hold capabilities.
    //
    // CLONE_NEWUSER|SIGCHLD. a raw syscall, not glibc's clone() wrapper, because
    // the wrapper wants a stack and a function and we only care about the errno.
    long rc = ::syscall(SYS_clone, 0x10000000ul /* CLONE_NEWUSER */ | 17ul /* SIGCHLD */,
                        0ul, 0ul, 0ul, 0ul);
    if (rc == 0) ::_exit(0);  // we are the child: leave, the parent reports
    if (rc > 0) {
        int st = 0;
        ::waitpid(static_cast<pid_t>(rc), &st, 0);
        return kEscaped;
    }
    return kBlocked;
}

inline int clone_newns() {
    // a mount namespace is the first step of a remount-something-writable escape.
    long rc = ::syscall(SYS_clone, 0x00020000ul /* CLONE_NEWNS */ | 17ul, 0ul, 0ul, 0ul, 0ul);
    if (rc == 0) ::_exit(0);
    if (rc > 0) {
        int st = 0;
        ::waitpid(static_cast<pid_t>(rc), &st, 0);
        return kEscaped;
    }
    return kBlocked;
}

inline int clone3_userns() {
    // clone3 is the hole under the clone flag rules. its flags live in a struct
    // in MEMORY, so seccomp cannot read them -- and dereferencing the pointer to
    // check would be unsound, because the guest can rewrite it after the check.
    //
    // so clone3 has to be denied outright, which is what makes the clone mask
    // meaningful. if this escapes, the clone rules are decoration.
    struct CloneArgs {
        std::uint64_t flags;
        std::uint64_t pidfd;
        std::uint64_t child_tid;
        std::uint64_t parent_tid;
        std::uint64_t exit_signal;
        std::uint64_t stack;
        std::uint64_t stack_size;
        std::uint64_t tls;
    } a{};
    a.flags = 0x10000000ull;  // CLONE_NEWUSER
    a.exit_signal = 17;       // SIGCHLD

    long rc = ::syscall(435 /* clone3 */, &a, sizeof a);
    if (rc == 0) ::_exit(0);
    if (rc > 0) {
        int st = 0;
        ::waitpid(static_cast<pid_t>(rc), &st, 0);
        return kEscaped;
    }
    // ENOSYS is the RIGHT denial here, not just any failure: glibc probes clone3
    // and only falls back to clone when the kernel says the syscall is missing.
    // EPERM would break pthread_create instead of redirecting it.
    return kBlocked;
}

inline int mmap_wx() {
    // a single writable+executable mapping is what most code-injection payloads
    // want: write the shellcode, jump to it, no mprotect in between. ordinary
    // programs never ask for one.
    void* p = ::mmap(nullptr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return kBlocked;
    ::munmap(p, 4096);
    return kEscaped;
}

inline int mprotect_wx() {
    // the two-step version of the same thing. W^X by itself cannot stop this --
    // the attacker maps writable, writes, then flips to executable -- so the
    // rule covers mprotect as well, and this checks that it does.
    void* p = ::mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return kNotApplicable;  // no anonymous memory at all
    int r = ::mprotect(p, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);
    ::munmap(p, 4096);
    return r == 0 ? kEscaped : kBlocked;
}


inline int regain_caps() {
    // try to put a capability back into the bounding set. the kernel offers no
    // way to do this, which is the whole point of dropping it, but a missing
    // no_new_privs would let an suid exec do it.
    if (::prctl(PR_CAPBSET_READ, 21 /* CAP_SYS_ADMIN */, 0, 0, 0) == 1) return kEscaped;
    return kBlocked;
}

// ---------------------------------------------------------------------------
// namespaces: escape the ones we are in
// ---------------------------------------------------------------------------

inline int unshare_userns() {
    // a nested user namespace would give us capabilities in it, which is a
    // stepping stone to a mount escape.
    return ::unshare(CLONE_NEWUSER) == 0 ? kEscaped : kBlocked;
}

inline int setns_escape() {
    int fd = ::open("/proc/1/ns/mnt", O_RDONLY);
    if (fd < 0) return kBlocked;
    long r = ::syscall(SYS_setns, fd, 0);
    ::close(fd);
    return r == 0 ? kEscaped : kBlocked;
}

inline int mount_escape() {
    // remount the host root somewhere we can read it
    ::mkdir("/tmp/clay_esc_mnt", 0755);
    int r = ::mount("/", "/tmp/clay_esc_mnt", nullptr, MS_BIND, nullptr);
    if (r == 0) {
        int got = read_path("/tmp/clay_esc_mnt/etc/passwd");
        ::umount("/tmp/clay_esc_mnt");
        ::rmdir("/tmp/clay_esc_mnt");
        return got;
    }
    ::rmdir("/tmp/clay_esc_mnt");
    return kBlocked;
}

inline int pivot_root_escape() {
    long r = ::syscall(SYS_pivot_root, "/", "/");
    return r == 0 ? kEscaped : kBlocked;
}

inline int chroot_escape() {
    // the classic double-chroot: chroot into a subdir, then .. out past the old
    // root. only works if chroot is available at all.
    ::mkdir("/tmp/clay_esc_ch", 0755);
    if (::chroot("/tmp/clay_esc_ch") != 0) {
        ::rmdir("/tmp/clay_esc_ch");
        return kBlocked;
    }
    int r = read_path("../../../../etc/passwd");
    return r;
}

// ---------------------------------------------------------------------------
// kernel interfaces that are escapes in themselves
// ---------------------------------------------------------------------------

inline int bpf_load() {
    long r = ::syscall(SYS_bpf, 5 /* BPF_PROG_LOAD */, nullptr, 0);
    // EFAULT means bpf() is REACHABLE (it validated our null pointer), which is
    // the thing we care about -- a reachable bpf() is a kernel attack surface.
    return (r == 0 || errno == EFAULT) ? kEscaped : kBlocked;
}

inline int perf_open() {
    long r = ::syscall(SYS_perf_event_open, nullptr, 0, -1, -1, 0);
    return (r >= 0 || errno == EFAULT) ? kEscaped : kBlocked;
}

inline int userfaultfd_open() {
    // userfaultfd has been used in several kernel exploits as a way to win
    // otherwise-tight races.
    long r = ::syscall(323 /* userfaultfd */, 0);
    if (r >= 0) {
        ::close(static_cast<int>(r));
        return kEscaped;
    }
    return kBlocked;
}

inline int io_uring_open() {
    // io_uring bypasses seccomp for the operations it queues, which makes it a
    // sandbox escape by design rather than by bug. it must not be reachable.
    long r = ::syscall(425 /* io_uring_setup */, 1, nullptr);
    return (r >= 0 || errno == EFAULT) ? kEscaped : kBlocked;
}

inline int kexec_load() {
    long r = ::syscall(SYS_kexec_load, 0, 0, nullptr, 0);
    return (r == 0 || errno == EFAULT) ? kEscaped : kBlocked;
}

inline int module_load() {
    long r = ::syscall(SYS_init_module, nullptr, 0, "");
    return (r == 0 || errno == EFAULT) ? kEscaped : kBlocked;
}

// ---------------------------------------------------------------------------
// terminal: inject into the host's tty
// ---------------------------------------------------------------------------

inline int tiocsti_inject() {
    // push a byte into the terminal's input queue. if we share a controlling
    // terminal with an interactive shell, this TYPES INTO THAT SHELL and the
    // command runs outside the sandbox. one of the most underrated escapes.
    char c = 'X';
    if (::ioctl(0, 0x5412 /* TIOCSTI */, &c) == 0) return kEscaped;
    return kBlocked;
}

inline int tiocsti_high_bits() {
    // the same escape, dressed up to slip past a filter that compares all 64 bits
    // of the request.
    //
    // ioctl's cmd is `unsigned int` in the kernel, so the register is TRUNCATED
    // before use: 0xdeadbeef00005412 runs as TIOCSTI. claybin had exactly this
    // bug -- the old TIOCSTI deny rule required the high half to be zero, saw a
    // value matching nothing, and let it through.
    //
    // the allow-list that replaced it is immune by SHAPE rather than by a flag:
    // it compares the low half only, so a dressed-up value lands on the same
    // entry the kernel will truncate it to, and anything not on the list is
    // denied whatever is above the line. that is the real argument for the
    // allow-list -- getting this wrong is invisible in a deny-list and
    // impossible in an allow-list. bpf_emit_test pins the deny-rule side, where
    // the difference is observable.
    //
    // the raw syscall, not glibc's ioctl(), because the wrapper takes an
    // `unsigned long` request and would drop the high bits before the kernel
    // ever sees them -- which would make this test pass for the wrong reason.
    char c = 'X';
    long r = ::syscall(SYS_ioctl, 0, 0xdeadbeef00005412ull, &c);
    return r == 0 ? kEscaped : kBlocked;
}

inline int isatty_still_works() {
    // not an escape: a REGRESSION check, and the reason the ioctl allow-list has
    // to be an allow-list of the right things rather than an empty one.
    //
    // TCGETS is what isatty() calls. a sandbox that blocks it breaks every
    // program that checks whether its output is a terminal, which is most of
    // them. "blocked" here would mean the policy is too tight to use, so the
    // polarity is deliberately inverted: reaching the kernel is the PASS.
    struct termios_probe {
        unsigned char pad[64];
    } t{};
    long r = ::syscall(SYS_ioctl, 1, 0x5401 /* TCGETS */, &t);
    // ENOTTY means it reached the kernel and the fd simply is not a terminal,
    // which is the expected answer under a pipe. EPERM means seccomp ate it.
    if (r == 0 || errno == ENOTTY || errno == EINVAL) return kBlocked;  // "ok"
    return kEscaped;                                                    // "broken"
}

inline int tioclinux_inject() {
    // TIOCLINUX subcommand 2 can do the same via the selection buffer.
    char arg[2] = {2, 0};
    if (::ioctl(0, 0x541C /* TIOCLINUX */, arg) == 0) return kEscaped;
    return kBlocked;
}

inline int tioccons_steal() {
    if (::ioctl(1, 0x541D /* TIOCCONS */, nullptr) == 0) return kEscaped;
    return kBlocked;
}

// ---------------------------------------------------------------------------
// devices
// ---------------------------------------------------------------------------

inline int dev_mem_read() { return read_path("/dev/mem"); }
inline int dev_kmsg_read() { return read_path("/dev/kmsg"); }
inline int dev_kcore_read() { return read_path("/proc/kcore"); }
inline int sysrq_trigger() { return write_path("/proc/sysrq-trigger"); }

// ---------------------------------------------------------------------------
// information disclosure: things that leak the host even if we cannot touch it
// ---------------------------------------------------------------------------

inline int read_host_cmdline() {
    // another process's command line. inside a pid namespace with its own
    // procfs, pid 1 is the sandbox's own shepherd (or the guest itself), whose
    // inherited argv is blanked. an escape is a non-empty command line there,
    // i.e. text that came from outside the sandbox.
    if (::getpid() == 1) return kBlocked;
    const int fd = ::open("/proc/1/cmdline", O_RDONLY);
    if (fd < 0) return kBlocked;
    char b[256];
    const ssize_t n = ::read(fd, b, sizeof b);
    ::close(fd);
    for (ssize_t k = 0; k < n; ++k)
        if (b[k] != '\0') return kEscaped;
    return kBlocked;
}

inline int read_kallsyms() {
    // kernel symbol addresses defeat KASLR, which turns an unexploitable bug
    // into an exploitable one.
    return read_path("/proc/kallsyms");
}

inline int read_host_mounts() {
    // the host's mount table names paths that exist outside the sandbox. not an
    // escape by itself, but a map for one.
    int fd = ::open("/proc/self/mountinfo", O_RDONLY);
    if (fd < 0) return kBlocked;
    char buf[8192];
    ssize_t n = ::read(fd, buf, sizeof buf - 1);
    ::close(fd);
    if (n <= 0) return kBlocked;
    buf[n] = '\0';
    // if we can see the staging paths claybin used, the pivot leaked
    return std::strstr(buf, ".clay") != nullptr ? kEscaped : kBlocked;
}

inline int net_raw_socket() {
    int s = ::socket(AF_INET, SOCK_RAW, 255);
    if (s >= 0) {
        ::close(s);
        return kEscaped;
    }
    return kBlocked;
}

inline int abstract_unix_socket() {
    // an abstract AF_UNIX socket is NOT namespaced by the mount namespace -- it
    // lives in the network namespace. so without a netns a guest can talk to
    // host services listening on abstract addresses, which is a real and
    // frequently-missed hole.
    int s = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return kBlocked;
    // try a well-known abstract name that a desktop session usually has
    struct sockaddr_un {
        unsigned short family;
        char path[108];
    } a{};
    a.family = AF_UNIX;
    a.path[0] = '\0';
    std::memcpy(a.path + 1, "dbus-", 5);
    int r = ::connect(s, reinterpret_cast<struct sockaddr*>(&a), 2 + 6);
    ::close(s);
    // ECONNREFUSED means the abstract namespace was REACHABLE, which is the
    // thing being tested -- not whether that particular name existed.
    return (r == 0 || errno == ECONNREFUSED) ? kEscaped : kBlocked;
}

inline int abstract_unix_live() {
    // the sharper version of the attack above, and the only one that can see
    // landlock scoping.
    //
    // scoping is checked against the PEER: the kernel compares the listening
    // socket's landlock domain with ours and refuses if they differ. a name that
    // nobody is listening on has no peer to compare against, so connecting to it
    // fails with ECONNREFUSED whether scoping is on or not -- which means the
    // heuristic above cannot distinguish "scoped" from "reachable but empty".
    //
    // so the supervisor binds a real abstract name outside the sandbox and passes
    // it in. reaching it is a genuine escape: a guest talking to a host service.
    const char* name = ::getenv("CLAY_ABSTRACT_PROBE");
    if (!name || !*name) return kNotApplicable;

    int s = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return kBlocked;

    struct sockaddr_un {
        unsigned short family;
        char path[108];
    } a{};
    a.family = AF_UNIX;
    a.path[0] = '\0';  // leading NUL is what makes it abstract
    std::size_t n = std::strlen(name);
    if (n > sizeof a.path - 2) n = sizeof a.path - 2;
    std::memcpy(a.path + 1, name, n);

    int r = ::connect(s, reinterpret_cast<struct sockaddr*>(&a),
                      static_cast<unsigned>(2 + 1 + n));
    ::close(s);
    // here a refusal is NOT an escape: the listener exists, so ECONNREFUSED
    // would mean we are looking at a different abstract namespace entirely.
    return r == 0 ? kEscaped : kBlocked;
}

// ---------------------------------------------------------------------------
// the network namespace boundary
// ---------------------------------------------------------------------------
//
// The filesystem attacks above have had a corpus since the start; the network
// boundary had none, which is why a shared netns went unnoticed long enough to
// become an audit finding. These are the specific things a guest would try.
//
// A netns is all-or-nothing, so most of these are a single question asked of
// several targets: can a datagram or a connection leave this namespace at all?

// the host's own loopback. THE finding: a sandbox sharing the host netns
// reaches every service on 127.0.0.1 -- a dev server, a database, another
// agent's debug port, an unauthenticated admin interface.
//
// The supervisor binds a real listener outside and passes its port in, for the
// same reason abstract_unix_live does: connecting to a port nobody holds fails
// either way, so an empty port cannot tell "isolated" from "reachable".
inline int net_host_loopback() {
    const char* port_s = ::getenv("CLAY_LOOPBACK_PROBE_PORT");
    if (!port_s || !*port_s) return kNotApplicable;
    int port = 0;
    for (const char* p = port_s; *p >= '0' && *p <= '9'; ++p) port = port * 10 + (*p - '0');
    if (port <= 0 || port > 65535) return kNotApplicable;

    int s = ::socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return kBlocked;
    struct sockaddr_in_min {
        unsigned short family;
        unsigned short port;
        unsigned int addr;
        char zero[8];
    } a{};
    a.family = AF_INET;
    a.port = static_cast<unsigned short>((port >> 8) | ((port & 0xff) << 8));   // htons
    unsigned char* ab = reinterpret_cast<unsigned char*>(&a.addr);
    ab[0] = 127; ab[1] = 0; ab[2] = 0; ab[3] = 1;
    const int r = ::connect(s, reinterpret_cast<struct sockaddr*>(&a), sizeof a);
    ::close(s);
    // The listener exists, so success is an escape and anything else means we
    // are in a different network namespace -- which is the wall working.
    return r == 0 ? kEscaped : kBlocked;
}

// a datagram to the host's loopback. UDP is a separate landlock access right
// (abi 10) and a separate thing to forget: a connect-based test says nothing
// about sendto.
//
// THE CARE THIS NEEDS, and the first version got it wrong. sendto() on UDP is
// fire-and-forget: in the guest's OWN netns it succeeds, because the kernel
// happily accepts a datagram addressed to the guest's own loopback where
// nothing is listening. A successful send is therefore NOT an escape. The
// escape is a REPLY -- which only arrives if the packet reached the host's
// echo listener.
inline int net_host_loopback_udp() {
    const char* port_s = ::getenv("CLAY_LOOPBACK_PROBE_PORT");
    if (!port_s || !*port_s) return kNotApplicable;
    int port = 0;
    for (const char* p = port_s; *p >= '0' && *p <= '9'; ++p) port = port * 10 + (*p - '0');
    if (port <= 0) return kNotApplicable;

    int s = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return kBlocked;
    // A short timeout: we are proving a negative, so waiting long buys
    // nothing and a hung attack reads as a hung test.
    struct timeval tv{};
    tv.tv_sec = 1;
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    struct sockaddr_in_min {
        unsigned short family;
        unsigned short port;
        unsigned int addr;
        char zero[8];
    } a{};
    a.family = AF_INET;
    a.port = static_cast<unsigned short>((port >> 8) | ((port & 0xff) << 8));
    unsigned char* ab = reinterpret_cast<unsigned char*>(&a.addr);
    ab[0] = 127; ab[1] = 0; ab[2] = 0; ab[3] = 1;
    const char byte = 'x';
    if (::sendto(s, &byte, 1, 0, reinterpret_cast<struct sockaddr*>(&a), sizeof a) < 0) {
        // Refused outright (EPERM under a landlock port rule, ENETUNREACH in
        // an empty namespace). Blocked before it left.
        ::close(s);
        return kBlocked;
    }
    char reply[8]{};
    const long got = ::recv(s, reply, sizeof reply, 0);
    ::close(s);
    // A reply means the host's listener answered us: the datagram crossed the
    // boundary. No reply means it went into our own empty loopback.
    return got > 0 ? kEscaped : kBlocked;
}

// the LAN. the other half of the same finding: the router's admin page, a NAS,
// a colleague's laptop. no listener is needed -- what matters is whether a
// SYN can leave, and a 200 ms connect that returns ENETUNREACH immediately is
// a different answer from one that times out.
inline int net_lan_reachable() {
    int s = ::socket(AF_INET, SOCK_STREAM | 04000 /*SOCK_NONBLOCK*/, 0);
    if (s < 0) return kBlocked;
    struct sockaddr_in_min {
        unsigned short family;
        unsigned short port;
        unsigned int addr;
        char zero[8];
    } a{};
    a.family = AF_INET;
    a.port = 0x5000;   // htons(80)
    unsigned char* ab = reinterpret_cast<unsigned char*>(&a.addr);
    ab[0] = 192; ab[1] = 168; ab[2] = 1; ab[3] = 1;
    const int r = ::connect(s, reinterpret_cast<struct sockaddr*>(&a), sizeof a);
    const int e = errno;
    ::close(s);
    if (r == 0) return kEscaped;            // immediate success: reachable
    // EINPROGRESS means the SYN is on its way: the packet left the namespace,
    // which is the escape even if nothing answers. ENETUNREACH/EPERM mean it
    // never got out.
    return e == EINPROGRESS ? kEscaped : kBlocked;
}

// cloud metadata. 169.254.169.254 hands out IAM credentials to anything that
// can reach it, which makes it the highest-value target on this list for a
// sandbox running on a cloud host.
inline int net_cloud_metadata() {
    int s = ::socket(AF_INET, SOCK_STREAM | 04000, 0);
    if (s < 0) return kBlocked;
    struct sockaddr_in_min {
        unsigned short family;
        unsigned short port;
        unsigned int addr;
        char zero[8];
    } a{};
    a.family = AF_INET;
    a.port = 0x5000;   // htons(80)
    unsigned char* ab = reinterpret_cast<unsigned char*>(&a.addr);
    ab[0] = 169; ab[1] = 254; ab[2] = 169; ab[3] = 254;
    const int r = ::connect(s, reinterpret_cast<struct sockaddr*>(&a), sizeof a);
    const int e = errno;
    ::close(s);
    if (r == 0) return kEscaped;
    return e == EINPROGRESS ? kEscaped : kBlocked;
}

// a PATHNAME unix socket, which is the half that landlock scoping does NOT
// cover: scoping (abi 6) is about abstract names, and RESOLVE_UNIX (abi 9) is
// what mediates sockets that live in the filesystem. dbus, docker and postgres
// all listen on pathname sockets.
inline int net_pathname_unix() {
    const char* path = ::getenv("CLAY_PATHNAME_SOCK");
    if (!path || !*path) return kNotApplicable;
    int s = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return kBlocked;
    struct sockaddr_un {
        unsigned short family;
        char path[108];
    } a{};
    a.family = AF_UNIX;
    std::size_t n = std::strlen(path);
    if (n > sizeof a.path - 1) n = sizeof a.path - 1;
    std::memcpy(a.path, path, n);
    const int r = ::connect(s, reinterpret_cast<struct sockaddr*>(&a), sizeof a);
    ::close(s);
    // The listener exists outside, so reaching it is the escape.
    return r == 0 ? kEscaped : kBlocked;
}

// ---------------------------------------------------------------------------
// the table
// ---------------------------------------------------------------------------

struct Attack {
    const char* name;
    int (*run)();
    // some attacks only make sense under a particular policy, e.g. the fd leak
    // needs the harness to leak one first.
    bool needs_leaked_fd;
};

inline const Attack* table(std::size_t& count) {
    static const Attack t[] = {
        // filesystem
        {"fs.read_etc_shadow", [] { return read_path("/etc/shadow"); }, false},
        {"fs.read_etc_passwd", [] { return read_path("/etc/passwd"); }, false},
        {"fs.read_root_ssh", [] { return read_path("/root/.ssh/id_rsa"); }, false},
        {"fs.write_etc", [] { return write_path("/etc/clay_probe"); }, false},
        {"fs.write_usr", [] { return write_path("/usr/clay_probe"); }, false},
        {"fs.stat_home", [] { return stat_path("/home"); }, false},
        {"fs.dotdot_climb", dotdot_climb, false},
        {"fs.symlink_escape", symlink_escape, false},
        {"fs.proc_root", proc_root_escape, false},
        {"fs.proc_cwd", proc_cwd_escape, false},
        {"fs.inherited_fd", inherited_fd_escape, true},

        // process
        {"proc.ptrace_attach", ptrace_attach, false},
        {"proc.kill_host_init", kill_host_init, false},
        {"proc.fork_bomb", fork_bomb, false},
        {"proc.setuid_root", setuid_escape, false},
        {"proc.regain_caps", regain_caps, false},

        // namespaces
        {"ns.unshare_userns", unshare_userns, false},
        {"ns.setns", setns_escape, false},
        {"ns.mount_bind_root", mount_escape, false},
        {"ns.pivot_root", pivot_root_escape, false},
        {"ns.chroot_double", chroot_escape, false},

        // kernel interfaces
        {"kern.bpf", bpf_load, false},
        {"kern.perf_event_open", perf_open, false},
        {"kern.userfaultfd", userfaultfd_open, false},
        {"kern.io_uring", io_uring_open, false},
        {"kern.kexec_load", kexec_load, false},
        {"kern.init_module", module_load, false},

        // terminal
        {"tty.tiocsti", tiocsti_inject, false},
        // the same request with high garbage above the 32-bit line. the kernel
        // truncates, so this really is TIOCSTI -- a filter comparing all 64 bits
        // is bypassed by it.
        {"tty.tiocsti_high_bits", tiocsti_high_bits, false},
        // inverted polarity: this one fails if the sandbox is too TIGHT.
        {"tty.isatty_not_broken", isatty_still_works, false},
        {"tty.tioclinux", tioclinux_inject, false},
        {"tty.tioccons", tioccons_steal, false},

        // devices
        {"dev.mem", dev_mem_read, false},
        {"dev.kmsg", dev_kmsg_read, false},
        {"dev.kcore", dev_kcore_read, false},
        {"dev.sysrq", sysrq_trigger, false},

        // disclosure
        {"info.host_cmdline", read_host_cmdline, false},
        {"info.kallsyms", read_kallsyms, false},
        {"info.staging_paths", read_host_mounts, false},
        {"net.raw_socket", net_raw_socket, false},
        {"net.abstract_unix", abstract_unix_socket, false},
        {"net.abstract_unix_live", abstract_unix_live, false},
        // the netns boundary. the supervisor passes a real target in for the
        // two that need one; the rest ask whether a packet can leave at all.
        {"net.host_loopback", net_host_loopback, false},
        {"net.host_loopback_udp", net_host_loopback_udp, false},
        {"net.lan", net_lan_reachable, false},
        {"net.cloud_metadata", net_cloud_metadata, false},
        {"net.pathname_unix", net_pathname_unix, false},
        // the flag-argument attacks. each of these is allowed by a filter that
        // checks syscall NUMBERS only, which is why argument filtering exists.
        {"ns.clone_newuser", clone_userns, false},
        {"ns.clone_newns", clone_newns, false},
        {"ns.clone3_newuser", clone3_userns, false},
        {"mem.mmap_wx", mmap_wx, false},
        {"mem.mprotect_wx", mprotect_wx, false},
    };
    count = sizeof t / sizeof t[0];
    return t;
}

#endif  // __linux__

}  // namespace clay::attacks
