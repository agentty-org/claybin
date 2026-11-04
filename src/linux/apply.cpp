// claybin: the post-fork path.
//
// RULES FOR THIS FILE, all of them load-bearing:
//
//   1. no allocation. after clone() in a process that had threads, malloc can
//      deadlock outright: another thread may have held the arena lock at fork
//      time and it is never coming back to release it.
//   2. no libc calls that might allocate or take a lock. that rules out stdio,
//      std::string, iostreams, and anything in <format>.
//   3. no exceptions (the library is built -fno-exceptions anyway).
//   4. syscalls only, through raw syscall() wrappers.
//   5. never return an error to a caller that might keep running. a half-built
//      sandbox is worse than no sandbox, so any failure here is fatal to the
//      child by construction.
//
// this is why the Plan is a flat arena of POD ops: walking it needs no
// allocation, and every string it hands to a syscall is already nul-terminated
// inside the arena.
#include "claybin/plan/plan.hpp"

#if defined(__linux__)

#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <type_traits>
#include <unistd.h>

namespace clay {


namespace {

// ---- raw syscall wrappers. no libc wrappers: several of them touch errno
// ---- through TLS or take locks we cannot rely on after a fork.

// A syscall argument is a register word. Integers of any width or sign and
// pointers all go in as one, so convert each explicitly here, once, instead
// of letting a `long` parameter sign-convert every unsigned field implicitly.
template <class T>
inline long syscall_word(T v) noexcept {
    if constexpr (std::is_pointer_v<T>)
        return reinterpret_cast<long>(v);
    else if constexpr (std::is_null_pointer_v<T>)
        return 0;
    else if constexpr (std::is_enum_v<T>)
        return static_cast<long>(static_cast<std::underlying_type_t<T>>(v));
    else {
        static_assert(std::is_integral_v<T>, "syscall argument must be an integer or pointer");
        return static_cast<long>(v);
    }
}

template <class... A>
    requires(sizeof...(A) <= 5)
inline long sys(long nr, A... args) {
    // Unused trailing slots stay 0, as the old defaulted parameters made
    // them: prctl and friends reject garbage in arguments they don't read.
    long w[5]{};
    if constexpr (sizeof...(A) > 0) {
        std::size_t i = 0;
        ((w[i++] = syscall_word(args)), ...);
    }
    return ::syscall(nr, w[0], w[1], w[2], w[3], w[4]);
}

// write a whole buffer to a path. used for uid_map/gid_map/setgroups, which
// must be written in a single write() -- the kernel rejects partial writes to
// them, so a short write is a hard failure rather than something to retry.
bool write_all(const char* path, const char* data, std::size_t len) {
    long fd = sys(SYS_openat, AT_FDCWD, reinterpret_cast<long>(path), O_WRONLY | O_CLOEXEC, 0);
    if (fd < 0) return false;
    long n = sys(SYS_write, fd, reinterpret_cast<long>(data), static_cast<long>(len));
    sys(SYS_close, fd);
    return n == static_cast<long>(len);
}

bool streq(const char* a, const char* b) {
    while (*a && *a == *b) { ++a; ++b; }
    return *a == '\0' && *b == '\0';
}

std::size_t cstr_len(const char* s) {
    std::size_t n = 0;
    while (s[n] != '\0') ++n;
    return n;
}

// ---- confined path resolution -----------------------------------------
//
// openat2's struct and flags. declared here rather than included because
// <linux/openat2.h> is not present on every build host, and this is a stable
// kernel ABI.
struct OpenHow {
    std::uint64_t flags;
    std::uint64_t mode;
    std::uint64_t resolve;
};
constexpr long kSysOpenat2 = 437;
// confine resolution to below the dirfd. this rejects absolute paths, ".."
// climbs, and any symlink whose target leaves the subtree -- while still
// allowing ordinary nested paths and symlinks that stay inside.
constexpr std::uint64_t kResolveBeneath = 0x08;
constexpr std::uint64_t kResolveNoMagiclinks = 0x02;

// open a path that is INSIDE THE GUEST TREE, with resolution confined to it.
//
// this is the fix for a real escape. the ops that materialise a caller's file
// into the tree -- touch, and write_fd_content for --file/--bind-data -- used to
// resolve their destination with plain openat, which follows symlinks. the
// destination is under our staging root, but the directories along the way can
// belong to a bind the guest controls, so a symlink planted there redirects the
// write anywhere on the host. measured before the fix: binding a directory
// containing `out -> /tmp/victim` and asking for --file /work/out/canary wrote
// the caller's bytes to /tmp/victim/canary, outside the sandbox. bubblewrap
// refuses the same invocation.
//
// RESOLVE_BENEATH rather than RESOLVE_NO_SYMLINKS: the latter also rejects
// harmless symlinks in the middle of a legitimate path, and rather than
// RESOLVE_IN_ROOT, which silently RE-ROOTS an escaping path instead of failing.
// failing is what we want -- a policy that cannot be honoured exactly should
// stop, not be quietly reinterpreted.
//
// `root_fd` must be an O_PATH fd for the tree root; `rel` is the path with the
// root prefix stripped, so it is relative and BENEATH can apply.
//
// returns -1 with errno set. ENOSYS means the kernel predates openat2 (5.6), and
// the caller decides what to do about that -- see confined_or_plain_open.
long open_beneath(int root_fd, const char* rel, std::uint64_t flags, std::uint32_t mode) {
    OpenHow how{};
    how.flags = flags;
    how.mode = mode;
    how.resolve = kResolveBeneath | kResolveNoMagiclinks;
    return sys(kSysOpenat2, root_fd, reinterpret_cast<long>(rel),
               reinterpret_cast<long>(&how), sizeof how);
}

// the staging root every guest path lives under. it has to be known here so a
// destination can be split into "the root we trust" and "the relative part the
// guest may have influenced" -- only the second half needs confining, and
// RESOLVE_BENEATH needs a relative path to work on.
//
// kept in step with compile.cpp's kNewRoot by a static check in the test, not by
// hope: if the two ever disagree, confinement silently stops applying because
// the prefix no longer matches.
constexpr const char* kGuestRoot = "/tmp/.clay/newroot";

// strip the staging-root prefix, yielding a path relative to it. returns null if
// `path` is not under the root, which is the caller's signal that confinement
// does not apply and the path is one of OUR OWN (the staging scratch files).
const char* relative_to_guest_root(const char* path) {
    // compare against the root, stopping at the end of EITHER string. the first
    // version only checked kGuestRoot's terminator, so a shorter path -- e.g.
    // "/tmp/.clay", which really is passed here -- was read past its end. that
    // is undefined behaviour, and in practice it matched whatever followed in
    // memory and misclassified staging paths as guest paths.
    std::size_t i = 0;
    for (; kGuestRoot[i] != '\0'; ++i) {
        if (path[i] == '\0') return nullptr;  // path is a prefix of the root
        if (path[i] != kGuestRoot[i]) return nullptr;
    }
    if (path[i] == '\0') return path + i;  // the root itself
    if (path[i] != '/') return nullptr;     // a sibling like /tmp/.clay/newrootX
    while (path[i] == '/') ++i;            // BENEATH rejects a leading slash
    return path + i;
}

// open the guest tree root itself. plain openat is correct here: this path is
// ours, created by us moments earlier, with no guest-controlled component.
long open_guest_root() {
    return sys(SYS_openat, AT_FDCWD, reinterpret_cast<long>(kGuestRoot),
               O_PATH | O_DIRECTORY | O_CLOEXEC, 0);
}

// mkdir -p, confined. the same walk as mkdir_p, but each component is created
// relative to the tree root with BENEATH applied -- so a symlink planted partway
// along by a guest-controlled bind cannot redirect where the directories land.
//
// mkdirat has no open_how, so confinement is achieved by opening each directory
// with open_beneath as we descend and creating the next component relative to
// THAT fd. a symlink in the middle fails the open rather than being followed.
//
// the failure reason comes back through `err` rather than errno, because the
// close() calls on the way out overwrite errno and the caller has to distinguish
// "this kernel has no openat2" from "confinement refused this path". reading a
// clobbered errno would turn the second into the first and silently disable the
// protection.
bool mkdir_p_beneath(int root_fd, const char* rel, std::uint32_t mode, char* scratch,
                     std::size_t cap, int* err) {
    *err = 0;
    std::size_t n = cstr_len(rel);
    if (n == 0 || n >= cap) {
        *err = ENAMETOOLONG;
        return n == 0;
    }
    for (std::size_t i = 0; i <= n; ++i) scratch[i] = rel[i];

    int dir = static_cast<int>(sys(SYS_dup, root_fd, 0, 0));
    if (dir < 0) {
        *err = errno;
        return false;
    }

    std::size_t start = 0;
    while (start < n) {
        std::size_t end = start;
        while (end < n && scratch[end] != '/') ++end;
        if (end == n) break;  // the last component is the FILE, not a directory
        char saved = scratch[end];
        scratch[end] = '\0';
        if (end > start) {
            long rc = sys(SYS_mkdirat, dir, reinterpret_cast<long>(scratch + start),
                          static_cast<long>(0755));
            if (rc < 0 && errno != EEXIST) {
                *err = errno;
                sys(SYS_close, dir);
                return false;
            }
            long next = open_beneath(dir, scratch + start,
                                     O_PATH | O_DIRECTORY | O_CLOEXEC, 0);
            if (next < 0) {
                *err = errno;
                sys(SYS_close, dir);
                return false;
            }
            sys(SYS_close, dir);
            dir = static_cast<int>(next);
        }
        scratch[end] = saved;
        start = end + 1;
    }

    // create the final component, still confined.
    bool ok = true;
    if (start < n) {
        long fd = open_beneath(dir, scratch + start, O_WRONLY | O_CREAT | O_CLOEXEC, mode);
        if (fd < 0) {
            *err = errno;
            ok = (errno == EEXIST);
            if (ok) *err = 0;
        } else {
            sys(SYS_close, fd);
        }
    }
    sys(SYS_close, dir);
    return ok;
}

// is this path the guest root itself? the root has no parent inside the tree, so
// it cannot be confined -- and it does not need to be, being a fixed string in
// our own staging tmpfs with no caller-supplied component.
//
// this is a separate predicate rather than an errno from the resolver on purpose.
// the first attempt signalled it as ENOENT, but openat2 returns ENOENT for real
// reasons too, so "is this the root" and "did confinement fail" became
// indistinguishable -- and the fallback for the former is to proceed unconfined.
// an ambiguous sentinel on that branch is how a protection quietly turns off.
bool is_guest_root(const char* path) {
    const char* rel = relative_to_guest_root(path);
    return rel != nullptr && rel[0] == '\0';
}

// resolve the PARENT of a guest path safely, creating directories along the way,
// and hand back a dirfd plus the final component.
//
// this is the primitive every op that writes into the guest tree should use. the
// first version of this fix confined only --file, which was too narrow: the same
// hole existed in --symlink and in a --bind destination, both verified to plant
// things on the host through a caller-controlled symlink. the fix for "one op
// resolves unsafely" is not three patches, it is one safe primitive that all of
// them go through.
//
// on success *dirfd is owned by the caller and must be closed, and *leaf points
// into `scratch`. on failure *err carries the reason -- via out-param, not errno,
// because the close() calls here overwrite it and a clobbered errno reads as
// ENOSYS, which is exactly the value that silently disables confinement.
bool resolve_parent_beneath(const char* path, char* scratch, std::size_t cap, int* dirfd,
                            const char** leaf, int* err) {
    *err = 0;
    *dirfd = -1;
    *leaf = nullptr;

    const char* rel = relative_to_guest_root(path);
    if (!rel) {
        *err = EXDEV;  // not under the guest root: caller should not be here
        return false;
    }
    std::size_t n = cstr_len(rel);
    if (n == 0) {
        // the root itself. callers are expected to have checked is_guest_root()
        // first; reaching here means they did not, so refuse rather than guess.
        *err = EINVAL;
        return false;
    }
    if (n >= cap) {
        *err = ENAMETOOLONG;
        return false;
    }
    for (std::size_t i = 0; i <= n; ++i) scratch[i] = rel[i];

    long root = open_guest_root();
    if (root < 0) {
        *err = errno;
        return false;
    }
    int dir = static_cast<int>(root);

    std::size_t start = 0;
    while (start < n) {
        std::size_t end = start;
        while (end < n && scratch[end] != '/') ++end;
        if (end == n) break;  // the remainder is the leaf, not a directory
        char saved = scratch[end];
        scratch[end] = '\0';
        if (end > start) {
            long rc = sys(SYS_mkdirat, dir, reinterpret_cast<long>(scratch + start),
                          static_cast<long>(0755));
            if (rc < 0 && errno != EEXIST) {
                *err = errno;
                sys(SYS_close, dir);
                return false;
            }
            // the descent is what enforces confinement: each component is opened
            // BENEATH the previous one, so a symlink partway along fails the open
            // instead of being followed. resolving the whole path in one call
            // would be equivalent, but mkdirat has no open_how, so the directory
            // creation has to be interleaved anyway.
            long next = open_beneath(dir, scratch + start, O_PATH | O_DIRECTORY | O_CLOEXEC, 0);
            if (next < 0) {
                *err = errno;
                sys(SYS_close, dir);
                return false;
            }
            sys(SYS_close, dir);
            dir = static_cast<int>(next);
        }
        scratch[end] = saved;
        start = end + 1;
    }

    if (start >= n) {
        // the path was the root itself, or ended in a slash: no leaf to act on.
        *err = EINVAL;
        sys(SYS_close, dir);
        return false;
    }

    *dirfd = dir;
    *leaf = scratch + start;
    return true;
}

// mkdir -p, without allocating. walks the path in place using a scratch buffer
// the caller owns, creating each component and ignoring EEXIST.
bool mkdir_p(const char* path, std::uint32_t mode, char* scratch, std::size_t cap) {
    std::size_t len = cstr_len(path);
    if (len == 0 || len + 1 > cap) return false;
    for (std::size_t i = 0; i <= len; ++i) scratch[i] = path[i];

    for (std::size_t i = 1; i <= len; ++i) {
        if (scratch[i] != '/' && i != len) continue;
        char saved = scratch[i];
        scratch[i] = '\0';
        long rc = sys(SYS_mkdirat, AT_FDCWD, reinterpret_cast<long>(scratch),
                      static_cast<long>(mode));
        if (rc < 0 && errno != EEXIST) return false;
        scratch[i] = saved;
    }
    return true;
}

// create an empty regular file, parents included. bind-mounting a device node
// needs a file to land on, not a directory.
bool touch_file(const char* path, std::uint32_t mode, char* scratch, std::size_t cap) {
    std::size_t len = cstr_len(path);
    if (len == 0 || len + 1 > cap) return false;

    // a destination inside the guest tree gets CONFINED resolution, because the
    // directories along the way can belong to a bind the guest controls and a
    // symlink planted there would redirect this write onto the host. paths
    // outside the tree are our own staging files, where there is nothing
    // guest-controlled to resolve through.
    if (const char* rel = relative_to_guest_root(path)) {
        long root = open_guest_root();
        if (root < 0) return false;
        int err = 0;
        bool ok = mkdir_p_beneath(static_cast<int>(root), rel, mode, scratch, cap, &err);
        sys(SYS_close, root);
        if (ok) return true;
        // ENOSYS means this kernel predates openat2 (5.6). fall through to the
        // unconfined path rather than refusing to start -- but ONLY for ENOSYS.
        // EXDEV and ELOOP are confinement doing its job, and treating them as
        // "try again without protection" would defeat the entire fix.
        if (err != ENOSYS) return false;
    }

    // make the parent directory first. copy the prefix into the scratch buffer
    // and terminate it there -- the earlier version handed mkdir_p a pointer
    // PAST the string it had just written, so the parent was never created and
    // the bind mount failed with ENOENT.
    std::size_t last_slash = 0;
    for (std::size_t i = 0; i < len; ++i)
        if (path[i] == '/') last_slash = i;
    if (last_slash > 0) {
        for (std::size_t i = 0; i < last_slash; ++i) scratch[i] = path[i];
        scratch[last_slash] = '\0';
        // walk it inline rather than recursing: one buffer, no aliasing.
        for (std::size_t i = 1; i <= last_slash; ++i) {
            if (scratch[i] != '/' && i != last_slash) continue;
            char saved = scratch[i];
            scratch[i] = '\0';
            long rc = sys(SYS_mkdirat, AT_FDCWD, reinterpret_cast<long>(scratch), 0755);
            if (rc < 0 && errno != EEXIST) return false;
            scratch[i] = saved;
        }
    }

    long fd = sys(SYS_openat, AT_FDCWD, reinterpret_cast<long>(path),
                  O_WRONLY | O_CREAT | O_CLOEXEC, static_cast<long>(mode));
    if (fd < 0) return errno == EEXIST;
    sys(SYS_close, fd);
    return true;
}

// render "N N 1\n" for a uid/gid map without touching snprintf, which may
// allocate. the buffer is caller-owned and stack-allocated.
std::size_t render_identity_map(char* buf, std::size_t cap, unsigned id) {
    auto put_uint = [&](std::size_t pos, unsigned v) -> std::size_t {
        char tmp[16];
        std::size_t n = 0;
        if (v == 0) tmp[n++] = '0';
        while (v > 0) {
            tmp[n++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
        for (std::size_t i = 0; i < n && pos < cap; ++i) buf[pos++] = tmp[n - 1 - i];
        return pos;
    };
    std::size_t p = 0;
    p = put_uint(p, id);
    if (p < cap) buf[p++] = ' ';
    p = put_uint(p, id);
    if (p < cap) buf[p++] = ' ';
    if (p < cap) buf[p++] = '1';
    if (p < cap) buf[p++] = '\n';
    return p;
}

// landlock syscall numbers. not in every libc's headers yet, so we use the
// numbers directly; they are stable ABI.
constexpr long kSysLandlockCreateRuleset = 444;
constexpr long kSysLandlockAddRule = 445;
constexpr long kSysLandlockRestrictSelf = 446;

// landlock's ruleset attr has GROWN across abi versions: abi 1-3 had only
// handled_access_fs, abi 4 added handled_access_net, and later abis add more
// (abi 6 scoping, and beyond). the kernel validates the size argument against
// what IT knows, so passing sizeof(our struct) means a newer kernel reads a
// truncated struct and rejects the call.
//
// so we declare it generously and pass the size matching the abi we detected,
// never more than the kernel understands.
struct LandlockRulesetAttr {
    std::uint64_t handled_access_fs;
    std::uint64_t handled_access_net;
    std::uint64_t scoped;
    std::uint64_t reserved[3];  // room for abis we do not know about yet
};

// how many bytes of the attr this abi actually understands.
constexpr std::size_t ruleset_attr_size(std::uint32_t abi) {
    if (abi >= 6) return 3 * sizeof(std::uint64_t);  // fs + net + scoped
    if (abi >= 4) return 2 * sizeof(std::uint64_t);  // fs + net
    return sizeof(std::uint64_t);                    // fs only
}
struct LandlockPathBeneathAttr {
    std::uint64_t allowed_access;
    std::int32_t parent_fd;
} __attribute__((packed));

constexpr int kLandlockRuleTypePathBeneath = 1;

// ---------------------------------------------------------------------------
// mountinfo, for the recursive remount below.
//
// this exists because of a kernel behaviour that is very easy to get wrong: a
// bind mount DOES NOT APPLY ITS FLAGS. `mount(src, dst, MS_BIND|MS_RDONLY)`
// gives you a writable mount. you have to follow it with an explicit
// MS_REMOUNT, and -- the part that actually bites -- the remount only affects
// the top mount, not the submounts underneath it.
//
// so `--ro-bind /home /home` on a machine where /home/x is its own mount leaves
// /home/x WRITABLE. that is a silent hole, and it is why this parser is here.
// ---------------------------------------------------------------------------

// the flags we care about preserving. dropping one during a remount would
// LOOSEN the mount, so the new flags are always OR'd onto the current ones.
struct MountFlags {
    bool ro{false};
    bool nosuid{false};
    bool nodev{false};
    bool noexec{false};
    bool noatime{false};
    bool nodiratime{false};
    bool relatime{false};

    std::uint64_t to_ms() const {
        std::uint64_t f = 0;
        if (ro) f |= 1;            // MS_RDONLY
        if (nosuid) f |= 2;        // MS_NOSUID
        if (nodev) f |= 4;         // MS_NODEV
        if (noexec) f |= 8;        // MS_NOEXEC
        if (noatime) f |= 1024;    // MS_NOATIME
        if (nodiratime) f |= 2048; // MS_NODIRATIME
        if (relatime) f |= 1ull << 21;  // MS_RELATIME
        return f;
    }
};

// does `prefix` cover `path`, component-aware? same rule as the policy layer.
bool path_covers(const char* prefix, const char* path) {
    std::size_t pl = cstr_len(prefix);
    if (pl == 1 && prefix[0] == '/') return true;
    for (std::size_t i = 0; i < pl; ++i)
        if (prefix[i] != path[i]) return false;
    return path[pl] == '\0' || path[pl] == '/';
}

// unescape a mountinfo field in place: the kernel octal-escapes space, tab,
// newline and backslash. a path with a space in it would otherwise be truncated,
// and a mount we fail to see is a mount we fail to lock down.
void unescape_inplace(char* s) {
    char* w = s;
    for (char* r = s; *r; ) {
        if (r[0] == '\\' && r[1] >= '0' && r[1] <= '7' && r[2] && r[3]) {
            *w++ = static_cast<char>(((r[1] - '0') << 6) | ((r[2] - '0') << 3) | (r[3] - '0'));
            r += 4;
        } else {
            *w++ = *r++;
        }
    }
    *w = '\0';
}

// remount every mount at or under `target` with `add` OR'd into its existing
// flags. allocation-free: reads mountinfo into a caller buffer and works in
// place.
//
// returns false only on a failure that matters. a submount we cannot read is
// one the guest cannot reach either, so EACCES is ignored -- that is
// bubblewrap's reasoning and it is sound.
// the same thing in one syscall (5.12+): mount_setattr with AT_RECURSIVE sets
// attr_set on every mount in the subtree and keeps what each already had, so
// an existing noexec survives just as in the walk below. the walk rereads
// mountinfo per bind, which is O(binds x mounts) and took seconds on a
// workspace with a few thousand protected paths. false means "use the walk".
bool remount_tree_fast(const char* target, std::uint64_t add) {
#ifndef SYS_mount_setattr
    (void)target; (void)add;
    return false;
#else
    struct MountAttr {
        std::uint64_t attr_set, attr_clr, propagation, userns_fd;
    } attr{};
    // MS_* to MOUNT_ATTR_*, only the bits remount_recursive adds.
    if (add & 1) attr.attr_set |= 0x1;   // MS_RDONLY -> MOUNT_ATTR_RDONLY
    if (add & 2) attr.attr_set |= 0x2;   // MS_NOSUID -> MOUNT_ATTR_NOSUID
    if (add & 4) attr.attr_set |= 0x4;   // MS_NODEV  -> MOUNT_ATTR_NODEV
    if (add & 8) attr.attr_set |= 0x8;   // MS_NOEXEC -> MOUNT_ATTR_NOEXEC
    if (add & ~std::uint64_t{0xf}) return false;   // anything else: the walk
    constexpr long kAtRecursive = 0x8000;
    return sys(SYS_mount_setattr, AT_FDCWD, reinterpret_cast<long>(target), kAtRecursive,
               reinterpret_cast<long>(&attr), static_cast<long>(sizeof attr)) == 0;
#endif
}

bool remount_tree(const char* target, std::uint64_t add, char* buf, std::size_t cap) {
    int fd = static_cast<int>(sys(SYS_openat, AT_FDCWD,
                                 reinterpret_cast<long>("/proc/self/mountinfo"),
                                 O_RDONLY | O_CLOEXEC, 0));
    if (fd < 0) return false;
    long total = 0;
    for (;;) {
        long n = sys(SYS_read, fd, reinterpret_cast<long>(buf + total),
                     static_cast<long>(cap - 1 - static_cast<std::size_t>(total)));
        if (n <= 0) break;
        total += n;
        if (static_cast<std::size_t>(total) >= cap - 1) break;
    }
    sys(SYS_close, fd);
    if (total <= 0) return false;
    buf[total] = '\0';

    bool all_ok = true;
    char* line = buf;
    while (line && *line) {
        char* eol = nullptr;
        for (char* p = line; *p; ++p)
            if (*p == '\n') { eol = p; break; }
        if (eol) *eol = '\0';

        // mountinfo: id parent major:minor root MOUNTPOINT OPTIONS ...
        // walk to field 5 (the mount point) and field 6 (the options).
        char* f[7] = {};
        int nf = 0;
        char* p = line;
        while (nf < 7 && *p) {
            f[nf++] = p;
            while (*p && *p != ' ') ++p;
            if (*p == ' ') *p++ = '\0';
        }
        if (nf >= 6) {
            char* mp = f[4];
            char* opts = f[5];
            unescape_inplace(mp);

            if (path_covers(target, mp)) {
                // parse the existing flags. these MUST be preserved: remounting
                // with only our own flags would drop e.g. an existing noexec,
                // which loosens the mount rather than tightening it.
                MountFlags cur;
                char* o = opts;
                while (o && *o) {
                    char* comma = nullptr;
                    for (char* q = o; *q; ++q)
                        if (*q == ',') { comma = q; break; }
                    if (comma) *comma = '\0';
                    if (streq(o, "ro")) cur.ro = true;
                    else if (streq(o, "nosuid")) cur.nosuid = true;
                    else if (streq(o, "nodev")) cur.nodev = true;
                    else if (streq(o, "noexec")) cur.noexec = true;
                    else if (streq(o, "noatime")) cur.noatime = true;
                    else if (streq(o, "nodiratime")) cur.nodiratime = true;
                    else if (streq(o, "relatime")) cur.relatime = true;
                    o = comma ? comma + 1 : nullptr;
                }

                std::uint64_t current = cur.to_ms();
                std::uint64_t want = current | add;
                if (want != current) {
                    constexpr std::uint64_t kBindRemount = 4096 | 32 | 32768;  // BIND|REMOUNT|SILENT
                    if (sys(SYS_mount, reinterpret_cast<long>("none"),
                            reinterpret_cast<long>(mp), 0,
                            static_cast<long>(kBindRemount | want), 0) < 0) {
                        // a mount we cannot read is a mount the guest cannot
                        // reach, so EACCES is safe to skip. anything else means
                        // we failed to lock down something reachable.
                        if (errno != EACCES) all_ok = false;
                    }
                }
            }
        }
        line = eol ? eol + 1 : nullptr;
    }
    return all_ok;
}

}  // namespace

Status Plan::apply_range(Phase first, Phase last, ApplyFds& fds) const {
    // capture our identity BEFORE anything runs. once unshare(CLONE_NEWUSER)
    // succeeds we are in a namespace with no map yet, so getuid() returns the
    // overflow uid (65534) rather than who we actually are -- and writing that
    // into uid_map is an attempt to map a uid we do not own, which the kernel
    // rejects with EPERM. this line is the whole reason the first escape test
    // run failed.
    const unsigned real_uid = static_cast<unsigned>(::getuid());
    const unsigned real_gid = static_cast<unsigned>(::getgid());

    // landlock needs the ruleset fd to live across every rule op, so it is held
    // here rather than inside the loop. it is created by the FIRST landlock op
    // we see, which requires knowing the handled-access mask -- and that lives
    // on the enforce op. so the compiler emits enforce's mask up front by
    // creating the ruleset before any rule: we look ahead for it here.
    int ll_fd = -1;
    Error fail{};

    auto die = [&](Errc c, const char* mech, int err) {
        fail = Error{c, mech, err};
        return false;
    };

    // find the enforce op's masks before walking, so the ruleset exists by the
    // time the first rule op runs. one extra pass over a handful of ops, with
    // no allocation.
    {
        LandlockEnforceOp enf{};
        bool found = false;
        for_each([&](OpCode c, std::span<const std::byte> p) {
            if (c == OpCode::landlock_enforce) {
                found = decode(p, enf);
                return false;
            }
            return true;
        });
        if (found) {
            LandlockRulesetAttr attr{};
            attr.handled_access_fs = enf.handled_fs;
            attr.handled_access_net = enf.handled_net;
            attr.scoped = enf.scoped;
            // pass exactly the prefix this abi knows. a newer kernel expects a
            // bigger struct and an older one rejects extra fields, so the size
            // has to track the detected abi rather than sizeof(attr).
            std::size_t attr_size = ruleset_attr_size(enf.abi);
            long fd = sys(kSysLandlockCreateRuleset, reinterpret_cast<long>(&attr),
                          static_cast<long>(attr_size), 0);
            if (fd < 0) return std::unexpected(Error{Errc::permission_denied,
                                                     "landlock_create_ruleset", errno});
            ll_fd = static_cast<int>(fd);
        }
    }

    bool ok = for_each([&](OpCode code, std::span<const std::byte> payload) {
        // phase window: spawn() splits the plan so it can fork into the pid
        // namespace between the namespace and mount phases.
        Phase p = phase_of(code);
        if (p < first || p >= last) return true;
        switch (code) {
            case OpCode::unshare: {
                UnshareOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "unshare", 0);
                if (sys(SYS_unshare, static_cast<long>(op.flags)) < 0)
                    return die(Errc::permission_denied, "unshare", errno);
                return true;
            }
            case OpCode::write_file: {
                WriteFileOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "write_file", 0);
                const char* path = cstr(op.path);
                const char* content = cstr(op.content);
                if (!path || !content) return die(Errc::invalid_policy, "write_file", 0);

                // an empty content ref means "map my own id to itself", which
                // we cannot bake in at compile time because the plan may be
                // built by a different process than the one applying it. note
                // this uses the identity captured before the unshare.
                if (op.content.len == 0) {
                    char buf[64];
                    std::size_t plen = cstr_len(path);
                    bool is_gid = plen >= 7 && path[plen - 7] == 'g';  // .../gid_map
                    std::size_t n =
                        render_identity_map(buf, sizeof buf, is_gid ? real_gid : real_uid);
                    if (!write_all(path, buf, n))
                        return die(Errc::permission_denied, "id_map", errno);
                    return true;
                }
                if (!write_all(path, content, op.content.len))
                    return die(Errc::permission_denied, "write_file", errno);
                return true;
            }
            case OpCode::mkdir_p: {
                MkdirOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "mkdir", 0);
                const char* path = cstr(op.path);
                if (!path) return die(Errc::invalid_policy, "mkdir", 0);
                char scratch[4096];

                // a mount's target directory comes through here, and it is a
                // guest path. verified escape before this: with a caller-bound
                // directory containing `out -> /tmp/victim`, a --bind whose
                // destination was /work/out/mnt created the mountpoint at
                // /tmp/victim/mnt, on the host.
                //
                // the staging paths (/tmp/.clay and its newroot) also come
                // through here and are NOT under the guest root, so they take the
                // plain path -- correctly, since we create them ourselves before
                // any caller-supplied mount exists.
                //
                // note this op must create the LEAF directory too, not just the
                // parents: it is mkdir -p, and its whole job is making a
                // mountpoint exist. an earlier version of this only resolved the
                // parent and left the leaf uncreated, which broke every mount
                // with ENOENT -- including in the tests, which is how it was
                // caught.
                // the guest root itself is excluded: compile() emits a mkdir for
                // it, and that mkdir is what CREATES the directory everything
                // else is confined to. it has no parent inside the tree, and it
                // needs no confinement -- a fixed string of ours.
                if (relative_to_guest_root(path) && !is_guest_root(path)) {
                    int dir = -1;
                    const char* leaf = nullptr;
                    int err = 0;
                    if (resolve_parent_beneath(path, scratch, sizeof scratch, &dir, &leaf, &err)) {
                        const long mode = static_cast<long>(op.mode ? op.mode : 0755);
                        // created owner-only first, so the open below always
                        // succeeds -- a requested mode without owner read
                        // (--perms 0311) would make O_RDONLY fail -- and so
                        // the directory is never briefly MORE open than asked.
                        long rc = sys(SYS_mkdirat, dir, reinterpret_cast<long>(leaf),
                                      op.mode ? 0700L : mode);
                        int merr = errno;
                        // mkdirat's mode is masked by the umask, so a caller's
                        // `--perms 0775 --dir d` became 0755 under the usual
                        // 022 (bwrap sets umask(0) for exactly this). and the
                        // setuid/setgid/sticky bits are never taken from mkdir.
                        // so when WE just made the directory and a mode was
                        // asked for, set it exactly.
                        //
                        // through an fd, not fchmodat: the fchmodat syscall has
                        // no flags argument and FOLLOWS a symlink at the leaf,
                        // and the guest tree can be shared with other writers
                        // between our mkdir and our chmod. O_NOFOLLOW|O_DIRECTORY
                        // on the parent fd refuses anything but the directory.
                        if (rc == 0 && op.mode != 0) {
                            long lfd = sys(SYS_openat, dir, reinterpret_cast<long>(leaf),
                                           O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, 0);
                            long crc = lfd < 0 ? -1 : sys(SYS_fchmod, lfd, mode);
                            int cerr = errno;
                            if (lfd >= 0) sys(SYS_close, lfd);
                            if (lfd < 0 || crc < 0) {
                                sys(SYS_close, dir);
                                return die(Errc::io_error, "mkdir: chmod", cerr);
                            }
                        }
                        sys(SYS_close, dir);
                        if (rc < 0 && merr != EEXIST) return die(Errc::io_error, "mkdir", merr);
                        return true;
                    }
                    // ONLY a kernel without openat2 falls back. every other
                    // failure is confinement refusing, and must stay fatal --
                    // treating a refusal as "retry without protection" would
                    // defeat the entire change.
                    if (err != ENOSYS) return die(Errc::io_error, "mkdir (confined)", err);
                }

                if (!mkdir_p(path, op.mode, scratch, sizeof scratch))
                    return die(Errc::io_error, "mkdir", errno);
                return true;
            }
            case OpCode::touch: {
                MkdirOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "touch", 0);
                const char* path = cstr(op.path);
                if (!path) return die(Errc::invalid_policy, "touch", 0);
                char scratch[4096];
                if (!touch_file(path, op.mode, scratch, sizeof scratch))
                    return die(Errc::io_error, "touch", errno);
                return true;
            }
            case OpCode::bind_target: {
                BindTargetOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "bind_target", 0);
                const char* src = cstr(op.source);
                const char* dst = cstr(op.dest);
                if (!src || !dst) return die(Errc::invalid_policy, "bind_target", 0);

                // stat the SOURCE to decide what the mount point must be. a
                // bind of a file onto a directory fails with ENOTDIR, and vice
                // versa, so this cannot be decided at compile time -- the plan
                // may well be applied on a different machine.
                //
                // statx, not newfstatat. SYS_newfstatat does not exist on
                // 32-bit x86 (it is SYS_fstatat64 there, number 300 vs 262),
                // so the i686 release build failed to compile outright --
                // `error: use of undeclared identifier 'SYS_newfstatat'`.
                //
                // Picking the per-arch syscall would also mean picking the
                // per-arch STRUCT: the hand-rolled kstat above is the x86_64
                // layout, and i686's stat64 orders and sizes its fields
                // differently, so a build that merely compiled would have
                // read st_mode out of the wrong offset -- silently treating
                // files as directories. statx avoids both problems at once:
                // it exists on every arch the kernel supports (4.11+), and
                // struct statx has ONE layout everywhere because the kernel
                // defines it with explicit widths.
                //
                // Only st_mode is read, so ask for STATX_TYPE alone and let
                // the kernel skip the rest.
                //
                // The trailing padding is LOAD-BEARING. The kernel writes a
                // full `struct statx` -- 256 bytes, verified against
                // <linux/stat.h> on both x86_64 and i686 -- so a struct that
                // only covers the fields we read would be overwritten past
                // its end, straight into the stack. Only the prefix layout
                // matters for correctness (stx_mode at offset 28, identical
                // on both arches because the kernel fixes the widths); the
                // tail just has to EXIST.
                struct kstatx {
                    unsigned int   stx_mask, stx_blksize;
                    unsigned long long stx_attributes;
                    unsigned int   stx_nlink, stx_uid, stx_gid;
                    unsigned short stx_mode, _pad1;
                    unsigned long long stx_ino, stx_size, stx_blocks,
                                       stx_attributes_mask;
                    long long      _rest[24];
                } stx{};
                static_assert(sizeof(kstatx) >= 256,
                              "the kernel writes 256 bytes of struct statx; "
                              "a smaller buffer is a stack overwrite");
                static_assert(offsetof(kstatx, stx_mode) == 28,
                              "stx_mode must sit where the kernel puts it");
                char scratch[4096];
                constexpr int kStatxType = 0x00000001;   // STATX_TYPE
                if (sys(SYS_statx, AT_FDCWD, reinterpret_cast<long>(src),
                        0 /* flags */, kStatxType,
                        reinterpret_cast<long>(&stx)) < 0) {
                    // the source does not exist. create NOTHING: for a
                    // --bind-try the whole point is that the path is absent,
                    // and leaving an empty directory behind would be a visible
                    // difference from bubblewrap and a lie about what is there.
                    return true;
                }
                constexpr unsigned int kIfmt = 0170000, kIfdir = 0040000;
                if ((stx.stx_mode & kIfmt) == kIfdir) {
                    // a bind's mount POINT is a guest path, so it gets confined
                    // resolution -- this is the op that made `--bind src
                    // /work/out/mnt` create a directory at /tmp/victim/mnt on the
                    // host, through a symlink in a caller-bound directory.
                    if (relative_to_guest_root(dst) && !is_guest_root(dst)) {
                        int dir = -1;
                        const char* leaf = nullptr;
                        int err = 0;
                        if (resolve_parent_beneath(dst, scratch, sizeof scratch, &dir, &leaf,
                                                   &err)) {
                            long rc = sys(SYS_mkdirat, dir, reinterpret_cast<long>(leaf),
                                          static_cast<long>(0755));
                            int merr = errno;
                            sys(SYS_close, dir);
                            if (rc < 0 && merr != EEXIST)
                                return die(Errc::io_error, "bind_target: mkdir", merr);
                            return true;
                        }
                        if (err != ENOSYS)
                            return die(Errc::io_error, "bind_target: mkdir (confined)", err);
                    }
                    if (!mkdir_p(dst, 0755, scratch, sizeof scratch))
                        return die(Errc::io_error, "bind_target: mkdir", errno);
                } else {
                    // touch_file already confines guest paths internally.
                    if (!touch_file(dst, 0600, scratch, sizeof scratch))
                        return die(Errc::io_error, "bind_target: touch", errno);
                }
                return true;
            }
            case OpCode::symlink_at: {
                SymlinkOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "symlink", 0);
                const char* tgt = cstr(op.target);
                const char* lnk = cstr(op.linkpath);
                if (!tgt || !lnk) return die(Errc::invalid_policy, "symlink", 0);

                // the link's LOCATION is a guest path, so it gets confined
                // resolution. verified escape before this: with a caller-bound
                // directory containing `out -> /tmp/victim`, --symlink x
                // /work/out/planted created the symlink at /tmp/victim/planted,
                // on the host. the link's TARGET is just a string the kernel
                // stores and needs no checking -- it is interpreted later, inside
                // the sandbox, where landlock and the mount tree apply.
                if (relative_to_guest_root(lnk)) {
                    char scratch[4096];
                    int dir = -1;
                    const char* leaf = nullptr;
                    int err = 0;
                    if (resolve_parent_beneath(lnk, scratch, sizeof scratch, &dir, &leaf, &err)) {
                        long rc = sys(SYS_symlinkat, reinterpret_cast<long>(tgt), dir,
                                      reinterpret_cast<long>(leaf));
                        int serr = errno;
                        sys(SYS_close, dir);
                        if (rc < 0 && serr != EEXIST)
                            return die(Errc::io_error, "symlink", serr);
                        return true;
                    }
                    // only a kernel without openat2 falls back to the unconfined
                    // path. a refusal is confinement working.
                    if (err != ENOSYS) return die(Errc::io_error, "symlink (confined)", err);
                }

                if (sys(SYS_symlinkat, reinterpret_cast<long>(tgt), AT_FDCWD,
                        reinterpret_cast<long>(lnk)) < 0 &&
                    errno != EEXIST)
                    return die(Errc::io_error, "symlink", errno);
                return true;
            }
            case OpCode::mount: {
                MountOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "mount", 0);
                const char* src = cstr(op.source);
                const char* tgt = cstr(op.target);
                const char* fst = cstr(op.fstype);
                const char* dat = op.data.len ? cstr(op.data) : nullptr;
                if (!src || !tgt || !fst) return die(Errc::invalid_policy, "mount", 0);

                // our own "may fail" bit, above the kernel's flag range. a
                // device node missing on this host, or a --bind-try whose
                // source is absent, is not a security failure: the path simply
                // is not there, which is the safe direction.
                constexpr std::uint64_t kOptional = 1ull << 56;
                const bool optional = (op.flags & kOptional) != 0;
                const std::uint64_t flags = op.flags & ~kOptional;

                if (sys(SYS_mount, reinterpret_cast<long>(src), reinterpret_cast<long>(tgt),
                        reinterpret_cast<long>(fst), static_cast<long>(flags),
                        reinterpret_cast<long>(dat)) < 0) {
                    if (!optional) return die(Errc::permission_denied, "mount", errno);
                }
                return true;
            }
            case OpCode::remount_recursive: {
                RemountRecursiveOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "remount_rec", 0);
                const char* tgt = cstr(op.target);
                if (!tgt) return die(Errc::invalid_policy, "remount_rec", 0);

                constexpr std::uint64_t kOptional = 1ull << 56;
                const bool optional = (op.add_flags & kOptional) != 0;
                const std::uint64_t add = op.add_flags & ~kOptional;

                // a generous buffer: mountinfo on a desktop is a few KB, and we
                // cannot allocate here, so it is on the stack. if it does not
                // fit we fail rather than lock down only the mounts we saw.
                char mi[64 * 1024];
                if (!remount_tree_fast(tgt, add) && !remount_tree(tgt, add, mi, sizeof mi)) {
                    if (!optional) return die(Errc::permission_denied, "remount_rec", errno);
                }
                return true;
            }
            case OpCode::write_fd_content: {
                WriteFdContentOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "write_fd", 0);
                const char* dst = cstr(op.dest);
                if (!dst || op.fd < 0) return die(Errc::invalid_policy, "write_fd", 0);

                const bool as_bind = (op.flags & 1u) != 0;
                const bool ro = (op.flags & 2u) != 0;

                char scratch[4096];

                // for a plain file the destination IS the target. for a bind we
                // write to a scratch path first, then mount it over dest and
                // unlink the scratch -- so the bytes exist at dest and nowhere
                // else, which is the whole point of --bind-data over --file.
                const char* write_to = dst;
                char tmp_path[256];
                if (as_bind) {
                    // a fixed name inside our own staging tmpfs. it is unlinked
                    // moments later and the tmpfs is gone after the pivot, so a
                    // predictable name costs nothing here.
                    const char* base = "/tmp/.clay/bindfile";
                    std::size_t n = 0;
                    for (; base[n]; ++n) tmp_path[n] = base[n];
                    // distinguish multiple bind-datas by fd number
                    int v = op.fd;
                    tmp_path[n++] = '.';
                    if (v == 0) tmp_path[n++] = '0';
                    char digits[12];
                    std::size_t dn = 0;
                    while (v > 0) { digits[dn++] = static_cast<char>('0' + v % 10); v /= 10; }
                    while (dn > 0) tmp_path[n++] = digits[--dn];
                    tmp_path[n] = '\0';
                    write_to = tmp_path;
                } else {
                    if (!touch_file(dst, op.perms, scratch, sizeof scratch))
                        return die(Errc::io_error, "write_fd: touch", errno);
                }

                // open the destination with CONFINED resolution when it is
                // inside the guest tree. touch_file above already created it
                // safely, but creating it safely and then opening it unsafely
                // reintroduces the whole bug: between the two, nothing stops the
                // final component from being a symlink, and this open has
                // O_CREAT so it would follow one.
                //
                // the bind case writes to our own staging scratch file, which no
                // guest can influence, so it uses the plain path.
                long out = -1;
                if (const char* rel = relative_to_guest_root(write_to)) {
                    long root = open_guest_root();
                    if (root < 0) return die(Errc::io_error, "write_fd: root", errno);
                    out = open_beneath(static_cast<int>(root), rel,
                                       O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, op.perms);
                    int err = errno;
                    sys(SYS_close, root);
                    // only a kernel without openat2 falls back. a refusal is the
                    // protection working and must stay a failure.
                    if (out < 0 && err != ENOSYS)
                        return die(Errc::io_error, "write_fd: open dest (confined)", err);
                }
                if (out < 0)
                    out = sys(SYS_openat, AT_FDCWD, reinterpret_cast<long>(write_to),
                              O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                              static_cast<long>(op.perms));
                if (out < 0) return die(Errc::io_error, "write_fd: open dest", errno);

                // the exact mode, set on the fd we hold. O_CREAT's mode is
                // masked by the umask (and is ignored when touch_file already
                // made the file), so `--perms 0640 --file` gave 0644 or worse.
                // bwrap fchmods for the same reason. on the fd, so no path is
                // re-resolved and nothing can be swapped in between.
                if (sys(SYS_fchmod, out, static_cast<long>(op.perms)) < 0) {
                    int err = errno;
                    sys(SYS_close, out);
                    return die(Errc::io_error, "write_fd: chmod", err);
                }

                // copy. a fixed stack buffer, no allocation: this runs post-fork.
                char buf[65536];
                for (;;) {
                    long n = sys(SYS_read, op.fd, reinterpret_cast<long>(buf),
                                 static_cast<long>(sizeof buf));
                    if (n == 0) break;
                    if (n < 0) {
                        sys(SYS_close, out);
                        return die(Errc::io_error, "write_fd: read", errno);
                    }
                    long off = 0;
                    while (off < n) {
                        long w = sys(SYS_write, out, reinterpret_cast<long>(buf + off),
                                     n - off);
                        if (w <= 0) {
                            sys(SYS_close, out);
                            return die(Errc::io_error, "write_fd: write", errno);
                        }
                        off += w;
                    }
                }
                sys(SYS_close, out);

                if (as_bind) {
                    if (!touch_file(dst, op.perms, scratch, sizeof scratch))
                        return die(Errc::io_error, "write_fd: bind target", errno);
                    std::uint64_t flags = 4096 /*MS_BIND*/ | 2 /*MS_NOSUID*/;
                    if (sys(SYS_mount, reinterpret_cast<long>(write_to),
                            reinterpret_cast<long>(dst), 0, static_cast<long>(flags), 0) < 0)
                        return die(Errc::permission_denied, "write_fd: bind", errno);
                    if (ro) {
                        std::uint64_t rf = flags | 32 /*MS_REMOUNT*/ | 1 /*MS_RDONLY*/;
                        if (sys(SYS_mount, reinterpret_cast<long>("none"),
                                reinterpret_cast<long>(dst), 0, static_cast<long>(rf), 0) < 0)
                            return die(Errc::permission_denied, "write_fd: remount ro", errno);
                    }
                    // unlink the backing file. the mount keeps it alive, but it
                    // now has NO NAME, so even a guest that escapes the tree has
                    // no path by which to reopen it. bubblewrap does the same and
                    // the reasoning is worth copying: belt and braces on top of
                    // it already being outside the new root.
                    sys(SYS_unlinkat, AT_FDCWD, reinterpret_cast<long>(write_to), 0);
                }
                return true;
            }
            case OpCode::pivot_root: {
                PivotRootOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "pivot_root", 0);
                const char* nr = cstr(op.new_root);
                const char* po = cstr(op.put_old);
                if (!nr || !po) return die(Errc::invalid_policy, "pivot_root", 0);
                // pivot_root requires the new root to be a mount point and the
                // cwd to be inside it, otherwise it returns EINVAL for reasons
                // that are very hard to read off the symptom.
                if (sys(SYS_chdir, reinterpret_cast<long>(nr)) < 0)
                    return die(Errc::io_error, "pivot_root: chdir", errno);
                if (sys(SYS_pivot_root, reinterpret_cast<long>(nr), reinterpret_cast<long>(po)) < 0)
                    return die(Errc::permission_denied, "pivot_root", errno);
                if (sys(SYS_chdir, reinterpret_cast<long>("/")) < 0)
                    return die(Errc::io_error, "pivot_root: chdir /", errno);
                return true;
            }
            case OpCode::pivot_into_newroot: {
                PivotRootOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "pivot2", 0);
                const char* nr = cstr(op.new_root);
                if (!nr) return die(Errc::invalid_policy, "pivot2", 0);

                // bubblewrap's trick. keep an fd on the CURRENT root, chdir into
                // the new one, then pivot_root(".", ".").
                //
                // the kernel documents put_old as needing to be underneath
                // new_root, but passing the same directory is explicitly fine
                // and is what runc and lxc do: it stacks the old root on top of
                // itself. we then fchdir back to the old root through the fd we
                // kept and detach it -- which leaves NO oldroot directory in the
                // guest's tree at all. doing it the documented way leaves a
                // visible mount point the guest can see even after the detach.
                long oldfd = sys(SYS_openat, AT_FDCWD, reinterpret_cast<long>("/"),
                                 O_DIRECTORY | O_RDONLY | O_CLOEXEC, 0);
                if (oldfd < 0) return die(Errc::io_error, "pivot2: open /", errno);

                if (sys(SYS_chdir, reinterpret_cast<long>(nr)) < 0) {
                    sys(SYS_close, oldfd);
                    return die(Errc::io_error, "pivot2: chdir newroot", errno);
                }
                if (sys(SYS_pivot_root, reinterpret_cast<long>("."),
                        reinterpret_cast<long>(".")) < 0) {
                    sys(SYS_close, oldfd);
                    return die(Errc::permission_denied, "pivot2: pivot_root", errno);
                }
                // step back into the old root via the fd, and detach it.
                if (sys(SYS_fchdir, oldfd) < 0) {
                    sys(SYS_close, oldfd);
                    return die(Errc::io_error, "pivot2: fchdir", errno);
                }
                sys(SYS_close, oldfd);

                // MNT_DETACH the old root. while it is mounted the entire host
                // filesystem is reachable, so a failure here is fatal.
                if (sys(SYS_umount2, reinterpret_cast<long>("."), 2 /* MNT_DETACH */) < 0)
                    return die(Errc::permission_denied, "pivot2: umount oldroot", errno);

                if (sys(SYS_chdir, reinterpret_cast<long>("/")) < 0)
                    return die(Errc::io_error, "pivot2: chdir /", errno);
                return true;
            }
            case OpCode::umount: {
                UmountOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "umount", 0);
                const char* t = cstr(op.target);
                if (!t) return die(Errc::invalid_policy, "umount", 0);
                if (sys(SYS_umount2, reinterpret_cast<long>(t), static_cast<long>(op.flags)) < 0)
                    return die(Errc::permission_denied, "umount", errno);
                // detaching the old root is not optional: while it is mounted,
                // the entire host filesystem is reachable through it and the
                // pivot bought us nothing. so also remove the mount point, and
                // treat a failure as fatal rather than cosmetic.
                sys(SYS_unlinkat, AT_FDCWD, reinterpret_cast<long>(t), 0x200 /* AT_REMOVEDIR */);
                return true;
            }
            case OpCode::dup2: {
                Dup2Op op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "dup2", 0);
                if (sys(SYS_dup3, op.from, op.to, 0) < 0)
                    return die(Errc::io_error, "dup2", errno);
                return true;
            }
            case OpCode::close_range: {
                CloseRangeOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "close_range", 0);

                // a leaked fd is a capability the sandbox never agreed to grant:
                // landlock mediates path RESOLUTION, and an already-open fd needs
                // none, so no wall we build can revoke one. closing them is the
                // only option.
                //
                // two kinds must survive, though:
                //   - the landlock ruleset fd, created before this op and used
                //     after it.
                //   - spawn()'s report pipe, or a later failure reaches the
                //     parent as a bare exit code with no reason attached.
                //
                // close_range() cannot express an exception, so rather than walk
                // /proc/self/fd (which needs dirent parsing in a no-allocation
                // context, and which I got wrong the first time in a way that
                // silently closed stdout) we sort the small keep set and issue
                // close_range over the gaps between them. bounded, obvious, and
                // impossible to get subtly wrong.
                std::uint32_t keep[32];
                std::uint32_t nkeep = 0;
                if (ll_fd >= 0) keep[nkeep++] = static_cast<std::uint32_t>(ll_fd);
                for (std::uint32_t k = 0; k < op.keep_count && nkeep < 32; ++k) {
                    std::uint32_t want = op.keep[k];
                    if (want == kReportFdSentinel) want = fds.report;
                    else if (want == kProxyListenFdSentinel) want = fds.proxy_keep;
                    else if (want == kRelayFdSentinel) want = fds.relay;
                    else if (want == kRelayFd2Sentinel) want = fds.relay2;
                    else if (want >= kPreservedFdSentinelBase &&
                             want < kPreservedFdSentinelBase + kMaxPreservedFds)
                        want = fds.preserved[want - kPreservedFdSentinelBase];
                    if (want != 0xffffffffu) keep[nkeep++] = want;
                }
                // insertion sort; nkeep is tiny and this needs no allocation.
                for (std::uint32_t i2 = 1; i2 < nkeep; ++i2) {
                    std::uint32_t v = keep[i2];
                    std::uint32_t j = i2;
                    while (j > 0 && keep[j - 1] > v) { keep[j] = keep[j - 1]; --j; }
                    keep[j] = v;
                }

                std::uint32_t from = op.lo;
                for (std::uint32_t k = 0; k < nkeep; ++k) {
                    if (keep[k] < from) continue;
                    if (keep[k] > from)
                        sys(SYS_close_range, static_cast<long>(from),
                            static_cast<long>(keep[k] - 1), 0);
                    from = keep[k] + 1;
                }
                if (from <= op.hi)
                    sys(SYS_close_range, static_cast<long>(from), static_cast<long>(op.hi), 0);
                return true;
            }
            case OpCode::set_hostname: {
                SetHostnameOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "sethostname", 0);
                const char* n = cstr(op.name);
                if (!n) return die(Errc::invalid_policy, "sethostname", 0);
                // best effort: fails without a uts namespace, which is not fatal
                sys(SYS_sethostname, reinterpret_cast<long>(n),
                    static_cast<long>(cstr_len(n)));
                return true;
            }
            case OpCode::chdir: {
                ChdirOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "chdir", 0);
                const char* path = cstr(op.path);
                if (!path) return die(Errc::invalid_policy, "chdir", 0);
                if (sys(SYS_chdir, reinterpret_cast<long>(path)) < 0)
                    return die(Errc::io_error, "chdir", errno);
                return true;
            }
            case OpCode::new_session: {
                // setsid detaches us from the controlling terminal. it fails with
                // EPERM if we are already a process group leader, which is
                // harmless -- we are then already in our own session.
                sys(SYS_setsid);
                return true;
            }
            case OpCode::die_with_parent: {
                // PR_SET_PDEATHSIG fires when our PARENT dies, so it has to be
                // set in the process that is actually the supervisor's child.
                // spawn() forks twice for the pid namespace, so this is set in
                // the guest and tracks the in-namespace shepherd (pid 1), which
                // itself tracks the outer child: if either goes, the sandbox
                // goes with it.
                if (::prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) < 0)
                    return die(Errc::io_error, "die_with_parent", errno);
                return true;
            }
            case OpCode::set_rlimit: {
                SetRlimitOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "setrlimit", 0);
                struct rlimit64 {
                    std::uint64_t cur, max;
                } rl{op.soft, op.hard};
                if (sys(SYS_prlimit64, 0, op.resource, reinterpret_cast<long>(&rl), 0) < 0)
                    return die(Errc::permission_denied, "setrlimit", errno);
                return true;
            }
            case OpCode::loopback_up: {
                LoopbackOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "loopback_up", 0);
                // a fresh netns has `lo` DOWN, so even 127.0.0.1 is unreachable.
                // ioctl on a throwaway socket rather than netlink: no
                // allocation, no message building, and it is the one call that
                // is safe this side of a fork.
                constexpr long kAfInet = 2;
                constexpr long kSockStream = 1;
                constexpr long kSockDgram = 2;
                constexpr long kSockCloexec = 0x80000;
                const long fd = sys(SYS_socket, kAfInet, kSockDgram | kSockCloexec, 0);
                if (fd < 0) return die(Errc::io_error, "loopback_up: socket", errno);
                // from <net/if.h> and <linux/sockios.h>, named here so this
                // file keeps its short include list. struct ifreq is 40 bytes
                // with flags at offset 16 (asserted in plan_test).
                constexpr unsigned long kSiocGifFlags = 0x8913;
                constexpr unsigned long kSiocSifFlags = 0x8914;
                constexpr short kIffUp = 0x1;
                constexpr short kIffRunning = 0x40;
                struct ifreq_min {
                    char name[16];
                    short flags;
                    char pad[22];
                } ifr{};
                ifr.name[0] = 'l'; ifr.name[1] = 'o'; ifr.name[2] = '\0';
                if (sys(SYS_ioctl, fd, static_cast<long>(kSiocGifFlags),
                        reinterpret_cast<long>(&ifr)) < 0) {
                    const int e = errno;
                    sys(SYS_close, fd);
                    return die(Errc::io_error, "loopback_up: get", e);
                }
                ifr.flags = static_cast<short>(ifr.flags | kIffUp | kIffRunning);
                if (sys(SYS_ioctl, fd, static_cast<long>(kSiocSifFlags),
                        reinterpret_cast<long>(&ifr)) < 0) {
                    const int e = errno;
                    sys(SYS_close, fd);
                    return die(Errc::permission_denied, "loopback_up: set", e);
                }
                sys(SYS_close, fd);
                if (op.listen_backlog == 0) return true;

                // the proxy listener, bound to 127.0.0.1:0 so the kernel picks
                // a free port. the supervisor accepts on this descriptor from
                // OUTSIDE the namespace, which is allowed: an accepted socket
                // belongs to the listener, not to the caller's namespace.
                struct sockaddr_in_min {
                    std::uint16_t family;
                    std::uint16_t port;      // network order
                    std::uint32_t addr;      // network order
                    char zero[8];
                } sa{};
                sa.family = 2;  // AF_INET
                {
                    unsigned char* pb = reinterpret_cast<unsigned char*>(&sa.port);
                    pb[0] = static_cast<unsigned char>((op.port >> 8) & 0xff);
                    pb[1] = static_cast<unsigned char>(op.port & 0xff);
                }
                // 127.0.0.1 in network byte order, written byte-wise so this
                // does not depend on htonl.
                {
                    unsigned char* b = reinterpret_cast<unsigned char*>(&sa.addr);
                    b[0] = 127; b[1] = 0; b[2] = 0; b[3] = 1;
                }
                const long lfd = sys(SYS_socket, kAfInet, kSockStream | kSockCloexec, 0);
                if (lfd < 0) return die(Errc::io_error, "loopback_up: listen socket", errno);
                if (sys(SYS_bind, lfd, reinterpret_cast<long>(&sa), sizeof sa) < 0) {
                    const int e = errno;
                    sys(SYS_close, lfd);
                    return die(Errc::io_error, "loopback_up: bind", e);
                }
                if (sys(SYS_listen, lfd, static_cast<long>(op.listen_backlog)) < 0) {
                    const int e = errno;
                    sys(SYS_close, lfd);
                    return die(Errc::io_error, "loopback_up: listen", e);
                }
                {
                    sockaddr_in_min got{};
                    std::uint32_t len = sizeof got;
                    if (sys(SYS_getsockname, lfd, reinterpret_cast<long>(&got),
                            reinterpret_cast<long>(&len)) < 0) {
                        const int e = errno;
                        sys(SYS_close, lfd);
                        return die(Errc::io_error, "loopback_up: getsockname", e);
                    }
                    const unsigned char* pb =
                        reinterpret_cast<const unsigned char*>(&got.port);
                    fds.proxy_port =
                        static_cast<std::uint16_t>((pb[0] << 8) | pb[1]);
                }
                fds.proxy_listen_fd = static_cast<int>(lfd);
                // keep it out of the close sweep, here and in every descendant
                // that inherits it: see kProxyListenFdSentinel.
                fds.proxy_keep = static_cast<std::uint32_t>(lfd);
                // which netns did this land in? the supervisor logs it next to
                // the guest's own, because "bound, but somewhere unreachable"
                // is the one failure that looks like success here.
                {
                    char buf[64];
                    const long nf = sys(SYS_readlinkat, -100 /* AT_FDCWD */,
                                        reinterpret_cast<long>("/proc/self/ns/net"),
                                        reinterpret_cast<long>(buf), sizeof buf - 1);
                    if (nf > 0) {
                        buf[nf] = '\0';
                        std::uint64_t ino = 0;
                        for (const char* p = buf; *p; ++p)
                            if (*p >= '0' && *p <= '9') ino = ino * 10 + std::uint64_t(*p - '0');
                        fds.proxy_netns_ino = ino;
                    }
                }
                return true;
            }
            case OpCode::set_ids: {
                SetIdsOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "setids", 0);
                // gid first: after setuid we may no longer be allowed to setgid.
                if (sys(SYS_setgid, op.gid) < 0)
                    return die(Errc::permission_denied, "setgid", errno);
                if (sys(SYS_setuid, op.uid) < 0)
                    return die(Errc::permission_denied, "setuid", errno);
                return true;
            }
            case OpCode::landlock_rule: {
                LandlockRuleOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "landlock", 0);
                if (ll_fd < 0) return die(Errc::invalid_policy, "landlock: rule before enforce", 0);
                const char* path = cstr(op.path);
                if (!path) return die(Errc::invalid_policy, "landlock", 0);

                long fd = sys(SYS_openat, AT_FDCWD, reinterpret_cast<long>(path),
                              O_PATH | O_CLOEXEC, 0);
                if (fd < 0) {
                    // a grant for a path that does not exist is not an escape
                    // risk -- there is nothing to reach -- so skip it rather
                    // than refusing to start.
                    return true;
                }
                LandlockPathBeneathAttr attr{op.allowed, static_cast<std::int32_t>(fd)};
                long rc = sys(kSysLandlockAddRule, ll_fd, kLandlockRuleTypePathBeneath,
                              reinterpret_cast<long>(&attr), 0);
                if (rc < 0 && errno == EINVAL) {
                    // landlock rejects directory-only rights on a regular file.
                    // the compiler cannot know which a path is (the plan may be
                    // applied elsewhere), so retry with the file-applicable
                    // subset rather than failing the whole sandbox.
                    constexpr std::uint64_t kFileOnly =
                        (1ull << 0) | (1ull << 1) | (1ull << 2) | (1ull << 14);
                    attr.allowed_access = op.allowed & kFileOnly;
                    if (attr.allowed_access != 0)
                        rc = sys(kSysLandlockAddRule, ll_fd, kLandlockRuleTypePathBeneath,
                                 reinterpret_cast<long>(&attr), 0);
                }
                sys(SYS_close, fd);
                if (rc < 0) return die(Errc::permission_denied, "landlock_add_rule", errno);
                return true;
            }
            case OpCode::landlock_net_rule: {
                LandlockNetRuleOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "landlock_net", 0);
                if (ll_fd < 0) return die(Errc::invalid_policy, "landlock_net: no ruleset", 0);

                // LANDLOCK_RULE_NET_PORT == 2. the port goes in host byte order,
                // which is worth stating because every other network API in the
                // kernel wants network order and getting it wrong here silently
                // permits a completely different port.
                struct NetPortAttr {
                    std::uint64_t allowed_access;
                    std::uint64_t port;
                } attr{op.allowed, op.port};
                if (sys(kSysLandlockAddRule, ll_fd, 2 /* NET_PORT */,
                        reinterpret_cast<long>(&attr), 0) < 0) {
                    // an older kernel that reported abi>=4 but lacks net support
                    // gives EINVAL. that is a degradation, not a failure: the
                    // filesystem rules still hold, and compile() already declined
                    // to claim `strong` unless every port was expressible.
                    if (errno != EINVAL)
                        return die(Errc::permission_denied, "landlock_net_rule", errno);
                }
                return true;
            }
            case OpCode::landlock_enforce: {
                LandlockEnforceOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "landlock", 0);
                if (ll_fd < 0) return die(Errc::invalid_policy, "landlock: no ruleset", 0);
                if (sys(kSysLandlockRestrictSelf, ll_fd, 0) < 0)
                    return die(Errc::permission_denied, "landlock_restrict_self", errno);
                sys(SYS_close, ll_fd);
                ll_fd = -1;
                return true;
            }
            case OpCode::drop_caps: {
                DropCapsOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "drop_caps", 0);
                // drop the bounding set so no exec can ever regain a capability.
                // CAP_LAST_CAP moves with kernels; walk until EINVAL.
                for (int cap = 0; cap <= 63; ++cap) {
                    if (op.keep & (1ull << cap)) continue;
                    if (::prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) < 0 && errno == EINVAL) break;
                }
                return true;
            }
            case OpCode::no_new_privs: {
                if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
                    return die(Errc::permission_denied, "no_new_privs", errno);
                return true;
            }
            case OpCode::seccomp_install: {
                SeccompInstallOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "seccomp", 0);
                auto blob = this->blob(op.program);
                if (blob.empty() || op.insn_count == 0)
                    return die(Errc::invalid_policy, "seccomp: empty program", 0);

                struct sock_fprog prog {
                    static_cast<unsigned short>(op.insn_count),
                        reinterpret_cast<struct sock_filter*>(
                            const_cast<std::byte*>(blob.data()))
                };

                // if the policy has any notify action, ask the kernel for a
                // listener fd. SECCOMP_FILTER_FLAG_NEW_LISTENER makes the return
                // value the fd rather than 0.
                //
                // the fd has to get back to the SUPERVISOR, which is a different
                // process -- so it goes over the report pipe as ancillary data.
                // there is no other channel: by this point we are about to exec
                // and everything else is closed.
                constexpr unsigned long kFlagNewListener = 8;
                if (op.flags & 1u) {
                    long lfd = sys(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                                   static_cast<long>(kFlagNewListener),
                                   reinterpret_cast<long>(&prog));
                    if (lfd < 0)
                        return die(Errc::permission_denied, "seccomp: new_listener", errno);
                    fds.notify_fd = static_cast<int>(lfd);
                    return true;
                }

                if (sys(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0,
                        reinterpret_cast<long>(&prog)) < 0)
                    return die(Errc::permission_denied, "seccomp", errno);
                return true;
            }
        }
        return die(Errc::invalid_policy, "unknown opcode", 0);
    });

    // defensive: a plan with landlock rules but no enforce op would leave this
    // open. well_ordered() plus compile() make that unreachable, but an fd leak
    // into the guest is a capability leak, so close it anyway.
    if (ll_fd >= 0) sys(SYS_close, ll_fd);

    if (!ok) return std::unexpected(fail);
    return {};
}

}  // namespace clay

#else  // not linux

namespace clay {

Status Plan::apply_range(Phase, Phase, ApplyFds&) const {
    return std::unexpected(Error{Errc::unsupported, "plan::apply: linux only"});
}

}  // namespace clay

#endif
