// claybin: the compiled plan.
//
// everything that can fail, allocate, take a lock, or call into libc happens
// while BUILDING a plan. applying one is a loop of raw syscalls: no malloc, no
// locks, no libc paths that touch the allocator, no unbounded work. that is
// what makes it async-signal-safe after clone(), and it is why spawning from an
// already-compiled plan costs about what the kernel costs.
//
// the arena is position-independent: ops refer to strings by (offset, length)
// into the same buffer, never by pointer. so a plan can be memcpy'd, placed in
// shared memory, or written down a pipe and applied by a different process.
//
// this header is pure. encoding, decoding and the ordering checks are all
// testable on a machine with no seccomp, no landlock and no kernel headers.
// only apply() is linux, and it lives in its own translation unit.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "claybin/core/error.hpp"

namespace clay {

// ---------------------------------------------------------------------------
// phases
//
// the ORDER of setup steps is a security property, not a style choice:
//
//   - mounts must happen after the namespaces that contain them
//   - landlock must come after mounts, or it locks down a tree that is about
//     to be replaced
//   - no_new_privs must precede BOTH landlock and seccomp. the kernel requires
//     it for landlock_restrict_self and for an unprivileged seccomp filter, and
//     without it an suid exec re-grants privilege across the wall we just
//     built. this cost an afternoon: landlock_restrict_self returns EPERM with
//     no explanation when nnp is unset, which surfaces later as an EACCES from
//     execve and looks exactly like a missing path grant.
//   - seccomp goes LAST, because a filter that denies mount/openat would
//     otherwise block the rest of our own setup
//
// so every op carries a phase, and a plan is only valid if phases are
// non-decreasing. that turns "we remembered the right order" into something
// the compiler checks and a test can prove for every policy.
// ---------------------------------------------------------------------------

enum class Phase : std::uint8_t {
    namespaces = 0,  // unshare, uid/gid maps
    mounts = 1,      // mount, pivot_root, umount
    fds = 2,         // dup2, close_range
    process = 3,     // hostname, chdir, rlimits, uid/gid
    privdrop = 4,    // no_new_privs, capability drop -- REQUIRED before landlock
    landlock = 5,    // filesystem/network restriction
    seccomp = 6,     // the last wall
    count_,
};

constexpr const char* to_string(Phase p) {
    switch (p) {
        case Phase::namespaces: return "namespaces";
        case Phase::mounts: return "mounts";
        case Phase::fds: return "fds";
        case Phase::process: return "process";
        case Phase::privdrop: return "privdrop";
        case Phase::landlock: return "landlock";
        case Phase::seccomp: return "seccomp";
        case Phase::count_: break;
    }
    return "?";
}

enum class OpCode : std::uint16_t {
    unshare = 1,
    write_file,     // uid_map, gid_map, setgroups: small writes with no libc
    mount,
    // remount a bind AND every submount under it, OR-ing flags onto whatever
    // each already has. a plain bind does not apply its flags, and a plain
    // remount only touches the top mount -- so without this a --ro-bind of a
    // tree containing its own submounts leaves those submounts WRITABLE.
    remount_recursive,
    mkdir_p,        // create a mount point (and its parents) inside the new tree
    touch,          // create an empty file as a bind target for a device node
    bind_target,    // create a mount point matching the SOURCE's kind (dir or file)
    symlink_at,     // /lib -> usr/lib, the usr-merge layout every distro needs
    // copy a caller-held fd's contents into the tree. with the bind flag set,
    // the bytes go to a temp file which is bound at `dest` and then UNLINKED, so
    // the backing file has no name the guest could open.
    write_fd_content,
    pivot_root,
    // the second half of bubblewrap's pivot dance: chdir into newroot, then
    // pivot_root(".", ".") so the old root stacks on top of itself and can be
    // detached leaving NO directory behind in the guest's tree.
    pivot_into_newroot,
    umount,
    dup2,
    close_range,    // close inherited descriptors. see Phase::fds for the order
                    // reasoning: this has to be LATE, after every fd the plan
                    // itself needs has been used.
    set_hostname,
    chdir,
    new_session,      // setsid: detach from the host's controlling terminal
    die_with_parent,  // PR_SET_PDEATHSIG, so an orphan cannot linger
    set_rlimit,
    set_ids,
    landlock_rule,
    // landlock network rule (abi 4+): mediate TCP bind/connect by PORT. a real
    // second wall over a netns, which is all-or-nothing.
    landlock_net_rule,
    landlock_enforce,
    drop_caps,
    no_new_privs,
    // PR_SET_MDWE: the kernel refuses to let this process GAIN execute on
    // writable memory, for its whole life.
    //
    // the seccomp W^X rule checks mmap/mprotect arguments one call at a time,
    // so it stops `mmap(PROT_WRITE|PROT_EXEC)` and misses the sequence that
    // every real JIT-shellcode path actually uses: map it writable, write to
    // it, then mprotect it executable. two individually innocent calls.
    // measured: that sequence succeeded under the arg filter alone.
    //
    // MDWE is a process property rather than a syscall predicate, so it sees
    // the transition instead of the call. it is strictly stronger and costs
    // one prctl.
    memory_deny_write_execute,
    seccomp_install,
    // bring `lo` up inside a fresh network namespace, and (when the policy
    // asked for proxied network) open a listening socket on 127.0.0.1 there.
    //
    // a new netns has a loopback device but it is DOWN, so 127.0.0.1 is
    // unreachable until someone flips IFF_UP -- which needs CAP_NET_ADMIN,
    // and we have it in our own user namespace. no address to assign:
    // 127.0.0.1/8 is built in.
    //
    // the listener exists because only a process INSIDE the namespace can
    // create one: setns(pidfd, CLONE_NEWNET) from the supervisor is EPERM
    // (it would need CAP_SYS_ADMIN in the guest's user namespace). so the
    // guest's own setup opens it and hands the descriptor back, and the
    // supervisor accepts on it from outside. apply() writes the fd and port
    // into ApplyFds.
    loopback_up,
};

constexpr Phase phase_of(OpCode c) {
    switch (c) {
        case OpCode::unshare:
        case OpCode::write_file: return Phase::namespaces;
        case OpCode::mount:
        case OpCode::remount_recursive:
        case OpCode::mkdir_p:
        case OpCode::touch:
        case OpCode::bind_target:
        case OpCode::symlink_at:
        case OpCode::write_fd_content:
        case OpCode::pivot_root:
        case OpCode::pivot_into_newroot:
        case OpCode::umount: return Phase::mounts;
        // the loopback listener belongs to the OUTER setup process: the
        // namespace phase runs before the fork into the pid namespace, so the
        // descriptor is held by a process that outlives the guest's exec.
        // anywhere later it would be the guest's own fd and die with exec,
        // leaving nothing listening.
        case OpCode::loopback_up: return Phase::namespaces;
        case OpCode::dup2: return Phase::fds;
        // close_range lives in privdrop, not fds. it has to run AFTER the mount
        // phase (which uses --file source fds) and after the landlock ruleset fd
        // exists, or it closes the very descriptors the rest of the plan needs.
        // putting it next to the other "give up capability" ops is also the
        // honest description of what it is.
        case OpCode::close_range: return Phase::privdrop;
        case OpCode::set_hostname:
        case OpCode::chdir:
        case OpCode::new_session:
        case OpCode::die_with_parent:
        case OpCode::set_rlimit:
        case OpCode::set_ids: return Phase::process;
        case OpCode::landlock_rule:
        case OpCode::landlock_net_rule:
        case OpCode::landlock_enforce: return Phase::landlock;
        case OpCode::drop_caps:
        case OpCode::no_new_privs: return Phase::privdrop;
        // with nnp: both are irreversible process properties, and MDWE must be
        // set before the guest's own code runs.
        case OpCode::memory_deny_write_execute: return Phase::privdrop;
        case OpCode::seccomp_install: return Phase::seccomp;
    }
    return Phase::seccomp;
}

constexpr const char* to_string(OpCode c) {
    switch (c) {
        case OpCode::unshare: return "unshare";
        case OpCode::write_file: return "write_file";
        case OpCode::mount: return "mount";
        case OpCode::remount_recursive: return "remount_rec";
        case OpCode::mkdir_p: return "mkdir_p";
        case OpCode::touch: return "touch";
        case OpCode::bind_target: return "bind_target";
        case OpCode::symlink_at: return "symlink";
        case OpCode::write_fd_content: return "write_fd";
        case OpCode::loopback_up: return "loopback_up";
        case OpCode::memory_deny_write_execute: return "mdwe";
        case OpCode::pivot_root: return "pivot_root";
        case OpCode::pivot_into_newroot: return "pivot_newroot";
        case OpCode::umount: return "umount";
        case OpCode::dup2: return "dup2";
        case OpCode::close_range: return "close_range";
        case OpCode::set_hostname: return "set_hostname";
        case OpCode::chdir: return "chdir";
        case OpCode::new_session: return "new_session";
        case OpCode::die_with_parent: return "die_with_parent";
        case OpCode::set_rlimit: return "set_rlimit";
        case OpCode::set_ids: return "set_ids";
        case OpCode::landlock_rule: return "landlock_rule";
        case OpCode::landlock_net_rule: return "landlock_net";
        case OpCode::landlock_enforce: return "landlock_enforce";
        case OpCode::drop_caps: return "drop_caps";
        case OpCode::no_new_privs: return "no_new_privs";
        case OpCode::seccomp_install: return "seccomp_install";
    }
    return "?";
}

// a blob living inside the arena. an offset, never a pointer, so the arena
// stays relocatable. strings are stored with a trailing nul so the post-fork
// path can hand `arena + off` straight to a syscall with no copy.
struct Ref {
    std::uint32_t off{0};
    std::uint32_t len{0};

    friend constexpr bool operator==(const Ref&, const Ref&) = default;
};

// every op starts with this. `size` covers the header plus payload, so a
// decoder can skip an op it does not know without understanding it.
struct OpHeader {
    std::uint16_t code;
    std::uint16_t size;
    std::uint32_t _pad;
};
static_assert(sizeof(OpHeader) == 8);

// ---- payloads. all fields fixed-width, 8-byte aligned, no padding holes ----

struct UnshareOp {
    std::uint64_t flags;
};
struct WriteFileOp {
    Ref path;
    Ref content;
};
struct MountOp {
    Ref source;
    Ref target;
    Ref fstype;
    Ref data;
    std::uint64_t flags;
};
struct PivotRootOp {
    Ref new_root;
    Ref put_old;
};
struct MkdirOp {
    Ref path;
    std::uint32_t mode;
    std::uint32_t _pad;
};
struct SymlinkOp {
    Ref target;
    Ref linkpath;
};
// create a mount point whose KIND matches the source: a directory for a
// directory, an empty regular file for a file. binding a file onto a directory
// fails with ENOTDIR, and the source can only be stat'd on the machine that
// applies the plan.
struct BindTargetOp {
    Ref source;
    Ref dest;
};
// copy `fd`'s contents to `dest`. flags bit 0 = bind it in and unlink the
// backing file, bit 1 = make that bind read-only.
struct WriteFdContentOp {
    Ref dest;
    std::int32_t fd;
    std::uint32_t perms;
    std::uint32_t flags;
    std::uint32_t _pad;
};
struct UmountOp {
    Ref target;
    std::uint64_t flags;
};
// remount `target` and everything under it, adding `add_flags` to each mount's
// existing flags. `optional` mirrors the mount op's bit.
struct RemountRecursiveOp {
    Ref target;
    std::uint64_t add_flags;
};
struct Dup2Op {
    std::int32_t from;
    std::int32_t to;
};
struct CloseRangeOp {
    std::uint32_t lo;
    std::uint32_t hi;
    // descriptors to spare. close_range() itself cannot express an exception, so
    // apply() walks /proc/self/fd when this is non-empty. small and fixed: the
    // report pipe, the two broker relay ends, any --file source not yet copied,
    // and the slots reserved for descriptors the caller asks spawn() to carry
    // into the guest (kPreservedFdSentinelBase, kMaxPreservedFds of them).
    std::uint32_t keep_count;
    std::uint32_t keep[24];
};

// a placeholder in CloseRangeOp::keep that spawn() rewrites to its own report
// pipe fd at apply time. the compiler cannot know that number -- the pipe does
// not exist until spawn runs -- so it reserves a slot instead.
inline constexpr std::uint32_t kReportFdSentinel = 0xfffffffeu;
// likewise for the broker relay pipe, which the guest writes its listener fd
// number to after the phase that closes inherited descriptors.
inline constexpr std::uint32_t kRelayFdSentinel = 0xfffffffdu;
// the relay pipe has TWO ends that must survive: the guest writes the listener
// number on one, and the CLONE_FILES helper -- which shares the same descriptor
// table -- reads it on the other. closing either breaks the handoff silently.
inline constexpr std::uint32_t kRelayFd2Sentinel = 0xfffffffcu;
// and the guest-side proxy listener. it is opened in the namespace phase and
// then INHERITED down the fork chain; the close sweep runs in a descendant,
// and closing it there drops the last in-namespace reference to the socket --
// so the bind goes away and the guest finds nothing listening on its own
// loopback, with no error anywhere. apply() fills this in once the listener
// exists, which is before the sweep in every ordering.
inline constexpr std::uint32_t kProxyListenFdSentinel = 0xfffffffbu;

// descriptors the CALLER asked to carry into the guest (Command::fds and the
// stdio shorthand). a range rather than one sentinel, because an embedder
// legitimately needs several -- stdin, a stdout/stderr pipe, maybe a status fd
// -- and the plan is compiled before any of their numbers are known.
//
// spawn() fills the matching slots just before applying the plan, the same way
// the report and relay pipes work. without this the close sweep runs first and
// the pipe an embedder is polling is already gone by the time the child reaches
// exec, which presents as a command that produces no output at all.
inline constexpr std::uint32_t kPreservedFdSentinelBase = 0xfffffff0u;
inline constexpr std::uint32_t kMaxPreservedFds = 8;

// The descriptors a plan's sentinels stand for, filled in by spawn() in the
// child just before apply(): the pipes do not exist when the plan is compiled.
// apply() writes notify_fd back when the policy asked for a seccomp listener.
struct ApplyFds {
    std::uint32_t report = 0xffffffffu;   // kReportFdSentinel
    std::uint32_t relay  = 0xffffffffu;   // kRelayFdSentinel
    std::uint32_t relay2 = 0xffffffffu;   // kRelayFd2Sentinel
    // kProxyListenFdSentinel. set by apply() itself when loopback_up opens
    // the listener, not by spawn(): it is the same ApplyFds, so a later phase
    // in the SAME apply sees it, and so does a descendant's sweep.
    std::uint32_t proxy_keep = 0xffffffffu;
    // slot N is kPreservedFdSentinelBase + N.
    std::uint32_t preserved[kMaxPreservedFds] = {
        0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu,
        0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu,
    };
    int notify_fd = -1;
    // the guest-side proxy listener opened by loopback_up, and the port the
    // kernel chose for it. -1/0 when the plan did not ask for one.
    int proxy_listen_fd = -1;
    std::uint16_t proxy_port = 0;
    // the netns inode the listener was bound in, for the "bound somewhere
    // unreachable" diagnosis.
    std::uint64_t proxy_netns_ino = 0;
};
struct SetHostnameOp {
    Ref name;
};
// loopback_up's payload: listen != 0 means also open a 127.0.0.1 listener
// with this backlog and report it back through ApplyFds.
struct LoopbackOp {
    std::uint32_t listen_backlog;
    std::uint32_t port;   // 0 = let the kernel choose
};
struct ChdirOp {
    Ref path;
};
struct SetRlimitOp {
    std::uint32_t resource;
    std::uint32_t _pad;
    std::uint64_t soft;
    std::uint64_t hard;
};
struct SetIdsOp {
    std::uint32_t uid;
    std::uint32_t gid;
};
struct LandlockRuleOp {
    Ref path;
    std::uint64_t allowed;  // landlock access bits
};
// a network rule: which TCP operations are permitted on one port.
struct LandlockNetRuleOp {
    std::uint64_t allowed;
    std::uint16_t port;
    std::uint16_t _pad[3];
};
struct LandlockEnforceOp {
    std::uint64_t handled_fs;   // access rights the ruleset governs
    std::uint64_t handled_net;
    // landlock scoping (abi 6+). unlike the fs and net sets these are not about
    // objects a rule can name -- they close two IPC channels that ignore the
    // filesystem entirely: abstract unix sockets, which live in the network
    // namespace rather than the mount namespace, and signals. there is no
    // add_rule for them, so they are handled-only with no grants.
    std::uint64_t scoped;
    std::uint32_t abi;          // the abi we compiled for
    std::uint32_t _pad;
};
struct DropCapsOp {
    std::uint64_t keep;  // bounding-set bits to retain; normally 0
};
struct NoNewPrivsOp {
    std::uint64_t _reserved;
};
struct SeccompInstallOp {
    Ref program;            // the BPF instructions, inline in the arena
    std::uint32_t insn_count;
    // bit 0: the policy contains a `notify` action, so ask the kernel for a
    // listener fd (SECCOMP_FILTER_FLAG_NEW_LISTENER) rather than installing the
    // filter silently.
    std::uint32_t flags;
};

// ---------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------

class PlanBuilder;

class Plan {
  public:
    Plan() = default;

    std::span<const std::byte> bytes() const { return arena_; }
    std::size_t size() const { return arena_.size(); }
    bool empty() const { return arena_.empty(); }

    // resolve a Ref to a nul-terminated C string inside the arena. returns
    // nullptr if the ref is out of bounds or not nul-terminated, which the
    // post-fork path treats as a hard failure rather than reading past the end.
    const char* cstr(Ref r) const {
        if (r.off + r.len + 1 > arena_.size()) return nullptr;
        const char* p = reinterpret_cast<const char*>(arena_.data()) + r.off;
        if (p[r.len] != '\0') return nullptr;
        return p;
    }

    std::span<const std::byte> blob(Ref r) const {
        if (r.off + r.len > arena_.size()) return {};
        return std::span<const std::byte>{arena_.data() + r.off, r.len};
    }

    // walk the ops. `fn(OpCode, payload_span)`; stops and returns false if the
    // stream is malformed.
    template <class Fn>
    bool for_each(Fn&& fn) const {
        std::size_t pos = ops_off_;
        while (pos + sizeof(OpHeader) <= arena_.size()) {
            OpHeader h{};
            std::memcpy(&h, arena_.data() + pos, sizeof h);
            if (h.size < sizeof(OpHeader)) return false;
            if (pos + h.size > arena_.size()) return false;
            std::span<const std::byte> payload{arena_.data() + pos + sizeof(OpHeader),
                                               h.size - sizeof(OpHeader)};
            if (!fn(static_cast<OpCode>(h.code), payload)) return false;
            pos += h.size;
        }
        return pos == arena_.size();
    }

    std::size_t op_count() const {
        std::size_t n = 0;
        for_each([&](OpCode, std::span<const std::byte>) {
            ++n;
            return true;
        });
        return n;
    }

    // phases must be non-decreasing. this is the ordering invariant spelled out
    // at the top of the file, checkable without running anything.
    bool well_ordered() const {
        Phase last = Phase::namespaces;
        bool ok = true;
        for_each([&](OpCode c, std::span<const std::byte>) {
            Phase p = phase_of(c);
            if (p < last) {
                ok = false;
                return false;
            }
            last = p;
            return true;
        });
        return ok;
    }

    bool has(OpCode want) const {
        bool found = false;
        for_each([&](OpCode c, std::span<const std::byte>) {
            if (c == want) found = true;
            return !found;
        });
        return found;
    }

    // decode one payload. by value + memcpy, so alignment is never assumed.
    template <class T>
    static bool decode(std::span<const std::byte> payload, T& out) {
        if (payload.size() < sizeof(T)) return false;
        std::memcpy(&out, payload.data(), sizeof(T));
        return true;
    }

    // apply the plan in the current process. POST-FORK ONLY: async-signal-safe,
    // allocation-free, and it must not be called on a process you want to keep.
    // defined in src/linux/apply.cpp; other platforms get a stub that refuses.
    Status apply(ApplyFds& fds) const { return apply_range(Phase::namespaces, Phase::count_, fds); }

    // apply only the ops strictly before `stop`. needed because entering a pid
    // namespace requires a fork between the namespace phase and the mount
    // phase: unshare(CLONE_NEWPID) makes our CHILDREN members, not us, and
    // mounting procfs requires membership.
    Status apply_until(Phase stop, ApplyFds& fds) const {
        return apply_range(Phase::namespaces, stop, fds);
    }

    // apply the ops from `start` onward.
    Status apply_from(Phase start, ApplyFds& fds) const { return apply_range(start, Phase::count_, fds); }

    Status apply_range(Phase first, Phase last, ApplyFds& fds) const;

    // the guest asked to BE pid 1 of its pid namespace (Policy::as_pid_1), so
    // spawn() runs it directly instead of behind an in-namespace shepherd.
    bool guest_is_pid_1() const { return guest_is_pid_1_; }
    void set_guest_is_pid_1(bool v) { guest_is_pid_1_ = v; }

  private:
    friend class PlanBuilder;
    std::vector<std::byte> arena_;
    std::uint32_t ops_off_{0};  // strings are interned below this point
    bool guest_is_pid_1_{false};
};

// ---------------------------------------------------------------------------
// PlanBuilder: all the fallible work lives here, ahead of the fork
// ---------------------------------------------------------------------------

class PlanBuilder {
  public:
    PlanBuilder() = default;

    // intern a string with a trailing nul so the post-fork path can pass it
    // straight to a syscall. identical strings are shared.
    Ref intern(std::string_view s) {
        if (auto it = interned_.find(s); it != interned_.end()) return it->second;
        Ref r{static_cast<std::uint32_t>(strings_.size()), static_cast<std::uint32_t>(s.size())};
        strings_.insert(strings_.end(), reinterpret_cast<const std::byte*>(s.data()),
                        reinterpret_cast<const std::byte*>(s.data()) + s.size());
        strings_.push_back(std::byte{0});
        interned_.emplace(std::string(s), r);
        return r;
    }

    Ref intern_blob(std::span<const std::byte> b) {
        Ref r{static_cast<std::uint32_t>(strings_.size()), static_cast<std::uint32_t>(b.size())};
        strings_.insert(strings_.end(), b.begin(), b.end());
        strings_.push_back(std::byte{0});  // keep cstr() usable on any ref
        return r;
    }

    template <class T>
    PlanBuilder& op(OpCode code, const T& payload) {
        Phase p = phase_of(code);
        if (p < last_phase_) {
            // a caller emitted ops out of order. record it rather than asserting:
            // build() turns it into an error the caller has to handle.
            ordering_broken_ = true;
        } else {
            last_phase_ = p;
        }
        OpHeader h{static_cast<std::uint16_t>(code),
                   static_cast<std::uint16_t>(sizeof(OpHeader) + sizeof(T)), 0};
        append(&h, sizeof h);
        append(&payload, sizeof payload);
        return *this;
    }

    Result<Plan> build() && {
        if (ordering_broken_)
            return std::unexpected(
                Error{Errc::invalid_policy, "plan: ops emitted out of phase order"});

        Plan p;
        // strings first, then ops. refs are offsets from the arena base, and
        // since strings occupy the front, their offsets are already correct.
        p.arena_.reserve(strings_.size() + ops_.size());
        p.arena_.insert(p.arena_.end(), strings_.begin(), strings_.end());
        p.ops_off_ = static_cast<std::uint32_t>(p.arena_.size());
        p.arena_.insert(p.arena_.end(), ops_.begin(), ops_.end());

        if (!p.well_ordered())
            return std::unexpected(Error{Errc::invalid_policy, "plan: not well ordered"});
        return p;
    }

  private:
    void append(const void* src, std::size_t n) {
        const auto* b = static_cast<const std::byte*>(src);
        ops_.insert(ops_.end(), b, b + n);
    }

    std::vector<std::byte> strings_;
    std::vector<std::byte> ops_;
    // transparent hash so intern() can look up a string_view without copying.
    struct SvHash {
        using is_transparent = void;
        std::size_t operator()(std::string_view s) const noexcept {
            return std::hash<std::string_view>{}(s);
        }
    };
    std::unordered_map<std::string, Ref, SvHash, std::equal_to<>> interned_;
    Phase last_phase_{Phase::namespaces};
    bool ordering_broken_{false};
};

}  // namespace clay
