// claybin: the policy, with phase encoded in the type.
//
//   Policy<Draft>   mutable, can grant authority, cannot be run
//     | seal() &&   consumes the draft
//   Policy<Sealed>  immutable, meet-able, auditable, compilable
//
// builder methods are rvalue-qualified so a draft threads linearly through the
// chain. you cannot keep a reference to a half-built policy and mutate it after
// someone else sealed a copy.
#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "claybin/core/error.hpp"
#include "claybin/core/lattice.hpp"
#include "claybin/policy/caps.hpp"
#include "claybin/policy/filesystem.hpp"
#include "claybin/policy/mounts.hpp"
#include "claybin/policy/resources.hpp"
#include "claybin/policy/syscalls.hpp"

namespace clay {

// phase tags
struct Draft {};
struct Sealed {};

template <class Phase>
class Policy;

// ---------------------------------------------------------------------------
// process / privilege authority
// ---------------------------------------------------------------------------

struct ProcOpsTag {};
using ProcOps = Flags<ProcOpsTag, std::uint32_t>;

inline constexpr ProcOps kProcFork{1u << 0};
inline constexpr ProcOps kProcExec{1u << 1};
inline constexpr ProcOps kProcPtrace{1u << 2};
inline constexpr ProcOps kProcSignalSelfTree{1u << 3};
inline constexpr ProcOps kProcSetuid{1u << 4};
inline constexpr ProcOps kProcNewNamespace{1u << 5};

// how strong a boundary the caller is asking for. not a hint: compile() fails
// rather than silently downgrading.
enum class Isolation : std::uint8_t {
    process,           // namespaces + landlock + seccomp + cgroup
    hardened_process,  // + strict syscall profile, no new namespaces, empty net ns
    microvm,           // separate kernel
};

struct EnvVar {
    std::string key;
    std::string value;
    friend bool operator==(const EnvVar&, const EnvVar&) = default;
};

// sentinel for "the caller did not ask for a specific id", which is different
// from asking for 0.
inline constexpr std::uint32_t kUnsetId = 0xffffffffu;

// the phase-independent payload. the Policy<Phase> wrapper adds the typestate.
struct PolicyData {
    FsAuthority fs{};
    NetAuthority net{};
    ResourceLimits resources{};
    SyscallPolicy syscalls{};
    ProcOps proc{};
    Isolation isolation{Isolation::process};

    // the filesystem tree to build, bubblewrap-style. orthogonal to `fs`:
    // mounts decide what is VISIBLE, landlock decides what is ACCESSIBLE.
    // empty means "inherit the host tree" and rely on landlock alone.
    MountPlan mounts{};

    // environment is authority too: PATH, LD_PRELOAD and friends are an
    // execution channel. default is empty, opt in by name.
    std::vector<EnvVar> env{};
    bool env_cleared{true};

    std::string hostname{"sandbox"};
    std::string workdir{"/"};

    // setsid() before exec, so the guest gets its own session and cannot reach
    // the host's controlling terminal via TIOCSTI keystroke injection -- a real
    // escape when the sandbox shares a tty with an interactive shell.
    bool new_session{false};

    // PR_SET_PDEATHSIG, so an orphaned sandbox dies with its supervisor rather
    // than surviving as a stray process nobody is watching.
    bool die_with_parent{false};

    // /proc/self/oom_score_adj for the guest. positive makes the kernel's OOM
    // killer pick the guest before the host's own processes, which is the
    // right order when a box with no memory cap runs a build that blows up.
    // raising it needs no privilege; lowering it does, so a guest can't undo
    // it. 0 leaves the inherited value alone.
    std::int32_t oom_score_adj{0};

    // put the guest in its OWN network namespace even though it has network
    // authority, and bring loopback up there.
    //
    // without this, "the guest may use the network" means sharing the host's
    // namespace: the guest reaches 127.0.0.1 services the host runs (a dev
    // server, a database, an unauthenticated admin port) and the whole LAN,
    // and net_isolation can only be reported `partial`. landlock's port rules
    // are the kernel-side answer but they filter by PORT, so :443 to a
    // production host and :443 to a router are the same rule.
    //
    // with it the namespace is empty apart from `lo`, so nothing is reachable
    // at all until the caller hands in a descriptor -- typically a connected
    // socket to its own proxy, which can then apply name-based policy where
    // the authority actually lives. the kernel enforces the boundary; the
    // caller decides what crosses it.
    bool netns_with_loopback{false};

    // open a listening socket on the guest's loopback during setup and hand
    // the descriptor back to the supervisor (ApplyFds::proxy_listen_fd).
    // only meaningful with netns_with_loopback. the supervisor accepts on it
    // from outside the namespace and decides what each connection may reach,
    // so this is the channel that makes a private netns usable.
    bool proxy_listener{false};

    // the port the guest-side listener binds. the SUPERVISOR picks it, because
    // it has to put the address in the guest's environment (http_proxy and
    // friends) before exec, and the namespace does not exist until setup runs.
    // any port is free in a fresh namespace, so there is nothing to collide
    // with. 0 with proxy_listener means "kernel's choice", reported back.
    std::uint16_t proxy_port{0};

    // close every inherited descriptor above stderr before the guest runs.
    //
    // ON BY DEFAULT, and that is a deliberate difference from bubblewrap. an
    // inherited fd is authority the sandbox never granted and that no wall can
    // revoke: landlock mediates path resolution, and an open fd needs none. a
    // caller who forgot they had a keyfile open has already lost.
    bool close_inherited_fds{true};

    // capabilities to KEEP in the bounding set. bottom (drop everything) is the
    // default and the right answer for almost every sandbox; --cap-add exists
    // because flatpak occasionally needs CAP_NET_BIND_SERVICE and similar.
    Caps keep_caps{Caps::nothing()};

    // the uid/gid the guest runs as inside its user namespace. unset means
    // "map our own id to itself", which is what a sandbox almost always wants.
    std::uint32_t uid{kUnsetId};
    std::uint32_t gid{kUnsetId};

    // become pid 1 of the new pid namespace rather than having a shepherd hold
    // that slot. changes signal semantics for the guest, so it is opt-in.
    bool as_pid_1{false};

    // an SELinux label for the exec'd process / for created files. not applied
    // unless the host has SELinux, and the report says so.
    std::string exec_label{};
    std::string file_label{};

    PolicyData meet(const PolicyData& o) const {
        PolicyData r;
        r.fs = fs.meet(o.fs);
        r.net = net.meet(o.net);
        r.resources = resources.meet(o.resources);
        r.syscalls = syscalls.meet(o.syscalls);
        r.proc = proc.meet(o.proc);
        // stronger isolation wins, and stronger is the larger enum value.
        r.isolation = isolation > o.isolation ? isolation : o.isolation;
        r.env_cleared = env_cleared || o.env_cleared;

        // mounts are an ordered construction, not a set, so there is no
        // meaningful intersection of two trees. take whichever side has one;
        // if both do, the caller has asked for something undefined and
        // compile() rejects it rather than inventing a tree.
        if (mounts.empty())
            r.mounts = o.mounts;
        else if (o.mounts.empty())
            r.mounts = mounts;
        else
            r.mounts = mounts;  // marked as a conflict by compile()

        // env intersects: a var survives only if both sides agree on it exactly.
        for (const auto& a : env)
            for (const auto& b : o.env)
                if (a.key == b.key && a.value == b.value) r.env.push_back(a);
        r.hostname = hostname;
        r.workdir = workdir;
        // both are hardening, so the meet takes whichever side asked for them:
        // composing policies must not be able to turn a protection off.
        r.new_session = new_session || o.new_session;
        r.die_with_parent = die_with_parent || o.die_with_parent;
        // "kill me first" is hardening too: the higher value wins.
        r.oom_score_adj = oom_score_adj > o.oom_score_adj ? oom_score_adj : o.oom_score_adj;
        // another hardening flag: either side asking for the private namespace
        // gets it.
        r.netns_with_loopback = netns_with_loopback || o.netns_with_loopback;
        // a channel is authority: it survives only if both sides offered it.
        r.proxy_listener = proxy_listener && o.proxy_listener;
        r.proxy_port = proxy_port ? proxy_port : o.proxy_port;
        // hardening: whichever side wants it, wins.
        r.close_inherited_fds = close_inherited_fds || o.close_inherited_fds;
        // capabilities are authority, so this is a real meet: a capability
        // survives only if BOTH sides kept it.
        r.keep_caps = keep_caps.meet(o.keep_caps);
        r.uid = uid;
        r.gid = gid;
        r.as_pid_1 = as_pid_1 && o.as_pid_1;
        r.exec_label = exec_label;
        r.file_label = file_label;
        return r;
    }

    bool subsumes(const PolicyData& o) const {
        return fs.subsumes(o.fs) && net.subsumes(o.net) && resources.subsumes(o.resources) &&
               syscalls.subsumes(o.syscalls) && proc.subsumes(o.proc) &&
               keep_caps.subsumes(o.keep_caps) && isolation <= o.isolation;
    }

    friend bool operator==(const PolicyData&, const PolicyData&) = default;
};

// ---------------------------------------------------------------------------
// Policy<Draft>: grants allowed
// ---------------------------------------------------------------------------

template <>
class Policy<Draft> {
  public:
    // a fresh draft grants no AUTHORITY: no filesystem, no network, no
    // syscalls beyond what a profile adds. you build up from nothing.
    //
    // resources are deliberately NOT bottom. a limit is a ceiling, so the
    // lattice bottom is 0, and 0 means "cannot allocate a single page" --
    // RLIMIT_AS=0 makes execve fail with EACCES before the program ever runs.
    // bottom is the right identity for permissions and the wrong default for
    // ceilings, so a draft starts unlimited and the caller tightens explicitly.
    //
    // core size is the one exception: 0. a guest that crashes (a seccomp
    // SIGSYS kill included) would otherwise dump its memory to the host's
    // core handler, which on systemd-coredump means the host journal.
    // core_dumps(true) opts back in.
    Policy() {
        data_.resources = ResourceLimits::everything();
        data_.resources.core_size = Bytes{0};
    }

    Policy(const Policy&) = default;
    Policy& operator=(const Policy&) = default;
    Policy(Policy&&) noexcept = default;

    // self-move must be a no-op, not a wipe.
    //
    // the builders are rvalue-qualified and return `Policy&&`, which makes the
    // natural loop body `p = std::move(p).bind(a, b);` a SELF-move-assignment.
    // the implicit operator= would move each vector member onto itself and
    // leave it empty, so a CLI parser accumulating mounts in a loop would
    // silently end up with none -- a sandbox missing exactly the walls the user
    // asked for. guard it.
    Policy& operator=(Policy&& o) noexcept {
        if (this != &o) data_ = std::move(o.data_);
        return *this;
    }

    // -- filesystem ---------------------------------------------------------
    Policy&& read(std::string_view p) && {
        data_.fs.grant(p, FileRights::read());
        return std::move(*this);
    }
    Policy&& read_write(std::string_view p) && {
        data_.fs.grant(p, FileRights::write());
        return std::move(*this);
    }
    Policy&& execute(std::string_view p) && {
        data_.fs.grant(p, FileRights::exec());
        return std::move(*this);
    }
    Policy&& grant(std::string_view p, FileRights r) && {
        data_.fs.grant(p, r);
        return std::move(*this);
    }
    // punch a hole inside an already-granted subtree.
    Policy&& deny(std::string_view p) && {
        data_.fs.deny(p);
        return std::move(*this);
    }

    // -- filesystem tree construction (the bubblewrap model) ---------------
    //
    // these build a NEW root from binds, rather than restricting the host's.
    // naming follows bwrap so a port is mechanical: --ro-bind is ro_bind, and
    // so on. each bind also implies the matching landlock grant, so the tree
    // and the access policy stay in sync without saying everything twice.
    Policy&& ro_bind(std::string src, std::string dst) && {
        data_.mounts.bind_ro(std::move(src), std::move(dst));
        return std::move(*this);
    }
    Policy&& bind(std::string src, std::string dst) && {
        data_.mounts.bind(std::move(src), std::move(dst));
        return std::move(*this);
    }
    Policy&& dev_bind(std::string src, std::string dst) && {
        data_.mounts.dev_bind(std::move(src), std::move(dst));
        return std::move(*this);
    }
    Policy&& bind_try(std::string src, std::string dst, bool ro = true) && {
        data_.mounts.bind_try(std::move(src), std::move(dst), ro);
        return std::move(*this);
    }
    // perms: the tmpfs root's mode, as bwrap's `--perms MODE --tmpfs DST`.
    // 0 keeps the default, 0755.
    Policy&& tmpfs(std::string dst, Bytes size = Bytes::unlimited(),
                   std::uint32_t perms = 0) && {
        data_.mounts.tmpfs(std::move(dst), size.is_unlimited() ? 0 : size.value(), perms);
        return std::move(*this);
    }
    Policy&& proc_fs(std::string dst = "/proc") && {
        data_.mounts.proc(std::move(dst));
        return std::move(*this);
    }
    Policy&& dev_fs(std::string dst = "/dev") && {
        data_.mounts.dev(std::move(dst));
        return std::move(*this);
    }

    // make a path be nothing, whatever the binds around it say.
    //
    // the sound way to express "everything under here except that", and the
    // one a credential mask needs: bind $HOME, then mask $HOME/.aws. `deny()`
    // cannot do this -- landlock has no negative rule (see MountKind::mask),
    // so a deny under a grant is silently inherited.
    Policy&& mask(std::string dst) && {
        data_.mounts.mask(std::move(dst));
        return std::move(*this);
    }
    Policy&& mqueue(std::string dst = "/dev/mqueue") && {
        data_.mounts.mqueue(std::move(dst));
        return std::move(*this);
    }
    Policy&& symlink(std::string target, std::string dst) && {
        data_.mounts.symlink(std::move(target), std::move(dst));
        return std::move(*this);
    }
    Policy&& mkdir(std::string dst, std::uint32_t perms = 0755) && {
        data_.mounts.dir(std::move(dst), perms);
        return std::move(*this);
    }

    // overlays. the lower layers are a required argument rather than accumulated
    // state, so an overlay with no layers is not representable -- bwrap can only
    // catch that at runtime.
    Policy&& overlay(std::vector<std::string> lowers, std::string upper, std::string work,
                     std::string dst) && {
        data_.mounts.overlay(std::move(lowers), std::move(upper), std::move(work),
                             std::move(dst));
        return std::move(*this);
    }
    // the useful one for untrusted builds: the guest may write anywhere in the
    // tree and every change is discarded when the sandbox exits.
    Policy&& tmp_overlay(std::vector<std::string> lowers, std::string dst) && {
        data_.mounts.tmp_overlay(std::move(lowers), std::move(dst));
        return std::move(*this);
    }
    Policy&& ro_overlay(std::vector<std::string> lowers, std::string dst) && {
        data_.mounts.ro_overlay(std::move(lowers), std::move(dst));
        return std::move(*this);
    }

    // ---- descriptors as sources ------------------------------------------
    //
    // an fd names an object, not a path, so these are immune to the symlink and
    // TOCTOU races that path-based binds have to defend against.
    Policy&& bind_fd(BorrowedFd fd, std::string dst, bool ro = false) && {
        data_.mounts.bind_fd(fd, std::move(dst), ro);
        return std::move(*this);
    }
    Policy&& file_from_fd(BorrowedFd fd, std::string dst, std::uint32_t perms = 0644) && {
        data_.mounts.file(fd, std::move(dst), perms);
        return std::move(*this);
    }
    // stronger than file_from_fd: the backing file is unlinked after the bind,
    // so the content has no name anywhere on the filesystem.
    Policy&& bind_data(BorrowedFd fd, std::string dst, bool ro = false,
                       std::uint32_t perms = 0644) && {
        data_.mounts.bind_data(fd, std::move(dst), ro, perms);
        return std::move(*this);
    }

    // -- network ------------------------------------------------------------
    Policy&& connect(std::string host, std::uint16_t port) && {
        data_.net.allow(std::move(host), port, kNetConnect);
        return std::move(*this);
    }
    // allow TCP bind on one port. enforced by landlock from abi 4, which is
    // finer than anything a network namespace can express -- a netns is
    // all-or-nothing, this is per-port.
    Policy&& bind_port(std::uint16_t port) && {
        data_.net.allow("", port, kNetBind);
        return std::move(*this);
    }
    Policy&& unix_sockets() && {
        data_.net.allow_any(kNetUnixSocket);
        return std::move(*this);
    }

    // -- resources ----------------------------------------------------------
    // let the guest write core files. off by default: see the constructor.
    Policy&& core_dumps(bool on) && {
        data_.resources.core_size = on ? Bytes{} : Bytes{0};
        return std::move(*this);
    }
    Policy&& memory(Bytes b) && {
        data_.resources.memory = b;
        return std::move(*this);
    }
    Policy&& processes(std::uint64_t n) && {
        data_.resources.pids = Count{n};
        return std::move(*this);
    }
    Policy&& open_files(std::uint64_t n) && {
        data_.resources.open_files = Count{n};
        return std::move(*this);
    }
    Policy&& cpu_time(Nanos n) && {
        data_.resources.cpu_time = n;
        return std::move(*this);
    }
    // a hard cpu ceiling as a percentage of one core: 50 = half a core,
    // 200 = two cores' worth. this is the one that bounds a busy loop.
    Policy&& cpu_percent(std::uint64_t pct) && {
        data_.resources.cpu_quota_percent = Count{pct};
        return std::move(*this);
    }
    Policy&& wall_clock(Nanos n) && {
        data_.resources.wall_clock = n;
        return std::move(*this);
    }

    // -- syscalls -----------------------------------------------------------
    Policy&& syscall_profile(SyscallPolicy p) && {
        data_.syscalls = std::move(p);
        return std::move(*this);
    }

    // -- process ------------------------------------------------------------
    Policy&& allow_fork() && {
        data_.proc = ProcOps{data_.proc.unsafe_join(kProcFork)};
        return std::move(*this);
    }
    Policy&& allow_exec() && {
        data_.proc = ProcOps{data_.proc.unsafe_join(kProcExec)};
        return std::move(*this);
    }

    // -- environment --------------------------------------------------------
    Policy&& env(std::string key, std::string value) && {
        data_.env.push_back({std::move(key), std::move(value)});
        return std::move(*this);
    }
    // inherit the parent's environment. OFF by default, because the environment
    // is authority -- PATH decides what gets executed, LD_PRELOAD decides what
    // code runs -- and inheriting it silently is how a sandbox ends up handing
    // the guest a channel nobody audited. named loudly so it is greppable.
    Policy&& inherit_env() && {
        data_.env_cleared = false;
        return std::move(*this);
    }
    Policy&& workdir(std::string p) && {
        data_.workdir = path::normalize(p);
        return std::move(*this);
    }
    Policy&& hostname(std::string h) && {
        data_.hostname = std::move(h);
        return std::move(*this);
    }
    // give the guest its own session. this is a real security measure, not
    // cosmetics: sharing a controlling terminal with the host lets a guest
    // inject keystrokes into it with TIOCSTI.
    Policy&& new_session() && {
        data_.new_session = true;
        return std::move(*this);
    }
    // die when the supervisor does, so an orphaned sandbox cannot outlive the
    // thing that was supposed to be watching it.
    Policy&& die_with_parent() && {
        data_.die_with_parent = true;
        return std::move(*this);
    }
    // range -1000..1000; see PolicyData::oom_score_adj.
    Policy&& oom_score_adj(std::int32_t v) && {
        data_.oom_score_adj = v < -1000 ? -1000 : v > 1000 ? 1000 : v;
        return std::move(*this);
    }
    // an own network namespace with loopback up, even WITH net authority.
    // see PolicyData::netns_with_loopback: nothing outside is reachable, so
    // the caller must pass in whatever channel it wants the guest to have.
    Policy&& private_netns() && {
        data_.netns_with_loopback = true;
        return std::move(*this);
    }
    // private_netns, plus a guest-side loopback listener the supervisor
    // accepts on. see PolicyData::proxy_listener. `port` 0 lets the kernel
    // choose, which the caller then reads from Spawned::proxy_port.
    Policy&& proxied_netns(std::uint16_t port = 0) && {
        data_.netns_with_loopback = true;
        data_.proxy_listener = true;
        data_.proxy_port = port;
        return std::move(*this);
    }
    // let the guest inherit the caller's open descriptors.
    //
    // named to be uncomfortable, because it should be: every inherited fd is
    // authority no wall can revoke. only `--bind-fd` and friends need this, and
    // they arrange it for themselves.
    Policy&& unsafe_inherit_fds() && {
        data_.close_inherited_fds = false;
        return std::move(*this);
    }

    // ---- capabilities ----------------------------------------------------
    //
    // the default is to drop everything, which is right for almost every
    // sandbox. keeping one is a real grant, so it lives here on the Draft --
    // and `forbidden_caps()` is refused outright, because CAP_SYS_ADMIN inside
    // a sandbox means there is no sandbox.
    Policy&& keep_cap(int cap) && {
        Caps want = Caps::of(cap);
        if (!want.meet(forbidden_caps()).is_nothing()) return std::move(*this);
        data_.keep_caps = Caps{data_.keep_caps.unsafe_join(want)};
        return std::move(*this);
    }
    Policy&& drop_cap(int cap) && {
        data_.keep_caps = Caps{data_.keep_caps.without(Caps::of(cap))};
        return std::move(*this);
    }
    Policy&& drop_all_caps() && {
        data_.keep_caps = Caps::nothing();
        return std::move(*this);
    }

    // ---- identity --------------------------------------------------------
    Policy&& uid(std::uint32_t id) && {
        data_.uid = id;
        return std::move(*this);
    }
    Policy&& gid(std::uint32_t id) && {
        data_.gid = id;
        return std::move(*this);
    }

    // run the guest AS pid 1 of its namespace, rather than behind a shepherd.
    // changes signal semantics (pid 1 ignores signals it has no handler for), so
    // it is opt-in.
    Policy&& as_pid_1() && {
        data_.as_pid_1 = true;
        return std::move(*this);
    }

    Policy&& exec_label(std::string label) && {
        data_.exec_label = std::move(label);
        return std::move(*this);
    }
    Policy&& file_label(std::string label) && {
        data_.file_label = std::move(label);
        return std::move(*this);
    }
    Policy&& isolation(Isolation lvl) && {
        data_.isolation = lvl;
        return std::move(*this);
    }

    // consumes the draft. after this there is no way back to a mutable policy,
    // so nothing can be widened behind a holder's back.
    Policy<Sealed> seal() &&;

  private:
    PolicyData data_;
};

// ---------------------------------------------------------------------------
// Policy<Sealed>: immutable, composable by meet only
// ---------------------------------------------------------------------------

template <>
class Policy<Sealed> {
  public:
    static Policy nothing() {
        PolicyData d;
        d.fs = FsAuthority::nothing();
        d.net = NetAuthority::nothing();
        d.resources = ResourceLimits::nothing();
        d.syscalls = SyscallPolicy::nothing();
        d.proc = ProcOps::nothing();
        d.isolation = Isolation::microvm;  // bottom authority = strongest boundary
        return Policy{std::move(d)};
    }

    static Policy everything() {
        PolicyData d;
        d.fs = FsAuthority::everything();
        d.net = NetAuthority::everything();
        d.resources = ResourceLimits::everything();
        d.syscalls = SyscallPolicy::everything();
        d.proc = ProcOps::everything();
        d.isolation = Isolation::process;
        d.env_cleared = false;
        return Policy{std::move(d)};
    }

    Policy meet(const Policy& o) const { return Policy{data_.meet(o.data_)}; }
    bool subsumes(const Policy& o) const { return data_.subsumes(o.data_); }
    bool is_nothing() const {
        return data_.fs.is_nothing() && data_.net.is_nothing() && data_.proc.is_nothing();
    }

    const PolicyData& data() const { return data_; }

    // reopen for editing. explicit and loud on purpose: it is the only way back
    // to a phase where authority can grow, so it should be greppable.
    Policy<Draft> unseal_for_editing() const;

    friend bool operator==(const Policy& a, const Policy& b) { return a.data_ == b.data_; }

  private:
    friend class Policy<Draft>;
    explicit Policy(PolicyData d) : data_(std::move(d)) {}
    PolicyData data_;
};

inline Policy<Sealed> Policy<Draft>::seal() && {
    data_.fs.normalize();
    return Policy<Sealed>{std::move(data_)};
}

static_assert(Lattice<Policy<Sealed>>);

}  // namespace clay
