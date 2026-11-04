#include "claybin/plan/compile.hpp"

#include <cstdio>
#if defined(_WIN32)
#include <cstdint>
#else
#include <unistd.h>
#endif

#include "claybin/bpf/emit.hpp"

namespace clay {
namespace {

// The caller's uid/gid, for the uid_map/gid_map writes and the setids op.
//
// Shimmed rather than #ifdef'd at each of the four call sites, because the
// surrounding code is PORTABLE by design: compile() turns a policy into a
// plan on any host (the file's own header says so, and agentty's settings
// pane calls it on macOS and Windows to preview the walls). Only apply() is
// linux-only. A bare <unistd.h> broke that promise and took the whole MinGW
// build down with it -- `'::getuid' has not been declared`.
//
// Windows returns 0/0. The values only ever reach a /proc write or a
// setresuid, neither of which exists there, and a plan built on Windows is
// inspected rather than applied -- so the number is a placeholder in a field
// nothing on that platform reads.
#if defined(_WIN32)
[[nodiscard]] inline std::uint32_t caller_uid() noexcept { return 0; }
[[nodiscard]] inline std::uint32_t caller_gid() noexcept { return 0; }
#else
[[nodiscard]] inline std::uint32_t caller_uid() noexcept {
    return static_cast<std::uint32_t>(::getuid());
}
[[nodiscard]] inline std::uint32_t caller_gid() noexcept {
    return static_cast<std::uint32_t>(::getgid());
}
#endif

// ---------------------------------------------------------------------------
// linux ABI constants. hardcoded rather than #included so this file compiles
// and tests anywhere; the linux-only apply() step is what actually needs the
// real headers.
// ---------------------------------------------------------------------------

constexpr std::uint64_t kCloneNewns = 0x00020000;
constexpr std::uint64_t kCloneNewuts = 0x04000000;
constexpr std::uint64_t kCloneNewipc = 0x08000000;
constexpr std::uint64_t kCloneNewuser = 0x10000000;
constexpr std::uint64_t kCloneNewpid = 0x20000000;
constexpr std::uint64_t kCloneNewnet = 0x40000000;
constexpr std::uint64_t kCloneNewcgroup = 0x02000000;

// landlock access bits (abi 1-5)
constexpr std::uint64_t kLlExecute = 1ull << 0;
constexpr std::uint64_t kLlWriteFile = 1ull << 1;
constexpr std::uint64_t kLlReadFile = 1ull << 2;
constexpr std::uint64_t kLlReadDir = 1ull << 3;
constexpr std::uint64_t kLlRemoveDir = 1ull << 4;
constexpr std::uint64_t kLlRemoveFile = 1ull << 5;
constexpr std::uint64_t kLlMakeChar = 1ull << 6;
constexpr std::uint64_t kLlMakeDir = 1ull << 7;
constexpr std::uint64_t kLlMakeReg = 1ull << 8;
constexpr std::uint64_t kLlMakeSock = 1ull << 9;
constexpr std::uint64_t kLlMakeFifo = 1ull << 10;
constexpr std::uint64_t kLlMakeBlock = 1ull << 11;
constexpr std::uint64_t kLlMakeSym = 1ull << 12;
constexpr std::uint64_t kLlRefer = 1ull << 13;     // abi 2
constexpr std::uint64_t kLlTruncate = 1ull << 14;  // abi 3
constexpr std::uint64_t kLlIoctlDev = 1ull << 15;  // abi 5

// rlimit resource numbers
constexpr std::uint32_t kRlimitCpu = 0;
constexpr std::uint32_t kRlimitCore = 4;
constexpr std::uint32_t kRlimitNofile = 7;
constexpr std::uint32_t kRlimitAs = 9;
constexpr std::uint32_t kRlimitNproc = 6;

// translate our portable rights to landlock's bits, clamped to what the host's
// abi actually understands. asking for a bit the kernel does not know makes
// landlock_create_ruleset fail outright, so clamping is required, not polite.
//
// the result is also masked against handled_access() by the caller: landlock
// rejects a rule whose allowed_access is not a subset of the ruleset's handled
// set, which is a very easy way to turn a working sandbox into a blanket deny.
std::uint64_t to_landlock(FileRights r, std::uint32_t abi) {
    std::uint64_t out = 0;
    if (r.any(FileRights{FileRights::kExecute})) out |= kLlExecute;
    if (r.any(FileRights{FileRights::kWriteFile})) out |= kLlWriteFile;
    if (r.any(FileRights{FileRights::kReadFile})) out |= kLlReadFile;
    if (r.any(FileRights{FileRights::kReadDir})) out |= kLlReadDir;
    if (r.any(FileRights{FileRights::kRemoveDir})) out |= kLlRemoveDir;
    if (r.any(FileRights{FileRights::kRemoveFile})) out |= kLlRemoveFile;
    if (r.any(FileRights{FileRights::kCreateDir})) out |= kLlMakeDir;
    if (r.any(FileRights{FileRights::kCreateFile})) out |= kLlMakeReg;
    if (r.any(FileRights{FileRights::kMakeSym})) out |= kLlMakeSym;
    if (r.any(FileRights{FileRights::kMakeSpecial}))
        out |= kLlMakeChar | kLlMakeSock | kLlMakeFifo | kLlMakeBlock;
    if (abi >= 2 && r.any(FileRights{FileRights::kRename})) out |= kLlRefer;
    if (abi >= 3 && r.any(FileRights{FileRights::kTruncate})) out |= kLlTruncate;
    if (abi >= 5 && r.any(FileRights{FileRights::kIoctlDev})) out |= kLlIoctlDev;
    return out;
}

// landlock network access bits (abi 4+). these mediate TCP bind and connect by
// PORT, which is a genuine second wall on top of the network namespace: a netns
// is all-or-nothing, landlock net is per-port.
constexpr std::uint64_t kLlBindTcp = 1ull << 0;
constexpr std::uint64_t kLlConnectTcp = 1ull << 1;

// the full set of rights a ruleset governs, for this abi. anything not in here
// is simply not mediated by landlock, so the report must not claim it is.
//
// IMPORTANT: we only ever ask for bits we actually know about. landlock keeps
// adding access rights (abi 10 has several we do not model), and asking for a
// bit the kernel does not know makes create_ruleset fail -- but under-asking is
// safe, it just means those operations are unmediated. since our FileRights
// vocabulary tops out at the abi-5 set, that is what we hand over.
std::uint64_t handled_access(std::uint32_t abi) {
    std::uint64_t h = kLlExecute | kLlWriteFile | kLlReadFile | kLlReadDir | kLlRemoveDir |
                      kLlRemoveFile | kLlMakeChar | kLlMakeDir | kLlMakeReg | kLlMakeSock |
                      kLlMakeFifo | kLlMakeBlock | kLlMakeSym;
    if (abi >= 2) h |= kLlRefer;
    if (abi >= 3) h |= kLlTruncate;
    if (abi >= 5) h |= kLlIoctlDev;
    return h;
}

constexpr std::uint64_t kMsRdonly = 1;
constexpr std::uint64_t kMsNosuid = 2;
constexpr std::uint64_t kMsNodev = 4;
constexpr std::uint64_t kMsNoexec = 8;
constexpr std::uint64_t kMsRemount = 32;
constexpr std::uint64_t kMsBind = 4096;
constexpr std::uint64_t kMsRec = 16384;
constexpr std::uint64_t kMsSlave = 1ull << 19;
constexpr std::uint64_t kMsSilent = 1ull << 15;

// our own flag, well above the kernel's range. marks a mount that may fail
// without failing the sandbox: a device node that does not exist on this host,
// or a --bind-try source. apply() strips it before the syscall.
constexpr std::uint64_t kClayMountOptional = 1ull << 56;

// where the new root is assembled before we pivot into it.
//
// bubblewrap's layout, and for its reasons: a base tmpfs with a "newroot"
// subdirectory inside it. pivoting to the SUBDIRECTORY rather than the base
// means a caller who binds something over / (or over the base path itself)
// cannot break our access to the old root mid-setup.
constexpr const char* kStageBase = "/tmp/.clay";
constexpr const char* kNewRoot = "/tmp/.clay/newroot";
constexpr const char* kOldRoot = "/tmp/.clay/oldroot";
// an empty mode-0444 file we bind over procfs entries that must not be WRITABLE.
// /dev/null will not do: a bind of it accepts writes, and remounting a device
// bind read-only is EPERM.
constexpr const char* kRoMaskFile = "/tmp/.clay/ro-mask";

}  // namespace

Result<Compiled> compile(const Policy<Sealed>& policy, const HostCapabilities& host) {
    const PolicyData& d = policy.data();
    Compiled out;
    GuaranteeReport::Builder report;
    PlanBuilder b;

    // -- refuse to silently downgrade -------------------------------------
    if (d.isolation == Isolation::microvm)
        return std::unexpected(Error{Errc::unsupported, "microvm backend not implemented"});

    if (d.isolation == Isolation::hardened_process) {
        // hardened means every wall, no exceptions. if the host cannot do one
        // of them, the caller asked for a guarantee we cannot give.
        if (!host.seccomp)
            return std::unexpected(Error{Errc::unsupported, "hardened: seccomp", 0});
        if (host.landlock_abi == 0)
            return std::unexpected(Error{Errc::unsupported, "hardened: landlock", 0});
        if (!host.user_namespaces)
            return std::unexpected(Error{Errc::unsupported, "hardened: user namespaces", 0});
    }

    auto degrade = [&](CapId c) { out.degraded.push_back(c); };

    // -- phase: namespaces -------------------------------------------------
    //
    // EVERY flag here is gated on a probed capability, including ipc. none of
    // these namespaces is unprivileged on its own: without CAP_SYS_ADMIN the
    // kernel only grants them when they are created TOGETHER with a user
    // namespace. so on a host that denies unprivileged userns, an unshare()
    // carrying any of them fails EPERM and takes the whole spawn with it.
    //
    // ipc used to be unconditional, which meant unshare_flags was never empty
    // and the op was emitted even when every other flag had been correctly
    // dropped -- turning "degrade to landlock+seccomp" into
    // "spawn failed: unshare (errno 1)" on exactly the locked-down hosts
    // claybin exists to serve.
    std::uint64_t unshare_flags = 0;
    if (host.user_namespaces) unshare_flags |= kCloneNewuser;
    if (host.mount_namespaces) unshare_flags |= kCloneNewns;
    if (host.pid_namespaces) unshare_flags |= kCloneNewpid;
    if (host.uts_namespaces) unshare_flags |= kCloneNewuts;
    if (host.ipc_namespaces) unshare_flags |= kCloneNewipc;
    // the child unshares after spawn has moved it into its cgroup (the gate
    // pipe), so the namespace root IS the box's group. same userns rule as
    // the rest: only with a user namespace or as root.
    if (host.cgroup_namespaces) unshare_flags |= kCloneNewcgroup;

    // a policy with no network authority gets an empty network namespace, which
    // is a stronger and cheaper guarantee than filtering socket syscalls.
    //
    // netns_with_loopback asks for the namespace EVEN WITH authority: the
    // guest keeps its sockets but the only peer it can reach is itself, so
    // the host's loopback services and the LAN are simply not there. a caller
    // that wants outbound traffic passes in a descriptor for it.
    const bool wants_net = !d.net.is_nothing();
    const bool private_netns = host.net_namespaces
        && (!wants_net || d.netns_with_loopback);
    if (private_netns) unshare_flags |= kCloneNewnet;

    if (unshare_flags) b.op(OpCode::unshare, UnshareOp{unshare_flags});

    if (host.user_namespaces) {
        // map only our own uid, and deny setgroups first: without that, a
        // process in a new user namespace can drop supplementary groups to
        // bypass a negative group permission.
        b.op(OpCode::write_file,
             WriteFileOp{b.intern("/proc/self/setgroups"), b.intern("deny")});

        // an empty content ref means "map my own id to itself", computed at
        // apply time because the plan may be built by another process. an
        // explicit --uid/--gid writes the mapping here instead.
        //
        // note an unprivileged user namespace can only map ONE id, and only one
        // it already owns, so `--uid 0` maps our real uid to 0 inside. that is
        // what bwrap does too, and it is not a privilege gain: uid 0 in a user
        // namespace owns nothing outside it.
        if (d.uid != kUnsetId) {
            char buf[64];
            std::snprintf(buf, sizeof buf, "%u %u 1\n", d.uid,
                          caller_uid());
            b.op(OpCode::write_file,
                 WriteFileOp{b.intern("/proc/self/uid_map"), b.intern(buf)});
        } else {
            b.op(OpCode::write_file, WriteFileOp{b.intern("/proc/self/uid_map"), b.intern("")});
        }
        if (d.gid != kUnsetId) {
            char buf[64];
            std::snprintf(buf, sizeof buf, "%u %u 1\n", d.gid,
                          caller_gid());
            b.op(OpCode::write_file,
                 WriteFileOp{b.intern("/proc/self/gid_map"), b.intern(buf)});
        } else {
            b.op(OpCode::write_file, WriteFileOp{b.intern("/proc/self/gid_map"), b.intern("")});
        }
        report.record(CapId::proc_isolation, Enforcement::strong, "userns+pidns");
    } else {
        degrade(CapId::proc_isolation);
        report.record(CapId::proc_isolation, Enforcement::none, "unavailable");
    }

    // oom_score_adj rides the same write_file op as the id maps, so it lands
    // in the namespaces phase. raising it needs no capability, and it has to
    // come before exec so the guest's first allocation is already scored.
    if (d.oom_score_adj > 0) {
        char buf[16];
        std::snprintf(buf, sizeof buf, "%d\n", d.oom_score_adj);
        b.op(OpCode::write_file,
             WriteFileOp{b.intern("/proc/self/oom_score_adj"), b.intern(buf)});
    }

    // loopback, and the proxy listener on it. this is a NAMESPACE-phase op
    // (see phase_of): it needs the new netns, which the unshare above just
    // made, and the listener must be held by this process rather than the
    // guest -- the guest's copy would close on exec.
    if (private_netns && wants_net)
        b.op(OpCode::loopback_up,
             LoopbackOp{d.proxy_listener ? 128u : 0u, d.proxy_port});

    if (!wants_net) {
        if (host.net_namespaces)
            report.record(CapId::net_isolation, Enforcement::strong, "netns");
        else
            degrade(CapId::net_isolation);
    } else if (private_netns) {
        // the namespace is the boundary, so this is the same `strong` the
        // no-network case gets. what the guest may reach THROUGH a passed-in
        // descriptor is the caller's policy, not a weaker kernel wall.
        report.record(CapId::net_isolation, Enforcement::strong, "netns+loopback");
    } else {
        // brokered network is only as strong as the notify supervisor, and we
        // have not built it yet. say so.
        report.record(CapId::net_isolation, Enforcement::partial, "policy-only");
    }

    // -- phase: mounts -----------------------------------------------------
    //
    // this is the bubblewrap model: build a whole new tree out of binds and
    // pivot into it, so the host filesystem is not merely restricted but
    // absent. what is not mounted cannot be named, which is a stronger and much
    // easier-to-audit property than "is denied".
    //
    // a host with no mount namespaces (windows, macOS, a locked-down linux)
    // cannot do this. rather than silently dropping the mounts, we ask the plan
    // how faithfully its OTHER interpretation -- pure access control -- can
    // stand in, and refuse when the answer is "it cannot".
    const bool building_tree = !d.mounts.empty() && host.mount_namespaces;

    if (!d.mounts.empty() && !host.mount_namespaces) {
        std::vector<FidelityNote> notes;
        Fidelity f = d.mounts.fidelity(&notes);
        if (f == Fidelity::impossible) {
            // name the reason. "unsupported" with no explanation is what sends
            // people to strace.
            const char* why = notes.empty() ? "mount plan needs a mount namespace"
                                            : notes.front().reason;
            return std::unexpected(Error{Errc::unsupported, why});
        }
        // approximate: the access interpretation is sound but weaker, so the
        // guarantee report must not claim the tree's strength.
        out.fidelity = f;
    }

    if (building_tree) {
        // counts tmp_overlay scratch areas, so each gets its own tmpfs rather
        // than sharing one and leaking changes between overlays.
        std::size_t ovl_index = 0;

        // 1. mark everything SLAVE, not private.
        //
        //    slave means we still RECEIVE mounts from the host but never
        //    propagate ours back to it. private would cut both directions,
        //    which sounds tighter but is actually worse: a long-running sandbox
        //    would silently miss a later host mount under a path it has bound,
        //    and see a stale tree. this is what bubblewrap does and the reason
        //    is worth copying along with the flag.
        b.op(OpCode::mount, MountOp{b.intern("none"), b.intern("/"), b.intern("none"),
                                    Ref{}, kMsRec | kMsSlave | kMsSilent});

        // 2. a tmpfs for the staging area, then newroot/ and oldroot/ inside it.
        //    pivoting to the SUBDIRECTORY (not the tmpfs root) is deliberate: a
        //    caller who binds something over / or over the staging path cannot
        //    then break our own access to the old root.
        b.op(OpCode::mkdir_p, MkdirOp{b.intern(kStageBase), 0755, 0});
        // mode=0755 here too. the staging tmpfs holds the bind-data scratch
        // files, and a sticky 1777 would make writing them fail for the same
        // reason a shell redirect over /dev/null does.
        b.op(OpCode::mount, MountOp{b.intern("tmpfs"), b.intern(kStageBase),
                                    b.intern("tmpfs"), b.intern("mode=0755"),
                                    kMsNosuid | kMsNodev});
        b.op(OpCode::mkdir_p, MkdirOp{b.intern(kNewRoot), 0755, 0});
        // newroot must itself be a MOUNT POINT for the second pivot_root to
        // work -- pivot_root(".", ".") returns EINVAL on a plain directory. a
        // recursive bind of the directory onto itself is how bubblewrap does
        // it, and it costs nothing.
        b.op(OpCode::mount, MountOp{b.intern(kNewRoot), b.intern(kNewRoot), b.intern("none"),
                                    Ref{}, kMsBind | kMsRec | kMsSilent});
        b.op(OpCode::mkdir_p, MkdirOp{b.intern(kOldRoot), 0755, 0});
        // the read-only mask file, used to cover procfs entries a guest must not
        // be able to write. created mode 0444 so the read-only remount works.
        b.op(OpCode::touch, MkdirOp{b.intern(kRoMaskFile), 0444, 0});

        // 3. every requested mount, rebased under the NEW ROOT. the source
        //    is interned too, because apply() needs to stat it to decide
        //    whether the mount point should be a file or a directory.
        for (const auto& m : d.mounts.mounts()) {
            std::string dst = std::string(kNewRoot) + path::normalize(m.dest);
            switch (m.kind) {
                case MountKind::bind:
                case MountKind::bind_ro:
                case MountKind::bind_dev: {
                    std::uint64_t flags = kMsBind | kMsRec;
                    if (m.kind != MountKind::bind_dev) flags |= kMsNodev;
                    if (m.kind == MountKind::bind_ro) flags |= kMsRdonly;
                    // nosuid always: a suid binary inside the sandbox is a
                    // privilege path we never want, and no_new_privs alone does
                    // not cover a nested userns.
                    flags |= kMsNosuid;
                    if (m.optional) flags |= kClayMountOptional;
                    // the mount point must exist AND be the same kind of thing
                    // as the source: binding a file onto a directory fails with
                    // ENOTDIR. we cannot stat at compile time (the plan may be
                    // applied on another machine), so emit both and let the
                    // apply step pick -- mkdir_p fails harmlessly if a file is
                    // already there, and touch fails harmlessly if a directory
                    // is. `bind_target` does exactly that.
                    //
                    // a bind_fd binds the PATH we resolved the descriptor to,
                    // not the descriptor. that is a real TOCTOU window and it is
                    // worth recording why it stays open, because two plausible
                    // ways of closing it do not work:
                    //
                    //   mount("/proc/self/fd/N", MS_BIND) is NOT refused by the
                    //   kernel -- mounts.hpp used to claim it was, and that is
                    //   wrong; it succeeds, and it follows the object rather than
                    //   the name. but only for a descriptor opened in the SAME
                    //   mount namespace. measured: the identical bind returns
                    //   EINVAL for an fd opened before unshare(CLONE_NEWNS) and
                    //   succeeds for one opened after. a caller's fd is always
                    //   the former, by definition, so this does not help.
                    //
                    //   open_tree(fd, OPEN_TREE_CLONE|AT_EMPTY_PATH) plus
                    //   move_mount() does bind a descriptor with no path at all,
                    //   and it works -- but it has the same namespace
                    //   restriction, and it would have to run in the PARENT
                    //   before the fork, which is a different shape of change
                    //   than this line.
                    //
                    // so the window is narrowed rather than closed: resolution
                    // happens in the parent, pre-fork, capturing the caller's own
                    // view. bubblewrap has the same window and documents it. a
                    // caller who needs it shut should bind a path they control
                    // rather than an fd into somebody else's directory.
                    b.op(OpCode::bind_target,
                         BindTargetOp{b.intern(m.source), b.intern(dst)});
                    b.op(OpCode::mount, MountOp{b.intern(m.source), b.intern(dst),
                                                b.intern("none"), Ref{}, flags});
                    // a bind mount DOES NOT APPLY ITS FLAGS -- the kernel
                    // ignores MS_RDONLY and friends on the initial bind -- and a
                    // plain remount only affects the top mount. so every bind
                    // gets a recursive remount that walks mountinfo and ORs the
                    // flags onto each submount's existing ones.
                    //
                    // without this, `--ro-bind /home /home` on a machine where
                    // /home/x is its own mount leaves /home/x writable. that is
                    // a silent hole, and it is why this op exists rather than
                    // the single remount that was here before.
                    std::uint64_t add = kMsNosuid;
                    if (m.kind != MountKind::bind_dev) add |= kMsNodev;
                    if (m.kind == MountKind::bind_ro) add |= kMsRdonly;
                    b.op(OpCode::remount_recursive,
                         RemountRecursiveOp{b.intern(dst),
                                            add | (m.optional ? kClayMountOptional : 0)});
                    break;
                }
                case MountKind::tmpfs: {
                    b.op(OpCode::mkdir_p, MkdirOp{b.intern(dst), 0755, 0});
                    // mode=0755, matching bubblewrap. tmpfs defaults to 1777,
                    // and the sticky bit there is not a small difference: it
                    // makes the kernel refuse O_CREAT on any file the guest does
                    // not own, which breaks a shell redirect over a bind-mounted
                    // file. see the devtmpfs case for the full story.
                    //
                    // the size, when the caller gave one, goes in the same option
                    // string. it was previously accepted and DROPPED, which made
                    // `.tmpfs("/tmp", 64_MB)` a silent lie -- the guest got an
                    // unbounded tmpfs, so a filled /tmp was host memory pressure
                    // rather than a contained ENOSPC. a resource limit that is
                    // quietly ignored is worse than one that is refused.
                    //
                    // the mode is the caller's when they gave one (bwrap's
                    // `--perms MODE --tmpfs DST`), 0755 otherwise. always four
                    // octal digits, so "mode=NNNN" has a fixed length.
                    const std::uint32_t mode = (m.perms ? m.perms : 0755u) & 07777u;
                    char opts[64] = "mode=0000";
                    opts[5] = static_cast<char>('0' + ((mode >> 9) & 7));
                    opts[6] = static_cast<char>('0' + ((mode >> 6) & 7));
                    opts[7] = static_cast<char>('0' + ((mode >> 3) & 7));
                    opts[8] = static_cast<char>('0' + (mode & 7));
                    if (m.size != 0) {
                        std::size_t n = 9;  // strlen("mode=NNNN")
                        const char* tail = ",size=";
                        for (std::size_t i = 0; tail[i]; ++i) opts[n++] = tail[i];
                        // decimal bytes, written by hand: this runs before the
                        // fork in a path that avoids snprintf for consistency
                        // with the rest of the compiler.
                        char digits[24];
                        std::size_t nd = 0;
                        std::uint64_t v = m.size;
                        while (v) {
                            digits[nd++] = static_cast<char>('0' + (v % 10));
                            v /= 10;
                        }
                        while (nd) opts[n++] = digits[--nd];
                        opts[n] = '\0';
                    }
                    b.op(OpCode::mount, MountOp{b.intern("tmpfs"), b.intern(dst),
                                                b.intern("tmpfs"), b.intern(opts),
                                                kMsNosuid | kMsNodev});
                    break;
                }
                case MountKind::proc: {
                    // a fresh procfs shows only our own pid namespace, so the
                    // guest cannot see or signal host processes through /proc.
                    //
                    // NOTE: this requires being a MEMBER of the pid namespace,
                    // not merely its creator. unshare(CLONE_NEWPID) puts our
                    // CHILDREN in the new namespace and leaves us outside it,
                    // so mounting procfs here fails with EPERM. spawn() does a
                    // second fork after apply() for exactly this reason.
                    b.op(OpCode::mkdir_p, MkdirOp{b.intern(dst), 0755, 0});
                    b.op(OpCode::mount, MountOp{b.intern("proc"), b.intern(dst),
                                                b.intern("proc"), Ref{},
                                                kMsNosuid | kMsNodev | kMsNoexec});

                    // MASK THE LEAKY ENTRIES.
                    //
                    // a fresh procfs is namespaced for PIDs but NOT for the
                    // kernel-global files, and several of those are a gift to an
                    // attacker. /proc/kallsyms hands over every kernel symbol
                    // address, which defeats KASLR and turns an unexploitable
                    // bug into an exploitable one. bubblewrap leaves these
                    // readable and expects the caller to think of it; the escape
                    // corpus caught claybin doing the same, which is how this
                    // list exists.
                    //
                    // masking is a bind of /dev/null over the file: reads get
                    // EOF rather than EACCES, which keeps programs that
                    // opportunistically peek at them working.
                    //
                    // but /dev/null ACCEPTS WRITES, so a bind of it over
                    // sysrq-trigger still lets a guest reboot the host. the
                    // corpus caught exactly that. so the write-dangerous ones get
                    // a read-only remount on top, and the read-only ones do not
                    // need it.
                    for (const char* leak : {"kallsyms", "modules", "config.gz",
                                             "slabinfo", "vmallocinfo",
                                             "sched_debug", "timer_list",
                                             "kcore", "kmsg"}) {
                        std::string target = dst + "/" + leak;
                        b.op(OpCode::mount,
                             MountOp{b.intern("/dev/null"), b.intern(target), b.intern("none"),
                                     Ref{}, kMsBind | kMsNosuid | kClayMountOptional});
                    }
                    // the write-dangerous ones need a READ-ONLY mask, and
                    // /dev/null cannot provide one: a bind of /dev/null accepts
                    // writes, and remounting THAT read-only returns EPERM (the
                    // kernel refuses to remount a device bind). so we bind an
                    // empty mode-0444 file from our own staging tmpfs instead,
                    // which remounts read-only happily.
                    //
                    // without this a guest can write /proc/sysrq-trigger and
                    // reboot the host. the escape corpus caught it, and then
                    // caught the /dev/null version of the fix not working.
                    for (const char* danger : {"sysrq-trigger", "sys/kernel/core_pattern",
                                               "sys/kernel/modprobe",
                                               "sys/kernel/uevent_helper"}) {
                        std::string target = dst + "/" + danger;
                        b.op(OpCode::mount,
                             MountOp{b.intern(kRoMaskFile), b.intern(target), b.intern("none"),
                                     Ref{}, kMsBind | kMsNosuid | kClayMountOptional});
                        b.op(OpCode::mount,
                             MountOp{b.intern("none"), b.intern(target), b.intern("none"),
                                     Ref{}, kMsBind | kMsRemount | kMsRdonly | kMsNosuid |
                                                kClayMountOptional});
                    }
                    // and the whole of /proc/sys, which is a large and
                    // ever-growing attack surface. a read-only bind of an empty
                    // tmpfs is the standard container answer.
                    b.op(OpCode::mount,
                         MountOp{b.intern("tmpfs"), b.intern(dst + "/sys"), b.intern("tmpfs"),
                                 Ref{}, kMsNosuid | kMsNodev | kMsNoexec | kMsRdonly |
                                            kClayMountOptional});

                    report.record(CapId::device_isolation, Enforcement::partial,
                                  "procfs leak masking");
                    break;
                }
                case MountKind::devtmpfs: {
                    // a tmpfs, then bind the handful of device nodes a program
                    // actually needs. binding individual nodes rather than
                    // mounting devtmpfs means /dev/mem and friends are simply
                    // absent rather than present-but-denied.
                    //
                    // the node list and the layout follow bubblewrap exactly,
                    // because guests depend on the details: six real devices
                    // bound in, then stdin/stdout/stderr as SYMLINKS into
                    // /proc/self/fd (they are not devices and cannot be bound),
                    // then a devpts instance with a ptmx symlink so a guest can
                    // actually allocate a pty.
                    b.op(OpCode::mkdir_p, MkdirOp{b.intern(dst), 0755, 0});
                    // mode=0755 is NOT cosmetic, and it is the one detail here
                    // that is easy to leave out.
                    //
                    // tmpfs defaults to 1777 -- world-writable plus the STICKY
                    // bit. sticky means the kernel refuses to let you touch a
                    // file you do not own, and O_CREAT counts as touching even
                    // when the file already exists. every device node below is
                    // bind-mounted from the host and owned by the outer root, so
                    // with the default mode `sh -c 'cmd > /dev/null'` fails with
                    // EACCES: the shell always passes O_CREAT on `>`.
                    //
                    // that reads exactly like a landlock denial, which is what
                    // makes it worth a comment -- it is not. it reproduces with
                    // zero landlock rules in the plan, and no grant fixes it.
                    // size=1m: only symlinks, mount points and empty bind
                    // targets live on this tmpfs. without a size it defaults
                    // to half of RAM, and /dev/shm used to be a plain dir on
                    // it, so a guest could fill host memory through it.
                    b.op(OpCode::mount, MountOp{b.intern("tmpfs"), b.intern(dst),
                                                b.intern("tmpfs"), b.intern("mode=0755,size=1m"),
                                                kMsNosuid | kMsNoexec});
                    for (const char* node : {"null", "zero", "full", "random", "urandom",
                                             "tty"}) {
                        std::string host_node = std::string("/dev/") + node;
                        std::string sand_node = dst + "/" + node;
                        // a bind mount needs the target to EXIST and to be the
                        // same kind of thing, so a device node needs an empty
                        // regular file to land on, not a directory.
                        b.op(OpCode::touch, MkdirOp{b.intern(sand_node), 0444, 0});
                        // optional: /dev/tty does not exist when there is no
                        // controlling terminal, and a missing device node is not
                        // a security failure -- it just is not there.
                        b.op(OpCode::mount,
                             MountOp{b.intern(host_node), b.intern(sand_node), b.intern("none"),
                                     Ref{}, kMsBind | kClayMountOptional});
                    }
                    // stdio are symlinks into procfs, not devices.
                    for (int fdno = 0; fdno < 3; ++fdno) {
                        static const char* names[] = {"stdin", "stdout", "stderr"};
                        std::string target = "/proc/self/fd/" + std::to_string(fdno);
                        b.op(OpCode::symlink_at,
                             SymlinkOp{b.intern(target), b.intern(dst + "/" + names[fdno])});
                    }
                    // and so are these two: /dev/fd is the classic alias for a
                    // process's own descriptor table, /dev/core for its memory.
                    b.op(OpCode::symlink_at,
                         SymlinkOp{b.intern("/proc/self/fd"), b.intern(dst + "/fd")});
                    b.op(OpCode::symlink_at,
                         SymlinkOp{b.intern("/proc/kcore"), b.intern(dst + "/core")});
                    // a private devpts, so a guest can open a pty without
                    // reaching the host's. newinstance is what keeps it private.
                    b.op(OpCode::mkdir_p, MkdirOp{b.intern(dst + "/pts"), 0755, 0});
                    b.op(OpCode::mount,
                         MountOp{b.intern("devpts"), b.intern(dst + "/pts"), b.intern("devpts"),
                                 b.intern("newinstance,ptmxmode=0666,mode=620"),
                                 kMsNosuid | kMsNoexec | kClayMountOptional});
                    b.op(OpCode::symlink_at,
                         SymlinkOp{b.intern("pts/ptmx"), b.intern(dst + "/ptmx")});
                    // /dev/shm is its own tmpfs with a cap, the way docker
                    // does it (64 MiB unless the mount asks for more). 1777
                    // because POSIX shm_open needs any user to create there.
                    b.op(OpCode::mkdir_p, MkdirOp{b.intern(dst + "/shm"), 0755, 0});
                    {
                        const std::uint64_t shm = m.size ? m.size : (64ull << 20);
                        const std::string opts = "mode=1777,size=" + std::to_string(shm);
                        b.op(OpCode::mount,
                             MountOp{b.intern("tmpfs"), b.intern(dst + "/shm"),
                                     b.intern("tmpfs"), b.intern(opts),
                                     kMsNosuid | kMsNodev | kMsNoexec});
                    }

                    report.record(CapId::device_isolation, Enforcement::strong, "dev allowlist");
                    break;
                }
                case MountKind::symlink: {
                    b.op(OpCode::symlink_at,
                         SymlinkOp{b.intern(m.source), b.intern(dst)});
                    break;
                }
                case MountKind::mask: {
                    // make the path be nothing. two ops, because the target may
                    // be a file or a directory and the plan may be applied on a
                    // machine where it is the other one:
                    //
                    //   * an empty tmpfs, for a directory
                    //   * the mode-0444 mask file, for a file
                    //
                    // both are marked optional, so whichever does not apply
                    // fails harmlessly -- mounting a tmpfs over a regular file
                    // is ENOTDIR, and binding a file over a directory is
                    // EISDIR. that is the same "emit both, let apply pick"
                    // shape bind_target already uses for exactly this reason.
                    //
                    // NOT a landlock deny: landlock has no negative rule, so a
                    // deny under a grant is silently inherited. see
                    // MountKind::mask.
                    b.op(OpCode::mount,
                         MountOp{b.intern("tmpfs"), b.intern(dst), b.intern("tmpfs"),
                                 b.intern("mode=0555,size=4k"),
                                 kMsNosuid | kMsNodev | kMsNoexec | kMsRdonly |
                                     kClayMountOptional});
                    b.op(OpCode::mount,
                         MountOp{b.intern(kRoMaskFile), b.intern(dst), b.intern("none"),
                                 Ref{}, kMsBind | kMsSilent | kClayMountOptional});
                    break;
                }
                case MountKind::dir: {
                    b.op(OpCode::mkdir_p, MkdirOp{b.intern(dst), m.perms ? m.perms : 0755u, 0});
                    break;
                }
                case MountKind::mqueue: {
                    // a posix message queue filesystem, its own instance, so the
                    // guest cannot see or write host queues.
                    //
                    // NOT optional: mounting mqueue needs privilege an
                    // unprivileged user namespace does not have, so this usually
                    // fails -- and bubblewrap fails too. making it optional would
                    // mean claybin "succeeds" with no /dev/mqueue while the caller
                    // believes they got one, which is exactly the kind of quiet
                    // divergence this library exists to avoid.
                    b.op(OpCode::mkdir_p, MkdirOp{b.intern(dst), 0755, 0});
                    b.op(OpCode::mount,
                         MountOp{b.intern("mqueue"), b.intern(dst), b.intern("mqueue"), Ref{},
                                 kMsNosuid | kMsNodev | kMsNoexec});
                    break;
                }

                case MountKind::file:
                case MountKind::bind_data:
                case MountKind::bind_data_ro: {
                    // copy the caller's fd into the tree. the fd number travels
                    // in the op, and the copy happens post-fork where we are
                    // already inside the namespace -- so the bytes land on OUR
                    // tmpfs and never touch a host path.
                    std::uint32_t flags = 0;
                    if (m.kind != MountKind::file) flags |= 1;  // bind it in
                    if (m.kind == MountKind::bind_data_ro) flags |= 2;  // read-only
                    b.op(OpCode::write_fd_content,
                         WriteFdContentOp{b.intern(dst),
                                          static_cast<std::int32_t>(m.content_fd),
                                          m.perms ? m.perms : 0644u, flags, 0});
                    break;
                }

                case MountKind::overlay:
                case MountKind::tmp_overlay:
                case MountKind::ro_overlay: {
                    // overlayfs takes its layers as a comma-separated option
                    // string, so a layer path containing a comma or a colon has
                    // to be escaped or the kernel parses it as a separator and
                    // silently mounts the wrong thing.
                    auto esc = [](const std::string& p) {
                        std::string o;
                        for (char c : p) {
                            if (c == ',' || c == ':' || c == '\\') o.push_back('\\');
                            o.push_back(c);
                        }
                        return o;
                    };

                    std::string opts = "lowerdir=";
                    bool first = true;
                    for (const auto& l : m.lowers) {
                        if (!first) opts += ":";
                        first = false;
                        opts += esc(l);
                    }

                    if (m.kind == MountKind::overlay) {
                        opts += ",upperdir=" + esc(m.source);
                        opts += ",workdir=" + esc(m.workdir);
                    } else if (m.kind == MountKind::tmp_overlay) {
                        // the upper and work layers live on a tmpfs we mount
                        // ourselves, so every change the guest makes is
                        // discarded when the sandbox exits. the tmpfs has to be
                        // mounted BEFORE the overlay that uses it.
                        std::string scratch = std::string(kStageBase) + "/ovl" +
                                              std::to_string(ovl_index);
                        b.op(OpCode::mkdir_p, MkdirOp{b.intern(scratch), 0755, 0});
                        b.op(OpCode::mount,
                             MountOp{b.intern("tmpfs"), b.intern(scratch), b.intern("tmpfs"),
                                     Ref{}, kMsNosuid | kMsNodev});
                        b.op(OpCode::mkdir_p, MkdirOp{b.intern(scratch + "/upper"), 0755, 0});
                        b.op(OpCode::mkdir_p, MkdirOp{b.intern(scratch + "/work"), 0755, 0});
                        opts += ",upperdir=" + esc(scratch + "/upper");
                        opts += ",workdir=" + esc(scratch + "/work");
                        ++ovl_index;
                    }
                    // ro_overlay gets no upperdir at all, which is what makes
                    // the merged view unwritable.

                    // userxattr is REQUIRED in a user namespace: without it the
                    // kernel tries to use trusted.* xattrs, which need
                    // CAP_SYS_ADMIN in the init namespace, and the mount fails
                    // with EPERM for no visible reason.
                    opts += ",userxattr";

                    b.op(OpCode::mkdir_p, MkdirOp{b.intern(dst), 0755, 0});
                    b.op(OpCode::mount,
                         MountOp{b.intern("overlay"), b.intern(dst), b.intern("overlay"),
                                 b.intern(opts), kMsNosuid | kMsNodev});
                    break;
                }
            }
        }

        // 4. pivot into the new tree and detach the old one.
        //
        //    two pivots, following bubblewrap. the first moves us into the
        //    staging tmpfs with the real root parked at oldroot/. the second
        //    uses the pivot_root(".", ".") trick: put_old is allowed to be the
        //    same directory as new_root, which stacks the old root ON TOP of
        //    itself and lets us umount it with no leftover directory in the
        //    guest's tree. doing it the obvious way leaves a visible /oldroot
        //    that the guest can see even after the detach.
        b.op(OpCode::pivot_root, PivotRootOp{b.intern(kStageBase), b.intern("oldroot")});
        b.op(OpCode::pivot_into_newroot, PivotRootOp{b.intern("/newroot"), Ref{}});

        report.record(CapId::fs_read, Enforcement::strong, "mount-ns");
        report.record(CapId::fs_write, Enforcement::strong, "mount-ns");
    }

    // -- phase: process ----------------------------------------------------
    if (host.uts_namespaces && !d.hostname.empty())
        b.op(OpCode::set_hostname, SetHostnameOp{b.intern(d.hostname)});

    // a new session detaches the guest from the host's controlling terminal.
    // that is not cosmetic: a guest sharing a tty can inject keystrokes into it
    // with TIOCSTI, which is a genuine escape when the host side is a shell.
    if (d.new_session) b.op(OpCode::new_session, NoNewPrivsOp{0});

    // and this makes an orphaned sandbox die rather than linger unsupervised.
    if (d.die_with_parent) b.op(OpCode::die_with_parent, NoNewPrivsOp{0});

    // an explicit --uid/--gid means the guest should RUN as that id, not merely
    // have it mapped. the mapping was written in the namespace phase; this is
    // the setresuid/setresgid that actually adopts it.
    if (d.uid != kUnsetId || d.gid != kUnsetId) {
        b.op(OpCode::set_ids,
             SetIdsOp{d.uid == kUnsetId ? caller_uid() : d.uid,
                      d.gid == kUnsetId ? caller_gid() : d.gid});
    }

    b.op(OpCode::chdir, ChdirOp{b.intern(d.workdir)});

    // rlimits are a coarse backstop and nothing more. RLIMIT_AS caps address
    // space, not resident memory, so it is a floor under the cgroup, not a
    // substitute for it. we set both when we can.
    const auto& r = d.resources;
    auto rlimit = [&](std::uint32_t res, std::uint64_t v) {
        b.op(OpCode::set_rlimit, SetRlimitOp{res, 0, v, v});
    };

    // try for a real cgroup first, because whether we get one decides what the
    // report may claim.
    bool have_cgroup = false;
    if (host.cgroups == cgroup::Availability::delegated &&
        (!r.memory.is_unlimited() || !r.pids.is_unlimited())) {
        auto g = cgroup::create(cgroup::probe(), r, "box");
        if (g) {
            out.cgroup = std::move(*g);
            have_cgroup = out.cgroup.valid();
        }
        // a failure here is not fatal: rlimits still apply and the report will
        // say `partial` rather than `strong`. but we must not pretend.
    }

    if (!r.memory.is_unlimited()) {
        rlimit(kRlimitAs, r.memory.value());
        if (have_cgroup && host.cgroup_memory)
            // memory.max plus memory.swap.max=0: a cap that swap can defeat is
            // not a cap.
            report.record(CapId::mem_limit, Enforcement::strong, "cgroup2 memory.max");
        else
            report.record(CapId::mem_limit, Enforcement::partial, "rlimit-as");
    }
    if (!r.pids.is_unlimited()) {
        rlimit(kRlimitNproc, r.pids.value());
        if (have_cgroup && host.cgroup_pids)
            report.record(CapId::pid_limit, Enforcement::strong, "cgroup2 pids.max");
        else
            // RLIMIT_NPROC is per-UID, not per-sandbox: another process running
            // as the same user counts against it. genuinely partial.
            report.record(CapId::pid_limit, Enforcement::partial, "rlimit-nproc");
    }
    if (!r.open_files.is_unlimited()) rlimit(kRlimitNofile, r.open_files.value());
    if (!r.core_size.is_unlimited()) rlimit(kRlimitCore, r.core_size.value());
    if (!r.cpu_time.is_unlimited()) {
        // RLIMIT_CPU is in seconds, and rounding down to 0 would kill instantly.
        std::uint64_t secs = r.cpu_time.value() / 1'000'000'000ull;
        rlimit(kRlimitCpu, secs ? secs : 1);
        report.record(CapId::cpu_limit, Enforcement::partial, "rlimit-cpu");
    }
    if (!r.cpu_quota_percent.is_unlimited()) {
        if (have_cgroup && host.cgroup_cpu)
            report.record(CapId::cpu_limit, Enforcement::strong, "cgroup2 cpu.max");
        else
            // the cpu controller is frequently NOT delegated to user sessions,
            // so asking for a quota and getting nothing is common. say so.
            report.record(CapId::cpu_limit, Enforcement::none, "cpu controller not delegated");
    }

    // wall-clock is not a kernel mechanism at all: it needs a supervisor with a
    // timer, which is the loop's job. record nothing rather than imply we did.

    // -- phase: privilege drop (BEFORE landlock) ---------------------------
    // landlock_restrict_self and seccomp both require no_new_privs to already
    // be set, so this phase has to come first. it fails with a bare EPERM
    // otherwise, which is almost impossible to diagnose from the symptom.
    if (host.no_new_privs) {
        // close inherited descriptors FIRST, while we still can name them.
        //
        // THIS IS A REAL HOLE BUBBLEWRAP LEAVES OPEN. an inherited fd is a
        // capability the sandbox never granted, and it bypasses every wall we
        // build: landlock mediates path RESOLUTION, and an already-open fd needs
        // none. a supervisor holding a descriptor on a private key when it spawns
        // a guest has handed that key over, and no mount or landlock policy takes
        // it back.
        //
        // bwrap closes only the fds it knows about; claybin closes everything,
        // because "fds the caller forgot" is exactly the dangerous set.
        //
        // it goes here rather than in the fds phase because the mount phase uses
        // --file source descriptors and the landlock ruleset fd is already open:
        // closing earlier takes out the descriptors the rest of the plan needs.
        if (d.close_inherited_fds) {
            CloseRangeOp cr{3, 0xffffffffu, 0, {}};
            if (cr.keep_count < sizeof cr.keep / sizeof cr.keep[0])
                cr.keep[cr.keep_count++] = kReportFdSentinel;
            // and the broker relay, when brokering: the guest writes to it after
            // this op runs, so closing it here would silently break the handoff.
            if (cr.keep_count < sizeof cr.keep / sizeof cr.keep[0])
                cr.keep[cr.keep_count++] = kRelayFdSentinel;
            if (cr.keep_count < sizeof cr.keep / sizeof cr.keep[0])
                cr.keep[cr.keep_count++] = kRelayFd2Sentinel;
            // and the guest's proxy listener: the sweep runs in a process that
            // INHERITED it, and closing it there unbinds the socket.
            if (cr.keep_count < sizeof cr.keep / sizeof cr.keep[0])
                cr.keep[cr.keep_count++] = kProxyListenFdSentinel;
            // and whatever descriptors the CALLER will ask spawn() to carry in.
            //
            // the sentinels are always emitted, even though most callers use
            // none: the plan is compiled before Command exists, so the compiler
            // cannot know how many there will be. an unused slot resolves to
            // 0xffffffff and is skipped, which costs nothing. the alternative --
            // compiling the plan per-spawn once the fds are known -- would make
            // a Plan no longer reusable across launches, which is one of the
            // points of having an IR at all.
            for (std::uint32_t s = 0; s < kMaxPreservedFds; ++s) {
                if (cr.keep_count >= sizeof cr.keep / sizeof cr.keep[0]) break;
                cr.keep[cr.keep_count++] = kPreservedFdSentinelBase + s;
            }
            b.op(OpCode::close_range, cr);
        }

        b.op(OpCode::no_new_privs, NoNewPrivsOp{0});
        // the bounding set: everything NOT in keep_caps is dropped, so a caller
        // who says nothing gets the empty set. forbidden_caps() is masked out
        // even if a caller managed to ask, because a sandbox holding
        // CAP_SYS_ADMIN is not a sandbox.
        Caps keep = d.keep_caps.without(forbidden_caps());
        b.op(OpCode::drop_caps, DropCapsOp{keep.bits()});
        if (keep.is_nothing()) {
            report.record(CapId::privilege_drop, Enforcement::strong,
                          "no_new_privs+empty bounding set");
        } else {
            // keeping any capability is a real weakening, and the report must
            // not describe it the same way as dropping everything.
            report.record(CapId::privilege_drop, Enforcement::partial,
                          "no_new_privs, some capabilities retained");
        }
    } else {
        degrade(CapId::privilege_drop);
        // without nnp we cannot install landlock or seccomp at all, so nothing
        // below would work either. say so rather than emitting a plan that is
        // going to fail at apply() time.
        return std::unexpected(
            Error{Errc::unsupported, "no_new_privs required for landlock/seccomp"});
    }

    // -- phase: landlock ---------------------------------------------------
    if (host.landlock_abi > 0) {
        const std::uint64_t handled = handled_access(host.landlock_abi);

        // landlock can also mediate TCP bind/connect by port, from abi 4. that is
        // a real second wall rather than a nicety: a network namespace is
        // all-or-nothing, so "this process may reach exactly port 443" has no
        // netns expression at all. combining them gives a guest with no netns
        // isolation (because it needs SOME network) a per-port restriction it
        // could not otherwise have.
        //
        // BUT only when there are per-port rules to add. landlock is
        // deny-by-default over whatever the ruleset HANDLES, so handling
        // connect_tcp and then adding no rules denies every connect the guest
        // makes -- including one to a proxy on its own loopback. a blanket
        // grant ("any port") has no landlock expression, so handling it is not
        // a weaker wall, it is a broken one.
        const bool net_by_port =
            wants_net && !d.net.blanket().any(kNetConnect)
            && !d.net.blanket().any(kNetBind)
            && std::any_of(d.net.endpoints().begin(), d.net.endpoints().end(),
                           [](const NetEndpoint& e) { return e.port != 0; });
        std::uint64_t handled_net = 0;
        const bool want_net_rules = host.landlock_abi >= 4 && net_by_port;
        if (want_net_rules) handled_net = kLlBindTcp | kLlConnectTcp;

        // when a tree was built, landlock rules apply to the SANDBOX paths, not
        // the host ones, because that is what exists after the pivot. the mount
        // plan already describes exactly those, so fold its implied grants in
        // and let meet() keep whichever is tighter.
        FsAuthority effective = d.fs;
        if (!d.mounts.empty()) {
            // the mount plan's other interpretation. on linux this is a second
            // independent wall over the real tree; on a mountless host it is
            // the only wall. same fold either way.
            FsAuthority implied = d.mounts.implied_authority();
            if (building_tree) {
                // the new root itself needs to be listable, or readdir("/")
                // fails and anything that walks the tree looks broken for no
                // visible reason. it is a tmpfs containing only what we
                // mounted, so this grants nothing the caller did not ask for.
                implied.grant("/", FileRights::read());
            }
            // three cases, and the middle one is the interesting one.
            //
            //   caller said NOTHING          -> the mounts decide.
            //   caller said only "NOT THAT"  -> the mounts decide, minus that.
            //   caller named grants          -> intersect: a path must be both
            //                                  mounted AND granted.
            //
            // the middle case used to fall into the third, and meet() treats
            // an unmentioned path as denied -- so an authority consisting only
            // of denials erased every mount-implied grant and the compiled
            // ruleset came out empty. a policy of "everything the mounts give
            // me, except my credentials" is the single most useful thing a
            // caller can say, and it produced a sandbox that could read
            // nothing at all.
            //
            // expressed as implied-THEN-deny rather than as a meet, because
            // that is what the caller meant: the denials are a subtraction
            // from whatever the tree provides, not a whitelist of their own.
            if (d.fs.is_nothing()) {
                effective = implied;
            } else if (d.fs.grants_nothing()) {
                effective = implied;
                for (const auto& g : d.fs.grants()) effective.deny(g.path);
            } else {
                effective = d.fs.meet(implied);
            }
        }

        for (const auto& g : effective.grants()) {
            // a rule may only allow what the ruleset handles. masking here
            // rather than trusting the translation keeps a future FileRights
            // bit from silently breaking every sandbox.
            std::uint64_t allowed = to_landlock(g.rights, host.landlock_abi) & handled;
            // a pure deny emits NO landlock rule, and this is a kernel limit
            // rather than a choice.
            //
            // landlock has no negative rule. landlock_add_rule() with
            // allowed_access == 0 is rejected outright -- measured, ENOMSG on
            // abi 10 -- and omitting the rule means the path INHERITS its
            // ancestor's grant, because resolution takes the most specific
            // matching rule and there now isn't one.
            //
            // so "grant $HOME, deny $HOME/.aws" is not expressible here at
            // all. i tried: the rule was written into the plan, reached the
            // kernel, and the credentials stayed readable, because the only
            // thing a zero-rights rule can do is fail to be added.
            //
            // the only ways to express it are to grant each SIBLING instead of
            // the parent, or to mask the path with a mount -- which is what
            // MountKind::file over an empty file does, and is how a caller
            // should spell a credential mask. see agentty's kAlwaysMasked.
            if (allowed == 0) continue;
            b.op(OpCode::landlock_rule, LandlockRuleOp{b.intern(g.path), allowed});
        }
        // network rules, one per allowed port. a port of 0 means "any", which
        // landlock cannot express -- so in that case we install no net rules and
        // the report says `partial` rather than pretending the ports were
        // enforced.
        bool net_fully_enforced = want_net_rules;
        if (want_net_rules) {
            for (const auto& e : d.net.endpoints()) {
                if (e.port == 0) {
                    net_fully_enforced = false;
                    continue;
                }
                std::uint64_t allowed = 0;
                if (e.ops.any(kNetConnect)) allowed |= kLlConnectTcp;
                if (e.ops.any(kNetBind)) allowed |= kLlBindTcp;
                if (allowed == 0) continue;
                b.op(OpCode::landlock_net_rule,
                     LandlockNetRuleOp{allowed, e.port, {}});
            }
        }

        // landlock scoping (abi 6+). this is the third kind of thing landlock
        // mediates, and it is different in shape from the other two: there is no
        // rule to add, only a handled set, because there is no object to name.
        //
        // it closes two channels that ignore the filesystem entirely, so no
        // amount of path or mount work touches them:
        //
        //   abstract unix sockets. these live in the NETWORK namespace, not the
        //   mount namespace, so a sandbox that only unshares mounts leaves the
        //   guest able to reach host services listening on abstract names -- and
        //   an abstract socket has no path, so landlock's fs rules cannot see it
        //   either. before scoping the only thing stopping this was an empty
        //   netns, which is all-or-nothing and gone the moment the guest needs
        //   real network. the escape corpus proves the gap was live: with network
        //   granted and scoping removed, net.abstract_unix_live escapes.
        //
        //   signals. without this the guest can signal any process sharing its
        //   uid, which includes the supervisor watching it.
        //
        // scoping is strictly better than a netns here because it COMPOSES: a
        // guest can have network and still be unable to reach the host's abstract
        // sockets, which the namespace approach cannot express.
        std::uint64_t scoped = 0;
        if (host.landlock_abi >= 6) {
            constexpr std::uint64_t kLlScopeAbstractUnix = 1ull << 0;
            constexpr std::uint64_t kLlScopeSignal = 1ull << 1;

            // both are unconditional, because scoping is about crossing the
            // sandbox BOUNDARY and no policy grants that. talking to a port is
            // not permission to talk to arbitrary host daemons, and the guest can
            // still signal its own children either way -- kProcSignalSelfTree is
            // about the guest's own tree, which scoping never touches.
            scoped |= kLlScopeAbstractUnix;
            scoped |= kLlScopeSignal;
        }

        b.op(OpCode::landlock_enforce,
             LandlockEnforceOp{handled, net_fully_enforced ? handled_net : 0, scoped,
                               host.landlock_abi, 0});

        report.record(CapId::fs_read, Enforcement::strong, "landlock");
        report.record(CapId::fs_write, Enforcement::strong, "landlock");
        report.record(CapId::fs_exec, Enforcement::strong, "landlock");
        if (net_fully_enforced) {
            // per-port TCP control, which a netns cannot give us. this is the one
            // case where granting network does NOT mean giving up enforcement.
            report.record(CapId::net_isolation, Enforcement::strong,
                          "landlock net (per-port TCP)");
        }
    } else if (!building_tree) {
        degrade(CapId::fs_read);
        degrade(CapId::fs_write);
        degrade(CapId::fs_exec);
    }

    // -- phase: seccomp (last wall) ---------------------------------------
    if (host.seccomp) {
        SyscallPolicy sys = d.syscalls;
        if (sys.default_action() == SysAction::kill_process && sys.rules().empty()) {
            // a policy that never named a syscall would kill the child before it
            // could exec. that is a policy bug, not something to paper over.
            return std::unexpected(
                Error{Errc::invalid_policy, "seccomp: empty allow-list would kill on exec"});
        }
        // does the policy delegate anything to a supervisor? if so the kernel
        // has to hand us a listener fd, which is a different install call.
        bool wants_notify = sys.default_action() == SysAction::notify;
        for (const auto& rule : sys.rules())
            if (rule.action == SysAction::notify) wants_notify = true;

        if (wants_notify && !host.seccomp_user_notif)
            return std::unexpected(Error{
                Errc::unsupported,
                "policy brokers syscalls but the kernel has no SECCOMP_RET_USER_NOTIF"});

        // a brokered policy needs sendmsg, and it needs it to be permitted by
        // the very filter being installed.
        //
        // the listener fd the kernel returns has to reach the SUPERVISOR, which
        // is a different process, and SCM_RIGHTS over a socket is the only
        // channel left by that point. that means one sendmsg AFTER the filter is
        // live -- so a filter that denies sendmsg makes brokering impossible and
        // fails with EPERM from our own policy, which is a memorably confusing
        // way to find out.
        //
        // sendmsg on an AF_UNIX socket the guest cannot name is not a meaningful
        // grant: it has no descriptor to send on once the handshake fd is closed.
        if (wants_notify) sys.allow(46 /* sendmsg */);

        auto prog = bpf::compile(sys);
        if (!prog) return std::unexpected(prog.error());

        auto blob = std::span<const std::byte>{
            reinterpret_cast<const std::byte*>(prog->insns.data()),
            prog->insns.size() * sizeof(bpf::Insn)};

        b.op(OpCode::seccomp_install,
             SeccompInstallOp{b.intern_blob(blob), static_cast<std::uint32_t>(prog->insns.size()),
                              wants_notify ? 1u : 0u});
        // a filter that permits everything is INSTALLED but is not a wall, and
        // saying `strong` for it is exactly the kind of claim this report
        // exists to make impossible. the arch guard alone is worth something --
        // it kills a foreign syscall convention -- so this is `partial`, not
        // `none`.
        //
        // found by agentty's settings pane: its "syscall filter: off" row
        // compiled to SyscallPolicy::everything() and the report cheerfully
        // said `strong syscall.filter`, which would have put a green wall on
        // screen for a filter the user had just turned off.
        if (sys.default_action() == SysAction::allow && sys.rules().empty() &&
            sys.arg_rules().empty() && sys.arg_allow_sets().empty()) {
            report.record(CapId::syscall_filter, Enforcement::partial,
                          "seccomp-bpf: arch guard only, all syscalls permitted");
        } else {
            report.record(CapId::syscall_filter, Enforcement::strong, "seccomp-bpf");
        }
        out.brokers_syscalls = wants_notify;
    } else {
        degrade(CapId::syscall_filter);
    }

    // the process backend shares a kernel with the host. always say so: this is
    // the single most important line in the whole report.
    //
    // the mechanism string distinguishes WHY, because "none" has two very
    // different causes and a caller deciding whether to care deserves the real
    // one:
    //
    //   process-backend, kvm available   we do not implement a microvm, but this
    //                                    host could run one. the gap is ours.
    //   process-backend, no kvm          the hardware boundary is not available
    //                                    here at all, so no backend could give
    //                                    it. the gap is the host's.
    //
    // that distinction is the whole reason HostCapabilities::kvm exists -- it
    // is otherwise unused by this backend. reporting a flat "process-backend"
    // invited the reader to assume the first case, which is wrong on most CI
    // runners and on every container without /dev/kvm passed through.
    report.record(CapId::host_kernel_isolation, Enforcement::none,
                  host.kvm ? "process-backend, kvm available"
                           : "process-backend, no kvm");

    // devices: with a tree we mount an explicit allowlist, so /dev/mem and
    // friends are ABSENT rather than denied. without one, the best we can do is
    // whatever landlock covers, which does not mediate device nodes usefully.
    if (!building_tree)
        report.record(CapId::device_isolation, Enforcement::none,
                      "needs a mount namespace for a /dev allowlist");

    auto plan = std::move(b).build();
    if (!plan) return std::unexpected(plan.error());

    out.plan = std::move(*plan);
    out.plan.set_guest_is_pid_1(d.as_pid_1);
    out.guarantees = std::move(report).build();
    return out;
}

}  // namespace clay
