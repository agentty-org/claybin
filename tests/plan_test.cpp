// the plan is the pre-fork/post-fork boundary, so its invariants are the ones
// that matter most: phase ordering (a security property), arena bounds (a
// memory-safety property), and relocatability (a correctness property).

#include "harness.hpp"

#include "claybin/plan/compile.hpp"
#include "claybin/plan/plan.hpp"
#include "claybin/policy/profiles.hpp"

using namespace clay;
using namespace clay::test;
using namespace clay::literals;

int main() {
    // -- arena: refs resolve, strings are shared --------------------------
    {
        PlanBuilder b;
        Ref a = b.intern("/workspace");
        Ref c = b.intern("/workspace");  // identical: must be interned once
        CHECK(a == c);
        Ref d = b.intern("/usr");
        CHECK(!(a == d));

        b.op(OpCode::chdir, ChdirOp{a});
        auto plan = std::move(b).build();
        CHECK(plan.has_value());
        CHECK_EQ(std::string(plan->cstr(a)), std::string("/workspace"));
        CHECK_EQ(std::string(plan->cstr(d)), std::string("/usr"));
    }

    // -- out-of-bounds refs are refused, not read -------------------------
    {
        PlanBuilder b;
        b.op(OpCode::chdir, ChdirOp{b.intern("/tmp")});
        auto plan = std::move(b).build();
        CHECK(plan.has_value());
        CHECK(plan->cstr(Ref{999999, 4}) == nullptr);
        CHECK(plan->cstr(Ref{0, 999999}) == nullptr);
        CHECK(plan->blob(Ref{999999, 4}).empty());
    }

    // -- phase ordering is enforced ---------------------------------------
    {
        // seccomp before landlock is backwards: the filter would block the very
        // syscalls landlock setup needs.
        PlanBuilder b;
        b.op(OpCode::seccomp_install, SeccompInstallOp{Ref{0, 0}, 0, 0});
        b.op(OpCode::landlock_enforce, LandlockEnforceOp{0, 0, 1, 0, 0});
        auto plan = std::move(b).build();
        CHECK(!plan.has_value());
        CHECK(plan.error().code == Errc::invalid_policy);
    }
    {
        // landlock before no_new_privs is also backwards, and this one is
        // subtle: landlock_restrict_self returns a bare EPERM when nnp is
        // unset, which surfaces much later as EACCES from execve.
        PlanBuilder b;
        b.op(OpCode::landlock_enforce, LandlockEnforceOp{0, 0, 1, 0, 0});
        b.op(OpCode::no_new_privs, NoNewPrivsOp{0});
        auto plan = std::move(b).build();
        CHECK(!plan.has_value());
    }
    {
        // and the right order builds fine
        PlanBuilder b;
        b.op(OpCode::unshare, UnshareOp{0});
        b.op(OpCode::chdir, ChdirOp{b.intern("/")});
        b.op(OpCode::no_new_privs, NoNewPrivsOp{0});
        b.op(OpCode::landlock_enforce, LandlockEnforceOp{0, 0, 1, 0, 0});
        b.op(OpCode::seccomp_install, SeccompInstallOp{Ref{0, 0}, 0, 0});
        auto plan = std::move(b).build();
        CHECK(plan.has_value());
        CHECK(plan->well_ordered());
        CHECK_EQ(plan->op_count(), std::size_t{5});
    }

    // -- phase_of covers every opcode with the right wall order -----------
    CHECK(phase_of(OpCode::unshare) < phase_of(OpCode::mount));
    CHECK(phase_of(OpCode::mount) < phase_of(OpCode::no_new_privs));
    // the three that matter most, in the order the kernel demands:
    // nnp -> landlock -> seccomp.
    CHECK(phase_of(OpCode::no_new_privs) < phase_of(OpCode::landlock_enforce));
    CHECK(phase_of(OpCode::landlock_enforce) < phase_of(OpCode::seccomp_install));
    for (auto c : {OpCode::unshare, OpCode::mount, OpCode::dup2, OpCode::chdir,
                   OpCode::landlock_rule, OpCode::drop_caps})
        CHECK(phase_of(c) <= phase_of(OpCode::seccomp_install));

    // -- the plan is relocatable ------------------------------------------
    {
        auto pol = Policy<Draft>{}
                       .read("/usr")
                       .read_write("/workspace")
                       .memory(512_MB)
                       .syscall_profile(profiles::base())
                       .seal();
        auto c = compile(pol, HostCapabilities::modern_linux());
        CHECK(c.has_value());

        // copy the raw bytes somewhere else, exactly as a fork or a pipe would.
        std::vector<std::byte> copy(c->plan.bytes().begin(), c->plan.bytes().end());
        CHECK_EQ(copy.size(), c->plan.size());
        // no absolute pointers means the copy is still walkable
        CHECK(c->plan.well_ordered());
        CHECK(c->plan.op_count() > 0);
    }

    // -- compile: the honest report ---------------------------------------
    {
        auto pol = Policy<Draft>{}
                       .read("/usr")
                       .read_write("/workspace")
                       .memory(512_MB)
                       .processes(64)
                       .syscall_profile(profiles::base())
                       .seal();

        auto c = compile(pol, HostCapabilities::modern_linux());
        CHECK(c.has_value());
        const auto& g = c->guarantees;

        CHECK(g.strength(CapId::fs_read) == Enforcement::strong);
        CHECK(g.strength(CapId::syscall_filter) == Enforcement::strong);
        CHECK(g.strength(CapId::net_isolation) == Enforcement::strong);  // no net -> netns
        CHECK(g.strength(CapId::privilege_drop) == Enforcement::strong);
        // resource limits: `strong` only when a real cgroup was created, which
        // depends on how THIS process was launched (cgroup v2 refuses to
        // delegate out of a cgroup holding processes). so assert the invariant
        // rather than a fixed value: strong iff we got a cgroup.
        if (c->cgroup.valid()) {
            CHECK(g.strength(CapId::mem_limit) == Enforcement::strong);
            CHECK(g.strength(CapId::pid_limit) == Enforcement::strong);
        } else {
            // rlimits only: RLIMIT_AS caps address space and RLIMIT_NPROC is
            // per-UID, so neither is a real per-sandbox cap.
            CHECK(g.strength(CapId::mem_limit) == Enforcement::partial);
            CHECK(g.strength(CapId::pid_limit) == Enforcement::partial);
        }
        // the line that must never be wrong: a process backend shares the kernel
        CHECK(g.strength(CapId::host_kernel_isolation) == Enforcement::none);
        CHECK(!g.witness<cap::HostKernelIsolation>().has_value());
        CHECK(c->degraded.empty());

        // and the walls are in the plan, in order
        CHECK(c->plan.has(OpCode::unshare));
        CHECK(c->plan.has(OpCode::landlock_enforce));
        CHECK(c->plan.has(OpCode::no_new_privs));
        CHECK(c->plan.has(OpCode::seccomp_install));
        CHECK(c->plan.well_ordered());
    }

    // -- a weak host degrades LOUDLY --------------------------------------
    {
        HostCapabilities old_kernel;
        old_kernel.user_namespaces = true;
        old_kernel.mount_namespaces = true;
        old_kernel.pid_namespaces = true;
        old_kernel.net_namespaces = true;
        old_kernel.seccomp = true;
        old_kernel.no_new_privs = true;
        old_kernel.landlock_abi = 0;  // no landlock
        // and no usable cgroups either
        old_kernel.cgroups = cgroup::Availability::unusable;

        auto pol = Policy<Draft>{}
                       .read("/usr")
                       .syscall_profile(profiles::base())
                       .seal();
        auto c = compile(pol, old_kernel);
        CHECK(c.has_value());
        // filesystem is NOT enforced, and the report says so rather than lying
        CHECK(c->guarantees.strength(CapId::fs_read) == Enforcement::none);
        CHECK(!c->guarantees.witness<cap::FilesystemRead>().has_value());
        CHECK(!c->degraded.empty());
        CHECK(!c->plan.has(OpCode::landlock_enforce));
        // but seccomp still went in
        CHECK(c->plan.has(OpCode::seccomp_install));
    }

    // -- a host that denies unprivileged userns emits NO unshare ---------
    //
    // regression: ipc used to be OR'd in unconditionally, so unshare_flags was
    // never empty and the op shipped even when every other namespace had been
    // correctly dropped. none of these namespaces is unprivileged on its own --
    // without CAP_SYS_ADMIN the kernel only grants them alongside a user
    // namespace -- so that op failed EPERM and killed the spawn with
    // "unshare (errno 1)" on exactly the locked-down hosts (Ubuntu 24.04's
    // AppArmor profile, hardened work laptops) that claybin exists to serve.
    {
        HostCapabilities locked_down;
        locked_down.user_namespaces = false;  // the uid_map write is denied
        locked_down.mount_namespaces = false;
        locked_down.pid_namespaces = false;
        locked_down.net_namespaces = false;
        locked_down.uts_namespaces = false;
        locked_down.ipc_namespaces = false;
        locked_down.seccomp = true;  // but these are UNPRIVILEGED
        locked_down.landlock_abi = 10;
        locked_down.no_new_privs = true;

        auto pol = Policy<Draft>{}
                       .read("/usr")
                       .syscall_profile(profiles::base())
                       .seal();
        auto c = compile(pol, locked_down);
        CHECK(c.has_value());

        // the whole point: no namespace op at all, rather than one that fails.
        CHECK(!c->plan.has(OpCode::unshare));

        // and the walls that DO work on such a host still went in.
        CHECK(c->plan.has(OpCode::landlock_enforce));
        CHECK(c->plan.has(OpCode::no_new_privs));
        CHECK(c->plan.has(OpCode::seccomp_install));
        CHECK(c->plan.well_ordered());
    }

    // -- every namespace flag is gated on its own capability --------------
    // a kernel that allows userns but genuinely lacks one other namespace must
    // not have that flag smuggled into the mask.
    {
        HostCapabilities no_ipc = HostCapabilities::modern_linux();
        no_ipc.ipc_namespaces = false;

        auto pol = Policy<Draft>{}
                       .read("/usr")
                       .syscall_profile(profiles::base())
                       .seal();
        auto c = compile(pol, no_ipc);
        CHECK(c.has_value());
        // userns is still there, so an unshare op is still correct...
        CHECK(c->plan.has(OpCode::unshare));
        // ...but it must not carry CLONE_NEWIPC.
        constexpr std::uint64_t kNewIpc = 0x08000000;
        bool checked = false;
        c->plan.for_each([&](OpCode code, std::span<const std::byte> payload) {
            if (code == OpCode::unshare) {
                UnshareOp op{};
                Plan::decode(payload, op);
                CHECK((op.flags & kNewIpc) == 0);
                checked = true;
            }
            return true;
        });
        CHECK(checked);
    }

    // -- audit fixes: shm cap, no core dumps, oom score, cgroup ns ---------
    {
        auto pol = Policy<Draft>{}
                       .read("/usr")
                       .dev_fs("/dev")
                       .oom_score_adj(500)
                       .syscall_profile(profiles::base())
                       .seal();
        auto c = compile(pol, HostCapabilities::modern_linux());
        CHECK(c.has_value());
        bool shm_capped = false, dev_capped = false, core0 = false, oom = false,
             cgroupns = false;
        c->plan.for_each([&](OpCode code, std::span<const std::byte> payload) {
            if (code == OpCode::mount) {
                MountOp op{};
                Plan::decode(payload, op);
                const char* tgt = c->plan.cstr(op.target);
                const char* dat = op.data.len ? c->plan.cstr(op.data) : "";
                const std::string_view t{tgt ? tgt : ""}, o{dat ? dat : ""};
                if (t.ends_with("/dev/shm") && o.find("size=67108864") != o.npos)
                    shm_capped = true;
                if (t.ends_with("/dev") && o.find("size=1m") != o.npos) dev_capped = true;
            } else if (code == OpCode::set_rlimit) {
                SetRlimitOp op{};
                Plan::decode(payload, op);
                if (op.resource == 4 /* RLIMIT_CORE */ && op.soft == 0 && op.hard == 0)
                    core0 = true;
            } else if (code == OpCode::write_file) {
                WriteFileOp op{};
                Plan::decode(payload, op);
                const char* p = c->plan.cstr(op.path);
                const char* v = c->plan.cstr(op.content);
                if (p && v && std::string_view{p} == "/proc/self/oom_score_adj" &&
                    std::string_view{v} == "500\n")
                    oom = true;
            } else if (code == OpCode::unshare) {
                UnshareOp op{};
                Plan::decode(payload, op);
                cgroupns = (op.flags & 0x02000000) != 0;
            }
            return true;
        });
        CHECK(shm_capped);
        CHECK(dev_capped);
        CHECK(core0);
        CHECK(oom);
        CHECK(cgroupns);

        // core dumps come back only when asked for.
        auto with_core = Policy<Draft>{}.read("/usr").core_dumps(true).seal();
        CHECK(with_core.data().resources.core_size.is_unlimited());

        // no cgroup ns on a host that can't create one.
        HostCapabilities no_cg = HostCapabilities::modern_linux();
        no_cg.cgroup_namespaces = false;
        auto c2 = compile(pol, no_cg);
        CHECK(c2.has_value());
        c2->plan.for_each([&](OpCode code, std::span<const std::byte> payload) {
            if (code == OpCode::unshare) {
                UnshareOp op{};
                Plan::decode(payload, op);
                CHECK((op.flags & 0x02000000) == 0);
            }
            return true;
        });
    }

    // -- private netns: the audit's #1 ------------------------------------
    {
        const auto hostcaps = HostCapabilities::modern_linux();
        // network authority WITHOUT the flag: shared namespace, honest report.
        auto shared = Policy<Draft>{}
                          .read("/usr")
                          .connect("", 0)
                          .syscall_profile(profiles::with_network())
                          .seal();
        auto cs = compile(shared, hostcaps);
        CHECK(cs.has_value());
        if (cs) {
            CHECK(cs->guarantees.strength(CapId::net_isolation) == Enforcement::partial);
            CHECK(!cs->plan.has(OpCode::loopback_up));
        }
        // with it: own namespace, loopback up, and the same `strong` the
        // no-network case reports.
        auto priv = Policy<Draft>{}
                        .read("/usr")
                        .connect("", 0)
                        .private_netns()
                        .syscall_profile(profiles::with_network())
                        .seal();
        auto cp = compile(priv, hostcaps);
        CHECK(cp.has_value());
        if (cp) {
            CHECK(cp->guarantees.strength(CapId::net_isolation) == Enforcement::strong);
            CHECK(cp->plan.has(OpCode::loopback_up));
            bool newnet = false;
            cp->plan.for_each([&](OpCode code, std::span<const std::byte> payload) {
                if (code == OpCode::unshare) {
                    UnshareOp op{};
                    Plan::decode(payload, op);
                    newnet = (op.flags & 0x40000000) != 0;
                }
                return true;
            });
            CHECK(newnet);
        }
        // no network at all: still an empty namespace, and no loopback (there
        // is nothing to reach).
        auto none = Policy<Draft>{}
                        .read("/usr")
                        .private_netns()
                        .syscall_profile(profiles::base())
                        .seal();
        auto cn = compile(none, hostcaps);
        CHECK(cn.has_value());
        if (cn) {
            CHECK(cn->guarantees.strength(CapId::net_isolation) == Enforcement::strong);
            CHECK(!cn->plan.has(OpCode::loopback_up));
        }
        // a host with no netns cannot pretend: no op, and the claim degrades.
        HostCapabilities no_netns = hostcaps;
        no_netns.net_namespaces = false;
        auto cx = compile(priv, no_netns);
        CHECK(cx.has_value());
        if (cx) {
            CHECK(cx->guarantees.strength(CapId::net_isolation) != Enforcement::strong);
            CHECK(!cx->plan.has(OpCode::loopback_up));
        }
    }

    // -- landlock abi gating: pathname unix sockets (abi 9) ----------------
    //
    // Measured on a real abi-10 host before this went in: without
    // RESOLVE_UNIX in the handled set, a landlock-confined process connects
    // to ANY pathname unix socket whatever its filesystem grants say. With
    // it, the same connect is EPERM. The host's dbus, docker and database
    // sockets are all pathname sockets, so the bit is worth asking for --
    // but only where the kernel knows it, because create_ruleset fails
    // outright on a bit it does not recognise.
    {
        constexpr std::uint64_t kResolveUnix = 1ull << 16;
        auto pol = Policy<Draft>{}
                       .read("/usr")
                       .syscall_profile(profiles::base())
                       .seal();
        auto allowed_bits = [&](std::uint32_t abi) -> std::uint64_t {
            HostCapabilities h = HostCapabilities::modern_linux();
            h.landlock_abi = abi;
            auto c = compile(pol, h);
            CHECK(c.has_value());
            std::uint64_t seen = 0;
            if (c)
                c->plan.for_each([&](OpCode code, std::span<const std::byte> payload) {
                    if (code == OpCode::landlock_rule) {
                        LandlockRuleOp op{};
                        Plan::decode(payload, op);
                        seen |= op.allowed;
                    }
                    return true;
                });
            return seen;
        };
        // abi 5 is the old ceiling: the bit must NOT appear, or the ruleset
        // is rejected by the kernel and the guest runs unconfined.
        CHECK((allowed_bits(5) & kResolveUnix) == 0);
        CHECK((allowed_bits(8) & kResolveUnix) == 0);
        // abi 9 is where the kernel learned it; a read grant carries it.
        CHECK((allowed_bits(9) & kResolveUnix) != 0);
        CHECK((allowed_bits(10) & kResolveUnix) != 0);
    }

    // -- W^X: the arg rule is partial, MDWE is the real wall ---------------
    {
        const auto hostcaps = HostCapabilities::modern_linux();
        // off by default: MDWE breaks every JIT (node/V8 will not start), and
        // a build sandbox has to run a normal toolchain.
        auto lax = Policy<Draft>{}
                       .read("/usr")
                       .syscall_profile(profiles::base())
                       .seal();
        CHECK(!lax.data().deny_write_execute);
        auto cl = compile(lax, hostcaps);
        CHECK(cl.has_value());
        if (cl) CHECK(!cl->plan.has(OpCode::memory_deny_write_execute));

        // asked for: the op is there, and it sits in privdrop -- with
        // no_new_privs, before the guest's own code runs.
        auto strict = Policy<Draft>{}
                          .read("/usr")
                          .deny_write_execute()
                          .syscall_profile(profiles::base())
                          .seal();
        CHECK(strict.data().deny_write_execute);
        auto cs = compile(strict, hostcaps);
        CHECK(cs.has_value());
        if (cs) {
            CHECK(cs->plan.has(OpCode::memory_deny_write_execute));
            CHECK(phase_of(OpCode::memory_deny_write_execute) == Phase::privdrop);
        }
        // hardening composes upward: either side asking for it wins.
        CHECK(lax.meet(strict).data().deny_write_execute);
    }

    // -- hardened refuses to downgrade ------------------------------------
    {
        HostCapabilities weak;
        weak.user_namespaces = true;
        weak.seccomp = true;
        weak.no_new_privs = true;
        weak.landlock_abi = 0;

        auto pol = Policy<Draft>{}
                       .read("/usr")
                       .isolation(Isolation::hardened_process)
                       .syscall_profile(profiles::base())
                       .seal();
        auto c = compile(pol, weak);
        // asking for hardened on a kernel that cannot deliver must FAIL, not
        // silently give you something weaker.
        CHECK(!c.has_value());
        CHECK(c.error().code == Errc::unsupported);
    }

    // -- an empty allow-list is a policy bug, caught at compile time ------
    {
        auto pol = Policy<Draft>{}.read("/usr").seal();  // never named a syscall
        auto c = compile(pol, HostCapabilities::modern_linux());
        CHECK(!c.has_value());
        CHECK(c.error().code == Errc::invalid_policy);
    }

    // -- microvm is not implemented, and says so --------------------------
    {
        auto pol = Policy<Draft>{}
                       .read("/usr")
                       .isolation(Isolation::microvm)
                       .syscall_profile(profiles::base())
                       .seal();
        auto c = compile(pol, HostCapabilities::modern_linux());
        CHECK(!c.has_value());
        CHECK(c.error().code == Errc::unsupported);
    }

    // -- granting network: per-port gets landlock, blanket does not --------
    {
        // a SPECIFIC port is expressible as a landlock net rule, so granting it
        // does not cost us enforcement -- this is the one case where allowing
        // network still reports `strong`, and it is something a netns cannot do.
        auto pol = Policy<Draft>{}
                       .read("/usr")
                       .connect("api.github.com", 443)
                       .syscall_profile(profiles::base())
                       .seal();
        auto c = compile(pol, HostCapabilities::modern_linux());
        CHECK(c.has_value());
        if (c) {
            CHECK(c->guarantees.strength(CapId::net_isolation) == Enforcement::strong);
            CHECK(c->plan.has(OpCode::landlock_net_rule));
        }
    }
    {
        // a BLANKET grant means any port, which landlock cannot express, so the
        // report must fall back to partial rather than imply per-port control.
        auto pol = Policy<Draft>{}
                       .read("/usr")
                       .connect("", 0)  // any host, any port
                       .syscall_profile(profiles::base())
                       .seal();
        auto c = compile(pol, HostCapabilities::modern_linux());
        CHECK(c.has_value());
        if (c) CHECK(c->guarantees.strength(CapId::net_isolation) == Enforcement::partial);
    }
    {
        // and on an abi too old for net rules, likewise partial.
        auto old = HostCapabilities::modern_linux();
        old.landlock_abi = 3;
        auto pol = Policy<Draft>{}
                       .read("/usr")
                       .connect("api.github.com", 443)
                       .syscall_profile(profiles::base())
                       .seal();
        auto c = compile(pol, old);
        CHECK(c.has_value());
        if (c) {
            CHECK(c->guarantees.strength(CapId::net_isolation) == Enforcement::partial);
            CHECK(!c->plan.has(OpCode::landlock_net_rule));
        }
    }

    // -- no claim without a corresponding op ------------------------------
    // the guarantee report is only meaningful if every `strong` is backed by a
    // mechanism actually present in the plan. this is the invariant that caught
    // a real bug: the compiler claimed "cgroup2+rlimit" for memory while
    // emitting no cgroup op at all.
    {
        for (bool net : {false, true}) {
            auto d = Policy<Draft>{}
                         .read("/usr")
                         .memory(512_MB)
                         .processes(64)
                         .syscall_profile(profiles::base());
            auto pol = net ? std::move(d).connect("example.com", 443).seal() : std::move(d).seal();
            auto c = compile(pol, HostCapabilities::modern_linux());
            CHECK(c.has_value());
            if (!c) continue;
            const auto& g = c->guarantees;

            if (g.strength(CapId::fs_read) >= Enforcement::strong)
                CHECK(c->plan.has(OpCode::landlock_enforce));
            if (g.strength(CapId::syscall_filter) >= Enforcement::strong)
                CHECK(c->plan.has(OpCode::seccomp_install));
            if (g.strength(CapId::privilege_drop) >= Enforcement::strong)
                CHECK(c->plan.has(OpCode::no_new_privs));
            if (g.strength(CapId::proc_isolation) >= Enforcement::strong)
                CHECK(c->plan.has(OpCode::unshare));

            // nothing may claim `isolated` on a process backend: that word is
            // reserved for a separate kernel.
            for (std::size_t i = 0; i < kCapCount; ++i)
                CHECK(g.strength(static_cast<CapId>(i)) < Enforcement::isolated);
        }
    }

    // -- a host with no usable cgroups must say `partial`, never `strong` ---
    {
        HostCapabilities shared = HostCapabilities::modern_linux();
        shared.cgroups = cgroup::Availability::unusable;
        shared.cgroup_memory = shared.cgroup_pids = false;

        auto pol = Policy<Draft>{}
                       .read("/usr")
                       .memory(512_MB)
                       .processes(64)
                       .syscall_profile(profiles::base())
                       .seal();
        auto c = compile(pol, shared);
        CHECK(c.has_value());
        if (c) {
            CHECK(!c->cgroup.valid());
            // rlimits still go in, but the claim is honest about what they are
            CHECK(c->guarantees.strength(CapId::mem_limit) == Enforcement::partial);
            CHECK(c->guarantees.strength(CapId::pid_limit) == Enforcement::partial);
            CHECK(c->plan.has(OpCode::set_rlimit));
        }
    }

    // -- profiles are sane -------------------------------------------------
    {
        auto p = profiles::base();
        CHECK(p.action_for(0) == SysAction::allow);    // read
        CHECK(p.action_for(1) == SysAction::allow);    // write
        CHECK(p.action_for(231) == SysAction::allow);  // exit_group
        // the escapes are killed, not merely denied
        CHECK(p.action_for(101) == SysAction::kill_process);  // ptrace
        CHECK(p.action_for(321) == SysAction::kill_process);  // bpf
        CHECK(p.action_for(308) == SysAction::kill_process);  // setns
        // base has no fork/exec
        CHECK(p.action_for(57) == SysAction::errno_);
        CHECK(profiles::with_processes().action_for(57) == SysAction::allow);
        // composing profiles can only restrict: compiler() & base() loses fork
        auto tight = profiles::compiler() & profiles::base();
        CHECK(tight.action_for(57) == SysAction::errno_);
    }

    return finish("plan_test");
}
