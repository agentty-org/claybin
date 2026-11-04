// claybin: policy -> plan.
//
// this is the whole "thinking" step, and it is deliberately pure: it takes a
// sealed policy plus a description of what the host kernel supports, and
// returns a plan and a guarantee report. no syscalls, so every compilation
// decision is unit-testable by describing a fake kernel.
//
// the report is the honest part. if the host cannot enforce something, the
// compiler says `none` instead of quietly dropping it.
#pragma once

#include "claybin/core/error.hpp"
#include "claybin/core/witness.hpp"
#include "claybin/linux/cgroup.hpp"
#include "claybin/plan/plan.hpp"
#include "claybin/policy/mounts.hpp"
#include "claybin/policy/policy.hpp"

namespace clay {

// what the host can actually do. probed once at runtime on linux, but a plain
// value so tests can describe any kernel, including ones that do not exist.
struct HostCapabilities {
    bool user_namespaces{false};
    bool mount_namespaces{false};
    bool pid_namespaces{false};
    bool net_namespaces{false};
    bool uts_namespaces{false};
    bool ipc_namespaces{false};
    // a private cgroup namespace makes the guest's own cgroup look like `/`,
    // so /proc/self/cgroup stops naming the host's slice layout.
    bool cgroup_namespaces{false};
    bool seccomp{false};
    bool seccomp_user_notif{false};

    // NOT a bool. "cgroup2 is mounted" and "we can actually use it" are
    // different facts: cgroup v2 refuses to enable controllers in a cgroup that
    // holds processes, so a caller launched into a shared cgroup (a terminal,
    // a desktop session) cannot get limits no matter what claybin does. the
    // earlier bool version of this field is exactly how a library ends up
    // claiming `strong` on memory while the write is going to fail.
    cgroup::Availability cgroups{cgroup::Availability::absent};
    bool cgroup_memory{false};
    bool cgroup_pids{false};
    // the cpu controller is frequently NOT delegated to user sessions even when
    // memory and pids are, so it needs its own flag rather than being assumed.
    bool cgroup_cpu{false};

    std::uint32_t landlock_abi{0};  // 0 = absent
    bool no_new_privs{false};

    // can this host back a microvm at all?
    //
    // NOT used by the process backend -- it is here so the gap between "we do
    // not implement a microvm" and "this host could not run one anyway" is
    // MEASURABLE rather than a matter of opinion. those are different answers
    // to "why is host.kernel_isolation none", and a caller deciding whether to
    // care deserves the real one.
    //
    // /dev/kvm being present and openable is the precondition every VMM shares
    // (firecracker's getting-started names exactly this: the kvm module plus
    // read-write access to the device). it is necessary, not sufficient -- a
    // VMM binary still has to exist -- so a true here means "the hardware
    // boundary is available", not "claybin can give it to you".
    bool kvm{false};

    static HostCapabilities none() { return {}; }

    // a modern linux box in a delegated scope. the reference target.
    static HostCapabilities modern_linux() {
        HostCapabilities h;
        h.user_namespaces = h.mount_namespaces = h.pid_namespaces = true;
        h.net_namespaces = h.uts_namespaces = h.ipc_namespaces = true;
        h.cgroup_namespaces = true;
        h.seccomp = h.seccomp_user_notif = true;
        h.cgroups = cgroup::Availability::delegated;
        h.cgroup_memory = h.cgroup_pids = true;
        h.cgroup_cpu = true;
        h.landlock_abi = 5;
        h.no_new_privs = true;
        // deliberately FALSE in the reference host: kvm is orthogonal to
        // everything else here, most CI runners lack it, and a reference that
        // claimed it would make the one capability we cannot deliver look
        // available in every test.
        h.kvm = false;
        return h;
    }
};

struct Compiled {
    Plan plan;
    GuaranteeReport guarantees;

    // capabilities the policy asked for that the host could not enforce. never
    // silently empty: compile() fails outright when a policy demands strictness
    // the host cannot deliver.
    std::vector<CapId> degraded;

    // how faithfully the mount plan survived. `exact` on any host with mount
    // namespaces; on a host without them, it says whether the access-control
    // interpretation was an exact stand-in or a weaker approximation. a plan
    // that could not be approximated at all makes compile() fail instead.
    Fidelity fidelity{Fidelity::exact};

    // the cgroup the child should join, if the host allowed one. empty when
    // limits are rlimit-only, and the guarantee report says `partial` then.
    //
    // this lives outside the Plan on purpose: creating it involves sysfs writes
    // that are not async-signal-safe, so it happens in the parent and the only
    // post-fork work is one write of a pid.
    cgroup::Group cgroup{};

    // true when the policy delegates at least one syscall to a supervisor, so
    // spawn() knows to expect a listener fd back from the child. a caller that
    // ignores it leaves the guest blocked forever on its first brokered call,
    // which is why it is on the struct rather than inferred.
    bool brokers_syscalls{false};

    // assert a floor, and fail if the host did not reach it.
    //
    // this is the difference between api portability and security portability.
    // the same policy compiles on linux, windows and macOS, but the walls you
    // actually get differ. a program that genuinely needs a syscall filter
    // should refuse to run where there is none rather than run unprotected, and
    // this is how it says so:
    //
    //   auto ok = c->require(Enforcement::strong,
    //                        {CapId::fs_read, CapId::syscall_filter});
    //
    // on macOS that fails, because seccomp has no equivalent there.
    Status require(Enforcement floor, std::initializer_list<CapId> caps) const {
        for (CapId id : caps) {
            if (guarantees.strength(id) < floor)
                return std::unexpected(Error{Errc::unsupported, cap_name(id)});
        }
        return {};
    }
};

// compile a sealed policy for a given host.
//
// fails when the policy demands a guarantee the host cannot provide (for
// example Isolation::hardened_process on a kernel with no seccomp). downgrading
// silently would be the single worst thing a sandbox library could do, so it is
// an error the caller has to see.
Result<Compiled> compile(const Policy<Sealed>& policy, const HostCapabilities& host);

// probe the running kernel. the only impure function in this header; on
// non-linux it reports `none()`.
HostCapabilities probe_host();

}  // namespace clay
