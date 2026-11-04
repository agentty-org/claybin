// claybin: proof-carrying guarantees.
//
// a Witness<Cap> is evidence that a mechanism was actually installed. its
// constructor is private and only a backend can reach it, so a guarantee cannot
// be fabricated by a caller or by a backend that quietly did nothing.
#pragma once

#include <array>
#include <cstdint>
#include <optional>

#include "claybin/core/lattice.hpp"

namespace clay {

// capability tags. these are the portable vocabulary: what a caller is allowed
// to *ask about*, independent of which os is underneath.
namespace cap {
struct FilesystemRead {
    static constexpr const char* name = "filesystem.read";
};
struct FilesystemWrite {
    static constexpr const char* name = "filesystem.write";
};
struct FilesystemExec {
    static constexpr const char* name = "filesystem.exec";
};
struct NetworkIsolation {
    static constexpr const char* name = "network.isolation";
};
struct ProcessIsolation {
    static constexpr const char* name = "process.isolation";
};
struct SyscallFilter {
    static constexpr const char* name = "syscall.filter";
};
struct MemoryLimit {
    static constexpr const char* name = "resource.memory";
};
struct CpuLimit {
    static constexpr const char* name = "resource.cpu";
};
struct PidLimit {
    static constexpr const char* name = "resource.pids";
};
struct PrivilegeDrop {
    static constexpr const char* name = "privilege.drop";
};
struct DeviceIsolation {
    static constexpr const char* name = "device.isolation";
};
// can the guest get executable memory it also wrote?
//
// its own row because the two mechanisms are not the same wall: the seccomp
// argument rule denies mmap/mprotect with PROT_WRITE|PROT_EXEC in one call
// (`partial` -- the mmap(W) then mprotect(X) sequence walks past it), while
// PR_SET_MDWE denies gaining exec on writable memory at all (`strong`).
// reporting one number for both would hide exactly the gap that matters.
struct MemoryWriteExecute {
    static constexpr const char* name = "memory.wx";
};
struct HostKernelIsolation {
    static constexpr const char* name = "host.kernel_isolation";
};
}  // namespace cap

enum class CapId : std::uint8_t {
    fs_read,
    fs_write,
    fs_exec,
    net_isolation,
    proc_isolation,
    syscall_filter,
    mem_limit,
    cpu_limit,
    pid_limit,
    privilege_drop,
    device_isolation,
    memory_wx,
    host_kernel_isolation,
    count_,
};

inline constexpr std::size_t kCapCount = static_cast<std::size_t>(CapId::count_);

template <class Cap>
struct cap_id;
// clang-format off
template <> struct cap_id<cap::FilesystemRead>      { static constexpr CapId value = CapId::fs_read; };
template <> struct cap_id<cap::FilesystemWrite>     { static constexpr CapId value = CapId::fs_write; };
template <> struct cap_id<cap::FilesystemExec>      { static constexpr CapId value = CapId::fs_exec; };
template <> struct cap_id<cap::NetworkIsolation>    { static constexpr CapId value = CapId::net_isolation; };
template <> struct cap_id<cap::ProcessIsolation>    { static constexpr CapId value = CapId::proc_isolation; };
template <> struct cap_id<cap::SyscallFilter>       { static constexpr CapId value = CapId::syscall_filter; };
template <> struct cap_id<cap::MemoryLimit>         { static constexpr CapId value = CapId::mem_limit; };
template <> struct cap_id<cap::CpuLimit>            { static constexpr CapId value = CapId::cpu_limit; };
template <> struct cap_id<cap::PidLimit>            { static constexpr CapId value = CapId::pid_limit; };
template <> struct cap_id<cap::PrivilegeDrop>       { static constexpr CapId value = CapId::privilege_drop; };
template <> struct cap_id<cap::DeviceIsolation>     { static constexpr CapId value = CapId::device_isolation; };
template <> struct cap_id<cap::MemoryWriteExecute>  { static constexpr CapId value = CapId::memory_wx; };
template <> struct cap_id<cap::HostKernelIsolation> { static constexpr CapId value = CapId::host_kernel_isolation; };
// clang-format on

constexpr const char* cap_name(CapId id) {
    switch (id) {
        case CapId::fs_read: return "filesystem.read";
        case CapId::fs_write: return "filesystem.write";
        case CapId::fs_exec: return "filesystem.exec";
        case CapId::net_isolation: return "network.isolation";
        case CapId::proc_isolation: return "process.isolation";
        case CapId::syscall_filter: return "syscall.filter";
        case CapId::mem_limit: return "resource.memory";
        case CapId::cpu_limit: return "resource.cpu";
        case CapId::pid_limit: return "resource.pids";
        case CapId::privilege_drop: return "privilege.drop";
        case CapId::device_isolation: return "device.isolation";
        case CapId::memory_wx: return "memory.wx";
        case CapId::host_kernel_isolation: return "host.kernel_isolation";
        case CapId::count_: break;
    }
    return "?";
}

class GuaranteeReport;

// evidence that `Cap` is enforced at `strength()` by `mechanism()`.
template <class Cap>
class Witness {
  public:
    Enforcement strength() const { return strength_; }
    // static string naming the thing that did the enforcing, e.g. "landlock:abi5".
    const char* mechanism() const { return mechanism_; }
    static constexpr const char* capability() { return Cap::name; }

  private:
    friend class GuaranteeReport;
    Witness(Enforcement s, const char* m) : strength_(s), mechanism_(m) {}

    Enforcement strength_;
    const char* mechanism_;
};

// the audit surface. backends fill it in as they install mechanisms; callers can
// only read it. anything a backend never touched reads back as `none`, which is
// the honest default rather than an optimistic one.
class GuaranteeReport {
  public:
    // only reachable by backends (which construct a Builder) -- a caller holding
    // a const report cannot invent a claim.
    class Builder;

    template <class Cap>
    std::optional<Witness<Cap>> witness() const {
        const auto& slot = slots_[static_cast<std::size_t>(cap_id<Cap>::value)];
        if (slot.strength == Enforcement::none) return std::nullopt;
        return Witness<Cap>{slot.strength, slot.mechanism};
    }

    Enforcement strength(CapId id) const {
        return slots_[static_cast<std::size_t>(id)].strength;
    }
    const char* mechanism(CapId id) const {
        return slots_[static_cast<std::size_t>(id)].mechanism;
    }

    // the report's overall floor. useful for "is this at least `strong`
    // everywhere i asked for".
    Enforcement weakest_of(std::initializer_list<CapId> ids) const {
        Enforcement acc = Enforcement::isolated;
        for (CapId id : ids) acc = clay::meet(acc, strength(id));
        return acc;
    }

  private:
    static constexpr const char* kUnset = "none";
    struct Slot {
        Enforcement strength{Enforcement::none};
        const char* mechanism{kUnset};
    };
    std::array<Slot, kCapCount> slots_{};
};

// defined out-of-line because it stores a GuaranteeReport by value, which is
// still incomplete inside the class body.
class GuaranteeReport::Builder {
  public:
    Builder& record(CapId id, Enforcement e, const char* mechanism) {
        auto& slot = report_.slots_[static_cast<std::size_t>(id)];
        // a capability enforced by several mechanisms is only as strong as the
        // strongest one that actually covers it, but we keep the mechanism name
        // that reached that strength for auditability.
        if (e > slot.strength) {
            slot.strength = e;
            slot.mechanism = mechanism;
        } else if (e == slot.strength && slot.mechanism == kUnset) {
            // an explicit `none` still carries a reason worth printing, e.g.
            // "process-backend" for host kernel isolation.
            slot.mechanism = mechanism;
        }
        return *this;
    }
    GuaranteeReport build() && { return report_; }

  private:
    GuaranteeReport report_{};
};

}  // namespace clay
