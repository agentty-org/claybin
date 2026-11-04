// claybin: network + resource authority.
#pragma once

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "claybin/core/lattice.hpp"

namespace clay {

// ---------------------------------------------------------------------------
// network
// ---------------------------------------------------------------------------

struct NetOpsTag {};
using NetOps = Flags<NetOpsTag, std::uint32_t>;

inline constexpr NetOps kNetConnect{1u << 0};
inline constexpr NetOps kNetBind{1u << 1};
inline constexpr NetOps kNetListen{1u << 2};
inline constexpr NetOps kNetUnixSocket{1u << 3};  // af_unix stays usable
inline constexpr NetOps kNetRaw{1u << 4};

// a host:port grant. `port == 0` means any port on that host; empty host means
// any host. resolution is NOT done here -- a name is brokered at connect time by
// the supervisor, so dns rebinding cannot widen the grant after the fact.
struct NetEndpoint {
    std::string host;  // empty = any
    std::uint16_t port{0};  // 0 = any
    NetOps ops{kNetConnect};

    friend bool operator==(const NetEndpoint&, const NetEndpoint&) = default;
};

// a set of (host, port) pairs. wildcards make these overlap, so meet has to
// reason about regions rather than about literal rules.
struct NetRegion {
    std::string host;  // empty = any
    std::uint16_t port{0};  // 0 = any

    friend bool operator==(const NetRegion&, const NetRegion&) = default;
};

// regions are closed under intersection, which is what makes the meet below
// exact. two wildcards intersect to a wildcard; a wildcard and a literal
// intersect to the literal; two different literals do not intersect at all.
inline bool intersect_region(const NetRegion& a, const NetRegion& b, NetRegion& out) {
    if (!a.host.empty() && !b.host.empty() && a.host != b.host) return false;
    if (a.port != 0 && b.port != 0 && a.port != b.port) return false;
    out.host = a.host.empty() ? b.host : a.host;
    out.port = a.port == 0 ? b.port : a.port;
    return true;
}

class NetAuthority {
  public:
    NetAuthority() = default;

    static NetAuthority nothing() { return NetAuthority{}; }
    static NetAuthority everything() {
        NetAuthority n;
        n.any_ = NetOps::everything();
        return n;
    }

    NetAuthority& allow(std::string host, std::uint16_t port, NetOps ops = kNetConnect) {
        for (auto& e : endpoints_) {
            if (e.host == host && e.port == port) {
                e.ops = NetOps{e.ops.unsafe_join(ops)};
                return *this;
            }
        }
        endpoints_.push_back({std::move(host), port, ops});
        sort_();
        return *this;
    }

    NetAuthority& allow_any(NetOps ops) {
        any_ = NetOps{any_.unsafe_join(ops)};
        return *this;
    }

    // ops permitted across the WHOLE region, folding in the blanket grant. for a
    // concrete (host, port) this is the ordinary lookup; for a wildcard region
    // only rules that cover the entire region count, which is exactly what the
    // empty-host / zero-port comparisons below give us.
    NetOps effective(std::string_view host, std::uint16_t port) const {
        NetOps acc = any_;
        for (const auto& e : endpoints_) {
            bool host_ok = e.host.empty() || e.host == host;
            bool port_ok = e.port == 0 || e.port == port;
            if (host_ok && port_ok) acc = NetOps{acc.unsafe_join(e.ops)};
        }
        return acc;
    }

    NetOps effective(const NetRegion& r) const { return effective(r.host, r.port); }

    NetAuthority meet(const NetAuthority& o) const {
        NetAuthority out;
        out.any_ = any_.meet(o.any_);

        // evaluating at the union of both rule sets is NOT enough: a wildcard on
        // one side crossed with a literal on the other names a region that
        // appears in neither list. the cross-product of regions is closed under
        // intersection, so it does cover every cell where the answer can change.
        for (const auto& ra : regions_()) {
            for (const auto& rb : o.regions_()) {
                NetRegion cell;
                if (!intersect_region(ra, rb, cell)) continue;
                NetOps ops = effective(cell).meet(o.effective(cell));
                if (ops.is_nothing()) continue;
                bool dup = false;
                for (auto& x : out.endpoints_) {
                    if (x.host == cell.host && x.port == cell.port) {
                        x.ops = ops;
                        dup = true;
                        break;
                    }
                }
                if (!dup) out.endpoints_.push_back({cell.host, cell.port, ops});
            }
        }
        out.sort_();
        out.prune_();
        return out;
    }

    bool subsumes(const NetAuthority& o) const {
        if (!any_.subsumes(o.any_)) return false;
        for (const auto& ra : regions_())
            for (const auto& rb : o.regions_()) {
                NetRegion cell;
                if (!intersect_region(ra, rb, cell)) continue;
                if (!effective(cell).subsumes(o.effective(cell))) return false;
            }
        return true;
    }

    bool is_nothing() const { return any_.is_nothing() && endpoints_.empty(); }

    const std::vector<NetEndpoint>& endpoints() const { return endpoints_; }
    NetOps blanket() const { return any_; }

    friend bool operator==(const NetAuthority& a, const NetAuthority& b) {
        if (a.any_ != b.any_) return false;
        // semantic, not structural: agree on every cell of the shared
        // arrangement, so equivalent-but-differently-spelled policies compare
        // equal and the lattice laws hold.
        for (const auto& ra : a.regions_())
            for (const auto& rb : b.regions_()) {
                NetRegion cell;
                if (!intersect_region(ra, rb, cell)) continue;
                if (a.effective(cell) != b.effective(cell)) return false;
            }
        return true;
    }

  private:
    // every rule's region, plus the blanket region the `any_` grant covers.
    std::vector<NetRegion> regions_() const {
        std::vector<NetRegion> rs;
        rs.reserve(endpoints_.size() + 1);
        rs.push_back({"", 0});
        for (const auto& e : endpoints_) rs.push_back({e.host, e.port});
        return rs;
    }

    void sort_() {
        std::sort(endpoints_.begin(), endpoints_.end(), [](const NetEndpoint& x, const NetEndpoint& y) {
            if (x.host != y.host) return x.host < y.host;
            return x.port < y.port;
        });
    }
    // an endpoint rule that adds nothing over the blanket grant is noise.
    void prune_() {
        std::erase_if(endpoints_, [&](const NetEndpoint& e) {
            return any_.subsumes(e.ops);
        });
    }

    NetOps any_{};
    std::vector<NetEndpoint> endpoints_;
};

// ---------------------------------------------------------------------------
// resources. each is a ceiling, so meet is min and composition tightens.
// ---------------------------------------------------------------------------

struct BytesTag {};
struct CountTag {};
struct NanosTag {};

using Bytes = Limit<BytesTag, std::uint64_t>;
using Count = Limit<CountTag, std::uint64_t>;
using Nanos = Limit<NanosTag, std::uint64_t>;

class ResourceLimits {
  public:
    Bytes memory{};
    // the THROTTLE, as distinct from the kill above.
    //
    // memory.max is a hard ceiling: cross it and the kernel OOM-kills the
    // guest. memory.high is reclaim pressure -- cross it and the guest is
    // slowed down, hard, but nothing dies. that difference is what makes a
    // DEFAULT possible: picking a hard cap for someone else's machine turns a
    // working `cargo build` into a kill that looks like our fault, while a
    // high mark only makes the pathological case crawl.
    //
    // both can be set; the kernel wants high < max.
    Bytes memory_high{};
    Bytes memory_swap{};
    Count pids{};
    Count open_files{};
    Nanos cpu_time{};
    Nanos wall_clock{};
    Count cpu_weight{};
    // a HARD ceiling on cpu share, as a percentage of one core (200 = two
    // cores' worth). distinct from cpu_weight, which only decides who wins
    // under contention: on an idle machine a weight-limited guest still gets a
    // whole core, so weight is not a limit at all in the sense a caller means.
    Count cpu_quota_percent{};
    Bytes io_read_bps{};
    Bytes io_write_bps{};
    // note: unlimited here so `everything()` is a genuine top element. "no core
    // dumps" is a policy default, not a lattice one: Policy<Draft>'s
    // constructor sets it to 0 (core_dumps(true) undoes it).
    Bytes core_size{};

    static ResourceLimits nothing() {
        ResourceLimits r;
        r.memory = Bytes::nothing();
        r.memory_high = Bytes::nothing();
        r.memory_swap = Bytes::nothing();
        r.pids = Count::nothing();
        r.open_files = Count::nothing();
        r.cpu_time = Nanos::nothing();
        r.wall_clock = Nanos::nothing();
        r.cpu_weight = Count::nothing();
        r.cpu_quota_percent = Count::nothing();
        r.io_read_bps = Bytes::nothing();
        r.io_write_bps = Bytes::nothing();
        r.core_size = Bytes::nothing();
        return r;
    }

    static ResourceLimits everything() { return ResourceLimits{}; }  // all unlimited

    ResourceLimits meet(const ResourceLimits& o) const {
        ResourceLimits r;
        r.memory = memory.meet(o.memory);
        r.memory_high = memory_high.meet(o.memory_high);
        r.memory_swap = memory_swap.meet(o.memory_swap);
        r.pids = pids.meet(o.pids);
        r.open_files = open_files.meet(o.open_files);
        r.cpu_time = cpu_time.meet(o.cpu_time);
        r.wall_clock = wall_clock.meet(o.wall_clock);
        r.cpu_weight = cpu_weight.meet(o.cpu_weight);
        r.cpu_quota_percent = cpu_quota_percent.meet(o.cpu_quota_percent);
        r.io_read_bps = io_read_bps.meet(o.io_read_bps);
        r.io_write_bps = io_write_bps.meet(o.io_write_bps);
        r.core_size = core_size.meet(o.core_size);
        return r;
    }

    bool subsumes(const ResourceLimits& o) const {
        return memory.subsumes(o.memory) && memory_high.subsumes(o.memory_high)
            && memory_swap.subsumes(o.memory_swap) &&
               pids.subsumes(o.pids) && open_files.subsumes(o.open_files) &&
               cpu_time.subsumes(o.cpu_time) && wall_clock.subsumes(o.wall_clock) &&
               cpu_weight.subsumes(o.cpu_weight) &&
               cpu_quota_percent.subsumes(o.cpu_quota_percent) &&
               io_read_bps.subsumes(o.io_read_bps) &&
               io_write_bps.subsumes(o.io_write_bps) && core_size.subsumes(o.core_size);
    }

    bool is_nothing() const {
        return memory.is_nothing() && pids.is_nothing() && cpu_time.is_nothing();
    }

    friend bool operator==(const ResourceLimits&, const ResourceLimits&) = default;
};

static_assert(Lattice<NetAuthority>);
static_assert(Lattice<ResourceLimits>);
static_assert(Lattice<Bytes>);

namespace literals {
constexpr Bytes operator""_KB(unsigned long long v) { return Bytes{v * 1024ull}; }
constexpr Bytes operator""_MB(unsigned long long v) { return Bytes{v * 1024ull * 1024ull}; }
constexpr Bytes operator""_GB(unsigned long long v) { return Bytes{v * 1024ull * 1024ull * 1024ull}; }
constexpr Nanos operator""_ms(unsigned long long v) { return Nanos{v * 1'000'000ull}; }
constexpr Nanos operator""_s(unsigned long long v) { return Nanos{v * 1'000'000'000ull}; }
constexpr Nanos operator""_min(unsigned long long v) { return Nanos{v * 60ull * 1'000'000'000ull}; }
}  // namespace literals

}  // namespace clay
