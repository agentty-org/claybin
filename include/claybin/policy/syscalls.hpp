// claybin: syscall authority as a lattice.
//
// a policy is a default action plus a sparse set of per-syscall overrides. the
// actions themselves form a chain ordered by permissiveness, so meet is just
// "the less permissive of the two" applied pointwise. that makes composing two
// syscall profiles automatically safe.
#pragma once

#include <algorithm>
#include <cstdint>
#include <iterator>   // back_inserter — libstdc++ leaks it via <algorithm>, libc++ does not
#include <span>
#include <vector>

#include "claybin/core/lattice.hpp"

namespace clay {

// ordered least-permissive to most-permissive. the numeric order IS the lattice
// order; do not reorder without updating meet().
enum class SysAction : std::uint8_t {
    kill_process = 0,  // SECCOMP_RET_KILL_PROCESS
    kill_thread = 1,
    trap = 2,      // SIGSYS, debuggable
    errno_ = 3,    // fail with an errno, most compatible denial
    notify = 4,    // SECCOMP_RET_USER_NOTIF: delegate to the supervisor
    log = 5,       // allowed, but recorded
    allow = 6,     // SECCOMP_RET_ALLOW
};

constexpr SysAction meet(SysAction a, SysAction b) { return a < b ? a : b; }

constexpr const char* to_string(SysAction a) {
    switch (a) {
        case SysAction::kill_process: return "kill_process";
        case SysAction::kill_thread: return "kill_thread";
        case SysAction::trap: return "trap";
        case SysAction::errno_: return "errno";
        case SysAction::notify: return "notify";
        case SysAction::log: return "log";
        case SysAction::allow: return "allow";
    }
    return "?";
}

using SysNr = std::uint32_t;

struct SyscallRule {
    SysNr nr;
    SysAction action;
    std::uint16_t errno_value;  // only meaningful for SysAction::errno_

    friend bool operator==(const SyscallRule&, const SyscallRule&) = default;
};

// ---------------------------------------------------------------------------
// argument filtering
//
// seccomp sees the syscall's REGISTER ARGUMENTS, not just its number, so a
// filter can say "ioctl is fine, except TIOCSTI". that matters because the
// alternative is binary: allow ioctl and accept keystroke injection into the
// host terminal, or deny it and break isatty() for every program.
//
// the deliberate limitation: only scalar equality on one argument. seccomp
// CANNOT dereference a pointer -- the memory could be changed between the check
// and the syscall (a real TOCTOU the kernel documents), so any filter that
// pretended to inspect a struct would be lying. equality on a register is the
// only thing that is actually sound.
// ---------------------------------------------------------------------------

// how an argument rule compares the register against `value`.
//
// equality alone is not enough for the interesting cases. the flag syscalls --
// clone, mmap, openat, socket -- pack independent bits into one register, and an
// attacker only has to set one extra harmless bit for an equality test to miss.
// `clone(CLONE_NEWUSER|CLONE_VM)` is not equal to `CLONE_NEWUSER`, so a policy
// that denies the latter by equality is trivially bypassed.
enum class ArgCmp : std::uint8_t {
    eq,        // arg == value
    masked_eq, // (arg & mask) == value  -- an exact field within the register
    any_set,   // (arg & mask) != 0      -- "any of these flags is present"
};

// how WIDE the kernel's own parameter is, which decides how much of the
// register a rule may compare.
//
// this is not a detail. seccomp always sees a full 64-bit register, but the
// kernel truncates it to the declared parameter type before using it -- and
// ioctl's cmd is `unsigned int`. so `ioctl(fd, 0xdeadbeef00005412, ...)` runs as
// TIOCSTI while a filter comparing all 64 bits sees a value that matches
// nothing and lets it past. measured, not reasoned about: a both-halves rule on
// TIOCGWINSZ denies 0x5413 and allows 0xdeadbeef00005413, which the kernel then
// executes as TIOCGWINSZ.
//
// so the rule is: compare exactly as many bits as the kernel uses. for a 64-bit
// parameter the high half must be checked, because ignoring it is the classic
// bypass in the other direction. for a 32-bit one it must NOT be.
enum class ArgWidth : std::uint8_t {
    bits64,  // the default: pointers, size_t, flags on clone/mmap
    bits32,  // int/unsigned int parameters. ioctl's request is the big one.
};

// an allow-list over one 32-bit argument: everything is denied except these
// values. the inverse of an ArgRule, and the only workable shape for a syscall
// as wide as ioctl -- there are thousands of requests and any driver can add
// more, so enumerating the dangerous ones is a losing game.
struct ArgAllowSet {
    SysNr nr;
    std::uint8_t arg_index;
    std::vector<std::uint32_t> values;  // sorted, deduped
    SysAction action;                   // what happens to everything else
    std::uint16_t errno_value;

    friend bool operator==(const ArgAllowSet&, const ArgAllowSet&) = default;
};

struct ArgRule {
    SysNr nr;
    std::uint8_t arg_index;   // 0-5
    std::uint64_t value;      // the value to match
    SysAction action;         // what to do when it MATCHES
    std::uint16_t errno_value;
    ArgCmp cmp{ArgCmp::eq};
    // only read for the masked comparisons. an all-ones mask with cmp==eq is the
    // same rule as plain equality, so `eq` just ignores it rather than forcing
    // every caller to spell out ~0.
    std::uint64_t mask{0};
    ArgWidth width{ArgWidth::bits64};

    friend bool operator==(const ArgRule&, const ArgRule&) = default;
};

// a stable total order over argument rules. it exists so two policies built by
// different paths compare equal, and so composition is deterministic. the
// comparison order is arbitrary but must cover every field that rule identity
// depends on, otherwise meet() can drop a distinct rule as a duplicate.
inline void sort_arg_rules(std::vector<ArgRule>& v) {
    std::sort(v.begin(), v.end(), [](const ArgRule& x, const ArgRule& y) {
        if (x.nr != y.nr) return x.nr < y.nr;
        if (x.arg_index != y.arg_index) return x.arg_index < y.arg_index;
        if (x.cmp != y.cmp) return x.cmp < y.cmp;
        if (x.width != y.width) return x.width < y.width;
        if (x.mask != y.mask) return x.mask < y.mask;
        return x.value < y.value;
    });
}

class SyscallPolicy {
  public:
    SyscallPolicy() = default;

    static SyscallPolicy nothing() {
        SyscallPolicy p;
        p.default_ = SysAction::kill_process;
        return p;
    }
    static SyscallPolicy everything() {
        SyscallPolicy p;
        p.default_ = SysAction::allow;
        return p;
    }

    SyscallPolicy& set_default(SysAction a, std::uint16_t err = 1 /*EPERM*/) {
        default_ = a;
        default_errno_ = err;
        return *this;
    }

    SyscallPolicy& allow(SysNr nr) { return set(nr, SysAction::allow); }
    SyscallPolicy& allow(std::span<const SysNr> nrs) {
        for (SysNr n : nrs) set(n, SysAction::allow);
        return *this;
    }
    SyscallPolicy& deny(SysNr nr, std::uint16_t err = 1) { return set(nr, SysAction::errno_, err); }
    SyscallPolicy& kill(SysNr nr) { return set(nr, SysAction::kill_process); }
    SyscallPolicy& notify(SysNr nr) { return set(nr, SysAction::notify); }

    SyscallPolicy& set(SysNr nr, SysAction a, std::uint16_t err = 1) {
        for (auto& r : rules_) {
            if (r.nr == nr) {
                r.action = a;
                r.errno_value = err;
                return *this;
            }
        }
        rules_.push_back({nr, a, err});
        std::sort(rules_.begin(), rules_.end(),
                  [](const SyscallRule& x, const SyscallRule& y) { return x.nr < y.nr; });
        return *this;
    }

    // deny ONE value of one argument, leaving the syscall otherwise allowed.
    //
    // this is how you get "ioctl yes, TIOCSTI no" instead of choosing between a
    // keystroke-injection escape and a broken isatty(). the argument rules are
    // checked BEFORE the per-syscall action, so a match here wins.
    SyscallPolicy& deny_arg(SysNr nr, std::uint8_t arg_index, std::uint64_t value,
                            SysAction a = SysAction::errno_, std::uint16_t err = 1,
                            ArgWidth w = ArgWidth::bits64) {
        return deny_arg_cmp(nr, arg_index, ArgCmp::eq, value, 0, a, err, w);
    }

    // deny one value of a 32-BIT argument. ioctl's request is the case that
    // matters: the kernel truncates cmd to `unsigned int`, so a rule that
    // compares all 64 bits is bypassed by setting any high bit.
    SyscallPolicy& deny_arg32(SysNr nr, std::uint8_t arg_index, std::uint32_t value,
                              SysAction a = SysAction::errno_, std::uint16_t err = 1) {
        return deny_arg_cmp(nr, arg_index, ArgCmp::eq, value, 0, a, err, ArgWidth::bits32);
    }

    // the inverse, and the shape a wide syscall really wants: everything about
    // this argument is denied EXCEPT the listed values.
    //
    // a deny-list on ioctl is close to meaningless -- there are thousands of
    // requests and any driver can add more -- so the useful policy is an
    // allow-list. this takes the whole set at once because the emitted code is a
    // single block: match any of these and fall through, otherwise deny.
    SyscallPolicy& allow_arg32_only(SysNr nr, std::uint8_t arg_index,
                                    std::span<const std::uint32_t> values,
                                    SysAction a = SysAction::errno_, std::uint16_t err = 1) {
        std::vector<std::uint32_t> v{values.begin(), values.end()};
        std::sort(v.begin(), v.end());
        v.erase(std::unique(v.begin(), v.end()), v.end());

        for (auto& s : allow_sets_) {
            if (s.nr == nr && s.arg_index == arg_index) {
                // two allow-lists on the same argument intersect. allowing fewer
                // values is more restrictive, and authority only ever narrows.
                std::vector<std::uint32_t> both;
                std::set_intersection(s.values.begin(), s.values.end(), v.begin(), v.end(),
                                      std::back_inserter(both));
                s.values = std::move(both);
                s.action = clay::meet(s.action, a);
                return *this;
            }
        }
        allow_sets_.push_back({nr, arg_index, std::move(v), a, err});
        std::sort(allow_sets_.begin(), allow_sets_.end(),
                  [](const ArgAllowSet& x, const ArgAllowSet& y) {
                      if (x.nr != y.nr) return x.nr < y.nr;
                      return x.arg_index < y.arg_index;
                  });
        return *this;
    }

    const std::vector<ArgAllowSet>& arg_allow_sets() const { return allow_sets_; }

    // deny when the MASKED field of an argument equals a value. this is the one
    // that handles the flag syscalls: `(clone_flags & CLONE_NEWUSER)` is a field
    // test, and no amount of extra harmless bits makes it miss.
    //
    // the two masked forms answer two different questions:
    //   any_set  "is ANY of these flags present"  -- clone(CLONE_NEWUSER|...)
    //   all_set  "are ALL of these set together"  -- mmap(PROT_WRITE|PROT_EXEC)
    SyscallPolicy& deny_arg_any(SysNr nr, std::uint8_t arg_index, std::uint64_t mask,
                                SysAction a = SysAction::errno_, std::uint16_t err = 1,
                                ArgWidth w = ArgWidth::bits64) {
        return deny_arg_cmp(nr, arg_index, ArgCmp::any_set, 0, mask, a, err, w);
    }

    // "all of these bits together" is just a masked equality where the expected
    // value IS the mask, so it needs no comparison mode of its own. the obvious
    // alternative -- a `not_all` mode -- reads like the right thing and is the
    // exact negation of what a deny rule wants, which is a live trap.
    SyscallPolicy& deny_arg_all(SysNr nr, std::uint8_t arg_index, std::uint64_t mask,
                                SysAction a = SysAction::errno_, std::uint16_t err = 1,
                                ArgWidth w = ArgWidth::bits64) {
        return deny_arg_cmp(nr, arg_index, ArgCmp::masked_eq, mask, mask, a, err, w);
    }

    SyscallPolicy& deny_arg_masked(SysNr nr, std::uint8_t arg_index, std::uint64_t mask,
                                   std::uint64_t value, SysAction a = SysAction::errno_,
                                   std::uint16_t err = 1, ArgWidth w = ArgWidth::bits64) {
        return deny_arg_cmp(nr, arg_index, ArgCmp::masked_eq, value & mask, mask, a, err, w);
    }

    SyscallPolicy& deny_arg_cmp(SysNr nr, std::uint8_t arg_index, ArgCmp cmp,
                                std::uint64_t value, std::uint64_t mask,
                                SysAction a = SysAction::errno_, std::uint16_t err = 1,
                                ArgWidth w = ArgWidth::bits64) {
        // a 32-bit rule can only talk about the low half, so anything the caller
        // put above the line is a policy bug, not a value to compare: silently
        // keeping it would emit a rule that matches nothing.
        if (w == ArgWidth::bits32) {
            value &= 0xffffffffull;
            mask &= 0xffffffffull;
        }
        for (auto& r : arg_rules_) {
            if (r.nr == nr && r.arg_index == arg_index && r.cmp == cmp && r.value == value &&
                r.mask == mask && r.width == w) {
                r.action = a;
                r.errno_value = err;
                return *this;
            }
        }
        arg_rules_.push_back({nr, arg_index, value, a, err, cmp, mask, w});
        sort_arg_rules(arg_rules_);
        return *this;
    }

    const std::vector<ArgRule>& arg_rules() const { return arg_rules_; }

    // remove every argument rule on one syscall argument. used to lift the
    // profiles' W^X rule for a JIT.
    SyscallPolicy& drop_arg_rules(SysNr nr, std::uint8_t arg_index) {
        std::erase_if(arg_rules_, [&](const ArgRule& r) {
            return r.nr == nr && r.arg_index == arg_index;
        });
        return *this;
    }

    SysAction action_for(SysNr nr) const {
        // rules_ is sorted, so this is a binary search in the hot audit path.
        auto it = std::lower_bound(rules_.begin(), rules_.end(), nr,
                                   [](const SyscallRule& r, SysNr v) { return r.nr < v; });
        if (it != rules_.end() && it->nr == nr) return it->action;
        return default_;
    }

    std::uint16_t errno_for(SysNr nr) const {
        auto it = std::lower_bound(rules_.begin(), rules_.end(), nr,
                                   [](const SyscallRule& r, SysNr v) { return r.nr < v; });
        if (it != rules_.end() && it->nr == nr) return it->errno_value;
        return default_errno_;
    }

    SyscallPolicy meet(const SyscallPolicy& o) const {
        SyscallPolicy out;
        out.default_ = clay::meet(default_, o.default_);
        out.default_errno_ = default_errno_;
        // the union of both rule sets is exactly the set of syscalls where the
        // result can differ from the new default.
        auto add = [&](SysNr nr) {
            for (const auto& r : out.rules_)
                if (r.nr == nr) return;
            SysAction a = clay::meet(action_for(nr), o.action_for(nr));
            std::uint16_t e = action_for(nr) <= o.action_for(nr) ? errno_for(nr) : o.errno_for(nr);
            if (a == out.default_) return;  // redundant with the default
            out.rules_.push_back({nr, a, e});
        };
        for (const auto& r : rules_) add(r.nr);
        for (const auto& r : o.rules_) add(r.nr);
        std::sort(out.rules_.begin(), out.rules_.end(),
                  [](const SyscallRule& x, const SyscallRule& y) { return x.nr < y.nr; });

        // argument rules are restrictions, so the meet keeps EVERY one from both
        // sides: a value either side wanted denied stays denied. that is the
        // right direction -- composing policies must not re-permit an argument
        // one of them ruled out.
        out.arg_rules_ = arg_rules_;
        for (const auto& r : o.arg_rules_) {
            bool have = false;
            for (auto& x : out.arg_rules_) {
                if (x.nr == r.nr && x.arg_index == r.arg_index && x.cmp == r.cmp &&
                    x.value == r.value && x.mask == r.mask && x.width == r.width) {
                    x.action = clay::meet(x.action, r.action);
                    have = true;
                    break;
                }
            }
            if (!have) out.arg_rules_.push_back(r);
        }
        sort_arg_rules(out.arg_rules_);

        // allow-lists compose by INTERSECTION, which is the opposite direction
        // from the deny rules above and for the same reason: fewer permitted
        // values is more restrictive. a set present on only one side carries over
        // unchanged, because the other side never spoke about that argument and
        // silence is not permission to widen.
        out.allow_sets_ = allow_sets_;
        for (const auto& s : o.allow_sets_) {
            bool have = false;
            for (auto& x : out.allow_sets_) {
                if (x.nr == s.nr && x.arg_index == s.arg_index) {
                    std::vector<std::uint32_t> both;
                    std::set_intersection(x.values.begin(), x.values.end(), s.values.begin(),
                                          s.values.end(), std::back_inserter(both));
                    x.values = std::move(both);
                    x.action = clay::meet(x.action, s.action);
                    have = true;
                    break;
                }
            }
            if (!have) out.allow_sets_.push_back(s);
        }
        std::sort(out.allow_sets_.begin(), out.allow_sets_.end(),
                  [](const ArgAllowSet& x, const ArgAllowSet& y) {
                      if (x.nr != y.nr) return x.nr < y.nr;
                      return x.arg_index < y.arg_index;
                  });
        return out;
    }

    bool subsumes(const SyscallPolicy& o) const {
        if (default_ < o.default_) return false;
        for (const auto& r : rules_)
            if (action_for(r.nr) < o.action_for(r.nr)) return false;
        for (const auto& r : o.rules_)
            if (action_for(r.nr) < o.action_for(r.nr)) return false;
        return true;
    }

    bool is_nothing() const { return default_ == SysAction::kill_process && rules_.empty(); }

    SysAction default_action() const { return default_; }
    std::uint16_t default_errno() const { return default_errno_; }
    const std::vector<SyscallRule>& rules() const { return rules_; }

    friend bool operator==(const SyscallPolicy& a, const SyscallPolicy& b) {
        if (a.default_ != b.default_) return false;
        for (const auto& r : a.rules_)
            if (a.action_for(r.nr) != b.action_for(r.nr)) return false;
        for (const auto& r : b.rules_)
            if (a.action_for(r.nr) != b.action_for(r.nr)) return false;
        return true;
    }

  private:
    SysAction default_{SysAction::kill_process};
    std::uint16_t default_errno_{1};
    std::vector<SyscallRule> rules_;
    std::vector<ArgRule> arg_rules_;
    std::vector<ArgAllowSet> allow_sets_;
};

static_assert(Lattice<SyscallPolicy>);

}  // namespace clay
