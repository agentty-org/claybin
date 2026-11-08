#include "claybin/bpf/emit.hpp"

#include <algorithm>
#include <cstddef>

namespace clay::bpf {
namespace {

constexpr Insn ld_abs(std::uint32_t off) { return Insn{kLd | kW | kAbs, 0, 0, off}; }
constexpr Insn jeq(std::uint32_t k, std::uint8_t jt, std::uint8_t jf) {
    return Insn{kJmp | kJeq | kK, jt, jf, k};
}
constexpr Insn jgt(std::uint32_t k, std::uint8_t jt, std::uint8_t jf) {
    return Insn{kJmp | kJgt | kK, jt, jf, k};
}
constexpr Insn jge(std::uint32_t k, std::uint8_t jt, std::uint8_t jf) {
    return Insn{kJmp | kJge | kK, jt, jf, k};
}
constexpr Insn ja(std::uint32_t off) { return Insn{kJmp | kJa, 0, 0, off}; }
constexpr Insn ret(std::uint32_t k) { return Insn{kRet | kK, 0, 0, k}; }
constexpr Insn jset(std::uint32_t k, std::uint8_t jt, std::uint8_t jf) {
    return Insn{kJmp | kJset | kK, jt, jf, k};
}
constexpr Insn and_k(std::uint32_t k) { return Insn{kAlu | kAnd | kK, 0, 0, k}; }

// placeholder jump targets inside an argument-rule block, patched once the
// block's length is known. 0xfe/0xff are safe as sentinels because a block is
// never more than a handful of instructions long, so a real offset can never
// collide with them.
constexpr std::uint8_t kMatch = 0xfe;  // -> the ret that applies the action
constexpr std::uint8_t kFail = 0xff;   // -> the accumulator restore, rule missed

// x86_64 tags x32 syscalls with this bit. filtering on the number alone while
// ignoring it is the classic seccomp bypass, so we reject the whole range.
constexpr std::uint32_t kX32SyscallBit = 0x40000000u;

class TreeEmitter {
  public:
    TreeEmitter(const std::vector<Interval>& ivs, std::uint32_t default_ret)
        : ivs_(ivs), default_ret_(default_ret) {}

    void emit(std::vector<Insn>& out) {
        out_ = &out;
        build(0, static_cast<long>(ivs_.size()) - 1, 1);
        // one shared default block at the tail; every miss lands here.
        std::size_t def = out_->size();
        out_->push_back(ret(default_ret_));
        for (std::size_t site : default_sites_) patch_ja(site, def);
    }

    std::uint32_t depth() const { return depth_; }

  private:
    // node layout (4 instructions, subtrees inline):
    //   [0] JGT hi   -> [1] if above the interval, else [2]
    //   [1] JA right    (32-bit target, so a big tree can never overflow a jump)
    //   [2] JGE lo   -> [3] if inside, else [4]
    //   [3] RET action
    //   [4] left subtree, emitted inline so its offset is always reachable
    //   ... right subtree, reached by the JA above
    void build(long lo, long hi, std::uint32_t level) {
        if (lo > hi) {
            default_sites_.push_back(out_->size());
            out_->push_back(ja(0));
            return;
        }
        depth_ = std::max(depth_, level);
        long mid = lo + (hi - lo) / 2;
        const Interval& iv = ivs_[static_cast<std::size_t>(mid)];

        out_->push_back(jgt(iv.hi, 0, 1));
        std::size_t right_site = out_->size();
        out_->push_back(ja(0));
        out_->push_back(jge(iv.lo, 0, 1));
        out_->push_back(ret(iv.ret));

        build(lo, mid - 1, level + 1);
        patch_ja(right_site, out_->size());
        build(mid + 1, hi, level + 1);
    }

    void patch_ja(std::size_t site, std::size_t target) {
        (*out_)[site].k = static_cast<std::uint32_t>(target - (site + 1));
    }

    const std::vector<Interval>& ivs_;
    std::uint32_t default_ret_;
    std::vector<Insn>* out_{nullptr};
    std::vector<std::size_t> default_sites_;
    std::uint32_t depth_{0};
};

}  // namespace

std::vector<Interval> fold_intervals(const SyscallPolicy& policy) {
    std::uint32_t def = action_to_ret(policy.default_action(), policy.default_errno());

    std::vector<Interval> singles;
    singles.reserve(policy.rules().size());
    for (const auto& r : policy.rules()) {
        std::uint32_t rv = action_to_ret(r.action, r.errno_value);
        if (rv == def) continue;  // the default already says this
        singles.push_back({r.nr, r.nr, rv});
    }
    std::sort(singles.begin(), singles.end(),
              [](const Interval& a, const Interval& b) { return a.lo < b.lo; });

    // merge contiguous runs with the same action. allow-lists are dense in runs
    // (read/write/open/close/stat... are adjacent numbers), so this is where the
    // ~400 -> ~60 collapse comes from.
    std::vector<Interval> out;
    out.reserve(singles.size());
    for (const auto& iv : singles) {
        if (!out.empty() && out.back().ret == iv.ret && out.back().hi + 1 == iv.lo) {
            out.back().hi = iv.hi;
        } else {
            out.push_back(iv);
        }
    }
    return out;
}

Result<Program> compile(const SyscallPolicy& policy, std::uint32_t arch) {
    if (arch == 0)
        return std::unexpected(Error{Errc::unsupported, "seccomp: unknown audit arch"});

    Program prog;
    prog.arch = arch;
    prog.default_ret = action_to_ret(policy.default_action(), policy.default_errno());
    prog.intervals = fold_intervals(policy);

    auto& out = prog.insns;
    out.reserve(prog.intervals.size() * 4 + 8);

    // prologue: arch guard first. a filter that checks syscall numbers without
    // pinning the arch is exploitable on any machine with more than one syscall
    // convention, so this is not optional.
    out.push_back(ld_abs(kOffArch));
    out.push_back(jeq(arch, 1, 0));
    out.push_back(ret(kRetKillProcess));
    out.push_back(ld_abs(kOffNr));

    // nr == -1 is a syscall a tracer cancelled (gdb, strace -e inject,
    // linuxity): the kernel skips it and runs nothing. Since 4.8 seccomp sees
    // it again after the tracer's change, and the x32 guard below would kill
    // the task for it, so a sandboxed debugger or emulator died on its first
    // cancelled call.
    out.push_back(jeq(0xffffffffu, 0, 1));
    out.push_back(ret(kRetAllow));

    if (arch == kAuditArchX86_64) {
        // reject the x32 range outright rather than trying to reason about it.
        out.push_back(jge(kX32SyscallBit, 0, 1));
        out.push_back(ret(kRetKillProcess));
    }

    // ---- argument rules, before the interval tree ------------------------
    //
    // these are exceptions carved out of an otherwise-allowed syscall, so they
    // have to be checked FIRST -- the tree would say `allow` and return.
    //
    // every comparison is done in TWO halves, low then high, because seccomp_data
    // gives us a 64-bit register and classic BPF only has a 32-bit accumulator.
    // checking only the low half is a real bypass: an attacker sets the high
    // bits, the comparison misses, and the syscall still does what they wanted.
    //
    // block shape is always [checks..., ret(action), ld nr]. the trailing load
    // restores the accumulator, because the interval tree that follows needs the
    // syscall number and every check here clobbered it with an argument. two
    // sentinels stand in for the jump targets while the block is being built,
    // since its length is not known until the last check is emitted.
    for (const auto& r : policy.arg_rules()) {
        std::uint32_t act = action_to_ret(r.action, r.errno_value);
        auto lo = static_cast<std::uint32_t>(r.value & 0xffffffffu);
        auto hi = static_cast<std::uint32_t>(r.value >> 32);
        auto mlo = static_cast<std::uint32_t>(r.mask & 0xffffffffu);
        auto mhi = static_cast<std::uint32_t>(r.mask >> 32);

        // a 32-bit kernel parameter must be compared in the low half ONLY.
        //
        // this is not an optimisation, it is the fix for a real bypass. the
        // kernel truncates the register to the declared parameter type before
        // using it, so ioctl(fd, 0xdeadbeef00005412) runs as TIOCSTI -- while a
        // filter that also requires the high half to be zero sees a value
        // matching nothing and waves it through. measured on 7.2: a both-halves
        // rule denies 0x5413 and allows 0xdeadbeef00005413, which the kernel
        // then executes as TIOCGWINSZ.
        //
        // the inverse mistake is just as real, which is why this is per-rule and
        // not a blanket policy: for a genuinely 64-bit argument, ignoring the
        // high half is the classic seccomp bypass in the other direction.
        const bool narrow = r.width == ArgWidth::bits32;
        if (narrow) {
            hi = 0;
            mhi = 0;
        }

        std::vector<Insn> body;
        bool dead = false;  // a rule whose predicate can never be true

        switch (r.cmp) {
            case ArgCmp::eq:
                body.push_back(ld_abs(arg_lo_off(r.arg_index)));
                body.push_back(jeq(lo, 0, kFail));
                if (!narrow) {
                    body.push_back(ld_abs(arg_hi_off(r.arg_index)));
                    body.push_back(jeq(hi, 0, kFail));
                }
                break;

            case ArgCmp::masked_eq:
                // (arg & mask) == value, per half. a half with a zero mask is
                // vacuously true when the expected value is zero there, and
                // impossible when it is not -- masking away a bit cannot leave it
                // set, so such a rule is dead and emitting it would be a lie.
                for (int half = 0; half < 2; ++half) {
                    std::uint32_t m = half ? mhi : mlo;
                    std::uint32_t v = half ? hi : lo;
                    if (m == 0) {
                        if (v != 0) dead = true;
                        continue;
                    }
                    body.push_back(ld_abs(half ? arg_hi_off(r.arg_index)
                                               : arg_lo_off(r.arg_index)));
                    body.push_back(and_k(m));
                    body.push_back(jeq(v & m, 0, kFail));
                }
                break;

            case ArgCmp::any_set:
                // (arg & mask) != 0: a match as soon as EITHER half has a bit, so
                // the first half's test jumps forward to the verdict on success
                // rather than falling through.
                //
                // the emptiness test is on the TRUNCATED halves, not r.mask: a
                // 32-bit rule whose mask lived entirely above the line asks about
                // bits the kernel never reads, so it can never fire and must be
                // dropped rather than emitted against the high half.
                if (mlo == 0 && mhi == 0) {
                    dead = true;  // nothing can be masked out of nothing
                    break;
                }
                if (mlo != 0 && mhi != 0) {
                    body.push_back(ld_abs(arg_lo_off(r.arg_index)));
                    body.push_back(jset(mlo, kMatch, 0));
                    body.push_back(ld_abs(arg_hi_off(r.arg_index)));
                    body.push_back(jset(mhi, 0, kFail));
                } else if (mlo != 0) {
                    body.push_back(ld_abs(arg_lo_off(r.arg_index)));
                    body.push_back(jset(mlo, 0, kFail));
                } else {
                    body.push_back(ld_abs(arg_hi_off(r.arg_index)));
                    body.push_back(jset(mhi, 0, kFail));
                }
                break;
        }

        if (dead) continue;

        std::size_t match_at = body.size();  // where ret(act) will land
        body.push_back(ret(act));
        std::size_t fail_at = body.size();  // the accumulator restore
        body.push_back(ld_abs(kOffNr));

        // resolve the sentinels now that both targets are known. offsets are
        // relative to the instruction AFTER the jump, hence the -1.
        for (std::size_t i = 0; i < body.size(); ++i) {
            auto fix = [&](std::uint8_t& t) {
                if (t == kMatch)
                    t = static_cast<std::uint8_t>(match_at - i - 1);
                else if (t == kFail)
                    t = static_cast<std::uint8_t>(fail_at - i - 1);
            };
            fix(body[i].jt);
            fix(body[i].jf);
        }

        // wrong syscall: skip the block whole. the accumulator is untouched on
        // this path, so control lands directly on the tree with nr still loaded.
        //
        // a jump offset is 8 bits. blocks top out at 6 instructions, so this is
        // unreachable -- but it is a silent miscompile if it ever is not, and a
        // seccomp filter that jumps to the wrong place fails OPEN.
        if (body.size() > 0xff)
            return std::unexpected(Error{Errc::too_many_rules, "seccomp: arg rule too large"});
        out.push_back(jeq(r.nr, 0, static_cast<std::uint8_t>(body.size())));
        out.insert(out.end(), body.begin(), body.end());
    }

    // ---- argument allow-lists --------------------------------------------
    //
    // the inverse shape: everything about this argument is denied except the
    // listed values. for a syscall as wide as ioctl this is the only workable
    // policy -- there are thousands of requests and any loaded driver can add
    // more, so a deny-list is a list of the escapes somebody already thought of.
    //
    // these go AFTER the deny rules so a deny still wins on a value that appears
    // in both. that ordering is what lets a caller allow a broad set and then
    // carve one value back out of it.
    //
    // shape is [match value -> fall through]* , ret(deny), ld nr. every hit jumps
    // past the deny to the restore, so the allowed path costs one compare per
    // listed value and lands on the interval tree exactly as if nothing happened.
    for (const auto& s : policy.arg_allow_sets()) {
        if (s.values.empty()) {
            // an empty allow-list denies the syscall outright. that is a real
            // policy -- the intersection of two disjoint allow-lists -- so it is
            // emitted rather than skipped, otherwise composing two policies could
            // silently GRANT the syscall back.
            out.push_back(jeq(s.nr, 0, 2));
            out.push_back(ret(action_to_ret(s.action, s.errno_value)));
            out.push_back(ld_abs(kOffNr));
            continue;
        }

        std::vector<Insn> body;
        body.push_back(ld_abs(arg_lo_off(s.arg_index)));
        // note there is no high-half check anywhere in here, and that is the
        // point: the allow-list is for 32-bit arguments, and the kernel truncates
        // them. requiring the high half to be zero would let
        // ioctl(fd, 0xdeadbeef00005412) past the filter to run as TIOCSTI.
        for (std::uint32_t v : s.values) body.push_back(jeq(v, kMatch, 0));
        body.push_back(ret(action_to_ret(s.action, s.errno_value)));

        std::size_t match_at = body.size();  // the accumulator restore
        body.push_back(ld_abs(kOffNr));

        for (std::size_t i = 0; i < body.size(); ++i) {
            auto fix = [&](std::uint8_t& t) {
                if (t == kMatch) t = static_cast<std::uint8_t>(match_at - i - 1);
            };
            fix(body[i].jt);
            fix(body[i].jf);
        }

        // an 8-bit jump offset caps how many values one block can hold. this is
        // reachable -- an allow-list of 300 ioctls is a reasonable thing to write
        // -- so it is a real error and not a defensive check.
        if (body.size() > 0xff)
            return std::unexpected(
                Error{Errc::too_many_rules, "seccomp: argument allow-list too long"});

        out.push_back(jeq(s.nr, 0, static_cast<std::uint8_t>(body.size())));
        out.insert(out.end(), body.begin(), body.end());
    }

    TreeEmitter emitter{prog.intervals, prog.default_ret};
    emitter.emit(out);
    prog.tree_depth = emitter.depth();

    // classic BPF programs are capped at 4096 instructions by the kernel.
    if (out.size() > 4096)
        return std::unexpected(Error{Errc::too_many_rules, "seccomp: program too large"});

    return prog;
}

std::uint32_t evaluate(const Program& prog, std::uint32_t nr, std::uint32_t arch) {
    return evaluate_with_args(prog, nr, arch, nullptr);
}

std::uint32_t evaluate_with_args(const Program& prog, std::uint32_t nr, std::uint32_t arch,
                                 const std::uint64_t* args) {
    // minimal classic-BPF interpreter over struct seccomp_data. only the opcodes
    // we emit are handled; anything else means the emitter changed without the
    // interpreter, so we fail loud instead of guessing.
    std::uint32_t acc = 0;
    std::size_t pc = 0;
    for (std::size_t steps = 0; steps < 100000 && pc < prog.insns.size(); ++steps) {
        const Insn& in = prog.insns[pc];
        std::uint16_t cls = in.code & 0x07;
        if (cls == kLd) {
            if (in.k == kOffArch) {
                acc = arch;
            } else if (in.k == kOffNr) {
                acc = nr;
            } else if (in.k >= kOffArgs) {
                // an argument half. index and which half fall out of the offset.
                std::uint32_t rel = in.k - kOffArgs;
                std::uint32_t idx = rel / 8;
                bool high = (rel % 8) == 4;
                std::uint64_t v = (args && idx < 6) ? args[idx] : 0;
                acc = high ? static_cast<std::uint32_t>(v >> 32)
                           : static_cast<std::uint32_t>(v & 0xffffffffu);
            } else {
                acc = 0;
            }
            ++pc;
        } else if (cls == kRet) {
            return in.k;
        } else if (cls == kAlu) {
            if ((in.code & 0xf0) != kAnd) break;  // only AND is ever emitted
            acc &= in.k;
            ++pc;
        } else if (cls == kJmp) {
            std::uint16_t op = in.code & 0xf0;
            if (op == kJa) {
                pc += 1 + in.k;
            } else {
                bool taken = (op == kJeq)    ? (acc == in.k)
                             : (op == kJgt)  ? (acc > in.k)
                             : (op == kJge)  ? (acc >= in.k)
                             : (op == kJset) ? ((acc & in.k) != 0)
                                             : false;
                pc += 1 + (taken ? in.jt : in.jf);
            }
        } else {
            break;
        }
    }
    return kRetKillProcess;  // fell off the end: treat as deny
}

}  // namespace clay::bpf
