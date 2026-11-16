// the seccomp filter is the one piece of this library that runs on every single
// guest syscall, and a bug in it is either a bypass or a crash. so it gets a
// differential test: the emitted BPF tree is executed by an interpreter and
// compared against a straight linear lookup, over EVERY syscall number.

#include "harness.hpp"

#include "claybin/bpf/emit.hpp"
#include "claybin/policy/profiles.hpp"
#include "claybin/policy/profiles_i386.hpp"
#include "claybin/policy/policy.hpp"

using namespace clay;
using namespace clay::bpf;
using namespace clay::test;

namespace {

// the reference: what the answer should be, computed the obvious slow way.
std::uint32_t reference(const SyscallPolicy& p, SysNr nr) {
    return action_to_ret(p.action_for(nr), p.errno_for(nr));
}

void differential(const SyscallPolicy& p, std::uint32_t max_nr = 600) {
    auto prog = compile(p, kAuditArchX86_64);
    CHECK(prog.has_value());
    if (!prog) return;
    for (SysNr nr = 0; nr < max_nr; ++nr) {
        std::uint32_t got = evaluate(*prog, nr, kAuditArchX86_64);
        std::uint32_t want = nr >= 512 && nr <= 547 ? kRetKillProcess : reference(p, nr);
        if (got != want) {
            std::fprintf(stderr, "  nr=%u got=%#x want=%#x\n", nr, got, want);
            CHECK_EQ(got, want);
            return;  // one report is enough, don't spam
        }
    }
    ++g_checks;
}

}  // namespace

int main() {
    {
        auto native = SyscallPolicy::everything();
        auto compat = profiles_i386::compiler();
        auto prog = compile(native, std::optional{compat}, kAuditArchX86_64);
        CHECK(prog.has_value());
        if (prog) {
            CHECK_EQ(evaluate(*prog, 11, kAuditArchI386), kRetAllow); // execve
            for (auto nr : {13u, 27u, 104u, 105u, 29u, 57u, 65u, 66u, 132u, 147u})
                CHECK_EQ(evaluate(*prog, nr, kAuditArchI386), kRetAllow);
            CHECK_EQ(evaluate(*prog, 3, 0u), kRetKillProcess); // unknown audit arch
            // Upstream's tracer-cancelled syscall exception applies only after
            // architecture validation, and must survive multi-ABI dispatch.
            CHECK_EQ(evaluate(*prog, 0xffffffffu, kAuditArchX86_64), kRetAllow);
            CHECK_EQ(evaluate(*prog, 0xffffffffu, kAuditArchI386), kRetAllow);
            CHECK_EQ(evaluate(*prog, 0xffffffffu, 0u), kRetKillProcess);
            CHECK_EQ(evaluate(*prog, 59, kAuditArchI386), kRetErrno | 1u);
            CHECK_EQ(evaluate(*prog, 59, kAuditArchX86_64), kRetAllow);
            CHECK_EQ(evaluate(*prog, 11, kAuditArchAarch64), kRetKillProcess);
            for (auto nr : {512u, 513u, 547u, 0x40000000u, 0x40000200u})
                CHECK_EQ(evaluate(*prog, nr, kAuditArchX86_64), kRetKillProcess);
            for (auto nr : {511u, 548u})
                CHECK_EQ(evaluate(*prog, nr, kAuditArchX86_64), kRetAllow);
            CHECK_EQ(evaluate(*prog, 0x40000003u, kAuditArchI386), kRetKillProcess);
            CHECK_EQ(evaluate(*prog, 90, kAuditArchI386), kRetErrno | 38u);
            for (auto nr : {192u,125u}) {
                std::uint64_t args[6]{};
                args[2] = 6;
                CHECK_EQ(evaluate_with_args(*prog, nr, kAuditArchI386, args), kRetErrno | 1u);
                args[2] = 5;
                CHECK_EQ(evaluate_with_args(*prog, nr, kAuditArchI386, args), kRetAllow);
            }
            std::uint64_t args[6]{0x10000000u};
            CHECK_EQ(evaluate_with_args(*prog, 120, kAuditArchI386, args), kRetErrno | 1u);
            args[0] = 0x100;
            CHECK_EQ(evaluate_with_args(*prog, 120, kAuditArchI386, args), kRetAllow);
            CHECK_EQ(evaluate(*prog, 37, kAuditArchI386), kRetAllow); // kill, as on x86_64
            CHECK_EQ(evaluate(*prog, 380, kAuditArchI386), kRetErrno | 1u); // pkey_mprotect, as native
            CHECK_EQ(evaluate(*prog, 26, kAuditArchI386), kRetKillProcess); // ptrace
            CHECK_EQ(evaluate(*prog, 288, kAuditArchI386), kRetErrno | 1u); // keyctl: EPERM, as native
            args[1] = 0x100005401ull; // ioctl ignores upper register bits
            CHECK_EQ(evaluate_with_args(*prog, 54, kAuditArchI386, args), kRetAllow);
            args[1] = 0x5412; // TIOCSTI
            CHECK_EQ(evaluate_with_args(*prog, 54, kAuditArchI386, args), kRetErrno | 1u);
        }
        auto only_native = compile(native, std::optional<SyscallPolicy>{}, kAuditArchX86_64);
        CHECK(only_native.has_value());
        CHECK_EQ(evaluate(*only_native, 11, kAuditArchI386), kRetKillProcess);
        // i386 rules may notify: broker::Request carries the arch.
        compat.notify(37);
        auto with_notify = compile(native, std::optional{compat}, kAuditArchX86_64);
        CHECK(with_notify.has_value());
        CHECK_EQ(evaluate(*with_notify, 37, kAuditArchI386), kRetUserNotif);
        CHECK_EQ(evaluate(*with_notify, 37, kAuditArchX86_64) != kRetUserNotif, true);
        auto network = profiles_i386::compiler_with_network();
        CHECK_EQ(network.action_for(102), SysAction::errno_);
        CHECK_EQ(network.errno_for(102), std::uint16_t{38});
        auto network_prog = compile(native, std::optional{network}, kAuditArchX86_64);
        CHECK(network_prog.has_value());
        if (network_prog) {
            CHECK_EQ(evaluate(*network_prog, 102, kAuditArchI386), kRetErrno | 38u);
            CHECK_EQ(evaluate(*network_prog, 359, kAuditArchI386), kRetAllow); // socket
        }
        PolicyData a, b;
        a.syscalls_i386 = profiles_i386::compiler();
        CHECK(a.subsumes(b));
        CHECK(!b.subsumes(a));
        CHECK(!a.meet(b).syscalls_i386);
        CHECK(!b.meet(a).syscalls_i386);
        b.syscalls_i386 = SyscallPolicy::everything();
        CHECK(b.subsumes(a));
        CHECK(a.meet(b).syscalls_i386.has_value());
    }
    // -- arch guard --------------------------------------------------------
    {
        SyscallPolicy p;
        p.set_default(SysAction::allow);
        auto prog = compile(p, kAuditArchX86_64);
        CHECK(prog.has_value());
        // right arch: allowed
        CHECK_EQ(evaluate(*prog, 0, kAuditArchX86_64), kRetAllow);
        // wrong arch must be killed, never merely denied. filtering on syscall
        // numbers without pinning the arch is the classic seccomp bypass.
        CHECK_EQ(evaluate(*prog, 0, kAuditArchAarch64), kRetKillProcess);
        // x32 range must be killed even with an allow-all default
        CHECK_EQ(evaluate(*prog, 0x40000000u, kAuditArchX86_64), kRetKillProcess);
        CHECK_EQ(evaluate(*prog, 0x40000001u, kAuditArchX86_64), kRetKillProcess);
    }

    // -- empty policy: deny everything -------------------------------------
    {
        SyscallPolicy p = SyscallPolicy::nothing();
        auto prog = compile(p, kAuditArchX86_64);
        CHECK(prog.has_value());
        CHECK_EQ(evaluate(*prog, 60, kAuditArchX86_64), kRetKillProcess);
        differential(p);
    }

    // -- a realistic allow-list --------------------------------------------
    {
        SyscallPolicy p;
        p.set_default(SysAction::errno_, 1);
        // a contiguous run: this is what folding is supposed to collapse
        for (SysNr nr = 0; nr <= 8; ++nr) p.allow(nr);
        p.allow(60);   // exit
        p.allow(231);  // exit_group
        p.allow(202);  // futex
        p.notify(41);  // socket -> broker
        p.kill(101);   // ptrace

        auto prog = compile(p, kAuditArchX86_64);
        CHECK(prog.has_value());
        // 0..8 became ONE interval, not nine
        bool found_run = false;
        for (const auto& iv : prog->intervals)
            if (iv.lo == 0 && iv.hi == 8) found_run = true;
        CHECK(found_run);

        CHECK_EQ(evaluate(*prog, 3, kAuditArchX86_64), kRetAllow);
        CHECK_EQ(evaluate(*prog, 41, kAuditArchX86_64), kRetUserNotif);
        CHECK_EQ(evaluate(*prog, 101, kAuditArchX86_64), kRetKillProcess);
        CHECK_EQ(evaluate(*prog, 9, kAuditArchX86_64), kRetErrno | 1);
        differential(p);
    }

    // -- the performance claim, as an assertion ----------------------------
    // ~400 allowed syscalls must fold and stay shallow. if someone regresses the
    // emitter into a linear chain, this fails.
    {
        SyscallPolicy p;
        p.set_default(SysAction::errno_, 1);
        for (SysNr nr = 0; nr < 400; ++nr) p.allow(nr);
        auto prog = compile(p, kAuditArchX86_64);
        CHECK(prog.has_value());
        // one fully contiguous run collapses to a single interval
        CHECK_EQ(prog->intervals.size(), std::size_t{1});
        CHECK(prog->insns.size() < 32);
        differential(p);
    }
    {
        // worst case: every other syscall allowed, so nothing merges.
        SyscallPolicy p;
        p.set_default(SysAction::errno_, 1);
        for (SysNr nr = 0; nr < 400; nr += 2) p.allow(nr);
        auto prog = compile(p, kAuditArchX86_64);
        CHECK(prog.has_value());
        CHECK_EQ(prog->intervals.size(), std::size_t{200});
        // 200 intervals: a balanced tree is 8 levels. a linear chain would be 200.
        CHECK(prog->tree_depth <= 9);
        CHECK(prog->insns.size() < 4096);
        differential(p);
    }

    // -- fuzz the emitter against the reference ----------------------------
    {
        Rng rng{0xB9Full};
        for (int i = 0; i < 200; ++i) {
            SyscallPolicy p;
            p.set_default(static_cast<SysAction>(rng.below(7)), 1);
            std::uint32_t n = rng.below(120);
            for (std::uint32_t k = 0; k < n; ++k)
                p.set(rng.below(500), static_cast<SysAction>(rng.below(7)), 1);
            differential(p);
        }
    }

    // -- degenerate shapes -------------------------------------------------
    {
        SyscallPolicy p;
        p.set_default(SysAction::kill_process);
        p.allow(0);  // first number
        differential(p, 8);
    }
    {
        SyscallPolicy p;
        p.set_default(SysAction::allow);
        p.kill(0xffffu);  // far from everything else
        differential(p, 0x10002u);
    }

    // -- argument filtering ------------------------------------------------
    // seccomp can see the syscall's register arguments, which is the only way to
    // say "ioctl is fine, except TIOCSTI". without it the choice is between
    // allowing a keystroke-injection escape and breaking isatty() everywhere.
    {
        SyscallPolicy p;
        p.set_default(SysAction::errno_, 1);
        p.allow(16);  // ioctl allowed in general
        p.deny_arg(16, 1, 0x5412, SysAction::errno_, 1);  // except TIOCSTI

        auto prog = compile(p, kAuditArchX86_64);
        CHECK(prog.has_value());
        if (!prog) return finish("bpf_emit_test");

        // a plain ioctl with some other request is allowed
        std::uint64_t args_ok[6] = {0, 0x5401, 0, 0, 0, 0};
        CHECK_EQ(evaluate_with_args(*prog, 16, kAuditArchX86_64, args_ok), kRetAllow);

        // TIOCSTI is denied
        std::uint64_t args_sti[6] = {0, 0x5412, 0, 0, 0, 0};
        CHECK_EQ(evaluate_with_args(*prog, 16, kAuditArchX86_64, args_sti), kRetErrno | 1);

        // THE BYPASS THAT MATTERS: setting the high 32 bits must not sneak past.
        // a filter that compares only the low half would see 0x5412 here and
        // let it through while the kernel still performs the ioctl.
        std::uint64_t args_hi[6] = {0, 0x100000000ull | 0x5412, 0, 0, 0, 0};
        CHECK_EQ(evaluate_with_args(*prog, 16, kAuditArchX86_64, args_hi), kRetAllow);
        // (allow is CORRECT here: it is a different request number, so the deny
        // rule should not match. the point is that it is evaluated as a full
        // 64-bit value rather than truncated.)

        // a DIFFERENT syscall with the same arg value is unaffected
        CHECK_EQ(evaluate_with_args(*prog, 0, kAuditArchX86_64, args_sti), kRetErrno | 1);
    }

    // arg rules must not disturb the tree that follows them: the accumulator
    // holds an argument mid-check and has to be restored to the syscall number.
    {
        SyscallPolicy p;
        p.set_default(SysAction::errno_, 1);
        for (SysNr nr = 0; nr < 64; ++nr) p.allow(nr);
        p.deny_arg(16, 1, 0x5412);
        p.deny_arg(16, 1, 0x541C);
        p.deny_arg(101, 0, 0);

        auto prog = compile(p, kAuditArchX86_64);
        CHECK(prog.has_value());
        if (!prog) return finish("bpf_emit_test");

        // every allowed syscall still resolves correctly with no args set
        for (SysNr nr = 0; nr < 64; ++nr) {
            if (nr == 101) continue;  // has an arg rule matching zero
            std::uint32_t got = evaluate(*prog, nr, kAuditArchX86_64);
            if (got != kRetAllow) {
                std::fprintf(stderr, "  nr=%u clobbered by arg rules: %#x\n", nr, got);
                CHECK_EQ(got, kRetAllow);
                break;
            }
        }
        ++g_checks;

        // and the denials still fire
        std::uint64_t sti[6] = {0, 0x5412, 0, 0, 0, 0};
        CHECK_EQ(evaluate_with_args(*prog, 16, kAuditArchX86_64, sti), kRetErrno | 1);
        std::uint64_t lin[6] = {0, 0x541C, 0, 0, 0, 0};
        CHECK_EQ(evaluate_with_args(*prog, 16, kAuditArchX86_64, lin), kRetErrno | 1);
    }

    // the real profile must deny TIOCSTI and still allow ioctl generally.
    {
        auto prog = compile(profiles::base(), kAuditArchX86_64);
        CHECK(prog.has_value());
        if (prog) {
            std::uint64_t sti[6] = {0, 0x5412, 0, 0, 0, 0};
            CHECK_EQ(evaluate_with_args(*prog, 16, kAuditArchX86_64, sti), kRetErrno | 1);
            std::uint64_t tcgets[6] = {0, 0x5401, 0, 0, 0, 0};
            CHECK_EQ(evaluate_with_args(*prog, 16, kAuditArchX86_64, tcgets), kRetAllow);
        }
    }

    // -- masked argument rules ---------------------------------------------
    //
    // equality alone cannot express the interesting policies. every flag syscall
    // packs independent bits into one register, so "deny CLONE_NEWUSER" is a bit
    // test and an equality test against CLONE_NEWUSER is bypassed by setting any
    // other harmless flag alongside it.
    //
    // this is checked against a SPEC written straight from the definition of each
    // comparison, over a value set chosen to hit every edge: the mask alone, the
    // mask plus noise, a subset of the mask, each half in isolation, and values
    // that only differ above the 32-bit line.
    {
        auto spec_matches = [](ArgCmp cmp, std::uint64_t mask, std::uint64_t value,
                               std::uint64_t arg) {
            switch (cmp) {
                case ArgCmp::eq: return arg == value;
                case ArgCmp::masked_eq: return (arg & mask) == (value & mask);
                case ArgCmp::any_set: return (arg & mask) != 0;
            }
            return false;
        };

        static constexpr std::uint64_t kMasks[] = {
            0x20000000ull,           // CLONE_NEWUSER: one bit, low half
            0x6ull,                  // PROT_WRITE|PROT_EXEC: two adjacent bits
            0xf0000000ull,           // all the top clone namespace bits
            0x100000000ull,          // one bit, HIGH half only
            0x300000000ull,          // two bits, high half only
            0x100000001ull,          // straddles the halves: the interesting one
            0xffffffffffffffffull,   // everything
        };
        static constexpr std::uint64_t kArgs[] = {
            0,
            1,
            0x6ull,
            0x2ull,
            0x4ull,
            0x7ull,
            0x20000000ull,
            0x20000f00ull,
            0xf0000000ull,
            0x100000000ull,
            0x100000001ull,
            0x300000000ull,
            0x200000000ull,
            0xffffffffffffffffull,
        };

        for (ArgCmp cmp : {ArgCmp::masked_eq, ArgCmp::any_set}) {
            for (std::uint64_t mask : kMasks) {
                for (std::uint64_t value : kArgs) {
                    SyscallPolicy p;
                    p.set_default(SysAction::allow);
                    p.allow(56);
                    p.deny_arg_cmp(56, 0, cmp, cmp == ArgCmp::masked_eq ? (value & mask) : 0,
                                   mask, SysAction::errno_, 1);

                    auto prog = compile(p, kAuditArchX86_64);
                    CHECK(prog.has_value());
                    if (!prog) return finish("bpf_emit_test");

                    for (std::uint64_t arg : kArgs) {
                        std::uint64_t args[6] = {arg, 0, 0, 0, 0, 0};
                        std::uint32_t got =
                            evaluate_with_args(*prog, 56, kAuditArchX86_64, args);
                        bool want_deny = spec_matches(cmp, mask,
                                                      cmp == ArgCmp::masked_eq ? value : 0, arg);
                        std::uint32_t want = want_deny ? (kRetErrno | 1) : kRetAllow;
                        if (got != want) {
                            std::fprintf(stderr,
                                         "  cmp=%d mask=%#llx value=%#llx arg=%#llx: "
                                         "got %#x want %#x\n",
                                         static_cast<int>(cmp),
                                         static_cast<unsigned long long>(mask),
                                         static_cast<unsigned long long>(value),
                                         static_cast<unsigned long long>(arg), got, want);
                            CHECK_EQ(got, want);
                            return finish("bpf_emit_test");
                        }
                        ++g_checks;
                    }
                }
            }
        }
    }

    // a masked rule whose predicate can never be true must not be emitted at
    // all. `(arg & 0) == 1` is such a rule: masking a bit away cannot leave it
    // set. emitting it would be worse than useless -- the block would clobber
    // the accumulator and the tree after it would read an argument as a syscall
    // number.
    {
        SyscallPolicy p;
        p.set_default(SysAction::errno_, 1);
        for (SysNr nr = 0; nr < 64; ++nr) p.allow(nr);
        p.deny_arg_cmp(56, 0, ArgCmp::masked_eq, 1, 0);      // impossible
        p.deny_arg_cmp(57, 0, ArgCmp::any_set, 0, 0);        // (arg & 0) != 0

        auto prog = compile(p, kAuditArchX86_64);
        CHECK(prog.has_value());
        if (!prog) return finish("bpf_emit_test");

        for (SysNr nr = 0; nr < 64; ++nr) {
            std::uint64_t args[6] = {0xffffffffffffffffull, 0, 0, 0, 0, 0};
            CHECK_EQ(evaluate_with_args(*prog, nr, kAuditArchX86_64, args), kRetAllow);
        }
    }

    // the profiles must actually stop the namespace and W^X moves.
    {
        auto prog = compile(profiles::with_processes(), kAuditArchX86_64);
        CHECK(prog.has_value());
        if (prog) {
            // the real pthread_create flag set, from linux/sched.h. it must be
            // allowed: a sandbox that cannot start a thread is not usable, and
            // CLONE_VM (0x100) sits close enough to CLONE_NEWNS (0x20000) that
            // getting the mask wrong breaks exactly this case.
            constexpr std::uint64_t kPthread = 0x00000100ull |  // CLONE_VM
                                               0x00000200ull |  // CLONE_FS
                                               0x00000400ull |  // CLONE_FILES
                                               0x00000800ull |  // CLONE_SIGHAND
                                               0x00010000ull;   // CLONE_THREAD
            std::uint64_t thread[6] = {kPthread, 0, 0, 0, 0, 0};
            CHECK_EQ(evaluate_with_args(*prog, 56, kAuditArchX86_64, thread), kRetAllow);

            // a plain fork-like clone with no flags at all is fine too.
            std::uint64_t plain[6] = {0, 0, 0, 0, 0, 0};
            CHECK_EQ(evaluate_with_args(*prog, 56, kAuditArchX86_64, plain), kRetAllow);

            // CLONE_NEWUSER alone, and hidden inside a legitimate thread clone:
            // both denied. the second is the case equality filtering misses.
            constexpr std::uint64_t kNewUser = 0x10000000ull;
            std::uint64_t newuser[6] = {kNewUser, 0, 0, 0, 0, 0};
            CHECK_EQ(evaluate_with_args(*prog, 56, kAuditArchX86_64, newuser), kRetErrno | 1);
            std::uint64_t hidden[6] = {kNewUser | kPthread, 0, 0, 0, 0, 0};
            CHECK_EQ(evaluate_with_args(*prog, 56, kAuditArchX86_64, hidden), kRetErrno | 1);

            // CLONE_NEWNS, the mount namespace, is the other one that matters.
            std::uint64_t newns[6] = {0x00020000ull, 0, 0, 0, 0, 0};
            CHECK_EQ(evaluate_with_args(*prog, 56, kAuditArchX86_64, newns), kRetErrno | 1);

            // CLONE_IO is 0x80000000 and is NOT a namespace, so it stays allowed.
            // it is adjacent to the namespace bits, which makes it the natural
            // off-by-one if the mask is ever edited by hand.
            std::uint64_t clone_io[6] = {0x80000000ull, 0, 0, 0, 0, 0};
            CHECK_EQ(evaluate_with_args(*prog, 56, kAuditArchX86_64, clone_io), kRetAllow);

            // clone3 has to be ENOSYS, not EPERM: glibc probes it and falls back
            // to clone, and the fallback only happens on ENOSYS.
            CHECK_EQ(evaluate(*prog, 435, kAuditArchX86_64), kRetErrno | 38);

            // W^X. PROT_READ|PROT_WRITE and PROT_READ|PROT_EXEC are both fine;
            // the two together are not, with or without extra bits.
            std::uint64_t rw[6] = {0, 0, 0x1 | 0x2, 0, 0, 0};
            CHECK_EQ(evaluate_with_args(*prog, 9, kAuditArchX86_64, rw), kRetAllow);
            std::uint64_t rx[6] = {0, 0, 0x1 | 0x4, 0, 0, 0};
            CHECK_EQ(evaluate_with_args(*prog, 9, kAuditArchX86_64, rx), kRetAllow);
            std::uint64_t rwx[6] = {0, 0, 0x1 | 0x2 | 0x4, 0, 0, 0};
            CHECK_EQ(evaluate_with_args(*prog, 9, kAuditArchX86_64, rwx), kRetErrno | 1);
            CHECK_EQ(evaluate_with_args(*prog, 10, kAuditArchX86_64, rwx), kRetErrno | 1);
        }
    }

    // -- 32-bit arguments, and the bypass that comes from ignoring width ----
    //
    // seccomp sees a full 64-bit register, but the kernel truncates it to the
    // declared parameter type before using it. ioctl's cmd is `unsigned int`, so
    // ioctl(fd, 0xdeadbeef00005412) really does run TIOCSTI -- while a filter
    // that also requires the high half to be zero sees a value matching nothing
    // and waves it through.
    //
    // this was a live bug in claybin's own TIOCSTI rule, confirmed against the
    // kernel before the fix: a both-halves rule denied 0x5413 and allowed
    // 0xdeadbeef00005413, which the kernel then executed as TIOCGWINSZ.
    {
        static constexpr std::uint64_t kHighGarbage = 0xdeadbeef00000000ull;

        // a 32-bit rule ignores the high half, so garbage above the line does not
        // help the attacker.
        SyscallPolicy narrow;
        narrow.set_default(SysAction::allow);
        narrow.allow(16);
        narrow.deny_arg32(16, 1, 0x5412 /* TIOCSTI */);

        auto np = compile(narrow, kAuditArchX86_64);
        CHECK(np.has_value());
        if (np) {
            std::uint64_t plain[6] = {0, 0x5412, 0, 0, 0, 0};
            CHECK_EQ(evaluate_with_args(*np, 16, kAuditArchX86_64, plain), kRetErrno | 1);
            std::uint64_t dressed[6] = {0, kHighGarbage | 0x5412, 0, 0, 0, 0};
            CHECK_EQ(evaluate_with_args(*np, 16, kAuditArchX86_64, dressed), kRetErrno | 1);
            // a different request is still allowed: the rule is about one value,
            // not about the low half generally.
            std::uint64_t other[6] = {0, 0x5413, 0, 0, 0, 0};
            CHECK_EQ(evaluate_with_args(*np, 16, kAuditArchX86_64, other), kRetAllow);
        }

        // the 64-bit form must keep checking the high half, because for a real
        // 64-bit argument ignoring it is the classic bypass in the other
        // direction. so the two widths genuinely differ, and the difference is
        // pinned here rather than left to whoever edits the emitter next.
        SyscallPolicy wide;
        wide.set_default(SysAction::allow);
        wide.allow(16);
        wide.deny_arg(16, 1, 0x5412);

        auto wp = compile(wide, kAuditArchX86_64);
        CHECK(wp.has_value());
        if (wp) {
            std::uint64_t plain[6] = {0, 0x5412, 0, 0, 0, 0};
            CHECK_EQ(evaluate_with_args(*wp, 16, kAuditArchX86_64, plain), kRetErrno | 1);
            std::uint64_t dressed[6] = {0, kHighGarbage | 0x5412, 0, 0, 0, 0};
            CHECK_EQ(evaluate_with_args(*wp, 16, kAuditArchX86_64, dressed), kRetAllow);
        }
    }

    // -- argument allow-lists ----------------------------------------------
    {
        static constexpr std::uint32_t kAllowed[] = {0x5401, 0x5413, 0x541B};

        SyscallPolicy p;
        p.set_default(SysAction::errno_, 1);
        for (SysNr nr = 0; nr < 64; ++nr) p.allow(nr);
        p.allow_arg32_only(16, 1, std::span<const std::uint32_t>{kAllowed});

        auto prog = compile(p, kAuditArchX86_64);
        CHECK(prog.has_value());
        if (prog) {
            for (std::uint32_t v : kAllowed) {
                std::uint64_t a[6] = {0, v, 0, 0, 0, 0};
                CHECK_EQ(evaluate_with_args(*prog, 16, kAuditArchX86_64, a), kRetAllow);
                // and the same value with high garbage: still allowed, because the
                // kernel would truncate it to exactly this request anyway. the
                // allow-list must not be MORE permissive for a dressed-up value
                // than for a plain one, nor less.
                std::uint64_t d[6] = {0, 0xdeadbeef00000000ull | v, 0, 0, 0, 0};
                CHECK_EQ(evaluate_with_args(*prog, 16, kAuditArchX86_64, d), kRetAllow);
            }

            // everything else is denied, including the escapes a deny-list would
            // have had to name: TIOCSTI, TIOCLINUX, TIOCCONS, TIOCSCTTY.
            for (std::uint32_t v : {0x5412u, 0x541Cu, 0x541Du, 0x540Eu, 0u, 0xffffffffu}) {
                std::uint64_t a[6] = {0, v, 0, 0, 0, 0};
                CHECK_EQ(evaluate_with_args(*prog, 16, kAuditArchX86_64, a), kRetErrno | 1);
            }

            // other syscalls are untouched: the block must restore the
            // accumulator, or the tree after it reads an argument as a syscall
            // number.
            for (SysNr nr = 0; nr < 64; ++nr) {
                if (nr == 16) continue;
                std::uint64_t a[6] = {0, 0x5412, 0, 0, 0, 0};
                CHECK_EQ(evaluate_with_args(*prog, nr, kAuditArchX86_64, a), kRetAllow);
            }
        }

        // a deny rule still wins over the allow-list, so a caller can allow a
        // broad set and carve one value back out.
        SyscallPolicy carved = p;
        carved.deny_arg32(16, 1, 0x5413, SysAction::errno_, 13 /* EACCES */);
        auto cp = compile(carved, kAuditArchX86_64);
        CHECK(cp.has_value());
        if (cp) {
            std::uint64_t a[6] = {0, 0x5413, 0, 0, 0, 0};
            CHECK_EQ(evaluate_with_args(*cp, 16, kAuditArchX86_64, a), kRetErrno | 13);
            std::uint64_t b[6] = {0, 0x5401, 0, 0, 0, 0};
            CHECK_EQ(evaluate_with_args(*cp, 16, kAuditArchX86_64, b), kRetAllow);
        }

        // allow-lists compose by INTERSECTION. two policies meeting can only ever
        // permit fewer values -- if it were union, composing two sealed policies
        // would GRANT authority, which is the one thing the lattice forbids.
        static constexpr std::uint32_t kOther[] = {0x5413, 0x541B, 0x5414};
        SyscallPolicy q;
        q.set_default(SysAction::errno_, 1);
        for (SysNr nr = 0; nr < 64; ++nr) q.allow(nr);
        q.allow_arg32_only(16, 1, std::span<const std::uint32_t>{kOther});

        auto mp = compile(p.meet(q), kAuditArchX86_64);
        CHECK(mp.has_value());
        if (mp) {
            // in both lists -> allowed
            for (std::uint32_t v : {0x5413u, 0x541Bu}) {
                std::uint64_t a[6] = {0, v, 0, 0, 0, 0};
                CHECK_EQ(evaluate_with_args(*mp, 16, kAuditArchX86_64, a), kRetAllow);
            }
            // in only one -> denied
            for (std::uint32_t v : {0x5401u, 0x5414u}) {
                std::uint64_t a[6] = {0, v, 0, 0, 0, 0};
                CHECK_EQ(evaluate_with_args(*mp, 16, kAuditArchX86_64, a), kRetErrno | 1);
            }
        }

        // disjoint allow-lists intersect to nothing, which denies the syscall
        // outright. it has to be EMITTED rather than skipped as empty, or the
        // composition would silently hand the syscall back.
        static constexpr std::uint32_t kDisjoint[] = {0x9999};
        SyscallPolicy z;
        z.set_default(SysAction::errno_, 1);
        for (SysNr nr = 0; nr < 64; ++nr) z.allow(nr);
        z.allow_arg32_only(16, 1, std::span<const std::uint32_t>{kDisjoint});

        auto zp = compile(p.meet(z), kAuditArchX86_64);
        CHECK(zp.has_value());
        if (zp) {
            for (std::uint32_t v : {0x5401u, 0x5413u, 0x9999u}) {
                std::uint64_t a[6] = {0, v, 0, 0, 0, 0};
                CHECK_EQ(evaluate_with_args(*zp, 16, kAuditArchX86_64, a), kRetErrno | 1);
            }
        }
    }

    // the profile's ioctl allow-list: isatty works, the tty escapes do not.
    {
        auto prog = compile(profiles::base(), kAuditArchX86_64);
        CHECK(prog.has_value());
        if (prog) {
            // TCGETS is what isatty() actually calls. if this breaks, every
            // program that checks for a terminal breaks with it.
            std::uint64_t tcgets[6] = {1, 0x5401, 0, 0, 0, 0};
            CHECK_EQ(evaluate_with_args(*prog, 16, kAuditArchX86_64, tcgets), kRetAllow);
            std::uint64_t winsz[6] = {1, 0x5413, 0, 0, 0, 0};
            CHECK_EQ(evaluate_with_args(*prog, 16, kAuditArchX86_64, winsz), kRetAllow);

            // the keystroke-injection family, plain and dressed in high garbage.
            for (std::uint32_t v : {0x5412u /* TIOCSTI */, 0x541Cu /* TIOCLINUX */,
                                    0x541Du /* TIOCCONS */, 0x540Eu /* TIOCSCTTY */}) {
                std::uint64_t a[6] = {1, v, 0, 0, 0, 0};
                CHECK_EQ(evaluate_with_args(*prog, 16, kAuditArchX86_64, a), kRetErrno | 1);
                std::uint64_t d[6] = {1, 0xdeadbeef00000000ull | v, 0, 0, 0, 0};
                CHECK_EQ(evaluate_with_args(*prog, 16, kAuditArchX86_64, d), kRetErrno | 1);
            }
        }
    }

    return finish("bpf_emit_test");
}
