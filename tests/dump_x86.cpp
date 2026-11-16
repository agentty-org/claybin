// dump what the x86_64 and i386 profiles do with every syscall number, for
// tests/x86_audit.sh to resolve through the kernel's own headers.
//
// separate from syscall_table_test for the same reason as dump_aarch64: the
// C++ test checks the names its author listed, and shares any misreading with
// the tables. the script reads <asm/unistd_64.h> and <asm/unistd_32.h> itself,
// so every number is checked, listed or not, and the two ABIs are compared by
// NAME -- which is how a call allowed on one and forgotten on the other shows.
//
// one row per (abi, profile, nr) that is not the profile's EPERM default:
//   <abi> <profile> <ALLOW|ARGS|NOTIFY|KILL|ERRNO=n> <nr>
#include <cstdio>

#include "claybin/policy/profiles.hpp"
#include "claybin/policy/profiles_i386.hpp"

using namespace clay;

namespace {

bool has_arg_rule(const SyscallPolicy& p, SysNr nr) {
    for (const auto& r : p.arg_rules()) if (r.nr == nr) return true;
    for (const auto& r : p.arg_allow_sets()) if (r.nr == nr) return true;
    return false;
}

void dump(const char* abi, const char* name, const SyscallPolicy& p) {
    for (SysNr nr = 0; nr < 512; ++nr) {
        const SysAction a = p.action_for(nr);
        const bool args = has_arg_rule(p, nr);
        switch (a) {
            case SysAction::allow:
                std::printf("%s %s %s %u\n", abi, name, args ? "ARGS" : "ALLOW", nr);
                break;
            case SysAction::notify:
                std::printf("%s %s NOTIFY %u\n", abi, name, nr);
                break;
            case SysAction::kill_process:
                std::printf("%s %s KILL %u\n", abi, name, nr);
                break;
            default: {
                const auto e = p.errno_for(nr);
                // the profiles' default is EPERM; only a deliberate other
                // errno (ENOSYS so glibc falls back, ENOTSUP for xattrs) is
                // worth a row.
                if (e != 1 || args) std::printf("%s %s ERRNO=%u %u\n", abi, name, e, nr);
            }
        }
    }
}

}  // namespace

int main() {
    dump("x86_64", "base", profiles::base());
    dump("x86_64", "compiler", profiles::compiler());
    dump("x86_64", "compiler_with_network", profiles::compiler_with_network());
    dump("i386", "base", profiles_i386::base());
    dump("i386", "compiler", profiles_i386::compiler());
    dump("i386", "compiler_with_network", profiles_i386::compiler_with_network());
}
