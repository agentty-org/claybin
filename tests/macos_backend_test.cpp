// the macOS backend's translation, tested on whatever host happens to be
// running. the point of keeping compile() pure is exactly this: translation
// bugs are found here rather than on a mac.
//
// what these tests really check is that the backend is HONEST. it is easy to
// write a macOS backend that accepts every policy and reports `strong`; the
// value is in the places it says `partial`, `advisory`, or refuses outright.

#include "harness.hpp"

#include "claybin/macos/backend.hpp"
#include "claybin/policy/shapes.hpp"

#include <string>
#include <string_view>

using namespace clay;
using namespace clay::test;
using namespace clay::literals;

namespace {

bool contains(std::string_view hay, std::string_view needle) {
    return hay.find(needle) != std::string_view::npos;
}

// does `before` appear earlier than `after`? SBPL is last-match-wins, so rule
// ORDER is semantics, not formatting -- this is a correctness check.
bool precedes(std::string_view hay, std::string_view before, std::string_view after) {
    const auto b = hay.find(before);
    const auto a = hay.find(after);
    return b != std::string_view::npos && a != std::string_view::npos && b < a;
}

}  // namespace

int main() {
    const auto mac = macos::HostCapabilities::modern_macos();

    // -- the headline honesty: NO SYSCALL FILTER ---------------------------
    // macOS has no seccomp equivalent available to an unprivileged process. a
    // backend that claimed `strong` here would be lying, and that lie is the
    // whole reason `Enforcement` is not a bool.
    {
        auto pol = shapes::system_ro().syscall_profile(profiles::base()).seal();
        auto c = macos::compile(pol, mac);
        CHECK(c.has_value());
        if (c) {
            CHECK(c->guarantees.strength(CapId::syscall_filter) == Enforcement::partial);
            // and it must NEVER be strong, whatever the policy asks for
            CHECK(c->guarantees.strength(CapId::syscall_filter) < Enforcement::strong);
        }
    }

    // a policy with NO syscall profile gets `none`, not a flattering `partial`.
    {
        auto pol = shapes::system_ro().seal();
        auto c = macos::compile(pol, mac);
        CHECK(c.has_value());
        if (c) CHECK(c->guarantees.strength(CapId::syscall_filter) == Enforcement::none);
    }

    // -- hardened_process must be REFUSED, not downgraded ------------------
    // hardened means every wall, and a syscall filter is one of them. silently
    // giving the caller less than they demanded is the single worst thing a
    // sandbox library can do.
    {
        auto pol = shapes::system_ro()
                       .syscall_profile(profiles::base())
                       .isolation(Isolation::hardened_process)
                       .seal();
        auto c = macos::compile(pol, mac);
        CHECK(!c.has_value());
        if (!c) CHECK(c.error().code == Errc::unsupported);
    }

    // -- microvm must be refused too ---------------------------------------
    // Hypervisor.framework exists, but a vm is a different product, not a
    // stronger flag on this one.
    {
        auto pol = shapes::system_ro().isolation(Isolation::microvm).seal();
        auto c = macos::compile(pol, mac);
        CHECK(!c.has_value());
    }

    // -- no seatbelt means no sandbox, and we say so -----------------------
    // rlimits alone are not a boundary. returning a `Compiled` here would hand
    // the caller a sandbox object for a host with no sandbox in it.
    {
        auto pol = shapes::system_ro().seal();
        auto c = macos::compile(pol, macos::HostCapabilities::none());
        CHECK(!c.has_value());
        if (!c) CHECK(c.error().code == Errc::unsupported);
    }

    // -- deny-default is the first thing in the profile ---------------------
    // SBPL is last-match-wins, so `(deny default)` has to come before every
    // allow. if it came last it would deny everything, including the grants.
    {
        auto pol = shapes::system_ro().seal();
        auto c = macos::compile(pol, mac);
        CHECK(c.has_value());
        if (c) {
            CHECK(contains(c->profile, "(version 1)"));
            CHECK(contains(c->profile, "(deny default)"));
            CHECK(precedes(c->profile, "(deny default)", "(allow file-read*"));
            CHECK(c->use_seatbelt);
        }
    }

    // -- a path remap must be REFUSED --------------------------------------
    // seatbelt is access control; it cannot make /opt/app appear at /app. this
    // is the Fidelity::impossible case, and running it would give the guest a
    // tree the report claimed it could not see.
    {
        auto pol = shapes::app_container("/opt/app", "/var/data").seal();
        auto c = macos::compile(pol, mac);
        CHECK(!c.has_value());
        if (!c) CHECK(c.error().code == Errc::unsupported);
    }

    // -- SBPL injection via a hostile path ---------------------------------
    // a workspace directory can contain `"` on APFS. interpolated raw it
    // closes the string and the rest is reparsed AS SBPL. the escape must make
    // it inert, and a control character -- which SBPL cannot represent at all
    // -- must DROP the rule rather than emit something malformed.
    {
        auto pol = Policy<Draft>{}
                       .ro_bind("/usr", "/usr")
                       .bind("/tmp/eva\"))(allow default)(deny file-read* (subpath \"/x",
                            "/tmp/eva\"))(allow default)(deny file-read* (subpath \"/x")
                       .seal();
        auto c = macos::compile(pol, mac);
        CHECK(c.has_value());
        if (c) {
            // the quote is escaped, so the injected text is inside the string
            CHECK(contains(c->profile, "\\\""));
            // and no bare `(allow default)` ever appears
            CHECK(!contains(c->profile, "\n(allow default)"));
        }
    }
    {
        // a newline cannot live in an SBPL string: fail closed, drop the rule.
        auto pol = Policy<Draft>{}.bind("/tmp/a\nb", "/tmp/a\nb").seal();
        auto c = macos::compile(pol, mac);
        CHECK(c.has_value());
        if (c) CHECK(!contains(c->profile, "a\nb"));
    }

    // -- the coarse file-write* fold must be CONSERVATIVE -------------------
    // seatbelt's file-write* covers create, unlink, rename and truncate as one
    // operation. a policy that asked only for "create files here" must NOT get
    // file-write*, because that would hand out unlink it never authorized.
    {
        // no mounts here on purpose: with a bind present the authority is
        // INTERSECTED with what the mounts imply, and /w is under none of
        // them -- so the grant would correctly vanish and this test would be
        // measuring the fold instead of the write translation.
        auto pol = Policy<Draft>{}.grant("/w", FileRights{FileRights::kCreateFile}).seal();
        auto c = macos::compile(pol, mac);
        CHECK(c.has_value());
        if (c) {
            CHECK(!contains(c->profile, "(allow file-write* (subpath \"/w\"))"));
            // and the caller is told the write grant was weakened
            CHECK(c->guarantees.strength(CapId::fs_write) == Enforcement::partial);
        }
    }
    {
        // a FULL write grant does get file-write*.
        auto pol = Policy<Draft>{}.grant("/w", FileRights::write()).seal();
        auto c = macos::compile(pol, mac);
        CHECK(c.has_value());
        if (c) CHECK(contains(c->profile, "(allow file-write* (subpath \"/w\"))"));
    }

    // -- network: denial is strong, an allow-list is not -------------------
    // this asymmetry is real. a total `(deny network*)` is one rule the kernel
    // enforces exactly; an endpoint allow-list is a filter over a namespace
    // with dns in it, resolved by us rather than by the kernel.
    {
        auto pol = shapes::system_ro().seal();  // no network granted
        auto c = macos::compile(pol, mac);
        CHECK(c.has_value());
        if (c) {
            CHECK(contains(c->profile, "(deny network*)"));
            CHECK(c->guarantees.strength(CapId::net_isolation) == Enforcement::strong);
            CHECK(!c->allow_network);
        }
    }
    {
        // `connect()` on the wildcard host is how a policy says "any endpoint";
        // there is no allow-everything shortcut, by design.
        auto pol = shapes::system_ro().connect("*", 0).seal();
        auto c = macos::compile(pol, mac);
        CHECK(c.has_value());
        if (c) {
            CHECK(c->allow_network);
            // we built no wall here, so we claim no credit for one.
            CHECK(c->guarantees.strength(CapId::net_isolation) != Enforcement::strong);
        }
    }

    // -- a unix socket is NOT "the network" --------------------------------
    // `unix_sockets()` sets a blanket NetOps bit. a backend that read any
    // blanket bit as "allow all IP" would turn a request for a local socket
    // into full internet access -- the most dangerous mistranslation here.
    {
        auto pol = shapes::system_ro().unix_sockets().seal();
        auto c = macos::compile(pol, mac);
        CHECK(c.has_value());
        if (c) {
            CHECK(!contains(c->profile, "(allow network*)"));
            CHECK(contains(c->profile, "(deny network*)"));
            CHECK(c->guarantees.strength(CapId::net_isolation) == Enforcement::strong);
        }
    }

    // -- network addresses are "host:port", and both halves wildcard --------
    // the policy layer spells "any host" as an EMPTY host and "any port" as
    // port 0. emitted verbatim that produced `(remote ip "")`, which the
    // kernel rejects outright -- and because spawn() fails closed on a bad
    // profile, a malformed rule here does not weaken the sandbox, it kills
    // every command that runs in it.
    {
        auto pol = shapes::system_ro().connect("", 443).connect("", 80).seal();
        auto c = macos::compile(pol, mac);
        CHECK(c.has_value());
        if (c) {
            CHECK(contains(c->profile, "\"*:443\""));
            CHECK(contains(c->profile, "\"*:80\""));
            // the shape the kernel refuses must never appear
            CHECK(!contains(c->profile, "(remote ip \"\")"));
        }
    }

    // -- a hostname rule is DROPPED, not widened ---------------------------
    // seatbelt accepts only `*` or `localhost` as the host and rejects the
    // whole profile for anything else. silently rewriting example.com to `*`
    // would hand the guest the entire internet while the report claimed one
    // host; dropping the rule leaves `(deny network*)` standing, which errs
    // toward too little access rather than too much.
    {
        auto pol = shapes::system_ro().connect("example.com", 443).seal();
        auto c = macos::compile(pol, mac);
        CHECK(c.has_value());
        if (c) {
            CHECK(!contains(c->profile, "example.com"));
            CHECK(!contains(c->profile, "\"*:443\""));  // NOT widened
            CHECK(contains(c->profile, "(deny network*)"));
        }
    }

    // -- an UNSET ProcOps is not a denial ----------------------------------
    // on linux ProcOps is advisory -- plan/compile.cpp never reads it, and
    // fork/exec come from the syscall profile instead. so a working linux
    // policy carries an EMPTY ProcOps, and reading that as "deny fork" made
    // `/bin/sh -c 'a && b'` die on its first subshell with "fork: Operation
    // not permitted": the same policy, silently stricter on one platform.
    {
        auto pol = shapes::system_ro().seal();  // never touches ProcOps
        auto c = macos::compile(pol, mac);
        CHECK(c.has_value());
        if (c) {
            CHECK(!c->deny_fork);
            CHECK(!c->deny_exec);
            CHECK(!contains(c->profile, "(deny process-fork)"));
        }
    }
    {
        // but a policy that states an intent gets it honoured: exec allowed,
        // fork withheld because it was not among the ops asked for.
        auto pol = shapes::system_ro().allow_exec().seal();
        auto c = macos::compile(pol, mac);
        CHECK(c.has_value());
        if (c) {
            CHECK(c->deny_fork);
            CHECK(!c->deny_exec);
        }
    }

    // -- /tmp, /etc and /var are symlinks into /private --------------------
    // seatbelt matches the RESOLVED path, so a grant on /tmp matches nothing:
    // the kernel sees /private/tmp. The failure mode is the nastiest kind --
    // the profile is valid, loads cleanly, reports fs_write strong, and then
    // `touch /tmp/x` returns EPERM -- so both spellings are emitted.
    {
        auto pol = Policy<Draft>{}.read_write("/tmp").seal();
        auto c = macos::compile(pol, mac);
        CHECK(c.has_value());
        if (c) {
            CHECK(contains(c->profile, "(allow file-write* (subpath \"/tmp\"))"));
            CHECK(contains(c->profile, "(allow file-write* (subpath \"/private/tmp\"))"));
        }
    }
    {
        // a path INSIDE one of them resolves too
        auto pol = Policy<Draft>{}.read_write("/var/folders/x").seal();
        auto c = macos::compile(pol, mac);
        CHECK(c.has_value());
        if (c) CHECK(contains(c->profile, "\"/private/var/folders/x\""));
    }
    {
        // but a path that merely SHARES A PREFIX must not be rewritten --
        // /tmpfoo is not inside /tmp, and silently moving it under /private
        // would grant a directory the policy never named.
        auto pol = Policy<Draft>{}.read_write("/tmpfoo").seal();
        auto c = macos::compile(pol, mac);
        CHECK(c.has_value());
        if (c) CHECK(!contains(c->profile, "/private/tmpfoo"));
    }

    // -- resources: rlimits are NOT cgroups --------------------------------
    // an rlimit is per-process; a cgroup counts a tree. four children under a
    // 1 GB RLIMIT_AS can use 4 GB between them, so `strong` would overstate it.
    {
        auto pol = shapes::system_ro().memory(1_GB).processes(64).seal();
        auto c = macos::compile(pol, mac);
        CHECK(c.has_value());
        if (c) {
            CHECK(c->guarantees.strength(CapId::mem_limit) == Enforcement::partial);
            // RLIMIT_NPROC counts the whole UID, not this tree: another
            // terminal window moves the limit. that is advisory, not a wall.
            CHECK(c->guarantees.strength(CapId::pid_limit) == Enforcement::advisory);
            CHECK(c->guarantees.strength(CapId::mem_limit) < Enforcement::strong);
        }
    }

    // -- RLIMIT_CPU rounds UP, never down ----------------------------------
    // the policy is in nanoseconds, RLIMIT_CPU is in seconds. truncating a
    // 500ms budget to 0 would SIGKILL the guest on its first tick -- a limit
    // silently turned into an execution ban.
    {
        auto pol = shapes::system_ro().cpu_time(Nanos{500'000'000}).seal();
        auto c = macos::compile(pol, mac);
        CHECK(c.has_value());
        if (c) {
            bool found = false;
            for (const auto& rl : c->rlimits) {
                if (rl.resource == 0 /* RLIMIT_CPU */) {
                    CHECK_EQ(rl.value, 1u);
                    found = true;
                }
            }
            CHECK(found);
        }
    }

    // -- host kernel isolation is never claimed ----------------------------
    // the guest runs on the same kernel. only a vm changes that.
    {
        auto pol = shapes::system_ro().seal();
        auto c = macos::compile(pol, mac);
        CHECK(c.has_value());
        if (c)
            CHECK(c->guarantees.strength(CapId::host_kernel_isolation) == Enforcement::none);
    }

    // -- determinism: same policy in, byte-identical profile out -----------
    // a wobbling profile is one nobody can diff in a review or a bug report.
    {
        auto c1 = macos::compile(shapes::system_ro().memory(1_GB).seal(), mac);
        auto c2 = macos::compile(shapes::system_ro().memory(1_GB).seal(), mac);
        CHECK(c1.has_value() && c2.has_value());
        if (c1 && c2) {
            CHECK(c1->profile == c2->profile);
            CHECK(c1->degraded == c2->degraded);
        }
    }

    // -- signals are scoped to the sandbox, not to the single process -------
    // `self` alone breaks every guest that kills its own child (timeout, make
    // -j cancelling, a shell's `kill %1`); an unscoped allow would let the
    // guest signal the supervisor. same-sandbox is the one correct scope.
    {
        auto c = macos::compile(shapes::system_ro().seal(), mac);
        CHECK(c.has_value());
        if (c) {
            CHECK(contains(c->profile, "(allow signal (target same-sandbox))"));
            CHECK(!contains(c->profile, "(allow signal)"));
            CHECK(!contains(c->profile, "(target others)"));
        }
    }

    // -- mach-lookup is an allowlist, never a blanket ---------------------
    // a bare (allow mach-lookup) hands the guest every launchd service:
    // pasteboard, keychain, launchd itself. DNS services ride along only
    // when the policy grants the network.
    {
        auto c = macos::compile(shapes::system_ro().seal(), mac);
        CHECK(c.has_value());
        if (c) {
            CHECK(!contains(c->profile, "(allow mach-lookup)"));
            CHECK(contains(c->profile, "com.apple.system.opendirectoryd.libinfo"));
            CHECK(!contains(c->profile, "com.apple.pasteboard"));
            CHECK(!contains(c->profile, "mDNSResponder"));
            CHECK(contains(c->profile, "(allow pseudo-tty)"));
            CHECK(contains(c->profile, "(allow process-info* (target same-sandbox))"));
        }
        auto n = macos::compile(shapes::system_ro().connect("*", 0).seal(), mac);
        CHECK(n.has_value());
        if (n) {
            CHECK(contains(n->profile, "com.apple.mDNSResponder"));
            // the keychain daemon: TLS does not need it, so nothing gets it.
            CHECK(!contains(n->profile, "com.apple.SecurityServer"));
        }
    }

    // -- proxied: one loopback port, nothing else, and no DNS --------------
    // the embedder's "full network" on darwin. connect("", 0) is ALSO set
    // (that is how the policy says what the proxy may reach), and reading
    // that blanket first would compile to (allow network*).
    {
        auto c = macos::compile(
            shapes::system_ro().connect("", 0).proxied_netns(49152).seal(), mac);
        CHECK(c.has_value());
        if (c) {
            CHECK(contains(c->profile, "(allow network-outbound (remote ip \"localhost:49152\"))"));
            CHECK(contains(c->profile, "(deny network*)"));
            CHECK(!contains(c->profile, "(allow network*)"));
            CHECK(!contains(c->profile, "mDNSResponder"));
            CHECK(!c->allow_network);
        }
    }

    // -- prerequisites can be turned off -----------------------------------
    // an implicit grant nobody can disable is one nobody audits.
    {
        macos::Options opts;
        opts.allow_process_prerequisites = false;
        auto c = macos::compile(shapes::system_ro().seal(), mac, opts);
        CHECK(c.has_value());
        if (c) CHECK(!contains(c->profile, "(allow mach-lookup)"));
        if (c) CHECK(!contains(c->profile, "(allow signal"));
    }

    return finish("macos_backend_test");
}
