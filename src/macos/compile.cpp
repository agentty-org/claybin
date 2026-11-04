// the macOS backend's compile step. pure, so it builds and tests on any host
// -- which is deliberate: the interesting content here is the TRANSLATION, and
// a translation bug is far easier to find in a unit test than on a mac.
//
// the output is an SBPL profile. SBPL is a scheme-ish DSL evaluated by the
// kernel's TrustedBSD module; its rules are evaluated IN ORDER with last-match
// winning, which is the opposite of landlock (where a ruleset only ever
// subtracts). that difference is the main source of bugs here and the reason
// emission order below is fixed rather than incidental:
//
//   1. (version 1)
//   2. (deny default)              -- everything is denied unless named
//   3. prerequisites               -- dyld cache, /dev/null, bootstrap port
//   4. filesystem grants           -- shallow to deep
//   5. filesystem DENIALS          -- after grants, so a deny inside a granted
//                                     subtree actually wins
//   6. network
//   7. process ops
//
// get 4 and 5 backwards and a `(deny file-write* (subpath "/etc"))` under an
// `(allow file-write* (subpath "/"))` silently does nothing.
#include "claybin/macos/backend.hpp"

#include <algorithm>

#include "claybin/policy/mounts.hpp"

namespace clay::macos {
namespace {

// -- SBPL string escaping ---------------------------------------------------
//
// a grant path comes from the caller and can contain anything APFS allows,
// which includes `"` and `\`. interpolated raw, such a path terminates the
// string literal early and the remainder is reparsed AS SBPL -- profile
// rejection at best, an injected `(allow default)` at worst. this is the same
// hazard agentty's sbpl_escape() exists for, and it belongs here, below the
// caller, so every user of the backend gets it.
//
// a control character cannot be represented in an SBPL string at all, so a
// path containing one yields `false` and the caller DROPS the rule rather than
// emitting something malformed: fail closed, never open.
bool sbpl_quote(std::string_view in, std::string& out) {
    out.clear();
    out.reserve(in.size() + 2);
    out.push_back('"');
    for (const char c : in) {
        const auto u = static_cast<unsigned char>(c);
        if (u < 0x20 || u == 0x7f) return false;  // unrepresentable -> drop
        if (c == '"' || c == '\\') out.push_back('\\');
        out.push_back(c);
    }
    out.push_back('"');
    return true;
}

// -- rights -> seatbelt operations ------------------------------------------
//
// this is where the two models grind against each other. landlock has thirteen
// separate bits; seatbelt has a coarse `file-write*` that covers create,
// unlink, rename, truncate, chmod and more as ONE operation. there is no way
// to say "may create files here but not delete them".
//
// the rule that keeps this sound: a coarse operation is only emitted when the
// policy granted EVERY fine-grained right it implies. granting file-write* for
// a policy that only asked for kCreateFile would hand out unlink, which the
// policy never authorized. so the fold is conservative in the one direction
// that matters, and the cost is that a partial write grant degrades to
// read-only plus the report saying so.
struct FileOps {
    bool read{false};
    bool write{false};  // the coarse file-write*
    bool exec{false};
    // the policy wanted write but not all of it; we emitted read-only and the
    // report must be downgraded.
    bool write_truncated{false};
};

constexpr std::uint32_t kWriteFamily =
    FileRights::kWriteFile | FileRights::kCreateFile | FileRights::kCreateDir |
    FileRights::kRemoveFile | FileRights::kRemoveDir | FileRights::kRename |
    FileRights::kTruncate;

FileOps to_file_ops(FileRights r) {
    FileOps o;
    o.read = r.any(FileRights{FileRights::kReadFile | FileRights::kReadDir});
    o.exec = r.any(FileRights{FileRights::kExecute});

    const bool wants_write = r.any(FileRights{kWriteFamily});
    const bool has_all_write = r.subsumes(FileRights{kWriteFamily});
    if (wants_write && has_all_write) {
        o.write = true;
        // file-write* implies being able to read what you wrote on macOS in
        // practice, but SBPL does not imply it, so read stays explicit.
    } else if (wants_write) {
        o.write_truncated = true;
    }
    return o;
}

// -- darwin's three root symlinks -------------------------------------------
//
// /etc, /tmp and /var are symlinks into /private on every mac. seatbelt
// evaluates a rule against the RESOLVED path, so `(subpath "/tmp")` matches
// nothing at all -- the kernel sees /private/tmp and finds no rule for it.
//
// The failure is quiet and misleading in the worst way: the profile is valid,
// loads cleanly, reports `fs_write: strong`, and then `touch /tmp/x` fails
// with EPERM. A caller reads that as "the sandbox is broken" rather than "the
// grant never applied", because every other grant in the same profile works.
//
// Emitting BOTH spellings is deliberate rather than emitting only the
// resolved one: the resolved path is what the kernel matches, and the
// original is kept so a human reading the profile sees the path they asked
// for. Neither grants anything the other does not -- they are the same
// directory under two names.
//
// This is a fixed list, not a readlink() call, because compile() is PURE: it
// must produce the same profile on a CI runner as on the target mac, and
// touching the filesystem here would make the output depend on the host.
// These three have been symlinks since OS X 10.0 and are part of the
// platform's layout rather than a local configuration.
std::string darwin_firmlink(std::string_view path) {
    struct Pair {
        std::string_view from;
        std::string_view to;
    };
    static constexpr Pair kPairs[] = {
        {"/etc", "/private/etc"},
        {"/tmp", "/private/tmp"},
        {"/var", "/private/var"},
    };
    for (const auto& p : kPairs) {
        if (path == p.from) return std::string{p.to};
        // a path INSIDE one of them, e.g. /tmp/build -> /private/tmp/build.
        // the length check keeps /tmpfoo from matching /tmp.
        if (path.size() > p.from.size() && path.starts_with(p.from) &&
            path[p.from.size()] == '/') {
            std::string out{p.to};
            out.append(path.substr(p.from.size()));
            return out;
        }
    }
    return {};
}

void emit_rule(std::string& p, const char* verb, const char* op, std::string_view path) {
    std::string quoted;
    if (!sbpl_quote(path, quoted)) return;  // fail closed
    p += "(";
    p += verb;
    p += " ";
    p += op;
    p += " (subpath ";
    p += quoted;
    p += "))\n";

    // and again under the resolved name, when there is one.
    const std::string resolved = darwin_firmlink(path);
    if (!resolved.empty()) emit_rule(p, verb, op, resolved);
}

// stat(2) on every ANCESTOR of `path`, and nothing else.
//
// the reason this exists: a blanket (allow file-read-metadata) is a disk-wide
// oracle. measured with it on, a guest with no home grant could stat(2) any
// path -- "does ~/.ssh/id_ed25519 exist", its size and mtime, the shape of
// every project on the machine. listing (readdir) stayed walled, and so did
// content; existence and metadata did not.
//
// what a grant actually needs is traversal of the path DOWN to it: realpath,
// getcwd, git's repo discovery and node's module resolution all lstat each
// component. so: (literal) on each ancestor, which stats that directory
// entry and lists nothing beneath it.
void emit_ancestor_metadata(std::string& p, std::string_view path) {
    for (int pass = 0; pass < 2; ++pass) {
        const std::string full = pass == 0 ? std::string{path} : darwin_firmlink(path);
        if (full.empty()) continue;
        for (std::size_t i = 1; i < full.size(); ++i) {
            if (full[i] != '/') continue;
            std::string quoted;
            if (!sbpl_quote(std::string_view{full}.substr(0, i), quoted)) return;
            p += "(allow file-read-metadata (literal ";
            p += quoted;
            p += "))\n";
        }
    }
}

// with no blanket mach-lookup, name resolution and TLS trust are mach
// services, not sockets: getaddrinfo asks mDNSResponder, Security.framework
// asks trustd. a guest granted the network but not these gets "could not
// resolve host". emitted ONLY on a network-allowing profile, never in the
// prerequisites, so a no-network guest has no DNS side channel.
// com.apple.SecurityServer (securityd) is deliberately ABSENT: it is the
// keychain daemon, and TLS verifies fine through trustd alone -- measured
// with curl, git, python urllib and node fetch.
void emit_resolver_grants(std::string& p) {
    p += "(allow mach-lookup\n"
         "  (global-name \"com.apple.dnssd.service\")\n"
         "  (global-name \"com.apple.mDNSResponder\")\n"
         "  (global-name \"com.apple.SystemConfiguration.DNSConfiguration\")\n"
         "  (global-name \"com.apple.SystemConfiguration.configd\")\n"
         "  (global-name \"com.apple.networkd\")\n"
         "  (global-name \"com.apple.trustd\")\n"
         "  (global-name \"com.apple.trustd.agent\")\n"
         "  (global-name \"com.apple.ocspd\"))\n";
    p += "(allow file-read* (literal \"/private/var/run/mDNSResponder\"))\n";
    p += "(allow network-outbound (literal \"/private/var/run/mDNSResponder\"))\n";
}

// the grants a dynamically linked darwin binary needs before main(). without
// these the guest dies in dyld with no useful message, and the user concludes
// the sandbox is broken rather than that it is working.
void emit_prerequisites(std::string& p) {
    p += "; prerequisites: without these a dynamically linked binary dies in\n"
         "; dyld before main(), which looks like a broken sandbox rather than\n"
         "; a working one.\n";
    // THE ROOT DIRECTORY ENTRY. this one is not obvious and costs an afternoon
    // to rediscover: dyld stats "/" during startup, and without it the process
    // takes SIGABRT before main() with an error naming a line in the KERNEL's
    // own SBPL prelude -- which points at the profile's syntax and not at the
    // missing grant, so it reads as "claybin emitted bad SBPL" rather than
    // "the guest could not see /".
    //
    // it is `literal`, NOT `subpath`: (subpath "/") would grant read on the
    // ENTIRE filesystem and quietly turn every profile into an open door.
    // the literal grants the directory entry itself and nothing beneath it.
    p += "(allow file-read* (literal \"/\"))\n";
    // the shared cache is one giant mapped file; every linked binary needs it.
    p += "(allow file-read* (subpath \"/usr/lib\"))\n";
    p += "(allow file-read* (subpath \"/System/Library\"))\n";
    // NOT a blanket (allow file-read-metadata): see emit_ancestor_metadata.
    // the root's own children are stat-able so `ls -l /` and path walks work;
    // granted subtrees get metadata through their file-read* grant, and the
    // path down to each one through its ancestors.
    p += "(allow file-read-metadata (regex #\"^/[^/]+$\"))\n";
    // dyld stats these on every exec, before any grant applies.
    p += "(allow file-read-metadata (subpath \"/private/var/db/dyld\")"
         " (subpath \"/System/Volumes/Preboot/Cryptexes\"))\n";
    // mapping a dylib out of the shared cache is its own operation on modern
    // macOS, separate from being allowed to read the file.
    p += "(allow file-map-executable)\n";
    // sysctl reads: libSystem queries hw.ncpu / kern.osversion during startup.
    p += "(allow sysctl-read)\n";
    // MACH SERVICES, BY NAME. a bare `(allow mach-lookup)` is the single
    // widest hole a seatbelt profile can have: every launchd service is a
    // confused deputy running OUTSIDE the sandbox. measured with it on, under
    // `(deny network*)` and no home grant, a guest could read the pasteboard
    // (pbpaste), enumerate keychains (security), and query launchd -- none of
    // which touch a file or a socket the profile mediates. so: the allowlist
    // Chrome's renderer and Codex converged on, and nothing else.
    //   opendirectoryd.libinfo   getpwuid/getgrgid -- `id`, `ls -l`, git
    //   logd / diagnosticd       os_log from libSystem; harmless sinks
    //   PowerManagement.control  caffeinate-style assertions; node/pytorch
    //   cfprefsd.daemon/agent    read-only CFPreferences for CF tools
    //   bsd.dirhelper            confstr(DARWIN_USER_TEMP_DIR) -- without
    //                            it xcrun, python and git fail at startup
    //   opendirectoryd.membership getgroups/ACL checks
    //   notification_center      notify(3): timezone/locale change pings
    p += "(allow mach-lookup\n"
         "  (global-name \"com.apple.system.opendirectoryd.libinfo\")\n"
         "  (global-name \"com.apple.system.opendirectoryd.membership\")\n"
         "  (global-name \"com.apple.system.notification_center\")\n"
         "  (global-name \"com.apple.bsd.dirhelper\")\n"
         "  (global-name \"com.apple.system.logger\")\n"
         "  (global-name \"com.apple.logd\")\n"
         "  (global-name \"com.apple.diagnosticd\")\n"
         "  (global-name \"com.apple.PowerManagement.control\")\n"
         "  (global-name \"com.apple.cfprefsd.daemon\")\n"
         "  (global-name \"com.apple.cfprefsd.agent\"))\n";
    p += "(allow file-read* file-write* (literal \"/dev/null\"))\n";
    // openpty(): `script`, expect, python's pty, any test harness spawning a
    // shell. ttys the guest opens itself carry the pty extension; one handed
    // in before sandbox_init does not, so ioctl (isatty/tcgetattr) is granted
    // separately -- without it an interactive shell decides it has no tty.
    p += "(allow pseudo-tty)\n";
    p += "(allow file-read* file-write* file-ioctl (literal \"/dev/ptmx\"))\n";
    p += "(allow file-read* file-write* (require-all (regex #\"^/dev/ttys[0-9]+$\")"
         " (extension \"com.apple.sandbox.pty\")))\n";
    p += "(allow file-ioctl (regex #\"^/dev/ttys[0-9]+$\"))\n";
    // POSIX semaphores: python multiprocessing's SemLock, and every
    // ProcessPoolExecutor. named, in a namespace no host secret lives in.
    p += "(allow ipc-posix-sem)\n";
    // ps/pgrep/proc_pidinfo on its OWN tree only -- not the host's.
    p += "(allow process-info* (target same-sandbox))\n";
    p += "(allow file-read* (literal \"/dev/random\") (literal \"/dev/urandom\"))\n";
    // a process that cannot signal itself cannot abort() or run a timer, and
    // one that cannot signal its own children cannot run `timeout`, a build
    // that cancels jobs, or a shell that reaps a `&` job with kill.
    // same-sandbox covers both (self is in the sandbox) while still denying
    // signals to anything outside it -- the host, the supervisor, other users.
    p += "(allow signal (target same-sandbox))\n";
}

}  // namespace

Result<Compiled> compile(const Policy<Sealed>& policy, const HostCapabilities& host,
                         const Options& opts) {
    const PolicyData& d = policy.data();
    Compiled out;
    GuaranteeReport::Builder report;

    // -- microvm: refuse rather than approximate ----------------------------
    //
    // Hypervisor.framework exists, but a vm is a different product, not a
    // stronger flag on this one. saying `isolated` here while running the
    // program on the host kernel would be the worst lie in the library.
    if (d.isolation == Isolation::microvm) {
        return std::unexpected(Error{Errc::unsupported,
                                     "microvm isolation needs a separate kernel; "
                                     "the macOS backend runs on the host kernel"});
    }

    if (!host.seatbelt) {
        // no seatbelt means no filesystem and no network wall. rlimits alone
        // are not a sandbox, and pretending otherwise is how issue #21 happened
        // on the other platform.
        return std::unexpected(
            Error{Errc::unsupported, "seatbelt (sandbox_init) unavailable on this host"});
    }

    // -- fidelity and the effective filesystem authority --------------------
    //
    // seatbelt filters operations on paths. it CANNOT rename a path, so a plan
    // that remaps /opt/app to /app has no access-control interpretation at all
    // and must be refused -- running it would give the guest a tree it was
    // never granted, under a report claiming the opposite.
    //
    // a bind also carries TWO interpretations: a tree, and the authority that
    // tree implies. seatbelt can only express the second, so the binds have to
    // be folded in here -- iterating d.fs alone would silently drop every
    // `ro_bind("/usr","/usr")` and emit a profile granting nothing, which looks
    // like a working sandbox right up until the guest cannot run /bin/sh.
    //
    // the fold matches the linux and windows backends exactly, including the
    // middle case: a caller who only said "NOT THAT" gets the mounts minus the
    // hole, rather than an intersection against an empty set.
    Enforcement fs_ceiling = Enforcement::strong;
    FsAuthority effective = d.fs;
    if (!d.mounts.empty()) {
        std::vector<FidelityNote> notes;
        const Fidelity f = d.mounts.fidelity(&notes);
        if (f == Fidelity::impossible) {
            const char* why = notes.empty()
                                  ? "mount plan needs path remapping; seatbelt is "
                                    "access control, not a tree"
                                  : notes.front().reason;
            return std::unexpected(Error{Errc::unsupported, why});
        }
        if (f == Fidelity::approximate) {
            // a tmpfs becomes "you may write here": sound, but it loses "starts
            // empty" and "is size-capped". the caller is told, not surprised.
            fs_ceiling = Enforcement::partial;
            out.degraded.push_back(CapId::fs_write);
        }
        FsAuthority implied = d.mounts.implied_authority();
        effective = d.fs.is_nothing() ? implied : d.fs.meet(implied);
    }
    effective.normalize();

    // -- the profile --------------------------------------------------------
    out.use_seatbelt = true;
    out.profile = "; generated by claybin";
    if (!opts.profile_name.empty()) {
        out.profile += " -- ";
        out.profile += opts.profile_name;
    }
    out.profile += "\n(version 1)\n";
    if (opts.deny_by_default) out.profile += "(deny default)\n";
    if (opts.trace_denials) out.profile += "(debug deny)\n";
    if (opts.allow_process_prerequisites) emit_prerequisites(out.profile);

    // -- filesystem ---------------------------------------------------------
    //
    // grants are emitted shallow-to-deep (FsAuthority::normalize() already
    // sorts them that way), which matters because SBPL is last-match-wins: a
    // deep rule has to come after the shallow one it refines, or it is dead.
    bool any_write = false;
    bool any_exec = false;
    bool any_truncated_write = false;

    if (host.sbpl_path_filters) {
        out.profile += "; filesystem authority, shallow to deep (SBPL is last-match-wins)\n";
        for (const auto& g : effective.grants()) {
            const FileOps ops = to_file_ops(g.rights);

            // record the truncation BEFORE the empty-grant branch below. a
            // create-only grant folds to no emittable operation at all, so it
            // falls into that branch and `continue`s -- and if the flag were
            // set after, the caller would be told their write grant was
            // honoured when in fact it was dropped on the floor.
            if (ops.write_truncated) any_truncated_write = true;

            // a grant of nothing is a DENIAL in an access-control model: the
            // policy carved a hole inside a wider grant. emit it as one, after
            // the wider grant, or the hole does not exist.
            if (!ops.read && !ops.write && !ops.exec) {
                emit_rule(out.profile, "deny", "file-read* file-write*", g.path);
                continue;
            }
            if (ops.read) emit_rule(out.profile, "allow", "file-read*", g.path);
            if (ops.read || ops.write || ops.exec)
                emit_ancestor_metadata(out.profile, g.path);
            if (ops.write) {
                emit_rule(out.profile, "allow", "file-write*", g.path);
                any_write = true;
            }
            if (ops.exec) {
                // process-exec is a separate operation from file-read*: being
                // able to read a binary is not being able to run it.
                emit_rule(out.profile, "allow", "process-exec", g.path);
                any_exec = true;
            }
        }

        const bool has_grants = !effective.grants().empty();
        report.record(CapId::fs_read,
                      has_grants ? meet(fs_ceiling, Enforcement::strong) : Enforcement::strong,
                      "seatbelt");
        report.record(CapId::fs_write,
                      any_truncated_write ? Enforcement::partial : fs_ceiling,
                      any_truncated_write ? "seatbelt (coarse file-write*)" : "seatbelt");
        report.record(CapId::fs_exec, fs_ceiling, "seatbelt");
        if (any_truncated_write) out.degraded.push_back(CapId::fs_write);
        (void)any_write;
        (void)any_exec;
    } else {
        // seatbelt without path filters is a very old dialect. deny-default
        // still works, so the walls exist, but we cannot carve them precisely.
        report.record(CapId::fs_read, Enforcement::partial, "seatbelt (no path filters)");
        report.record(CapId::fs_write, Enforcement::partial, "seatbelt (no path filters)");
        report.record(CapId::fs_exec, Enforcement::partial, "seatbelt (no path filters)");
        out.degraded.push_back(CapId::fs_read);
    }

    // -- network ------------------------------------------------------------
    //
    // the asymmetry here is real and worth stating: DENYING all network is a
    // single rule the kernel enforces exactly, so it reports `strong`.
    // ALLOWING specific endpoints is a path filter over a namespace with dns,
    // redirects and ipv6 literals in it, so it reports `partial` at best.
    const NetOps blanket = d.net.blanket();
    // AF_UNIX is not "the network". `unix_sockets()` sets a blanket op, and
    // reading that as "allow all IP" would turn a policy asking for a local
    // socket into one with full internet access -- the single most dangerous
    // mistranslation available in this file. seatbelt agrees with the policy
    // here: `network*` covers AF_INET/AF_INET6, and AF_UNIX is a separate
    // `network-outbound (path ...)` operation.
    const NetOps kIpOps{(kNetConnect.bits() | kNetBind.bits() | kNetListen.bits() |
                         kNetRaw.bits())};
    const bool blanket_ip = blanket.any(kIpOps);
    const bool wants_unix = blanket.any(kNetUnixSocket);

    if (wants_unix) {
        // a local socket, not a route off the machine. granted on its own line
        // so a reader of the profile can see which of the two it is.
        out.profile += "(allow network-outbound (regex #\"^/private/tmp/\"))\n";
        out.profile += "(allow network-bind (regex #\"^/private/tmp/\"))\n";
    }

    if (d.proxy_listener && d.proxy_port != 0) {
        // the macOS shape of linux's proxied netns. there is no private
        // namespace to put the guest in, but seatbelt CAN pin outbound IP to
        // one loopback port -- measured: 127.0.0.1:PORT connects, every other
        // loopback port, ::1, the LAN and the internet are EPERM. the
        // supervisor serves that port and decides what each CONNECT may
        // reach (no host loopback, no RFC1918, no metadata).
        //
        // checked BEFORE blanket_ip on purpose: the embedder spells "proxied
        // full network" as connect("", 0) + proxied_netns, and reading the
        // blanket first would hand out (allow network*) -- the very hole
        // this branch exists to close.
        //
        // NO resolver grants: the proxy resolves names on the host side, so
        // the guest needs no DNS at all, and has no DNS side channel.
        out.profile += "(deny network*)\n";
        out.profile += "(allow network-outbound (remote ip \"localhost:" +
                       std::to_string(d.proxy_port) + "\"))\n";
        out.allow_network = false;
        report.record(CapId::net_isolation, Enforcement::strong,
                      "seatbelt (loopback proxy port only)");
    } else if (blanket_ip) {
        // the policy allows the network outright. nothing to isolate, and the
        // report says `none` rather than crediting us for a wall we did not
        // build.
        out.profile += "(allow network*)\n";
        emit_resolver_grants(out.profile);
        out.allow_network = true;
        report.record(CapId::net_isolation, Enforcement::none, "network allowed by policy");
    } else if (d.net.endpoints().empty()) {
        // total denial: a single rule the kernel enforces exactly, equivalent
        // to an empty network namespace in what the guest can reach. this is
        // the one network answer that is genuinely `strong`.
        out.profile += "(deny network*)\n";
        out.allow_network = false;
        report.record(CapId::net_isolation,
                      // a unix-socket grant is a hole in the wall, but not one
                      // that reaches off the machine. still `strong` for IP.
                      Enforcement::strong, "seatbelt (deny network*)");
    } else if (host.sbpl_network_filters) {
        // per-endpoint allow-list. seatbelt matches on the ADDRESS, so a host
        // NAME has to be resolved before we get here -- by the caller, not by
        // the kernel, and dns can answer differently next time. that gap is
        // exactly why this is partial and not strong.
        out.profile += "(deny network*)\n";
        emit_resolver_grants(out.profile);
        bool dropped_host_rule = false;
        for (const auto& e : d.net.endpoints()) {
            if (e.ops.is_nothing()) continue;

            // the empty host and the zero port are WILDCARDS, not literals.
            // that is the policy layer's own convention (`connect("", port)`
            // is "this port on any host"), and emitting them verbatim
            // produced `(remote ip "")`, which the kernel rejects with "port
            // missing in network address" -- taking the whole profile down
            // and, through spawn()'s fail-closed path, the command with it.
            //
            // SBPL spells the wildcard `*`, and the host and port are one
            // "host:port" string rather than two fields.
            //
            // THE HOST IS NOT A FILTER ON THIS PLATFORM. seatbelt accepts only
            // `*` or `localhost` there and rejects the whole profile for
            // anything else ("host must be * or localhost in network
            // address"). so a policy naming a hostname cannot be honoured:
            // emitting it kills the profile, and silently widening it to `*`
            // would hand the guest the entire internet while the report
            // claimed one host. drop the rule, record the capability as
            // degraded, and leave `(deny network*)` standing -- the guest
            // loses access it asked for, which is the safe direction.
            if (!e.host.empty() && e.host != "localhost" && e.host != "*") {
                dropped_host_rule = true;
                continue;
            }

            std::string addr = e.host.empty() ? std::string{"*"} : e.host;
            addr += ":";
            addr += e.port == 0 ? std::string{"*"} : std::to_string(e.port);

            std::string quoted;
            if (!sbpl_quote(addr, quoted)) continue;  // fail closed
            std::string rule = "(allow network-outbound (remote ip ";
            rule += quoted;
            rule += "))";
            out.profile += rule;
            out.profile += "\n";
            out.network_rules.push_back(std::move(rule));
        }
        out.allow_network = true;
        report.record(CapId::net_isolation, Enforcement::partial,
                      dropped_host_rule
                          ? "seatbelt (port allow-list; hostname rules dropped)"
                          : "seatbelt (endpoint allow-list)");
        out.degraded.push_back(CapId::net_isolation);
    } else {
        // the policy named endpoints but this host cannot express them. deny
        // everything rather than allow everything: a sandbox that fails open
        // on an old host is worse than one that fails loudly.
        out.profile += "(deny network*)\n";
        out.allow_network = false;
        report.record(CapId::net_isolation, Enforcement::strong,
                      "seatbelt (deny network*; endpoint filters unsupported)");
        out.degraded.push_back(CapId::net_isolation);
    }

    // -- process operations -------------------------------------------------
    //
    // ProcOps is NOT consulted to decide fork/exec, and that asymmetry is
    // deliberate rather than an oversight.
    //
    // On linux, `ProcOps` is advisory: src/plan/compile.cpp never reads it,
    // because fork and exec are governed by the SYSCALL PROFILE there --
    // `profiles::compiler()` permits clone/execve, `profiles::base()` does
    // not. A caller who built a working linux policy therefore has a default-
    // constructed (empty) ProcOps and a profile that allows forking.
    //
    // Reading that empty ProcOps here as "deny fork, deny exec" turned every
    // such policy into a sandbox where `/bin/sh -c` dies on its first
    // subshell with "fork: Operation not permitted" -- the same policy,
    // silently stricter on one platform.
    //
    // So an EMPTY ProcOps means "unspecified", not "deny everything", and the
    // denial is opt-in: a caller who sets any proc op at all is stating an
    // intent, and the ones they left out are then genuinely withheld. The
    // lattice cannot distinguish "unset" from "bottom" for us, so this is the
    // one place that distinction has to be made by hand.
    if (host.sbpl_process_filters) {
        if (!d.proc.is_nothing()) {
            if (!d.proc.any(kProcFork)) {
                out.profile += "(deny process-fork)\n";
                out.deny_fork = true;
            }
            if (!d.proc.any(kProcExec)) {
                out.profile += "(deny process-exec)\n";
                out.deny_exec = true;
            }
        }

        // `process-fork` needs an explicit ALLOW, not merely the absence of a
        // deny. it is its own seatbelt operation, so `(deny default)` catches
        // it, and a profile that says nothing about forking is a profile in
        // which `/bin/sh -c 'a && b'` dies on its first subshell.
        //
        // this is the mirror image of the trap above: there, an unset ProcOps
        // was read as a denial; here, an unset ProcOps has to be turned into
        // an explicit grant. both come from `(deny default)` meaning strictly
        // more on macOS than an empty landlock ruleset does on linux.
        if (!out.deny_fork) out.profile += "(allow process-fork)\n";
        // seatbelt confines THIS process and everything it forks: the profile
        // is inherited and cannot be dropped. that is a real process boundary,
        // but it is not a pid namespace -- the guest still sees every pid on
        // the machine and can signal anything the policy's signal rules allow.
        report.record(CapId::proc_isolation, Enforcement::partial,
                      "seatbelt (inherited profile, shared pid space)");
        out.degraded.push_back(CapId::proc_isolation);
    } else {
        report.record(CapId::proc_isolation, Enforcement::none, "no seatbelt process filters");
    }
    out.new_process_group = true;

    // -- the headline honesty: no syscall filter ----------------------------
    //
    // this must NEVER be strong, whatever the policy says. macOS has no
    // seccomp equivalent available to an unprivileged process; the seatbelt
    // operations above are a fixed menu of MAC hooks, not a programmable
    // filter over syscall numbers and argument registers.
    if (!d.syscalls.is_nothing()) {
        report.record(CapId::syscall_filter, Enforcement::partial,
                      "seatbelt operations (no syscall filter on macOS)");
        out.degraded.push_back(CapId::syscall_filter);
    } else {
        report.record(CapId::syscall_filter, Enforcement::none, "macOS has no seccomp");
    }

    if (d.isolation == Isolation::hardened_process) {
        // hardened means every wall, and a syscall filter is one of them.
        // downgrading silently is the single worst thing a sandbox library can
        // do, so this is an error the caller has to see.
        return std::unexpected(Error{
            Errc::unsupported,
            "hardened_process needs a syscall filter; macOS has no seccomp equivalent"});
    }

    // -- resources: rlimits, which are NOT cgroups --------------------------
    //
    // an rlimit is per-process and inherited; a cgroup counts a tree. four
    // children under a 1 GB RLIMIT_AS can use 4 GB between them, so this is a
    // genuinely weaker guarantee and says so.
    if (host.rlimits) {
        const auto& r = d.resources;
        // RLIMIT_* values are stable ABI; named here rather than included so
        // this file stays compilable on a host whose <sys/resource.h> numbers
        // them differently. the apply side uses the real constants.
        constexpr int kRlimitCpu = 0;
        constexpr int kRlimitCore = 4;
        constexpr int kRlimitAs = 5;
        constexpr int kRlimitNproc = 7;
        constexpr int kRlimitNofile = 8;

        if (!r.memory.is_unlimited()) {
            out.rlimits.push_back({kRlimitAs, r.memory.value()});
            report.record(CapId::mem_limit, Enforcement::partial, "RLIMIT_AS (per-process)");
            out.degraded.push_back(CapId::mem_limit);
        }
        if (!r.cpu_time.is_unlimited()) {
            // RLIMIT_CPU is in SECONDS; the policy is in nanoseconds. round UP,
            // so a limit is never silently relaxed to zero by truncation --
            // RLIMIT_CPU=0 would SIGKILL the guest on its first tick.
            const std::uint64_t secs = (r.cpu_time.value() + 999'999'999ull) / 1'000'000'000ull;
            out.rlimits.push_back({kRlimitCpu, secs});
            report.record(CapId::cpu_limit, Enforcement::partial, "RLIMIT_CPU (per-process)");
            out.degraded.push_back(CapId::cpu_limit);
        }
        if (!r.pids.is_unlimited()) {
            out.rlimits.push_back({kRlimitNproc, r.pids.value()});
            // RLIMIT_NPROC counts processes for the whole UID, not for this
            // tree: another terminal window moves this limit. that is advisory,
            // not a boundary, and calling it `partial` would overstate it.
            report.record(CapId::pid_limit, Enforcement::advisory,
                          "RLIMIT_NPROC (per-UID, not per-tree)");
            out.degraded.push_back(CapId::pid_limit);
        }
        if (!r.open_files.is_unlimited())
            out.rlimits.push_back({kRlimitNofile, r.open_files.value()});
        if (!r.core_size.is_unlimited())
            out.rlimits.push_back({kRlimitCore, r.core_size.value()});
    }

    // -- privilege and devices ----------------------------------------------
    //
    // there is no user namespace here, so there is no uid remapping and no
    // capability set to drop. what seatbelt does give is a profile that cannot
    // be escaped by exec, which stops the classic setuid-helper escalation.
    report.record(CapId::privilege_drop, Enforcement::partial,
                  "seatbelt profile survives exec (no user namespace)");
    report.record(CapId::device_isolation,
                  host.sbpl_path_filters ? Enforcement::partial : Enforcement::none,
                  "seatbelt /dev path filters");
    report.record(CapId::host_kernel_isolation, Enforcement::none,
                  "shared host kernel (use a vm for isolation)");

    // keep `degraded` a set with a stable order: it goes in user-visible output
    // and a wobbling order makes a diffable report undiffable.
    std::sort(out.degraded.begin(), out.degraded.end());
    out.degraded.erase(std::unique(out.degraded.begin(), out.degraded.end()),
                       out.degraded.end());

    out.guarantees = std::move(report).build();
    return out;
}

#if !defined(__APPLE__)
// off-macOS the backend is compile-only. probe reports a host with nothing,
// and spawn refuses rather than silently running the program unconfined --
// the same reason the linux apply path has no portable fallback.
HostCapabilities probe_host() { return HostCapabilities::none(); }

Result<Spawned> spawn(const Compiled&, const SpawnRequest&) {
    return std::unexpected(
        Error{Errc::unsupported, "the macOS backend can only be applied on macOS"});
}
#endif

}  // namespace clay::macos
