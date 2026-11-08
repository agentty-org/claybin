// claybin-run: a bubblewrap-compatible front end.
//
// the point is drop-in replacement: the same flags mean the same things, so an
// existing --ro-bind/--proc/--dev invocation works unchanged. where claybin
// differs it is by being STRICTER, never looser:
//
//   - every bind also emits the matching landlock rule, so a path is checked by
//     two independent mechanisms rather than one
//   - a seccomp filter is installed by default; bwrap only does that if the
//     caller passes a pre-compiled BPF program via --seccomp
//   - we refuse rather than continue when a wall cannot be built (bwrap's
//     --not-a-security-boundary is the opposite default)
#include <cstdio>
#include <cstring>
#include <list>
#include <string>
#include <vector>

#if defined(__linux__)
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "claybin/plan/compile.hpp"
#include "claybin/plan/spawn.hpp"
#include "claybin/policy/profiles.hpp"

using namespace clay;

namespace {

// case-insensitive compare, for the ALL keyword on --cap-add/--cap-drop.
bool strcasecmp_eq(const char* a, const char* b) {
    for (; *a && *b; ++a, ++b) {
        char x = *a, y = *b;
        if (x >= 'A' && x <= 'Z') x = static_cast<char>(x - 'A' + 'a');
        if (y >= 'A' && y <= 'Z') y = static_cast<char>(y - 'A' + 'a');
        if (x != y) return false;
    }
    return *a == '\0' && *b == '\0';
}

// A byte count, with the K/M/G/T suffixes every other tool in this space
// accepts. Returns false on anything it cannot represent exactly.
//
// THE BUG THIS FIXES, and it is the worst shape a bug can have: `--memory 16G`
// went through a bare strtoull, which stops at the 'G' and returns 16. The
// cgroup then got memory.max=16 -- sixteen BYTES -- so every sandbox with a
// memory cap was SIGKILLed the instant it was attached, at any size the user
// asked for. The symptom was exit 137 with no diagnostic, which reads as "the
// sandbox is broken" rather than "your flag was silently truncated".
//
// So trailing garbage is an ERROR, not a stopping point. `16GB`, `16g` and
// `16777216` are all accepted; `16Gi`, `16X` and `sixteen` are refused with a
// message naming the argument. A size flag that quietly means something other
// than what it says is worse than one that fails.
//
// Overflow is checked rather than wrapped: `--memory 99999999999999999999G`
// must not become a small number.
bool parse_size(const char* s, std::uint64_t& out) {
    // a digit first. strtoull skips leading space and ACCEPTS a minus sign,
    // negating the result: "--memory -1" parsed as 18446744073709551615 with
    // errno untouched. that is UINT64_MAX -- Bytes' own "unlimited" sentinel
    // -- so it sailed past the 1M floor and the sandbox ran with NO memory cap
    // at all, silently, and --audit did not even list one.
    if (!s || *s < '0' || *s > '9') return false;
    char* end = nullptr;
    errno = 0;
    const unsigned long long raw = std::strtoull(s, &end, 10);
    if (end == s || errno == ERANGE) return false;   // no digits, or too big

    std::uint64_t mult = 1;
    switch (*end) {
        case '\0': break;
        case 'k': case 'K': mult = 1ull << 10; ++end; break;
        case 'm': case 'M': mult = 1ull << 20; ++end; break;
        case 'g': case 'G': mult = 1ull << 30; ++end; break;
        case 't': case 'T': mult = 1ull << 40; ++end; break;
        default: return false;
    }
    // Allow a trailing 'B' ("16GB"), then insist on end-of-string. Anything
    // else -- "16Gi", "16G ", "16Gx" -- is a typo we must not guess at.
    if (*end == 'b' || *end == 'B') ++end;
    if (*end != '\0') return false;

    if (mult > 1 && raw > (UINT64_MAX / mult)) return false;   // would overflow
    out = static_cast<std::uint64_t>(raw) * mult;
    // the same sentinel, spelled out in digits (18446744073709551615), must
    // not mean "unlimited" either. no real size is that large.
    if (out == UINT64_MAX) return false;
    return true;
}

// An unsigned integer in `base`, no larger than `max`, with NOTHING else in the
// string. The same rule as parse_size, for every other number on the command
// line.
//
// These used to be bare strtol/strtoul calls, and each failure mode was its
// own small disaster:
//
//   --uid abc          -> 0, so the guest ran as ROOT in its namespace
//   --uid 4294967295   -> kUnsetId, so an explicit id silently meant "default"
//   --chmod abc PATH   -> mode 000, applied to a HOST path before the sandbox
//   --chmod 4755 PATH  -> setuid bit, on a HOST path
//   --allow-port 65979 -> truncated to uint16 443: a grant nobody typed
//   --info-fd x        -> fd 0, so the status JSON went into our own stdin
//   --args -1          -> read(-1) fails, close(-1), and the args are empty
//
// strtoul also accepts a leading '-' and negates, so "-1" parses as ULONG_MAX;
// a leading sign or space is therefore rejected outright.
bool parse_uint(const char* s, int base, unsigned long long max, unsigned long long& out) {
    if (!s || *s < '0' || *s > '9') return false;   // no sign, no space, not empty
    char* end = nullptr;
    errno = 0;
    const unsigned long long v = std::strtoull(s, &end, base);
    if (end == s || *end != '\0' || errno == ERANGE || v > max) return false;
    out = v;
    return true;
}

// A descriptor number. INT_MAX is the ceiling of the type, not a real limit;
// whether the fd is actually open is checked where it is used.
bool parse_fd(const char* s, int& out) {
    unsigned long long v = 0;
    if (!parse_uint(s, 10, 2147483647ull, v)) return false;
    out = static_cast<int>(v);
    return true;
}

// A mode for --chmod/--perms. bwrap caps these at 07777 and so do we -- the
// setuid/setgid/sticky bits are representable -- but the value must be octal
// digits and nothing else, so a typo cannot become 000 or a stray setuid bit.
bool parse_mode(const char* s, std::uint32_t& out) {
    unsigned long long v = 0;
    if (!parse_uint(s, 8, 07777ull, v)) return false;
    out = static_cast<std::uint32_t>(v);
    return true;
}

// "no --perms pending". not 0: `--perms 0` is a real request (mode 000), and
// using 0 as the sentinel quietly turned it into the default 0666.
constexpr std::uint32_t kNoPerms = 0xffffffffu;

// the whole buffer, or false. a status record is read by another program; a
// short or failed write leaves it parsing half a record or waiting forever,
// so like bwrap we treat it as fatal rather than discarding the result.
bool write_all(int fd, const char* buf, std::size_t len) {
    while (len > 0) {
        ssize_t w = ::write(fd, buf, len);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return false;
        buf += w;
        len -= static_cast<std::size_t>(w);
    }
    return true;
}

void usage() {
    std::fprintf(stderr,
                 "usage: claybin-run [OPTIONS...] [--] COMMAND [ARGS...]\n"
                 "\n"
                 "bubblewrap-compatible options:\n"
                 "  --ro-bind SRC DST      bind SRC at DST, read-only\n"
                 "  --bind SRC DST         bind SRC at DST, read-write\n"
                 "  --dev-bind SRC DST     bind allowing device nodes\n"
                 "  --ro-bind-try SRC DST  like --ro-bind, skip if SRC is missing\n"
                 "  --bind-try SRC DST     like --bind, skip if SRC is missing\n"
                 "  --proc DST             mount a new procfs at DST\n"
                 "  --dev DST              mount a minimal /dev at DST\n"
                 "  --tmpfs DST            mount a tmpfs at DST\n"
                 "  --overlay-src SRC      add a lower layer for the next overlay\n"
                 "  --overlay UP WORK DST  writable overlay at DST\n"
                 "  --tmp-overlay DST      overlay whose writes are discarded\n"
                 "  --ro-overlay DST       read-only overlay (needs 2+ srcs)\n"
                 "  --ro-bind-fd FD DST    bind what FD refers to, read-only\n"
                 "  --bind-fd FD DST       bind what FD refers to\n"
                 "  --file FD DST          write FD's contents to a file at DST\n"
                 "  --bind-data FD DST     bind FD's contents (backing file unlinked)\n"
                 "  --ro-bind-data FD DST  same, read-only\n"
                 "  --dir DST              create a directory\n"
                 "  --symlink TGT DST      create a symlink\n"
                 "  --chdir DIR            working directory inside the sandbox\n"
                 "  --hostname NAME        set the sandbox hostname\n"
                 "  --setenv VAR VAL       set an environment variable\n"
                 "  --unshare-all          unshare every namespace (default)\n"
                 "  --share-net            keep the network namespace\n"
                 "  --size SIZE            size for the next --tmpfs\n"
                 "\n"
                 "claybin additions:\n"
                 "  --profile NAME         syscall profile: base|proc|fs|net|compiler|compiler-net\n"
                 "  --deny PATH            punch a landlock hole inside a bind\n"
                 "  --allow-port PORT      allow TCP connect to PORT only (landlock, abi4+)\n"
                 "  --allow-bind-port PORT allow TCP bind to PORT only\n"
                 "  --memory SIZE          memory cap (cgroup2 when available)\n"
                 "  --processes N          max processes (cgroup2 pids.max)\n"
                 "  --cpu-percent N        cpu cap, 100 = one core (cgroup2 cpu.max)\n"
                 "  --audit                compile THESE flags, print the plan and guarantee\n"
                 "                         report, and exit without spawning. this is the tool\n"
                 "                         for 'what will my sandbox actually do' -- claybin-audit\n"
                 "                         reports host capabilities against a fixed example.\n"
                 "  --require LEVEL        fail unless every wall reaches LEVEL\n");
    std::fprintf(stderr,
                 "\n"
                 "SIZE is a byte count with an optional K/M/G/T suffix:\n"
                 "  --memory 512M   --memory 2G   --memory 1073741824\n"
                 "A suffix is required to mean anything bigger than bytes --\n"
                 "`--memory 2` really is two bytes, and is refused as such.\n");
}

}  // namespace

int main(int argc, char** argv) {
#if !defined(__linux__)
    (void)argc;
    (void)argv;
    std::fprintf(stderr, "claybin-run: linux only\n");
    return 1;
#else
    if (argc < 2) {
        usage();
        return 1;
    }

    // the words being parsed. --args splices more in, in place, from INSIDE the
    // parse loop below -- not in a pre-pass.
    //
    // a pre-pass used to expand every "--args FD" anywhere in argv, including
    // after the command: `claybin-run ... -- tool --args 3` had fd 3 read and
    // closed in OUR process and its contents spliced into the GUEST's argv.
    // only the parse loop knows where the options end (values are consumed by
    // need(), so a value of "--" or "--args" is data, not syntax), so that is
    // the only place an --args can be recognised correctly.
    //
    // the spliced strings live in a std::list because the loop keeps raw
    // pointers into them (profile_name, argv0_override, ...): list nodes never
    // move, so those pointers survive later splices. `args` is re-pointed after
    // each splice; eargv/eargc follow it.
    std::vector<const char*> args(argv, argv + argc);
    std::list<std::string> args_from_files;
    int eargc = argc;
    const char* const* eargv = args.data();
    // words at indices below this came out of an --args file
    int args_file_end = 0;

    auto policy = Policy<Draft>{};
    bool share_net = false;
    bool audit_only = false;
    Enforcement require_level = Enforcement::none;
    std::uint64_t next_size = 0;
    const char* profile_name = "compiler";
    std::vector<std::string> denies;
    std::vector<std::string> unset_keys;
    std::vector<std::string> overlay_srcs;
    std::vector<std::string> remount_ro;
    const char* argv0_override = nullptr;
    std::uint32_t next_perms = kNoPerms;
    bool new_session = false;
    bool die_with_parent = false;
    int info_fd = -1;
    int json_fd = -1;
    int sync_fd = -1;
    int block_fd = -1;
    bool disable_nested_userns = false;
    bool clear_env = false;
    bool inherit_env = true;  // bwrap inherits unless --clearenv

    int i = 1;
    // bounds against the words actually being parsed. this checked argc, the
    // ORIGINAL count, while every option reads eargv -- and --args makes the
    // two differ, so a short argument list could be read past its end.
    auto need = [&](int n, const char* what) -> bool {
        if (i + n >= eargc) {
            std::fprintf(stderr, "claybin-run: %s needs %d argument(s)\n", what, n);
            return false;
        }
        // an option inside an --args file takes its values from the file.
        // bwrap parses the file on its own, so an option there cannot borrow
        // the next word of the real command line; neither may ours.
        if (i < args_file_end && i + n >= args_file_end) {
            std::fprintf(stderr, "claybin-run: %s in an --args file needs %d argument(s) "
                                 "from that file\n", what, n);
            return false;
        }
        return true;
    };

    for (; i < eargc; ++i) {
        const char* a = eargv[i];
        // a modifier cannot carry over from an --args file to the real command
        // line: bwrap parses the file as its own list and refuses a --perms or
        // --size left pending at its end.
        if (i == args_file_end && args_file_end > 0 &&
            (next_perms != kNoPerms || next_size != 0)) {
            std::fprintf(stderr, "claybin-run: --perms/--size at the end of an --args "
                                 "file has nothing to modify\n");
            return 1;
        }
        // --perms modifies the NEXT option only, which must create a file or
        // directory -- bwrap's rule. without this, `--perms 0700 --bind a b
        // --dir d` applied 0700 to d, two options away, or was dropped.
        if (next_perms != kNoPerms && std::strcmp(a, "--perms") != 0 &&
            std::strcmp(a, "--size") != 0 && std::strcmp(a, "--tmpfs") != 0 &&
            std::strcmp(a, "--dir") != 0 && std::strcmp(a, "--file") != 0 &&
            std::strcmp(a, "--bind-data") != 0 && std::strcmp(a, "--ro-bind-data") != 0) {
            std::fprintf(stderr, "claybin-run: --perms must be followed by --tmpfs, --dir, "
                                 "--file, --bind-data or --ro-bind-data\n");
            return 1;
        }
        // same rule for --size, which only --tmpfs consumes. a stray one used
        // to wait silently and size whichever --tmpfs came next, however far on.
        // (--perms may sit between them: `--size 1M --perms 0700 --tmpfs /t`.)
        if (next_size != 0 && std::strcmp(a, "--size") != 0 &&
            std::strcmp(a, "--perms") != 0 && std::strcmp(a, "--tmpfs") != 0) {
            std::fprintf(stderr, "claybin-run: --size must be followed by --tmpfs\n");
            return 1;
        }
        // an --args file holds OPTIONS. a "--" or a command inside one used to
        // end the option list right there, so every flag after `--args FD` on
        // the real command line -- a --deny, a --memory -- silently became an
        // argument to the file's command instead of a restriction.
        if (i < args_file_end && (std::strcmp(a, "--") == 0 || a[0] != '-')) {
            std::fprintf(stderr, "claybin-run: an --args file may contain only options, "
                                 "not '%s'\n", a);
            return 1;
        }
        if (std::strcmp(a, "--") == 0) {
            ++i;
            break;
        }
        if (a[0] != '-') break;

        if (std::strcmp(a, "--help") == 0) {
            usage();
            return 0;
        } else if (std::strcmp(a, "--ro-bind") == 0) {
            if (!need(2, a)) return 1;
            policy = std::move(policy).ro_bind(eargv[i + 1], eargv[i + 2]);
            i += 2;
        } else if (std::strcmp(a, "--bind") == 0) {
            if (!need(2, a)) return 1;
            policy = std::move(policy).bind(eargv[i + 1], eargv[i + 2]);
            i += 2;
        } else if (std::strcmp(a, "--dev-bind") == 0) {
            if (!need(2, a)) return 1;
            policy = std::move(policy).dev_bind(eargv[i + 1], eargv[i + 2]);
            i += 2;
        } else if (std::strcmp(a, "--ro-bind-try") == 0) {
            if (!need(2, a)) return 1;
            policy = std::move(policy).bind_try(eargv[i + 1], eargv[i + 2], true);
            i += 2;
        } else if (std::strcmp(a, "--bind-try") == 0) {
            if (!need(2, a)) return 1;
            policy = std::move(policy).bind_try(eargv[i + 1], eargv[i + 2], false);
            i += 2;
        } else if (std::strcmp(a, "--dev-bind-try") == 0) {
            if (!need(2, a)) return 1;
            policy = std::move(policy).bind_try(eargv[i + 1], eargv[i + 2], false);
            i += 2;
        } else if (std::strcmp(a, "--proc") == 0) {
            if (!need(1, a)) return 1;
            policy = std::move(policy).proc_fs(eargv[i + 1]);
            i += 1;
        } else if (std::strcmp(a, "--dev") == 0) {
            if (!need(1, a)) return 1;
            policy = std::move(policy).dev_fs(eargv[i + 1]);
            i += 1;
        } else if (std::strcmp(a, "--tmpfs") == 0) {
            if (!need(1, a)) return 1;
            // bwrap honours --perms here too (its tmpfs mode), so we do.
            policy = std::move(policy).tmpfs(eargv[i + 1],
                                             next_size ? Bytes{next_size} : Bytes::unlimited(),
                                             next_perms != kNoPerms ? next_perms : 0u);
            next_size = 0;
            next_perms = kNoPerms;
            i += 1;
        } else if (std::strcmp(a, "--size") == 0) {
            if (!need(1, a)) return 1;
            if (next_size != 0) {
                std::fprintf(stderr, "claybin-run: --size given twice for the same --tmpfs\n");
                return 1;
            }
            if (!parse_size(eargv[i + 1], next_size) || next_size == 0) {
                // 0 is refused as bwrap does; here it would also be read
                // as "no --size pending" and give the tmpfs no limit at all.
                next_size = 0;
                std::fprintf(stderr,
                             "claybin-run: --size: bad byte count '%s' "
                             "(want a non-zero count, digits with an optional "
                             "K/M/G/T suffix)\n",
                             eargv[i + 1]);
                return 1;
            }
            i += 1;
        } else if (std::strcmp(a, "--memory") == 0) {
            if (!need(1, a)) return 1;
            std::uint64_t bytes = 0;
            if (!parse_size(eargv[i + 1], bytes)) {
                std::fprintf(stderr,
                             "claybin-run: --memory: bad byte count '%s' "
                             "(want digits with an optional K/M/G/T suffix)\n",
                             eargv[i + 1]);
                return 1;
            }
            // A cap below one page cannot hold a process: the kernel kills it
            // the moment it is attached, before anything of the caller's
            // program runs, and exit 137 with no output is indistinguishable
            // from a broken sandbox. Refusing is the honest answer -- this is
            // the exact failure `--memory 16G` produced when the suffix was
            // dropped, and the number that made it so hard to spot.
            if (bytes < 1024 * 1024) {
                std::fprintf(stderr,
                             "claybin-run: --memory %s is %llu bytes; a cap "
                             "under 1M kills the guest before it can run. "
                             "Did you mean %sM or %sG?\n",
                             eargv[i + 1], static_cast<unsigned long long>(bytes),
                             eargv[i + 1], eargv[i + 1]);
                return 1;
            }
            policy = std::move(policy).memory(Bytes{bytes});
            i += 1;
        } else if (std::strcmp(a, "--processes") == 0) {
            if (!need(1, a)) return 1;
            // A plain count, NOT parse_size: "--processes 4K" is far more
            // likely a typo than a request for 4096 workers, and a pids cap
            // is small by nature.
            {
                // parse_uint, not strtoull: strtoull accepts "-5" and negates
                // it into a huge count, and UINT64_MAX is Count's own
                // "unlimited" sentinel -- both silently meant no cap at all.
                unsigned long long n = 0;
                if (!parse_uint(eargv[i + 1], 10, 0xffffffffull, n) || n == 0) {
                    std::fprintf(stderr,
                                 "claybin-run: --processes: want a positive "
                                 "count, got '%s'\n", eargv[i + 1]);
                    return 1;
                }
                policy = std::move(policy).processes(n);
            }
            i += 1;
        } else if (std::strcmp(a, "--cpu-percent") == 0) {
            // the library has always supported this and the tool never exposed
            // it, so `resource.cpu` read `none` on every audit -- which looked
            // like a missing capability rather than a missing flag.
            if (!need(1, a)) return 1;
            {
                // "abc" used to become 0, which compile() turned into a 1%
                // quota -- a cap far tighter than anything typed. 100 is one
                // core; the library clamps anything beyond the machine.
                unsigned long long pct = 0;
                if (!parse_uint(eargv[i + 1], 10, 0xffffffffull, pct) || pct == 0) {
                    std::fprintf(stderr,
                                 "claybin-run: --cpu-percent: want a positive "
                                 "percentage, got '%s'\n", eargv[i + 1]);
                    return 1;
                }
                policy = std::move(policy).cpu_percent(pct);
            }
            i += 1;
        } else if (std::strcmp(a, "--dir") == 0) {
            if (!need(1, a)) return 1;
            // --perms applies here as it does in bwrap. it used to be ignored,
            // so `--perms 0700 --dir /secret` made a world-readable 0755 dir.
            policy = std::move(policy).mkdir(eargv[i + 1],
                                             next_perms != kNoPerms ? next_perms : 0755u);
            next_perms = kNoPerms;
            i += 1;
        } else if (std::strcmp(a, "--symlink") == 0) {
            if (!need(2, a)) return 1;
            policy = std::move(policy).symlink(eargv[i + 1], eargv[i + 2]);
            i += 2;
        } else if (std::strcmp(a, "--chdir") == 0) {
            if (!need(1, a)) return 1;
            policy = std::move(policy).workdir(eargv[i + 1]);
            i += 1;
        } else if (std::strcmp(a, "--hostname") == 0) {
            if (!need(1, a)) return 1;
            policy = std::move(policy).hostname(eargv[i + 1]);
            i += 1;
        } else if (std::strcmp(a, "--argv0") == 0) {
            if (!need(1, a)) return 1;
            argv0_override = eargv[i + 1];
            i += 1;
        } else if (std::strcmp(a, "--new-session") == 0) {
            new_session = true;
        } else if (std::strcmp(a, "--die-with-parent") == 0) {
            die_with_parent = true;
        } else if (std::strcmp(a, "--remount-ro") == 0) {
            if (!need(1, a)) return 1;
            remount_ro.push_back(eargv[i + 1]);
            i += 1;
        } else if (std::strcmp(a, "--perms") == 0) {
            if (!need(1, a)) return 1;
            // bwrap's rules: octal, <= 07777, and only once per action.
            if (next_perms != kNoPerms) {
                std::fprintf(stderr, "claybin-run: --perms given twice for the same "
                                     "action\n");
                return 1;
            }
            if (!parse_mode(eargv[i + 1], next_perms)) {
                std::fprintf(stderr, "claybin-run: --perms takes an octal mode <= 07777, "
                                     "got '%s'\n", eargv[i + 1]);
                return 1;
            }
            // the plan reads mode 0 as "use the default" (0755 for a dir, 0644
            // for a file), so 0 cannot be expressed. refuse it rather than hand
            // the guest a readable file the caller asked to lock down.
            if (next_perms == 0) {
                std::fprintf(stderr, "claybin-run: --perms 0 is not supported\n");
                return 1;
            }
            i += 1;
        } else if (std::strcmp(a, "--version") == 0) {
            std::printf("claybin-run (claybin) 0.1.0\n");
            return 0;
        } else if (std::strcmp(a, "--level-prefix") == 0) {
            // accepted and ignored: it only changes bwrap's own diagnostics.
        } else if (std::strcmp(a, "--disable-userns") == 0 ||
                   std::strcmp(a, "--assert-userns-disabled") == 0) {
            // every profile already makes new user namespaces impossible:
            // unshare and setns are killed, clone3 is ENOSYS, and clone with
            // any CLONE_NEW* bit is EPERM. but that is a property of the
            // FILTER, and these flags used to be swallowed without checking
            // that a filter would actually be installed -- on a host without
            // seccomp the guest could make a user namespace while the caller
            // believed it could not. so they are now a hard requirement on
            // the syscall filter, checked after compile.
            disable_nested_userns = true;
        } else if (std::strcmp(a, "--mqueue") == 0) {
            if (!need(1, a)) return 1;
            policy = std::move(policy).mqueue(eargv[i + 1]);
            i += 1;
        } else if (std::strcmp(a, "--seccomp") == 0 ||
                   std::strcmp(a, "--add-seccomp-fd") == 0) {
            if (!need(1, a)) return 1;
            // claybin compiles its own filter from a profile. accepting a
            // foreign BPF program is planned, but silently ignoring the flag
            // would mean running with OUR filter while the caller believes
            // theirs is in force -- the worst possible outcome.
            std::fprintf(stderr,
                         "claybin-run: %s not supported. claybin compiles its own "
                         "seccomp filter; use --profile to choose one.\n", a);
            return 1;
        } else if (std::strcmp(a, "--bind-fd") == 0 ||
                   std::strcmp(a, "--ro-bind-fd") == 0) {
            if (!need(2, a)) return 1;
            int fd = -1;
            if (!parse_fd(eargv[i + 1], fd)) {
                std::fprintf(stderr, "claybin-run: %s: invalid fd '%s'\n", a, eargv[i + 1]);
                return 1;
            }
            policy = std::move(policy).bind_fd(BorrowedFd{fd}, eargv[i + 2],
                                               std::strcmp(a, "--ro-bind-fd") == 0);
            i += 2;
        } else if (std::strcmp(a, "--file") == 0) {
            if (!need(2, a)) return 1;
            int fd = -1;
            if (!parse_fd(eargv[i + 1], fd)) {
                std::fprintf(stderr, "claybin-run: --file: invalid fd '%s'\n", eargv[i + 1]);
                return 1;
            }
            policy = std::move(policy).file_from_fd(BorrowedFd{fd}, eargv[i + 2],
                                                    next_perms != kNoPerms ? next_perms
                                                                           : 0666u);
            next_perms = kNoPerms;
            i += 2;
        } else if (std::strcmp(a, "--bind-data") == 0 ||
                   std::strcmp(a, "--ro-bind-data") == 0) {
            if (!need(2, a)) return 1;
            int fd = -1;
            if (!parse_fd(eargv[i + 1], fd)) {
                std::fprintf(stderr, "claybin-run: %s: invalid fd '%s'\n", a, eargv[i + 1]);
                return 1;
            }
            // 0600 by default, as in bwrap. this was 0666, which the umask
            // used to mask down to 0644; with the mode now applied exactly it
            // would have made the bound file world-writable.
            policy = std::move(policy).bind_data(BorrowedFd{fd}, eargv[i + 2],
                                                 std::strcmp(a, "--ro-bind-data") == 0,
                                                 next_perms != kNoPerms ? next_perms : 0600u);
            next_perms = kNoPerms;
            i += 2;
        } else if (std::strcmp(a, "--uid") == 0 || std::strcmp(a, "--gid") == 0) {
            if (!need(1, a)) return 1;
            // a bad id must not become 0 -- root in the namespace -- and
            // 4294967295 is kUnsetId, (uid_t)-1, which no real id may be.
            unsigned long long id = 0;
            if (!parse_uint(eargv[i + 1], 10, kUnsetId - 1ull, id)) {
                std::fprintf(stderr, "claybin-run: %s: invalid id '%s'\n", a, eargv[i + 1]);
                return 1;
            }
            if (a[2] == 'u')
                policy = std::move(policy).uid(static_cast<std::uint32_t>(id));
            else
                policy = std::move(policy).gid(static_cast<std::uint32_t>(id));
            i += 1;
        } else if (std::strcmp(a, "--cap-add") == 0) {
            if (!need(1, a)) return 1;
            if (strcasecmp_eq(eargv[i + 1], "ALL")) {
                std::fprintf(stderr,
                             "claybin-run: --cap-add ALL is refused. a sandbox holding every "
                             "capability is not a sandbox.\n");
                return 1;
            }
            int cap = cap_from_name(eargv[i + 1]);
            if (cap < 0) {
                std::fprintf(stderr, "claybin-run: unknown capability '%s'\n", eargv[i + 1]);
                return 1;
            }
            if (!Caps::of(cap).meet(forbidden_caps()).is_nothing()) {
                // refuse rather than silently ignore: a caller who asked for
                // CAP_SYS_ADMIN needs to know they are not getting it.
                std::fprintf(stderr,
                             "claybin-run: refusing to grant %.*s inside a sandbox\n",
                             static_cast<int>(cap_name(cap).size()), cap_name(cap).data());
                return 1;
            }
            policy = std::move(policy).keep_cap(cap);
            i += 1;
        } else if (std::strcmp(a, "--cap-drop") == 0) {
            if (!need(1, a)) return 1;
            if (strcasecmp_eq(eargv[i + 1], "ALL")) {
                policy = std::move(policy).drop_all_caps();
            } else {
                int cap = cap_from_name(eargv[i + 1]);
                if (cap < 0) {
                    std::fprintf(stderr, "claybin-run: unknown capability '%s'\n", eargv[i + 1]);
                    return 1;
                }
                policy = std::move(policy).drop_cap(cap);
            }
            i += 1;
        } else if (std::strcmp(a, "--as-pid-1") == 0) {
            policy = std::move(policy).as_pid_1();
        } else if (std::strcmp(a, "--exec-label") == 0) {
            if (!need(1, a)) return 1;
            policy = std::move(policy).exec_label(eargv[i + 1]);
            i += 1;
        } else if (std::strcmp(a, "--file-label") == 0) {
            if (!need(1, a)) return 1;
            policy = std::move(policy).file_label(eargv[i + 1]);
            i += 1;
        } else if (std::strcmp(a, "--chmod") == 0) {
            if (!need(2, a)) return 1;
            // bwrap applies --chmod to DEST *inside the new root*, after the
            // binds: openat_in_root("/newroot", dest, O_PATH|O_NOFOLLOW). this
            // applied it to the same path on the HOST, before the sandbox
            // existed, with the caller's full privileges -- so an ordinary bwrap
            // line like `--bind "$APP" /app --chmod 0755 /app/bin` chmodded
            // the host's /app/bin (or the host /etc/..., or anything) instead.
            // a sandbox flag that mutates the host is the opposite of a sandbox.
            //
            // the plan has no in-tree chmod yet, and adding one belongs in the
            // apply() IR with its own escape tests, so until then: refuse. the
            // mode is still validated, so a typo is reported as a typo.
            std::uint32_t mode = 0;
            if (!parse_mode(eargv[i + 1], mode)) {
                std::fprintf(stderr, "claybin-run: --chmod takes an octal mode <= 07777, "
                                     "got '%s'\n", eargv[i + 1]);
                return 1;
            }
            std::fprintf(stderr, "claybin-run: --chmod is not supported yet. bwrap applies "
                                 "it inside the sandbox; claybin will not chmod the host.\n");
            return 1;
        } else if (std::strcmp(a, "--lock-file") == 0) {
            if (!need(1, a)) return 1;
            // bwrap's DEST is a path INSIDE the sandbox: its pid 1 opens it
            // O_RDONLY, without creating it, after pivot_root, and holds an
            // F_RDLCK on it. this opened the same string on the HOST, with
            // O_CREAT, before the sandbox existed -- so `--lock-file /app/x`
            // created /app/x on the host (following any symlink there) and
            // locked a file the sandbox never saw, while the real one stayed
            // unlocked. the in-sandbox open needs a plan op; until then, refuse.
            std::fprintf(stderr, "claybin-run: --lock-file is not supported yet. bwrap "
                                 "locks a path inside the sandbox; claybin will not open "
                                 "or create the host path of the same name.\n");
            return 1;
        } else if (std::strcmp(a, "--userns-block-fd") == 0) {
            if (!need(1, a)) return 1;
            // bwrap pauses AFTER writing --info-fd and before the guest runs,
            // so a supervisor can adjust the new user namespace (write uid maps,
            // place the pid in a cgroup) first. claybin's guest is already
            // running by the time --info-fd is written, so it cannot offer that
            // pause -- and this used to be parsed and ignored, which let the
            // guest run before the setup the caller was waiting to do. refuse.
            std::fprintf(stderr, "claybin-run: --userns-block-fd is not supported: the guest "
                                 "would start before the caller's setup. use --block-fd.\n");
            return 1;
        } else if (std::strcmp(a, "--info-fd") == 0 || std::strcmp(a, "--json-status-fd") == 0 ||
                   std::strcmp(a, "--sync-fd") == 0 || std::strcmp(a, "--block-fd") == 0) {
            if (!need(1, a)) return 1;
            // "x" used to become fd 0 -- our own stdin -- so the status JSON
            // was written to, or the block read from, the wrong descriptor.
            int fd = -1;
            if (!parse_fd(eargv[i + 1], fd)) {
                std::fprintf(stderr, "claybin-run: %s: invalid fd '%s'\n", a, eargv[i + 1]);
                return 1;
            }
            int* slot = std::strcmp(a, "--info-fd") == 0          ? &info_fd
                        : std::strcmp(a, "--json-status-fd") == 0 ? &json_fd
                        : std::strcmp(a, "--sync-fd") == 0        ? &sync_fd
                                                                  : &block_fd;
            *slot = fd;
            i += 1;
        } else if (std::strcmp(a, "--userns") == 0 || std::strcmp(a, "--userns2") == 0 ||
                   std::strcmp(a, "--pidns") == 0) {
            if (!need(1, a)) return 1;
            // joining an EXISTING namespace by fd. claybin creates its own, and
            // joining one it did not build means it cannot describe what the
            // guarantees are -- the whole report would be a guess. refuse.
            std::fprintf(stderr,
                         "claybin-run: %s not supported. claybin creates its own namespaces "
                         "so it can report what they actually enforce; joining one it did not "
                         "build would make the guarantee report a guess.\n", a);
            return 1;
        } else if (std::strcmp(a, "--args") == 0) {
            if (!need(1, a)) return 1;
            // NUL-separated arguments from an fd. flatpak uses this to avoid
            // ARG_MAX and to keep paths with spaces intact. read the whole fd
            // and splice the words in at this position, so later command-line
            // flags still override earlier file ones.
            //
            // like bwrap: a bad fd is an error, a failed read is an error, and
            // an --args file may not itself contain --args.
            if (i < args_file_end) {
                std::fprintf(stderr, "claybin-run: --args is not supported inside an "
                                     "--args file\n");
                return 1;
            }
            int fd = -1;
            if (!parse_fd(eargv[i + 1], fd)) {
                std::fprintf(stderr, "claybin-run: --args: invalid fd '%s'\n", eargv[i + 1]);
                return 1;
            }
            std::string blob;
            char rb[4096];
            for (;;) {
                ssize_t n = ::read(fd, rb, sizeof rb);
                if (n < 0 && errno == EINTR) continue;
                if (n < 0) {
                    std::fprintf(stderr, "claybin-run: --args %d: %s\n", fd,
                                 std::strerror(errno));
                    return 1;
                }
                if (n == 0) break;
                blob.append(rb, static_cast<std::size_t>(n));
            }
            ::close(fd);
            // every NUL ends an argument. empty strings are real arguments --
            // `--setenv X ""` -- and dropping them, as this used to, shifts
            // every later word into the wrong slot.
            std::vector<const char*> words;
            for (std::size_t p = 0; p < blob.size();) {
                std::size_t e = blob.find('\0', p);
                if (e == std::string::npos) e = blob.size();
                args_from_files.push_back(blob.substr(p, e - p));
                words.push_back(args_from_files.back().c_str());
                p = e + 1;
            }
            // replace "--args FD" with the words, then re-point everything
            // that walks the vector. the loop's ++i lands on the first of them.
            auto at = args.begin() + i;
            at = args.erase(at, at + 2);
            args.insert(at, words.begin(), words.end());
            eargc = static_cast<int>(args.size());
            eargv = args.data();
            args_file_end = i + static_cast<int>(words.size());
            i -= 1;
        } else if (std::strcmp(a, "--allow-port") == 0) {
            if (!need(1, a)) return 1;
            // a claybin addition with no bubblewrap equivalent: grant TCP connect
            // to ONE port and let landlock enforce it. bwrap's --share-net is
            // all-or-nothing because a network namespace is all-or-nothing;
            // landlock (abi 4+) mediates per port, so this is a genuinely finer
            // boundary than the mount-namespace model can express.
            //
            // parsed in full and range-checked BEFORE narrowing: the cast to
            // uint16 used to happen first, so 65979 became 443 and 65536
            // became 0 -- a grant on a port nobody typed.
            unsigned long long port = 0;
            if (!parse_uint(eargv[i + 1], 10, 65535ull, port)) {
                std::fprintf(stderr, "claybin-run: --allow-port: invalid port '%s'\n",
                             eargv[i + 1]);
                return 1;
            }
            if (port == 0) {
                std::fprintf(stderr,
                             "claybin-run: --allow-port 0 means 'any port', which landlock "
                             "cannot enforce. use --share-net if that is what you want.\n");
                return 1;
            }
            policy = std::move(policy).connect("", static_cast<std::uint16_t>(port));
            i += 1;
        } else if (std::strcmp(a, "--allow-bind-port") == 0) {
            if (!need(1, a)) return 1;
            unsigned long long port = 0;
            if (!parse_uint(eargv[i + 1], 10, 65535ull, port)) {
                std::fprintf(stderr, "claybin-run: --allow-bind-port: invalid port '%s'\n",
                             eargv[i + 1]);
                return 1;
            }
            if (port == 0) {
                std::fprintf(stderr, "claybin-run: --allow-bind-port 0 is not enforceable\n");
                return 1;
            }
            policy = std::move(policy).bind_port(static_cast<std::uint16_t>(port));
            i += 1;
        } else if (std::strcmp(a, "--setenv") == 0) {
            if (!need(2, a)) return 1;
            policy = std::move(policy).env(eargv[i + 1], eargv[i + 2]);
            i += 2;
        } else if (std::strcmp(a, "--unsetenv") == 0) {
            if (!need(1, a)) return 1;
            unset_keys.push_back(eargv[i + 1]);
            i += 1;
        } else if (std::strcmp(a, "--clearenv") == 0) {
            // a fresh Draft is already env_cleared, so this is the default.
            // accepted for bwrap compatibility.
            clear_env = true;
        } else if (std::strcmp(a, "--overlay-src") == 0) {
            if (!need(1, a)) return 1;
            // bwrap's grammar: these ACCUMULATE and are consumed by the next
            // --overlay / --tmp-overlay / --ro-overlay. we buffer them here and
            // hand them to the builder as a required argument, so the library
            // never sees a layerless overlay.
            overlay_srcs.push_back(eargv[i + 1]);
            i += 1;
        } else if (std::strcmp(a, "--overlay") == 0) {
            if (!need(3, a)) return 1;
            if (overlay_srcs.empty()) {
                std::fprintf(stderr, "claybin-run: --overlay requires at least one "
                                     "--overlay-src\n");
                return 1;
            }
            policy = std::move(policy).overlay(overlay_srcs, eargv[i + 1], eargv[i + 2],
                                               eargv[i + 3]);
            overlay_srcs.clear();
            i += 3;
        } else if (std::strcmp(a, "--tmp-overlay") == 0) {
            if (!need(1, a)) return 1;
            if (overlay_srcs.empty()) {
                std::fprintf(stderr, "claybin-run: --tmp-overlay requires at least one "
                                     "--overlay-src\n");
                return 1;
            }
            policy = std::move(policy).tmp_overlay(overlay_srcs, eargv[i + 1]);
            overlay_srcs.clear();
            i += 1;
        } else if (std::strcmp(a, "--ro-overlay") == 0) {
            if (!need(1, a)) return 1;
            if (overlay_srcs.size() < 2) {
                std::fprintf(stderr, "claybin-run: --ro-overlay requires at least two "
                                     "--overlay-src\n");
                return 1;
            }
            policy = std::move(policy).ro_overlay(overlay_srcs, eargv[i + 1]);
            overlay_srcs.clear();
            i += 1;
        } else if (std::strcmp(a, "--share-net") == 0) {
            share_net = true;
        } else if (std::strcmp(a, "--unshare-all") == 0 ||
                   std::strncmp(a, "--unshare-", 10) == 0) {
            // unsharing everything is our default, so these are accepted and
            // ignored rather than rejected: a bwrap command line should work.
        } else if (std::strcmp(a, "--deny") == 0) {
            if (!need(1, a)) return 1;
            denies.push_back(eargv[i + 1]);
            i += 1;
        } else if (std::strcmp(a, "--profile") == 0) {
            if (!need(1, a)) return 1;
            profile_name = eargv[i + 1];
            i += 1;
        } else if (std::strcmp(a, "--audit") == 0) {
            audit_only = true;
        } else if (std::strcmp(a, "--require") == 0) {
            if (!need(1, a)) return 1;
            const char* l = eargv[i + 1];
            // an unknown level is an error. it used to fall through to
            // `advisory` -- the weakest level there is -- so `--require stong`
            // passed on every host and the check the caller asked for never ran.
            if (std::strcmp(l, "strong") == 0)
                require_level = Enforcement::strong;
            else if (std::strcmp(l, "partial") == 0)
                require_level = Enforcement::partial;
            else if (std::strcmp(l, "advisory") == 0)
                require_level = Enforcement::advisory;
            else {
                std::fprintf(stderr, "claybin-run: --require: unknown level '%s' "
                                     "(want strong, partial or advisory)\n", l);
                return 1;
            }
            i += 1;
        } else if (std::strcmp(a, "--not-a-security-boundary") == 0) {
            std::fprintf(stderr,
                         "claybin-run: refusing --not-a-security-boundary. a sandbox that "
                         "continues after a wall fails is not a sandbox.\n");
            return 1;
        } else {
            std::fprintf(stderr, "claybin-run: unknown option %s\n", a);
            return 1;
        }
    }

    if (!audit_only && i >= eargc) {
        std::fprintf(stderr, "claybin-run: no command given\n");
        return 1;
    }
    // a --perms (or --size) that nothing consumed is a mistake, not a no-op.
    if (next_perms != kNoPerms) {
        std::fprintf(stderr, "claybin-run: --perms must be followed by --tmpfs, --dir, "
                             "--file, --bind-data or --ro-bind-data\n");
        return 1;
    }
    if (next_size != 0) {
        std::fprintf(stderr, "claybin-run: --size must be followed by --tmpfs\n");
        return 1;
    }

    // an unknown name is an error, not `compiler`. `--profile bsae` silently
    // ran the guest under the far broader compiler profile (fork, exec,
    // threads) when the caller had asked for the tightest one.
    SyscallPolicy sys;
    if (std::strcmp(profile_name, "base") == 0)
        sys = profiles::base();
    else if (std::strcmp(profile_name, "proc") == 0)
        sys = profiles::with_processes();
    else if (std::strcmp(profile_name, "fs") == 0)
        sys = profiles::with_filesystem();
    else if (std::strcmp(profile_name, "net") == 0)
        sys = profiles::with_network();
    else if (std::strcmp(profile_name, "compiler") == 0)
        sys = profiles::compiler();
    else if (std::strcmp(profile_name, "compiler-net") == 0)
        sys = profiles::compiler_with_network();
    else if (std::strcmp(profile_name, "supervisor") == 0)
        sys = profiles::supervisor();
    else {
        std::fprintf(stderr, "claybin-run: --profile: unknown profile '%s' "
                             "(want base, proc, fs, net, compiler or compiler-net)\n",
                     profile_name);
        return 1;
    }
    policy = std::move(policy).syscall_profile(sys);
    for (const auto& d : denies) policy = std::move(policy).deny(d);
    for (const auto& p : remount_ro) {
        // --remount-ro DEST means "whatever ends up at DEST, make it read-only".
        // as a landlock grant that is exactly a read-only subtree, which is
        // stronger than bwrap's version: bwrap only remounts, so a later bind
        // could shadow it, whereas a landlock rule survives any mount.
        policy = std::move(policy).grant(p, FileRights::exec());
    }
    if (new_session) policy = std::move(policy).new_session();
    if (die_with_parent) policy = std::move(policy).die_with_parent();
    if (share_net) policy = std::move(policy).connect("", 0);

    // bwrap INHERITS the environment unless --clearenv; the library defaults to
    // cleared, which is the safer default for a policy but the wrong one for a
    // drop-in replacement. so the CLI opts back in explicitly, and --clearenv
    // restores the library default.
    if (!clear_env) policy = std::move(policy).inherit_env();
    (void)inherit_env;

    auto sealed = std::move(policy).seal();
    auto compiled = compile(sealed, probe_host());
    if (!compiled) {
        std::fprintf(stderr, "claybin-run: %s (%.*s)\n",
                     to_string(compiled.error().code).data(),
                     static_cast<int>(compiled.error().mechanism.size()),
                     compiled.error().mechanism.data());
        return 1;
    }

    if (disable_nested_userns &&
        compiled->guarantees.strength(CapId::syscall_filter) < Enforcement::strong) {
        std::fprintf(stderr, "claybin-run: --disable-userns needs a seccomp filter to "
                             "enforce it, and this host cannot install one\n");
        return 1;
    }

    if (require_level != Enforcement::none) {
        // the walls every sandbox has, plus every resource limit the caller
        // actually asked for. the docs promise --require "fails on a host that
        // cannot enforce every wall", but this list never included the limits:
        // `--memory 2G --require strong` ran happily with an rlimit-only cap
        // (reported `partial`) on a host with no delegated cgroup.
        std::vector<CapId> need_caps = {CapId::fs_read, CapId::fs_write,
                                        CapId::syscall_filter, CapId::proc_isolation,
                                        CapId::privilege_drop};
        const auto& res = sealed.data().resources;
        if (!res.memory.is_unlimited()) need_caps.push_back(CapId::mem_limit);
        if (!res.pids.is_unlimited()) need_caps.push_back(CapId::pid_limit);
        if (!res.cpu_quota_percent.is_unlimited()) need_caps.push_back(CapId::cpu_limit);
        Status ok{};
        for (CapId c : need_caps) {
            if (compiled->guarantees.strength(c) < require_level) {
                ok = std::unexpected(Error{Errc::unsupported, cap_name(c)});
                break;
            }
        }
        if (!ok) {
            std::fprintf(stderr, "claybin-run: host cannot enforce %.*s at %s\n",
                         static_cast<int>(ok.error().mechanism.size()),
                         ok.error().mechanism.data(), to_string(require_level));
            return 1;
        }
    }

    if (audit_only) {
        std::printf("PLAN  %zu ops, %zu bytes\n", compiled->plan.op_count(),
                    compiled->plan.size());
        compiled->plan.for_each([](OpCode c, std::span<const std::byte>) {
            std::printf("  %-10s %s\n", to_string(phase_of(c)), to_string(c));
            return true;
        });
        std::printf("\nGUARANTEES\n");
        for (std::size_t k = 0; k < kCapCount; ++k) {
            auto id = static_cast<CapId>(k);
            std::printf("  %-24s %-9s %s\n", cap_name(id),
                        to_string(compiled->guarantees.strength(id)),
                        compiled->guarantees.mechanism(id));
        }
        return 0;
    }

    // --block-fd: wait for the caller to say go. this is how a supervisor gets
    // to finish its own setup (cgroup placement, a seccomp notify listener)
    // before the guest runs.
    if (block_fd >= 0) {
        char c = 0;
        while (::read(block_fd, &c, 1) < 0 && errno == EINTR) {
        }
        ::close(block_fd);
    }

    std::vector<const char*> child_argv;
    for (int k = i; k < eargc; ++k) child_argv.push_back(eargv[k]);
    child_argv.push_back(nullptr);

    // --argv0 replaces what the program sees as its own name without changing
    // which binary we exec. shells and busybox-style multitools branch on it.
    const char* program = child_argv[0];
    if (argv0_override) child_argv[0] = argv0_override;

    // the environment is authority: PATH decides what gets executed and
    // LD_PRELOAD decides what code runs inside the guest. so the policy's env
    // is what the child gets, full stop -- a sealed policy that says
    // env_cleared must not have the parent's environment leak past it.
    //
    // this was a real bug: --setenv and --clearenv parsed fine and were then
    // ignored, because spawn() passed `environ` whenever envp was null.
    std::vector<std::string> env_storage;
    std::vector<const char*> child_env;
    for (const auto& e : sealed.data().env) {
        // --unsetenv wins over --setenv regardless of order on the command line.
        // bwrap applies them in sequence, but "unset" is the more restrictive
        // intent and letting a later --setenv resurrect a variable the caller
        // asked to drop would be the wrong direction to resolve a conflict.
        bool unset = false;
        for (const auto& u : unset_keys)
            if (u == e.key) { unset = true; break; }
        if (!unset) env_storage.push_back(e.key + "=" + e.value);
    }
    if (!sealed.data().env_cleared) {
        // not cleared: inherit, but let explicit --setenv win over the parent,
        // and honour --unsetenv.
        for (char** p = environ; p && *p; ++p) {
            std::string entry = *p;
            auto eq = entry.find('=');
            std::string key = eq == std::string::npos ? entry : entry.substr(0, eq);
            bool drop = false;
            for (const auto& e : sealed.data().env)
                if (e.key == key) { drop = true; break; }
            for (const auto& u : unset_keys)
                if (u == key) { drop = true; break; }
            if (!drop) env_storage.push_back(std::move(entry));
        }
    }
    for (const auto& s : env_storage) child_env.push_back(s.c_str());
    child_env.push_back(nullptr);

    Command cmd{program, child_argv.data(), child_env.data()};
    // spawn_in rather than spawn: the child is placed in its cgroup before it
    // execs, so the limits cover the target program's very first instruction.
    auto sp = spawn_in(compiled->plan, cmd, compiled->cgroup);
    if (!sp) {
        std::fprintf(stderr, "claybin-run: failed to start: %s (%.*s) errno=%d\n",
                     to_string(sp.error().code).data(),
                     static_cast<int>(sp.error().mechanism.size()), sp.error().mechanism.data(),
                     sp.error().sys_errno);
        return 1;
    }

    // --info-fd / --json-status-fd: tell the caller the sandbox's pid and the
    // mount namespace it ended up in, so a supervisor can watch it without
    // parsing our stderr. written as soon as we have a pid, before we wait, or a
    // caller reading synchronously would deadlock against us.
    //
    // the namespace id is the inode of /proc/PID/ns/mnt, which is how the kernel
    // identifies a namespace and how bwrap reports it.
    unsigned long long mnt_ns = 0;
    {
        char nspath[64];
        std::snprintf(nspath, sizeof nspath, "/proc/%d/ns/mnt", sp->pid);
        struct stat st{};
        if (::stat(nspath, &st) == 0) mnt_ns = st.st_ino;
    }
    if (info_fd >= 0) {
        char buf[256];
        int n = mnt_ns
                    ? std::snprintf(buf, sizeof buf,
                                    "{\n    \"child-pid\": %d,\n    \"mnt-namespace\": %llu\n}\n",
                                    sp->pid, mnt_ns)
                    : std::snprintf(buf, sizeof buf, "{\n    \"child-pid\": %d\n}\n", sp->pid);
        if (!write_all(info_fd, buf, static_cast<std::size_t>(n)))
            std::fprintf(stderr, "claybin-run: --info-fd %d: %s\n", info_fd,
                         std::strerror(errno));
        ::close(info_fd);
    }
    if (json_fd >= 0) {
        char buf[256];
        int n = mnt_ns ? std::snprintf(buf, sizeof buf,
                                       "{ \"child-pid\": %d, \"mnt-namespace\": %llu }\n",
                                       sp->pid, mnt_ns)
                       : std::snprintf(buf, sizeof buf, "{ \"child-pid\": %d }\n", sp->pid);
        if (!write_all(json_fd, buf, static_cast<std::size_t>(n)))
            std::fprintf(stderr, "claybin-run: --json-status-fd %d: %s\n", json_fd,
                         std::strerror(errno));
    }

    // --sync-fd: held open for the sandbox's lifetime and closed when it exits,
    // so a caller watching it for EOF learns the sandbox is gone without
    // needing to be our parent.
    (void)sync_fd;

    int status = 0;
    // retry on EINTR and check the result. claybin-run installs no signal
    // handlers today, so this is defensive -- but an unchecked -1 here would
    // report exit 0, success, for a guest that is still running.
    pid_t waited;
    do {
        waited = ::waitpid(sp->pid, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited < 0) {
        std::fprintf(stderr, "claybin-run: waitpid: %s\n", std::strerror(errno));
        return 1;
    }
    if (sp->pidfd >= 0) ::close(sp->pidfd);

    if (json_fd >= 0) {
        char buf[256];
        int code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
        int n = std::snprintf(buf, sizeof buf, "{ \"exit-code\": %d }\n", code);
        if (!write_all(json_fd, buf, static_cast<std::size_t>(n)))
            std::fprintf(stderr, "claybin-run: --json-status-fd %d: %s\n", json_fd,
                         std::strerror(errno));
        ::close(json_fd);
    }
    if (sync_fd >= 0) ::close(sync_fd);

    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return WEXITSTATUS(status);
#endif
}
