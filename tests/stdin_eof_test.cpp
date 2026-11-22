// stdin_eof_test -- a sandboxed child sees EOF when its supervisor closes stdin.
//
// A long-lived child (an MCP server, an ACP agent) is told to finish by EOF on
// its stdin. claybin's setup processes that stay behind -- the outer waiter and
// the pid-1 shepherd -- never exec, so CLOEXEC does nothing for them, and they
// used to keep a copy of every descriptor the caller had at fork time. One of
// those is the write end of the guest's stdin pipe: the supervisor closes its
// end, the shepherd's copy keeps the pipe open, and the guest waits forever.
//
// The test spawns `cat` reading a pipe, writes a line, closes the write end,
// and requires cat to echo the line and EXIT within a few seconds.

#include "harness.hpp"

#include <cstring>
#include <string>

#if defined(__linux__)
#include <fcntl.h>
#include <poll.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "claybin/plan/compile.hpp"
#include "claybin/plan/spawn.hpp"
#include "claybin/policy/profiles.hpp"

using namespace clay;
using namespace clay::test;

int main() {
#if defined(__linux__)
    const auto host = probe_host();
    if (!host.seccomp && host.landlock_abi == 0) return skip("stdin_eof_test");

    auto d = Policy<Draft>{};
    d = std::move(d).ro_bind("/usr", "/usr");
    for (const char* p : {"/lib", "/lib64", "/bin"}) d = std::move(d).bind_try(p, p);
    d = std::move(d).syscall_profile(profiles::compiler());
    auto c = compile(std::move(d).seal(), host);
    CHECK(c.has_value());
    if (!c) return finish("stdin_eof_test");

    int in[2], out[2];
    if (::pipe2(in, O_CLOEXEC) != 0 || ::pipe2(out, O_CLOEXEC) != 0)
        return skip("stdin_eof_test", "pipe");

    const char* argv[] = {"/usr/bin/cat", nullptr};
    const char* envp[] = {nullptr};
    Command cmd{"/usr/bin/cat", argv, envp};
    cmd.stdin_fd = in[0];
    cmd.stdout_fd = out[1];
    auto sp = spawn(c->plan, cmd);
    ::close(in[0]);
    ::close(out[1]);
    CHECK(sp.has_value());
    if (!sp) return finish("stdin_eof_test");

    (void)!::write(in[1], "hello\n", 6);
    ::close(in[1]);   // the only write end the caller has: cat must now see EOF

    // read until EOF on cat's stdout, bounded
    std::string got;
    for (;;) {
        pollfd p{out[0], POLLIN, 0};
        if (::poll(&p, 1, 5000) <= 0) break;   // 5 s with nothing: cat is stuck
        char buf[64];
        const ssize_t n = ::read(out[0], buf, sizeof buf);
        if (n <= 0) break;
        got.append(buf, static_cast<std::size_t>(n));
    }
    ::close(out[0]);
    CHECK(got == "hello\n");

    // and it must have EXITED, not merely gone quiet
    int st = 0;
    pid_t r = 0;
    for (int i = 0; i < 50 && r == 0; ++i) {
        r = ::waitpid(sp->pid, &st, WNOHANG);
        if (r == 0) ::usleep(100'000);
    }
    if (r == 0) {
        std::fprintf(stderr, "  cat did not exit after stdin EOF\n");
        ::kill(sp->pid, SIGKILL);
        ::waitpid(sp->pid, &st, 0);
    }
    CHECK(r == sp->pid);
    if (sp->pidfd >= 0) ::close(sp->pidfd);
#endif
    return finish("stdin_eof_test");
}
