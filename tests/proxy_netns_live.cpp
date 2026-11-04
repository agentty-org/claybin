// does the proxied-netns handoff actually work?
//
// the shape under test, which is the whole point of the mechanism:
//   - the guest runs in its OWN network namespace, so the host's loopback
//     services and the LAN are not reachable
//   - its setup opened a listener on 127.0.0.1 inside that namespace and
//     handed the descriptor out; the supervisor accepts on it from here
//   - a connection the guest makes to that port arrives on our accept()
//
// the guest is THIS binary re-execed with one argument, the way escape_test
// does it: a shell needs its own interpreter, loader and symlink farm inside
// the box, and that has nothing to do with what is being tested.
#include "claybin/plan/compile.hpp"
#include "claybin/plan/spawn.hpp"
#include "claybin/policy/policy.hpp"
#include "claybin/policy/profiles.hpp"
#include "harness.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace clay;
using namespace clay::test;

namespace {

// the guest side: read the port from fd 4 (the supervisor only learns it
// after the plan has run, so it cannot be an argv value), connect to
// 127.0.0.1:<port>, say hello, read the reply.
int guest() {
    char pbuf[16]{};
    const ssize_t pn = ::read(4, pbuf, sizeof pbuf - 1);
    if (pn <= 0) { std::fprintf(stderr, "guest: no port on fd 4\n"); return 1; }
    const int port = std::atoi(pbuf);
    const int fd = static_cast<int>(::socket(2 /*AF_INET*/, 1 /*SOCK_STREAM*/, 0));
    if (fd < 0) { std::fprintf(stderr, "guest: socket failed\n"); return 2; }
    struct {
        std::uint16_t family;
        std::uint16_t port;
        std::uint32_t addr;
        char zero[8];
    } sa{};
    sa.family = 2;
    unsigned char* pb = reinterpret_cast<unsigned char*>(&sa.port);
    pb[0] = static_cast<unsigned char>((port >> 8) & 0xff);
    pb[1] = static_cast<unsigned char>(port & 0xff);
    unsigned char* ab = reinterpret_cast<unsigned char*>(&sa.addr);
    ab[0] = 127; ab[1] = 0; ab[2] = 0; ab[3] = 1;
    if (::connect(fd, reinterpret_cast<struct sockaddr*>(&sa), sizeof sa) < 0) {
        std::fprintf(stderr, "guest: connect failed\n");
        return 3;
    }
    const char* msg = "hello-from-guest";
    if (::write(fd, msg, std::strlen(msg)) < 0) return 4;
    char buf[8]{};
    const ssize_t n = ::read(fd, buf, sizeof buf - 1);
    ::close(fd);
    if (n <= 0) return 5;
    std::printf("guest-got:%s\n", buf);
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::strcmp(argv[1], "--guest") == 0) return guest();

    const auto host = probe_host();
    if (!host.user_namespaces || !host.mount_namespaces)
        return skip("proxy_netns_live");
    if (!host.net_namespaces) return skip("proxy_netns_live", "no network namespaces");

    char self[4096];
    const ssize_t sl = ::readlink("/proc/self/exe", self, sizeof self - 1);
    if (sl <= 0) return skip("proxy_netns_live", "cannot find own path");
    self[sl] = '\0';
    // /tmp is the box's own tmpfs, so a bind target can be created there;
    // inside the read-only /usr bind it would be EROFS.
    constexpr const char* kGuestPath = "/tmp/clay-proxy-guest";

    // a box with network authority AND its own namespace, plus the listener.
    auto pol = Policy<Draft>{}
                   .read("/usr")
                   .execute("/usr")
                   .ro_bind("/usr", "/usr")
                   // the ELF interpreter is /lib64/ld-linux-x86-64.so.2, and on
                   // a merged-/usr distro /lib and /lib64 are symlinks. the box
                   // gets the same ones or nothing dynamic can start.
                   .symlink("usr/lib", "/lib")
                   .symlink("usr/lib", "/lib64")
                   .symlink("usr/bin", "/bin")
                   .proc_fs("/proc")
                   .dev_fs("/dev")
                   .tmpfs("/tmp", Bytes{16ull << 20})
                   .execute("/tmp")
                   .ro_bind(self, kGuestPath)
                   .connect("", 0)
                   .proxied_netns()
                   // agentty's posture closes inherited fds, and that sweep
                   // runs in a process that inherited the listener. the bug
                   // this catches was invisible without it.
                   .syscall_profile(profiles::compiler_with_network())
                   .workdir("/tmp")
                   .seal();

    auto compiled = compile(pol, host);
    CHECK(compiled.has_value());
    if (!compiled) return finish("proxy_netns_live");
    // the audit's #1: this is what used to read `partial`.
    CHECK(compiled->guarantees.strength(CapId::net_isolation) == Enforcement::strong);

    // the guest reads the port from fd 4: the kernel only picks it while the
    // plan is being applied, so it cannot be baked into argv.
    int out[2], portpipe[2];
    if (::pipe(out) < 0) return finish("proxy_netns_live");
    if (::pipe(portpipe) < 0) return finish("proxy_netns_live");

    const char* gargv[] = {kGuestPath, "--guest", nullptr};

    Command cmd{kGuestPath, gargv, nullptr};
    cmd.stdout_fd = out[1];
    cmd.stderr_fd = out[1];
    cmd.fds[0] = Command::FdMap{portpipe[0], 4};
    cmd.fd_count = 1;

    auto sp = spawn(compiled->plan, cmd);
    ::close(out[1]);
    ::close(portpipe[0]);
    CHECK(sp.has_value());
    if (!sp) {
        std::printf("spawn failed: %.*s (errno %d)\n",
                    static_cast<int>(sp.error().mechanism.size()), sp.error().mechanism.data(),
                    sp.error().sys_errno);
        ::close(out[0]);
        ::close(portpipe[1]);
        return finish("proxy_netns_live");
    }

    // the listener came back, with the port the kernel chose.
    CHECK(sp->proxy_listen_fd >= 0);
    CHECK(sp->proxy_port != 0);
    std::printf("guest listener: fd=%d port=%u\n", sp->proxy_listen_fd,
                static_cast<unsigned>(sp->proxy_port));

    {
        const std::string line = std::to_string(sp->proxy_port) + "\n";
        ssize_t w = ::write(portpipe[1], line.data(), line.size());
        (void)w;
        ::close(portpipe[1]);
    }

    // accept from OUTSIDE the namespace. this is the claim: the descriptor
    // belongs to the listener, so accept() needs no netns membership.
    bool accepted = false;
    std::string got;
    if (sp->proxy_listen_fd >= 0) {
        struct pollfd p{sp->proxy_listen_fd, POLLIN, 0};
        if (::poll(&p, 1, 5000) == 1 && (p.revents & POLLIN)) {
            const int c = ::accept(sp->proxy_listen_fd, nullptr, nullptr);
            if (c >= 0) {
                accepted = true;
                char buf[128]{};
                struct pollfd q{c, POLLIN, 0};
                if (::poll(&q, 1, 5000) == 1) {
                    const ssize_t n = ::read(c, buf, sizeof buf - 1);
                    if (n > 0) got.assign(buf, static_cast<std::size_t>(n));
                }
                ssize_t w = ::write(c, "ok", 2);
                (void)w;
                ::close(c);
            }
        }
    }
    CHECK(accepted);
    CHECK(got == "hello-from-guest");

    std::string guest_out;
    {
        char buf[512];
        for (;;) {
            const ssize_t n = ::read(out[0], buf, sizeof buf);
            if (n <= 0) break;
            guest_out.append(buf, static_cast<std::size_t>(n));
        }
    }
    ::close(out[0]);
    int status = 0;
    ::waitpid(sp->pid, &status, 0);
    if (sp->proxy_listen_fd >= 0) ::close(sp->proxy_listen_fd);
    if (sp->pidfd >= 0) ::close(sp->pidfd);
    std::printf("guest said: %s", guest_out.c_str());
    CHECK(guest_out.find("guest-got:ok") != std::string::npos);

    return finish("proxy_netns_live");
}
