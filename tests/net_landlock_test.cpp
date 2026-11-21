// net_landlock_test -- network walls on a host with NO network namespace.
//
// Two promises have to survive the loss of a netns (Ubuntu 24.04's AppArmor
// default denies the user namespace a netns needs):
//
//   * "no network"    -> landlock net handles TCP (and UDP on abi 10+) and
//                        grants nothing.
//   * "only via proxy" -> landlock grants TCP connect to the supervisor's
//                        host-loopback proxy port and nothing else.
//
// and in both, ICMP ping sockets (outside landlock's net model) are refused
// by seccomp. Plan checks run everywhere; live connects run when this process
// genuinely cannot create a user namespace (CI: bwrap --disable-userns).

#include "harness.hpp"

#include <cstring>
#include <string>

#if defined(__linux__)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "claybin/plan/compile.hpp"
#include "claybin/plan/spawn.hpp"
#include "claybin/policy/profiles.hpp"

using namespace clay;
using namespace clay::test;

#if defined(__linux__)

namespace {

// 0 = the attempt SUCCEEDED.
int try_tcp(std::uint16_t port) {
    const int s = ::socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return 1;
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    const int rc = ::connect(s, reinterpret_cast<sockaddr*>(&a), sizeof a);
    ::close(s);
    return rc == 0 ? 0 : 1;
}
int try_udp() {
    const int s = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return 1;
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(9);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    const auto rc = ::sendto(s, "x", 1, 0, reinterpret_cast<sockaddr*>(&a), sizeof a);
    ::close(s);
    return rc == 1 ? 0 : 1;
}
int try_ping() {
    const int s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (s < 0) return 1;
    ::close(s);
    return 0;
}

int run_attack(const char* name, std::uint16_t open_port, std::uint16_t other_port) {
    if (!std::strcmp(name, "tcp_proxy")) return try_tcp(open_port) == 0 ? 42 : 1;   // control
    if (!std::strcmp(name, "tcp_other")) return try_tcp(other_port);
    if (!std::strcmp(name, "udp")) return try_udp();
    if (!std::strcmp(name, "ping")) return try_ping();
    return 3;
}

int listener(std::uint16_t& port) {
    const int s = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t len = sizeof a;
    ::bind(s, reinterpret_cast<sockaddr*>(&a), sizeof a);
    ::listen(s, 16);
    ::getsockname(s, reinterpret_cast<sockaddr*>(&a), &len);
    port = ntohs(a.sin_port);
    return s;
}

HostCapabilities no_netns(HostCapabilities h) {
    h.user_namespaces = h.mount_namespaces = h.pid_namespaces = h.net_namespaces =
        h.uts_namespaces = h.ipc_namespaces = h.cgroup_namespaces = false;
    return h;
}

Policy<Draft> base(const std::string& self_dir) {
    auto d = Policy<Draft>{};
    d = std::move(d).ro_bind("/usr", "/usr");
    for (const char* p : {"/lib", "/lib64", "/bin"}) d = std::move(d).bind_try(p, p);
    d = std::move(d).ro_bind(self_dir, self_dir);
    return d;
}

int attack(const Compiled& c, const char* self, const char* name, std::uint16_t a,
           std::uint16_t b) {
    const std::string pa = std::to_string(a), pb = std::to_string(b);
    const char* argv[] = {self, "attack", name, pa.c_str(), pb.c_str(), nullptr};
    const char* envp[] = {nullptr};
    Command cmd{self, argv, envp};
    auto sp = spawn(c.plan, cmd);
    if (!sp) return -1;
    int st = 0;
    ::waitpid(sp->pid, &st, 0);
    if (sp->pidfd >= 0) ::close(sp->pidfd);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}

}  // namespace

#endif

int main(int argc, char** argv) {
#if defined(__linux__)
    if (argc >= 5 && !std::strcmp(argv[1], "attack"))
        return run_attack(argv[2], static_cast<std::uint16_t>(std::atoi(argv[3])),
                          static_cast<std::uint16_t>(std::atoi(argv[4])));
    const auto real = probe_host();
    if (real.landlock_abi < 4) return skip("net_landlock_test", "landlock net needs abi 4");
    char self[4096]{};
    if (::readlink("/proc/self/exe", self, sizeof self - 1) <= 0)
        return skip("net_landlock_test", "no /proc/self/exe");
    std::string self_dir{self};
    self_dir.resize(self_dir.rfind('/'));

    std::uint16_t proxy_port = 0, other_port = 0;
    const int lp = listener(proxy_port);
    const int lo = listener(other_port);

    auto proxied = [&](const HostCapabilities& h) {
        auto d = base(self_dir);
        d = std::move(d).connect("", 0).proxied_netns(3128).host_proxy_fallback(proxy_port);
        d = std::move(d).syscall_profile(profiles::compiler_with_network());
        return compile(std::move(d).seal(), h);
    };
    auto offline = [&](const HostCapabilities& h) {
        auto d = base(self_dir);
        d = std::move(d).syscall_profile(profiles::compiler_with_network());
        return compile(std::move(d).seal(), h);
    };

    // ---- plan: what the report claims on a modelled no-netns host ----------
    {
        auto c = proxied(no_netns(real));
        CHECK(c.has_value());
        if (c) {
            const std::string m = c->guarantees.mechanism(CapId::net_isolation);
            CHECK(m.find("proxy port only") != std::string::npos);
            CHECK(c->guarantees.strength(CapId::net_isolation)
                  == (real.landlock_abi >= 10 ? Enforcement::strong : Enforcement::partial));
        }
        auto o = offline(no_netns(real));
        CHECK(o.has_value());
        if (o) {
            const std::string m = o->guarantees.mechanism(CapId::net_isolation);
            CHECK(m.find("no tcp") != std::string::npos);
        }
        // landlock too old for net: the proxy fallback must REFUSE, never
        // quietly share the host network.
        auto old = no_netns(real);
        old.landlock_abi = 3;
        CHECK(!proxied(old).has_value());
    }

    // ---- live, only where there genuinely is no netns ----------------------
    if (real.net_namespaces) {
        std::fprintf(stderr, "  (live attacks skipped: this host has network namespaces)\n");
    } else {
        auto c = proxied(real);
        CHECK(c.has_value());
        if (c) {
            CHECK(attack(*c, self, "tcp_proxy", proxy_port, other_port) == 42);
            CHECK(attack(*c, self, "tcp_other", proxy_port, other_port) == 1);
            if (real.landlock_abi >= 10)
                CHECK(attack(*c, self, "udp", proxy_port, other_port) == 1);
            CHECK(attack(*c, self, "ping", proxy_port, other_port) == 1);
        }
        auto o = offline(real);
        CHECK(o.has_value());
        if (o) {
            CHECK(attack(*o, self, "tcp_other", proxy_port, other_port) == 1);
            CHECK(attack(*o, self, "tcp_proxy", proxy_port, other_port) == 1);
            if (real.landlock_abi >= 10)
                CHECK(attack(*o, self, "udp", proxy_port, other_port) == 1);
            CHECK(attack(*o, self, "ping", proxy_port, other_port) == 1);
        }
    }
    ::close(lp);
    ::close(lo);
#else
    (void)argc;
    (void)argv;
#endif
    return finish("net_landlock_test");
}
