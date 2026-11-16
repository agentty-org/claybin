#include "claybin/broker/notify.hpp"

#if defined(__linux__)

#include <cerrno>
#include <cstring>
#include <linux/seccomp.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace clay::broker {
namespace {

// the notification structs. defined here rather than relying on the kernel
// headers being new enough, because seccomp_notif grew fields over time and a
// too-small struct is rejected.
struct Notif {
    std::uint64_t id;
    std::uint32_t pid;
    std::uint32_t flags;
    // struct seccomp_data, inline
    std::int32_t nr;
    std::uint32_t arch;
    std::uint64_t instruction_pointer;
    std::uint64_t args[6];
};

struct NotifResp {
    std::uint64_t id;
    std::int64_t val;
    std::int32_t error;
    std::uint32_t flags;
};

struct NotifAddfd {
    std::uint64_t id;
    std::uint32_t flags;
    std::uint32_t srcfd;
    std::uint32_t newfd;
    std::uint32_t newfd_flags;
};

// ioctl numbers. these are _IOWR('!', n, struct ...), and the sizes are part of
// the encoding, so they are computed rather than hardcoded.
template <class T>
constexpr unsigned long iowr(unsigned n) {
    // _IOC(dir=3 for READ|WRITE, type='!', nr=n, size=sizeof(T))
    return (3ul << 30) | (static_cast<unsigned long>('!') << 8) | n |
           (static_cast<unsigned long>(sizeof(T)) << 16);
}

constexpr unsigned long kNotifRecv = iowr<Notif>(0);
constexpr unsigned long kNotifSend = iowr<NotifResp>(1);
// ID_VALID and ADDFD are _IOW, not _IOWR: the kernel only reads them. using the
// wrong direction bit produces a completely different ioctl number and the call
// fails with ENOTTY, which reads like an unsupported kernel rather than a typo.
// verified against <linux/seccomp.h>: RECV 0xc0502100, SEND 0xc0182101,
// ID_VALID 0x40082102, ADDFD 0x40182103.
constexpr unsigned long kNotifIdValid =
    (1ul << 30) | (static_cast<unsigned long>('!') << 8) | 2u |
    (static_cast<unsigned long>(sizeof(std::uint64_t)) << 16);
constexpr unsigned long kNotifAddfd =
    (1ul << 30) | (static_cast<unsigned long>('!') << 8) | 3u |
    (static_cast<unsigned long>(sizeof(NotifAddfd)) << 16);

// ioctl's request is `unsigned long` in glibc, `int` in musl (POSIX), and
// Bionic declares BOTH `int` and `unsigned` overloads, so its address can't be
// taken (`decltype(&::ioctl)` doesn't resolve). The kernel decodes only the low
// 32 bits, so pass the request as `unsigned`: glibc widens it losslessly, musl
// converts it to the same bit pattern, and Bionic picks its unsigned overload.
// RECV and SEND have bit 31 set, which is why it must not go through `int`.
template <class Arg>
int notif_ioctl(int fd, unsigned long request, Arg* arg) {
    static_assert(sizeof(unsigned) >= sizeof(std::uint32_t),
                  "the ioctl request must hold the 32-bit encoding");
    return ::ioctl(fd, static_cast<unsigned>(request), arg);
}

// SECCOMP_ADDFD_FLAG_SEND: install the fd AND use it as the syscall's return
// value, in one atomic step. without this the supervisor would have to install
// the fd and then separately respond with its number, and the guest could see an
// inconsistent state in between.
constexpr std::uint32_t kAddfdFlagSend = 2;

}  // namespace

Result<Request> Listener::next() {
    if (!fd_.valid()) return std::unexpected(Error{Errc::invalid_policy, "broker: no fd"});

    Notif n{};
    // the kernel requires the struct be zeroed: it rejects a request with
    // unrecognised bits set, which is how it stays forward-compatible.
    std::memset(&n, 0, sizeof n);
    if (notif_ioctl(fd_.get(), kNotifRecv, &n) < 0)
        return std::unexpected(Error{Errc::io_error, "broker: NOTIF_RECV", errno});

    Request r;
    r.id = n.id;
    r.pid = n.pid;
    r.nr = static_cast<SysNr>(n.nr);
    r.arch = n.arch;
    for (int i = 0; i < 6; ++i) r.args[i] = n.args[i];
    return r;
}

bool Listener::still_valid(const Request& req) const {
    if (!fd_.valid()) return false;
    std::uint64_t id = req.id;
    // ID_VALID returns 0 when the notification is live, -ENOENT when the guest
    // thread has died. this is the ONLY way to know that the thing we inspected
    // is the thing we are about to answer.
    return notif_ioctl(fd_.get(), kNotifIdValid, &id) == 0;
}

Status Listener::respond(const Request& req, const Decision& d) {
    if (!fd_.valid()) return std::unexpected(Error{Errc::invalid_policy, "broker: no fd"});

    // re-check liveness before answering. if the guest thread died, the id may
    // already have been reused by a different syscall, and answering it would
    // approve something nobody inspected.
    if (!still_valid(req))
        return std::unexpected(Error{Errc::already_consumed, "broker: notification expired"});

    if (d.kind == Decision::Kind::inject_fd) {
        if (d.injected_fd < 0)
            return std::unexpected(Error{Errc::invalid_policy, "broker: no fd to inject"});

        NotifAddfd add{};
        add.id = req.id;
        // SEND makes the install and the response one operation, so the guest
        // cannot observe a half-finished state.
        add.flags = kAddfdFlagSend;
        add.srcfd = static_cast<std::uint32_t>(d.injected_fd);
        add.newfd = 0;
        add.newfd_flags = 0;
        if (notif_ioctl(fd_.get(), kNotifAddfd, &add) < 0)
            return std::unexpected(Error{Errc::io_error, "broker: NOTIF_ADDFD", errno});
        return {};
    }

    NotifResp resp{};
    resp.id = req.id;
    if (d.kind == Decision::Kind::allow) {
        // SECCOMP_USER_NOTIF_FLAG_CONTINUE == 1: let the kernel perform the
        // syscall as written.
        //
        // WORTH KNOWING: the kernel documents this as unsafe for any syscall
        // whose arguments are pointers, because between our decision and the
        // kernel's read the guest can change them. we expose it anyway because
        // it is sound for scalar-only syscalls, and the header says which is
        // which -- but this is exactly the trap the comment up there warns about.
        resp.flags = 1;
        resp.val = 0;
        resp.error = 0;
    } else {
        // a denial needs no CONTINUE: we supply the errno and the syscall never
        // runs, so there is no TOCTOU window at all.
        resp.flags = 0;
        resp.val = 0;
        resp.error = -d.error;
    }

    if (notif_ioctl(fd_.get(), kNotifSend, &resp) < 0)
        return std::unexpected(Error{Errc::io_error, "broker: NOTIF_SEND", errno});
    return {};
}

Status Listener::poll_once(const Handler& h) {
    auto req = next();
    if (!req) return std::unexpected(req.error());
    return respond(*req, h(*req));
}

Decision decide_socket(const Request& req, bool any_network_allowed) {
    // socket(domain, type, protocol) -- all three are scalars, so this decision
    // touches no guest memory and has no TOCTOU window.
    const auto domain = static_cast<int>(req.args[0]);
    const auto type = static_cast<int>(req.args[1] & 0xffu);

    if (!any_network_allowed) return Decision::deny_it(13 /* EACCES */);

    // AF_INET / AF_INET6 only, and stream/datagram only. a raw socket is a
    // packet-forging primitive and AF_PACKET is worse, so those stay denied
    // however permissive the policy is.
    constexpr int kAfInet = 2, kAfInet6 = 10, kAfUnix = 1;
    constexpr int kSockStream = 1, kSockDgram = 2;

    if (domain != kAfInet && domain != kAfInet6 && domain != kAfUnix)
        return Decision::deny_it(97 /* EAFNOSUPPORT */);
    if (type != kSockStream && type != kSockDgram)
        return Decision::deny_it(93 /* EPROTONOSUPPORT */);

    return Decision::allow_it();
}

}  // namespace clay::broker

#else

namespace clay::broker {
Result<Request> Listener::next() {
    return std::unexpected(Error{Errc::unsupported, "broker: linux only"});
}
Status Listener::respond(const Request&, const Decision&) {
    return std::unexpected(Error{Errc::unsupported, "broker: linux only"});
}
Status Listener::poll_once(const Handler&) {
    return std::unexpected(Error{Errc::unsupported, "broker: linux only"});
}
bool Listener::still_valid(const Request&) const { return false; }
Decision decide_socket(const Request&, bool) { return Decision::deny_it(); }
}  // namespace clay::broker

#endif
