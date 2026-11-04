#include "claybin/linux/cgroup.hpp"

#if defined(__linux__)

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace clay::cgroup {
namespace {

constexpr const char* kRoot = "/sys/fs/cgroup";

// read a whole small file into a caller buffer. returns length, or -1.
long read_file(const char* path, char* buf, std::size_t cap) {
    int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = ::read(fd, buf, cap - 1);
    ::close(fd);
    if (n < 0) return -1;
    buf[n] = '\0';
    return static_cast<long>(n);
}

Status write_file(const std::string& path, const char* value) {
    int fd = ::open(path.c_str(), O_WRONLY | O_CLOEXEC);
    if (fd < 0) return std::unexpected(Error{Errc::io_error, "cgroup: open", errno});
    ssize_t n = ::write(fd, value, std::strlen(value));
    int err = errno;
    ::close(fd);
    if (n < 0) return std::unexpected(Error{Errc::io_error, "cgroup: write", err});
    return {};
}

bool has_word(const char* haystack, const char* word) {
    std::size_t wl = std::strlen(word);
    const char* p = haystack;
    while ((p = std::strstr(p, word)) != nullptr) {
        bool left = (p == haystack) || p[-1] == ' ' || p[-1] == '\n';
        char r = p[wl];
        bool right = r == '\0' || r == ' ' || r == '\n';
        if (left && right) return true;
        p += wl;
    }
    return false;
}

// our own cgroup path, from /proc/self/cgroup. v2 lines look like "0::/path".
bool own_cgroup(std::string& out) {
    char buf[4096];
    if (read_file("/proc/self/cgroup", buf, sizeof buf) < 0) return false;
    // find the "0::" line: the unified hierarchy
    const char* line = buf;
    while (line && *line) {
        if (line[0] == '0' && line[1] == ':' && line[2] == ':') {
            const char* start = line + 3;
            const char* end = std::strchr(start, '\n');
            out.assign(start, end ? static_cast<std::size_t>(end - start) : std::strlen(start));
            return true;
        }
        line = std::strchr(line, '\n');
        if (line) ++line;
    }
    return false;
}

}  // namespace

Probe probe() {
    Probe pr;

    // is cgroup v2 even mounted?
    char ctl[512];
    std::string root_ctl = std::string(kRoot) + "/cgroup.controllers";
    if (read_file(root_ctl.c_str(), ctl, sizeof ctl) < 0) {
        pr.reason = "cgroup v2 not mounted";
        return pr;
    }

    std::string rel;
    if (!own_cgroup(rel)) {
        pr.reason = "cannot read /proc/self/cgroup";
        return pr;
    }
    pr.own_path = std::string(kRoot) + (rel == "/" ? "" : rel);

    // which controllers are available TO US, which is what our own cgroup's
    // cgroup.controllers says -- the root's list is irrelevant if our parent
    // did not delegate them down.
    char mine[512] = "";
    std::string my_ctl = pr.own_path + "/cgroup.controllers";
    if (read_file(my_ctl.c_str(), mine, sizeof mine) < 0) {
        pr.reason = "cannot read our cgroup.controllers";
        return pr;
    }
    pr.memory = has_word(mine, "memory");
    pr.pids = has_word(mine, "pids");
    pr.cpu = has_word(mine, "cpu");
    pr.io = has_word(mine, "io");
    // can we actually delegate? the blocker is cgroup v2's no-internal-process
    // rule: controllers cannot be enabled in a cgroup's subtree while that
    // cgroup holds processes.
    //
    // that is almost always true of wherever we were launched -- even a fresh
    // `systemd-run --scope` contains the shell and its children. the standard
    // fix is to move the processes into a leaf child, which leaves the parent
    // empty and free to delegate.
    //
    // BUT the move is one-way, and getting that wrong cost me a shell. the
    // no-internal-process rule is symmetric: once subtree_control is set on our
    // own cgroup, that cgroup can no longer HOLD processes, so moving them back
    // returns EBUSY forever. an earlier version did the move, delegated, and
    // then tried to restore -- which silently could not work on exactly the
    // path where it mattered, leaving every process in the session parked in a
    // scratch cgroup. the next probe then nested another one inside it. i found
    // my own shell 330 levels deep.
    //
    // so the design is: if a move is needed, the processes STAY in a permanent
    // sibling leaf, not a scratch directory we intend to delete. that leaf is a
    // normal place for them to live -- it is what systemd-run would have given
    // us -- and nothing needs undoing afterwards.
    // the leaf our processes live in, as a SIBLING of our cgroup rather than a
    // child of it. that detail is the whole fix.
    //
    // a child does not work, and the reason took me three attempts to see: after
    // the move, our own cgroup IS the leaf, so the next probe's own_path is one
    // level deeper and creates another child inside that. reusing a fixed NAME
    // does not help when the parent keeps descending. probe() runs on every
    // compile, so this compounds per launch -- i found my shell 330 levels down,
    // with the terminal unable to print its own cgroup path.
    //
    // a sibling is stable: once we live in <parent>/clay-main, a later probe
    // computes the same <parent>/clay-main and the mkdir is a no-op EEXIST.
    std::string leaf_dir;
    bool already_leaf = false;
    std::string parent_path;
    {
        std::size_t slash = pr.own_path.rfind('/');
        if (slash != std::string::npos && slash > 0) {
            parent_path = pr.own_path.substr(0, slash);
            leaf_dir = parent_path + "/clay-main";
            already_leaf = (pr.own_path == leaf_dir);
        }
    }
    if (leaf_dir.empty()) leaf_dir = pr.own_path + "/clay-main";

    // the case that matters for repeat runs: we are already the leaf, and our
    // PARENT already delegates. nothing needs doing -- a sandbox cgroup becomes
    // our sibling under that parent, where the controllers already are.
    //
    // getting here without this check is what made every probe after the first
    // report `unusable`: we hold processes, so enabling controllers below
    // OURSELVES is EBUSY forever, and that looked like failure when in fact the
    // delegation was already in place one level up.
    if (already_leaf && !parent_path.empty()) {
        char pctl[512] = "";
        // whole words, as everywhere else in this file. a bare strstr found
        // "cpu" inside "cpuset", so a parent delegating only cpuset reported
        // the cpu controller, and the guarantee report then claimed a STRONG
        // cpu.max quota that create() could never write.
        if (read_file((parent_path + "/cgroup.subtree_control").c_str(), pctl, sizeof pctl) > 0 &&
            (has_word(pctl, "memory") || has_word(pctl, "pids"))) {
            pr.memory = has_word(pctl, "memory");
            pr.pids = has_word(pctl, "pids");
            pr.cpu = has_word(pctl, "cpu");
            pr.io = has_word(pctl, "io");
            pr.delegating_path = parent_path;
            pr.availability = Availability::delegated;
            return pr;
        }
    }

    std::string subtree = pr.own_path + "/cgroup.subtree_control";
    // ask only for what we have; asking for an absent controller is its own EINVAL
    std::string want;
    if (pr.memory) want += "+memory ";
    if (pr.pids) want += "+pids ";
    if (pr.cpu) want += "+cpu";
    if (want.empty()) {
        pr.availability = Availability::unusable;
        pr.reason = "no memory or pids controller delegated to us";
        return pr;
    }

    auto st = write_file(subtree, want.c_str());
    if (!st && st.error().sys_errno == EBUSY) {
        // our cgroup holds processes, so controllers cannot be enabled below it.
        // move them to the sibling leaf and LEAVE them there -- the move is
        // one-way, because setting subtree_control here makes this cgroup unable
        // to hold processes ever again.
        //
        // if we are already the leaf, there is nowhere better to go: the
        // processes are ours and EBUSY here means we genuinely cannot delegate.
        // say so rather than digging another level.
        if (already_leaf) {
            pr.availability = Availability::unusable;
            pr.reason = "cgroup holds processes we cannot move; launch in a delegated "
                        "scope (systemd-run --user --scope) for cgroup limits";
            return pr;
        }
        if (::mkdir(leaf_dir.c_str(), 0755) < 0 && errno != EEXIST) {
            pr.availability = Availability::unusable;
            pr.reason = "cannot create a leaf cgroup to move our processes into";
            return pr;
        }
        std::string procs_path = pr.own_path + "/cgroup.procs";
        std::string leaf_procs = leaf_dir + "/cgroup.procs";
        char procs[8192];
        long n = read_file(procs_path.c_str(), procs, sizeof procs);
        bool moved_any = false;
        if (n > 0) {
            const char* line = procs;
            while (line && *line) {
                const char* end = std::strchr(line, '\n');
                std::string pid(line, end ? static_cast<std::size_t>(end - line)
                                          : std::strlen(line));
                // a pid that will not move is not fatal: it may have exited, or
                // belong to something we cannot touch. we only need the cgroup
                // to end up EMPTY, which the retry below actually tests.
                if (!pid.empty() && write_file(leaf_procs, pid.c_str())) moved_any = true;
                line = end ? end + 1 : nullptr;
            }
        }
        if (moved_any) st = write_file(subtree, want.c_str());
        // we now live in the leaf, so the delegating cgroup is the one we just
        // left -- a sandbox cgroup must be created there, beside us.
        if (st) pr.delegating_path = pr.own_path;

        // if delegation still failed, the move bought nothing -- so undo it.
        // THIS restore is safe precisely because subtree_control did not get
        // set: the parent can still hold processes.
        if (!st) {
            char leaf_now[8192];
            long m = read_file(leaf_procs.c_str(), leaf_now, sizeof leaf_now);
            if (m > 0) {
                const char* line = leaf_now;
                while (line && *line) {
                    const char* end = std::strchr(line, '\n');
                    std::string pid(line, end ? static_cast<std::size_t>(end - line)
                                              : std::strlen(line));
                    if (!pid.empty()) (void)write_file(procs_path, pid.c_str());
                    line = end ? end + 1 : nullptr;
                }
            }
            ::rmdir(leaf_dir.c_str());
        }
    }

    if (!st) {
        pr.availability = Availability::unusable;
        // EBUSY even after the leaf move means something else holds this
        // cgroup, and the fix is on the launching side, not in claybin.
        pr.reason = st.error().sys_errno == EBUSY
                        ? "cgroup holds processes we cannot move; launch in a delegated "
                          "scope (systemd-run --user --scope) for cgroup limits"
                        : "cannot enable controllers in our subtree";
        return pr;
    }

    // it worked. confirm a child actually gets the controllers, using a scratch
    // cgroup that holds NO processes -- so removing it cannot fail and cannot
    // strand anything.
    std::string probe_dir = pr.own_path + "/.clay-probe";
    ::mkdir(probe_dir.c_str(), 0755);
    char child_ctl[512] = "";
    std::string cc = probe_dir + "/cgroup.controllers";
    read_file(cc.c_str(), child_ctl, sizeof child_ctl);
    if (::rmdir(probe_dir.c_str()) < 0) {
        // should be impossible: we never put a process in it. if it ever
        // happens, say so rather than leaving a stray cgroup behind silently.
        pr.reason = "probe cgroup could not be removed";
    }

    // report what the CHILD actually got, not what we asked for: a controller
    // the parent has may still not be delegable down, and claiming otherwise is
    // how a cpu quota silently does nothing.
    pr.memory = has_word(child_ctl, "memory");
    pr.pids = has_word(child_ctl, "pids");
    pr.cpu = has_word(child_ctl, "cpu");
    pr.io = has_word(child_ctl, "io");

    if (!pr.memory && !pr.pids) {
        pr.availability = Availability::unusable;
        pr.reason = "subtree_control accepted but no controllers appeared";
        return pr;
    }

    pr.availability = Availability::delegated;
    return pr;
}

Result<Group> create(const Probe& pr, const ResourceLimits& limits,
                     std::string_view name_hint) {
    if (pr.availability != Availability::delegated)
        return std::unexpected(Error{Errc::unsupported, pr.reason});

    const int hint_len = static_cast<int>(name_hint.size() > 32 ? 32 : name_hint.size());
    const int self_pid = static_cast<int>(::getpid());

    Group g;
    // the sandbox cgroup goes beside us, not beneath us.
    //
    // cgroup v2's no-internal-process rule means the cgroup we OCCUPY can never
    // have controllers enabled in its subtree while we are in it -- so a child
    // of it gets memory.max, pids.max and friends only if we first vacate, and
    // vacating is what caused the 330-deep runaway. a sibling under the same
    // delegating parent has the controllers already and needs no moving.
    //
    // pr.delegating_path is that parent when the probe had to relocate us, and
    // own_path otherwise, so this is correct in both shapes.
    const std::string& parent = pr.delegating_path.empty() ? pr.own_path : pr.delegating_path;

    // a FRESH directory, every time. EEXIST is a collision, never a reuse.
    //
    // this used to tolerate EEXIST and carry on with whatever was there, and the
    // name was unique per PROCESS, not per call. so:
    //
    //   - a process holding two groups at once -- a supervisor running two
    //     sandboxes -- got the SAME cgroup twice. the guests shared one memory
    //     pool, the second policy's limits overwrote the first's,
    //     Group::kill() on one killed both, and if the first Group died while
    //     the second was compiled but not yet spawned, its rmdir removed the
    //     second's cgroup and the second attach failed.
    //   - a directory that already had our name -- left by a dead process that
    //     had our pid (a claybin-run killed by a signal never runs ~Group), or
    //     made by a claybin in another pid namespace, where the same pid can be
    //     live -- was adopted with its old limits still in it. we only write
    //     the limits the policy sets, so a pids-only policy inherited a stale
    //     memory.max, and the guest could land beside processes still living
    //     in that cgroup.
    //
    // clay-<hint>-<pid> first, so `ls` still says which process owns a sandbox;
    // clay-<hint>-<pid>-<n> when that is taken. mkdir is the atomic
    // test-and-set: no counter, no lock, no state in the library, and correct
    // across threads and processes alike. the bound only caps the work if the
    // parent is somehow full of our names; then we fail, we do not spin.
    constexpr int kMaxNameAttempts = 1024;
    std::string fresh;
    for (int attempt = 0; attempt < kMaxNameAttempts && fresh.empty(); ++attempt) {
        char name[128];
        if (attempt == 0)
            std::snprintf(name, sizeof name, "clay-%.*s-%d", hint_len, name_hint.data(),
                          self_pid);
        else
            std::snprintf(name, sizeof name, "clay-%.*s-%d-%d", hint_len, name_hint.data(),
                          self_pid, attempt);
        std::string candidate = parent + "/" + name;
        if (::mkdir(candidate.c_str(), 0755) == 0)
            fresh = std::move(candidate);
        else if (errno != EEXIST)
            return std::unexpected(Error{Errc::io_error, "cgroup: mkdir", errno});
    }
    if (fresh.empty())
        return std::unexpected(Error{Errc::io_error, "cgroup: mkdir", EEXIST});

    // only now does g own a path, so no failure above can hand release() a
    // directory to rmdir -- least of all one that belongs to someone else. from
    // here on, every failure return leaves the rmdir to release(), once.
    g.path_ = std::move(fresh);

    // hold a directory fd: after a pivot_root the path is gone, but an fd on it
    // still works, and it also means the attach cannot be redirected by a
    // symlink swap between create and attach.
    g.fd_ = ::open(g.path_.c_str(), O_DIRECTORY | O_CLOEXEC);
    if (g.fd_ < 0) {
        // no rmdir here: returning destroys g, and its release() removes the
        // directory. a second rmdir by name could only hit a cgroup another
        // create() had made under that name in between, and it used to run
        // before errno was read, so its failure replaced open's.
        return std::unexpected(Error{Errc::io_error, "cgroup: open dir", errno});
    }

    char buf[32];
    auto set = [&](const char* file, std::uint64_t v) -> Status {
        std::snprintf(buf, sizeof buf, "%llu", static_cast<unsigned long long>(v));
        return write_file(g.path_ + "/" + file, buf);
    };

    // memory.high is independent of memory.max: a throttle without a kill is
    // a valid policy (and the only one it is safe to DEFAULT to), so it is
    // written whether or not a hard cap was asked for.
    if (pr.memory && !limits.memory_high.is_unlimited()) {
        if (auto st = set("memory.high", limits.memory_high.value()); !st)
            return std::unexpected(st.error());
    }

    if (pr.memory && !limits.memory.is_unlimited()) {
        if (auto st = set("memory.max", limits.memory.value()); !st)
            return std::unexpected(st.error());
        // without this, the guest can exceed its memory cap by swapping. a
        // memory limit that swap defeats is not a memory limit, so a failure
        // here is fatal rather than ignored -- the report would otherwise say
        // `strong` for a cap the guest can walk straight past.
        //
        // clang's -Wunused-value caught this: the first version discarded the
        // nodiscard Status from the unlimited branch while checking it in the
        // other, which is the inconsistency that lets a silent failure through.
        if (limits.memory_swap.is_unlimited()) {
            if (auto st = write_file(g.path_ + "/memory.swap.max", "0"); !st)
                return std::unexpected(st.error());
        } else if (auto st = set("memory.swap.max", limits.memory_swap.value()); !st) {
            return std::unexpected(st.error());
        }
    }

    if (pr.pids && !limits.pids.is_unlimited()) {
        if (auto st = set("pids.max", limits.pids.value()); !st)
            return std::unexpected(st.error());
    }

    // the cpu writes are fatal like the others, and for the same reason: the
    // caller reports cpu_limit as `strong` exactly when this returns a group.
    // these were discarded with (void), so a refused cpu.max -- an EINVAL,
    // the controller vanishing from subtree_control -- still produced a
    // report claiming a hard quota the kernel never held.
    if (pr.cpu && !limits.cpu_weight.is_unlimited()) {
        // cpu.weight is 1-10000; clamp rather than reject so a caller passing
        // a share count gets something sensible.
        std::uint64_t w = limits.cpu_weight.value();
        if (w == 0) w = 1;
        if (w > 10000) w = 10000;
        if (auto st = set("cpu.weight", w); !st) return std::unexpected(st.error());
    }

    // cpu.max is a HARD quota: "$MAX $PERIOD" microseconds of cpu per period.
    // this is the one that actually bounds a busy loop -- cpu.weight only
    // decides who wins when there is contention, so on an idle machine a
    // weight-limited guest still gets a whole core.
    if (pr.cpu && !limits.cpu_quota_percent.is_unlimited()) {
        std::uint64_t pct = limits.cpu_quota_percent.value();
        if (pct == 0) pct = 1;
        // a quota above the machine's whole capacity is not a cap at all, and
        // left unbounded kPeriod * pct wraps for a large enough pct -- into a
        // SMALL quota the caller never asked for. 1024 cores is far beyond any
        // host this runs on and keeps the product well inside 64 bits.
        constexpr std::uint64_t kMaxPct = 1024 * 100;
        if (pct > kMaxPct) pct = kMaxPct;
        constexpr std::uint64_t kPeriod = 100000;  // 100ms, the kernel default
        std::uint64_t quota = (kPeriod * pct) / 100;
        if (quota == 0) quota = 1000;
        char q[64];
        std::snprintf(q, sizeof q, "%llu %llu", static_cast<unsigned long long>(quota),
                      static_cast<unsigned long long>(kPeriod));
        if (auto st = write_file(g.path_ + "/cpu.max", q); !st)
            return std::unexpected(st.error());
    }

    return g;
}

Status Group::attach(int pid) const {
    if (fd_ < 0) return std::unexpected(Error{Errc::invalid_policy, "cgroup: no group"});
    int fd = ::openat(fd_, "cgroup.procs", O_WRONLY | O_CLOEXEC);
    if (fd < 0) return std::unexpected(Error{Errc::io_error, "cgroup: open procs", errno});
    char buf[32];
    int n = std::snprintf(buf, sizeof buf, "%d", pid);
    ssize_t w = ::write(fd, buf, static_cast<std::size_t>(n));
    int err = errno;
    ::close(fd);
    if (w < 0) return std::unexpected(Error{Errc::io_error, "cgroup: attach", err});
    return {};
}

Status Group::kill() const {
    if (fd_ < 0) return std::unexpected(Error{Errc::invalid_policy, "cgroup: no group"});
    int fd = ::openat(fd_, "cgroup.kill", O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return std::unexpected(Error{Errc::unsupported, "cgroup: no cgroup.kill", errno});
    ssize_t w = ::write(fd, "1", 1);
    int err = errno;
    ::close(fd);
    if (w < 0) return std::unexpected(Error{Errc::io_error, "cgroup: kill", err});
    return {};
}

bool Group::kill_supported() const {
    if (fd_ < 0) return false;
    return ::faccessat(fd_, "cgroup.kill", W_OK, 0) == 0;
}

void Group::release() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
    if (!path_.empty()) {
        // only succeeds once the cgroup is empty, which is what we want: a
        // still-running sandbox keeps its cgroup alive.
        ::rmdir(path_.c_str());
        path_.clear();
    }
}

}  // namespace clay::cgroup

#else

namespace clay::cgroup {
Probe probe() {
    Probe p;
    p.reason = "cgroups are linux-only";
    return p;
}
Result<Group> create(const Probe& p, const ResourceLimits&, std::string_view) {
    return std::unexpected(Error{Errc::unsupported, p.reason});
}
Status Group::attach(int) const {
    return std::unexpected(Error{Errc::unsupported, "cgroups are linux-only"});
}
Status Group::kill() const {
    return std::unexpected(Error{Errc::unsupported, "cgroups are linux-only"});
}
bool Group::kill_supported() const { return false; }
void Group::release() {}
}  // namespace clay::cgroup

#endif
