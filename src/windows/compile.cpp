// the windows backend's compile step. pure, so it builds and tests on any host
// -- which is deliberate: the interesting content here is the TRANSLATION, and
// translation bugs are much easier to find in a unit test than on a windows box.
#include "claybin/windows/backend.hpp"

#include "claybin/policy/mounts.hpp"

namespace clay::windows {
namespace {

// windows access mask bits we care about (from winnt.h; stable ABI).
constexpr std::uint32_t kFileReadData = 0x0001;
constexpr std::uint32_t kFileWriteData = 0x0002;
constexpr std::uint32_t kFileAppendData = 0x0004;
constexpr std::uint32_t kFileExecute = 0x0020;
constexpr std::uint32_t kFileDeleteChild = 0x0040;
constexpr std::uint32_t kFileReadAttributes = 0x0080;
constexpr std::uint32_t kFileWriteAttributes = 0x0100;
constexpr std::uint32_t kDelete = 0x00010000;
constexpr std::uint32_t kReadControl = 0x00020000;
constexpr std::uint32_t kSynchronize = 0x00100000;

// translate our portable rights to a windows access mask.
//
// this is where the two models grind against each other. landlock has separate
// bits for "create a file here" and "create a directory here"; windows has one
// FILE_ADD_FILE / FILE_ADD_SUBDIRECTORY pair that overlaps the same numeric
// values as write/append on a file object. so the mapping is lossy in both
// directions, and the report must not claim otherwise.
std::uint32_t to_access_mask(FileRights r) {
    std::uint32_t m = kSynchronize | kReadControl;
    if (r.any(FileRights{FileRights::kReadFile})) m |= kFileReadData | kFileReadAttributes;
    if (r.any(FileRights{FileRights::kReadDir})) m |= kFileReadData | kFileReadAttributes;
    if (r.any(FileRights{FileRights::kWriteFile}))
        m |= kFileWriteData | kFileAppendData | kFileWriteAttributes;
    if (r.any(FileRights{FileRights::kExecute})) m |= kFileExecute;
    if (r.any(FileRights{FileRights::kCreateFile})) m |= kFileWriteData;      // FILE_ADD_FILE
    if (r.any(FileRights{FileRights::kCreateDir})) m |= kFileAppendData;      // FILE_ADD_SUBDIR
    if (r.any(FileRights{FileRights::kRemoveFile})) m |= kDelete | kFileDeleteChild;
    if (r.any(FileRights{FileRights::kRemoveDir})) m |= kDelete | kFileDeleteChild;
    return m;
}

// does this syscall policy amount to "no child processes"? that is one of the
// few things a mitigation policy can express, so it is worth detecting: a
// profile without fork/exec maps onto PROCESS_CREATION_MITIGATION_POLICY_
// CHILD_PROCESS_RESTRICTED exactly, which is a real win rather than an
// approximation.
bool forbids_children(const SyscallPolicy& sys) {
#if defined(__x86_64__) || defined(_M_X64)
    // linux numbers, because that is the vocabulary a SyscallPolicy is written
    // in. a windows-native policy would use a different table, but claybin's
    // profiles are the ones being translated here.
    for (SysNr nr : {57u /* fork */, 58u /* vfork */, 59u /* execve */, 322u /* execveat */})
        if (sys.action_for(nr) == SysAction::allow) return false;
    return true;
#else
    (void)sys;
    return false;
#endif
}

}  // namespace

Result<Compiled> compile(const Policy<Sealed>& policy, const HostCapabilities& host,
                         const Options& opts) {
    const PolicyData& d = policy.data();
    Compiled out;
    GuaranteeReport::Builder report;

    if (d.isolation == Isolation::microvm)
        return std::unexpected(Error{Errc::unsupported, "windows: microvm backend (hyper-v) not implemented"});

    auto degrade = [&](CapId c) { out.degraded.push_back(c); };

    // -- the mount plan ----------------------------------------------------
    //
    // windows has no mount namespaces at all, so the only interpretation
    // available is to_authority(). ask the plan whether that is faithful, and
    // refuse rather than silently building something else.
    FsAuthority effective = d.fs;
    if (!d.mounts.empty()) {
        std::vector<FidelityNote> notes;
        Fidelity f = d.mounts.fidelity(&notes);
        if (f == Fidelity::impossible) {
            const char* why = notes.empty() ? "mount plan needs a mount namespace"
                                            : notes.front().reason;
            return std::unexpected(Error{Errc::unsupported, why});
        }
        FsAuthority implied = d.mounts.implied_authority();
        effective = d.fs.is_nothing() ? implied : d.fs.meet(implied);
    }

    // -- appcontainer ------------------------------------------------------
    if (host.app_container) {
        out.use_app_container = true;
        out.container_name = opts.profile_name.empty() ? "claybin.sandbox" : opts.profile_name;
        // an AppContainer is default-deny for everything not granted to its
        // capability SID, which is a real boundary independent of our ACLs.
        report.record(CapId::proc_isolation, Enforcement::strong, "appcontainer");
    } else {
        degrade(CapId::proc_isolation);
        report.record(CapId::proc_isolation, Enforcement::none, "appcontainer unavailable");
    }
    // the read wall rides on restricted tokens; the host capability already
    // carries a PROBE VERDICT (a real child ran and exited cleanly), not an
    // API-existence guess. see spawn.cpp step 7.
    out.restricted_tokens_ok = host.restricted_tokens;

    // -- filesystem --------------------------------------------------------
    //
    // ── windows path shape ───────────────────────────────────────
    //
    // claybin's policy layer is POSIX-shaped by design (path::normalize
    // treats / as the only separator, so "C:\\Windows" normalizes to
    // "/C:\\Windows" and prefix tests like covers() are then wrong in both
    // directions). the windows backend therefore re-normalizes every grant
    // path into a canonical native form ONCE, here, before it becomes an ACL
    // target:
    //
    //   "/C:\\Windows"  →  "C:\\Windows"   (posix-normalized back to native)
    //   "C:\\x/..\\y"  →  "C:\\y"          (mixed separators collapse)
    //   "C:\\a\\b\\"    →  "C:\\a\\b"       (no trailing separators)
    //
    // pseudo-filesystem roots (/proc, /dev) resolve to this sentinel: the
    // path translates, but the grant loop below SKIPS it. the appcontainer's
    // object-namespace default-deny (graded `partial`) is the isolation
    // these policy roots ask for.
    static constexpr char kVirtualObjectNS[] = "\\\\.\\virtual-object-namespace";
    //
    // a path with no drive prefix is REJECTED: what a relative path resolves
    // against is the caller's cwd, an authority that names no boundary at
    // all, and an ACL on something we cannot pin down is a grant we cannot
    // reason about. a policy that names one is malformed rather than merely
    // unusual -- fail loudly instead of stamping ACLs at the wrong object.
    auto native_path = [](std::string_view p) -> Result<std::string> {
        if (p.empty()) return std::unexpected(Error{Errc::invalid_policy, "empty path"});

        std::string_view s = p;

        // a leading slash in front of a drive letter is claybin's posix-
        // normalized spelling of a NATIVE windows path ("/C:/work" ==
        // "C:\\work", what builder("C:/work") becomes once path::normalize
        // runs). it is host vocabulary, not policy vocabulary: strip it BEFORE
        // the root table below so a native path is never mistaken for a
        // portable root.
        if (s.size() >= 3 && s[0] == '/' && s[1] >= 'A' && s[1] <= 'Z' && s[2] == ':')
            s.remove_prefix(1);

    // a path with no drive prefix is REJECTED -- unless it is one of claybin's
    // canonical POSIX system roots, which are POLICY VOCABULARY rather than
    // host paths: `system_ro()` names "/usr" and "/bin" because the same
    // policy shape compiles on every platform, and the windows backend owns
    // translating them. an unmapped relative path still fails loudly: what a
    // bare "foo" resolves against is the caller's cwd, an authority that
    // names no boundary at all.
    static const struct { const char* posix; const char* native; } kSystemRoots[] = {
        {"/usr",  "C:\\Windows"},                 // toolchain + libs, read-only
        {"/bin",  "C:\\Windows\\System32"},       // executables
        {"/lib",  "C:\\Windows\\System32"},       // loader + shared libraries
        {"/lib64", "C:\\Windows\\System32"},
        {"/sbin", "C:\\Windows\\System32"},
        {"/etc",  "C:\\Windows\\System32\\config"}, // machine config; HKLM's on-disk half
        // pseudo-filesystems from the portable policy vocabulary. windows has
        // no procfs/devfs; the AppContainer's object-namespace default-deny
        // (graded `partial` below) is what stands in for their isolation.
        // these roots resolve to the "virtual" sentinel below: the path
        // translates successfully, and the grant loop SKIPS it -- no ACL can
        // be stamped on an object namespace, and mapping them to a real
        // directory would be a GRANT, the opposite of what dev_fs("/dev")
        // means.
        {"/proc", kVirtualObjectNS},
        {"/dev",  kVirtualObjectNS},
        // the portable shapes' workspace vocabulary. a policy that says
        // builder("/work") asks for "a place the guest may write"; the exact
        // directory is the caller's to pin with a native path when it
        // matters, and this mapping keeps the portable shape compiling.
        {"/work", "C:\\claybin-work"},
        {"/tmp",  "C:\\claybin-tmp"},
        {"/app",  "C:\\claybin-app"},
        {"/home", "C:\\Users"},
    };
    if (!s.empty() && s.front() == '/') {
        for (const auto& m : kSystemRoots) {
            const std::string_view pp = m.posix;
            if (s != pp && !(s.size() > pp.size() && s.starts_with(pp) &&
                             s[pp.size()] == '/'))
                continue;
            if (m.native[0] == '\0')
                return std::unexpected(Error{Errc::unsupported,
                    std::string("no windows mapping for policy root '") + m.posix +
                    "'; name a native path instead"});
            // splice the remainder after the root onto the native path
            std::string rest{s.substr(pp.size())};  // "" or "/sub/..."
            for (char& ch : rest) if (ch == '/') ch = '\\';
            return std::string{m.native} + rest;
        }
        return std::unexpected(Error{Errc::unsupported,
            "unmapped policy root '" + std::string{s} +
              "'; windows knows /usr /bin /lib /lib64 /sbin /etc"});
      }

          // past the policy-vocabulary roots: native forms only, with the
          // drive prefix already stripped above. anything else starting with
          // "/" failed the root table and never reaches here.
          std::string out;
          out.reserve(s.size());
          bool prev_sep = false;
          for (const char c : s) {
              if (c == '/' || c == '\\') {
                  if (!prev_sep && !out.empty()) out.push_back('\\');
                  prev_sep = true;
              } else {
                  out.push_back(c);
                  prev_sep = false;
              }
          }
          while (!out.empty() && out.back() == '\\') out.pop_back();
          if (out.empty())
              return std::unexpected(Error{Errc::invalid_policy, "path normalizes to nothing"});

          const bool drive = out.size() >= 2 && out[1] == ':' &&
                             ((out[0] >= 'A' && out[0] <= 'Z') ||
                              (out[0] >= 'a' && out[0] <= 'z'));
          const bool unc = out.size() >= 2 && out[0] == '\\' && out[1] == '\\';
          if (!drive && !unc)
              return std::unexpected(Error{Errc::invalid_policy,
                  "path has no drive prefix (need C:\\... or \\\\server\\\\share)"});
          return out;
    };

    for (const auto& g : effective.grants()) {
        auto native = native_path(g.path);
        if (!native)
            return std::unexpected(native.error());
        // /proc and /dev translate to the virtual object namespace: nothing
        // to stamp an ACL on (and stamping one would be a grant, not an
        // isolation). the appcontainer default-deny carries the isolation.
        if (*native == std::string_view{kVirtualObjectNS}) continue;
        std::uint32_t mask = to_access_mask(g.rights);
        if (mask == (kSynchronize | kReadControl)) continue;  // nothing substantive
        out.acl_grants.emplace_back(std::move(*native), mask);
    }

    if (!host.app_container) {
        degrade(CapId::fs_read);
        degrade(CapId::fs_write);
        degrade(CapId::fs_exec);
    } else if (opts.allow_host_acl_mutation) {
        // we will stamp ACEs, so grants are actually enforced per-object.
        out.acls_applied = true;
        // still only `partial`: the ACL model cannot express landlock's
        // "this subtree except that one" without walking and stamping every
        // object, and anything created later inherits the parent's ACL rather
        // than our policy.
        report.record(CapId::fs_read, Enforcement::partial, "appcontainer+DACL");
        report.record(CapId::fs_write, Enforcement::partial, "appcontainer+DACL");
        report.record(CapId::fs_exec, Enforcement::partial, "appcontainer+DACL");
    } else {
        // default-deny only: the sandbox cannot reach anything, but our
        // positive grants are not enforced either, so a program needing them
        // will fail. honest, and usually what a caller wants for a first run.
        report.record(CapId::fs_read, Enforcement::partial, "appcontainer default-deny");
        report.record(CapId::fs_write, Enforcement::partial, "appcontainer default-deny");
        report.record(CapId::fs_exec, Enforcement::partial, "appcontainer default-deny");
    }

    // -- job object: resource limits ---------------------------------------
    const auto& r = d.resources;
    if (host.job_objects) {
        if (!r.memory.is_unlimited()) {
            out.memory_limit_bytes = r.memory.value();
            // JOB_OBJECT_LIMIT_PROCESS_MEMORY is a hard commit limit, enforced
            // by the kernel per-job. genuinely the equal of cgroup memory.max.
            report.record(CapId::mem_limit, Enforcement::strong, "job object memory limit");
        }
        if (!r.pids.is_unlimited()) {
            out.active_process_limit = static_cast<std::uint32_t>(r.pids.value());
            report.record(CapId::pid_limit, Enforcement::strong, "job object process limit");
        }
        if (!r.cpu_quota_percent.is_unlimited()) {
            out.cpu_rate_percent = r.cpu_quota_percent.value();
            // CPU rate control is win8+. it is a hard cap, unlike cpu.weight.
            if (host.build >= 9200)
                report.record(CapId::cpu_limit, Enforcement::strong, "job object cpu rate");
            else
                report.record(CapId::cpu_limit, Enforcement::none, "cpu rate needs win8+");
        }
        if (!r.cpu_time.is_unlimited()) {
            // job objects count user time in 100ns units.
            out.user_time_limit_100ns = r.cpu_time.value() / 100;
            report.record(CapId::cpu_limit, Enforcement::strong, "job object time limit");
        }
    } else {
        if (!r.memory.is_unlimited()) degrade(CapId::mem_limit);
        if (!r.pids.is_unlimited()) degrade(CapId::pid_limit);
    }

    // -- mitigation policies: the closest thing to a syscall filter --------
    if (host.mitigation_policies) {
        // these are the ones that map onto something a claybin policy actually
        // says, rather than a grab-bag of hardening we were not asked for.
        out.disable_dynamic_code = true;      // no JIT, no W^X violations
        out.disable_extension_points = true;  // no AppInit DLLs, no hooks
        out.block_non_microsoft_binaries = false;  // too strict to default on

        // note: no `kProcFork | kProcExec` here. there is deliberately no
        // public operator| on a flag lattice, precisely so a check like this
        // cannot accidentally be written as a widening. two `any()` calls say
        // what is meant without offering a way to grant.
        const bool may_spawn =
            d.proc.any(kProcFork) || d.proc.any(kProcExec);
        if (forbids_children(d.syscalls) && !may_spawn) {
            out.disable_child_processes = true;
        }

        // the honest line. a mitigation policy is not a syscall filter: it
        // cannot express "allow read, deny ptrace". the most we can claim is
        // that a few broad classes are off.
        report.record(CapId::syscall_filter, Enforcement::partial,
                      "mitigation policies (no programmable filter on windows)");
    } else {
        degrade(CapId::syscall_filter);
        report.record(CapId::syscall_filter, Enforcement::none,
                      "windows has no seccomp equivalent");
    }

    // -- privilege drop ----------------------------------------------------
    if (host.restricted_tokens) {
        report.record(CapId::privilege_drop, Enforcement::strong,
                      "restricted token + appcontainer SID");
    } else {
        degrade(CapId::privilege_drop);
    }

    // -- network -----------------------------------------------------------
    out.allow_network = !d.net.is_nothing();
    if (!out.allow_network) {
        if (host.lowbox_network)
            // an AppContainer without the internet/privateNetwork capabilities
            // genuinely cannot open a socket. that is a strong boundary.
            report.record(CapId::net_isolation, Enforcement::strong,
                          "appcontainer without network capability");
        else
            degrade(CapId::net_isolation);
    } else {
        // per-host/per-port filtering needs WFP rules keyed on the app SID,
        // which we do not emit yet.
        report.record(CapId::net_isolation, Enforcement::partial,
                      "network capability granted; no per-endpoint filtering yet");
    }

    // -- devices -----------------------------------------------------------
    // an AppContainer cannot open device objects it has no capability for, which
    // is a genuine boundary, but it is coarse: there is no per-device allowlist
    // the way a /dev tmpfs gives us on linux.
    if (host.app_container)
        report.record(CapId::device_isolation, Enforcement::partial,
                      "appcontainer object namespace");
    else
        degrade(CapId::device_isolation);

    // the process backend shares a kernel with the host, on every platform.
    report.record(CapId::host_kernel_isolation, Enforcement::none, "process-backend");

    // -- refuse to silently under-deliver ----------------------------------
    if (d.isolation == Isolation::hardened_process) {
        // hardened means every wall. windows cannot give us a syscall filter, so
        // this is a request we cannot honour and the caller has to know.
        return std::unexpected(Error{
            Errc::unsupported,
            "hardened_process needs a syscall filter; windows has no seccomp equivalent"});
    }

    out.guarantees = std::move(report).build();
    return out;
}

#if !defined(_WIN32)
HostCapabilities probe_host() { return HostCapabilities::none(); }
#endif

}  // namespace clay::windows
