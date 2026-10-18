// claybin: the windows backend.
//
// this file exists to prove the IR was designed right, and to be honest about
// where it is not. it compiles a sealed policy to windows primitives:
//
//   AppContainer         a capability SID; the process runs with a token that
//                        has no access to anything not granted to that SID
//   restricted token     drops groups and privileges from the token
//   Job Object           memory, cpu and process-count limits. genuinely the
//                        equal of cgroup v2 here, sometimes better.
//   mitigation policies  a fixed menu (no dynamic code, no child processes,
//                        signature requirements), NOT arbitrary syscall filtering
//
// THE HONEST PART, up front. windows differs from linux in two ways that no
// amount of API design hides:
//
// 1. there is no syscall filter. seccomp has no windows equivalent available to
//    a normal process. Process Mitigation Policies are a menu of hardening
//    switches, not a programmable filter. so SyscallPolicy compiles to a subset
//    of those switches and the report says `partial` at best, `none` usually.
//
// 2. the filesystem model is ACL-on-object, not path-prefix. linux landlock
//    says "this subtree, these rights" in one call. windows says "this object's
//    DACL grants this SID these rights", per object. so a recursive grant means
//    walking the tree and stamping ACEs, which (a) is slow, (b) MUTATES THE HOST
//    FILESYSTEM, and (c) needs cleaning up afterwards.
//
// (b) is the important one. claybin's whole premise is that a policy is a
// description with no side effects until it is applied to a child. on windows a
// filesystem grant has a side effect on the host, so this backend refuses to do
// it implicitly: the caller must opt in with `allow_host_acl_mutation`, and if
// they do not, filesystem grants report `partial` (enforced by the AppContainer's
// default deny, not by our grants) rather than `strong`.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "claybin/core/error.hpp"
#include "claybin/core/witness.hpp"
#include "claybin/policy/policy.hpp"

namespace clay::windows {

// what this host can do. the windows analogue of HostCapabilities, probed the
// same way and just as unwilling to guess.
struct HostCapabilities {
    bool app_container{false};     // win8+; the main sandbox primitive
    bool job_objects{false};       // nt-era, always present in practice
    bool nested_jobs{false};       // win8+; without it a job inside a job fails
    bool mitigation_policies{false};  // win8+
    bool restricted_tokens{false};
    bool wfp{false};               // windows filtering platform, for network
    bool lowbox_network{false};    // appcontainer network capability control
    std::uint32_t build{0};        // major build number, for feature gates

    static HostCapabilities none() { return {}; }

    static HostCapabilities modern_windows() {
        HostCapabilities h;
        h.app_container = h.job_objects = h.nested_jobs = true;
        h.mitigation_policies = h.restricted_tokens = true;
        h.wfp = h.lowbox_network = true;
        h.build = 22000;
        return h;
    }
};

// the options that change what this backend is ALLOWED to do, as opposed to
// what it is able to do. defaults are the conservative ones.
struct Options {
    // permit stamping ACEs onto host filesystem objects to implement grants.
    // off by default: it mutates state outside the sandbox, which every other
    // claybin backend never does. with it off, filesystem enforcement comes
    // only from the AppContainer's default-deny and reports `partial`.
    bool allow_host_acl_mutation{false};

    // an AppContainer profile name. a stable name means a stable capability SID,
    // so grants persist across runs -- convenient, but it also means two
    // sandboxes sharing a name share authority. unnamed (the default) derives a
    // fresh one per sandbox.
    std::string profile_name{};
};

// a compiled windows sandbox. the analogue of Plan, but not a byte arena: the
// win32 API takes structs and handles, not a syscall stream, so there is nothing
// to serialize and no fork to survive.
struct Compiled {
    // ---- appcontainer ----
    bool use_app_container{false};
    std::string container_name;
    // capability SIDs to grant, as strings. deliberately a small set: each one
    // is a broad grant, so they are listed rather than computed.
    std::vector<std::string> capabilities;

    // ---- job object limits ----
    std::uint64_t memory_limit_bytes{0};   // 0 = none
    std::uint32_t active_process_limit{0}; // 0 = none
    std::uint64_t cpu_rate_percent{0};     // 0 = none; job object CPU rate control
    std::uint64_t user_time_limit_100ns{0};

    // ---- the read wall's gate ----
    // copied from host.restricted_tokens, which PROBED rather than assumed:
    // several insider builds accept CreateRestrictedToken and then kill
    // every child during ntdll init, so only a host that ran a real child
    // under a restricted token and saw it exit cleanly gets this wall.
    bool restricted_tokens_ok{false};

    // ---- mitigation policies ----
    bool disable_dynamic_code{false};
    bool disable_child_processes{false};
    bool disable_win32k{false};          // no gdi/user32 syscalls
    bool block_non_microsoft_binaries{false};
    bool disable_extension_points{false};

    // ---- filesystem ----
    // paths the sandbox may read/write, already resolved. only meaningful when
    // Options::allow_host_acl_mutation is set; otherwise informational, and the
    // report says so.
    std::vector<std::pair<std::string, std::uint32_t>> acl_grants;
    bool acls_applied{false};

    // ---- network ----
    bool allow_network{false};

    GuaranteeReport guarantees;
    std::vector<CapId> degraded;
};

// compile for windows. pure: no handles are created, nothing is applied. that
// keeps it testable on a linux box, which is how this file is developed and how
// its tests run in CI.
Result<Compiled> compile(const Policy<Sealed>& policy, const HostCapabilities& host,
                         const Options& opts = {});

// probe the running system. returns none() off windows.
//
// the WINDOWS version caches its verdict for the process lifetime (first
// call wins). the restricted+appcontainer child probe is process-warmth
// dependent on some insider builds -- re-probing per compile() call can
// return a verdict that contradicts the caller's earlier measurement and
// produce spawns that die. see spawn.cpp cached_host_probe().
HostCapabilities probe_host();

// ---- the apply step -------------------------------------------------------
//
// everything impure lives in src/windows/spawn.cpp, guarded by _WIN32, for the
// same reason the linux and macos backends split compile from apply: the
// translation is testable anywhere, the application is not. on linux the
// kernel does the isolating in the child after fork; on windows the walls are
// stamped onto the process AT CREATION -- token, job, mitigation policies are
// CreateProcess arguments, not things a child can do to itself afterwards --
// so there is no fork-and-apply here: spawn() builds the process in the
// parent, fully confined before its first instruction runs, and the caller
// adopts it. the child-side async-signal-safety rules of the other backends
// simply do not arise.

struct Spawned {
    int pid{-1};
    // The process HANDLE, already open. The caller OWNS it: it is the waitable
    // exit (signalled when the process ends, level-triggered) and the reap
    // source (GetExitCodeProcess). Closing it does NOT end the child; that is
    // the job's business. nullptr only on failure, which never reaches a
    // caller because failure is an error return.
    void* process{nullptr};
    // The job object handle, already open. The caller OWNS it: closing it is
    // the kill switch (KILL_ON_JOB_CLOSE takes the whole tree down, and a
    // grandchild cannot escape a job the way it can escape a process group).
    // nullptr when no job was applied (never, when the host probed healthy).
    void* job{nullptr};
};

// create the sandboxed process. mirrors clay::macos::spawn() structurally, so
// an embedder's spawn path reads the same on all three platforms.
//
// `fds` maps CALLER handles onto child descriptors -- on windows the parent
// side of a pipe is a HANDLE, not an int, so the map is void* where the other
// backends say int. each mapped handle is duplicated inheritable here and the
// duplicate closed after the child has its copy; the caller's original is
// untouched. `stdin_fd` -2 opens the NUL device in the child, -1 inherits.
struct SpawnRequest {
    const char* program{nullptr};
    const char* const* argv{nullptr};
    // Full environment for the child, or nullptr to inherit ours unchanged.
    // The block is built and sorted here: CreateProcess wants a case-
    // insensitively sorted double-NUL-terminated block and a caller that
    // guesses at that order gets silently-dropped variables.
    const char* const* envp{nullptr};

    struct FdMap {
        void* parent{nullptr};   // caller-side HANDLE
        int child_fd{-1};        // 0 = stdin, 1 = stdout, 2 = stderr
    };
    static constexpr int kMaxFdMaps = 8;
    FdMap fds[kMaxFdMaps]{};
    int fd_count{0};

    // -2 means the NUL device, -1 means inherit. same sentinels as Command.
    static constexpr int kDevNull = -2;
    int stdin_fd{-1};
    int stdout_fd{-1};
    int stderr_fd{-1};

    std::string workdir{};
};

// returns in the parent only. unlike the posix backends there is no child-side
// exit protocol (kExitPlanFailed 126/127): every failure mode here is visible
// in the parent BEFORE the target program runs, so a failed spawn is an error
// return, never a child that half-started unconfined. no supervision: polling,
// reaping and teardown stay with the caller, which holds the returned job.
// takes Compiled by value: the ACL pass may have to degrade acls_applied when
// the host refuses the stamping, and the report stays honest about it.
Result<Spawned> spawn(Compiled c, const SpawnRequest& req);

}  // namespace clay::windows
