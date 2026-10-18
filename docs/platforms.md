# platform reality

the honest version, because a sandbox library that oversells its portability is
worse than one that only targets linux.

## what ports cleanly

the **policy algebra** is pure value types. no OS anywhere in it. `FsAuthority`,
`NetAuthority`, `ResourceLimits`, the lattice laws, the typestate, the guarantee
report: all of it compiles and tests identically on any platform with a c++23
compiler. that is most of the library by line count and essentially all of the
interesting design.

the **compile step** is a pure function of `(Policy, HostCapabilities)`, so a
new backend is a new `compile_for_X()` plus a new opcode set. nothing about the
front end changes.

## what does not port

### syscall filtering: linux only

seccomp has no equivalent anywhere else.

- **macOS** has no syscall filter available to unprivileged processes. seatbelt
  can filter some *operations* by name (`process-fork`, `process-exec`,
  `sysctl-read`), which is a fixed menu of MAC hooks -- not a programmable
  filter over syscall numbers and argument registers. claybin sets the ones a
  policy implies and reports `partial` at best, never `strong`.
- **windows** has Process Mitigation Policies, which are a fixed menu of
  hardening switches (no dynamic code, no child processes, binary signature
  requirements), not arbitrary syscall filtering.

so `SyscallPolicy` compiles to a handful of coarse operations off linux and the
report says so. that is not a gap to be papered over later; it is a real
difference in what the OS will do for you.

### the filesystem model differs, not just the API

this is the one that actually hurts.

- **linux landlock** and **macOS seatbelt** are both *path-prefix* models, so
  `FsAuthority`'s "grant a subtree, punch a hole" maps almost directly.
- **windows** is *ACL-on-object*. you do not grant "read `C:\workspace`
  recursively" to a process; you give the AppContainer's capability SID an ACE
  on specific objects. a recursive grant means walking and stamping DACLs, which
  is slow, mutates the host filesystem, and needs cleanup.

so `deny("/workspace/.git")` is one landlock rule on linux, one SBPL clause on
macOS, and a DACL edit on windows. same policy, three very different costs and
one of them has side effects on the host.

### resource limits

- **linux**: cgroup v2. the real thing.
- **windows**: job objects, genuinely comparable. memory, CPU, process count,
  all enforced per-job.
- **macOS**: rlimits only. no cgroup equivalent, so memory is `partial` forever.

windows is actually the *strongest* of the three here, which is a good reminder
that the ranking is per-capability, not per-OS.

## the matrix

what a policy compiles to, per capability, on a modern host. the linux column is
measured on this machine (landlock abi 10, cgroup v2 delegated); the macOS
column is measured on darwin 24 (`tests/macos_live_check.cpp` enters the
profile and asserts the walls hold); the windows column is measured on windows
11 insider (`tests/windows_live_check.cpp` creates the profile, stamps real
ACLs and spawns a real confined child).

| capability | linux | windows | macOS |
|---|---|---|---|
| filesystem read/write | **strong** (landlock + mount ns) | partial (AppContainer/DACL) | **strong** (seatbelt) |
| filesystem exec | **strong** | partial | **strong** (seatbelt) |
| network isolation | **strong** (netns) | **strong** (no net capability) | **strong** *denying*, partial *allow-listing* |
| process isolation | **strong** (user+pid ns) | **strong** (AppContainer) | partial (inherited profile, shared pid space) |
| syscall filter | **strong** (seccomp) | partial (mitigations) | **none** |
| memory limit | **strong** (cgroup2) | **strong** (job object) | partial (rlimit) |
| pid limit | **strong** (cgroup2) | **strong** (job object) | **advisory** (RLIMIT_NPROC is per-UID) |
| cpu limit | strong *if the cpu controller is delegated* | **strong** (job cpu rate, win8+) | partial (rlimit) |
| privilege drop | **strong** | **strong** (restricted token) | partial |
| device isolation | **strong** (/dev allowlist) | partial (object namespace) | partial |
| host kernel isolation | **none** | **none** | **none** |

that last row is `none` everywhere for the process backend, by definition. only
a microvm backend changes it.

four entries deserve a note because they surprised me:

- **windows job objects are genuinely as strong as cgroup v2** for memory, pids
  and cpu. windows is the *better* platform on that axis, which is a good
  reminder that the ranking is per-capability and not per-OS.
- **the linux cpu limit is conditional**, because distributions frequently do
  not delegate the `cpu` controller to user sessions even when they delegate
  `memory` and `pids`. claybin reports `none` with that exact reason rather than
  pretending a quota was applied.
- **macOS network isolation is two different answers, not one.** `(deny
  network*)` is a single rule the kernel enforces exactly, so denying the
  network outright is genuinely `strong` -- equal to an empty netns in what the
  guest can reach. an endpoint *allow-list* is `partial`, because seatbelt
  matches on the address and the name-to-address step happens in userspace
  where DNS can answer differently next time.
- **macOS pid limits are `advisory`, not `partial`.** RLIMIT_NPROC counts
  processes for the whole UID rather than for this process tree, so another
  terminal window moves the limit. that is not a boundary, and calling it
  `partial` would have overstated it.

## what "no syscall filter" costs

windows and macOS both report `partial` or `none` for `syscall.filter`, and it is
worth being precise about what that means rather than waving at it.

seccomp lets claybin say "this process may call `read`, and calling `ptrace`
kills it". windows Process Mitigation Policies are a fixed menu: no dynamic
code, no child processes, no non-microsoft DLLs, no extension points. useful, and
claybin sets the ones a policy implies -- a profile with no `fork`/`exec` maps
exactly onto `CHILD_PROCESS_RESTRICTED` -- but it cannot express an arbitrary
allow-list. so a program that needs "everything except these twelve syscalls"
is simply not expressible there.

the consequence for callers is concrete: `compile()` **refuses**
`Isolation::hardened_process` on both windows and macOS, because hardened means
every wall and one of them does not exist. that refusal is the feature. a
library that returned a weaker sandbox and let the caller find out later would
be worse than useless.

## so is it "easily cross-platform"?

**the API, yes. the security, no** — and pretending otherwise is the failure mode
this library was designed to avoid.

what makes it workable is that the difference is *reported rather than hidden*.
the same policy compiles everywhere, and `Compiled::guarantees` tells you
exactly which walls you actually got. a program that needs a syscall filter can
refuse to run on macOS instead of silently running unprotected.

that is what `Compiled::require()` is for:

```cpp
auto c = clay::compile(policy, clay::probe_host());
// on macOS this FAILS rather than running with no syscall filter
auto ok = c->require(Enforcement::strong, {CapId::fs_read, CapId::syscall_filter});
```

the portable *subset* is small: filesystem + process + resources. everything
beyond that is a per-platform decision the caller has to make explicitly.

## order of work

1. **linux first, properly.** it is the only platform where all the walls exist,
   so it is the only place the design can be validated end to end. *done.*
2. **windows second.** job objects and AppContainer are well documented and the
   model is genuinely strong; the filesystem translation is the real work.
   *done: compile step in `src/windows/compile.cpp`, apply step in
   `src/windows/spawn.cpp` (appcontainer profile + DACL/integrity grants,
   restricted token where the host proves it usable, job object, mitigation
   policies), live-checked in `tests/windows_live_check.cpp`.*
3. **macOS third.** seatbelt is deprecated-but-universal (chrome still uses it),
   undocumented, and the App Sandbox alternative needs entitlements and code
   signing, which rules out sandboxing arbitrary binaries. *done: compile step
   in `src/macos/compile.cpp`, apply step in `src/macos/spawn.cpp`.*

the backends are independent, so this order is a scheduling choice, not a
dependency chain.

## notes from writing the macOS backend

things that cost real time, recorded so the next person does not pay twice.

### SBPL is last-match-wins

landlock rules only ever *subtract*: a ruleset is a ceiling and order is
irrelevant. SBPL is the opposite -- rules are evaluated top to bottom and the
LAST match decides. so `(deny file-write* (subpath "/etc"))` placed *before*
`(allow file-write* (subpath "/"))` does nothing at all.

`emit order` in `compile.cpp` is therefore fixed and commented: version,
deny-default, prerequisites, grants shallow-to-deep, then denials. a grant that
carves a hole inside a wider grant has to come after it or the hole is dead.

### the root directory grant

a profile that grants `/usr`, `/System` and `/bin` but not `/` itself makes
every dynamically linked binary die with **SIGABRT before main()**, and the
kernel's error message names a line in its own SBPL prelude:

```
syntax error: expecting ')'
sbpl1:108:4: (defined? 'APFSIOC_GET_GRAFT_INFO)
```

which points at the profile's *syntax* and not at the missing grant, so it reads
as "claybin emitted bad SBPL". it did not. dyld stats `/` during startup and the
fix is one line:

```
(allow file-read* (literal "/"))
```

`literal`, emphatically not `subpath` -- `(subpath "/")` grants read on the
entire filesystem and silently turns every profile into an open door.

### the coarse file-write\*

landlock has thirteen separate filesystem bits; seatbelt has one `file-write*`
covering create, unlink, rename, truncate and chmod together. there is no way to
say "may create files here but not delete them".

the fold is therefore conservative in the one direction that matters: a coarse
operation is emitted only when the policy granted EVERY fine-grained right it
implies. a create-only grant degrades to read-only and the report says
`fs_write: partial`, rather than quietly handing out `unlink`.

### a unix socket is not "the network"

`unix_sockets()` sets a blanket `NetOps` bit. reading any blanket bit as "allow
all IP" would turn a policy asking for a local socket into one with full
internet access. the backend splits them, and `macos_backend_test` has a case
pinning it, because it is the most dangerous single mistranslation in the file.

### descriptors go up before the wall does

the fd shuffle happens *before* `sandbox_init`, which looks backwards. two
reasons: doing it after requires the profile to permit `open("/dev/null")` and
`dup2`, and -- more importantly -- the kernel writes its own rejection message
to stderr when a profile is refused. with stderr not yet redirected, that
message lands on the caller's terminal instead of in the pipe they supplied for
exactly this purpose.

## notes from writing the windows backend

recorded the same way, because windows cost the most debugging time per line
of code.

### the probe must be process-lifetime cached

the restricted-token + appcontainer child probe is **process-warmth
dependent** on some builds (insider 26300 measured): early calls in a process
report death, later ones -- after enough real spawns -- report success. a
`compile()` that re-probes per call can therefore see a verdict that
contradicts the caller's own measurement minutes earlier, and build a wall
that kills every guest with 0xC0000142 during ntdll init. the verdict is now
taken once, from the coldest call, in a function-local `const` static (a
magic static: thread-safe once-init, and the vendored-library lint rejects
both `<atomic>` and mutable statics).

the corollary: a probe verdict that overpromises is worse than none. the
probe child must run in the **exact production spawn shape** -- writable
command line (with `lpApplicationName=nullptr` createprocess parses and
modifies it, so a string literal there is an access violation),
CREATE_SUSPENDED, assigned to a job before resume, PROC_THREAD_ATTRIBUTE_
HANDLE_LIST, the real restricted list (BUILTIN\Users + Everyone, not the
near-no-op user-SID list) -- and must survive **three** runs, because one
pass means nothing on a host where the combo is flaky.

### graceful stop cannot reach grandchildren

an adopted child carries no job handle in the host's process abstraction, so
a graceful stop is TerminateProcess on the LEADER only. a grandchild
(`ping` inside `cmd`) survives it and keeps the stdout pipe open -- and the
post-exit drain then waits for the grandchild to finish naturally (measured:
19.9 s for `ping -n 21`; after the fix: 0.35 s). the exec loop therefore
fires the sandbox's exact tree kill (TerminateJobObject) BEFORE the graceful
stop, and keeps the grace window only as a fallback. "ask first, then kill"
is a posix shape; on windows the order is "kill the tree, then flush".

### /proc and /dev are policy roots without filesystems

the portable policy vocabulary binds procfs and devfs; windows has neither.
mapping the roots to a real directory would be a GRANT -- the opposite of
what a policy asking for dev_fs("/dev") means -- so they resolve to a
virtual-object-namespace sentinel and the grant loop skips them: nothing to
stamp an ACL on, and the appcontainer's default-deny is the isolation those
roots asked for.

### profiles are state on disk, and the appx service wedges

CreateAppContainerProfile leaves a directory under %LOCALAPPDATA%\Packages
keyed by the profile name (claybin suffixes a hash of the capability set, so
different capability sets never share one). two operational notes: a probe
that crashes between create and delete leaves the profile behind, and the
next run must tolerate ERROR_ALREADY_EXISTS by deriving the existing SID
rather than failing; and on insider builds the appx deployment service can
wedge after hundreds of create/delete cycles (0x800706C6,
RPC_S_SERVER_UNAVAILABLE), which looks like a code failure but is host
state -- a reboot clears it, a service restart often does not.
