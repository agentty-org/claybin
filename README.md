# claybin

a drop-in replacement for [bubblewrap](https://github.com/containers/bubblewrap),
and the authority compiler underneath it.

```sh
# same flags, same resulting tree. the /lib symlinks are not decoration:
# a dynamically linked binary needs its loader, and without them BOTH
# commands fail with ENOENT -- which is the first thing you would have hit.
bwrap        --unshare-all --ro-bind /usr /usr \
             --symlink usr/lib /lib --symlink usr/lib /lib64 --symlink usr/bin /bin \
             --proc /proc --dev /dev --tmpfs /tmp --chdir / -- /bin/ls /
claybin-run  --unshare-all --ro-bind /usr /usr \
             --symlink usr/lib /lib --symlink usr/lib /lib64 --symlink usr/bin /bin \
             --proc /proc --dev /dev --tmpfs /tmp --chdir / -- /bin/ls /
```

(on debian and ubuntu the loader lives in `/usr/lib/x86_64-linux-gnu`, so bind
`/lib` and `/lib64` from the host instead of symlinking them.)

the difference is what happens underneath. bubblewrap gives you a mount
namespace; claybin gives you a mount namespace **and** a landlock ruleset **and**
a seccomp filter compiled from the same description, plus a report of exactly
which walls the host could actually build.

see [docs/bubblewrap.md](docs/bubblewrap.md) for the porting guide.

it owns no event loop. supervising a sandboxed process is an event-loop job, and
that job belongs to [jaal](https://github.com/agentty-org/jaal) — see
[docs/jaal.md](docs/jaal.md).

> **Status: early — read this before using it for anything that matters.**
>
> claybin is days old. what follows is the honest state, not a pitch.
>
> **works and is tested.** the mount model, landlock (including abi 6 scoping),
> seccomp with argument filtering, cgroup2 memory/pids/cpu limits, the policy
> algebra, and seccomp-notify brokering. the macOS port (seatbelt + rlimits,
> live-checked on darwin 24) and the Windows port (appcontainer + restricted
> token + job object, live-checked on windows 11 insider; see
> docs/platforms.md "notes from writing the windows backend") are applied and
> measured on their hosts rather than promised. 19 test binaries, an escape corpus of
> 47 named attacks that spawns real processes and tries to break out (46
> blocked, 0 escaped, 1 not applicable on this kernel), a differential BPF
> interpreter, 1.28M fuzzed policies, and 57 conformance checks against real
> bubblewrap. CI runs gcc, clang+libc++, asan+ubsan, and a lane that fails if
> the sandboxing tests skip themselves.
>
> **not tested.** aarch64 and riscv64 have never executed — the aarch64 syscall
> tables are cross-checked against the kernel's own headers, which is not the
> same thing. only two linux kernels have ever run this (6.8 and 7.2); macOS
> and Windows each ran the port's own live checks on their respective hosts
> (darwin 24, windows 11 insider 26300) but no CI lane exercises either.
>
> **known open.** `bind_fd` has a TOCTOU window between resolving the descriptor
> and mounting its path. it is not closable from inside claybin — both
> path-free bind routes are scoped to the mount namespace the fd came from, and
> the kernel rules are pinned in `mount_test` so a future relaxation is
> noticed. bubblewrap has the same window.
>
> **nobody has reviewed this but me.** that is the single biggest reason not to
> trust it yet. one focused session on it found six real bugs, including a
> seccomp bypass (ioctl's request is 32 bits, so a filter comparing 64 was
> defeated by setting a high bit), three symlink escapes where a caller-supplied
> path could write outside the sandbox, and a capability probe that reported
> "user namespaces: yes" on hosts where the uid_map write fails. all fixed, each
> with a test that fails when the fix is reverted — but a defect-discovery rate
> like that is the signal, and there is no reason to think that session was the
> last one.
>
> if you want a sandbox in production today, use
> [bubblewrap](https://github.com/containers/bubblewrap). it is a decade old,
> audited, and runs under every flatpak on earth. use claybin if you want the
> stronger seccomp and landlock story, can tolerate finding bugs, and are
> willing to report them.

## the library underneath

```cpp
#include <claybin/policy/policy.hpp>

using namespace clay;
using namespace clay::literals;

auto policy = Policy<Draft>{}
    .ro_bind("/usr", "/usr")        // build a tree, bubblewrap-style
    .bind("/workspace", "/work")
    .deny("/work/.git")             // ...and punch a landlock hole in it
    .tmpfs("/tmp", 64_MB)
    .memory(512_MB)
    .syscall_profile(profiles::compiler())
    .seal();                        // consumes the draft; nothing can widen it

auto compiled = compile(policy, probe_host());
auto ok = compiled->require(Enforcement::strong, {CapId::fs_read, CapId::syscall_filter});
```

## why it is different

- **two independent filesystem walls.** every bind emits a landlock rule, so a
  path is checked by the mount namespace *and* by landlock. an escape has to
  beat both, and they fail in different directions.
- **authority is a lattice.** composition is `meet`. there is no way to widen a
  sealed policy, because the widening operator does not exist.
- **proof-carrying.** `Witness<Cap>` can only be minted by the backend that
  installed the mechanism. no backend is allowed to pretend.
- **it refuses rather than degrades.** bubblewrap has
  `--not-a-security-boundary`; claybin fails instead.
- **fast by phase split.** all thinking happens ahead of the fork and compiles
  into a POD plan. the post-fork path is raw syscalls, zero allocation,
  async-signal-safe.
- **zero deps.** no libseccomp, no libcap, no libmount. the BPF is a balanced
  interval tree, `O(log n)` per guest syscall instead of a linear chain.

see [docs/design.md](docs/design.md), and
[docs/platforms.md](docs/platforms.md) for what does and does not port off
linux.

## build

no dependencies beyond a c++23 compiler and cmake.

```sh
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j
ctest --test-dir build --output-on-failure
```

## license

MIT
