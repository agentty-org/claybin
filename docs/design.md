# claybin design

an authority compiler. it computes what a process may do and installs the
mechanisms that enforce it. it owns no loop — see [jaal.md](jaal.md) for why
that is a deliberate boundary and not a missing feature.

## the one idea

authority is an algebra, not a pile of flags. every policy component is a
**bounded meet-semilattice**:

- `T::nothing()` is bottom (no authority at all)
- `T::everything()` is top (whatever the host can express)
- `a.meet(b)` is the greatest lower bound
- `a.subsumes(b)` is the partial order `a >= b`

composition of two policies is `meet`. that is the whole security model:

    compose(A, B) <= A   and   compose(A, B) <= B

there is no `operator|` in the public api. you cannot accidentally widen a
sandbox by combining profiles. adding authority is only possible while a policy
is still a `Draft`, where it is explicit user intent.

## laws we actually test

for every lattice type, with random samples:

- idempotent: `a & a == a`
- commutative: `a & b == b & a`
- associative: `(a & b) & c == a & (b & c)`
- decreasing: `a & b <= a` and `a & b <= b`
- order agrees with meet: `a.subsumes(b)` iff `a & b == b`
- bottom absorbs: `a & nothing() == nothing()`
- top is identity: `a & everything() == a`

if a backend type breaks a law, the sandbox has a privilege bug. so the laws are
tests, not comments.

## the cross-platform problem, and the type-theoretic answer

bubblewrap's model is mount namespaces, which only linux has. so "cross-platform
bubblewrap" cannot mean "mounts everywhere". what saves it is that a mount plan
is a **free structure** — an ordered sequence whose only composition is
concatenation — and a free structure is defined by its interpretations.

claybin gives `MountPlan` two:

    to_tree(plan)       a filesystem construction     linux only
    to_authority(plan)  an FsAuthority                everywhere

on linux we evaluate both, and they become two independent walls that check each
other. on a host with no mount namespaces only the second exists.

that raises the real question, and it is the one most portable sandbox libraries
get wrong by not asking: **is the second interpretation faithful to the first?**

it depends on the plan, and it is decidable by looking at it. the deciding
property is *remapping*:

- `--ro-bind /usr /usr` says "this path keeps its name". access control can say
  exactly that. `Fidelity::exact`.
- `--tmpfs /tmp` becomes "you may write here", losing *starts empty* and
  *size-capped*. sound but weaker: `Fidelity::approximate`.
- `--ro-bind /opt/app /app` says "this path gets a NEW name". no access-control
  system can rename a path. `Fidelity::impossible`.

fidelity is itself a meet — a plan is only as faithful as its least faithful
mount — so it composes like everything else here. `compile()` consults it and
**refuses** on a mountless host rather than silently handing back less, naming
the offending mount in the error.

the soundness obligation is that `to_authority` never grants a path
`to_tree` would not have made visible. that is a property, so it is
property-tested against random plans rather than asserted in a comment
(`tests/mount_algebra_test.cpp`).

the practical payoff is in `shapes.hpp`: `system_ro`, `builder` and `strict` are
written with same-path binds only, so they are `exact` and compile to a real
sandbox on any backend. `app_container` remaps, so it is linux-only *by
construction* and says so at compile time instead of at a user's runtime.

## typestate

illegal states are unrepresentable, enforced by phantom phase tags:

    Policy<Draft>            mutable, can grant, cannot run
      | seal() &&            consumes the draft
    Policy<Sealed>           immutable, meet-able, hashable, auditable
      | compile(backend)     fallible, allocates, does all the thinking
    Plan                     POD. no pointers to heap. memcpy-safe across fork

the chain ends at `Plan` on purpose. a `Plan` is a value you can apply as many
times as you like; it does not own a process, so claybin never has to reap one.
process ownership is the loop's job.

builder methods are rvalue-qualified, so a draft threads linearly through the
chain instead of being aliased and mutated behind your back.

## proof-carrying guarantees

`Witness<Cap>` has a private constructor. only a backend that actually installed
the mechanism can mint one. so this is not a claim, it is evidence:

    auto g = sandbox.guarantees();
    if (auto w = g.witness<cap::NetworkIsolation>(); w && w->strength() >= Enforcement::strong)
        ...

`Enforcement` is `none | advisory | partial | strong | isolated`. a backend that
cannot enforce something reports `none`. it never pretends. this is the
difference between api portability and **security portability**: the same policy
compiles everywhere, and the report tells you what you actually got.

## phase split (this is where the speed comes from)

everything that can fail, allocate, take a lock, or call into libc lives
**before** the fork. it compiles into a `Plan`: a flat byte arena of ops and
nul-terminated strings, no heap pointers, trivially copyable.

after `clone()` the child runs `plan.apply()`, which is a loop of raw syscalls.
no malloc, no locks, no libc paths that touch the allocator, no unbounded work.
async-signal-safe by construction, because there is nothing else in there.

cost of a spawn ends up being the kernel's cost plus a few microseconds, and the
policy work is paid once even if you spawn ten thousand children from the same
compiled plan.

note what is NOT here: waiting. `plan.apply()` runs in the child and returns or
execs. reaping the child, pumping its output and timing it out belong to whoever
owns the event loop.

## seccomp

we emit classic BPF ourselves. sorted syscall numbers are folded into
**intervals of equal action**, then laid out as a balanced binary search tree.
~400 allowed syscalls collapse to ~60 intervals, ~6 levels deep, 4 instructions
executed per level. libseccomp's chain is a linear scan; ours is `O(log n)` and
that cost is paid on every single syscall the guest makes.

the emitter is pure and portable: policy in, instruction vector out. no kernel
headers needed to build or test it. only the install step is linux. tests run a
tiny BPF interpreter and differential-check the tree against a reference linear
lookup over every syscall number, so the fast path is verified, not assumed.

## backends

    Policy<Sealed> ──> Security IR ──> backend
                                        linux   : user/mount/pid/net ns, landlock,
                                                  seccomp, cgroup v2, caps, pidfd
                                        windows : appcontainer, restricted token,
                                                  job object, mitigation policies
                                        macos   : seatbelt profile, rlimits
                                        microvm : kvm / hyper-v / virtualization.fx

the IR is the contract. backends only ever *lose* expressiveness, and when they
do they say so in the guarantee report.

## threat model

attacker controls: the executable, argv, env, stdin, any file we expose, network
responses, and all child processes. they can run arbitrary native code and any
syscall we allow.

attacker must not: read the host filesystem outside grants, reach host
credentials or sockets, gain capabilities, signal host processes, exceed
resource limits, or talk to unintended hosts.

kernel exploits are explicitly **out of scope** for the process backend. that is
what the microvm backend is for, and the guarantee report says
`HostKernelIsolation: none` on the process backend so nobody gets confused.
see [microvm.md](microvm.md) for the plan.

## non-goals

- not a container runtime. no images, no registries, no orchestration.
- no oci, no daemon, no root helper.
- no dependency the user did not ask for.
- **no event loop.** no reactor, no thread pool, no process supervision. a
  security library that grows a loop ends up with a worse one than a library
  written for the job, and its races get hidden behind the security story. the
  supervisor is a jaal program; see [jaal.md](jaal.md).
