# the microvm backend

status: not built. `Isolation::microvm` exists in the policy type, and every
backend's `compile()` refuses it today. this doc says why we want it and what
it should do.

## why

every backend claybin has now runs the guest on the host's kernel. namespaces,
landlock, seccomp, cgroups, appcontainer and seatbelt are all rules the host
kernel enforces on itself. they are good walls, but they share one weakness:
a bug in the kernel is a bug in every wall at once.

the threat model in [design.md](design.md) says this plainly. kernel exploits
are out of scope for the process backend, and the guarantee report says
`host.kernel_isolation: none` on every platform, so nobody is misled.

that is fine for most use. it is not fine when:

- the code is actively hostile, not just buggy. an agent told to run a
  stranger's repo, a malicious npm postinstall, a prompt-injected command.
- the host matters a lot more than the task. a dev machine with ssh keys,
  cloud creds and a browser session.
- a seccomp profile can't be tight enough. `compiler()` has to allow a few
  hundred syscalls to run a real toolchain, and each one is kernel attack
  surface. linux ships local privilege escalations every year, and io_uring,
  netfilter, user namespaces and ebpf are where many of them come from.

a process sandbox cuts that surface down. it can't take it away. a vm can:
the guest gets its own kernel, so a kernel bug inside it only owns the
guest. to reach the host, the attacker has to break the hypervisor (kvm) and
the vmm (the userspace device model). that's a much smaller target, and it's
the boundary cloud providers use between tenants.

## what it will do

same input, stronger boundary. a caller writes the same `Policy` it writes
now and sets `isolation(Isolation::microvm)`. nothing else changes for them.

- **boot a small vm per spawn.** a minimal kernel, no init system, our own
  tiny pid 1 in the guest that sets things up and execs the command. it
  needs to start fast enough to sit behind a single shell command.
- **map the policy onto the vm**, not onto host namespaces:
  - filesystem grants become virtio-fs (or 9p) shares of exactly the granted
    paths, read-only where the policy says so. nothing else of the host exists
    in the guest.
  - network: none means no network device. a proxy policy means a vsock
    channel to the host-side proxy agentty already runs, so the same
    allowlist still applies.
  - memory and cpu limits become the vm's ram and vcpu count. these are hard
    limits by construction.
  - env, argv, cwd and stdio go over vsock.
- **keep the process walls inside the guest too.** the guest pid 1 can still
  apply landlock and seccomp to the command. that's defence in depth, and it
  costs almost nothing.
- **report honestly.** `host.kernel_isolation` becomes `isolated`, which is the
  only place that value is allowed. anything the vm can't do (say, a device the
  host lacks) is reported as degraded, same as every other backend.
- **refuse rather than fall back.** no kvm means `compile()` fails with the
  reason. it never quietly runs the command on the process backend.
  `HostCapabilities::kvm` already exists so that reason is real.

## what it will not do

- no images, no registry, no oci. the guest root is the host's own `/usr`,
  shared read-only, so tools are the same versions as outside.
- no long-lived vms or snapshots in the first version. one spawn, one vm.
- no gpu or usb passthrough.

## costs

- startup. a process sandbox spawns in milliseconds. a vm takes longer, even a
  small one. that's why process stays the default and microvm is for the
  postures that ask for it.
- memory per running command, for the guest kernel and page cache.
- a dependency. we'd need a vmm, which goes against "no dependency the user
  did not ask for", so it must be optional and picked up at runtime.
- file io through virtio-fs is slower than a bind mount. big builds will feel
  it.

## how, per platform

- **linux:** kvm. the candidates for the vmm are libkrun, firecracker and
  cloud-hypervisor. libkrun fits best: it's a library, not a daemon, it has
  virtio-fs and vsock built in, and it's made for running one process in a
  small vm. firecracker is the most battle-tested, but it's a separate binary
  driven over a socket and has no virtio-fs.
- **macos:** Hypervisor.framework, which libkrun already supports, so the
  linux work mostly carries over. `HostCapabilities::hypervisor` is already
  probed.
- **windows:** hyper-v, through the host compute apis. hardest of the three,
  and last.

## order of work

1. linux on libkrun, behind a build option. guest pid 1, virtio-fs shares,
   no network.
2. vsock proxy for the network allowlist.
3. guarantee report, conformance tests, and the escape corpus run inside the
   vm.
4. macos.
5. windows.

the escape corpus is the acceptance test. every attack that's `blocked` on the
process backend has to stay blocked, and the kernel-level ones should become
unreachable rather than just filtered.
