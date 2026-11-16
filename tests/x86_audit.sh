#!/bin/sh
# audit the x86_64 and i386 syscall profiles against the kernel's own headers.
#
# the i386 profile is a second, hand-written table for the same sandbox, and
# hand copies drift: when it was added it was missing kill, utimensat and the
# timer calls that x86_64 allows. so every number in both profiles is resolved
# through <asm/unistd_64.h> and <asm/unistd_32.h>, and the two ABIs must agree
# BY NAME, except for the reviewed differences listed below.
#
# also, as in aarch64_audit: a number that names no syscall, or a forbidden
# syscall allowed anywhere, fails.
#
# usage: x86_audit.sh <path-to-clay_dump_x86>
set -e

DUMP="${1:-}"
if [ -z "$DUMP" ] || [ ! -x "$DUMP" ]; then
    echo "skip x86_audit: no dump binary (pass \$<TARGET_FILE:clay_dump_x86>)"
    exit 0
fi
H64=/usr/include/asm/unistd_64.h
H32=/usr/include/asm/unistd_32.h
for h in "$H64" "$H32"; do
    if [ ! -r "$h" ]; then
        echo "skip x86_audit: $h not readable"
        exit 0
    fi
done

OUT=$(mktemp)
trap 'rm -f "$OUT"' EXIT
"$DUMP" > "$OUT" || { echo "FAIL x86_audit: dump failed"; exit 1; }

python3 - "$H64" "$H32" "$OUT" <<'PY'
import re, sys, collections

def table(path):
    t = {}
    for line in open(path):
        m = re.match(r'#define __NR_(\w+)\s+(\d+)\s*$', line)
        if m:
            t[int(m.group(2))] = m.group(1)
    return t

names = {"x86_64": table(sys.argv[1]), "i386": table(sys.argv[2])}

FORBIDDEN = {
    'ptrace', 'mount', 'umount', 'umount2', 'pivot_root', 'chroot', 'unshare',
    'setns', 'bpf', 'perf_event_open', 'init_module', 'delete_module',
    'finit_module', 'kexec_load', 'kexec_file_load', 'reboot', 'setfsuid',
    'setfsgid', 'setfsuid32', 'setfsgid32', 'open_by_handle_at',
    'process_vm_readv', 'process_vm_writev', 'pidfd_getfd', 'userfaultfd',
    'io_uring_setup', 'add_key', 'request_key', 'keyctl', 'syslog', 'acct',
    'swapon', 'swapoff', 'quotactl', 'clone3', 'iopl', 'ioperm', 'vm86',
    'vm86old', 'modify_ldt', 'socketcall',
}

# i386 spells some calls differently. compare on the x86_64 name.
ALIAS = {
    'mmap2': 'mmap', 'fcntl64': 'fcntl', '_llseek': 'lseek', 'stat64': 'stat',
    'lstat64': 'lstat', 'fstat64': 'fstat', 'fstatat64': 'newfstatat',
    'ugetrlimit': 'getrlimit', '_newselect': 'select', 'sendfile64': 'sendfile',
    'truncate64': 'truncate', 'ftruncate64': 'ftruncate', 'statfs64': 'statfs',
    'fstatfs64': 'fstatfs', 'fadvise64_64': 'fadvise64', 'sigreturn': 'rt_sigreturn',
    'eventfd': 'eventfd2',
}
for n in ('getuid', 'getgid', 'geteuid', 'getegid', 'setuid', 'setgid', 'chown',
          'fchown', 'lchown', 'getgroups', 'setgroups', 'setresuid', 'getresuid',
          'setresgid', 'getresgid', 'setreuid', 'setregid'):
    ALIAS[n + '32'] = n
for n in ('pselect6', 'ppoll', 'io_pgetevents', 'recvmmsg', 'mq_timedsend',
          'mq_timedreceive', 'semtimedop', 'rt_sigtimedwait', 'futex',
          'sched_rr_get_interval', 'utimensat', 'clock_getres', 'clock_nanosleep'):
    ALIAS[n + '_time64'] = n
for n in ('clock_gettime', 'clock_settime', 'clock_adjtime', 'timer_gettime',
          'timer_settime', 'timerfd_gettime', 'timerfd_settime'):
    ALIAS[n + '64'] = n

# reviewed differences between the ABIs. each one is a deliberate choice, not
# drift; adding to this set is the review.
I386_ONLY = {
    # 32-bit-only calls with no x86_64 counterpart of that name
    'waitpid', 'signal', 'sigaction', 'sigprocmask', 'sigsuspend', 'sigpending',
    'nice', 'stime', 'readdir', 'mmap', 'ipc', 'socketcall', 'select', 'time',
    'utime', 'getpgrp', 'pause', 'alarm',
    # i386 manages TLS with these; x86_64 uses arch_prctl
    'set_thread_area', 'get_thread_area',
}
X86_64_ONLY = {
    'arch_prctl',  # i386: set_thread_area
    'newfstatat',  # i386: fstatat64
}
I386_ONLY_KILL = {
    'umount',      # the old i386 spelling of umount2, which both kill
}

rows = collections.defaultdict(lambda: collections.defaultdict(dict))
for line in open(sys.argv[3]):
    abi, prof, act, nr = line.split()
    rows[abi][prof][int(nr)] = act

fail = []
for abi in ("x86_64", "i386"):
    for prof, tbl in rows[abi].items():
        for nr, act in tbl.items():
            name = names[abi].get(nr)
            if name is None:
                if act in ("ALLOW", "ARGS", "NOTIFY"):
                    fail.append(f"{abi} {prof}: nr {nr} is permitted but names no syscall")
                continue
            if name in FORBIDDEN and act in ("ALLOW", "ARGS", "NOTIFY"):
                fail.append(f"{abi} {prof}: forbidden {name} ({nr}) is {act}")

def by_name(abi, prof):
    out = {}
    for nr, act in rows[abi][prof].items():
        name = names[abi].get(nr)
        if name is None:
            continue
        key = ALIAS.get(name, name) if abi == "i386" else name
        if act in ("ALLOW", "ARGS", "NOTIFY"):
            out[key] = act
    return out

# base() is a building block and the two files split it differently; parity
# is checked on the profiles a host actually applies.
for prof in ("compiler", "compiler_with_network"):
    n64, n32 = by_name("x86_64", prof), by_name("i386", prof)
    exists32 = {ALIAS.get(n, n) for n in names["i386"].values()}
    for name in sorted(set(n64) - set(n32)):
        if name in exists32 and name not in X86_64_ONLY:
            fail.append(f"{prof}: x86_64 allows {name}, i386 doesn't")
    for name in sorted(set(n32) - set(n64)):
        if name not in I386_ONLY:
            fail.append(f"{prof}: i386 allows {name}, x86_64 doesn't")
    # the killed set must match too: a call killed on one ABI and merely
    # refused on the other is the same drift, just quieter.
    def killed(abi):
        out = set()
        for nr, act in rows[abi][prof].items():
            name = names[abi].get(nr)
            if name and act == "KILL":
                out.add(ALIAS.get(name, name) if abi == "i386" else name)
        return out
    k64, k32 = killed("x86_64"), killed("i386")
    for name in sorted(k64 - k32):
        if name in exists32:
            fail.append(f"{prof}: x86_64 kills {name}, i386 doesn't")
    for name in sorted(k32 - k64):
        if name not in I386_ONLY_KILL:
            fail.append(f"{prof}: i386 kills {name}, x86_64 doesn't")

if fail:
    print("FAIL x86_audit:")
    for f in fail:
        print("    " + f)
    sys.exit(1)

total = sum(len(t) for a in rows.values() for t in a.values())
print(f"ok x86_audit ({total} entries over 2 ABIs resolved through the kernel "
      f"headers; i386 and x86_64 agree by name)")
PY
