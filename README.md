# Multi-Arch EDR & Rootkit Hook Detector

A single Linux binary that audits a live system for the seven most common ways
an EDR product (or a rootkit) can intercept activity:

| Layer | What's checked | Source of truth |
|---|---|---|
| Userspace inline patches | A curated set of hot functions in `libc`, `libssl`, `libcrypto`, `libpthread`, `libdl`, `libpam`, `libaudit` | on-disk `.so` bytes vs. `/proc/PID/mem` |
| Env preload | `LD_PRELOAD`, `/etc/ld.so.preload` | filesystem / environment |
| eBPF programs | Every hook-capable BPF program (KPROBE / TRACING / LSM / TRACEPOINT / PERF_EVENT / SYSCALL) | `bpf()` syscall, BTF, `BPF_TASK_FD_QUERY`, `BPF_LINK_GET_NEXT_ID` |
| Non-BPF kprobes | Every kprobe/kretprobe, including those from SystemTap or custom LKMs | `/sys/kernel/debug/kprobes/list` |
| uprobes | Every uprobe, regardless of attachment method | `tracefs/uprobe_events` |
| ftrace hooks | Functions hooked via ftrace with a custom trampoline (rootkit ftrace-abuse) + the global `current_tracer` state | `tracefs/enabled_functions`, `tracefs/current_tracer` |
| Active LSMs | The list and order of loaded LSMs; unknown names get flagged | `/sys/kernel/security/lsm` |
| Tainted kernel modules | Loaded modules with `O` (out-of-tree), `E` (unsigned), or `F` (force-loaded) flags | `/proc/modules` |

Supports **ARM64 (AArch64)** and **x86-64** binaries. The architecture
is detected per-library from each ELF's `e_machine`, so a single scanner binary
handles mixed environments. The CLI emits either human-readable text or a
single valid JSON document for machine consumption.

## Quickstart

```bash
make
sudo ./edr_hooks_check          # full system scan
./edr_hooks_check --self        # current process only, no root needed
sudo ./edr_hooks_check --json   # machine-readable output
```

### CLI options

| Flag | Meaning |
|---|---|
| `-p, --pid <PID>` | Scan only the given process |
| `-l, --lib <PATH>` | Restrict userspace inspection to a specific library |
| `-s, --self` | Self-scan (current PID only); no root required |
| `-v, --verbose` | Per-source listings (kprobe addresses, function names, …). Use twice for extra detail |
| `-x, --hexdump` | Show on-disk vs. in-memory instruction bytes for each detected userspace hook |
| `-j, --json` | Emit the entire report as a single JSON object |
| `-h, --help` | Show usage and exit |

### Exit code

- `0` — no userspace hooks and no kernel-side hook signals detected
- `1` — at least one of: userspace patched function, eBPF hook program, kprobe, uprobe, or ftrace trampoline found

## Detection mechanisms

### Userspace inline patches

For each monitored library loaded by each scanned process, the scanner:

1. Reads the on-disk `.so` and parses the ELF dynamic symbol table to locate every monitored function's virtual address.
2. Reads a fixed-size window from both the file (`pread`) and `/proc/PID/mem` at `base_addr + (vaddr − preferred_base)`.
   - **ARM64**: 8 fixed-width instructions (32 bytes).
   - **x86-64 / i386**: 64 bytes (≈10–15 variable-length instructions), decoded by a built-in length decoder.
3. If the bytes differ, runs arch-specific scoring heuristics that filter known benign patterns — PLT stubs, syscall trampolines, tail calls, function epilogues, IFUNC dispatch, thin wrappers ≤ 32 bytes — and classifies the remainder as **LOW / MEDIUM / HIGH** confidence.

### eBPF kernel hooks

Runs system-wide, talks to `bpf()` directly. For each loaded BPF program:

1. `BPF_PROG_GET_NEXT_ID` loops until `ENOENT`.
2. `BPF_PROG_GET_FD_BY_ID` + `BPF_OBJ_GET_INFO_BY_FD` retrieves type, name, UID, `attach_btf_id`.
3. Attach target is resolved via three independent paths:
   - **vmlinux BTF** (`BPF_BTF_GET_FD_BY_ID` on ID 1, parsing the type section) — needed for fentry/fexit/LSM whose target is stored as a BTF type ID.
   - **`BPF_TASK_FD_QUERY`** walking `/proc/*/fd` — catches BCC-style perf_event attachments where the program is reachable via an open file descriptor but has no `bpf_link` object.
   - **`BPF_LINK_GET_NEXT_ID`** + `BPF_OBJ_GET_INFO_BY_FD` — catches pinned links (incl. raw_tracepoint / perf_event variants with their concrete attach point).

Only hook-capable types are reported: `KPROBE`, `TRACEPOINT`, `RAW_TRACEPOINT`, `RAW_TP_WRITABLE`, `PERF_EVENT`, `TRACING`, `LSM`, `SYSCALL`. Pure-networking types (XDP, SOCKET_FILTER, SCHED_CLS, …) are intentionally ignored.

### Non-BPF kprobes

`/sys/kernel/debug/kprobes/list` enumerates every active kprobe/kretprobe in the kernel — including those registered by non-BPF tools like SystemTap or by custom kernel modules. Each line is parsed into `{address, type (k/r/p), symbol+offset, active, optimized, ftrace_based}`. Requires root + debugfs mounted.

### uprobes

`tracefs/uprobe_events` lists every uprobe regardless of how it was attached (BPF, perf, manual write). Tried under both `/sys/kernel/tracing/` (modern) and `/sys/kernel/debug/tracing/` (legacy debugfs mount).

### ftrace hooks

`tracefs/enabled_functions` lists every kernel function currently hooked via ftrace. Lines containing `tramp:` indicate a real code redirection (rootkit ftrace abuse is a popular LKM hooking technique because it bypasses direct function patching); lines without are passive tracers. Only trampoline-bearing entries count toward the hook total.

`tracefs/current_tracer` is read separately — if it's anything other than `nop`, the scanner emits a warning entry because kernel-wide function tracing being on is unusual on a production system.

### Active LSMs

`/sys/kernel/security/lsm` is a comma-separated list of activated LSMs (in load order). Known good names are accepted silently; anything else is flagged. The full list is always emitted in JSON mode so machine consumers can verify ordering.

### Tainted kernel modules

`/proc/modules` is parsed for the trailing parenthesised taint flags. The scanner classifies each module as some combination of:

- `O` = out-of-tree
- `E` = unsigned
- `F` = force-loaded
- `P` = proprietary

Out-of-tree + unsigned + forced modules are flagged as worth investigating (a malicious LKM is almost always all three). Proprietary alone is informational (covers legit vendor drivers).

## Output

### Text mode (with `-v`)

```
========================================================
  Multi-Arch EDR Hook Detector (ARM64 + x86 / x86-64)
========================================================

[+] No /etc/ld.so.preload

[*] Scanning eBPF kernel hooks...
  security_file_open                  [TRACING]        prog=falco_filopen
  do_unlinkat                         [KPROBE]         prog=kp_unlink
    2 kernel hook(s) found  (out of 38 eBPF program(s) seen)

[*] Scanning kprobes...
  ffffffff8108a2c0   k   __x64_sys_open+0x0 [FTRACE]
  ffffffff810b5450   r   __x64_sys_kill+0x0
    2 kprobe(s) registered (2 active)

[*] Scanning uprobes...
[+] No uprobes registered

[*] Scanning ftrace hooks...
    14 ftrace hook(s), 0 with custom trampoline — run with -v for the list

[*] Active LSMs...
  capability
  yama
  apparmor
  bpf

[*] Scanning kernel modules...
  nvidia                          taint=[OE] out-of-tree UNSIGNED
  vboxdrv                         taint=[OE] out-of-tree UNSIGNED
    187 module(s) loaded, 2 flagged (out-of-tree / unsigned / forced)


Scanning processes...

[!] PID 1234 (sshd): 2 hook(s)

========================================================
SUMMARY
========================================================
Processes scanned:           42
Processes w/ userland hooks: 1
Userspace hooks:             2
eBPF kernel hooks:           2
Active kprobes:              2
uprobes:                     0
ftrace trampoline hooks:     0
Unknown LSMs:                0
Out-of-tree/unsigned mods:   2
--------------------------------------------------------
Total signals:               8

[!] Suspicious activity found — investigate above
    Run with -v for the full per-source listings
    Run with -x to see userland instruction hexdumps
========================================================
```
## License

See `LICENSE`.
