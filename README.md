# Multi-Arch EDR & Rootkit Hook Detector

A single Linux binary that audits a live system for the most common ways
an EDR product (or a rootkit) can intercept activity:

| Layer | What's checked | Source of truth |
|---|---|---|
| Userspace inline patches | A curated set of hot functions in `libc`, `libssl`, `libcrypto`, `libpthread`, `libdl`, `libpam`, `libaudit` | on-disk `.so` bytes vs. `/proc/PID/mem` |
| GOT / PLT hijacks | The same curated functions, but imported via the GOT of every loaded module — caught even when the function body is untouched | ELF `JUMP_SLOT`/`GLOB_DAT` relocations vs. live slot value in `/proc/PID/mem` |
| Loader injection | `LD_PRELOAD`, `LD_AUDIT`, target-root `/etc/ld.so.preload`, and direct loader `--preload`/`--audit` arguments | `/proc/PID/environ`, `/proc/PID/cmdline`, `/proc/PID/root/etc/ld.so.preload` |
| eBPF programs | Attached hook-capable BPF programs, distinguished from merely-loaded programs | `bpf()` syscall, BTF, `BPF_TASK_FD_QUERY`, every current `bpf_link` hook variant |
| Non-BPF kprobes | Every kprobe/kretprobe, including those from SystemTap or custom LKMs | `/sys/kernel/debug/kprobes/list` |
| uprobes | Tracefs-registered uprobe events; other attachment methods explicitly remain incomplete | `tracefs/uprobe_events` |
| ftrace hooks | IPMODIFY / direct-call redirection signals, separate trampoline metadata, and global `current_tracer` state | `tracefs/enabled_functions`, `tracefs/current_tracer` |
| Kernel integrity | Critical syscall entries, x86 IDT/ARM64 vector targets, and live LSM callback ownership/targets | running-kernel BTF, `/proc/kallsyms`, read-only `/proc/kcore` |
| VDSO tampering | Per-process `[vdso]` pages checked against a trusted ABI-specific image, or an ABI/size-group majority without one | trusted baseline or cross-process `/proc/PID/mem` comparison |
| Active LSMs | The list and order of loaded LSMs; unknown names get flagged | `/sys/kernel/security/lsm` |
| Tainted kernel modules | Loaded modules with `O` (out-of-tree), `E` (unsigned), or `F` (force-loaded) flags | `/proc/modules` |

Supports **ARM64 (AArch64)**, **x86-64** and **i386** target ELF images. The architecture
is detected per-library from each ELF's `e_machine`, so a single scanner binary
handles mixed environments. The CLI emits either human-readable text or a
valid JSON document for machine consumption (one document per line in watch mode).

## Quickstart

```bash
make
sudo ./edr_hooks_check          # full system scan
./edr_hooks_check --self --scope userspace  # own process; VDSO still uses system-wide peers
sudo ./edr_hooks_check --json   # machine-readable output
sudo ./edr_hooks_check -p 1234 --watch 5 --json  # periodic NDJSON
```

### CLI options

| Flag | Meaning |
|---|---|
| `-p, --pid <PID>` | Select a process for inline, GOT, and preload checks |
| `-l, --lib <PATH>` | Match a path/name substring for inline libraries and GOT importing modules; preload and VDSO checks retain their scope |
| `-s, --self` | Select the current PID for inline, GOT, and preload checks |
| `--scope <NAME>` | `all` (default), `userspace`, or `kernel` |
| `--baseline-root <DIR>` | Use a separately protected root tree as the trusted userspace/VDSO reference |
| `--policy <PATH>` | Load tab-delimited glob allowlist rules |
| `--profile <NAME>` | `default` leaves unknown LSMs/tainted modules informational; `strict` makes them signals |
| `--watch <SEC>` | Repeat complete snapshots; JSON output becomes one self-contained object per line (NDJSON) |
| `-v, --verbose` | Per-source listings (kprobe addresses, function names, …). Use twice for extra detail |
| `-x, --hexdump` | Show on-disk vs. in-memory instruction bytes for each detected userspace hook; enables verbose output |
| `-j, --json` | Emit the entire report as a single JSON object |
| `-h, --help` | Show usage and exit |

`userspace` runs preload, inline, GOT, and VDSO checks. VDSO comparison always
uses system-wide peers, including when a PID or library is selected. `kernel`
runs system-wide eBPF, kprobe, uprobe, ftrace, syscall dispatch, LSM, and module checks. PID/library
selectors are rejected with `--scope kernel`; `--self` and `--pid` cannot be
combined. An unprivileged all-process userspace request falls back to the
scanner's PID, which is recorded in the JSON scope.

Each userspace pass confirms `/proc/PID/stat` start time before and after its ELF reads so PID reuse or exit is marked incomplete. Watch mode repeats full, independently parseable reports because an in-place memory patch can change without a maps or filesystem event.

### Exit code

- `0` — no hook signals detected with complete coverage of the requested scope
- `1` — at least one of: active loader injection, userspace/baseline mismatch, GOT/PLT hijack, attached eBPF hook, kprobe, uprobe, ftrace redirection, syscall-table redirection, or VDSO anomaly found

  (Unknown LSMs and tainted modules are informational under the default profile and signals under `--profile strict`.)
- `2` — the request was invalid, or at least one requested source was unavailable, incomplete, or unsupported and no hook finding took precedence

## Detection mechanisms

### Userspace inline patches

For each monitored library loaded by each scanned process, the scanner:

1. Opens the mapped library through `/proc/PID/map_files`, falling back to the target-root path only when its device/inode matches the maps record. The descriptor stays open through ELF parsing and baseline byte reads. Selects monitored symbol names independently of the file-access path. This works through `/proc/PID/map_files` handles, recognizes both SONAME (`libc.so.6`) and legacy dentry (`libc-2.x.so`) forms, and includes pthread/libdl functions exported by libc since glibc 2.34.
2. Reads a fixed-size window from both the file (`pread`) and `/proc/PID/mem` at `base_addr + (vaddr − preferred_base)`.
   - **ARM64**: 8 fixed-width instructions (32 bytes).
   - **x86-64 / i386**: 64 bytes (≈10–15 variable-length instructions), decoded by a built-in length decoder.
3. Any unexplained byte difference is a **LOW**-confidence integrity signal; arch-specific control-flow scoring raises likely redirects to **MEDIUM / HIGH** confidence. The scoring recognises full-range trampolines that begin with no relative branch: `push imm; ret` on i386/x86-64, `mov r64, imm64; jmp r64` on x86-64, and `movz/movk…; br Xn` on ARM64.

With `--baseline-root DIR`, each mapped target is paired with `DIR` plus its absolute process path. Both complete files are SHA-256 hashed. A mismatch is a high-confidence image-integrity signal, and symbols/code bytes then come from the trusted copy. Missing or geometrically incompatible references make coverage incomplete instead of falling back to a potentially replaced live file. Populate the baseline offline from the same OS/container image and protect it separately from the scanned root.

ABI-specific VDSO references use `DIR/vdso/MACHINE-CLASS-DATA-OSABI-ABIVERSION-FLAGS-LENGTH.bin`; capture their exact bytes from a known-good matching kernel.

### Loader injection

For every selected userspace process, the scanner checks initial `LD_PRELOAD` and `LD_AUDIT` entries, the target root's `/etc/ld.so.preload`, and direct dynamic-loader invocations using `--preload` or `--audit`. Separator-only values are ignored. These are active interception configurations, so they count as signals unless policy allows them.

### Policy and profiles

Policy files contain tab-separated `allow<TAB>kind-glob<TAB>subject-glob[<TAB>detail-glob]` records. Blank lines and `#` comments are accepted. Kinds are `baseline`, `preload`, `loader`, `inline`, `got`, `ebpf`, `kprobe`, `uprobe`, `ftrace`, `vdso`, `kernel_table`, `idt`, `vector`, `lsm_hook`, `lsm`, and `module`. Fields use `fnmatch(3)` glob semantics. An allow rule changes signal counts and exit status, but never hides missing-source or parse coverage. JSON retains allowed records; text shows them with `-v`.

For example, these rules allow one module family, a development interposer, and one observer's target family:

```text
allow	module	nvidia	*
allow	preload	/usr/lib/libasan.so	LD_PRELOAD
allow	ebpf	observe_*	security_*
```

### GOT / PLT hijacks

Inline patching is not the only way to intercept a call: overwriting a Global Offset Table entry reroutes every call site through the PLT without touching a single byte of the target function, so the inline check above can't see it. For each loaded module instance (the main executable and every `.so`), restricted to the importing module path when `--lib` is set, the scanner:

1. Parses the module's `JUMP_SLOT` / `GLOB_DAT` relocations (RELA on x86-64/ARM64, REL on i386) and keeps those whose symbol is a monitored function.
2. Computes each GOT slot's runtime address (`base + (r_offset − preferred_base)`) and reads the live pointer from `/proc/PID/mem`.
3. Flags the entry when that pointer does **not** land in a persistent legitimate executable mapping. Lazy-bound slots point into the module's own PLT and real interposers (including `LD_PRELOAD`) resolve into on-disk `.so` files — neither trips the check. Anonymous, memfd-backed, deleted, non-executable, and unmapped targets are reported.

### eBPF kernel hooks

Runs system-wide, talks to `bpf()` directly. For each loaded BPF program:

1. `BPF_PROG_GET_NEXT_ID` loops until `ENOENT`.
2. `BPF_PROG_GET_FD_BY_ID` + `BPF_OBJ_GET_INFO_BY_FD` retrieves type, name, UID, and BTF metadata.
3. Attach target is resolved via three independent paths:
   - **Attach BTF** — uses `attach_btf_id` and `attach_btf_obj_id`; discovers vmlinux by kernel metadata and resolves module split-BTF type/string offsets against that base.
   - **`BPF_TASK_FD_QUERY`** walking `/proc/*/fd` — catches BCC-style perf_event attachments where the program is reachable via an open file descriptor but has no `bpf_link` object.
   - **`BPF_LINK_GET_NEXT_ID`** + `BPF_OBJ_GET_INFO_BY_FD` — proves link-backed attachment and resolves raw/perf links plus kprobe-multi, uprobe-multi, and tracing-multi target sets.

Only hook-capable types are reported: `KPROBE`, `TRACEPOINT`, `RAW_TRACEPOINT`, `RAW_TP_WRITABLE`, `PERF_EVENT`, `TRACING`, `LSM`, `SYSCALL`. A program is a hook signal only when a live link or perf-event FD proves attachment; loaded-but-unproven programs stay visible in JSON/verbose evidence. Pure-networking types (XDP, SOCKET_FILTER, SCHED_CLS, …) are intentionally ignored.

### Kernel integrity

On x86-64 and ARM64, selected high-impact `sys_call_table` slots are read through the `/proc/kcore` ELF mapping and compared with `__x64_sys_*` / `__arm64_sys_*` addresses. On x86-64 all present IDT gates are validated and critical exception vectors are compared with their expected handlers; on ARM64 direct exception-vector branches are checked for targets outside core text.

The LSM check uses the running kernel's BTF rather than a compiled-in layout. It supports both legacy `security_hook_heads` lists and modern static-call tables, resolves each critical callback's owner, reads the active static-call target and key state, and flags disabled, changed, inactive-owner, or outside-core targets. Kernel lockdown, hidden symbols, missing BTF, or unreadable `/proc/kcore` make the relevant source explicitly incomplete.

### Non-BPF kprobes

`/sys/kernel/debug/kprobes/list` enumerates every registered kprobe/kretprobe in the kernel — including those registered by non-BPF tools like SystemTap or by custom kernel modules. Each line is parsed into `{address, type (k/r), symbol+offset, active, optimized, ftrace_based}`. Requires root + debugfs mounted.

### uprobes

`tracefs/uprobe_events` lists tracefs-registered uprobes. It is tried under both `/sys/kernel/tracing/` (modern) and `/sys/kernel/debug/tracing/` (legacy debugfs mount); non-tracefs perf-event uprobes remain explicitly incomplete.

### ftrace hooks

`tracefs/enabled_functions` lists every kernel function with an ftrace callback. Active `I` (IPMODIFY) and `D` (direct-call) flags count as redirection signals; `tramp:` metadata is reported separately because not every custom trampoline can modify control flow. This catches the ftrace technique used by LKMs without treating ordinary tracing callbacks as hooks.

`tracefs/current_tracer` is read separately — if it's anything other than `nop`, the scanner emits a warning entry because kernel-wide function tracing being on is unusual on a production system.

### VDSO tampering

The kernel maps the same position-independent `[vdso]` image (`gettimeofday`, `clock_gettime`, `getcpu`) into every process, so its bytes are identical across comparable processes. A rootkit that patches one process's vdso breaks copy-on-write and leaves that process with a private, modified page that has **no on-disk baseline** to diff against. The scanner reads every readable `[vdso]` via `/proc/PID/mem`, groups them by validated ELF ABI and length, and flags a content variant only when it is a strict minority within that same group.

Without a trusted baseline, a *global* patch applied before COW can alter every process identically without creating a minority. `--baseline-root` closes that gap when the matching trusted VDSO exists. CRIU-restored processes can legitimately carry a divergent vdso proxy, so treat a peer-only hit as "investigate", not proof.

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

[+] No preload indicators in 42 process(es) inspected

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

[*] Checking VDSO consistency...
[+] VDSO consistent across 42 process(es) (1 variant)

[*] Scanning GOT/PLT for hijacks...
[+] No GOT/PLT hijacks detected


Scanning processes...

[!] PID 1234 (sshd): 2 hook(s)

========================================================
SUMMARY
========================================================
Processes scanned:           42
Processes w/ inline hooks:   1
Inline code hooks:           2
GOT/PLT hijacks:             0
Preload indicators:          0
eBPF kernel hooks:           2
Active kprobes:              2
uprobes:                     0
ftrace redirection signals:  0
Unknown LSMs:                0
Out-of-tree/unsigned mods:   2
VDSO anomalies:              0
--------------------------------------------------------
Total signals:               8

[!] Hook signals detected; investigate the findings above.
[?] Coverage incomplete; additional findings cannot be ruled out. Sources: uprobes
========================================================
```

