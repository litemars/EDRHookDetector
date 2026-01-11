# ARM64 EDR Hook Detector

A small, focused tool to detect in-memory EDR hooks on ARM64 Linux by comparing in-memory libc function bytes with the clean on-disk bytes and applying ARM64-specific heuristics.

This repository contains a compact C program that inspects running processes, locates loaded libraries (libc and other common libraries), reads a short window of instructions from both the on-disk library and the process memory, and attempts to detect suspicious in-memory replacements/trampolines while avoiding known benign patterns.

## Features

- ARM64 (aarch64) specific heuristics for detecting inline hooks and trampolines
- Compares on-disk and in-memory instruction sequences for candidate functions
- Filters common benign cases: syscall_cp stubs, PLT/GOT stubs, thin wrappers
- CLI options to scan a single PID or restrict to a library path/name
- Small, zero-dependency C program; compiles with a standard GCC toolchain

## Limitations

- Platform: Instruction heuristics are specific to ARM64 and glibc conventions on that platform.
- Scope: Userland-only detection; kernel hooks (eBPF, kprobes, kernel modules) are out of scope.
- Permissions: Root is required to read other processes' `/proc/[pid]/mem`.

## Quickstart (build & run)

Build with the included Makefile:

```bash
make
```

Run the default scanner (binary: `edr_arm64_edr_hooks`) with root privileges for full scanning:

```bash
sudo ./edr_arm64_edr_hooks
```

Common options:

- `-p, --pid <PID>`    Scan only the given process ID
- `-l, --lib <PATH>`   Restrict inspection to a specific library path or filename
- `-v, --verbose`      Verbose output (per-function details)
- `-h, --help`         Show help
- `-x, --hexdump`      Show hexdump of modified instructions
- `-j, --json`         Output in JSON format

Example: scan PID 1234 with verbose output

```bash
sudo ./edr_arm64_edr_hooks --pid 1234 --verbose
```


## Detection overview

- The program reads a few 32-bit ARM64 instructions from the on-disk ELF for monitored functions and from the target process memory.
- It recognizes the `syscall_cp` cancellable syscall stub (NOP + MOV imm + SVC) and several other benign trampoline patterns and avoids flagging them as hooks.
- A function is considered suspicious when both the disk and in-memory sequences appear to be real code, they differ, and the in-memory version lacks the SVC/syscall while the disk version contains it — a pattern that often indicates an in-memory replacement.

## Output

- The scanner prints a banner, checks for `/etc/ld.so.preload`, and scans processes. Detected hooks per PID are reported; a summary is printed at the end.
- Use `--verbose` to see which functions were flagged.

Example (trimmed):

```
================================================
  ARM64 EDR Hook Detector
================================================

[+] No /etc/ld.so.preload

Scanning processes...

[!] PID 1234: 2 hooks

SUMMARY
Processes scanned:    120
With hooks:           1
Total hooks:          2

================================================
```



