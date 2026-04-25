# Multi-Arch EDR Hook Detector

A focused tool to detect in-memory EDR hooks on Linux by comparing in-memory library function bytes with the clean on-disk bytes and applying architecture-specific heuristics. Supports both **ARM64 (AArch64)** and **x86 / x86-64** targets.

This repository contains a compact C program that inspects running processes, locates loaded libraries (libc and other common libraries), reads a short window of instructions from both the on-disk library and the process memory, and attempts to detect suspicious in-memory replacements/trampolines while avoiding known benign patterns.

## Features

- **Multi-architecture**: ARM64 and x86/x86-64 heuristics in a single binary; architecture is detected automatically from each library's ELF header at runtime
- Compares on-disk and in-memory instruction sequences for candidate functions
- Filters common benign cases: syscall_cp stubs, PLT/GOT stubs, thin wrappers, tail-call optimisations, and IFUNC alternative implementations
- x86 includes a lightweight variable-length instruction decoder covering syscall instructions (SYSCALL, INT 0x80, SYSENTER), direct/indirect branches, and NOP sequences
- CLI options to scan a single PID or restrict to a library path/name
- JSON output mode
- Small, zero-dependency C program; compiles with a standard GCC toolchain

## Limitations

- Scope: Userland-only detection; kernel hooks (eBPF, kprobes, kernel modules) are out of scope.
- Permissions: Root is required to read other processes' `/proc/[pid]/mem`.
- The x86 instruction decoder is intentionally minimal — it handles the common function-prologue patterns needed for hook detection, not every opcode.

## Quickstart (build & run)

Build with the included Makefile:

```bash
make
```

Run the scanner (binary: `edr_hooks_check`) with root privileges for full scanning:

```bash
sudo ./edr_hooks_check
```

Common options:

- `-p, --pid <PID>`    Scan only the given process ID
- `-l, --lib <PATH>`   Restrict inspection to a specific library path or filename
- `-s, --self`         Scan only the current process (no root needed)
- `-v, --verbose`      Verbose output (use twice for more detail)
- `-x, --hexdump`      Show hexdump of modified instructions
- `-j, --json`         Output in JSON format
- `-h, --help`         Show help

Example: scan PID 1234 with verbose output

```bash
sudo ./edr_hooks_check --pid 1234 --verbose
```


## Detection overview

- The program reads a window of bytes from the on-disk ELF for each monitored function and from the target process memory.
- **ARM64**: reads 8 fixed-width 32-bit instructions (32 bytes). Detects SVC removal, suspicious B/BL/BR additions, and checks several benign trampoline patterns.
- **x86/x86-64**: reads 64 bytes (enough for ~10–15 variable-length instructions). A lightweight decoder identifies syscall instructions (SYSCALL / INT 0x80 / SYSENTER), direct jumps (JMP rel8/rel32, CALL rel32), indirect branches (JMP r/m, CALL r/m), NOPs, and RET. The same disk-vs-memory scoring logic is then applied.
- Architecture is determined from the ELF `e_machine` field of each library at scan time, so a single scanner binary handles mixed environments.
- A function is considered suspicious when the disk and in-memory sequences differ, and the in-memory version lacks a syscall instruction that is present on disk — a pattern that strongly indicates in-memory replacement.

## Source layout

| File | Contents |
|---|---|
| `common.h` | Shared types, constants, and function declarations |
| `common.c` | ELF parsing (ELF32 + ELF64), process scanning, output, arch dispatch |
| `arch_arm64.h/c` | ARM64 opcode constants and `detect_hook_confidence_arm64()` |
| `arch_x86.h/c` | x86 instruction decoder and `detect_hook_confidence_x86()` |
| `main.c` | CLI argument parsing and main scan loop |

## Output

Example (trimmed):

```
========================================================
  Multi-Arch EDR Hook Detector (ARM64 + x86 / x86-64)
========================================================

[+] No /etc/ld.so.preload

Scanning processes...

[!] PID 1234: 2 hook(s)

SUMMARY
Processes scanned:    120
With hooks:           1
Total hooks:          2

========================================================
```
