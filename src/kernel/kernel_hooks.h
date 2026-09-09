#ifndef KERNEL_HOOKS_H
#define KERNEL_HOOKS_H

#include "common.h"

int scan_kprobes(const Config *config, int *incomplete);
int scan_uprobes(const Config *config, int *incomplete);
int scan_ftrace_hooks(const Config *config, int *incomplete);
int scan_lsm_modules(const Config *config, int *incomplete);
int scan_tainted_modules(const Config *config, int *incomplete);

#endif /* KERNEL_HOOKS_H */
