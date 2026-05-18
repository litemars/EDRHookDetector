#ifndef KERNEL_HOOKS_H
#define KERNEL_HOOKS_H

#include "common.h"

int scan_kprobes(const Config *config);
int scan_uprobes(const Config *config);
int scan_ftrace_hooks(const Config *config);
int scan_lsm_modules(const Config *config);
int scan_tainted_modules(const Config *config);

#endif /* KERNEL_HOOKS_H */
