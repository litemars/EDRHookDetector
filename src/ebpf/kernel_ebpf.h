#ifndef KERNEL_EBPF_H
#define KERNEL_EBPF_H

#include "common.h"

int scan_ebpf_programs(const Config *config, int *incomplete);

#endif /* KERNEL_EBPF_H */
