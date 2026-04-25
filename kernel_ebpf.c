#define _GNU_SOURCE
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>

#include "kernel_ebpf.h"

/*
 * Fallback definitions for program types added in kernels 5.3–5.14.
 * These are stable ABI values — the numbers never change once assigned.
 */
#ifndef BPF_PROG_TYPE_TRACING
#define BPF_PROG_TYPE_TRACING           26
#endif
#ifndef BPF_PROG_TYPE_STRUCT_OPS
#define BPF_PROG_TYPE_STRUCT_OPS        27
#endif
#ifndef BPF_PROG_TYPE_EXT
#define BPF_PROG_TYPE_EXT               28
#endif
#ifndef BPF_PROG_TYPE_LSM
#define BPF_PROG_TYPE_LSM               29
#endif
#ifndef BPF_PROG_TYPE_SK_LOOKUP
#define BPF_PROG_TYPE_SK_LOOKUP         30
#endif
#ifndef BPF_PROG_TYPE_SYSCALL
#define BPF_PROG_TYPE_SYSCALL           31
#endif

static int bpf_call(int cmd, union bpf_attr *attr, unsigned int size) {
    return (int)syscall(__NR_bpf, cmd, attr, size);
}

static const char *prog_type_str(uint32_t type) {
    switch ((int)type) {
        case BPF_PROG_TYPE_UNSPEC:                  return "UNSPEC";
        case BPF_PROG_TYPE_SOCKET_FILTER:           return "SOCKET_FILTER";
        case BPF_PROG_TYPE_KPROBE:                  return "KPROBE";
        case BPF_PROG_TYPE_SCHED_CLS:               return "SCHED_CLS";
        case BPF_PROG_TYPE_SCHED_ACT:               return "SCHED_ACT";
        case BPF_PROG_TYPE_TRACEPOINT:              return "TRACEPOINT";
        case BPF_PROG_TYPE_XDP:                     return "XDP";
        case BPF_PROG_TYPE_PERF_EVENT:              return "PERF_EVENT";
        case BPF_PROG_TYPE_CGROUP_SKB:              return "CGROUP_SKB";
        case BPF_PROG_TYPE_CGROUP_SOCK:             return "CGROUP_SOCK";
        case BPF_PROG_TYPE_LWT_IN:                  return "LWT_IN";
        case BPF_PROG_TYPE_LWT_OUT:                 return "LWT_OUT";
        case BPF_PROG_TYPE_LWT_XMIT:               return "LWT_XMIT";
        case BPF_PROG_TYPE_SOCK_OPS:                return "SOCK_OPS";
        case BPF_PROG_TYPE_SK_SKB:                  return "SK_SKB";
        case BPF_PROG_TYPE_CGROUP_DEVICE:           return "CGROUP_DEVICE";
        case BPF_PROG_TYPE_SK_MSG:                  return "SK_MSG";
        case BPF_PROG_TYPE_RAW_TRACEPOINT:          return "RAW_TRACEPOINT";
        case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:        return "CGROUP_SOCK_ADDR";
        case BPF_PROG_TYPE_LWT_SEG6LOCAL:           return "LWT_SEG6LOCAL";
        case BPF_PROG_TYPE_LIRC_MODE2:              return "LIRC_MODE2";
        case BPF_PROG_TYPE_SK_REUSEPORT:            return "SK_REUSEPORT";
        case BPF_PROG_TYPE_FLOW_DISSECTOR:          return "FLOW_DISSECTOR";
        case BPF_PROG_TYPE_CGROUP_SYSCTL:           return "CGROUP_SYSCTL";
        case BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE: return "RAW_TRACEPOINT_WRITABLE";
        case BPF_PROG_TYPE_CGROUP_SOCKOPT:          return "CGROUP_SOCKOPT";
        case BPF_PROG_TYPE_TRACING:                 return "TRACING";
        case BPF_PROG_TYPE_STRUCT_OPS:              return "STRUCT_OPS";
        case BPF_PROG_TYPE_EXT:                     return "EXT";
        case BPF_PROG_TYPE_LSM:                     return "LSM";
        case BPF_PROG_TYPE_SK_LOOKUP:               return "SK_LOOKUP";
        case BPF_PROG_TYPE_SYSCALL:                 return "SYSCALL";
        default:                                     return "UNKNOWN";
    }
}

/*
 * Returns 1 for program types that can intercept kernel execution paths:
 * tracing hooks (fentry/fexit/fmod_ret), kprobes, LSM callbacks,
 * tracepoints, perf events, and the general SYSCALL type.
 * These are the types an EDR would load; legitimate system software
 * uses them too, so presence alone is not proof of malice.
 */
static int is_hook_capable(uint32_t type) {
    switch ((int)type) {
        case BPF_PROG_TYPE_KPROBE:
        case BPF_PROG_TYPE_TRACEPOINT:
        case BPF_PROG_TYPE_PERF_EVENT:
        case BPF_PROG_TYPE_RAW_TRACEPOINT:
        case BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE:
        case BPF_PROG_TYPE_TRACING:
        case BPF_PROG_TYPE_LSM:
        case BPF_PROG_TYPE_SYSCALL:
            return 1;
        default:
            return 0;
    }
}

void scan_ebpf_programs(const Config *config) {
    if (!config->json_output)
        printf("[*] Scanning eBPF programs...\n");
    else
        printf("{\"ebpf_programs\":[");

    uint32_t id      = 0;
    int      total   = 0;
    int      n_hooks = 0;
    int      printed = 0;

    for (;;) {
        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.start_id = id;

        int ret = bpf_call(BPF_PROG_GET_NEXT_ID, &attr, sizeof(attr));
        if (ret < 0) {
            if (errno == ENOENT) break;
            if (errno == EPERM || errno == EACCES) {
                if (config->json_output)
                    printf("]}\n");
                else
                    fprintf(stderr, "[!] eBPF enumeration requires root\n");
                return;
            }
            if (errno == ENOSYS) {
                if (config->json_output)
                    printf("]}\n");
                else
                    fprintf(stderr, "[!] bpf() syscall unavailable — kernel too old or eBPF disabled\n");
                return;
            }
            break;
        }
        id = attr.next_id;

        memset(&attr, 0, sizeof(attr));
        attr.start_id = id;
        int fd = bpf_call(BPF_PROG_GET_FD_BY_ID, &attr, sizeof(attr));
        if (fd < 0) continue;

        struct bpf_prog_info info;
        memset(&info, 0, sizeof(info));
        memset(&attr, 0, sizeof(attr));
        attr.info.bpf_fd   = (uint32_t)fd;
        attr.info.info_len = (uint32_t)sizeof(info);
        attr.info.info     = (uint64_t)(uintptr_t)&info;

        ret = bpf_call(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
        close(fd);
        if (ret < 0) continue;

        total++;
        int hook = is_hook_capable(info.type);
        if (hook) n_hooks++;

        if (!config->verbose && !hook && !config->json_output) continue;

        char name_buf[BPF_OBJ_NAME_LEN + 1];
        memcpy(name_buf, info.name, BPF_OBJ_NAME_LEN);
        name_buf[BPF_OBJ_NAME_LEN] = '\0';

        if (config->json_output) {
            if (printed > 0) printf(",");
            printf("{\"id\":%u,\"type\":\"%s\",\"name\":\"%s\",\"uid\":%u,\"hook_capable\":%s}",
                   info.id,
                   prog_type_str(info.type),
                   name_buf[0] ? name_buf : "",
                   info.created_by_uid,
                   hook ? "true" : "false");
        } else {
            printf("  [%-28s] id=%-5u name=%-16s uid=%u%s\n",
                   prog_type_str(info.type),
                   info.id,
                   name_buf[0] ? name_buf : "<unnamed>",
                   info.created_by_uid,
                   hook ? "  [hook-capable]" : "");
        }
        printed++;
    }

    if (config->json_output) {
        printf("]}\n");
        return;
    }

    if (total == 0) {
        printf("[+] No eBPF programs loaded\n");
    } else {
        printf("    %d program(s) found, %d hook-capable\n", total, n_hooks);
        if (n_hooks == 0)
            printf("[+] No hook-capable eBPF programs\n");
        if (!config->verbose && total > n_hooks)
            printf("    Run with -v to see non-hook-capable programs\n");
    }
}
