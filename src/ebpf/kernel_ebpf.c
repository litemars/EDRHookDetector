#define _GNU_SOURCE
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>

#include "kernel_ebpf.h"

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
#ifndef BPF_BTF_GET_FD_BY_ID
#define BPF_BTF_GET_FD_BY_ID            19
#endif

static int bpf_call(int cmd, union bpf_attr *attr, unsigned int size) {
    return (int)syscall(__NR_bpf, cmd, attr, size);
}

/* ── BTF name resolution ─────────────────────────────────────────────────── */

#define BTF_MAGIC_VAL 0xeb9fu

struct btf_hdr {
    uint16_t magic;
    uint8_t  version;
    uint8_t  flags;
    uint32_t hdr_len;
    uint32_t type_off;
    uint32_t type_len;
    uint32_t str_off;
    uint32_t str_len;
};

struct btf_typ {
    uint32_t name_off;
    uint32_t info;
    uint32_t size_or_type;
};

/* bpf_btf_info is not in older kernel headers */
struct btf_obj_info {
    uint64_t btf;
    uint32_t btf_size;
    uint32_t id;
    uint64_t name;
    uint32_t name_len;
    uint32_t kernel_btf;
};

static uint8_t       *g_btf_data = NULL;
static const uint8_t *g_type_sec = NULL;
static uint32_t       g_type_len = 0;
static const char    *g_str_sec  = NULL;
static uint32_t       g_str_len  = 0;

static uint32_t btf_extra(uint32_t kind, uint32_t vlen) {
    switch (kind) {
        case 1:  return 4;            /* INT */
        case 3:  return 12;           /* ARRAY */
        case 4:
        case 5:  return vlen * 12u;   /* STRUCT, UNION */
        case 6:  return vlen * 8u;    /* ENUM */
        case 13: return vlen * 8u;    /* FUNC_PROTO */
        case 14: return 4;            /* VAR */
        case 15: return vlen * 12u;   /* DATASEC */
        case 17: return 4;            /* DECL_TAG */
        case 19: return vlen * 12u;   /* ENUM64 */
        case 0: case 2: case 7: case 8: case 9: case 10: case 11:
        case 12: case 16: case 18:    return 0;
        default: return UINT32_MAX;   /* unknown kind — stop iteration */
    }
}

static void load_kernel_btf(void) {
    if (g_btf_data) return;
    g_btf_partial = 0;

    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.start_id = 1u;   /* kernel vmlinux BTF always has ID=1 */
    int fd = bpf_call(BPF_BTF_GET_FD_BY_ID, &attr, sizeof(attr));
    if (fd < 0) return;

    struct btf_obj_info info;
    memset(&info, 0, sizeof(info));
    memset(&attr, 0, sizeof(attr));
    attr.info.bpf_fd   = (uint32_t)fd;
    attr.info.info_len = (uint32_t)sizeof(info);
    attr.info.info     = (uint64_t)(uintptr_t)&info;
    if (bpf_call(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) < 0) {
        close(fd); return;
    }

    uint32_t sz = info.btf_size;
    if (sz == 0 || sz > 64u * 1024u * 1024u) { close(fd); return; }

    uint8_t *buf = malloc(sz);
    if (!buf) { close(fd); return; }

    memset(&info, 0, sizeof(info));
    info.btf      = (uint64_t)(uintptr_t)buf;
    info.btf_size = sz;
    memset(&attr, 0, sizeof(attr));
    attr.info.bpf_fd   = (uint32_t)fd;
    attr.info.info_len = (uint32_t)sizeof(info);
    attr.info.info     = (uint64_t)(uintptr_t)&info;
    int rc = bpf_call(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
    close(fd);
    if (rc < 0) { free(buf); return; }

    struct btf_hdr *hdr = (struct btf_hdr *)buf;
    if (sz < sizeof(*hdr) || hdr->magic != BTF_MAGIC_VAL) { free(buf); return; }

    uint32_t ts = hdr->hdr_len + hdr->type_off;
    uint32_t ss = hdr->hdr_len + hdr->str_off;
    if (ts + hdr->type_len > sz || ss + hdr->str_len > sz) { free(buf); return; }

    g_btf_data = buf;
    g_type_sec = buf + ts;
    g_type_len = hdr->type_len;
    g_str_sec  = (const char *)(buf + ss);
    g_str_len  = hdr->str_len;
}

static int g_btf_partial = 0;   /* set if iteration aborted on unknown kind */

static const char *btf_resolve(uint32_t type_id) {
    if (!type_id || !g_btf_data) return NULL;

    const uint8_t *p   = g_type_sec;
    const uint8_t *end = p + g_type_len;
    uint32_t       id  = 0;

    while (p + sizeof(struct btf_typ) <= end) {
        id++;
        const struct btf_typ *t = (const struct btf_typ *)p;
        uint32_t kind  = (t->info >> 24) & 0x1fu;
        uint32_t vlen  = t->info & 0xffffu;
        uint32_t extra = btf_extra(kind, vlen);

        if (extra == UINT32_MAX) {
            /* Unknown BTF kind (newer kernel). We can't compute the size of
             * this entry, so we cannot reliably advance past it. Mark BTF
             * resolution as partial and stop — but only the FIRST time, so
             * subsequent calls don't keep re-iterating the prefix. */
            g_btf_partial = 1;
            break;
        }

        if (id == type_id) {
            if (t->name_off < g_str_len && g_str_sec[t->name_off])
                return g_str_sec + t->name_off;
            return NULL;
        }

        p += sizeof(struct btf_typ) + extra;
    }
    return NULL;
}

/* ── Hook classification ─────────────────────────────────────────────────── */

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

static const char *prog_type_str(uint32_t type) {
    switch ((int)type) {
        case BPF_PROG_TYPE_KPROBE:                  return "KPROBE";
        case BPF_PROG_TYPE_TRACEPOINT:              return "TRACEPOINT";
        case BPF_PROG_TYPE_PERF_EVENT:              return "PERF_EVENT";
        case BPF_PROG_TYPE_RAW_TRACEPOINT:          return "RAW_TRACEPOINT";
        case BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE: return "RAW_TP_WRITABLE";
        case BPF_PROG_TYPE_TRACING:                 return "TRACING";
        case BPF_PROG_TYPE_LSM:                     return "LSM";
        case BPF_PROG_TYPE_SYSCALL:                 return "SYSCALL";
        default:                                    return "UNKNOWN";
    }
}

/* ── Main scan ───────────────────────────────────────────────────────────── */

int scan_ebpf_programs(const Config *config) {
    if (!config->json_output)
        printf("[*] Scanning eBPF kernel hooks...\n");
    else
        printf("{\"ebpf_hooks\":[");

    load_kernel_btf();

    uint32_t id          = 0;
    int      n_hooks     = 0;
    int      printed     = 0;
    int      n_seen      = 0;     /* total programs the kernel listed */
    int      n_skipped   = 0;     /* programs we couldn't query */

    for (;;) {
        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.start_id = id;

        int ret = bpf_call(BPF_PROG_GET_NEXT_ID, &attr, sizeof(attr));
        if (ret < 0) {
            if (errno == ENOENT) break;
            if (errno == EPERM || errno == EACCES) {
                if (config->json_output) printf("]}\n");
                else fprintf(stderr, "[!] eBPF enumeration requires root\n");
                return 0;
            }
            if (errno == ENOSYS) {
                if (config->json_output) printf("]}\n");
                else fprintf(stderr, "[!] bpf() syscall not available\n");
                return 0;
            }
            if (!config->json_output)
                fprintf(stderr, "[!] BPF_PROG_GET_NEXT_ID failed: %s (id=%u, stopping)\n",
                        strerror(errno), id);
            break;
        }
        id = attr.next_id;
        n_seen++;

        memset(&attr, 0, sizeof(attr));
        attr.start_id = id;
        int fd = bpf_call(BPF_PROG_GET_FD_BY_ID, &attr, sizeof(attr));
        if (fd < 0) {
            n_skipped++;
            if (config->verbose && !config->json_output)
                fprintf(stderr, "[!] PROG_GET_FD_BY_ID(id=%u) failed: %s\n",
                        id, strerror(errno));
            continue;
        }

        struct bpf_prog_info info;
        memset(&info, 0, sizeof(info));
        memset(&attr, 0, sizeof(attr));
        attr.info.bpf_fd   = (uint32_t)fd;
        attr.info.info_len = (uint32_t)sizeof(info);
        attr.info.info     = (uint64_t)(uintptr_t)&info;
        ret = bpf_call(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
        close(fd);
        if (ret < 0) {
            n_skipped++;
            if (config->verbose && !config->json_output)
                fprintf(stderr, "[!] OBJ_GET_INFO_BY_FD(id=%u) failed: %s\n",
                        id, strerror(errno));
            continue;
        }

        if (!is_hook_capable(info.type)) continue;
        n_hooks++;

        /* Resolve the attached kernel function name via BTF (kernel 5.5+) */
        const char *fn_name = btf_resolve(info.attach_btf_id);

        char prog_name[BPF_OBJ_NAME_LEN + 1];
        memcpy(prog_name, info.name, BPF_OBJ_NAME_LEN);
        prog_name[BPF_OBJ_NAME_LEN] = '\0';

        if (config->json_output) {
            if (printed > 0) printf(",");
            printf("{\"kernel_function\":\"%s\",\"prog_type\":\"%s\",\"prog_name\":\"%s\",\"uid\":%u}",
                   fn_name ? fn_name : "",
                   prog_type_str(info.type),
                   prog_name,
                   info.created_by_uid);
        } else {
            if (fn_name)
                printf("  %-32s [%-16s] prog=%s\n",
                       fn_name, prog_type_str(info.type),
                       prog_name[0] ? prog_name : "<unnamed>");
            else
                printf("  %-32s [%-16s]%s\n",
                       prog_name[0] ? prog_name : "<unnamed>",
                       prog_type_str(info.type),
                       info.attach_btf_id ? " (btf unresolved)" : "");
        }
        printed++;
    }

    if (config->json_output) {
        printf("]}\n");
    } else {
        if (n_hooks == 0)
            printf("[+] No hook-capable eBPF programs (%d total seen)\n", n_seen);
        else
            printf("    %d kernel hook(s) found  (out of %d eBPF program(s) seen", n_hooks, n_seen);
        if (!n_hooks && n_skipped == 0) {
            /* nothing extra */
        } else if (n_hooks) {
            if (n_skipped > 0)
                printf(", %d skipped - rerun with -v for details", n_skipped);
            printf(")\n");
        }
        if (n_skipped > 0 && n_hooks == 0)
            printf("[!] %d program(s) could not be queried (rerun with -v for details)\n",
                   n_skipped);
    }

    if (!config->json_output && g_btf_partial)
        fprintf(stderr, "[!] BTF resolution partial: kernel uses a BTF kind this build doesn't know;"
                       " some kernel function names may be missing\n");

    if (g_btf_data) {
        free(g_btf_data);
        g_btf_data = NULL;
    }

    return n_hooks;
}
