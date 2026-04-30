#define _GNU_SOURCE
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
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
#ifndef BPF_TASK_FD_QUERY
#define BPF_TASK_FD_QUERY               20
#endif
#ifndef BPF_LINK_GET_FD_BY_ID
#define BPF_LINK_GET_FD_BY_ID           30
#endif
#ifndef BPF_LINK_GET_NEXT_ID
#define BPF_LINK_GET_NEXT_ID            31
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

static uint8_t       *g_btf_data    = NULL;
static const uint8_t *g_type_sec    = NULL;
static uint32_t       g_type_len    = 0;
static const char    *g_str_sec     = NULL;
static uint32_t       g_str_len     = 0;
static int            g_btf_partial = 0;   /* set if iteration aborted on unknown kind */

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

/* ── Attach-point resolution via BPF_TASK_FD_QUERY ───────────────────────── */
/*
 * info.name is capped at BPF_OBJ_NAME_LEN (16 bytes), so program names like
 * "kprobe__tcp_v6_connect" arrive truncated. BCC-style tools attach via the
 * legacy perf_event_open + PERF_EVENT_IOC_SET_BPF path (no BPF link object),
 * so link iteration can't recover names. Instead we walk /proc/<pid>/fd, ask
 * the kernel via BPF_TASK_FD_QUERY about each FD, and build a prog_id → real
 * attach-target map. Works for kprobe/kretprobe/uprobe/uretprobe/tracepoint/
 * raw_tracepoint regardless of how the program was attached.
 */

struct attach_entry {
    uint32_t prog_id;
    char     name[256];
};

static struct attach_entry *g_attaches     = NULL;
static int                  g_attaches_n   = 0;
static int                  g_attaches_cap = 0;

static int attaches_push(uint32_t prog_id, const char *name) {
    if (!name || !name[0]) return 0;
    for (int i = 0; i < g_attaches_n; i++)
        if (g_attaches[i].prog_id == prog_id) return 0;   /* already known */

    if (g_attaches_n == g_attaches_cap) {
        int   newcap = g_attaches_cap ? g_attaches_cap * 2 : 64;
        void *p      = realloc(g_attaches,
                               (size_t)newcap * sizeof(*g_attaches));
        if (!p) return -1;
        g_attaches     = p;
        g_attaches_cap = newcap;
    }
    g_attaches[g_attaches_n].prog_id = prog_id;
    snprintf(g_attaches[g_attaches_n].name,
             sizeof(g_attaches[g_attaches_n].name), "%s", name);
    g_attaches_n++;
    return 0;
}

/* Layout of union bpf_attr's task_fd_query member, redeclared so we don't
 * depend on the build host's UAPI headers being recent enough. */
struct tfq_attr {
    uint32_t pid;
    uint32_t fd;
    uint32_t flags;
    uint32_t buf_len;
    uint64_t buf;            /* pointer to user buffer for the name */
    uint32_t prog_id;
    uint32_t fd_type;
    uint64_t probe_offset;
    uint64_t probe_addr;
};

static int all_digits(const char *s) {
    if (!*s) return 0;
    for (; *s; s++) if (*s < '0' || *s > '9') return 0;
    return 1;
}

static void load_task_fd_attaches(void) {
    DIR *proc = opendir("/proc");
    if (!proc) return;

    struct dirent *de;
    while ((de = readdir(proc)) != NULL) {
        if (!all_digits(de->d_name)) continue;
        uint32_t pid = (uint32_t)strtoul(de->d_name, NULL, 10);

        char fdpath[64];
        snprintf(fdpath, sizeof(fdpath), "/proc/%u/fd", pid);
        DIR *fdd = opendir(fdpath);
        if (!fdd) continue;

        struct dirent *fde;
        while ((fde = readdir(fdd)) != NULL) {
            if (!all_digits(fde->d_name)) continue;
            uint32_t fd = (uint32_t)strtoul(fde->d_name, NULL, 10);

            char namebuf[256];
            namebuf[0] = '\0';

            struct tfq_attr a;
            memset(&a, 0, sizeof(a));
            a.pid     = pid;
            a.fd      = fd;
            a.buf     = (uint64_t)(uintptr_t)namebuf;
            a.buf_len = (uint32_t)sizeof(namebuf);

            int rc = (int)syscall(__NR_bpf, BPF_TASK_FD_QUERY, &a, sizeof(a));
            /* Most FDs aren't BPF/perf — kernel returns ENOTSUPP/EBADF/etc.
             * ENOSPC means our buffer is short but prog_id/name are valid. */
            if (rc < 0 && errno != ENOSPC) continue;
            if (a.prog_id == 0) continue;

            namebuf[sizeof(namebuf) - 1] = '\0';
            attaches_push(a.prog_id, namebuf);
        }
        closedir(fdd);
    }
    closedir(proc);
}

/* Layout of bpf_link_info — local definition so we don't need recent kernel
 * UAPI headers. Only the link types we name-resolve are populated; the rest
 * of the union is padded out to the largest variant we care about. */

#define LINK_TYPE_RAW_TP    1
#define LINK_TYPE_PERF_EV   7

#define BPF_PE_UPROBE       1
#define BPF_PE_URETPROBE    2
#define BPF_PE_KPROBE       3
#define BPF_PE_KRETPROBE    4
#define BPF_PE_TRACEPOINT   5

struct link_info_buf {
    uint32_t type;
    uint32_t id;
    uint32_t prog_id;
    uint32_t _pad0;
    union {
        struct {
            uint64_t tp_name;
            uint32_t tp_name_len;
        } raw_tracepoint;
        struct {
            uint32_t pe_type;
            uint32_t _pad1;
            union {
                struct {
                    uint64_t file_name;
                    uint32_t name_len;
                    uint32_t offset;
                    uint64_t cookie;
                } uprobe;
                struct {
                    uint64_t func_name;
                    uint32_t name_len;
                    uint32_t offset;
                    uint64_t addr;
                    uint64_t missed;
                    uint32_t cookie;
                } kprobe;
                struct {
                    uint64_t tp_name;
                    uint32_t name_len;
                    uint64_t cookie;
                } tracepoint;
            };
        } perf_event;
        uint8_t _pad[176];
    };
};

static int link_query_info(int fd, struct link_info_buf *info) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.info.bpf_fd   = (uint32_t)fd;
    attr.info.info_len = (uint32_t)sizeof(*info);
    attr.info.info     = (uint64_t)(uintptr_t)info;
    return bpf_call(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
}

/* Iterate every BPF link (including pinned ones in bpffs) and recover the
 * attach target. Complements load_task_fd_attaches: a pinned link won't
 * appear in any /proc/<pid>/fd, but is reachable via BPF_LINK_GET_NEXT_ID. */
static void load_bpf_links(void) {
    uint32_t id = 0;

    for (;;) {
        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.start_id = id;
        if (bpf_call(BPF_LINK_GET_NEXT_ID, &attr, sizeof(attr)) < 0)
            break;
        id = attr.next_id;

        memset(&attr, 0, sizeof(attr));
        attr.start_id = id;
        int fd = bpf_call(BPF_LINK_GET_FD_BY_ID, &attr, sizeof(attr));
        if (fd < 0) continue;

        struct link_info_buf info;
        memset(&info, 0, sizeof(info));
        if (link_query_info(fd, &info) < 0) { close(fd); continue; }

        char namebuf[256];
        namebuf[0] = '\0';

        switch (info.type) {
        case LINK_TYPE_RAW_TP:
            info.raw_tracepoint.tp_name     = (uint64_t)(uintptr_t)namebuf;
            info.raw_tracepoint.tp_name_len = sizeof(namebuf);
            link_query_info(fd, &info);
            break;
        case LINK_TYPE_PERF_EV:
            switch (info.perf_event.pe_type) {
            case BPF_PE_KPROBE:
            case BPF_PE_KRETPROBE:
                info.perf_event.kprobe.func_name = (uint64_t)(uintptr_t)namebuf;
                info.perf_event.kprobe.name_len  = sizeof(namebuf);
                link_query_info(fd, &info);
                break;
            case BPF_PE_TRACEPOINT:
                info.perf_event.tracepoint.tp_name  = (uint64_t)(uintptr_t)namebuf;
                info.perf_event.tracepoint.name_len = sizeof(namebuf);
                link_query_info(fd, &info);
                break;
            case BPF_PE_UPROBE:
            case BPF_PE_URETPROBE:
                info.perf_event.uprobe.file_name = (uint64_t)(uintptr_t)namebuf;
                info.perf_event.uprobe.name_len  = sizeof(namebuf);
                link_query_info(fd, &info);
                break;
            }
            break;
        }
        close(fd);

        namebuf[sizeof(namebuf) - 1] = '\0';
        if (namebuf[0])
            attaches_push(info.prog_id, namebuf);
    }
}

static const char *attach_lookup(uint32_t prog_id) {
    for (int i = 0; i < g_attaches_n; i++)
        if (g_attaches[i].prog_id == prog_id)
            return g_attaches[i].name[0] ? g_attaches[i].name : NULL;
    return NULL;
}

static void attaches_free(void) {
    free(g_attaches);
    g_attaches     = NULL;
    g_attaches_n   = 0;
    g_attaches_cap = 0;
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
    load_task_fd_attaches();
    load_bpf_links();

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

        /* Prefer the real attach target recovered from /proc walk (works for
         * legacy BCC-style perf_event attachments); fall back to BTF for
         * fentry/fexit/LSM/tracing programs that have attach_btf_id set. */
        const char *fn_name = attach_lookup(info.id);
        if (!fn_name)
            fn_name = btf_resolve(info.attach_btf_id);

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
                printf("  %-48s [%-16s] prog=%s\n",
                       fn_name, prog_type_str(info.type),
                       prog_name[0] ? prog_name : "<unnamed>");
            else
                printf("  %-48s [%-16s]%s\n",
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
    attaches_free();
    return n_hooks;
}
