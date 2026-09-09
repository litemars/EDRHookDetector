#define _GNU_SOURCE
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
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
#ifndef BPF_BTF_GET_NEXT_ID
#define BPF_BTF_GET_NEXT_ID            23
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

struct btf_blob {
    uint32_t id;
    uint8_t *data;
    const uint8_t *types;
    uint32_t type_len;
    uint32_t type_count;
    const char *strings;
    uint32_t str_len;
    uint32_t kernel_btf;
    char name[256];
};

static struct btf_blob g_kernel_btf = {0};
static struct btf_blob g_object_btf = {0};
static int g_btf_partial = 0;

static void btf_free(struct btf_blob *btf) {
    free(btf->data);
    memset(btf, 0, sizeof(*btf));
}

static uint32_t btf_extra(uint32_t kind, uint32_t vlen) {
    /* vlen is 16-bit in valid BTF; guard against overflow from corrupt blobs. */
    if (vlen > 0x10000u) return UINT32_MAX;
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

static int btf_sections_valid(const struct btf_hdr *hdr, uint32_t size,
                              uint32_t *type_start, uint32_t *str_start) {
    if (size < sizeof(*hdr) || hdr->magic != BTF_MAGIC_VAL ||
        hdr->hdr_len < sizeof(*hdr) || hdr->hdr_len > size ||
        hdr->type_off > size - hdr->hdr_len ||
        hdr->str_off > size - hdr->hdr_len)
        return 0;

    uint32_t ts = hdr->hdr_len + hdr->type_off;
    uint32_t ss = hdr->hdr_len + hdr->str_off;
    if (hdr->type_len > size - ts || hdr->str_len > size - ss)
        return 0;

    *type_start = ts;
    *str_start = ss;
    return 1;
}

static int btf_info_query(int fd, struct btf_obj_info *info) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.info.bpf_fd = (uint32_t)fd;
    attr.info.info_len = (uint32_t)sizeof(*info);
    attr.info.info = (uint64_t)(uintptr_t)info;
    return bpf_call(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
}

static int load_btf_object(uint32_t id, struct btf_blob *btf) {
    if (!id) return 0;
    if (btf->id == id && btf->data) return 1;
    btf_free(btf);
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.start_id = id;
    int fd = bpf_call(BPF_BTF_GET_FD_BY_ID, &attr, sizeof(attr));
    if (fd < 0) return 0;

    struct btf_obj_info info;
    memset(&info, 0, sizeof(info));
    if (btf_info_query(fd, &info) < 0 || info.btf_size < sizeof(struct btf_hdr) ||
        info.btf_size > 64u * 1024u * 1024u) {
        close(fd); return 0;
    }
    uint32_t size = info.btf_size;
    uint8_t *data = malloc(size);
    if (!data) { close(fd); return 0; }
    memset(&info, 0, sizeof(info));
    info.btf = (uint64_t)(uintptr_t)data;
    info.btf_size = size;
    info.name = (uint64_t)(uintptr_t)btf->name;
    info.name_len = (uint32_t)sizeof(btf->name);
    int rc = btf_info_query(fd, &info);
    close(fd);
    if (rc < 0 || info.btf_size < sizeof(struct btf_hdr) || info.btf_size > size) {
        free(data); return 0;
    }

    struct btf_hdr hdr;
    memcpy(&hdr, data, sizeof(hdr));
    uint32_t ts, ss;
    if (hdr.version != 1 || !btf_sections_valid(&hdr, info.btf_size, &ts, &ss)) {
        free(data); return 0;
    }
    uint32_t off = 0, count = 0;
    while (off < hdr.type_len) {
        struct btf_typ t;
        if (hdr.type_len - off < sizeof(t)) { free(data); return 0; }
        memcpy(&t, data + ts + off, sizeof(t));
        uint32_t extra = btf_extra((t.info >> 24) & 0x1fu, t.info & 0xffffu);
        if (extra == UINT32_MAX || extra > hdr.type_len - off - sizeof(t)) {
            g_btf_partial = 1;
            free(data); return 0;
        }
        off += (uint32_t)sizeof(t) + extra;
        count++;
    }
    btf->id = id;
    btf->data = data;
    btf->types = data + ts;
    btf->type_len = hdr.type_len;
    btf->type_count = count;
    btf->strings = (const char *)(data + ss);
    btf->str_len = hdr.str_len;
    btf->kernel_btf = info.kernel_btf;
    btf->name[sizeof(btf->name) - 1] = '\0';
    return 1;
}

static void load_kernel_btf(void) {
    /* BTF object IDs are allocated at runtime; ID 1 is not a contract. */
    if (g_kernel_btf.data) return;
    uint32_t id = 0;
    for (;;) {
        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.start_id = id;
        if (bpf_call(BPF_BTF_GET_NEXT_ID, &attr, sizeof(attr)) < 0 || attr.next_id <= id)
            return;
        id = attr.next_id;
        if (!load_btf_object(id, &g_kernel_btf)) continue;
        if (g_kernel_btf.kernel_btf && strcmp(g_kernel_btf.name, "vmlinux") == 0)
            return;
        btf_free(&g_kernel_btf);
    }
}

static const char *btf_string(const struct btf_blob *btf, uint32_t off) {
    if (off >= btf->str_len || !btf->strings[off] ||
        !memchr(btf->strings + off, '\0', btf->str_len - off)) return NULL;
    return btf->strings + off;
}

static int btf_type_by_id(const struct btf_blob *btf, uint32_t type_id,
                          const struct btf_blob *base, struct btf_typ *type,
                          const struct btf_blob **owner) {
    if (!btf->data || !type_id) return 0;
    if (base) {
        if (type_id <= base->type_count)
            return btf_type_by_id(base, type_id, NULL, type, owner);
        type_id -= base->type_count;
    }
    if (type_id > btf->type_count) return 0;
    uint32_t off = 0;
    for (uint32_t id = 1; id <= btf->type_count; id++) {
        struct btf_typ t;
        memcpy(&t, btf->types + off, sizeof(t));
        uint32_t kind = (t.info >> 24) & 0x1fu;
        if (id == type_id) {
            *type = t;
            *owner = btf;
            return 1;
        }
        off += (uint32_t)sizeof(t) + btf_extra(kind, t.info & 0xffffu);
    }
    return 0;
}

static const char *btf_type_name(const struct btf_blob *owner,
                                 const struct btf_blob *base, uint32_t name_off) {
    if (base && owner != base) {
        if (name_off < base->str_len) return btf_string(base, name_off);
        return btf_string(owner, name_off - base->str_len);
    }
    return btf_string(owner, name_off);
}

static const char *btf_lookup(const struct btf_blob *btf, uint32_t type_id,
                              const struct btf_blob *base) {
    struct btf_typ type;
    const struct btf_blob *owner;
    /* Program func_info describes a FUNC, never a tracepoint typedef. */
    if (!btf_type_by_id(btf, type_id, base, &type, &owner) ||
        ((type.info >> 24) & 0x1fu) != 12u) return NULL;
    return btf_type_name(owner, base, type.name_off);
}

static const char *btf_kernel_target(const struct btf_blob *btf, uint32_t type_id,
                                     const struct btf_blob *base, int tracing,
                                     const char **kind) {
    const char *name = btf_lookup(btf, type_id, base);
    if (name) { *kind = "kernel_function"; return name; }
    if (!tracing) return NULL;

    /* TP_BTF uses TYPEDEF btf_trace_<event> -> PTR -> FUNC_PROTO.
     * Check the complete chain; neither a prefix alone nor a callback name
     * establishes a tracepoint target. Split IDs remain relative to vmlinux. */
    struct btf_typ type;
    const struct btf_blob *owner;
    if (!btf_type_by_id(btf, type_id, base, &type, &owner) ||
        ((type.info >> 24) & 0x1fu) != 8u) return NULL;
    name = btf_type_name(owner, base, type.name_off);
    static const char prefix[] = "btf_trace_";
    if (!name || strncmp(name, prefix, sizeof(prefix) - 1) ||
        !name[sizeof(prefix) - 1]) return NULL;
    if (!btf_type_by_id(btf, type.size_or_type, base, &type, &owner) ||
        ((type.info >> 24) & 0x1fu) != 2u) return NULL;
    if (!btf_type_by_id(btf, type.size_or_type, base, &type, &owner) ||
        ((type.info >> 24) & 0x1fu) != 13u) return NULL;
    *kind = "raw_tracepoint";
    return name + sizeof(prefix) - 1;
}

static const char *btf_resolve_target(uint32_t object_id, uint32_t type_id,
                                      int tracing, const char **kind) {
    if (!type_id) return NULL;
    if (!object_id || object_id == g_kernel_btf.id) {
        return btf_kernel_target(&g_kernel_btf, type_id, NULL, tracing, kind);
    }
    if (!load_btf_object(object_id, &g_object_btf)) return NULL;
    if (!g_object_btf.kernel_btf) {
        *kind = "bpf_function";
        return btf_lookup(&g_object_btf, type_id, NULL);
    }
    if (strcmp(g_object_btf.name, "vmlinux") == 0)
        return btf_kernel_target(&g_object_btf, type_id, NULL, tracing, kind);
    /* A module's split BTF extends the running vmlinux type IDs and strings. */
    if (!g_kernel_btf.data) return NULL;
    return btf_kernel_target(&g_object_btf, type_id, &g_kernel_btf, tracing, kind);
}

static const char *btf_resolve_prog(const struct bpf_prog_info *info, int prog_fd) {
    if (!info->btf_id || !info->nr_func_info || info->func_info_rec_size < 8u ||
        info->func_info_rec_size > 1024u * 1024u / info->nr_func_info) return NULL;
    size_t size = (size_t)info->nr_func_info * info->func_info_rec_size;
    uint8_t *finfo = calloc(1, size);
    if (!finfo) return NULL;
    struct bpf_prog_info pinfo;
    memset(&pinfo, 0, sizeof(pinfo));
    pinfo.nr_func_info = info->nr_func_info;
    pinfo.func_info_rec_size = info->func_info_rec_size;
    pinfo.func_info = (uint64_t)(uintptr_t)finfo;
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.info.bpf_fd = (uint32_t)prog_fd;
    attr.info.info_len = (uint32_t)sizeof(pinfo);
    attr.info.info = (uint64_t)(uintptr_t)&pinfo;
    int rc = bpf_call(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
    uint32_t type_id = 0;
    if (rc == 0 && pinfo.nr_func_info && pinfo.func_info_rec_size >= 8u)
        memcpy(&type_id, finfo + 4, sizeof(type_id));
    free(finfo);
    if (!type_id || !load_btf_object(info->btf_id, &g_object_btf) ||
        g_object_btf.kernel_btf) return NULL;
    return btf_lookup(&g_object_btf, type_id, NULL);
}

struct attach_entry {
    uint32_t prog_id;
    char     name[256];
    const char *kind;
    const char *source;
    uint64_t offset;
    uint64_t address;
};

static struct attach_entry *g_attaches     = NULL;
static int                  g_attaches_n   = 0;
static int                  g_attaches_cap = 0;

static int attaches_push(uint32_t prog_id, const char *name, const char *kind,
                          const char *source, uint64_t offset, uint64_t address) {
    if ((!name || !name[0]) && !address) return 0;
    if (!name) name = "";
    if (strlen(name) >= sizeof(g_attaches[0].name)) return -1;
    for (int i = 0; i < g_attaches_n; i++)
        if (g_attaches[i].prog_id == prog_id &&
            strcmp(g_attaches[i].name, name) == 0 &&
            strcmp(g_attaches[i].kind, kind) == 0 &&
            g_attaches[i].offset == offset && g_attaches[i].address == address)
            return 0;

    if (g_attaches_n == g_attaches_cap) {
        if (g_attaches_cap > INT_MAX / 2) return -1;
        int   newcap = g_attaches_cap ? g_attaches_cap * 2 : 64;
        void *p      = realloc(g_attaches,
                               (size_t)newcap * sizeof(*g_attaches));
        if (!p) return -1;
        g_attaches     = p;
        g_attaches_cap = newcap;
    }
    g_attaches[g_attaches_n].prog_id = prog_id;
    g_attaches[g_attaches_n].kind = kind;
    g_attaches[g_attaches_n].source = source;
    g_attaches[g_attaches_n].offset = offset;
    g_attaches[g_attaches_n].address = address;
    snprintf(g_attaches[g_attaches_n].name,
             sizeof(g_attaches[g_attaches_n].name), "%s", name);
    g_attaches_n++;
    return 0;
}

/* Redeclared here to avoid depending on recent UAPI headers. */
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
            /* A truncated pathname/symbol is not an authoritative target name. */
            if (rc < 0) continue;
            if (a.prog_id == 0) continue;

            namebuf[sizeof(namebuf) - 1] = '\0';
            const char *kind;
            switch (a.fd_type) {
                case 0: kind = "raw_tracepoint"; break;
                case 1: kind = "tracepoint"; break;
                case 2: kind = "kprobe"; break;
                case 3: kind = "kretprobe"; break;
                case 4: kind = "uprobe"; break;
                case 5: kind = "uretprobe"; break;
                default: continue;
            }
            attaches_push(a.prog_id, namebuf, kind, "task_fd_query",
                          a.probe_offset, a.probe_addr);
        }
        closedir(fdd);
    }
    closedir(proc);
}


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
                    uint64_t cookie;
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
        const char *kind = NULL;
        uint64_t offset = 0, address = 0;
        int named = -1;

        switch (info.type) {
        case LINK_TYPE_RAW_TP:
            kind = "raw_tracepoint";
            info.raw_tracepoint.tp_name     = (uint64_t)(uintptr_t)namebuf;
            info.raw_tracepoint.tp_name_len = (uint32_t)sizeof(namebuf);
            named = link_query_info(fd, &info);
            break;
        case LINK_TYPE_PERF_EV:
            switch (info.perf_event.pe_type) {
            case BPF_PE_KPROBE:
            case BPF_PE_KRETPROBE:
                kind = info.perf_event.pe_type == BPF_PE_KPROBE ? "kprobe" : "kretprobe";
                info.perf_event.kprobe.func_name = (uint64_t)(uintptr_t)namebuf;
                info.perf_event.kprobe.name_len  = (uint32_t)sizeof(namebuf);
                named = link_query_info(fd, &info);
                offset = info.perf_event.kprobe.offset;
                address = info.perf_event.kprobe.addr;
                break;
            case BPF_PE_TRACEPOINT:
                kind = "tracepoint";
                info.perf_event.tracepoint.tp_name  = (uint64_t)(uintptr_t)namebuf;
                info.perf_event.tracepoint.name_len = (uint32_t)sizeof(namebuf);
                named = link_query_info(fd, &info);
                break;
            case BPF_PE_UPROBE:
            case BPF_PE_URETPROBE:
                kind = info.perf_event.pe_type == BPF_PE_UPROBE ? "uprobe" : "uretprobe";
                info.perf_event.uprobe.file_name = (uint64_t)(uintptr_t)namebuf;
                info.perf_event.uprobe.name_len  = (uint32_t)sizeof(namebuf);
                named = link_query_info(fd, &info);
                offset = info.perf_event.uprobe.offset;
                break;
            }
            break;
        }
        close(fd);

        namebuf[sizeof(namebuf) - 1] = '\0';
        if (named == 0 && kind)
            attaches_push(info.prog_id, namebuf, kind, "bpf_link", offset, address);
    }
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

int scan_ebpf_programs(const Config *config, int *incomplete) {
    if (!config->json_output)
        printf("[*] Scanning eBPF kernel hooks...\n");
    else
        printf("\"ebpf_hooks\":[");

    g_btf_partial = 0;
    load_kernel_btf();
    load_bpf_links();
    load_task_fd_attaches();

    uint32_t id            = 0;
    int      n_hooks       = 0;
    int      printed       = 0;
    int      n_seen        = 0;     /* total programs the kernel listed */
    int      n_skipped     = 0;     /* programs we couldn't query */
    int      print_summary = 1;     /* suppress textual summary on hard abort */

    for (;;) {
        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.start_id = id;

        int ret = bpf_call(BPF_PROG_GET_NEXT_ID, &attr, sizeof(attr));
        if (ret < 0) {
            if (errno == ENOENT) break;
            if (errno == EPERM || errno == EACCES) {
                if (incomplete) *incomplete = 1;
                if (!config->json_output)
                    fprintf(stderr, "[!] eBPF enumeration requires root\n");
                print_summary = 0;
                break;
            }
            if (errno == ENOSYS) {
                if (incomplete) *incomplete = 1;
                if (!config->json_output)
                    fprintf(stderr, "[!] bpf() syscall not available\n");
                print_summary = 0;
                break;
            }
            if (!config->json_output)
                fprintf(stderr, "[!] BPF_PROG_GET_NEXT_ID failed: %s (id=%u, stopping)\n",
                        strerror(errno), id);
            if (incomplete) *incomplete = 1;
            break;
        }
        id = attr.next_id;
        n_seen++;

        memset(&attr, 0, sizeof(attr));
        attr.start_id = id;
        int fd = bpf_call(BPF_PROG_GET_FD_BY_ID, &attr, sizeof(attr));
        if (fd < 0) {
            n_skipped++;
            if (incomplete) *incomplete = 1;
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
        if (ret < 0) {
            close(fd);
            n_skipped++;
            if (incomplete) *incomplete = 1;
            if (config->verbose && !config->json_output)
                fprintf(stderr, "[!] OBJ_GET_INFO_BY_FD(id=%u) failed: %s\n",
                        id, strerror(errno));
            continue;
        }

        if (!is_hook_capable(info.type)) { close(fd); continue; }

        /* Kernel attach metadata describes targets. Program func_info describes
         * the BPF callback itself and must never be promoted to a target. */
        const char *target_kind = "kernel_function";
        const char *target = btf_resolve_target(info.attach_btf_obj_id,
                                               info.attach_btf_id,
                                               info.type == BPF_PROG_TYPE_TRACING,
                                               &target_kind);
        if (target)
            attaches_push(info.id, target, target_kind, "attach_btf", 0, 0);
        const char *callback = btf_resolve_prog(&info, fd);
        close(fd);

        char prog_name[BPF_OBJ_NAME_LEN + 1];
        memcpy(prog_name, info.name, BPF_OBJ_NAME_LEN);
        prog_name[BPF_OBJ_NAME_LEN] = '\0';
        n_hooks++;

        const struct attach_entry *first = NULL;
        const char *kernel_function = NULL;
        int n_targets = 0;
        for (int i = 0; i < g_attaches_n; i++) {
            const struct attach_entry *entry = &g_attaches[i];
            if (entry->prog_id != info.id) continue;
            if (!first) first = entry;
            n_targets++;
            if (!kernel_function && entry->name[0] && (!strcmp(entry->kind, "kernel_function") ||
                !strcmp(entry->kind, "kprobe") || !strcmp(entry->kind, "kretprobe")))
                kernel_function = entry->name;
        }
        if (config->json_output) {
            if (printed > 0) printf(",");
            printf("{");
            json_print_string_field("kernel_function", kernel_function ? kernel_function : "");
            printf(",\"prog_type\":\"%s\",\"prog_name\":\"", prog_type_str(info.type));
            json_print_escaped(prog_name);
            printf("\",\"program_function\":\"");
            if (callback) json_print_escaped(callback);
            printf("\",\"target_status\":\"%s\",\"targets\":[",
                   n_targets ? "resolved" : "unresolved");
            int emitted = 0;
            for (int i = 0; i < g_attaches_n; i++) {
                const struct attach_entry *entry = &g_attaches[i];
                if (entry->prog_id != info.id) continue;
                if (emitted++) printf(",");
                printf("{");
                json_print_string_field("name", entry->name);
                printf(",\"kind\":\"%s\",\"source\":\"%s\",\"offset\":%" PRIu64
                       ",\"address\":%" PRIu64 "}", entry->kind, entry->source,
                       entry->offset, entry->address);
            }
            printf("],\"attach_btf_obj_id\":%u,\"attach_btf_id\":%u,"
                   "\"uid\":%u,\"benign\":false}", info.attach_btf_obj_id,
                   info.attach_btf_id, info.created_by_uid);
        } else {
            printf("  %-48s [%-16s] prog=%s\n",
                   first && first->name[0] ? first->name : "<target unresolved>",
                   prog_type_str(info.type), prog_name[0] ? prog_name : "<unnamed>");
            for (int i = 0; i < g_attaches_n; i++) {
                const struct attach_entry *entry = &g_attaches[i];
                if (entry->prog_id != info.id) continue;
                printf("    target=%s kind=%s source=%s offset=%" PRIu64 " address=0x%" PRIx64 "\n",
                       entry->name[0] ? entry->name : "<unnamed>", entry->kind,
                       entry->source, entry->offset, entry->address);
            }
            if (callback) printf("    BPF callback=%s\n", callback);
        }
        printed++;
    }

    if (config->json_output) {
        printf("]");
    } else if (print_summary) {
        if (n_hooks == 0)
            printf("[+] No suspicious eBPF hooks (%d program(s) seen)\n", n_seen);
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

    btf_free(&g_kernel_btf);
    btf_free(&g_object_btf);
    attaches_free();
    return n_hooks;
}
