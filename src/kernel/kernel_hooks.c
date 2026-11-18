#define _GNU_SOURCE
#include "common.h"
#include "kernel_hooks.h"
#include <inttypes.h>
#include <limits.h>
#include <sys/syscall.h>
#include <sys/utsname.h>

#define KERNEL_RECORD_SIZE (64u * 1024u)

typedef struct {
    int fd;
    Elf64_Phdr *loads;
    unsigned int nloads;
} KernelCore;

static void kernel_core_close(KernelCore *core) {
    if (core->fd >= 0) close(core->fd);
    free(core->loads);
    memset(core, 0, sizeof(*core));
    core->fd = -1;
}

static int kernel_core_open(KernelCore *core) {
    memset(core, 0, sizeof(*core));
    core->fd = -1;
    int fd = open("/proc/kcore", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    Elf64_Ehdr eh;
    if (pread(fd, &eh, sizeof(eh), 0) != (ssize_t)sizeof(eh) ||
        memcmp(eh.e_ident, ELFMAG, SELFMAG) || eh.e_ident[EI_CLASS] != ELFCLASS64 ||
        eh.e_ident[EI_DATA] != ELFDATA2LSB || eh.e_type != ET_CORE ||
        eh.e_ehsize < sizeof(eh) || eh.e_phentsize != sizeof(Elf64_Phdr) ||
        !eh.e_phnum || eh.e_phnum > 4096 ||
        eh.e_phoff > (uint64_t)INT64_MAX ||
        (uint64_t)eh.e_phnum * sizeof(Elf64_Phdr) >
            (uint64_t)INT64_MAX - eh.e_phoff) {
        close(fd); errno = EINVAL; return -1;
    }
    Elf64_Phdr *ph = calloc(eh.e_phnum, sizeof(*ph));
    if (!ph) { close(fd); errno = ENOMEM; return -1; }
    size_t bytes = (size_t)eh.e_phnum * sizeof(*ph);
    if (pread(fd, ph, bytes, (off_t)eh.e_phoff) != (ssize_t)bytes) {
        free(ph); close(fd); errno = EIO; return -1;
    }
    core->fd = fd;
    core->loads = ph;
    core->nloads = eh.e_phnum;
    return 0;
}

static int kernel_core_read(const KernelCore *core, uint64_t address,
                            void *out, size_t size) {
    for (unsigned int i = 0; i < core->nloads; i++) {
        const Elf64_Phdr *p = &core->loads[i];
        if (p->p_type != PT_LOAD || address < p->p_vaddr) continue;
        uint64_t delta = address - p->p_vaddr;
        if (delta > p->p_filesz || size > p->p_filesz - delta ||
            p->p_offset > (uint64_t)INT64_MAX - delta) continue;
        uint64_t absolute = p->p_offset + delta;
        if (size > (uint64_t)INT64_MAX - absolute) continue;
        off_t offset = (off_t)absolute;
        size_t done = 0;
        while (done < size) {
            ssize_t got = pread(core->fd, (uint8_t *)out + done, size - done,
                                offset + (off_t)done);
            if (got < 0 && errno == EINTR) continue;
            if (got <= 0) return -1;
            done += (size_t)got;
        }
        return 0;
    }
    errno = EFAULT;
    return -1;
}

static int kallsyms_lookup(const char *wanted, uint64_t *address) {
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) return -1;
    char line[1024], symbol[512], type;
    unsigned long long value;
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strchr(line, '\n')) {
            int c; while ((c = fgetc(f)) != EOF && c != '\n') {}
            continue;
        }
        if (sscanf(line, "%llx %c %511s", &value, &type, symbol) == 3 &&
            !strcmp(symbol, wanted)) {
            *address = (uint64_t)value;
            found = value != 0;
            break;
        }
    }
    int failed = ferror(f);
    fclose(f);
    return failed ? -1 : found;
}

static int kallsyms_address_name(uint64_t address, char *name, size_t name_size) {
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) return -1;
    char line[1024], symbol[512], type;
    unsigned long long value;
    int found = 0, failed = 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strchr(line, '\n')) {
            int c; while ((c = fgetc(f)) != EOF && c != '\n') {}
            continue;
        }
        if (sscanf(line, "%llx %c %511s", &value, &type, symbol) == 3 &&
            (uint64_t)value == address) {
            snprintf(name, name_size, "%s", symbol);
            found = 1;
            break;
        }
    }
    failed = ferror(f);
    fclose(f);
    return failed ? -1 : found;
}

/* Never interpret a short read or a continuation of an oversized line as a
 * complete kernel record. Drain rejected records and retain later valid ones. */
static int kernel_read_record_mode(FILE *f, char *line, size_t capacity,
                                   int *partial, int allow_eof) {
    for (;;) {
        size_t used = 0;
        int bad = 0, c;
        while ((c = fgetc(f)) != EOF && c != '\n') {
            if (!c || (c < 0x20 && c != '\t') || c == 0x7f) bad = 1;
            if (used + 1 < capacity) line[used++] = (char)c;
            else bad = 1;
        }
        if (c == EOF) {
            /* securityfs/lsm is a bounded string without a trailing newline;
             * its clean EOF is authoritative, unlike seq_file record streams. */
            if (allow_eof && used && !bad && !ferror(f)) {
                line[used] = '\0';
                return 1;
            }
            if (used || bad || ferror(f)) *partial = 1;
            return 0;
        }
        line[used] = '\0';
        if (bad) { *partial = 1; continue; }
        return 1;
    }
}

static int kernel_read_record(FILE *f, char *line, size_t capacity, int *partial) {
    return kernel_read_record_mode(f, line, capacity, partial, 0);
}

static char *kernel_token(char **cursor) {
    char *p = *cursor;
    while (*p == ' ' || *p == '\t') p++;
    if (!*p) { *cursor = p; return NULL; }
    char *token = p;
    while (*p && *p != ' ' && *p != '\t') p++;
    if (*p) *p++ = '\0';
    *cursor = p;
    return token;
}

static int kernel_number(const char *s, int hex) {
    if (hex && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    if (!*s) return 0;
    size_t digits = 0;
    for (; *s; s++, digits++)
        if (!(*s >= '0' && *s <= '9') &&
            !(hex && ((*s >= 'a' && *s <= 'f') || (*s >= 'A' && *s <= 'F'))))
            return 0;
    return digits <= (hex ? 16u : 20u);
}

static int kernel_identifier(const char *s) {
    if (!*s) return 0;
    for (; *s; s++)
        if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') ||
              (*s >= '0' && *s <= '9') || *s == '_' || *s == '-' || *s == '.'))
            return 0;
    return 1;
}

static int kprobe_suffix_valid(const char *s) {
    while (*s == ' ' || *s == '\t') s++;
    /* kallsyms emits the module name as a separate optional field. */
    if (*s && *s != '[') {
        size_t n = strcspn(s, " \t");
        if (n > 255u) return 0;
        s += n;
    }
    while (*s) {
        while (*s == ' ' || *s == '\t') s++;
        if (!*s) break;
        if (*s != '[') return 0;
        const char *end = strchr(s, ']');
        if (!end || end == s + 1 || (size_t)(end - s) > 256u) return 0;
        s = end + 1;
    }
    return 1;
}

static int tracefs_path(const char *suffix, char *out, size_t outsz) {
    const char *roots[] = {
        "/sys/kernel/tracing",
        "/sys/kernel/debug/tracing",
        NULL
    };
    for (int i = 0; roots[i]; i++) {
        snprintf(out, outsz, "%s/%s", roots[i], suffix);
        if (access(out, F_OK) == 0) return 1;
    }
    out[0] = '\0';
    return 0;
}

/* debugfs emits exactly "0\n" or "1\n". An unavailable or partial value
 * cannot establish whether a registered probe is currently armed. */
static int kprobes_global_enabled(void) {
    FILE *f = fopen("/sys/kernel/debug/kprobes/enabled", "r");
    if (!f) return -1;
    char value[3];
    size_t len = fread(value, 1, sizeof(value), f);
    int failed = ferror(f);
    fclose(f);
    if (failed || len != 2 || value[1] != '\n' ||
        (value[0] != '0' && value[0] != '1'))
        return -1;
    return value[0] - '0';
}

int scan_kprobes(const Config *config, int *incomplete) {
    const char *path = "/sys/kernel/debug/kprobes/list";

    if (!config->json_output)
        printf("[*] Scanning kprobes...\n");
    else
        printf("\"kprobes\":[");

    FILE *f = fopen(path, "r");
    if (!f) {
        if (incomplete) *incomplete = 1;
        if (config->json_output) {
            printf("]");
        } else {
            if (errno == EACCES || errno == EPERM)
                printf("[!] %s not readable (need root)\n", path);
            else if (errno == ENOENT)
                printf("[!] %s missing (debugfs not mounted / kprobes disabled)\n", path);
            else
                printf("[!] Cannot open %s: %s\n", path, strerror(errno));
        }
        return 0;
    }

    int globally_enabled = kprobes_global_enabled();
    if (globally_enabled < 0) {
        if (incomplete) *incomplete = 1;
        if (!config->json_output)
            printf("[?] Kprobe global enable state unavailable or invalid; activity may be unknown\n");
    } else if (!globally_enabled && !config->json_output) {
        printf("[*] Kprobes are globally disabled\n");
    }

    int active = 0, allowed_active = 0, signals = 0;
    int total = 0, printed = 0, unknown = 0;
    int listing_incomplete = 0;
    char line[KERNEL_RECORD_SIZE];

    while (kernel_read_record(f, line, sizeof(line), &listing_incomplete)) {
        if (line[0] == '\0' || line[0] == '\n' || line[0] == '#') continue;
        line[strcspn(line, "\n")] = '\0';

        char *cursor = line;
        char *addr = kernel_token(&cursor);
        char *type = kernel_token(&cursor);
        char *symbol = kernel_token(&cursor);
        if (!addr || !type || !symbol || !kernel_number(addr, 1) ||
            (strcmp(type, "k") && strcmp(type, "r")) ||
            !kprobe_suffix_valid(cursor)) {
            listing_incomplete = 1;
            continue;
        }

        int disabled  = strstr(cursor, "[DISABLED]")  != NULL;
        int gone      = strstr(cursor, "[GONE]")      != NULL;
        int optimized = strstr(cursor, "[OPTIMIZED]") != NULL;
        int ftrace    = strstr(cursor, "[FTRACE]")    != NULL;
        int probe_active = (disabled || gone || globally_enabled == 0)
            ? 0 : globally_enabled;
        int allowed = probe_active > 0 && policy_allows(config, "kprobe", symbol, type);

        total++;
        if (probe_active > 0) { active++; allowed_active += allowed; signals += !allowed; }
        else if (probe_active < 0) unknown++;

        if (config->json_output) {
            if (printed > 0) printf(",");
            printf("{\"address\":\"");
            json_print_escaped(addr);
            printf("\",\"type\":\"");
            json_print_escaped(type);
            printf("\",\"symbol\":\"");
            json_print_escaped(symbol);
            printf("\",\"active\":%s,\"disabled\":%s,\"gone\":%s,"
                   "\"globally_enabled\":%s,\"optimized\":%s,\"ftrace_based\":%s,"
                   "\"allowed\":%s}",
                   probe_active < 0 ? "null" : (probe_active ? "true" : "false"),
                   disabled ? "true" : "false",
                   gone ? "true" : "false",
                   globally_enabled < 0 ? "null" : (globally_enabled ? "true" : "false"),
                   optimized ? "true" : "false",
                   ftrace ? "true" : "false", allowed ? "true" : "false");
            printed++;
        } else if (config->verbose) {
            printf("  %-18s %-3s %s%s%s%s%s%s\n",
                   addr, type, symbol,
                   disabled  ? " [DISABLED]"  : "",
                   gone      ? " [GONE]"      : "",
                   optimized ? " [OPTIMIZED]" : "",
                   ftrace    ? " [FTRACE]"    : "",
                   probe_active < 0 ? " [ACTIVITY UNKNOWN]" :
                   allowed ? " [ALLOW]" : "");
        }
    }
    if (ferror(f)) listing_incomplete = 1;
    fclose(f);
    if (listing_incomplete && incomplete) *incomplete = 1;

    if (config->json_output) {
        printf("]");
    } else {
        if (listing_incomplete)
            printf("[?] Kprobe listing could not be fully read or parsed\n");
        if (total == 0 && !listing_incomplete)
            printf("[+] No kprobes registered\n");
        else {
            printf("    %d kprobe(s) registered (%d active", total, active);
            if (allowed_active) printf(", %d allowed", allowed_active);
            if (unknown) printf(", %d activity unknown", unknown);
            printf(")%s\n",
                   config->verbose ? "" : " — run with -v for the list");
        }
    }

    return signals;
}

static void finish_uprobe_output(const Config *config, int tracefs_inspected) {
    const char *reason = "Non-tracefs uprobes (including non-BPF perf attachments) "
                         "are not enumerated.";
    if (config->json_output) {
        printf("],\"uprobe_coverage\":{\"complete\":false,\"tracefs_inspected\":%s,"
               "\"reason\":\"", tracefs_inspected ? "true" : "false");
        json_print_escaped(reason);
        printf("\"}");
    } else {
        printf("[?] Uprobe coverage incomplete: %s\n", reason);
    }
}

int scan_uprobes(const Config *config, int *incomplete) {
    char path[256];
    int  have_path = tracefs_path("uprobe_events", path, sizeof(path));

    /* trace_uprobe.c does not add perf_event_open-created local probes to
     * dyn_event, which backs uprobe_events. BPF_TASK_FD_QUERY also rejects
     * perf events without a BPF program (bpf_get_perf_event_info). Thus this
     * source cannot establish that no uprobes exist outside tracefs. */
    if (incomplete) *incomplete = 1;

    if (!config->json_output)
        printf("[*] Scanning uprobes...\n");
    else
        printf("\"uprobes\":[");

    if (!have_path) {
        if (!config->json_output) printf("[!] tracefs uprobe_events not found\n");
        finish_uprobe_output(config, 0);
        return 0;
    }

    FILE *f = fopen(path, "r");
    if (!f) {
        if (!config->json_output) {
            if (errno == EACCES || errno == EPERM)
                printf("[!] %s not readable (need root)\n", path);
            else
                printf("[!] Cannot open %s: %s\n", path, strerror(errno));
        }
        finish_uprobe_output(config, 0);
        return 0;
    }

    int total = 0, allowed_total = 0, signals = 0, printed = 0, read_failed = 0;
    char line[KERNEL_RECORD_SIZE];

    while (kernel_read_record(f, line, sizeof(line), &read_failed)) {
        if (line[0] == '\0' || line[0] == '\n' || line[0] == '#') continue;
        line[strcspn(line, "\n")] = '\0';

        char *cursor = line;
        char *prefix = kernel_token(&cursor);
        while (*cursor == ' ' || *cursor == '\t') cursor++;
        char *target = cursor;
        char *separator = prefix ? strchr(prefix, ':') : NULL;
        if (!prefix || !separator || separator == prefix ||
            (prefix[0] != 'p' && prefix[0] != 'r') || !separator[1] || !*target) {
            read_failed = 1;
            continue;
        }

        int allowed = policy_allows(config, "uprobe", target, prefix);
        total++;
        allowed_total += allowed;
        signals += !allowed;

        if (config->json_output) {
            if (printed > 0) printf(",");
            printf("{\"event\":\"");
            json_print_escaped(prefix);
            printf("\",");
            json_print_string_field("target", target);
            printf(",\"allowed\":%s}", allowed ? "true" : "false");
            printed++;
        } else if (config->verbose) {
            printf("  %s  %s%s\n", prefix, target, allowed ? " [ALLOW]" : "");
        }
    }
    if (ferror(f)) read_failed = 1;
    fclose(f);

    if (!config->json_output) {
        if (read_failed)
            printf("[!] Failed while reading %s; tracefs listing is incomplete\n", path);
        if (total == 0)
            printf("[*] No uprobe events found in the inspected tracefs listing\n");
        else
            printf("    %d tracefs uprobe event(s) registered%s\n",
                   total,
                   config->verbose ? "" : " — run with -v for the list");
        if (allowed_total && config->verbose)
            printf("    %d tracefs uprobe event(s) allowed by policy\n", allowed_total);
    }
    finish_uprobe_output(config, !read_failed);

    return signals;
}

static int ftrace_redirection_flags(const char *line, int *ip_modify,
                                     int *direct_call) {
    *ip_modify = 0;
    *direct_call = 0;

    /* The count is followed by single-letter flags, then optional callback
     * details. Stop at that suffix so letters in module/callback names are
     * never interpreted as flags. 'M' records history, not an active redirect. */
    const char *p = strchr(line, '(');
    if (!p || p == line || (p[-1] != ' ' && p[-1] != '\t') ||
        p[1] < '0' || p[1] > '9') return 0;
    p++;
    while (*p >= '0' && *p <= '9') p++;
    if (*p++ != ')' || (*p && *p != ' ' && *p != '\t')) return 0;

    while (*p) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        char flag = *p++;
        if (*p && *p != ' ' && *p != '\t') {
            p--;
            return !strncmp(p, "->", 2) || !strncmp(p, "tramp:", 6) ||
                   !strncmp(p, "ops:", 4) || *p == '{';
        }
        if (flag == 'I') *ip_modify = 1;
        else if (flag == 'D') *direct_call = 1;
        else if (flag != 'R' && flag != 'O' && flag != 'M') return 0;
    }
    return 1;
}

int scan_ftrace_hooks(const Config *config, int *incomplete) {
    char enabled_path[256], tracer_path[256];
    int  have_enabled = tracefs_path("enabled_functions", enabled_path, sizeof(enabled_path));
    int  have_tracer  = tracefs_path("current_tracer",    tracer_path,  sizeof(tracer_path));

    if (!config->json_output)
        printf("[*] Scanning ftrace hooks...\n");
    else
        printf("\"ftrace_hooks\":[");

    int listing_incomplete = 0, tracer_incomplete = !have_tracer;
    char tracer[64] = {0};
    if (have_tracer) {
        FILE *tf = fopen(tracer_path, "r");
        if (tf) {
            if (!kernel_read_record(tf, tracer, sizeof(tracer), &tracer_incomplete) ||
                !kernel_identifier(tracer)) tracer_incomplete = 1;
            char extra[64];
            if (kernel_read_record(tf, extra, sizeof(extra), &tracer_incomplete))
                tracer_incomplete = 1;
            fclose(tf);
        } else tracer_incomplete = 1;
    }
    if (tracer_incomplete) {
        tracer[0] = '\0';
        if (incomplete) *incomplete = 1;
        if (!config->json_output)
            printf("[?] Ftrace current_tracer could not be fully read or parsed\n");
    }

    int printed = 0;
    int hooks_with_tramp = 0;
    int redirections    = 0;
    int allowed_redirects = 0;
    int hooks_total      = 0;
    int tracer_signal    = 0;

    if (tracer[0] && strcmp(tracer, "nop") != 0) {
        int allowed = policy_allows(config, "ftrace", "current_tracer", tracer);
        tracer_signal = config->profile_strict && !allowed;
        if (config->json_output) {
            printf("{\"kind\":\"current_tracer\",\"value\":\"");
            json_print_escaped(tracer);
            printf("\",\"signal\":%s,\"allowed\":%s}",
                   tracer_signal ? "true" : "false", allowed ? "true" : "false");
            printed++;
        } else {
            printf("  [!] current_tracer = %s (kernel-wide function tracing active)\n",
                   tracer);
        }
    }

    if (!have_enabled) {
        if (incomplete) *incomplete = 1;
        if (config->json_output) printf("]");
        else if (!tracer[0]) printf("[!] tracefs not available\n");
        return tracer_signal;
    }

    FILE *f = fopen(enabled_path, "r");
    if (!f) {
        if (incomplete) *incomplete = 1;
        if (config->json_output) {
            printf("]");
        } else {
            if (errno == EACCES || errno == EPERM)
                printf("[!] %s not readable (need root)\n", enabled_path);
            else
                printf("[!] Cannot open %s: %s\n", enabled_path, strerror(errno));
        }
        return tracer_signal;
    }

    char line[KERNEL_RECORD_SIZE];
    int previous_direct = 0;
    while (kernel_read_record(f, line, sizeof(line), &listing_incomplete)) {
        if (line[0] == '\0' || line[0] == '\n' || line[0] == '#') continue;
        line[strcspn(line, "\n")] = '\0';
        /* The kernel emits direct trampoline details on a second indented
         * line. It is metadata for the preceding site, not another site. */
        if (line[0] == '\t' || line[0] == ' ') {
            const char *detail = line;
            while (*detail == ' ' || *detail == '\t') detail++;
            if (!previous_direct ||
                !((!strncmp(detail, "direct-->", 9) && detail[9]) ||
                  (!strncmp(detail, "direct(jmp)-->", 14) && detail[14])))
                listing_incomplete = 1;
            previous_direct = 0;
            continue;
        }

        /* A direct record without its following target detail is not a
         * complete snapshot (the seq_file record was truncated or raced). */
        if (previous_direct) listing_incomplete = 1;

        int ip_modify, direct_call;
        if (!ftrace_redirection_flags(line, &ip_modify, &direct_call)) {
            listing_incomplete = 1;
            previous_direct = 0;
            continue;
        }
        previous_direct = direct_call;
        hooks_total++;

        char *cursor = line;
        char *symbol = kernel_token(&cursor);
        if (strstr(cursor, "ERROR!")) listing_incomplete = 1;

        const char *tramp = strstr(cursor, "tramp:");
        int has_tramp = (tramp != NULL);
        if (has_tramp) hooks_with_tramp++;
        int allowed = (ip_modify || direct_call) &&
            policy_allows(config, "ftrace", symbol,
                          direct_call ? "direct" : "ipmodify");
        if (ip_modify || direct_call) {
            redirections += !allowed;
            allowed_redirects += allowed;
        }

        if (config->json_output) {
            if (printed > 0) printf(",");
            printf("{\"kind\":\"function\",\"symbol\":\"");
            json_print_escaped(symbol);
            printf("\",\"has_trampoline\":%s,\"ip_modify\":%s,\"direct_call\":%s,"
                   "\"allowed\":%s",
                   has_tramp ? "true" : "false",
                   ip_modify ? "true" : "false",
                   direct_call ? "true" : "false",
                   allowed ? "true" : "false");
            if (has_tramp) {
                printf(",\"trampoline\":\"");
                json_print_escaped(tramp);
                printf("\"");
            }
            printf("}");
            printed++;
        } else if (config->verbose || ((ip_modify || direct_call) && !allowed)) {
            printf("  %-48s %s%s%s%s\n", symbol,
                   ip_modify ? "[IPMODIFY] " : "",
                   direct_call ? "[DIRECT] " : "",
                   has_tramp ? tramp : "(standard/shared trampoline)",
                   allowed ? " [ALLOW]" : "");
        }
    }
    if (previous_direct) listing_incomplete = 1;
    if (ferror(f)) listing_incomplete = 1;
    fclose(f);
    if (listing_incomplete && incomplete) *incomplete = 1;

    if (config->json_output) {
        printf("]");
    } else {
        if (listing_incomplete)
            printf("[?] Ftrace callback listing could not be fully read or parsed\n");
        if (hooks_total == 0 && !listing_incomplete)
            printf("[+] No ftrace function hooks\n");
        else
            printf("    %d ftrace callback site(s), %d redirection signal(s), "
                   "%d with custom trampoline%s\n",
                   hooks_total, redirections, hooks_with_tramp,
                   config->verbose ? "" : " — run with -v for the list");
        if (allowed_redirects && config->verbose)
            printf("    %d ftrace redirection(s) allowed by policy\n", allowed_redirects);
    }

    return redirections + tracer_signal;
}


int scan_lsm_modules(const Config *config, int *incomplete) {
    const char *path = "/sys/kernel/security/lsm";

    if (!config->json_output)
        printf("[*] Active LSMs...\n");
    else
        printf("\"lsm_modules\":[");

    FILE *f = fopen(path, "r");
    if (!f) {
        if (incomplete) *incomplete = 1;
        if (config->json_output) {
            printf("]");
        } else {
            printf("[!] Cannot read %s: %s\n", path, strerror(errno));
        }
        return 0;
    }

    int listing_incomplete = 0;
    char buf[KERNEL_RECORD_SIZE];
    if (!kernel_read_record_mode(f, buf, sizeof(buf), &listing_incomplete, 1) || !buf[0]) {
        if (incomplete) *incomplete = 1;
        fclose(f);
        if (config->json_output) printf("]");
        else printf("[!] %s empty, unreadable, or malformed\n", path);
        return 0;
    }
    char extra[KERNEL_RECORD_SIZE];
    if (kernel_read_record_mode(f, extra, sizeof(extra), &listing_incomplete, 1))
        listing_incomplete = 1;
    if (ferror(f)) listing_incomplete = 1;
    fclose(f);
    buf[strcspn(buf, "\n")] = '\0';

    static const char *known[] = {
        "capability", "yama", "apparmor", "selinux", "tomoyo", "smack",
        "landlock", "lockdown", "integrity", "ima", "evm", "bpf", "safesetid",
        "loadpin", "ipe",
        NULL
    };

    int printed = 0, unknown = 0;
    char *cursor = buf;
    char *tok;
    while ((tok = strsep(&cursor, ",")) != NULL) {
        if (!kernel_identifier(tok)) { listing_incomplete = 1; continue; }
        int is_known = 0;
        for (int i = 0; known[i]; i++) {
            if (strcmp(tok, known[i]) == 0) { is_known = 1; break; }
        }
        int allowed = !is_known && policy_allows(config, "lsm", tok, "");
        if (!is_known && !allowed) unknown++;

        if (config->json_output) {
            if (printed > 0) printf(",");
            printf("{\"name\":\"");
            json_print_escaped(tok);
            printf("\",\"known\":%s,\"allowed\":%s}",
                   is_known ? "true" : "false", allowed ? "true" : "false");
            printed++;
        } else {
            printf("  %s%s\n", tok, is_known ? "" :
                   allowed ? "  [ALLOW] unknown LSM" : "  [!] unknown LSM");
        }
    }

    if (listing_incomplete && incomplete) *incomplete = 1;
    if (listing_incomplete && !config->json_output)
        printf("[?] LSM listing could not be fully read or parsed\n");

    if (config->json_output)
        printf("]");
    else if (unknown > 0)
        printf("[!] %d unknown LSM(s) present — investigate\n", unknown);

    return unknown;
}

int scan_tainted_modules(const Config *config, int *incomplete) {
    const char *path = "/proc/modules";

    if (!config->json_output)
        printf("[*] Scanning kernel modules...\n");
    else
        printf("\"kernel_modules\":[");

    FILE *f = fopen(path, "r");
    if (!f) {
        if (incomplete) *incomplete = 1;
        if (config->json_output) {
            printf("]");
        } else {
            printf("[!] Cannot open %s: %s\n", path, strerror(errno));
        }
        return 0;
    }

    int printed = 0;
    int suspicious = 0;
    int total = 0, listing_incomplete = 0;
    char line[KERNEL_RECORD_SIZE];

    while (kernel_read_record(f, line, sizeof(line), &listing_incomplete)) {
        if (line[0] == '\0' || line[0] == '\n') continue;
        line[strcspn(line, "\n")] = '\0';
        char *cursor = line;
        char *name = kernel_token(&cursor);
        char *size = kernel_token(&cursor);
        char *references = kernel_token(&cursor);
        char *dependencies = kernel_token(&cursor);
        char *state = kernel_token(&cursor);
        char *address = kernel_token(&cursor);
        if (!name || !size || !references || !dependencies || !state || !address ||
            !kernel_identifier(name) || !kernel_number(size, 0) ||
            (strcmp(references, "-") && !kernel_number(references[0] == '-' ? references + 1 : references, 0)) ||
            (strcmp(state, "Live") && strcmp(state, "Loading") && strcmp(state, "Unloading")) ||
            !kernel_number(address, 1)) {
            listing_incomplete = 1;
            continue;
        }

        /* Taint flags are the last parenthesised field on the line. */
        char taint[32] = {0};
        while (*cursor == ' ' || *cursor == '\t') cursor++;
        const char *lp = *cursor == '(' ? cursor : NULL;
        const char *rp = lp ? strchr(lp, ')') : NULL;
        if (*cursor) {
            if (!lp || !rp || rp == lp + 1 ||
                (size_t)(rp - lp - 1) >= sizeof(taint)) {
                listing_incomplete = 1;
                continue;
            }
            const char *tail = rp + 1;
            while (*tail == ' ' || *tail == '\t') tail++;
            int valid_flags = !*tail;
            for (const char *flag = lp + 1; flag < rp; flag++)
                if (!((*flag >= 'A' && *flag <= 'Z') || *flag == '+' || *flag == '-'))
                    valid_flags = 0;
            if (!valid_flags) { listing_incomplete = 1; continue; }
            size_t n = (size_t)(rp - lp - 1);
            memcpy(taint, lp + 1, n);
            taint[n] = '\0';
        }
        total++;

        int out_of_tree = (strchr(taint, 'O') != NULL);
        int unsigned_m  = (strchr(taint, 'E') != NULL);
        int forced      = (strchr(taint, 'F') != NULL);
        int proprietary = (strchr(taint, 'P') != NULL);

        int interesting = (out_of_tree || unsigned_m || forced);
        int allowed = interesting && policy_allows(config, "module", name, taint);
        if (interesting && !allowed) suspicious++;

    
        if (config->json_output) {
            if (printed > 0) printf(",");
            printf("{\"name\":\"");
            json_print_escaped(name);
            printf("\",\"taint\":\"");
            json_print_escaped(taint);
            printf("\",\"out_of_tree\":%s,\"unsigned\":%s,\"forced\":%s,\"proprietary\":%s,"
                   "\"allowed\":%s}",
                   out_of_tree ? "true" : "false",
                   unsigned_m  ? "true" : "false",
                   forced      ? "true" : "false",
                   proprietary ? "true" : "false", allowed ? "true" : "false");
            printed++;
        } else if (interesting || config->verbose) {
            printf("  %-32s taint=[%s]%s%s%s%s\n",
                   name, taint[0] ? taint : "-",
                   out_of_tree ? " out-of-tree" : "",
                   unsigned_m  ? " UNSIGNED"    : "",
                   forced      ? " forced"      : "",
                   allowed     ? " [ALLOW]"     : "");
        }
    }
    if (ferror(f)) listing_incomplete = 1;
    fclose(f);
    if (listing_incomplete && incomplete) *incomplete = 1;

    if (config->json_output) {
        printf("]");
    } else {
        if (listing_incomplete)
            printf("[?] Kernel module listing could not be fully read or parsed\n");
        printf("    %d module(s) loaded, %d flagged (out-of-tree / unsigned / forced)\n",
               total, suspicious);
    }

    return suspicious;
}

/* Minimal BTF reader used only to derive randomized live LSM layouts. */
struct kernel_btf_header {
    uint16_t magic;
    uint8_t version, flags;
    uint32_t hdr_len, type_off, type_len, str_off, str_len;
};
struct kernel_btf_type { uint32_t name_off, info, size_type; };
struct kernel_btf_member { uint32_t name_off, type, offset; };
struct kernel_btf_array { uint32_t type, index_type, nelems; };
typedef struct {
    uint8_t *data;
    const uint8_t *types;
    uint32_t type_len;
    const char *strings;
    uint32_t str_len;
} KernelBtf;

static uint32_t kernel_btf_extra(uint32_t kind, uint32_t vlen) {
    switch (kind) {
        case 1: return 4;
        case 3: return 12;
        case 4: case 5: return vlen <= 0xffffu ? vlen * 12u : UINT32_MAX;
        case 6: case 13: return vlen <= 0xffffu ? vlen * 8u : UINT32_MAX;
        case 14: case 17: return 4;
        case 15: case 19: return vlen <= 0xffffu ? vlen * 12u : UINT32_MAX;
        case 0: case 2: case 7: case 8: case 9: case 10: case 11:
        case 12: case 16: case 18: return 0;
        default: return UINT32_MAX;
    }
}

static void kernel_btf_close(KernelBtf *btf) {
    free(btf->data);
    memset(btf, 0, sizeof(*btf));
}

static int kernel_btf_load(KernelBtf *btf) {
    memset(btf, 0, sizeof(*btf));
    int fd = open("/sys/kernel/btf/vmlinux", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size < (off_t)sizeof(struct kernel_btf_header) ||
        st.st_size > 64 * 1024 * 1024) {
        close(fd); errno = EINVAL; return -1;
    }
    size_t size = (size_t)st.st_size;
    uint8_t *data = malloc(size);
    if (!data) { close(fd); errno = ENOMEM; return -1; }
    size_t done = 0;
    while (done < size) {
        ssize_t got = read(fd, data + done, size - done);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) { free(data); close(fd); errno = EIO; return -1; }
        done += (size_t)got;
    }
    close(fd);
    struct kernel_btf_header h;
    memcpy(&h, data, sizeof(h));
    if (h.magic != 0xeb9fu || h.version != 1 || h.hdr_len < sizeof(h) ||
        h.hdr_len > size || h.type_off > size - h.hdr_len ||
        h.str_off > size - h.hdr_len) {
        free(data); errno = EINVAL; return -1;
    }
    uint32_t types = h.hdr_len + h.type_off, strings = h.hdr_len + h.str_off;
    if (h.type_len > size - types || h.str_len > size - strings) {
        free(data); errno = EINVAL; return -1;
    }
    uint32_t off = 0;
    while (off < h.type_len) {
        struct kernel_btf_type t;
        if (h.type_len - off < sizeof(t)) { free(data); errno = EINVAL; return -1; }
        memcpy(&t, data + types + off, sizeof(t));
        uint32_t extra = kernel_btf_extra((t.info >> 24) & 0x1fu, t.info & 0xffffu);
        if (extra == UINT32_MAX || extra > h.type_len - off - sizeof(t)) {
            free(data); errno = EINVAL; return -1;
        }
        off += (uint32_t)sizeof(t) + extra;
    }
    btf->data = data;
    btf->types = data + types;
    btf->type_len = h.type_len;
    btf->strings = (const char *)data + strings;
    btf->str_len = h.str_len;
    return 0;
}

static const char *kernel_btf_string(const KernelBtf *btf, uint32_t off) {
    if (off >= btf->str_len ||
        !memchr(btf->strings + off, '\0', btf->str_len - off)) return NULL;
    return btf->strings + off;
}

static int kernel_btf_type_id(const KernelBtf *btf, uint32_t id,
                              struct kernel_btf_type *type,
                              const uint8_t **payload) {
    uint32_t off = 0;
    for (uint32_t current = 1; off < btf->type_len; current++) {
        struct kernel_btf_type t;
        memcpy(&t, btf->types + off, sizeof(t));
        uint32_t extra = kernel_btf_extra((t.info >> 24) & 0x1fu, t.info & 0xffffu);
        if (current == id) {
            *type = t;
            if (payload) *payload = btf->types + off + sizeof(t);
            return 1;
        }
        off += (uint32_t)sizeof(t) + extra;
    }
    return 0;
}

static int kernel_btf_find(const KernelBtf *btf, uint32_t kind,
                           const char *name, uint32_t *id_out,
                           struct kernel_btf_type *type_out) {
    uint32_t off = 0;
    for (uint32_t id = 1; off < btf->type_len; id++) {
        struct kernel_btf_type t;
        memcpy(&t, btf->types + off, sizeof(t));
        uint32_t tkind = (t.info >> 24) & 0x1fu;
        uint32_t extra = kernel_btf_extra(tkind, t.info & 0xffffu);
        const char *tname = kernel_btf_string(btf, t.name_off);
        if (tkind == kind && tname && !strcmp(tname, name)) {
            *id_out = id;
            if (type_out) *type_out = t;
            return 1;
        }
        off += (uint32_t)sizeof(t) + extra;
    }
    return 0;
}

static int kernel_btf_member_named(const KernelBtf *btf, uint32_t struct_id,
                                   const char *name, uint32_t *type_id,
                                   uint32_t *byte_offset) {
    struct kernel_btf_type t;
    const uint8_t *payload;
    if (!kernel_btf_type_id(btf, struct_id, &t, &payload) ||
        (((t.info >> 24) & 0x1fu) != 4u && ((t.info >> 24) & 0x1fu) != 5u))
        return 0;
    uint32_t vlen = t.info & 0xffffu;
    int kind_flag = (t.info >> 31) != 0;
    for (uint32_t i = 0; i < vlen; i++) {
        struct kernel_btf_member m;
        memcpy(&m, payload + i * sizeof(m), sizeof(m));
        const char *member = kernel_btf_string(btf, m.name_off);
        uint32_t bits = kind_flag ? m.offset & 0xffffffu : m.offset;
        uint32_t width = kind_flag ? m.offset >> 24 : 0;
        if (member && !strcmp(member, name) && bits % 8u == 0 && width == 0) {
            *type_id = m.type;
            *byte_offset = bits / 8u;
            return 1;
        }
    }
    return 0;
}

static int kernel_btf_resolve(const KernelBtf *btf, uint32_t *id,
                              struct kernel_btf_type *type,
                              const uint8_t **payload) {
    for (int depth = 0; depth < 16; depth++) {
        if (!kernel_btf_type_id(btf, *id, type, payload)) return 0;
        uint32_t kind = (type->info >> 24) & 0x1fu;
        if (kind != 8u && kind != 9u && kind != 10u && kind != 11u &&
            kind != 18u) return 1;
        *id = type->size_type;
    }
    return 0;
}

static int kernel_btf_array_info(const KernelBtf *btf, uint32_t id,
                                 uint32_t *element_type, uint32_t *count) {
    struct kernel_btf_type t;
    const uint8_t *payload;
    if (!kernel_btf_resolve(btf, &id, &t, &payload) ||
        ((t.info >> 24) & 0x1fu) != 3u) return 0;
    struct kernel_btf_array array;
    memcpy(&array, payload, sizeof(array));
    *element_type = array.type;
    *count = array.nelems;
    return 1;
}

static int kernel_btf_struct_size(const KernelBtf *btf, uint32_t id,
                                  uint32_t *size) {
    struct kernel_btf_type t;
    if (!kernel_btf_resolve(btf, &id, &t, NULL) ||
        ((t.info >> 24) & 0x1fu) != 4u || !t.size_type) return 0;
    *size = t.size_type;
    return 1;
}

static int kernel_core_read_string(const KernelCore *core, uint64_t address,
                                   char *out, size_t size) {
    if (!address || size < 2 || kernel_core_read(core, address, out, size - 1) < 0)
        return -1;
    out[size - 1] = '\0';
    char *nul = memchr(out, '\0', size - 1);
    if (!nul) { errno = EINVAL; return -1; }
    for (char *p = out; p < nul; p++)
        if ((unsigned char)*p < 0x20 || (unsigned char)*p >= 0x7f) {
            errno = EINVAL; return -1;
        }
    return 0;
}

static int active_lsm_name(const char *active, const char *name) {
    size_t n = strlen(name);
    const char *p = active;
    while (p && *p) {
        size_t len = strcspn(p, ",\n");
        if (len == n && !memcmp(p, name, n)) return 1;
        p += len;
        if (*p) p++;
    }
    return 0;
}

static int lsm_hook_offsets(const KernelBtf *btf, uint32_t *hook_list_type,
                            uint32_t *hook_off, uint32_t *owner_off,
                            uint32_t *owner_name_off, int *owner_is_id) {
    uint32_t hook_type = 0;
    if (!kernel_btf_find(btf, 4, "security_hook_list", hook_list_type, NULL) ||
        !kernel_btf_member_named(btf, *hook_list_type, "hook", &hook_type,
                                 hook_off))
        return 0;
    uint32_t owner_type = 0;
    if (kernel_btf_member_named(btf, *hook_list_type, "lsmid", &owner_type,
                                owner_off)) {
        struct kernel_btf_type ptr, owner;
        if (!kernel_btf_type_id(btf, owner_type, &ptr, NULL) ||
            ((ptr.info >> 24) & 0x1fu) != 2u) return 0;
        owner_type = ptr.size_type;
        if (!kernel_btf_resolve(btf, &owner_type, &owner, NULL) ||
            ((owner.info >> 24) & 0x1fu) != 4u ||
            !kernel_btf_member_named(btf, owner_type, "name", &owner_type,
                                     owner_name_off))
            return 0;
        *owner_is_id = 1;
        return 1;
    }
    if (kernel_btf_member_named(btf, *hook_list_type, "lsm", &owner_type,
                                owner_off)) {
        *owner_name_off = 0;
        *owner_is_id = 0;
        return 1;
    }
    return 0;
}

static int read_lsm_hook(const KernelCore *core, uint64_t hook_list,
                         uint32_t hook_off, uint32_t owner_off,
                         uint32_t owner_name_off, int owner_is_id,
                         uint64_t *callback, char *owner, size_t owner_size) {
    uint64_t owner_object = 0, owner_name = 0;
    if (kernel_core_read(core, hook_list + hook_off, callback, sizeof(*callback)) < 0 ||
        kernel_core_read(core, hook_list + owner_off, &owner_object,
                         sizeof(owner_object)) < 0 || !*callback || !owner_object)
        return -1;
    if (owner_is_id) {
        if (kernel_core_read(core, owner_object + owner_name_off, &owner_name,
                             sizeof(owner_name)) < 0) return -1;
    } else owner_name = owner_object;
    return kernel_core_read_string(core, owner_name, owner, owner_size);
}

static int report_lsm_hook(const Config *config, int *printed, const char *hook,
                           const char *owner, uint64_t expected_callback,
                           uint64_t callback,
                           uint64_t text_start, uint64_t text_end,
                           const char *active, int *callbacks) {
    int outside = callback < text_start || callback >= text_end;
    int owner_inactive = active[0] && !active_lsm_name(active, owner);
    int target_changed = callback != expected_callback;
    int mismatch = outside || owner_inactive || target_changed;
    (*callbacks)++;
    if (!mismatch && config->verbose <= 1) return 0;
    char callback_name[512] = {0}, detail[768];
    if (kallsyms_address_name(callback, callback_name, sizeof(callback_name)) <= 0)
        snprintf(callback_name, sizeof(callback_name), "0x%016" PRIx64, callback);
    snprintf(detail, sizeof(detail), "%s:%s", owner, callback_name);
    int allowed = mismatch && policy_allows(config, "lsm_hook", hook, detail);

    if (config->json_output && (mismatch || config->verbose > 1)) {
        if ((*printed)++) printf(",");
        printf("{\"kind\":\"lsm_hook\",\"hook\":\"");
        json_print_escaped(hook);
        printf("\",");
        json_print_string_field("owner", owner);
        printf(",\"callback\":\"");
        json_print_escaped(callback_name);
        printf("\",\"address\":\"0x%016" PRIx64 "\","
               "\"expected_address\":\"0x%016" PRIx64 "\",\"target_changed\":%s,"
               "\"outside_core_text\":%s,\"owner_inactive\":%s,"
               "\"mismatch\":%s,\"allowed\":%s}",
               callback, expected_callback, target_changed ? "true" : "false",
               outside ? "true" : "false",
               owner_inactive ? "true" : "false", mismatch ? "true" : "false",
               allowed ? "true" : "false");
    } else if (!config->json_output && (mismatch || config->verbose > 1)) {
        printf("  LSM %-24s owner=%s callback=%s%s%s%s%s\n", hook, owner,
               callback_name, outside ? " [OUTSIDE CORE TEXT]" : "",
               owner_inactive ? " [OWNER INACTIVE]" : "",
               target_changed ? " [TARGET CHANGED]" : "",
               allowed ? " [ALLOW]" : "");
    }
    return mismatch && !allowed;
}

static int scan_lsm_hook_table(const Config *config, int *incomplete,
                               const KernelCore *core, uint64_t text_start,
                               uint64_t text_end, int *printed) {
    static const char *const hooks[] = {
        "ptrace_access_check", "bprm_check_security", "inode_permission",
        "file_open", "file_permission", "mmap_file", "file_mprotect",
        "socket_connect", "task_kill", "kernel_read_file", "kernel_load_data",
        "bpf", NULL
    };
    KernelBtf btf;
    if (kernel_btf_load(&btf) < 0) {
        if (incomplete) *incomplete = 1;
        if (!config->json_output) printf("[?] Running-kernel BTF is unavailable for LSM validation\n");
        return 0;
    }
    uint32_t hook_list_type = 0, hook_off = 0, owner_off = 0, owner_name_off = 0;
    int owner_is_id = 0;
    if (!lsm_hook_offsets(&btf, &hook_list_type, &hook_off, &owner_off,
                          &owner_name_off, &owner_is_id)) {
        kernel_btf_close(&btf);
        if (incomplete) *incomplete = 1;
        if (!config->json_output) printf("[?] Running BTF lacks the LSM hook ownership layout\n");
        return 0;
    }

    char active[4096] = {0};
    FILE *af = fopen("/sys/kernel/security/lsm", "r");
    if (af) {
        size_t got = fread(active, 1, sizeof(active) - 1, af);
        if (ferror(af) || (!feof(af) && got == sizeof(active) - 1)) {
            active[0] = '\0';
            if (incomplete) *incomplete = 1;
        }
        fclose(af);
    } else if (incomplete) *incomplete = 1;

    uint64_t table = 0;
    int signals = 0, callbacks = 0, supported_hooks = 0, partial = 0;
    uint32_t table_type = 0;
    if (kallsyms_lookup("static_calls_table", &table) > 0 &&
        kernel_btf_find(&btf, 4, "lsm_static_calls_table", &table_type, NULL)) {
        uint32_t entry_type = 0, entry_size = 0, field_type = 0, hl_off = 0;
        uint32_t key_member_type = 0, key_off = 0, key_type = 0, key_func_off = 0;
        uint32_t active_off = 0, active_member_type = 0;
        uint32_t false_type = 0, false_key_type = 0, false_key_off = 0;
        uint32_t static_key_type = 0, enabled_type = 0, enabled_off = 0;
        uint32_t atomic_type = 0, counter_type = 0, counter_off = 0;
        /* Every selected member has the same fixed-size lsm_static_call array. */
        uint32_t member_type = 0, member_off = 0, slots = 0;
        if (!kernel_btf_member_named(&btf, table_type, hooks[0], &member_type, &member_off) ||
            !kernel_btf_array_info(&btf, member_type, &entry_type, &slots) ||
            !kernel_btf_struct_size(&btf, entry_type, &entry_size) ||
            !kernel_btf_member_named(&btf, entry_type, "hl", &field_type, &hl_off) ||
            !kernel_btf_member_named(&btf, entry_type, "key", &key_member_type, &key_off) ||
            !kernel_btf_member_named(&btf, entry_type, "active", &active_member_type,
                                     &active_off) ||
            !kernel_btf_find(&btf, 4, "static_key_false", &false_type, NULL) ||
            !kernel_btf_member_named(&btf, false_type, "key", &false_key_type,
                                     &false_key_off) ||
            !slots || slots > 64 || !entry_size) {
            partial = 1;
        } else {
            struct kernel_btf_type key_pointer;
            if (!kernel_btf_type_id(&btf, key_member_type, &key_pointer, NULL) ||
                ((key_pointer.info >> 24) & 0x1fu) != 2u) {
                partial = 1;
            } else {
                key_type = key_pointer.size_type;
                if (!kernel_btf_member_named(&btf, key_type, "func", &field_type,
                                             &key_func_off))
                    partial = 1;
            }
            static_key_type = false_key_type;
            if (!kernel_btf_resolve(&btf, &static_key_type, &key_pointer, NULL) ||
                !kernel_btf_member_named(&btf, static_key_type, "enabled",
                                         &enabled_type, &enabled_off)) {
                partial = 1;
            } else {
                atomic_type = enabled_type;
                if (!kernel_btf_resolve(&btf, &atomic_type, &key_pointer, NULL) ||
                    !kernel_btf_member_named(&btf, atomic_type, "counter",
                                             &counter_type, &counter_off))
                    partial = 1;
            }
        }
        if (!partial) for (int h = 0; hooks[h]; h++) {
            if (!kernel_btf_member_named(&btf, table_type, hooks[h],
                                         &member_type, &member_off))
                continue; /* Hook was compiled out by this kernel config. */
            supported_hooks++;
            for (uint32_t slot = 0; slot < slots; slot++) {
                uint64_t entry = table + member_off + (uint64_t)slot * entry_size;
                uint64_t hl = 0, expected_callback = 0, key = 0, live_callback = 0;
                uint64_t active_key = 0;
                int active_count = 0;
                if (kernel_core_read(core, entry + hl_off, &hl, sizeof(hl)) < 0) {
                    partial = 1; break;
                }
                if (!hl) continue;
                char owner[128];
                if (read_lsm_hook(core, hl, hook_off, owner_off, owner_name_off,
                                  owner_is_id, &expected_callback, owner, sizeof(owner)) < 0 ||
                    kernel_core_read(core, entry + key_off, &key, sizeof(key)) < 0 ||
                    !key || kernel_core_read(core, key + key_func_off, &live_callback,
                                             sizeof(live_callback)) < 0 ||
                    kernel_core_read(core, entry + active_off, &active_key,
                                     sizeof(active_key)) < 0 || !active_key ||
                    kernel_core_read(core, active_key + false_key_off + enabled_off +
                                     counter_off, &active_count,
                                     sizeof(active_count)) < 0) {
                    partial = 1; continue;
                }
                if (active_count <= 0) live_callback = 0;
                signals += report_lsm_hook(config, printed, hooks[h], owner,
                                           expected_callback, live_callback,
                                           text_start, text_end, active, &callbacks);
            }
        }
    } else if (kallsyms_lookup("security_hook_heads", &table) > 0) {
        uint32_t heads_type = 0, list_off = 0, next_off = 0;
        uint32_t hlist_type = 0, first_type = 0, first_off = 0;
        uint32_t hnode_type = 0, next_type = 0;
        if (!kernel_btf_find(&btf, 4, "security_hook_heads", &heads_type, NULL) ||
            !kernel_btf_member_named(&btf, hook_list_type, "list", &hnode_type, &list_off) ||
            !kernel_btf_find(&btf, 4, "hlist_node", &hnode_type, NULL) ||
            !kernel_btf_member_named(&btf, hnode_type, "next", &next_type, &next_off) ||
            !kernel_btf_find(&btf, 4, "hlist_head", &hlist_type, NULL) ||
            !kernel_btf_member_named(&btf, hlist_type, "first", &first_type, &first_off)) {
            partial = 1;
        } else for (int h = 0; hooks[h]; h++) {
            uint32_t head_type = 0, head_off = 0;
            if (!kernel_btf_member_named(&btf, heads_type, hooks[h], &head_type, &head_off))
                continue;
            supported_hooks++;
            uint64_t node = 0;
            if (kernel_core_read(core, table + head_off + first_off, &node,
                                 sizeof(node)) < 0) { partial = 1; continue; }
            for (int slot = 0; node && slot < 64; slot++) {
                if (node < list_off) { partial = 1; break; }
                uint64_t hl = node - list_off, callback = 0, next = 0;
                char owner[128];
                if (read_lsm_hook(core, hl, hook_off, owner_off, owner_name_off,
                                  owner_is_id, &callback, owner, sizeof(owner)) < 0 ||
                    kernel_core_read(core, node + next_off, &next, sizeof(next)) < 0 ||
                    next == node) {
                    partial = 1; break;
                }
                signals += report_lsm_hook(config, printed, hooks[h], owner, callback, callback,
                                           text_start, text_end, active, &callbacks);
                node = next;
                if (slot == 63 && node) partial = 1;
            }
        }
    } else partial = 1;
    if (!supported_hooks || !callbacks) partial = 1;
    kernel_btf_close(&btf);
    if (partial && incomplete) *incomplete = 1;
    if (!config->json_output)
        printf("    %d live LSM callback(s) validated across %d critical hook(s)%s\n",
               callbacks, supported_hooks, partial ? " (partial)" : "");
    return signals;
}

static const char *expected_x86_vector(unsigned int vector) {
    switch (vector) {
        case 0: return "asm_exc_divide_error";
        case 1: return "asm_exc_debug";
        case 2: return "asm_exc_nmi";
        case 3: return "asm_exc_int3";
        case 6: return "asm_exc_invalid_op";
        case 8: return "asm_exc_double_fault";
        case 13: return "asm_exc_general_protection";
        case 14: return "asm_exc_page_fault";
        case 18: return "asm_exc_machine_check";
        default: return NULL;
    }
}

static int scan_idt_table(const Config *config, int *incomplete,
                          const KernelCore *core, uint64_t text_start,
                          uint64_t text_end, int *printed) {
    uint64_t idt = 0;
    if (kallsyms_lookup("idt_table", &idt) <= 0) {
        if (incomplete) *incomplete = 1;
        if (!config->json_output) printf("[?] Live IDT backing table is unavailable\n");
        return 0;
    }
    uint8_t gates[256][16];
    if (kernel_core_read(core, idt, gates, sizeof(gates)) < 0) {
        if (incomplete) *incomplete = 1;
        if (!config->json_output) printf("[?] Live IDT backing table cannot be read\n");
        return 0;
    }

    int signals = 0, checked = 0, critical = 0;
    for (unsigned int vector = 0; vector < 256; vector++) {
        uint16_t low, segment, bits, middle;
        uint32_t high, reserved;
        memcpy(&low, gates[vector], sizeof(low));
        memcpy(&segment, gates[vector] + 2, sizeof(segment));
        memcpy(&bits, gates[vector] + 4, sizeof(bits));
        memcpy(&middle, gates[vector] + 6, sizeof(middle));
        memcpy(&high, gates[vector] + 8, sizeof(high));
        memcpy(&reserved, gates[vector] + 12, sizeof(reserved));
        int present = (bits >> 15) & 1u;
        uint64_t handler = low | ((uint64_t)middle << 16) | ((uint64_t)high << 32);
        uint32_t gate_type = (bits >> 8) & 0x1fu;
        const char *expected_name = expected_x86_vector(vector);
        uint64_t expected = 0;
        int expected_known = expected_name && kallsyms_lookup(expected_name, &expected) > 0;
        if (!present && !expected_known) continue;
        if (present) checked++;
        int invalid_gate = !present || !segment || reserved ||
                           (gate_type != 0xeu && gate_type != 0xfu);
        int outside = !present || handler < text_start || handler >= text_end;
        int redirect = expected_known && handler != expected;
        if (expected_known) critical++;
        int mismatch = invalid_gate || outside || redirect;
        char actual_name[512] = {0}, identity[512], subject[16];
        if (!mismatch && expected_known)
            snprintf(actual_name, sizeof(actual_name), "%s", expected_name);
        else if (!mismatch || kallsyms_address_name(handler, actual_name, sizeof(actual_name)) <= 0)
            snprintf(actual_name, sizeof(actual_name), "0x%016" PRIx64, handler);
        snprintf(identity, sizeof(identity), "%s", actual_name);
        snprintf(subject, sizeof(subject), "%u", vector);
        int allowed = mismatch && policy_allows(config, "idt", subject, identity);
        signals += mismatch && !allowed;

        if (config->json_output && (mismatch || config->verbose > 1)) {
            if ((*printed)++) printf(",");
            printf("{\"kind\":\"idt\",\"vector\":%u,\"handler\":\"", vector);
            json_print_escaped(actual_name);
            printf("\",\"address\":\"0x%016" PRIx64 "\",\"gate_type\":%u,"
                   "\"present\":%s,\"outside_core_text\":%s,\"invalid_gate\":%s,"
                   "\"redirected\":%s,\"allowed\":%s",
                   handler, gate_type, present ? "true" : "false",
                   outside ? "true" : "false",
                   invalid_gate ? "true" : "false", redirect ? "true" : "false",
                   allowed ? "true" : "false");
            if (expected_known) {
                printf(",\"expected\":\"");
                json_print_escaped(expected_name);
                printf("\",\"expected_address\":\"0x%016" PRIx64 "\"", expected);
            }
            printf("}");
        } else if (!config->json_output && (mismatch || config->verbose > 1)) {
            printf("  IDT vector=%3u handler=%-40s%s%s%s%s\n", vector, actual_name,
                   redirect ? " [REDIRECT]" : "", outside ? " [OUTSIDE CORE TEXT]" : "",
                   invalid_gate ? " [INVALID GATE]" : "", allowed ? " [ALLOW]" : "");
        }
    }
    if (!config->json_output)
        printf("    %d present IDT vector(s) checked; %d critical targets exact\n",
               checked, critical);
    return signals;
}

static int scan_arm_vector_code(const Config *config, int *incomplete,
                                const KernelCore *core, uint64_t text_start,
                                uint64_t text_end, int *printed) {
    uint64_t vectors = 0;
    if (kallsyms_lookup("vectors", &vectors) <= 0 ||
        vectors < text_start || vectors >= text_end) {
        if (incomplete) *incomplete = 1;
        if (!config->json_output) printf("[?] ARM64 exception-vector symbol is unavailable\n");
        return 0;
    }
    uint32_t code[2048 / sizeof(uint32_t)];
    if (kernel_core_read(core, vectors, code, sizeof(code)) < 0) {
        if (incomplete) *incomplete = 1;
        if (!config->json_output) printf("[?] ARM64 exception-vector code cannot be read\n");
        return 0;
    }
    int signals = 0, branches = 0;
    for (size_t i = 0; i < sizeof(code) / sizeof(code[0]); i++) {
        uint32_t insn = code[i];
        if ((insn & 0x7c000000u) != 0x14000000u) continue; /* B/BL imm26 */
        int32_t immediate = (int32_t)(insn & 0x03ffffffu);
        if (immediate & 0x02000000) immediate |= (int32_t)~0x03ffffffu;
        int64_t signed_target = (int64_t)(vectors + i * 4u) +
                                (int64_t)immediate * 4;
        uint64_t target = signed_target < 0 ? 0 : (uint64_t)signed_target;
        int outside = target < text_start || target >= text_end;
        branches++;
        if (!outside && config->verbose <= 1) continue;
        char target_name[512] = {0}, detail[512], subject[32];
        if (kallsyms_address_name(target, target_name, sizeof(target_name)) <= 0)
            snprintf(target_name, sizeof(target_name), "0x%016" PRIx64, target);
        snprintf(detail, sizeof(detail), "%s", target_name);
        snprintf(subject, sizeof(subject), "%zu", (i * 4u) / 128u);
        int allowed = outside && policy_allows(config, "vector", subject, detail);
        signals += outside && !allowed;
        if (config->json_output) {
            if ((*printed)++) printf(",");
            printf("{\"kind\":\"arm64_vector\",\"slot\":%zu,\"instruction_offset\":%zu,"
                   "\"target\":\"", (i * 4u) / 128u, i * 4u);
            json_print_escaped(target_name);
            printf("\",\"target_address\":\"0x%016" PRIx64 "\","
                   "\"outside_core_text\":%s,\"allowed\":%s}",
                   target, outside ? "true" : "false", allowed ? "true" : "false");
        } else {
            printf("  ARM64 vector slot=%2zu target=%s%s%s\n", (i * 4u) / 128u,
                   target_name, outside ? " [OUTSIDE CORE TEXT]" : "",
                   allowed ? " [ALLOW]" : "");
        }
    }
    if (!branches && incomplete) *incomplete = 1;
    if (!config->json_output)
        printf("    %d direct ARM64 exception-vector branch(es) validated%s\n",
               branches, branches ? "" : " (partial)");
    return signals;
}

int scan_kernel_integrity(const Config *config, int *incomplete) {
    if (!config->json_output)
        printf("[*] Validating critical syscall-table entries...\n");
    else
        printf("\"kernel_integrity\":[");

    struct utsname uts;
    const char *prefix = NULL;
    int x86_64 = 0, arm64 = 0;
    if (uname(&uts) == 0) {
        if (!strcmp(uts.machine, "x86_64")) { prefix = "__x64_sys_"; x86_64 = 1; }
        else if (!strcmp(uts.machine, "aarch64")) { prefix = "__arm64_sys_"; arm64 = 1; }
    }
    if (!prefix) {
        if (incomplete) *incomplete = 1;
        if (!config->json_output)
            printf("[?] Critical syscall-table verification is currently available on x86-64 and ARM64\n");
        else printf("]");
        return 0;
    }

    uint64_t table = 0, text_start = 0, text_end = 0;
    int have_table = kallsyms_lookup("sys_call_table", &table) > 0;
    if (kallsyms_lookup("_stext", &text_start) <= 0 ||
        kallsyms_lookup("_etext", &text_end) <= 0 ||
        text_end <= text_start) {
        if (incomplete) *incomplete = 1;
        if (!config->json_output)
            printf("[?] Kernel symbol addresses are hidden or incomplete\n");
        else printf("]");
        return 0;
    }

    KernelCore core;
    if (kernel_core_open(&core) < 0) {
        if (incomplete) *incomplete = 1;
        if (!config->json_output)
            printf("[?] /proc/kcore cannot be read: %s\n", strerror(errno));
        else printf("]");
        return 0;
    }

    struct syscall_check { long number; const char *name; };
    static const struct syscall_check checks[] = {
#ifdef SYS_read
        {SYS_read, "read"},
#endif
#ifdef SYS_write
        {SYS_write, "write"},
#endif
#ifdef SYS_openat
        {SYS_openat, "openat"},
#endif
#ifdef SYS_execve
        {SYS_execve, "execve"},
#endif
#ifdef SYS_mprotect
        {SYS_mprotect, "mprotect"},
#endif
#ifdef SYS_ptrace
        {SYS_ptrace, "ptrace"},
#endif
#ifdef SYS_bpf
        {SYS_bpf, "bpf"},
#endif
#ifdef SYS_init_module
        {SYS_init_module, "init_module"},
#endif
#ifdef SYS_finit_module
        {SYS_finit_module, "finit_module"},
#endif
    };

    int signals = 0, syscall_signals = 0, checked = 0;
    int partial = !have_table, printed = 0;
    for (size_t i = 0; have_table && i < sizeof(checks) / sizeof(checks[0]); i++) {
        if (checks[i].number < 0) { partial = 1; continue; }
        char expected_name[96];
        snprintf(expected_name, sizeof(expected_name), "%s%s", prefix, checks[i].name);
        uint64_t expected = 0, actual = 0;
        if (kallsyms_lookup(expected_name, &expected) <= 0 ||
            (uint64_t)checks[i].number > (UINT64_MAX - table) / sizeof(actual) ||
            kernel_core_read(&core, table + (uint64_t)checks[i].number * sizeof(actual),
                             &actual, sizeof(actual)) < 0) {
            partial = 1;
            continue;
        }
        checked++;
        int mismatch = actual != expected;
        int outside_text = actual < text_start || actual >= text_end;
        char actual_name[512] = {0}, identity[544];
        if (kallsyms_address_name(actual, actual_name, sizeof(actual_name)) <= 0)
            snprintf(actual_name, sizeof(actual_name), "0x%016" PRIx64, actual);
        snprintf(identity, sizeof(identity), "%s", actual_name);
        int allowed = mismatch && policy_allows(config, "kernel_table",
                                                checks[i].name, identity);
        syscall_signals += mismatch && !allowed;

        if (config->json_output) {
            if (printed++) printf(",");
            printf("{\"kind\":\"syscall_table\",\"syscall\":\"");
            json_print_escaped(checks[i].name);
            printf("\",\"number\":%ld,\"expected\":\"", checks[i].number);
            json_print_escaped(expected_name);
            printf("\",\"expected_address\":\"0x%016" PRIx64 "\",\"actual\":\"",
                   expected);
            json_print_escaped(actual_name);
            printf("\",\"actual_address\":\"0x%016" PRIx64 "\","
                   "\"outside_core_text\":%s,\"mismatch\":%s,\"allowed\":%s}",
                   actual, outside_text ? "true" : "false",
                   mismatch ? "true" : "false", allowed ? "true" : "false");
        } else if (mismatch || config->verbose) {
            printf("  %-16s [%3ld] expected=%s actual=%s%s%s\n",
                   checks[i].name, checks[i].number, expected_name, actual_name,
                   outside_text ? " [OUTSIDE CORE TEXT]" : "",
                   allowed ? " [ALLOW]" : mismatch ? " [MISMATCH]" : "");
        }
    }
    signals += syscall_signals;
    if (!config->json_output) {
        if (syscall_signals)
            printf("[!] %d critical syscall-table entr%s redirected\n",
                   syscall_signals, syscall_signals == 1 ? "y" : "ies");
        else
            printf("[+] %d critical syscall-table entries match running-kernel symbols\n",
                   checked);
        if (partial)
            printf("[?] Some critical syscall entries could not be validated\n");
    }

    if (x86_64)
        signals += scan_idt_table(config, incomplete, &core, text_start, text_end, &printed);
    else if (arm64)
        signals += scan_arm_vector_code(config, incomplete, &core, text_start, text_end, &printed);
    signals += scan_lsm_hook_table(config, incomplete, &core, text_start, text_end, &printed);
    kernel_core_close(&core);
    if (partial && incomplete) *incomplete = 1;
    if (config->json_output) printf("]");
    return signals;
}
