#define _GNU_SOURCE
#include "common.h"
#include "kernel_hooks.h"

#define KERNEL_RECORD_SIZE (64u * 1024u)

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

    int active = 0, total = 0, printed = 0, unknown = 0;
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

        total++;
        if (probe_active > 0) active++;
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
                   "\"globally_enabled\":%s,\"optimized\":%s,\"ftrace_based\":%s}",
                   probe_active < 0 ? "null" : (probe_active ? "true" : "false"),
                   disabled ? "true" : "false",
                   gone ? "true" : "false",
                   globally_enabled < 0 ? "null" : (globally_enabled ? "true" : "false"),
                   optimized ? "true" : "false",
                   ftrace ? "true" : "false");
            printed++;
        } else if (config->verbose) {
            printf("  %-18s %-3s %s%s%s%s%s%s\n",
                   addr, type, symbol,
                   disabled  ? " [DISABLED]"  : "",
                   gone      ? " [GONE]"      : "",
                   optimized ? " [OPTIMIZED]" : "",
                   ftrace    ? " [FTRACE]"    : "",
                   probe_active < 0 ? " [ACTIVITY UNKNOWN]" : "");
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
            if (unknown) printf(", %d activity unknown", unknown);
            printf(")%s\n",
                   config->verbose ? "" : " — run with -v for the list");
        }
    }

    return active;
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

    int total = 0, printed = 0, read_failed = 0;
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

        total++;

        if (config->json_output) {
            if (printed > 0) printf(",");
            printf("{\"event\":\"");
            json_print_escaped(prefix);
            printf("\",");
            json_print_string_field("target", target);
            printf("}");
            printed++;
        } else if (config->verbose) {
            printf("  %s  %s\n", prefix, target);
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
    }
    finish_uprobe_output(config, !read_failed);

    return total;
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
    int hooks_total      = 0;

    if (tracer[0] && strcmp(tracer, "nop") != 0) {
        if (config->json_output) {
            printf("{\"kind\":\"current_tracer\",\"value\":\"");
            json_print_escaped(tracer);
            printf("\"}");
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
        return 0;
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
        return 0;
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

        const char *tramp = strstr(cursor, "tramp:");
        int has_tramp = (tramp != NULL);
        if (has_tramp) hooks_with_tramp++;
        if (ip_modify || direct_call) redirections++;

        if (config->json_output) {
            if (printed > 0) printf(",");
            printf("{\"kind\":\"function\",\"symbol\":\"");
            json_print_escaped(symbol);
            printf("\",\"has_trampoline\":%s,\"ip_modify\":%s,\"direct_call\":%s",
                   has_tramp ? "true" : "false",
                   ip_modify ? "true" : "false",
                   direct_call ? "true" : "false");
            if (has_tramp) {
                printf(",\"trampoline\":\"");
                json_print_escaped(tramp);
                printf("\"");
            }
            printf("}");
            printed++;
        } else if (config->verbose || ip_modify || direct_call) {
            printf("  %-48s %s%s%s\n", symbol,
                   ip_modify ? "[IPMODIFY] " : "",
                   direct_call ? "[DIRECT] " : "",
                   has_tramp ? tramp : "(standard/shared trampoline)");
        }
    }
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
    }

    return redirections;
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
        if (!is_known) unknown++;

        if (config->json_output) {
            if (printed > 0) printf(",");
            printf("{\"name\":\"");
            json_print_escaped(tok);
            printf("\",\"known\":%s}", is_known ? "true" : "false");
            printed++;
        } else {
            printf("  %s%s\n", tok, is_known ? "" : "  [!] unknown LSM");
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
        if (interesting) suspicious++;

    
        if (config->json_output) {
            if (printed > 0) printf(",");
            printf("{\"name\":\"");
            json_print_escaped(name);
            printf("\",\"taint\":\"");
            json_print_escaped(taint);
            printf("\",\"out_of_tree\":%s,\"unsigned\":%s,\"forced\":%s,\"proprietary\":%s}",
                   out_of_tree ? "true" : "false",
                   unsigned_m  ? "true" : "false",
                   forced      ? "true" : "false",
                   proprietary ? "true" : "false");
            printed++;
        } else if (interesting || config->verbose) {
            printf("  %-32s taint=[%s]%s%s%s\n",
                   name, taint[0] ? taint : "-",
                   out_of_tree ? " out-of-tree" : "",
                   unsigned_m  ? " UNSIGNED"    : "",
                   forced      ? " forced"      : "");
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
