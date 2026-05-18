#define _GNU_SOURCE
#include "common.h"
#include "kernel_hooks.h"

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

int scan_kprobes(const Config *config) {
    const char *path = "/sys/kernel/debug/kprobes/list";

    if (!config->json_output)
        printf("[*] Scanning kprobes...\n");
    else
        printf("\"kprobes\":[");

    FILE *f = fopen(path, "r");
    if (!f) {
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

    int active = 0, total = 0, printed = 0;
    char line[512];

    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '\0' || line[0] == '\n' || line[0] == '#') continue;
        line[strcspn(line, "\n")] = '\0';

        char addr[32]  = {0};
        char type[8]   = {0};
        char symbol[256] = {0};
        if (sscanf(line, "%31s %7s %255s", addr, type, symbol) < 3) continue;

        int disabled  = strstr(line, "[DISABLED]")  != NULL;
        int optimized = strstr(line, "[OPTIMIZED]") != NULL;
        int ftrace    = strstr(line, "[FTRACE]")    != NULL;

        total++;
        if (!disabled) active++;

        if (config->json_output) {
            if (printed > 0) printf(",");
            printf("{\"address\":\"");
            json_print_escaped(addr);
            printf("\",\"type\":\"");
            json_print_escaped(type);
            printf("\",\"symbol\":\"");
            json_print_escaped(symbol);
            printf("\",\"active\":%s,\"optimized\":%s,\"ftrace_based\":%s}",
                   disabled ? "false" : "true",
                   optimized ? "true" : "false",
                   ftrace ? "true" : "false");
            printed++;
        } else if (config->verbose) {
            printf("  %-18s %-3s %s%s%s%s\n",
                   addr, type, symbol,
                   disabled  ? " [DISABLED]"  : "",
                   optimized ? " [OPTIMIZED]" : "",
                   ftrace    ? " [FTRACE]"    : "");
        }
    }
    fclose(f);

    if (config->json_output) {
        printf("]");
    } else {
        if (total == 0)
            printf("[+] No kprobes registered\n");
        else
            printf("    %d kprobe(s) registered (%d active)%s\n",
                   total, active,
                   config->verbose ? "" : " — run with -v for the list");
    }

    return active;
}

int scan_uprobes(const Config *config) {
    char path[256];
    int  have_path = tracefs_path("uprobe_events", path, sizeof(path));

    if (!config->json_output)
        printf("[*] Scanning uprobes...\n");
    else
        printf("\"uprobes\":[");

    if (!have_path) {
        if (config->json_output) printf("]");
        else printf("[!] tracefs uprobe_events not found\n");
        return 0;
    }

    FILE *f = fopen(path, "r");
    if (!f) {
        if (config->json_output) {
            printf("]");
        } else {
            if (errno == EACCES || errno == EPERM)
                printf("[!] %s not readable (need root)\n", path);
            else
                printf("[!] Cannot open %s: %s\n", path, strerror(errno));
        }
        return 0;
    }

    int total = 0, printed = 0;
    char line[1024];

    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '\0' || line[0] == '\n' || line[0] == '#') continue;
        line[strcspn(line, "\n")] = '\0';

        char prefix[256] = {0};
        char target[512] = {0};
        if (sscanf(line, "%255s %511[^\n]", prefix, target) < 2) continue;

        total++;

        if (config->json_output) {
            if (printed > 0) printf(",");
            printf("{\"event\":\"");
            json_print_escaped(prefix);
            printf("\",\"target\":\"");
            json_print_escaped(target);
            printf("\"}");
            printed++;
        } else if (config->verbose) {
            printf("  %s  %s\n", prefix, target);
        }
    }
    fclose(f);

    if (config->json_output) {
        printf("]");
    } else {
        if (total == 0)
            printf("[+] No uprobes registered\n");
        else
            printf("    %d uprobe(s) registered%s\n",
                   total,
                   config->verbose ? "" : " — run with -v for the list");
    }

    return total;
}

int scan_ftrace_hooks(const Config *config) {
    char enabled_path[256], tracer_path[256];
    int  have_enabled = tracefs_path("enabled_functions", enabled_path, sizeof(enabled_path));
    int  have_tracer  = tracefs_path("current_tracer",    tracer_path,  sizeof(tracer_path));

    if (!config->json_output)
        printf("[*] Scanning ftrace hooks...\n");
    else
        printf("\"ftrace_hooks\":[");

    char tracer[64] = {0};
    if (have_tracer) {
        FILE *tf = fopen(tracer_path, "r");
        if (tf) {
            if (fgets(tracer, sizeof(tracer), tf))
                tracer[strcspn(tracer, "\n")] = '\0';
            fclose(tf);
        }
    }

    int printed = 0;
    int hooks_with_tramp = 0;
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
        if (config->json_output) printf("]");
        else if (!tracer[0]) printf("[!] tracefs not available\n");
        return 0;
    }

    FILE *f = fopen(enabled_path, "r");
    if (!f) {
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

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '\0' || line[0] == '\n' || line[0] == '#') continue;
        line[strcspn(line, "\n")] = '\0';
        hooks_total++;

        char symbol[256] = {0};
        sscanf(line, "%255s", symbol);

        const char *tramp = strstr(line, "tramp:");
        int has_tramp = (tramp != NULL);
        if (has_tramp) hooks_with_tramp++;

        if (config->json_output) {
            if (printed > 0) printf(",");
            printf("{\"kind\":\"function\",\"symbol\":\"");
            json_print_escaped(symbol);
            printf("\",\"has_trampoline\":%s",
                   has_tramp ? "true" : "false");
            if (has_tramp) {
                printf(",\"trampoline\":\"");
                json_print_escaped(tramp);
                printf("\"");
            }
            printf("}");
            printed++;
        } else if (config->verbose) {
            printf("  %-48s %s\n", symbol, has_tramp ? tramp : "(no trampoline)");
        }
    }
    fclose(f);

    if (config->json_output) {
        printf("]");
    } else {
        if (hooks_total == 0)
            printf("[+] No ftrace function hooks\n");
        else
            printf("    %d ftrace hook(s), %d with custom trampoline%s\n",
                   hooks_total, hooks_with_tramp,
                   config->verbose ? "" : " — run with -v for the list");
    }

    return hooks_with_tramp;
}


int scan_lsm_modules(const Config *config) {
    const char *path = "/sys/kernel/security/lsm";

    if (!config->json_output)
        printf("[*] Active LSMs...\n");
    else
        printf("\"lsm_modules\":[");

    FILE *f = fopen(path, "r");
    if (!f) {
        if (config->json_output) {
            printf("]");
        } else {
            printf("[!] Cannot read %s: %s\n", path, strerror(errno));
        }
        return 0;
    }

    char buf[512] = {0};
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        if (config->json_output) printf("]");
        else printf("[!] %s empty\n", path);
        return 0;
    }
    fclose(f);
    buf[strcspn(buf, "\n")] = '\0';

    static const char *known[] = {
        "capability", "yama", "apparmor", "selinux", "tomoyo", "smack",
        "landlock", "lockdown", "integrity", "ima", "evm", "bpf", "safesetid",
        NULL
    };

    int printed = 0, unknown = 0;
    char *saveptr = NULL;
    for (char *tok = strtok_r(buf, ",", &saveptr); tok; tok = strtok_r(NULL, ",", &saveptr)) {
        while (*tok == ' ') tok++;
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

    if (config->json_output)
        printf("]");
    else if (unknown > 0)
        printf("[!] %d unknown LSM(s) present — investigate\n", unknown);

    return unknown;
}

int scan_tainted_modules(const Config *config) {
    const char *path = "/proc/modules";

    if (!config->json_output)
        printf("[*] Scanning kernel modules...\n");
    else
        printf("\"kernel_modules\":[");

    FILE *f = fopen(path, "r");
    if (!f) {
        if (config->json_output) {
            printf("]");
        } else {
            printf("[!] Cannot open %s: %s\n", path, strerror(errno));
        }
        return 0;
    }

    int printed = 0;
    int suspicious = 0;
    int total = 0;
    char line[1024];

    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '\0' || line[0] == '\n') continue;
        line[strcspn(line, "\n")] = '\0';
        total++;

        char name[64] = {0};
        if (sscanf(line, "%63s", name) < 1) continue;

        /* Taint flags are the last parenthesised field on the line. */
        char taint[32] = {0};
        const char *lp = strrchr(line, '(');
        const char *rp = lp ? strchr(lp, ')') : NULL;
        if (lp && rp && rp > lp + 1) {
            size_t n = (size_t)(rp - lp - 1);
            if (n >= sizeof(taint)) n = sizeof(taint) - 1;
            memcpy(taint, lp + 1, n);
            taint[n] = '\0';
        }

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
    fclose(f);

    if (config->json_output) {
        printf("]");
    } else {
        printf("    %d module(s) loaded, %d flagged (out-of-tree / unsigned / forced)\n",
               total, suspicious);
    }

    return suspicious;
}
