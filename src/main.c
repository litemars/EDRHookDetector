#define _GNU_SOURCE
#include "common.h"
#include "kernel_ebpf.h"
#include "kernel_hooks.h"
#include <inttypes.h>
#include <time.h>

static void print_usage(const char *prog_name) {
    printf("Multi-Arch EDR Hook Detector (ARM64 + x86/x86-64)\n");
    printf("Usage: %s [options]\n\n", prog_name);
    printf("Options:\n");
    printf("  -p, --pid <PID>     Scan only the given PID\n");
    printf("  -l, --lib <PATH>    Only inspect this library path/name\n");
    printf("  -v, --verbose       Verbose output (use twice for more detail)\n");
    printf("  -j, --json          Output in JSON format\n");
    printf("  -x, --hexdump       Show hexdump of modified instructions\n");
    printf("  -s, --self          Select the current process for userspace checks\n");
    printf("      --scope <NAME>  all (default), userspace, or kernel\n");
    printf("      --policy <PATH> Load tab-delimited allowlist policy rules\n");
    printf("      --profile <NAME> default or strict signal policy\n");
    printf("      --baseline-root <DIR> Compare userspace files with a trusted root\n");
    printf("      --watch <SEC>   Repeat complete reports (JSON becomes NDJSON)\n");
    printf("  -h, --help          Show this help\n");
    printf("\nPID and library selectors affect userspace checks; VDSO uses system-wide peers.\n");
    printf("Kernel sources are system-wide. --lib selects inline libraries and GOT importing modules.\n");
    printf("Exit: 0 = no findings with complete coverage; 1 = findings; 2 = invalid/incomplete.\n");
    printf("\nMonitored libraries:\n");
    for (int i = 0; target_libs[i].lib_pattern != NULL; i++)
        printf("  * %s\n", target_libs[i].lib_pattern);
}

static int parse_pid(const char *arg, pid_t *pid_out) {
    char *end = NULL;
    errno = 0;
    long value = strtol(arg, &end, 10);
    if (errno == ERANGE || end == arg || *end != '\0' || value <= 0 ||
        value > (long)INT32_MAX)
        return -1;
    *pid_out = (pid_t)value;
    return 0;
}

enum { SOURCE_ENV, SOURCE_BPF, SOURCE_KPROBE, SOURCE_UPROBE, SOURCE_FTRACE,
       SOURCE_KERNEL_INTEGRITY, SOURCE_LSM, SOURCE_MODULES, SOURCE_VDSO,
       SOURCE_GOT, SOURCE_INLINE, SOURCE_COUNT };
static const char *const source_names[SOURCE_COUNT] = {
    "environment", "ebpf", "kprobes", "uprobes", "ftrace", "kernel_integrity",
    "lsm", "modules", "vdso", "got", "inline"
};

static int run_source(int selected, const char *json_key,
                       int (*scan)(const Config *, int *), const Config *config,
                       int *status) {
    if (config->json_output) printf(",");
    else if (selected) printf("\n");
    if (!selected) {
        *status = -1;
        if (config->json_output) printf("\"%s\":[]", json_key);
        return 0;
    }
    return scan(config, status);
}

static int report_result(const Config *config, const char *scope, const int *status,
                         int hook_signals, int informational_signals) {
    int incomplete = 0;
    for (int i = 0; i < SOURCE_COUNT; i++) incomplete |= status[i] > 0;
    const char *verdict = hook_signals ? "findings_detected" :
                          incomplete ? "inconclusive" : "no_findings";
    if (config->json_output) {
        printf("],\"scope\":{\"selection\":\"%s\",\"userspace_pid\":", scope);
        if (!strcmp(scope, "kernel")) printf("null");
        else if (config->target_pid) printf("%d", config->target_pid);
        else printf("null");
        printf(",\"userspace_processes\":\"%s\",",
               !strcmp(scope, "kernel") ? "not_requested" :
               config->target_pid ? "selected_pid" : "all");
        json_print_string_field("library_filter", config->target_lib);
        printf(",");
        json_print_string_field("policy", config->policy_path);
        printf(",");
        json_print_string_field("baseline_root", config->baseline_root);
        printf(",\"profile\":\"%s\",\"vdso\":\"%s\",\"kernel\":\"%s\"},"
               "\"coverage\":{\"complete\":%s,\"sources\":{",
               config->profile_strict ? "strict" : "default",
               status[SOURCE_VDSO] < 0 ? "not_requested" :
               config->baseline_root[0] ? "trusted_baseline" : "system_wide_peers",
               status[SOURCE_BPF] < 0 ? "not_requested" : "system_wide",
               incomplete ? "false" : "true");
        for (int i = 0; i < SOURCE_COUNT; i++)
            printf("%s\"%s\":\"%s\"", i ? "," : "", source_names[i],
                   status[i] < 0 ? "not_requested" : status[i] ? "incomplete" : "complete");
        printf("}},\"verdict\":{\"status\":\"%s\",\"hook_signals\":%d,"
               "\"informational_signals\":%d}}\n", verdict, hook_signals, informational_signals);
    } else {
        if (hook_signals) printf("\n[!] Hook signals detected; investigate the findings above.\n");
        else if (!incomplete) printf("\n[+] No hook signals detected in the requested scope.\n");
        if (informational_signals) printf("[*] Informational indicators also need context; see above.\n");
        if (incomplete) {
            printf("[?] Coverage incomplete; additional findings cannot be ruled out. Sources:");
            for (int i = 0; i < SOURCE_COUNT; i++)
                if (status[i] > 0) printf(" %s", source_names[i]);
            printf("\n");
        }
    }
    return hook_signals ? 1 : incomplete ? 2 : 0;
}

int main(int argc, char *argv[]) {
    Config config = {0};
    int self_scan = 0, help = 0;
    const char *scope = "all";

    static const struct option longopts[] = {
        {"pid",     required_argument, NULL, 'p'},
        {"lib",     required_argument, NULL, 'l'},
        {"verbose", no_argument,       NULL, 'v'},
        {"json",    no_argument,       NULL, 'j'},
        {"hexdump", no_argument,       NULL, 'x'},
        {"self",    no_argument,       NULL, 's'},
        {"help",    no_argument,       NULL, 'h'},
        {"scope",   required_argument, NULL, 1000},
        {"policy",  required_argument, NULL, 1001},
        {"baseline-root", required_argument, NULL, 1002},
        {"watch",   required_argument, NULL, 1003},
        {"profile", required_argument, NULL, 1004},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:l:vjxsh", longopts, NULL)) != -1) {
        switch (opt) {
            case 'p':
                if (parse_pid(optarg, &config.target_pid) < 0) {
                    fprintf(stderr, "Invalid PID: %s\n", optarg);
                    return 2;
                }
                break;
            case 'l':
                if (!optarg[0] || strlen(optarg) >= sizeof(config.target_lib)) {
                    fprintf(stderr, "Library filter must contain 1–511 bytes\n");
                    return 2;
                }
                snprintf(config.target_lib, sizeof(config.target_lib), "%s", optarg);
                break;
            case 'v': config.verbose++;    break;
            case 'j': config.json_output = 1; break;
            case 'x': config.show_hexdump = 1; break;
            case 's': self_scan = 1; break;
            case 1000:
                if (strcmp(optarg, "all") && strcmp(optarg, "userspace") && strcmp(optarg, "kernel")) {
                    fprintf(stderr, "Invalid scope: %s\n", optarg);
                    return 2;
                }
                scope = optarg;
                break;
            case 1001:
                if (!optarg[0] || strlen(optarg) >= sizeof(config.policy_path)) {
                    fprintf(stderr, "Policy path must contain 1–511 bytes\n");
                    return 2;
                }
                snprintf(config.policy_path, sizeof(config.policy_path), "%s", optarg);
                break;
            case 1002:
                if (optarg[0] != '/' || strlen(optarg) >= sizeof(config.baseline_root)) {
                    fprintf(stderr, "Baseline root must be an absolute path of at most 511 bytes\n");
                    return 2;
                }
                snprintf(config.baseline_root, sizeof(config.baseline_root), "%s", optarg);
                while (strlen(config.baseline_root) > 1 &&
                       config.baseline_root[strlen(config.baseline_root) - 1] == '/')
                    config.baseline_root[strlen(config.baseline_root) - 1] = '\0';
                break;
            case 1003: {
                char *end = NULL;
                errno = 0;
                unsigned long value = strtoul(optarg, &end, 10);
                if (errno || end == optarg || *end || value < 1 || value > 86400) {
                    fprintf(stderr, "Watch interval must be between 1 and 86400 seconds\n");
                    return 2;
                }
                config.watch_seconds = (unsigned int)value;
                break;
            }
            case 1004:
                if (!strcmp(optarg, "strict")) config.profile_strict = 1;
                else if (!strcmp(optarg, "default")) config.profile_strict = 0;
                else {
                    fprintf(stderr, "Profile must be default or strict\n");
                    return 2;
                }
                break;
            case 'h': help = 1; break;
            default: return 2;
        }
    }

    if (optind != argc) {
        fprintf(stderr, "Unexpected positional argument: %s\n", argv[optind]);
        return 2;
    }
    if (self_scan && config.target_pid) {
        fprintf(stderr, "--self and --pid cannot be combined\n");
        return 2;
    }
    int userspace = strcmp(scope, "kernel") != 0;
    int kernel = strcmp(scope, "userspace") != 0;
    if (!userspace && (self_scan || config.target_pid || config.target_lib[0])) {
        fprintf(stderr, "PID and library selectors require all or userspace scope\n");
        return 2;
    }
    if (help) { print_usage(argv[0]); return 0; }
    if (config.policy_path[0] && load_policy_file(&config, config.policy_path) < 0) {
        fprintf(stderr, "Cannot load policy %s: %s\n", config.policy_path, strerror(errno));
        return 2;
    }
    if (config.show_hexdump && !config.verbose) config.verbose = 1;
    if (self_scan) config.target_pid = getpid();

    if (userspace && geteuid() != 0 && config.target_pid == 0) {
        if (!config.json_output) {
            fprintf(stderr, "[!] Must run as root to scan all processes\n");
            fprintf(stderr, "[*] Use -s/--self to scan current process without root\n");
            fprintf(stderr, "[*] Use -p/--pid to scan a specific owned process\n");
        }
        config.target_pid = getpid();
        if (!config.json_output)
            fprintf(stderr, "[*] Auto-enabling self-scan mode (PID %d)\n\n",
                    config.target_pid);
    }

    uint64_t scan_sequence = 0;
scan_pass:
    scan_sequence++;
    if (!config.json_output) {
        if (config.watch_seconds) {
            time_t now = time(NULL);
            printf("WATCH SNAPSHOT #%" PRIu64 "  time=%lld\n",
                   scan_sequence, (long long)now);
        }
        printf("========================================================\n");
        printf("  Multi-Arch EDR Hook Detector (ARM64 + x86 / x86-64)\n");
        printf("========================================================\n\n");
        printf("Monitored libraries:\n");
        for (int i = 0; target_libs[i].lib_pattern != NULL; i++)
            printf("  * %s\n", target_libs[i].lib_pattern);
        printf("\n");
    }

    if (config.json_output) {
        printf("{\"scan\":{\"sequence\":%" PRIu64 ",\"time\":%lld},",
               scan_sequence, (long long)time(NULL));
    }

    int status[SOURCE_COUNT] = {0};
    int preload_indicators = 0;
    if (userspace)
        preload_indicators = check_environment_hooks(&config, &status[SOURCE_ENV]);
    else {
        status[SOURCE_ENV] = -1;
        if (config.json_output) printf("\"warnings\":[]");
    }
    int ebpf_hooks = run_source(kernel, "ebpf_hooks", scan_ebpf_programs, &config, &status[SOURCE_BPF]);
    int kprobe_hooks = run_source(kernel, "kprobes", scan_kprobes, &config, &status[SOURCE_KPROBE]);
    int uprobe_hooks = run_source(kernel, "uprobes", scan_uprobes, &config, &status[SOURCE_UPROBE]);
    int ftrace_hooks = run_source(kernel, "ftrace_hooks", scan_ftrace_hooks, &config, &status[SOURCE_FTRACE]);
    int kernel_integrity = run_source(kernel, "kernel_integrity", scan_kernel_integrity,
                                      &config, &status[SOURCE_KERNEL_INTEGRITY]);
    int unknown_lsms = run_source(kernel, "lsm_modules", scan_lsm_modules, &config, &status[SOURCE_LSM]);
    int tainted_mods = run_source(kernel, "kernel_modules", scan_tainted_modules, &config, &status[SOURCE_MODULES]);
    int vdso_anom = run_source(userspace, "vdso", scan_vdso_consistency, &config, &status[SOURCE_VDSO]);
    int got_hijacks = run_source(userspace, "got_hijacks", scan_got_hijacks, &config, &status[SOURCE_GOT]);

    if (config.json_output) printf(",\"processes\":[");
    else printf("\n");

    int total = 0, hooked = 0, total_hooks = 0;
    int first_json = 1;

    if (!userspace) status[SOURCE_INLINE] = -1;
    else if (config.target_pid != 0) {
        int hooks = scan_process(config.target_pid, &config, &first_json, &status[SOURCE_INLINE]);
        if (hooks > 0) {
            hooked = 1;
            total_hooks = hooks;
            if (!config.verbose && !config.json_output) {
                char name[256];
                get_process_name(config.target_pid, name, sizeof(name));
                printf("[!] PID %d (%s): %d hook(s)\n", config.target_pid, name, hooks);
            }
        }
        total = 1;
    } else {
        if (!config.json_output)
            printf("\nScanning processes...\n");

        DIR *proc = opendir("/proc");
        if (!proc) {
            fprintf(stderr, "Failed to open /proc: %s\n", strerror(errno));
            status[SOURCE_INLINE] = 1;
            return report_result(&config, scope, status, ebpf_hooks + kprobe_hooks + uprobe_hooks +
                                 ftrace_hooks + kernel_integrity + vdso_anom + got_hijacks + preload_indicators,
                                 unknown_lsms + tainted_mods);
        }

        struct dirent *entry;
        for (;;) {
            errno = 0;
            entry = readdir(proc);
            if (!entry) { if (errno) status[SOURCE_INLINE] = 1; break; }
            if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;

            char *endp;
            long val = strtol(entry->d_name, &endp, 10);
            if (endp == entry->d_name || *endp != '\0' || val <= 0 || val > INT32_MAX) continue;
            pid_t pid = (pid_t)val;

            int hooks = scan_process(pid, &config, &first_json, &status[SOURCE_INLINE]);

            if (hooks > 0) {
                hooked++;
                total_hooks += hooks;
                if (!config.verbose && !config.json_output) {
                    char name[256];
                    get_process_name(pid, name, sizeof(name));
                    printf("[!] PID %d (%s): %d hook(s)\n", pid, name, hooks);
                }
            }
            total++;
        }
        closedir(proc);
    }

    /* Signals that flip the exit code; VDSO anomalies count as tampering. */
    int kernel_hooks = ebpf_hooks + kprobe_hooks + uprobe_hooks + ftrace_hooks +
                       kernel_integrity + vdso_anom;
    /* Informational only — unknown LSMs and tainted modules need local context. */
    int informational_signals = config.profile_strict ? 0 : unknown_lsms + tainted_mods;
    int hook_signals = preload_indicators + total_hooks + kernel_hooks + got_hijacks +
                       (config.profile_strict ? unknown_lsms + tainted_mods : 0);

    if (config.json_output) {
        int json_result = report_result(&config, scope, status, hook_signals,
                                        informational_signals);
        if (config.watch_seconds) {
            unsigned int left = config.watch_seconds;
            while (left) left = sleep(left);
            goto scan_pass;
        }
        return json_result;
    }

    int grand_total = hook_signals + informational_signals;
    printf("\n========================================================\n");
    printf("SUMMARY\n");
    printf("========================================================\n");
    printf("Scope:                       %s\n", scope);
    if (userspace) printf("Userspace selection:         %s (PID %d); VDSO uses system-wide peers\n",
                          config.target_pid ? "selected PID" : "all processes", config.target_pid);
    if (kernel) printf("Kernel selection:            system-wide\n");
    printf("Processes attempted:         %d\n", total);
    printf("Processes w/ inline hooks:   %d\n", hooked);
    printf("Inline code hooks:           %d\n", total_hooks);
    printf("GOT/PLT hijacks:             %d\n", got_hijacks);
    printf("Preload indicators:          %d\n", preload_indicators);
    printf("eBPF kernel hooks:           %d\n", ebpf_hooks);
    printf("Active kprobes:              %d\n", kprobe_hooks);
    printf("uprobes:                     %d\n", uprobe_hooks);
    printf("ftrace redirection signals:  %d\n", ftrace_hooks);
    printf("Kernel integrity signals:    %d\n", kernel_integrity);
    printf("Unknown LSMs:                %d\n", unknown_lsms);
    printf("Out-of-tree/unsigned mods:   %d\n", tainted_mods);
    printf("VDSO anomalies:              %d\n", vdso_anom);
    printf("--------------------------------------------------------\n");
    printf("Total signals:               %d\n", grand_total);

    int result = report_result(&config, scope, status, hook_signals, informational_signals);
    printf("========================================================\n");
    if (config.watch_seconds) {
        unsigned int left = config.watch_seconds;
        while (left) left = sleep(left);
        goto scan_pass;
    }
    return result;
}
