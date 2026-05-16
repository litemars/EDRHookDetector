#define _GNU_SOURCE
#include "common.h"
#include "kernel_ebpf.h"

static void print_usage(const char *prog_name) {
    printf("Multi-Arch EDR Hook Detector (ARM64 + x86/x86-64)\n");
    printf("Usage: %s [options]\n\n", prog_name);
    printf("Options:\n");
    printf("  -p, --pid <PID>     Scan only the given PID\n");
    printf("  -l, --lib <PATH>    Only inspect this library path/name\n");
    printf("  -v, --verbose       Verbose output (use twice for more detail)\n");
    printf("  -j, --json          Output in JSON format\n");
    printf("  -x, --hexdump       Show hexdump of modified instructions\n");
    printf("  -s, --self          Scan only the current process (no root needed)\n");
    printf("  -h, --help          Show this help\n");
    printf("\nMonitored libraries:\n");
    for (int i = 0; target_libs[i].lib_pattern != NULL; i++)
        printf("  * %s\n", target_libs[i].lib_pattern);
}

int main(int argc, char *argv[]) {
    Config config = {0};
    int self_scan = 0;

    static const struct option longopts[] = {
        {"pid",     required_argument, NULL, 'p'},
        {"lib",     required_argument, NULL, 'l'},
        {"verbose", no_argument,       NULL, 'v'},
        {"json",    no_argument,       NULL, 'j'},
        {"hexdump", no_argument,       NULL, 'x'},
        {"self",    no_argument,       NULL, 's'},
        {"help",    no_argument,       NULL, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:l:vjxsh", longopts, NULL)) != -1) {
        switch (opt) {
            case 'p': config.target_pid = (pid_t)atoi(optarg); break;
            case 'l': snprintf(config.target_lib, sizeof(config.target_lib), "%s", optarg); break;
            case 'v': config.verbose++;    break;
            case 'j': config.json_output = 1; break;
            case 'x': config.show_hexdump = 1; break;
            case 's': self_scan = 1; break;
            case 'h': default: print_usage(argv[0]); return 0;
        }
    }

    if (self_scan) config.target_pid = getpid();

    if (geteuid() != 0 && config.target_pid == 0) {
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

    if (!config.json_output) {
        printf("========================================================\n");
        printf("  Multi-Arch EDR Hook Detector (ARM64 + x86 / x86-64)\n");
        printf("========================================================\n\n");
        printf("Monitored libraries:\n");
        for (int i = 0; target_libs[i].lib_pattern != NULL; i++)
            printf("  * %s\n", target_libs[i].lib_pattern);
        printf("\n");
    }

    if (config.json_output) printf("{");

    check_environment_hooks(&config);

    if (config.json_output) printf(",");
    else printf("\n");

    int ebpf_hooks = scan_ebpf_programs(&config);
    if (ebpf_hooks < 0) ebpf_hooks = 0;

    if (config.json_output) printf(",\"processes\":[");
    else printf("\n");

    int total = 0, hooked = 0, total_hooks = 0;
    int first_json = 1;

    if (config.target_pid != 0) {
        int hooks = scan_process(config.target_pid, &config, &first_json);
        if (hooks > 0) {
            hooked = 1;
            total_hooks = hooks;
            if (!config.verbose && !config.json_output) {
                char name[256];
                get_process_name(config.target_pid, name, sizeof(name));
                printf("[!] PID %d (%s): %d hook(s)\n", config.target_pid, name, hooks);
            }
        }
        total = (hooks >= 0) ? 1 : 0;
    } else {
        if (!config.json_output)
            printf("\nScanning processes...\n");

        DIR *proc = opendir("/proc");
        if (!proc) {
            fprintf(stderr, "Failed to open /proc: %s\n", strerror(errno));
            if (config.json_output) printf("]}\n");
            return 1;
        }

        struct dirent *entry;
        while ((entry = readdir(proc)) != NULL) {
            if (entry->d_type != DT_DIR) continue;
            if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;

            char *endp;
            long val = strtol(entry->d_name, &endp, 10);
            if (endp == entry->d_name || *endp != '\0' || val <= 0) continue;
            pid_t pid = (pid_t)val;

            int hooks = scan_process(pid, &config, &first_json);

            if (hooks > 0) {
                hooked++;
                total_hooks += hooks;
                if (!config.verbose && !config.json_output) {
                    char name[256];
                    get_process_name(pid, name, sizeof(name));
                    printf("[!] PID %d (%s): %d hook(s)\n", pid, name, hooks);
                }
            }
            if (hooks >= 0) total++;
        }
        closedir(proc);
    }

    if (config.json_output) {
        printf("]}\n");
        return ((hooked > 0) || (ebpf_hooks > 0)) ? 1 : 0;
    }

    int grand_total = total_hooks + ebpf_hooks;
    printf("\n========================================================\n");
    printf("SUMMARY\n");
    printf("========================================================\n");
    printf("Processes scanned:    %d\n", total);
    printf("Processes w/ hooks:   %d\n", hooked);
    printf("Userspace hooks:      %d\n", total_hooks);
    printf("eBPF kernel hooks:    %d\n", ebpf_hooks);
    printf("Total hooks:          %d\n", grand_total);

    if (grand_total == 0) {
        printf("\n[+] No EDR hooks detected!\n");
    } else {
        printf("\n[!] EDR hooks found!\n");
        if (!config.verbose)      printf("    Run with -v for details\n");
        if (!config.show_hexdump) printf("    Run with -x to see instruction hexdumps\n");
    }
    printf("========================================================\n");

    return ((hooked > 0) || (ebpf_hooks > 0)) ? 1 : 0;
}
