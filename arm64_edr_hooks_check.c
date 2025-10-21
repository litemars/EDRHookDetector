#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>
#include <dirent.h>
#include <stdint.h>
#include <getopt.h>

#define STT_GNU_IFUNC 10
#define MAX_PROCESSES 2048
#define MAX_FUNCTIONS 256
#define CHECK_INSNS 8

// ARM64 opcodes
#define NOP         0xd503201f
#define SVC_MASK    0xFFE0001F
#define SVC         0xd4000001
#define B_MASK      0xFC000000
#define B_OPCODE    0x14000000
#define RET         0xd65f03c0
#define ADRP_MASK   0x9F000000
#define ADRP        0x90000000
#define LDR_MASK    0xFFC00000
#define LDR         0xF9400000
#define MOV_IMM_MASK 0xFFE00000
#define MOV_IMM     0xD2800000

typedef struct {
    char name[128];
    unsigned long vaddr;
    unsigned long file_offset;
} FunctionInfo;

typedef struct {
    char path[512];
    char short_name[64];
    unsigned long base_addr;
    FunctionInfo functions[MAX_FUNCTIONS];
    int func_count;
} LibraryInfo;

// Target libraries and their monitored functions
static const struct {
    const char *lib_pattern;
    const char *functions[30];
} target_libs[] = {
    {
        "libc.so.6",
        {
            "open", "openat", "creat", "close",
            "read", "write", "pread", "pwrite",
            "socket", "connect", "bind", "listen", "accept",
            "send", "recv", "sendto", "recvfrom",
            "execve", "fork", "clone",
            "mmap", "munmap", "mprotect",
            "ptrace", "kill", "prctl",
            NULL
        }
    },
    {
        "libpthread.so",
        {
            "pthread_create", "pthread_exit", "pthread_kill",
            "pthread_mutex_lock", "pthread_mutex_unlock",
            NULL
        }
    },
    {
        "libdl.so",
        {
            "dlopen", "dlsym", "dlclose", "dlmopen",
            NULL
        }
    },
    {
        "libssl.so",
        {
            "SSL_read", "SSL_write", "SSL_connect",
            "SSL_accept", "SSL_do_handshake",
            NULL
        }
    },
    {
        "libcrypto.so",
        {
            "EVP_EncryptInit", "EVP_DecryptInit",
            "EVP_EncryptUpdate", "EVP_DecryptUpdate",
            NULL
        }
    },
    {
        "libaudit.so",
        {
            "audit_log_user_message", "audit_open",
            NULL
        }
    },
    {
        "libpam.so",
        {
            "pam_authenticate", "pam_open_session",
            NULL
        }
    },
    {NULL, {NULL}}
};

// Pattern detection functions
static int32_t get_branch_offset(uint32_t insn) {
    int32_t offset = (insn & 0x03FFFFFF) << 2;
    if (offset & 0x08000000) offset |= 0xF0000000;
    return offset;
}

static int is_syscall_cp_stub(uint32_t *insns) {
    return (insns[0] == NOP &&
            (insns[1] & MOV_IMM_MASK) == MOV_IMM &&
            (insns[2] & SVC_MASK) == SVC);
}

static int is_plt_stub(uint32_t *insns) {
    return ((insns[0] & ADRP_MASK) == ADRP &&
            (insns[1] & LDR_MASK) == LDR);
}

static int is_function_epilogue(uint32_t *insns) {
    for (int i = 0; i < 4; i++) {
        if (insns[i] == RET) return 1;
    }
    return 0;
}

static int is_tail_call_optimization(uint32_t *insns) {
    if ((insns[0] & B_MASK) == B_OPCODE) {
        int32_t offset = get_branch_offset(insns[0]);
        if (offset < 0 || (offset > 0 && offset < 0x200)) {
            return 1;
        }
    }
    return 0;
}

static int is_wrapper_function(uint32_t *insns) {
    if ((insns[0] & B_MASK) == B_OPCODE) {
        int32_t offset = get_branch_offset(insns[0]);
        if (offset > 0 && offset < 0x10000) {
            return 1;
        }
    }
    return 0;
}

static int is_alternative_implementation(uint32_t *disk, uint32_t *mem) {
    for (int i = 0; i < 4; i++) {
        if (mem[i] == RET && i < 3) {
            return 1;
        }
    }
    return 0;
}

static int is_real_edr_hook(uint32_t *disk, uint32_t *mem) {
    if (is_syscall_cp_stub(disk)) return 0;
    if (is_plt_stub(disk)) return 0;
    if (is_wrapper_function(disk)) return 0;
    if (is_tail_call_optimization(mem)) return 0;
    if (is_function_epilogue(mem)) return 0;
    if (is_alternative_implementation(disk, mem)) return 0;

    int disk_has_svc = 0, mem_has_svc = 0;
    for (int i = 0; i < CHECK_INSNS; i++) {
        if ((disk[i] & SVC_MASK) == SVC) disk_has_svc = 1;
        if ((mem[i] & SVC_MASK) == SVC) mem_has_svc = 1;
    }

    if (disk_has_svc && !mem_has_svc) {
        if ((mem[0] & B_MASK) == B_OPCODE) {
            int32_t offset = get_branch_offset(mem[0]);
            if ((offset > 0 && offset < 0x1000) || 
                (offset < 0 && offset > -0x1000)) {
                return 0;
            }
        }
        return 1;
    }

    if ((mem[0] & B_MASK) == B_OPCODE && (disk[0] & B_MASK) != B_OPCODE) {
        if (disk[0] != NOP && !is_plt_stub(disk)) {
            int32_t offset = get_branch_offset(mem[0]);
            if (offset > 0x100000 || offset < -0x100000) {
                return 1;
            }
        }
    }

    return 0;
}

// ELF parsing
static unsigned long vaddr_to_offset(void *elf_map, unsigned long vaddr) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_map;
    Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)elf_map + ehdr->e_phoff);

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            unsigned long seg_start = phdr[i].p_vaddr;
            unsigned long seg_end = seg_start + phdr[i].p_memsz;
            if (vaddr >= seg_start && vaddr < seg_end) {
                return phdr[i].p_offset + (vaddr - seg_start);
            }
        }
    }
    return 0;
}

static int is_monitored_function(const char *name, const char *lib_name) {
    for (int i = 0; target_libs[i].lib_pattern != NULL; i++) {
        if (strstr(lib_name, target_libs[i].lib_pattern)) {
            for (int j = 0; target_libs[i].functions[j] != NULL; j++) {
                if (strcmp(name, target_libs[i].functions[j]) == 0) {
                    return 1;
                }
            }
        }
    }
    return 0;
}

static int extract_functions_from_elf(const char *lib_path, FunctionInfo *funcs, int max_funcs) {
    int fd = open(lib_path, O_RDONLY);
    if (fd < 0) return 0;

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return 0;
    }

    void *elf_map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (elf_map == MAP_FAILED) {
        close(fd);
        return 0;
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_map;
    if (memcmp(ehdr->e_ident, ELFMAG, 4) != 0 || ehdr->e_machine != 183) {
        munmap(elf_map, st.st_size);
        close(fd);
        return 0;
    }

    Elf64_Shdr *shdr = (Elf64_Shdr *)((char *)elf_map + ehdr->e_shoff);
    int func_count = 0;

    const char *lib_name = strrchr(lib_path, '/');
    if (lib_name) lib_name++; else lib_name = lib_path;

    for (int i = 0; i < ehdr->e_shnum && func_count < max_funcs; i++) {
        if (shdr[i].sh_type != SHT_DYNSYM) continue;

        Elf64_Sym *symtab = (Elf64_Sym *)((char *)elf_map + shdr[i].sh_offset);
        int sym_count = shdr[i].sh_size / sizeof(Elf64_Sym);

        Elf64_Shdr *strtab_shdr = &shdr[shdr[i].sh_link];
        char *strtab = (char *)elf_map + strtab_shdr->sh_offset;

        for (int j = 0; j < sym_count && func_count < max_funcs; j++) {
            unsigned char st_type = ELF64_ST_TYPE(symtab[j].st_info);

            if (st_type == STT_GNU_IFUNC) continue;
            if (st_type != STT_FUNC) continue;
            if (symtab[j].st_value == 0 || symtab[j].st_shndx == SHN_UNDEF) continue;

            const char *name = strtab + symtab[j].st_name;
            if (!is_monitored_function(name, lib_name)) continue;

            strncpy(funcs[func_count].name, name, sizeof(funcs[func_count].name) - 1);
            funcs[func_count].vaddr = symtab[j].st_value;
            funcs[func_count].file_offset = vaddr_to_offset(elf_map, symtab[j].st_value);
            func_count++;
        }
        break;
    }

    munmap(elf_map, st.st_size);
    close(fd);
    return func_count;
}

static int get_loaded_libraries(pid_t pid, LibraryInfo *libs, int max_libs) {
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *f = fopen(maps_path, "r");
    if (!f) return -1;

    char line[1024];
    int lib_count = 0;
    char last_path[512] = {0};

    while (fgets(line, sizeof(line), f) && lib_count < max_libs) {
        unsigned long start, end;
        char perms[5], path[512];
        int offset;

        if (sscanf(line, "%lx-%lx %4s %x %*s %*s %511s",
                   &start, &end, perms, &offset, path) < 4) {
            continue;
        }

        if (perms[2] != 'x' || offset != 0 || !strstr(path, ".so")) continue;
        if (strcmp(path, last_path) == 0) continue;

        int is_target = 0;
        const char *lib_name = strrchr(path, '/');
        if (lib_name) lib_name++; else lib_name = path;

        for (int i = 0; target_libs[i].lib_pattern != NULL; i++) {
            if (strstr(lib_name, target_libs[i].lib_pattern)) {
                is_target = 1;
                break;
            }
        }

        if (!is_target) continue;

        strncpy(libs[lib_count].path, path, sizeof(libs[lib_count].path) - 1);
        strncpy(libs[lib_count].short_name, lib_name, sizeof(libs[lib_count].short_name) - 1);
        libs[lib_count].base_addr = start;
        libs[lib_count].func_count = 0;
        strncpy(last_path, path, sizeof(last_path) - 1);
        lib_count++;
    }

    fclose(f);
    return lib_count;
}

static int read_bytes(const char *path, unsigned long offset, void *buf, size_t size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t got = pread(fd, buf, size, (off_t)offset);
    close(fd);
    return (got == (ssize_t)size) ? 0 : -1;
}

static int read_mem(pid_t pid, unsigned long addr, void *buf, size_t size) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t got = pread(fd, buf, size, (off_t)addr);
    close(fd);
    return (got == (ssize_t)size) ? 0 : -1;
}

static int get_process_name(pid_t pid, char *name, size_t size) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    if (fgets(name, size, f)) {
        name[strcspn(name, "\n")] = 0;
        fclose(f);
        return 0;
    }
    fclose(f);
    return -1;
}

static pid_t g_target_pid = 0;
static char g_target_lib[512] = {0};

static int scan_process(pid_t pid, int verbose) {
    LibraryInfo libs[32];
    int lib_count = get_loaded_libraries(pid, libs, 32);
    if (lib_count <= 0) return -1;

    char proc_name[256];
    get_process_name(pid, proc_name, sizeof(proc_name));

    int total_hooks = 0;
    int first_hook = 1;

    for (int i = 0; i < lib_count; i++) {
        if (g_target_lib[0] != '\0' && !strstr(libs[i].path, g_target_lib)) continue;

        libs[i].func_count = extract_functions_from_elf(libs[i].path,
                                                        libs[i].functions,
                                                        MAX_FUNCTIONS);

        for (int j = 0; j < libs[i].func_count; j++) {
            uint32_t disk[CHECK_INSNS], mem[CHECK_INSNS];
            size_t check_size = CHECK_INSNS * sizeof(uint32_t);

            if (read_bytes(libs[i].path, libs[i].functions[j].file_offset, 
                          disk, check_size) < 0) continue;

            unsigned long mem_addr = libs[i].base_addr + libs[i].functions[j].vaddr;
            if (read_mem(pid, mem_addr, mem, check_size) < 0) continue;

            if (memcmp(disk, mem, check_size) == 0) continue;

            if (is_real_edr_hook(disk, mem)) {
                if (first_hook) {
                    if (verbose) {
                        printf("\n[!] PID %d (%s):\n", pid, proc_name);
                    }
                    first_hook = 0;
                }
                if (verbose) {
                    printf("    [HOOK] %s in %s\n", 
                           libs[i].functions[j].name,
                           libs[i].short_name);
                }
                total_hooks++;
            }
        }
    }

    return total_hooks;
}

int main(int argc, char *argv[]) {
    int verbose = 0;
    struct option longopts[] = {
        {"pid", required_argument, NULL, 'p'},
        {"lib", required_argument, NULL, 'l'},
        {"verbose", no_argument, NULL, 'v'},
        {"help", no_argument, NULL, 'h'},
        {0,0,0,0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:l:vh", longopts, NULL)) != -1) {
        switch (opt) {
            case 'p': g_target_pid = (pid_t)atoi(optarg); break;
            case 'l': strncpy(g_target_lib, optarg, sizeof(g_target_lib)-1); break;
            case 'v': verbose = 1; break;
            case 'h':
            default:
                printf("ARM64 Multi-Library EDR Hook Detector\n");
                printf("Usage: %s [-p pid] [-l libpath] [-v] [-h]\n", argv[0]);
                printf("  -p, --pid    Scan only the given PID\n");
                printf("  -l, --lib    Only inspect this library path/name\n");
                printf("  -v, --verbose  Verbose output\n");
                printf("  -h, --help     Show this help\n");
                printf("\nChecks: libc, libpthread, libdl, libssl, libcrypto, libaudit, libpam\n");
                return 0;
        }
    }

    if (geteuid() != 0) {
        fprintf(stderr, "[!] Must run as root\nThe results might be partial\n");
    }

    printf("========================================================\n");
    printf("  ARM64 - EDR Hook Detector                \n");
    printf("========================================================\n\n");

    printf("Checking libraries:\n");
    for (int i = 0; target_libs[i].lib_pattern != NULL; i++) {
        printf("  • %s\n", target_libs[i].lib_pattern);
    }
    printf("\n");

    FILE *preload = fopen("/etc/ld.so.preload", "r");
    if (preload) {
        printf("[!] /etc/ld.so.preload exists\n");
        fclose(preload);
    } else {
        printf("[+] No /etc/ld.so.preload\n");
    }

    int total = 0, hooked = 0, total_hooks = 0;

    if (g_target_pid != 0) {
        // Only scan the specific PID requested
        int hooks = scan_process(g_target_pid, verbose);
        if (hooks > 0) {
            hooked = 1;
            total_hooks = hooks;
        }
        total = (hooks >= 0) ? 1 : 0;
    } else {
        DIR *proc = opendir("/proc");
        if (!proc) {
            fprintf(stderr, "Failed to open /proc\n");
            return 1;
        }

        printf("\nScanning processes...\n");

        struct dirent *entry;
        while ((entry = readdir(proc)) != NULL) {
            if (entry->d_type != DT_DIR || entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;
            pid_t pid = atoi(entry->d_name);
            int hooks = scan_process(pid, verbose);

            if (hooks > 0) {
                hooked++;
                total_hooks += hooks;
                if (!verbose) {
                    char name[256];
                    get_process_name(pid, name, sizeof(name));
                    printf("[!] PID %d (%s): %d hooks\n", pid, name, hooks);
                }
            }
            if (hooks >= 0) total++;
        }
        closedir(proc);
    }

    printf("\n========================================================\n");
    printf("SUMMARY\n");
    printf("========================================================\n");
    printf("Processes scanned:    %d\n", total);
    printf("With hooks:           %d\n", hooked);
    printf("Total hooks:          %d\n", total_hooks);

    if (hooked == 0) {
        printf("\n[+] No EDR hooks detected!\n");
    } else {
        printf("\n[!] EDR hooks found!\n");
        printf("    Run with -v for details\n");
    }

    printf("========================================================\n");

    return (hooked > 0) ? 1 : 0;
}