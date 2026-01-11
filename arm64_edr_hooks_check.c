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
#include <errno.h>

#define STT_GNU_IFUNC 10
#define MAX_PROCESSES 2048
#define MAX_FUNCTIONS 256
#define MAX_LIBRARIES 32
#define CHECK_INSNS 8

// ARM64 opcodes
#define NOP          0xd503201f
#define SVC_MASK     0xFFE0001F
#define SVC          0xd4000001
#define B_MASK       0xFC000000
#define B_OPCODE     0x14000000
#define BL_MASK      0xFC000000
#define BL_OPCODE    0x94000000
#define BR_MASK      0xFFFFFC1F
#define BR_OPCODE    0xD61F0000
#define BLR_MASK     0xFFFFFC1F
#define BLR_OPCODE   0xD63F0000
#define RET          0xd65f03c0
#define ADRP_MASK    0x9F000000
#define ADRP         0x90000000
#define LDR_MASK     0xFFC00000
#define LDR          0xF9400000
#define MOV_IMM_MASK 0xFFE00000
#define MOV_IMM      0xD2800000

typedef enum {
    HOOK_CONFIDENCE_NONE = 0,
    HOOK_CONFIDENCE_LOW = 1,
    HOOK_CONFIDENCE_MEDIUM = 2,
    HOOK_CONFIDENCE_HIGH = 3
} HookConfidence;

typedef struct {
    char name[128];
    unsigned long vaddr;
    unsigned long file_offset;
} FunctionInfo;

typedef struct {
    char path[512];
    char short_name[64];
    unsigned long base_addr;
    unsigned long preferred_base; 
    FunctionInfo functions[MAX_FUNCTIONS];
    int func_count;
} LibraryInfo;

typedef struct {
    pid_t target_pid;
    char target_lib[512];
    int verbose;
    int json_output;
    int show_hexdump;
} Config;

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
        "libc.so", 
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
    // Check if memory version is a short stub that returns early
    // This is benign if the disk version is a full implementation
    int disk_has_code = 0;
    int mem_early_ret = 0;
    
    // Check if disk has substantial code (not just a stub)
    for (int i = 0; i < 4; i++) {
        if (disk[i] != NOP && disk[i] != 0) {
            disk_has_code = 1;
            break;
        }
    }
    
    // Check if memory has early return (within first 3 instructions)
    for (int i = 0; i < 3; i++) {
        if (mem[i] == RET) {
            mem_early_ret = 1;
            break;
        }
    }
    
    // Alternative implementation: disk has code but mem returns early
    // This can happen with IFUNC resolvers choosing optimized paths
    return (disk_has_code && mem_early_ret);
}

static int is_indirect_branch(uint32_t insn) {
    return ((insn & BR_MASK) == BR_OPCODE ||
            (insn & BLR_MASK) == BLR_OPCODE);
}

static int is_branch_with_link(uint32_t insn) {
    return (insn & BL_MASK) == BL_OPCODE;
}

static HookConfidence detect_hook_confidence(uint32_t *disk, uint32_t *mem) {
    // Filter out known benign patterns
    if (is_syscall_cp_stub(disk)) return HOOK_CONFIDENCE_NONE;
    if (is_plt_stub(disk)) return HOOK_CONFIDENCE_NONE;
    if (is_wrapper_function(disk)) return HOOK_CONFIDENCE_NONE;
    if (is_tail_call_optimization(mem)) return HOOK_CONFIDENCE_NONE;
    if (is_function_epilogue(mem)) return HOOK_CONFIDENCE_NONE;
    if (is_alternative_implementation(disk, mem)) return HOOK_CONFIDENCE_NONE;

    int score = 0;
    int disk_has_svc = 0, mem_has_svc = 0;
    
    for (int i = 0; i < CHECK_INSNS; i++) {
        if ((disk[i] & SVC_MASK) == SVC) disk_has_svc = 1;
        if ((mem[i] & SVC_MASK) == SVC) mem_has_svc = 1;
    }

    // High confidence: syscall removed from memory
    if (disk_has_svc && !mem_has_svc) {
        if ((mem[0] & B_MASK) == B_OPCODE) {
            int32_t offset = get_branch_offset(mem[0]);
            // Small local branches are likely benign optimizations
            if ((offset > 0 && offset < 0x1000) || 
                (offset < 0 && offset > -0x1000)) {
                return HOOK_CONFIDENCE_NONE;
            }
        }
        score += 3;
    }

    // Medium confidence: unconditional branch added where there wasn't one
    if ((mem[0] & B_MASK) == B_OPCODE && (disk[0] & B_MASK) != B_OPCODE) {
        if (disk[0] != NOP && !is_plt_stub(disk)) {
            int32_t offset = get_branch_offset(mem[0]);
            // Long jumps (>1MB) are very suspicious
            if (offset > 0x100000 || offset < -0x100000) {
                score += 3;
            } else {
                score += 1;
            }
        }
    }

    // Additional checks for indirect branches (often used in hooks)
    if (is_indirect_branch(mem[0]) && !is_indirect_branch(disk[0])) {
        score += 2;
    }
    
    // Branch with link added (call to hook handler)
    if (is_branch_with_link(mem[0]) && !is_branch_with_link(disk[0])) {
        score += 2;
    }

    if (score >= 3) return HOOK_CONFIDENCE_HIGH;
    if (score >= 2) return HOOK_CONFIDENCE_MEDIUM;
    if (score >= 1) return HOOK_CONFIDENCE_LOW;
    return HOOK_CONFIDENCE_NONE;
}

static int vaddr_to_offset(void *elf_map, size_t map_size, unsigned long vaddr, 
                           unsigned long *offset_out, unsigned long *preferred_base_out) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_map;
    
    // Validate program header access
    if (ehdr->e_phoff + ehdr->e_phnum * sizeof(Elf64_Phdr) > map_size) {
        return -1;
    }
    
    Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)elf_map + ehdr->e_phoff);
    unsigned long preferred_base = (unsigned long)-1;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            if (preferred_base == (unsigned long)-1) {
                preferred_base = phdr[i].p_vaddr;
            }
            
            unsigned long seg_start = phdr[i].p_vaddr;
            unsigned long seg_end = seg_start + phdr[i].p_memsz;
            if (vaddr >= seg_start && vaddr < seg_end) {
                *offset_out = phdr[i].p_offset + (vaddr - seg_start);
                if (preferred_base_out) {
                    *preferred_base_out = preferred_base;
                }
                return 0;
            }
        }
    }
    return -1;
}

static int is_monitored_function(const char *name, const char *lib_name) {
    if (!name || !lib_name) return 0;
    
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

static int extract_functions_from_elf(const char *lib_path, FunctionInfo *funcs, 
                                       int max_funcs, unsigned long *preferred_base_out,
                                       int verbose) {
    int fd = open(lib_path, O_RDONLY);
    if (fd < 0) {
        if (verbose) {
            fprintf(stderr, "[!] Cannot open %s: %s\n", lib_path, strerror(errno));
        }
        return 0;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        if (verbose) {
            fprintf(stderr, "[!] Cannot stat %s: %s\n", lib_path, strerror(errno));
        }
        close(fd);
        return 0;
    }

    // Validate minimum size for ELF header
    if ((size_t)st.st_size < sizeof(Elf64_Ehdr)) {
        if (verbose) {
            fprintf(stderr, "[!] File too small for ELF: %s\n", lib_path);
        }
        close(fd);
        return 0;
    }

    void *elf_map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (elf_map == MAP_FAILED) {
        if (verbose) {
            fprintf(stderr, "[!] Cannot mmap %s: %s\n", lib_path, strerror(errno));
        }
        close(fd);
        return 0;
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_map;
    
    if (memcmp(ehdr->e_ident, ELFMAG, 4) != 0) {
        munmap(elf_map, st.st_size);
        close(fd);
        return 0;
    }
    
    // 183 = EM_AARCH64
    if (ehdr->e_machine != 183) {
        if (verbose) {
            fprintf(stderr, "[!] Not ARM64 ELF: %s (machine=%d)\n", lib_path, ehdr->e_machine);
        }
        munmap(elf_map, st.st_size);
        close(fd);
        return 0;
    }

    if (ehdr->e_shoff + ehdr->e_shnum * sizeof(Elf64_Shdr) > (size_t)st.st_size) {
        if (verbose) {
            fprintf(stderr, "[!] Invalid section headers in %s\n", lib_path);
        }
        munmap(elf_map, st.st_size);
        close(fd);
        return 0;
    }

    Elf64_Shdr *shdr = (Elf64_Shdr *)((char *)elf_map + ehdr->e_shoff);
    int func_count = 0;

    const char *lib_name = strrchr(lib_path, '/');
    lib_name = lib_name ? lib_name + 1 : lib_path;

    // Get preferred base address from first PT_LOAD
    unsigned long preferred_base = 0;
    Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)elf_map + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            preferred_base = phdr[i].p_vaddr;
            break;
        }
    }
    if (preferred_base_out) {
        *preferred_base_out = preferred_base;
    }

    for (int i = 0; i < ehdr->e_shnum && func_count < max_funcs; i++) {
        if (shdr[i].sh_type != SHT_DYNSYM) continue;

        // Validate symbol table bounds
        if (shdr[i].sh_offset + shdr[i].sh_size > (size_t)st.st_size) {
            continue;
        }

        Elf64_Sym *symtab = (Elf64_Sym *)((char *)elf_map + shdr[i].sh_offset);
        long unsigned int sym_count = shdr[i].sh_size / sizeof(Elf64_Sym);

        // Validate string table index
        if (shdr[i].sh_link >= ehdr->e_shnum) {
            continue;
        }

        Elf64_Shdr *strtab_shdr = &shdr[shdr[i].sh_link];
        
        // Validate string table bounds
        if (strtab_shdr->sh_offset + strtab_shdr->sh_size > (size_t)st.st_size) {
            continue;
        }
        
        char *strtab = (char *)elf_map + strtab_shdr->sh_offset;

        for (int j = 0; j < (int) sym_count && func_count < max_funcs; j++) {
            unsigned char st_type = ELF64_ST_TYPE(symtab[j].st_info);

            if (st_type == STT_GNU_IFUNC) continue;
            if (st_type != STT_FUNC) continue;
            if (symtab[j].st_value == 0 || symtab[j].st_shndx == SHN_UNDEF) continue;

            // Validate string table offset
            if (symtab[j].st_name >= strtab_shdr->sh_size) {
                continue;
            }

            const char *name = strtab + symtab[j].st_name;
            if (!is_monitored_function(name, lib_name)) continue;

            snprintf(funcs[func_count].name, sizeof(funcs[func_count].name), "%s", name);
            funcs[func_count].vaddr = symtab[j].st_value;
            
            unsigned long offset;
            if (vaddr_to_offset(elf_map, st.st_size, symtab[j].st_value, &offset, NULL) == 0) {
                funcs[func_count].file_offset = offset;
            } else {
                funcs[func_count].file_offset = 0;
            }
            func_count++;
        }
        break;
    }

    munmap(elf_map, st.st_size);
    close(fd);
    return func_count;
}

static int get_loaded_libraries(pid_t pid, LibraryInfo **libs_out, int max_libs, int verbose) {
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *f = fopen(maps_path, "r");
    if (!f) {
        if (verbose) {
            fprintf(stderr, "[!] Cannot open %s: %s\n", maps_path, strerror(errno));
        }
        return -1;
    }

    // Allocate on heap to avoid stack overflow
    LibraryInfo *libs = calloc(max_libs, sizeof(LibraryInfo));
    if (!libs) {
        fclose(f);
        return -1;
    }

    char line[1024];
    int lib_count = 0;
    char last_path[512] = {0};

    while (fgets(line, sizeof(line), f) && lib_count < max_libs) {
        unsigned long start, end, offset; 
        char perms[5] = {0};
        char path[512] = {0}; 

        int parsed = sscanf(line, "%lx-%lx %4s %lx %*s %*s %511s",
                           &start, &end, perms, &offset, path);
        
        if (parsed < 4) {
            continue;
        }

        if (parsed < 5 || path[0] == '\0') {
            continue;
        }

        if (perms[2] != 'x' || offset != 0 || !strstr(path, ".so")) continue;
        if (strcmp(path, last_path) == 0) continue;

        int is_target = 0;
        const char *lib_name = strrchr(path, '/');
        lib_name = lib_name ? lib_name + 1 : path;

        for (int i = 0; target_libs[i].lib_pattern != NULL; i++) {
            if (strstr(lib_name, target_libs[i].lib_pattern)) {
                is_target = 1;
                break;
            }
        }

        if (!is_target) continue;

        snprintf(libs[lib_count].path, sizeof(libs[lib_count].path), "%s", path);
        snprintf(libs[lib_count].short_name, sizeof(libs[lib_count].short_name), "%s", lib_name);
        libs[lib_count].base_addr = start;
        libs[lib_count].preferred_base = 0;
        libs[lib_count].func_count = 0;
        snprintf(last_path, sizeof(last_path), "%s", path);
        lib_count++;
    }

    fclose(f);
    *libs_out = libs;
    return lib_count;
}

static int read_bytes(const char *path, unsigned long offset, void *buf, size_t size, int verbose) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        if (verbose) {
            fprintf(stderr, "[!] Cannot open %s: %s\n", path, strerror(errno));
        }
        return -1;
    }
    ssize_t got = pread(fd, buf, size, (off_t)offset);
    close(fd);
    
    if (got != (ssize_t)size) {
        if (verbose) {
            fprintf(stderr, "[!] Short read from %s: got %zd, expected %zu\n", 
                    path, got, size);
        }
        return -1;
    }
    return 0;
}

static int read_mem(pid_t pid, unsigned long addr, void *buf, size_t size, int verbose) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        if (verbose) {
            fprintf(stderr, "[!] Cannot open %s: %s\n", path, strerror(errno));
        }
        return -1;
    }
    ssize_t got = pread(fd, buf, size, (off_t)addr);
    close(fd);
    
    if (got != (ssize_t)size) {
        if (verbose > 1) {  // Only show on extra verbose
            fprintf(stderr, "[!] Short read from PID %d mem at 0x%lx\n", pid, addr);
        }
        return -1;
    }
    return 0;
}

static int get_process_name(pid_t pid, char *name, int size) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (!f) {
        snprintf(name, size, "<unknown>");
        return -1;
    }
    if (fgets(name, size, f)) {
        name[strcspn(name, "\n")] = '\0';
        fclose(f);
        return 0;
    }
    fclose(f);
    snprintf(name, size, "<unknown>");
    return -1;
}

// Helper to print hexdump of instructions
static void print_hexdump(const char *label, uint32_t *insns, int count) {
    printf("    %s: ", label);
    for (int i = 0; i < count; i++) {
        printf("%08x ", insns[i]);
    }
    printf("\n");
}

// Helper to get confidence string
static const char *confidence_str(HookConfidence conf) {
    switch (conf) {
        case HOOK_CONFIDENCE_HIGH: return "HIGH";
        case HOOK_CONFIDENCE_MEDIUM: return "MEDIUM";
        case HOOK_CONFIDENCE_LOW: return "LOW";
        default: return "NONE";
    }
}

static int scan_process(pid_t pid, const Config *config) {
    LibraryInfo *libs = NULL;
    int lib_count = get_loaded_libraries(pid, &libs, MAX_LIBRARIES, config->verbose);
    if (lib_count <= 0) {
        if (libs) free(libs);
        return -1;
    }

    char proc_name[256];
    get_process_name(pid, proc_name, sizeof(proc_name));

    int total_hooks = 0;
    int first_hook = 1;

    for (int i = 0; i < lib_count; i++) {
        if (config->target_lib[0] != '\0' && !strstr(libs[i].path, config->target_lib)) {
            continue;
        }

        libs[i].func_count = extract_functions_from_elf(
            libs[i].path,
            libs[i].functions,
            MAX_FUNCTIONS,
            &libs[i].preferred_base,
            config->verbose
        );

        for (int j = 0; j < libs[i].func_count; j++) {
            uint32_t disk[CHECK_INSNS] = {0};
            uint32_t mem[CHECK_INSNS] = {0};
            size_t check_size = CHECK_INSNS * sizeof(uint32_t);

            if (libs[i].functions[j].file_offset == 0) {
                continue;
            }

            if (read_bytes(libs[i].path, libs[i].functions[j].file_offset, 
                          disk, check_size, config->verbose) < 0) {
                continue;
            }

            unsigned long mem_addr = libs[i].base_addr + 
                (libs[i].functions[j].vaddr - libs[i].preferred_base);
            
            if (read_mem(pid, mem_addr, mem, check_size, config->verbose) < 0) {
                continue;
            }

            if (memcmp(disk, mem, check_size) == 0) {
                continue;
            }

            HookConfidence confidence = detect_hook_confidence(disk, mem);
            
            if (confidence != HOOK_CONFIDENCE_NONE) {
                if (first_hook) {
                    if (config->json_output) {
                        printf("{\"pid\":%d,\"name\":\"%s\",\"hooks\":[", pid, proc_name);
                    } else if (config->verbose) {
                        printf("\n[!] PID %d (%s):\n", pid, proc_name);
                    }
                    first_hook = 0;
                }
                
                if (config->json_output) {
                    if (total_hooks > 0) printf(",");
                    printf("{\"function\":\"%s\",\"library\":\"%s\",\"confidence\":\"%s\"}",
                           libs[i].functions[j].name,
                           libs[i].short_name,
                           confidence_str(confidence));
                } else if (config->verbose) {
                    printf("    [HOOK] %s in %s (confidence: %s)\n", 
                           libs[i].functions[j].name,
                           libs[i].short_name,
                           confidence_str(confidence));
                    
                    if (config->show_hexdump) {
                        print_hexdump("Disk", disk, CHECK_INSNS);
                        print_hexdump("Mem ", mem, CHECK_INSNS);
                    }
                }
                total_hooks++;
            }
        }
    }

    if (!first_hook && config->json_output) {
        printf("]}");
    }

    free(libs);
    return total_hooks;
}

static void check_environment_hooks(const Config *config) {
    // Check LD_PRELOAD
    char *ld_preload = getenv("LD_PRELOAD");
    if (ld_preload && strlen(ld_preload) > 0) {
        if (config->json_output) {
            printf("{\"warning\":\"LD_PRELOAD\",\"value\":\"%s\"}\n", ld_preload);
        } else {
            printf("[!] LD_PRELOAD is set: %s\n", ld_preload);
        }
    }

    // Check /etc/ld.so.preload
    FILE *preload = fopen("/etc/ld.so.preload", "r");
    if (preload) {
        char content[1024] = {0};
        size_t len = fread(content, 1, sizeof(content) - 1, preload);
        fclose(preload);
        
        // Remove trailing newline
        if (len > 0 && content[len-1] == '\n') {
            content[len-1] = '\0';
        }
        
        if (config->json_output) {
            printf("{\"warning\":\"ld.so.preload\",\"exists\":true,\"content\":\"%s\"}\n", 
                   len > 0 ? content : "");
        } else {
            printf("[!] /etc/ld.so.preload exists");
            if (len > 0) {
                printf(": %s", content);
            }
            printf("\n");
        }
    } else if (!config->json_output) {
        printf("[+] No /etc/ld.so.preload\n");
    }
}

static void print_usage(const char *prog_name) {
    printf("ARM64 Multi-Library EDR Hook Detector\n");
    printf("Usage: %s [options]\n\n", prog_name);
    printf("Options:\n");
    printf("  -p, --pid <PID>     Scan only the given PID\n");
    printf("  -l, --lib <PATH>    Only inspect this library path/name\n");
    printf("  -v, --verbose       Verbose output (use twice for more detail)\n");
    printf("  -j, --json          Output in JSON format\n");
    printf("  -x, --hexdump       Show hexdump of modified instructions\n");
    printf("  -s, --self          Scan only the current process (no root needed)\n");
    printf("  -h, --help          Show this help\n");
    printf("\nChecked libraries:\n");
    for (int i = 0; target_libs[i].lib_pattern != NULL; i++) {
        printf("  • %s\n", target_libs[i].lib_pattern);
    }
}

int main(int argc, char *argv[]) {
    Config config = {0};
    int self_scan = 0;
    
    struct option longopts[] = {
        {"pid", required_argument, NULL, 'p'},
        {"lib", required_argument, NULL, 'l'},
        {"verbose", no_argument, NULL, 'v'},
        {"json", no_argument, NULL, 'j'},
        {"hexdump", no_argument, NULL, 'x'},
        {"self", no_argument, NULL, 's'},
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:l:vjxsh", longopts, NULL)) != -1) {
        switch (opt) {
            case 'p': 
                config.target_pid = (pid_t)atoi(optarg); 
                break;
            case 'l': 
                snprintf(config.target_lib, sizeof(config.target_lib), "%s", optarg);
                break;
            case 'v': 
                config.verbose++; 
                break;
            case 'j':
                config.json_output = 1;
                break;
            case 'x':
                config.show_hexdump = 1;
                break;
            case 's':
                self_scan = 1;
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return 0;
        }
    }

    // Self-scan mode for non-root users
    if (self_scan) {
        config.target_pid = getpid();
    }

    // Check if we need root and don't have it
    if (geteuid() != 0 && config.target_pid == 0) {
        if (!config.json_output) {
            fprintf(stderr, "[!] Must run as root to scan all processes\n");
            fprintf(stderr, "[*] Use -s/--self to scan current process without root\n");
            fprintf(stderr, "[*] Use -p/--pid to scan a specific owned process\n");
        }
        // Auto-enable self-scan mode
        config.target_pid = getpid();
        if (!config.json_output) {
            fprintf(stderr, "[*] Auto-enabling self-scan mode (PID %d)\n\n", config.target_pid);
        }
    }

    if (!config.json_output) {
        printf("========================================================\n");
        printf("  ARM64 - EDR Hook Detector\n");
        printf("========================================================\n\n");

        printf("Checking libraries:\n");
        for (int i = 0; target_libs[i].lib_pattern != NULL; i++) {
            printf("  • %s\n", target_libs[i].lib_pattern);
        }
        printf("\n");
    }

    check_environment_hooks(&config);

    int total = 0, hooked = 0, total_hooks = 0;

    if (config.target_pid != 0) {
        // Scan specific PID
        int hooks = scan_process(config.target_pid, &config);
        if (hooks > 0) {
            hooked = 1;
            total_hooks = hooks;
            if (!config.verbose && !config.json_output) {
                char name[256];
                get_process_name(config.target_pid, name, sizeof(name));
                printf("[!] PID %d (%s): %d hooks\n", config.target_pid, name, hooks);
            }
        }
        total = (hooks >= 0) ? 1 : 0;
    } else {
        // Scan all processes
        DIR *proc = opendir("/proc");
        if (!proc) {
            fprintf(stderr, "Failed to open /proc: %s\n", strerror(errno));
            return 1;
        }

        if (!config.json_output) {
            printf("\nScanning processes...\n");
        } else {
            printf("[");
        }

        int first_json = 1;
        struct dirent *entry;
        while ((entry = readdir(proc)) != NULL) {
            if (entry->d_type != DT_DIR) continue;
            if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;
            
            pid_t pid = atoi(entry->d_name);
            int hooks = scan_process(pid, &config);

            if (hooks > 0) {
                if (config.json_output && !first_json) {
                    printf(",");
                }
                first_json = 0;
                
                hooked++;
                total_hooks += hooks;
                
                if (!config.verbose && !config.json_output) {
                    char name[256];
                    get_process_name(pid, name, sizeof(name));
                    printf("[!] PID %d (%s): %d hooks\n", pid, name, hooks);
                }
            }
            if (hooks >= 0) total++;
        }
        closedir(proc);
        
        if (config.json_output) {
            printf("]\n");
        }
    }

    if (!config.json_output) {
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
            if (!config.verbose) {
                printf("    Run with -v for details\n");
            }
            if (!config.show_hexdump) {
                printf("    Run with -x to see instruction hexdumps\n");
            }
        }

        printf("========================================================\n");
    }

    return (hooked > 0) ? 1 : 0;
}
