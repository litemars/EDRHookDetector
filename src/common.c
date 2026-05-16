#define _GNU_SOURCE
#include "common.h"
#include "arch_arm64.h"
#include "arch_x86.h"

/* ── Target library / function table ────────────────────────────────────── */

const TargetLibEntry target_libs[] = {
    { "libc.so.6", {
        "open", "openat", "creat", "close",
        "read", "write", "pread", "pwrite",
        "socket", "connect", "bind", "listen", "accept",
        "send", "recv", "sendto", "recvfrom",
        "execve", "fork", "clone",
        "mmap", "munmap", "mprotect",
        "ptrace", "kill", "prctl",
        NULL } },
    { "libc.so", {
        "open", "openat", "creat", "close",
        "read", "write", "pread", "pwrite",
        "socket", "connect", "bind", "listen", "accept",
        "send", "recv", "sendto", "recvfrom",
        "execve", "fork", "clone",
        "mmap", "munmap", "mprotect",
        "ptrace", "kill", "prctl",
        NULL } },
    { "libpthread.so", {
        "pthread_create", "pthread_exit", "pthread_kill",
        "pthread_mutex_lock", "pthread_mutex_unlock",
        NULL } },
    { "libdl.so", {
        "dlopen", "dlsym", "dlclose", "dlmopen",
        NULL } },
    { "libssl.so", {
        "SSL_read", "SSL_write", "SSL_connect",
        "SSL_accept", "SSL_do_handshake",
        NULL } },
    { "libcrypto.so", {
        "EVP_EncryptInit", "EVP_DecryptInit",
        "EVP_EncryptUpdate", "EVP_DecryptUpdate",
        NULL } },
    { "libaudit.so", {
        "audit_log_user_message", "audit_open",
        NULL } },
    { "libpam.so", {
        "pam_authenticate", "pam_open_session",
        NULL } },
    { NULL, { NULL } }
};

/* ── ELF helpers ─────────────────────────────────────────────────────────── */

static int is_monitored_function(const char *name, const char *lib_name) {
    if (!name || !lib_name) return 0;
    for (int i = 0; target_libs[i].lib_pattern != NULL; i++) {
        if (strstr(lib_name, target_libs[i].lib_pattern)) {
            for (int j = 0; target_libs[i].functions[j] != NULL; j++) {
                if (strcmp(name, target_libs[i].functions[j]) == 0) return 1;
            }
        }
    }
    return 0;
}

/* ELF64: virtual address → file offset */
static int vaddr_to_offset64(void *elf_map, size_t map_size,
                              uint64_t vaddr, unsigned long *off_out,
                              unsigned long *preferred_base_out) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_map;
    if (ehdr->e_phoff + (size_t)ehdr->e_phnum * sizeof(Elf64_Phdr) > map_size)
        return -1;
    Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)elf_map + ehdr->e_phoff);
    unsigned long pbase = (unsigned long)-1;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD) continue;
        if (pbase == (unsigned long)-1) pbase = (unsigned long)phdr[i].p_vaddr;
        if (vaddr >= phdr[i].p_vaddr && vaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
            *off_out = (unsigned long)(phdr[i].p_offset + (vaddr - phdr[i].p_vaddr));
            if (preferred_base_out) *preferred_base_out = pbase;
            return 0;
        }
    }
    return -1;
}

/* ELF32: virtual address → file offset */
static int vaddr_to_offset32(void *elf_map, size_t map_size,
                              uint32_t vaddr, unsigned long *off_out,
                              unsigned long *preferred_base_out) {
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)elf_map;
    if (ehdr->e_phoff + (size_t)ehdr->e_phnum * sizeof(Elf32_Phdr) > map_size)
        return -1;
    Elf32_Phdr *phdr = (Elf32_Phdr *)((char *)elf_map + ehdr->e_phoff);
    unsigned long pbase = (unsigned long)-1;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD) continue;
        if (pbase == (unsigned long)-1) pbase = (unsigned long)phdr[i].p_vaddr;
        if (vaddr >= phdr[i].p_vaddr && vaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
            *off_out = (unsigned long)(phdr[i].p_offset + (vaddr - phdr[i].p_vaddr));
            if (preferred_base_out) *preferred_base_out = pbase;
            return 0;
        }
    }
    return -1;
}

/* Parse the dynamic symbol table of an already-mapped ELF64 binary. */
static int extract_elf64(void *elf_map, size_t map_size, const char *lib_path,
                          FunctionInfo *funcs, int max_funcs,
                          unsigned long *preferred_base_out, int *arch_out,
                          int verbose) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_map;

    if (ehdr->e_machine != EM_AARCH64 && ehdr->e_machine != EM_X86_64) {
        if (verbose)
            fprintf(stderr, "[!] Unsupported ELF64 machine type %d in %s\n",
                    ehdr->e_machine, lib_path);
        return 0;
    }
    if (arch_out) *arch_out = (int)ehdr->e_machine;

    if (ehdr->e_shoff + (size_t)ehdr->e_shnum * sizeof(Elf64_Shdr) > map_size) {
        if (verbose) fprintf(stderr, "[!] Invalid section headers in %s\n", lib_path);
        return 0;
    }

    /* Preferred base from first PT_LOAD */
    unsigned long pbase = 0;
    if (ehdr->e_phoff + (size_t)ehdr->e_phnum * sizeof(Elf64_Phdr) <= map_size) {
        Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)elf_map + ehdr->e_phoff);
        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == PT_LOAD) { pbase = (unsigned long)phdr[i].p_vaddr; break; }
        }
    }
    if (preferred_base_out) *preferred_base_out = pbase;

    const char *lib_name = strrchr(lib_path, '/');
    lib_name = lib_name ? lib_name + 1 : lib_path;

    Elf64_Shdr *shdr = (Elf64_Shdr *)((char *)elf_map + ehdr->e_shoff);
    int func_count = 0;

    for (int i = 0; i < ehdr->e_shnum && func_count < max_funcs; i++) {
        if (shdr[i].sh_type != SHT_DYNSYM) continue;
        if (shdr[i].sh_offset + shdr[i].sh_size > map_size) continue;
        if (shdr[i].sh_link >= ehdr->e_shnum) continue;

        Elf64_Sym  *symtab     = (Elf64_Sym *)((char *)elf_map + shdr[i].sh_offset);
        size_t      sym_count  = shdr[i].sh_size / sizeof(Elf64_Sym);
        Elf64_Shdr *strtab_sh  = &shdr[shdr[i].sh_link];
        if (strtab_sh->sh_offset + strtab_sh->sh_size > map_size) continue;
        char *strtab = (char *)elf_map + strtab_sh->sh_offset;

        for (size_t j = 0; j < sym_count && func_count < max_funcs; j++) {
            unsigned char st = ELF64_ST_TYPE(symtab[j].st_info);
            if (st == STT_GNU_IFUNC) continue;
            if (st != STT_FUNC)      continue;
            if (symtab[j].st_value == 0 || symtab[j].st_shndx == SHN_UNDEF) continue;
            if (symtab[j].st_name >= strtab_sh->sh_size) continue;

            const char *name = strtab + symtab[j].st_name;
            if (!is_monitored_function(name, lib_name)) continue;

            snprintf(funcs[func_count].name, sizeof(funcs[func_count].name), "%s", name);
            funcs[func_count].vaddr = (unsigned long)symtab[j].st_value;

            unsigned long file_off = 0;
            if (vaddr_to_offset64(elf_map, map_size, symtab[j].st_value, &file_off, NULL) == 0)
                funcs[func_count].file_offset = file_off;
            func_count++;
        }
        break; /* only one SHT_DYNSYM section */
    }
    return func_count;
}

/* Parse the dynamic symbol table of an already-mapped ELF32 binary. */
static int extract_elf32(void *elf_map, size_t map_size, const char *lib_path,
                          FunctionInfo *funcs, int max_funcs,
                          unsigned long *preferred_base_out, int *arch_out,
                          int verbose) {
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)elf_map;

    if (ehdr->e_machine != EM_386) {
        if (verbose)
            fprintf(stderr, "[!] Unsupported ELF32 machine type %d in %s\n",
                    ehdr->e_machine, lib_path);
        return 0;
    }
    if (arch_out) *arch_out = (int)ehdr->e_machine;

    if (ehdr->e_shoff + (size_t)ehdr->e_shnum * sizeof(Elf32_Shdr) > map_size) {
        if (verbose) fprintf(stderr, "[!] Invalid section headers in %s\n", lib_path);
        return 0;
    }

    /* Preferred base from first PT_LOAD */
    unsigned long pbase = 0;
    if (ehdr->e_phoff + (size_t)ehdr->e_phnum * sizeof(Elf32_Phdr) <= map_size) {
        Elf32_Phdr *phdr = (Elf32_Phdr *)((char *)elf_map + ehdr->e_phoff);
        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == PT_LOAD) { pbase = (unsigned long)phdr[i].p_vaddr; break; }
        }
    }
    if (preferred_base_out) *preferred_base_out = pbase;

    const char *lib_name = strrchr(lib_path, '/');
    lib_name = lib_name ? lib_name + 1 : lib_path;

    Elf32_Shdr *shdr = (Elf32_Shdr *)((char *)elf_map + ehdr->e_shoff);
    int func_count = 0;

    for (int i = 0; i < ehdr->e_shnum && func_count < max_funcs; i++) {
        if (shdr[i].sh_type != SHT_DYNSYM) continue;
        if (shdr[i].sh_offset + shdr[i].sh_size > map_size) continue;
        if (shdr[i].sh_link >= ehdr->e_shnum) continue;

        Elf32_Sym  *symtab    = (Elf32_Sym *)((char *)elf_map + shdr[i].sh_offset);
        size_t      sym_count = shdr[i].sh_size / sizeof(Elf32_Sym);
        Elf32_Shdr *strtab_sh = &shdr[shdr[i].sh_link];
        if (strtab_sh->sh_offset + strtab_sh->sh_size > map_size) continue;
        char *strtab = (char *)elf_map + strtab_sh->sh_offset;

        for (size_t j = 0; j < sym_count && func_count < max_funcs; j++) {
            unsigned char st = ELF32_ST_TYPE(symtab[j].st_info);
            if (st == STT_GNU_IFUNC) continue;
            if (st != STT_FUNC)      continue;
            if (symtab[j].st_value == 0 || symtab[j].st_shndx == SHN_UNDEF) continue;
            if (symtab[j].st_name >= strtab_sh->sh_size) continue;

            const char *name = strtab + symtab[j].st_name;
            if (!is_monitored_function(name, lib_name)) continue;

            snprintf(funcs[func_count].name, sizeof(funcs[func_count].name), "%s", name);
            funcs[func_count].vaddr = (unsigned long)symtab[j].st_value;

            unsigned long file_off = 0;
            if (vaddr_to_offset32(elf_map, map_size, symtab[j].st_value, &file_off, NULL) == 0)
                funcs[func_count].file_offset = file_off;
            func_count++;
        }
        break;
    }
    return func_count;
}

int extract_functions_from_elf(const char *lib_path, FunctionInfo *funcs,
                                int max_funcs, unsigned long *preferred_base_out,
                                int *arch_out, int verbose) {
    if (arch_out) *arch_out = 0;

    int fd = open(lib_path, O_RDONLY);
    if (fd < 0) {
        if (verbose) fprintf(stderr, "[!] Cannot open %s: %s\n", lib_path, strerror(errno));
        return 0;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        if (verbose) fprintf(stderr, "[!] Cannot stat %s: %s\n", lib_path, strerror(errno));
        close(fd); return 0;
    }

    if ((size_t)st.st_size < EI_NIDENT + 2) { close(fd); return 0; }

    void *elf_map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (elf_map == MAP_FAILED) {
        if (verbose) fprintf(stderr, "[!] Cannot mmap %s: %s\n", lib_path, strerror(errno));
        close(fd); return 0;
    }

    int result = 0;
    const uint8_t *ident = (const uint8_t *)elf_map;

    if (memcmp(ident, ELFMAG, SELFMAG) != 0) goto done;

    switch (ident[EI_CLASS]) {
        case ELFCLASS64:
            result = extract_elf64(elf_map, (size_t)st.st_size, lib_path,
                                   funcs, max_funcs, preferred_base_out, arch_out, verbose);
            break;
        case ELFCLASS32:
            result = extract_elf32(elf_map, (size_t)st.st_size, lib_path,
                                   funcs, max_funcs, preferred_base_out, arch_out, verbose);
            break;
        default:
            if (verbose)
                fprintf(stderr, "[!] Unknown ELF class in %s\n", lib_path);
            break;
    }

done:
    munmap(elf_map, (size_t)st.st_size);
    close(fd);
    return result;
}

/* ── Process / memory helpers ────────────────────────────────────────────── */

int get_loaded_libraries(pid_t pid, LibraryInfo **libs_out, int max_libs, int verbose) {
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *f = fopen(maps_path, "r");
    if (!f) {
        if (verbose) fprintf(stderr, "[!] Cannot open %s: %s\n", maps_path, strerror(errno));
        return -1;
    }

    LibraryInfo *libs = calloc((size_t)max_libs, sizeof(LibraryInfo));
    if (!libs) { fclose(f); return -1; }

    char line[1024];
    int  lib_count = 0;
    char last_path[512] = {0};

    while (fgets(line, sizeof(line), f) && lib_count < max_libs) {
        unsigned long start, end, offset;
        char perms[5] = {0};
        char path[512] = {0};

        int parsed = sscanf(line, "%lx-%lx %4s %lx %*s %*s %511s",
                            &start, &end, perms, &offset, path);
        if (parsed < 4) continue;
        if (parsed < 5 || path[0] == '\0') continue;
        if (offset != 0 || !strstr(path, ".so")) continue;
        if (strcmp(path, last_path) == 0) continue;

        const char *lib_name = strrchr(path, '/');
        lib_name = lib_name ? lib_name + 1 : path;

        int is_target = 0;
        for (int i = 0; target_libs[i].lib_pattern != NULL; i++) {
            if (strstr(lib_name, target_libs[i].lib_pattern)) { is_target = 1; break; }
        }
        if (!is_target) continue;

        snprintf(libs[lib_count].path,       sizeof(libs[lib_count].path),       "%s", path);
        snprintf(libs[lib_count].short_name, sizeof(libs[lib_count].short_name), "%s", lib_name);
        libs[lib_count].base_addr      = start;
        libs[lib_count].preferred_base = 0;
        libs[lib_count].arch           = 0;
        libs[lib_count].func_count     = 0;
        snprintf(last_path, sizeof(last_path), "%s", path);
        lib_count++;
    }

    fclose(f);
    *libs_out = libs;
    return lib_count;
}

int read_bytes(const char *path, unsigned long offset, void *buf, size_t size, int verbose) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        if (verbose) fprintf(stderr, "[!] Cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }
    ssize_t got = pread(fd, buf, size, (off_t)offset);
    close(fd);
    if (got != (ssize_t)size) {
        if (verbose)
            fprintf(stderr, "[!] Short read from %s: got %zd, expected %zu\n",
                    path, got, size);
        return -1;
    }
    return 0;
}

int read_mem(pid_t pid, unsigned long addr, void *buf, size_t size, int verbose) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        if (verbose) fprintf(stderr, "[!] Cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }
    ssize_t got = pread(fd, buf, size, (off_t)addr);
    close(fd);
    if (got != (ssize_t)size) {
        if (verbose > 1)
            fprintf(stderr, "[!] Short read from PID %d mem at 0x%lx\n", pid, addr);
        return -1;
    }
    return 0;
}

int get_process_name(pid_t pid, char *name, int size) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (!f) { snprintf(name, size, "<unknown>"); return -1; }
    if (fgets(name, size, f)) {
        name[strcspn(name, "\n")] = '\0';
        fclose(f);
        return 0;
    }
    fclose(f);
    snprintf(name, size, "<unknown>");
    return -1;
}

/* ── Output helpers ──────────────────────────────────────────────────────── */

const char *confidence_str(HookConfidence conf) {
    switch (conf) {
        case HOOK_CONFIDENCE_HIGH:   return "HIGH";
        case HOOK_CONFIDENCE_MEDIUM: return "MEDIUM";
        case HOOK_CONFIDENCE_LOW:    return "LOW";
        default:                     return "NONE";
    }
}

void json_print_escaped(const char *s) {
    if (!s) return;
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
            case '"':  fputs("\\\"", stdout); break;
            case '\\': fputs("\\\\", stdout); break;
            case '\b': fputs("\\b",  stdout); break;
            case '\f': fputs("\\f",  stdout); break;
            case '\n': fputs("\\n",  stdout); break;
            case '\r': fputs("\\r",  stdout); break;
            case '\t': fputs("\\t",  stdout); break;
            default:
                if (c < 0x20) printf("\\u%04x", (unsigned int)c);
                else          putchar((int)c);
                break;
        }
    }
}

static void print_hexdump_words(const char *label, const uint32_t *insns, int count) {
    printf("    %s: ", label);
    for (int i = 0; i < count; i++) printf("%08x ", insns[i]);
    printf("\n");
}

static void print_hexdump_bytes(const char *label, const uint8_t *bytes, int len) {
    printf("    %s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x ", bytes[i]);
        if ((i + 1) % 16 == 0 && i + 1 < len) printf("\n           ");
    }
    printf("\n");
}

void check_environment_hooks(const Config *config) {
    char *ld_preload = getenv("LD_PRELOAD");

    char preload_content[1024] = {0};
    size_t preload_len = 0;
    int has_preload_file = 0;
    FILE *preload_f = fopen("/etc/ld.so.preload", "r");
    if (preload_f) {
        has_preload_file = 1;
        preload_len = fread(preload_content, 1, sizeof(preload_content) - 1, preload_f);
        fclose(preload_f);
        if (preload_len > 0 && preload_content[preload_len - 1] == '\n')
            preload_content[--preload_len] = '\0';
    }

    if (config->json_output) {
        printf("\"warnings\":[");
        int first = 1;
        if (ld_preload && strlen(ld_preload) > 0) {
            printf("{\"type\":\"LD_PRELOAD\",\"value\":\"");
            json_print_escaped(ld_preload);
            printf("\"}");
            first = 0;
        }
        if (has_preload_file) {
            if (!first) printf(",");
            printf("{\"type\":\"ld.so.preload\",\"exists\":true,\"content\":\"");
            if (preload_len > 0) json_print_escaped(preload_content);
            printf("\"}");
        }
        printf("]");
    } else {
        if (ld_preload && strlen(ld_preload) > 0)
            printf("[!] LD_PRELOAD is set: %s\n", ld_preload);
        if (has_preload_file) {
            printf("[!] /etc/ld.so.preload exists");
            if (preload_len > 0) printf(": %s", preload_content);
            printf("\n");
        } else {
            printf("[+] No /etc/ld.so.preload\n");
        }
    }
}

/* ── Process scanner ─────────────────────────────────────────────────────── */

int scan_process(pid_t pid, const Config *config, int *first_json) {
    LibraryInfo *libs = NULL;
    int lib_count = get_loaded_libraries(pid, &libs, MAX_LIBRARIES, config->verbose);
    if (lib_count <= 0) { if (libs) free(libs); return -1; }

    char proc_name[256];
    get_process_name(pid, proc_name, sizeof(proc_name));

    int total_hooks = 0;
    int first_hook  = 1;

    for (int i = 0; i < lib_count; i++) {
        if (config->target_lib[0] != '\0' &&
            !strstr(libs[i].path, config->target_lib))
            continue;

        libs[i].func_count = extract_functions_from_elf(
            libs[i].path, libs[i].functions, MAX_FUNCTIONS,
            &libs[i].preferred_base, &libs[i].arch, config->verbose);

        int is_x86 = (libs[i].arch == EM_X86_64 || libs[i].arch == EM_386);
        size_t check_size = is_x86
            ? (size_t)CHECK_BYTES_X86
            : (size_t)(CHECK_INSNS * (int)sizeof(uint32_t));

        for (int j = 0; j < libs[i].func_count; j++) {
            if (libs[i].functions[j].file_offset == 0) continue;

            uint8_t disk_buf[CHECK_BYTES_X86];
            uint8_t mem_buf[CHECK_BYTES_X86];
            memset(disk_buf, 0, sizeof(disk_buf));
            memset(mem_buf,  0, sizeof(mem_buf));

            if (read_bytes(libs[i].path, libs[i].functions[j].file_offset,
                           disk_buf, check_size, config->verbose) < 0)
                continue;

            unsigned long mem_addr = libs[i].base_addr +
                (libs[i].functions[j].vaddr - libs[i].preferred_base);

            if (read_mem(pid, mem_addr, mem_buf, check_size, config->verbose) < 0)
                continue;

            if (memcmp(disk_buf, mem_buf, check_size) == 0) continue;

            HookConfidence confidence;
            if (is_x86)
                confidence = detect_hook_confidence_x86(disk_buf, mem_buf, (int)check_size);
            else
                confidence = detect_hook_confidence_arm64(
                    (const uint32_t *)disk_buf, (const uint32_t *)mem_buf);

            if (confidence == HOOK_CONFIDENCE_NONE) continue;

            if (first_hook) {
                if (config->json_output) {
                    if (!*first_json) printf(",");
                    *first_json = 0;
                    printf("{\"pid\":%d,\"name\":\"", pid);
                    json_print_escaped(proc_name);
                    printf("\",\"hooks\":[");
                } else if (config->verbose)
                    printf("\n[!] PID %d (%s):\n", pid, proc_name);
                first_hook = 0;
            }

            if (config->json_output) {
                if (total_hooks > 0) printf(",");
                printf("{\"function\":\"");
                json_print_escaped(libs[i].functions[j].name);
                printf("\",\"library\":\"");
                json_print_escaped(libs[i].short_name);
                printf("\",\"confidence\":\"%s\"}", confidence_str(confidence));
            } else if (config->verbose) {
                printf("    [HOOK] %s in %s (confidence: %s)\n",
                       libs[i].functions[j].name,
                       libs[i].short_name,
                       confidence_str(confidence));
                if (config->show_hexdump) {
                    if (is_x86) {
                        print_hexdump_bytes("Disk", disk_buf, (int)check_size);
                        print_hexdump_bytes("Mem ", mem_buf,  (int)check_size);
                    } else {
                        print_hexdump_words("Disk", (const uint32_t *)disk_buf, CHECK_INSNS);
                        print_hexdump_words("Mem ", (const uint32_t *)mem_buf,  CHECK_INSNS);
                    }
                }
            }
            total_hooks++;
        }
    }

    if (!first_hook && config->json_output) printf("]}");

    free(libs);
    return total_hooks;
}
