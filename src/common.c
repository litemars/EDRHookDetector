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

/* Is `name` a monitored function in ANY library? Used by the GOT scanner,
 * where the importing module is not the defining library, so the per-library
 * association in is_monitored_function() does not apply. */
static int is_monitored_symbol(const char *name) {
    if (!name || !name[0]) return 0;
    for (int i = 0; target_libs[i].lib_pattern != NULL; i++)
        for (int j = 0; target_libs[i].functions[j] != NULL; j++)
            if (strcmp(name, target_libs[i].functions[j]) == 0) return 1;
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

/* ── Parsed-ELF cache ────────────────────────────────────────────────────── */
/* The dynamic-symbol parse of a given library file is identical no matter
 * which process mapped it, so key the result on (st_dev, st_ino) and parse
 * each unique file just once. On a busy host this turns hundreds of repeated
 * mmap/parse/munmap cycles for the shared libc into one. */

typedef struct {
    dev_t          dev;
    ino_t          ino;
    int            func_count;
    unsigned long  preferred_base;
    int            arch;
    FunctionInfo  *funcs;          /* malloc'd: func_count entries (NULL if 0) */
} ElfCacheEnt;

static ElfCacheEnt *g_elf_cache        = NULL;
static int          g_elf_cache_n      = 0;
static int          g_elf_cache_cap    = 0;
static int          g_elf_cache_atexit = 0;

void elf_cache_free(void) {
    for (int i = 0; i < g_elf_cache_n; i++) free(g_elf_cache[i].funcs);
    free(g_elf_cache);
    g_elf_cache     = NULL;
    g_elf_cache_n   = 0;
    g_elf_cache_cap = 0;
}

static const ElfCacheEnt *elf_cache_get(dev_t dev, ino_t ino) {
    for (int i = 0; i < g_elf_cache_n; i++)
        if (g_elf_cache[i].dev == dev && g_elf_cache[i].ino == ino)
            return &g_elf_cache[i];
    return NULL;
}

static void elf_cache_put(dev_t dev, ino_t ino, const FunctionInfo *funcs,
                          int func_count, unsigned long preferred_base, int arch) {
    if (func_count < 0) return;
    if (g_elf_cache_n == g_elf_cache_cap) {
        int   newcap = g_elf_cache_cap ? g_elf_cache_cap * 2 : 16;
        void *p      = realloc(g_elf_cache, (size_t)newcap * sizeof(*g_elf_cache));
        if (!p) return;                       /* skip caching on OOM — not fatal */
        g_elf_cache     = p;
        g_elf_cache_cap = newcap;
    }
    FunctionInfo *copy = NULL;
    if (func_count > 0) {
        copy = malloc((size_t)func_count * sizeof(FunctionInfo));
        if (!copy) return;
        memcpy(copy, funcs, (size_t)func_count * sizeof(FunctionInfo));
    }
    ElfCacheEnt *e    = &g_elf_cache[g_elf_cache_n++];
    e->dev            = dev;
    e->ino            = ino;
    e->func_count     = func_count;
    e->preferred_base = preferred_base;
    e->arch           = arch;
    e->funcs          = copy;
    if (!g_elf_cache_atexit) { atexit(elf_cache_free); g_elf_cache_atexit = 1; }
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

    /* Cache hit: same file → identical parse, no need to mmap again. */
    const ElfCacheEnt *hit = elf_cache_get(st.st_dev, st.st_ino);
    if (hit) {
        close(fd);
        int n = (hit->func_count < max_funcs) ? hit->func_count : max_funcs;
        if (n > 0) memcpy(funcs, hit->funcs, (size_t)n * sizeof(FunctionInfo));
        if (preferred_base_out) *preferred_base_out = hit->preferred_base;
        if (arch_out)           *arch_out           = hit->arch;
        return n;
    }

    if ((size_t)st.st_size < EI_NIDENT + 2) { close(fd); return 0; }

    void *elf_map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (elf_map == MAP_FAILED) {
        if (verbose) fprintf(stderr, "[!] Cannot mmap %s: %s\n", lib_path, strerror(errno));
        close(fd); return 0;
    }

    int            result = 0;
    unsigned long  pbase  = 0;
    int            arch   = 0;
    const uint8_t *ident  = (const uint8_t *)elf_map;

    if (memcmp(ident, ELFMAG, SELFMAG) != 0) goto done;

    switch (ident[EI_CLASS]) {
        case ELFCLASS64:
            result = extract_elf64(elf_map, (size_t)st.st_size, lib_path,
                                   funcs, max_funcs, &pbase, &arch, verbose);
            break;
        case ELFCLASS32:
            result = extract_elf32(elf_map, (size_t)st.st_size, lib_path,
                                   funcs, max_funcs, &pbase, &arch, verbose);
            break;
        default:
            if (verbose)
                fprintf(stderr, "[!] Unknown ELF class in %s\n", lib_path);
            break;
    }

done:
    if (preferred_base_out) *preferred_base_out = pbase;
    if (arch_out)           *arch_out           = arch;
    elf_cache_put(st.st_dev, st.st_ino, funcs, result, pbase, arch);
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

int get_process_name(pid_t pid, char *name, size_t size) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (!f) { snprintf(name, size, "<unknown>"); return -1; }
    if (fgets(name, (int)size, f)) {
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
                confidence = detect_hook_confidence_x86(
                    disk_buf, mem_buf, (int)check_size,
                    libs[i].arch == EM_X86_64);
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

/* ── VDSO consistency check ──────────────────────────────────────────────── */
/* The kernel maps the same [vdso] image (gettimeofday/clock_gettime/…) into
 * every process. Its bytes are position-independent and therefore identical
 * across all processes of a given architecture. A rootkit that patches one
 * process's vdso breaks copy-on-write and leaves that process with a private,
 * modified page — which has no on-disk baseline to diff against. We catch it
 * by comparing vdso contents across processes: group by (length, hash) and
 * flag any variant that is a strict minority among same-length vdsos (same
 * length ⇒ same architecture, so a content mismatch is the tampering signal;
 * different length is just a 32- vs 64-bit process and is expected).
 *
 * Limitation: a global patch of the shared vdso (before COW) would alter every
 * process identically, leaving no minority to flag. That case needs a trusted
 * baseline and is out of scope here. CRIU-restored processes can also carry a
 * vdso proxy that legitimately differs; treat a hit as "investigate", not proof. */

#define VDSO_MAX_BYTES     (64u * 1024u)
#define VDSO_MAX_VARIANTS  32

static uint64_t fnv1a64(const uint8_t *p, size_t n) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

static int find_vdso_range(pid_t pid, unsigned long *start, unsigned long *end) {
    char maps[64];
    snprintf(maps, sizeof(maps), "/proc/%d/maps", pid);
    FILE *f = fopen(maps, "r");
    if (!f) return 0;
    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "[vdso]") && sscanf(line, "%lx-%lx", start, end) == 2) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

int scan_vdso_consistency(const Config *config) {
    if (!config->json_output)
        printf("[*] Checking VDSO consistency...\n");
    else
        printf("\"vdso\":[");

    struct vdso_variant {
        size_t   len;
        uint64_t hash;
        int      count;
        pid_t    pid;
        char     name[64];
    } var[VDSO_MAX_VARIANTS];
    int nvar    = 0;
    int scanned = 0;

    uint8_t *buf = malloc(VDSO_MAX_BYTES);
    if (!buf) { if (config->json_output) printf("]"); return 0; }

    DIR *proc = opendir("/proc");
    if (!proc) {
        free(buf);
        if (config->json_output) printf("]");
        else printf("[!] Cannot open /proc: %s\n", strerror(errno));
        return 0;
    }

    struct dirent *e;
    while ((e = readdir(proc)) != NULL) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        char *endp;
        long  v = strtol(e->d_name, &endp, 10);
        if (*endp != '\0' || v <= 0) continue;
        pid_t pid = (pid_t)v;

        unsigned long start = 0, end = 0;
        if (!find_vdso_range(pid, &start, &end) || end <= start) continue;
        size_t len = (size_t)(end - start);
        if (len == 0 || len > VDSO_MAX_BYTES) continue;
        if (read_mem(pid, start, buf, len, 0) < 0) continue;   /* perms / gone */

        scanned++;
        uint64_t h   = fnv1a64(buf, len);
        int      idx = -1;
        for (int i = 0; i < nvar; i++)
            if (var[i].len == len && var[i].hash == h) { idx = i; break; }
        if (idx < 0) {
            if (nvar >= VDSO_MAX_VARIANTS) continue;   /* implausibly many — ignore extras */
            idx = nvar++;
            var[idx].len   = len;
            var[idx].hash  = h;
            var[idx].count = 0;
            var[idx].pid   = pid;
            get_process_name(pid, var[idx].name, sizeof(var[idx].name));
        }
        var[idx].count++;
    }
    closedir(proc);
    free(buf);

    /* A variant is suspicious if another variant of the SAME length has a
     * strictly larger process count (i.e. it is the same-arch minority). */
    int flag[VDSO_MAX_VARIANTS] = {0};
    int suspicious_procs = 0;
    for (int i = 0; i < nvar; i++) {
        for (int j = 0; j < nvar; j++) {
            if (j != i && var[j].len == var[i].len && var[j].count > var[i].count) {
                flag[i] = 1;
                break;
            }
        }
        if (flag[i]) suspicious_procs += var[i].count;
    }

    if (config->json_output) {
        for (int i = 0; i < nvar; i++) {
            if (i) printf(",");
            printf("{\"len\":%zu,\"hash\":\"%016llx\",\"processes\":%d,\"example_pid\":%d,"
                   "\"example_name\":\"",
                   var[i].len, (unsigned long long)var[i].hash, var[i].count, (int)var[i].pid);
            json_print_escaped(var[i].name);
            printf("\",\"suspicious\":%s}", flag[i] ? "true" : "false");
        }
        printf("]");
    } else if (scanned == 0) {
        printf("[!] No readable VDSO mappings (need root to compare across processes)\n");
    } else if (scanned < 2) {
        printf("[*] Only 1 readable VDSO — cross-process comparison needs root\n");
    } else if (suspicious_procs == 0) {
        printf("[+] VDSO consistent across %d process(es) (%d variant%s)\n",
               scanned, nvar, nvar == 1 ? "" : "s");
    } else {
        printf("[!] VDSO inconsistency: %d process(es) differ from the same-size majority\n",
               suspicious_procs);
        for (int i = 0; i < nvar; i++)
            if (flag[i])
                printf("    hash=%016llx len=%zu on %d proc(s), e.g. PID %d (%s)\n",
                       (unsigned long long)var[i].hash, var[i].len, var[i].count,
                       (int)var[i].pid, var[i].name);
    }

    return suspicious_procs;
}

/* ── GOT / PLT hijack detection ──────────────────────────────────────────── */
/* Inline-byte diffing misses pointer-table redirection: overwriting a GOT
 * slot reroutes every call through the PLT without altering a single
 * instruction of the target function. We parse the JUMP_SLOT / GLOB_DAT
 * relocations of every file-backed module for imports of monitored functions,
 * read the live slot value from /proc/PID/mem, and flag any whose target does
 * NOT land in a legitimate executable mapping (a real library file or the
 * vdso). Lazy-bound slots point into the module's own PLT (file-backed, exec)
 * and interposers/LD_PRELOAD resolve into real .so files, so neither trips the
 * check — the signal is specifically a pointer into anonymous/injected memory. */

#ifndef R_X86_64_GLOB_DAT
#define R_X86_64_GLOB_DAT   6
#endif
#ifndef R_X86_64_JUMP_SLOT
#define R_X86_64_JUMP_SLOT  7
#endif
#ifndef R_AARCH64_GLOB_DAT
#define R_AARCH64_GLOB_DAT  1025
#endif
#ifndef R_AARCH64_JUMP_SLOT
#define R_AARCH64_JUMP_SLOT 1026
#endif
#ifndef R_386_GLOB_DAT
#define R_386_GLOB_DAT      6
#endif
#ifndef R_386_JMP_SLOT
#define R_386_JMP_SLOT      7
#endif

#define GOT_MAX_SLOTS    64       /* monitored imports tracked per module    */
#define GOT_MAX_MODULES  1024
#define GOT_MAX_REGIONS  32768

typedef struct {
    char          name[128];
    unsigned long slot_vaddr;     /* link-time vaddr of the GOT entry */
} GotSlot;

static int got64_collect(void *map, size_t sz, int machine,
                         GotSlot *out, int max_out, unsigned long *pref_base_out) {
    Elf64_Ehdr *eh = (Elf64_Ehdr *)map;
    if (eh->e_shoff + (size_t)eh->e_shnum * sizeof(Elf64_Shdr) > sz) return 0;
    Elf64_Shdr *sh = (Elf64_Shdr *)((char *)map + eh->e_shoff);

    unsigned long pbase = 0;
    if (eh->e_phoff + (size_t)eh->e_phnum * sizeof(Elf64_Phdr) <= sz) {
        Elf64_Phdr *ph = (Elf64_Phdr *)((char *)map + eh->e_phoff);
        for (int i = 0; i < eh->e_phnum; i++)
            if (ph[i].p_type == PT_LOAD) { pbase = (unsigned long)ph[i].p_vaddr; break; }
    }
    if (pref_base_out) *pref_base_out = pbase;

    unsigned long js = (machine == EM_AARCH64) ? R_AARCH64_JUMP_SLOT : R_X86_64_JUMP_SLOT;
    unsigned long gd = (machine == EM_AARCH64) ? R_AARCH64_GLOB_DAT  : R_X86_64_GLOB_DAT;

    int count = 0;
    for (int s = 0; s < eh->e_shnum && count < max_out; s++) {
        if (sh[s].sh_type != SHT_RELA)                      continue;
        if (sh[s].sh_offset + sh[s].sh_size > sz)           continue;
        if (sh[s].sh_link >= eh->e_shnum)                   continue;

        Elf64_Shdr *symsh = &sh[sh[s].sh_link];
        if (symsh->sh_type != SHT_DYNSYM && symsh->sh_type != SHT_SYMTAB) continue;
        if (symsh->sh_offset + symsh->sh_size > sz)         continue;
        if (symsh->sh_link >= eh->e_shnum)                  continue;
        Elf64_Shdr *strsh = &sh[symsh->sh_link];
        if (strsh->sh_offset + strsh->sh_size > sz)         continue;

        Elf64_Sym  *syms = (Elf64_Sym *)((char *)map + symsh->sh_offset);
        size_t      nsym = symsh->sh_size / sizeof(Elf64_Sym);
        const char *str  = (const char *)map + strsh->sh_offset;
        size_t      strn = strsh->sh_size;

        Elf64_Rela *ra = (Elf64_Rela *)((char *)map + sh[s].sh_offset);
        size_t      nr = sh[s].sh_size / sizeof(Elf64_Rela);
        for (size_t r = 0; r < nr && count < max_out; r++) {
            unsigned long type = (unsigned long)ELF64_R_TYPE(ra[r].r_info);
            if (type != js && type != gd) continue;
            uint64_t si = ELF64_R_SYM(ra[r].r_info);
            if (si == 0 || si >= nsym) continue;
            uint32_t no = syms[si].st_name;
            if (no >= strn) continue;
            const char *nm = str + no;
            if (!is_monitored_symbol(nm)) continue;
            snprintf(out[count].name, sizeof(out[count].name), "%s", nm);
            out[count].slot_vaddr = (unsigned long)ra[r].r_offset;
            count++;
        }
    }
    return count;
}

static int got32_collect(void *map, size_t sz, GotSlot *out, int max_out,
                         unsigned long *pref_base_out) {
    Elf32_Ehdr *eh = (Elf32_Ehdr *)map;
    if (eh->e_shoff + (size_t)eh->e_shnum * sizeof(Elf32_Shdr) > sz) return 0;
    Elf32_Shdr *sh = (Elf32_Shdr *)((char *)map + eh->e_shoff);

    unsigned long pbase = 0;
    if (eh->e_phoff + (size_t)eh->e_phnum * sizeof(Elf32_Phdr) <= sz) {
        Elf32_Phdr *ph = (Elf32_Phdr *)((char *)map + eh->e_phoff);
        for (int i = 0; i < eh->e_phnum; i++)
            if (ph[i].p_type == PT_LOAD) { pbase = (unsigned long)ph[i].p_vaddr; break; }
    }
    if (pref_base_out) *pref_base_out = pbase;

    int count = 0;
    for (int s = 0; s < eh->e_shnum && count < max_out; s++) {
        if (sh[s].sh_type != SHT_REL)                       continue;
        if (sh[s].sh_offset + sh[s].sh_size > sz)           continue;
        if (sh[s].sh_link >= eh->e_shnum)                   continue;

        Elf32_Shdr *symsh = &sh[sh[s].sh_link];
        if (symsh->sh_type != SHT_DYNSYM && symsh->sh_type != SHT_SYMTAB) continue;
        if (symsh->sh_offset + symsh->sh_size > sz)         continue;
        if (symsh->sh_link >= eh->e_shnum)                  continue;
        Elf32_Shdr *strsh = &sh[symsh->sh_link];
        if (strsh->sh_offset + strsh->sh_size > sz)         continue;

        Elf32_Sym  *syms = (Elf32_Sym *)((char *)map + symsh->sh_offset);
        size_t      nsym = symsh->sh_size / sizeof(Elf32_Sym);
        const char *str  = (const char *)map + strsh->sh_offset;
        size_t      strn = strsh->sh_size;

        Elf32_Rel  *re = (Elf32_Rel *)((char *)map + sh[s].sh_offset);
        size_t      nr = sh[s].sh_size / sizeof(Elf32_Rel);
        for (size_t r = 0; r < nr && count < max_out; r++) {
            unsigned int type = ELF32_R_TYPE(re[r].r_info);
            if (type != R_386_JMP_SLOT && type != R_386_GLOB_DAT) continue;
            uint32_t si = ELF32_R_SYM(re[r].r_info);
            if (si == 0 || si >= nsym) continue;
            uint32_t no = syms[si].st_name;
            if (no >= strn) continue;
            const char *nm = str + no;
            if (!is_monitored_symbol(nm)) continue;
            snprintf(out[count].name, sizeof(out[count].name), "%s", nm);
            out[count].slot_vaddr = (unsigned long)re[r].r_offset;
            count++;
        }
    }
    return count;
}

/* Open+parse a module file, returning its monitored-import GOT slots. */
static int module_gots(const char *path, GotSlot *out, int max_out,
                       int *arch_out, unsigned long *pref_out) {
    *arch_out = 0;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    struct stat st;
    if (fstat(fd, &st) < 0 || (size_t)st.st_size < EI_NIDENT + 2) { close(fd); return 0; }
    void *m = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (m == MAP_FAILED) return 0;

    int rc = 0;
    const uint8_t *id = (const uint8_t *)m;
    if (memcmp(id, ELFMAG, SELFMAG) == 0) {
        if (id[EI_CLASS] == ELFCLASS64) {
            Elf64_Ehdr *eh = (Elf64_Ehdr *)m;
            if (eh->e_machine == EM_X86_64 || eh->e_machine == EM_AARCH64) {
                *arch_out = (int)eh->e_machine;
                rc = got64_collect(m, (size_t)st.st_size, eh->e_machine, out, max_out, pref_out);
            }
        } else if (id[EI_CLASS] == ELFCLASS32) {
            Elf32_Ehdr *eh = (Elf32_Ehdr *)m;
            if (eh->e_machine == EM_386) {
                *arch_out = EM_386;
                rc = got32_collect(m, (size_t)st.st_size, out, max_out, pref_out);
            }
        }
    }
    munmap(m, (size_t)st.st_size);
    return rc;
}

typedef struct { unsigned long start, end; int legit, exec; char name[32]; } MemRegion;
typedef struct { char path[512]; unsigned long base; } GotModule;

/* Return the label of the region containing `ptr` if that region is a hijack
 * target (executable, non-file-backed code), else NULL (no finding).
 *
 * A GOT/PLT hijack redirects a call into attacker-controlled CODE, so the only
 * thing worth flagging is a pointer into an *executable* mapping that is not a
 * legitimate on-disk module. Everything else is a false positive:
 *   - unmapped / below the lowest mapping  -> lazy/unresolved or a misread slot,
 *     never a live code target;
 *   - non-executable region                -> a data pointer, not a redirection;
 *   - file-backed executable (or the vdso)  -> normal binding, lazy PLT stubs and
 *     LD_PRELOAD interposers all land here. */
static const char *classify_got_target(const MemRegion *regs, int n, unsigned long ptr) {
    for (int i = 0; i < n; i++) {
        if (ptr < regs[i].start || ptr >= regs[i].end) continue;
        if (!regs[i].exec)  return NULL;   /* not executable -> not a code hook   */
        if (regs[i].legit)  return NULL;   /* real module / vdso -> legit target  */
        return regs[i].name[0] ? regs[i].name : "anon-exec";
    }
    return NULL;   /* unmapped -> not a resolved call target, not a hook */
}

static void basename_into(char *dst, size_t dsz, const char *path) {
    const char *b = strrchr(path, '/');
    snprintf(dst, dsz, "%s", b ? b + 1 : path);
}

static int scan_got_for_pid(pid_t pid, const Config *config, int *first_json) {
    char maps[64];
    snprintf(maps, sizeof(maps), "/proc/%d/maps", pid);
    FILE *f = fopen(maps, "r");
    if (!f) return 0;

    MemRegion *regs = malloc((size_t)GOT_MAX_REGIONS * sizeof(*regs));
    GotModule *mods = malloc((size_t)GOT_MAX_MODULES * sizeof(*mods));
    if (!regs || !mods) { free(regs); free(mods); fclose(f); return 0; }
    int nreg = 0, nmod = 0;

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        unsigned long start, end, off;
        char perms[5] = {0}, path[512] = {0};
        int p = sscanf(line, "%lx-%lx %4s %lx %*s %*s %511s",
                       &start, &end, perms, &off, path);
        if (p < 4 || end <= start) continue;
        int has_path = (p == 5 && path[0]);
        int exec     = (perms[2] == 'x');

        if (nreg < GOT_MAX_REGIONS) {
            regs[nreg].start = start;
            regs[nreg].end   = end;
            regs[nreg].exec  = exec;
            regs[nreg].legit = has_path &&
                               (path[0] == '/' ||
                                strcmp(path, "[vdso]") == 0 ||
                                strcmp(path, "[vsyscall]") == 0);
            if (has_path) basename_into(regs[nreg].name, sizeof(regs[nreg].name), path);
            else          snprintf(regs[nreg].name, sizeof(regs[nreg].name), "anon");
            nreg++;
        }

        if (has_path && off == 0 && path[0] == '/' && nmod < GOT_MAX_MODULES) {
            int dup = 0;
            for (int i = 0; i < nmod; i++)
                if (strcmp(mods[i].path, path) == 0) { dup = 1; break; }
            if (!dup) {
                snprintf(mods[nmod].path, sizeof(mods[nmod].path), "%s", path);
                mods[nmod].base = start;
                nmod++;
            }
        }
    }
    fclose(f);

    int  found = 0;
    char proc_name[256];
    int  have_name = 0;
    GotSlot slots[GOT_MAX_SLOTS];

    for (int m = 0; m < nmod; m++) {
        int           arch  = 0;
        unsigned long pref  = 0;
        int           nslot = module_gots(mods[m].path, slots, GOT_MAX_SLOTS, &arch, &pref);
        if (nslot <= 0) continue;
        int ptrsize = (arch == EM_386) ? 4 : 8;

        for (int k = 0; k < nslot; k++) {
            unsigned long addr = mods[m].base + (slots[k].slot_vaddr - pref);
            unsigned long ptr  = 0;
            if (ptrsize == 4) {
                uint32_t t;
                if (read_mem(pid, addr, &t, sizeof(t), 0) < 0) continue;
                ptr = t;
            } else {
                uint64_t t;
                if (read_mem(pid, addr, &t, sizeof(t), 0) < 0) continue;
                ptr = (unsigned long)t;
            }
            if (ptr == 0) continue;     /* unbound weak symbol — not a hook */

            const char *label = classify_got_target(regs, nreg, ptr);
            if (!label) continue;

            if (!have_name) { get_process_name(pid, proc_name, sizeof(proc_name)); have_name = 1; }

            char modbase[64];
            basename_into(modbase, sizeof(modbase), mods[m].path);

            if (config->json_output) {
                if (!*first_json) printf(",");
                *first_json = 0;
                printf("{\"pid\":%d,\"name\":\"", pid);
                json_print_escaped(proc_name);
                printf("\",\"function\":\"");
                json_print_escaped(slots[k].name);
                printf("\",\"module\":\"");
                json_print_escaped(modbase);
                printf("\",\"target\":\"0x%lx\",\"location\":\"", ptr);
                json_print_escaped(label);
                printf("\"}");
            } else {
                printf("  [GOT] PID %d (%s): %s in %s -> 0x%lx (%s)\n",
                       pid, proc_name, slots[k].name, modbase, ptr, label);
            }
            found++;
        }
    }

    free(regs);
    free(mods);
    return found;
}

int scan_got_hijacks(const Config *config) {
    if (!config->json_output)
        printf("[*] Scanning GOT/PLT for hijacks...\n");
    else
        printf("\"got_hijacks\":[");

    int first_json = 1;
    int total      = 0;

    if (config->target_pid != 0) {
        total += scan_got_for_pid(config->target_pid, config, &first_json);
    } else {
        DIR *proc = opendir("/proc");
        if (proc) {
            struct dirent *e;
            while ((e = readdir(proc)) != NULL) {
                if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
                char *endp;
                long  v = strtol(e->d_name, &endp, 10);
                if (*endp != '\0' || v <= 0) continue;
                total += scan_got_for_pid((pid_t)v, config, &first_json);
            }
            closedir(proc);
        }
    }

    if (config->json_output)
        printf("]");
    else if (total == 0)
        printf("[+] No GOT/PLT hijacks detected\n");
    else
        printf("    %d GOT/PLT hijack(s) detected — investigate\n", total);

    return total;
}
