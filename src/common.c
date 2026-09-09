#define _GNU_SOURCE
#include "common.h"
#include "arch_arm64.h"
#include "arch_x86.h"
#include "elf_validation.h"
#include <inttypes.h>
#include <limits.h>
#include <sys/types.h>
#ifdef __linux__
#include <sys/sysmacros.h>
#endif

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

/* Match symbols independently of the filename used to open the ELF. A
 * map_files handle has no library basename, and glibc >= 2.34 exports the
 * former libpthread/libdl functions from libc. Library selection happens in
 * get_loaded_libraries; the cached parse is identical for every path alias. */
static int is_monitored_symbol(const char *name) {
    if (!name || !name[0]) return 0;
    for (int i = 0; target_libs[i].lib_pattern != NULL; i++)
        for (int j = 0; target_libs[i].functions[j] != NULL; j++)
            if (strcmp(name, target_libs[i].functions[j]) == 0) return 1;
    return 0;
}

static int range_in_file(size_t file_size, uint64_t offset, uint64_t length) {
    return offset <= file_size && length <= (uint64_t)file_size - offset;
}

/* This parser requires section tables. Sectionless/extended-numbering ELFs
 * are unsupported, not evidence of zero symbols or zero relocations. */
static int valid_elf64_header(const Elf64_Ehdr *ehdr, size_t map_size) {
    return map_size >= sizeof(*ehdr) &&
           ehdr->e_ident[EI_DATA] == ELFDATA2LSB &&
           ehdr->e_ident[EI_VERSION] == EV_CURRENT &&
           ehdr->e_version == EV_CURRENT &&
           ehdr->e_ehsize == sizeof(*ehdr) &&
           ehdr->e_phentsize == sizeof(Elf64_Phdr) &&
           ehdr->e_shentsize == sizeof(Elf64_Shdr) &&
           ehdr->e_phnum != 0 && ehdr->e_phnum != PN_XNUM && ehdr->e_phoff != 0 &&
           ehdr->e_shnum != 0 && ehdr->e_shoff != 0 &&
           ehdr->e_phoff % _Alignof(Elf64_Phdr) == 0 &&
           ehdr->e_shoff % _Alignof(Elf64_Shdr) == 0 &&
           range_in_file(map_size, ehdr->e_phoff,
                         (uint64_t)ehdr->e_phnum * sizeof(Elf64_Phdr)) &&
           range_in_file(map_size, ehdr->e_shoff,
                         (uint64_t)ehdr->e_shnum * sizeof(Elf64_Shdr));
}

static int valid_elf32_header(const Elf32_Ehdr *ehdr, size_t map_size) {
    return map_size >= sizeof(*ehdr) &&
           ehdr->e_ident[EI_DATA] == ELFDATA2LSB &&
           ehdr->e_ident[EI_VERSION] == EV_CURRENT &&
           ehdr->e_version == EV_CURRENT &&
           ehdr->e_ehsize == sizeof(*ehdr) &&
           ehdr->e_phentsize == sizeof(Elf32_Phdr) &&
           ehdr->e_shentsize == sizeof(Elf32_Shdr) &&
           ehdr->e_phnum != 0 && ehdr->e_phnum != PN_XNUM && ehdr->e_phoff != 0 &&
           ehdr->e_shnum != 0 && ehdr->e_shoff != 0 &&
           ehdr->e_phoff % _Alignof(Elf32_Phdr) == 0 &&
           ehdr->e_shoff % _Alignof(Elf32_Shdr) == 0 &&
           range_in_file(map_size, ehdr->e_phoff,
                         (uint64_t)ehdr->e_phnum * sizeof(Elf32_Phdr)) &&
           range_in_file(map_size, ehdr->e_shoff,
                         (uint64_t)ehdr->e_shnum * sizeof(Elf32_Shdr));
}

/* ELF64: virtual address → file offset */
static int vaddr_to_offset64(void *elf_map, size_t map_size,
                              uint64_t vaddr, unsigned long *off_out,
                              unsigned long *preferred_base_out) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_map;
    if (!valid_elf64_header(ehdr, map_size) ||
        !range_in_file(map_size, ehdr->e_phoff,
                       (uint64_t)ehdr->e_phnum * sizeof(Elf64_Phdr)))
        return -1;
    Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)elf_map + ehdr->e_phoff);
    unsigned long pbase = (unsigned long)-1;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD) continue;
        if (pbase == (unsigned long)-1) pbase = (unsigned long)phdr[i].p_vaddr;
        if (vaddr >= phdr[i].p_vaddr && vaddr - phdr[i].p_vaddr < phdr[i].p_filesz) {
            uint64_t file_offset = phdr[i].p_offset + (vaddr - phdr[i].p_vaddr);
            if (file_offset < phdr[i].p_offset || !range_in_file(map_size, file_offset, 1))
                return -1;
            *off_out = (unsigned long)file_offset;
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
    if (!valid_elf32_header(ehdr, map_size) ||
        !range_in_file(map_size, ehdr->e_phoff,
                       (uint64_t)ehdr->e_phnum * sizeof(Elf32_Phdr)))
        return -1;
    Elf32_Phdr *phdr = (Elf32_Phdr *)((char *)elf_map + ehdr->e_phoff);
    unsigned long pbase = (unsigned long)-1;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD) continue;
        if (pbase == (unsigned long)-1) pbase = (unsigned long)phdr[i].p_vaddr;
        if (vaddr >= phdr[i].p_vaddr && vaddr - phdr[i].p_vaddr < phdr[i].p_filesz) {
            uint64_t file_offset = phdr[i].p_offset + (vaddr - phdr[i].p_vaddr);
            if (file_offset < phdr[i].p_offset || !range_in_file(map_size, file_offset, 1))
                return -1;
            *off_out = (unsigned long)file_offset;
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
                          int verbose, int *truncated) {
    *truncated = 0;
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_map;

    if (!valid_elf64_header(ehdr, map_size) ||
        !elf_runtime_symbols_supported(elf_map, map_size, 1)) {
        if (verbose) fprintf(stderr, "[!] Unsupported or invalid ELF headers in %s (section tables required)\n", lib_path);
        return -1;
    }

    if (ehdr->e_machine != EM_AARCH64 && ehdr->e_machine != EM_X86_64) {
        if (verbose)
            fprintf(stderr, "[!] Unsupported ELF64 machine type %d in %s\n",
                    ehdr->e_machine, lib_path);
        return -1;
    }
    if (arch_out) *arch_out = (int)ehdr->e_machine;

    if (!range_in_file(map_size, ehdr->e_shoff,
                       (uint64_t)ehdr->e_shnum * sizeof(Elf64_Shdr))) {
        if (verbose) fprintf(stderr, "[!] Invalid section headers in %s\n", lib_path);
        return -1;
    }

    /* Preferred base from first PT_LOAD */
    unsigned long pbase = 0;
    if (range_in_file(map_size, ehdr->e_phoff,
                      (uint64_t)ehdr->e_phnum * sizeof(Elf64_Phdr))) {
        Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)elf_map + ehdr->e_phoff);
        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == PT_LOAD) { pbase = (unsigned long)phdr[i].p_vaddr; break; }
        }
    }
    if (preferred_base_out) *preferred_base_out = pbase;

    Elf64_Shdr *shdr = (Elf64_Shdr *)((char *)elf_map + ehdr->e_shoff);
    int func_count = 0;
    int have_dynsym = 0;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_type != SHT_DYNSYM) continue;
        have_dynsym = 1;
        if (!range_in_file(map_size, shdr[i].sh_offset, shdr[i].sh_size) ||
            shdr[i].sh_offset % _Alignof(Elf64_Sym) != 0 ||
            shdr[i].sh_entsize != sizeof(Elf64_Sym) ||
            shdr[i].sh_size % sizeof(Elf64_Sym) != 0 ||
            shdr[i].sh_link >= ehdr->e_shnum) return -1;

        Elf64_Sym  *symtab     = (Elf64_Sym *)((char *)elf_map + shdr[i].sh_offset);
        size_t      sym_count  = shdr[i].sh_size / sizeof(Elf64_Sym);
        Elf64_Shdr *strtab_sh  = &shdr[shdr[i].sh_link];
        if (strtab_sh->sh_type != SHT_STRTAB ||
            !range_in_file(map_size, strtab_sh->sh_offset, strtab_sh->sh_size)) return -1;
        char *strtab = (char *)elf_map + strtab_sh->sh_offset;

        for (size_t j = 0; j < sym_count; j++) {
            unsigned char st = ELF64_ST_TYPE(symtab[j].st_info);
            if (st == STT_GNU_IFUNC) continue;
            if (st != STT_FUNC)      continue;
            if (symtab[j].st_value == 0 || symtab[j].st_shndx == SHN_UNDEF) continue;
            if (symtab[j].st_name >= strtab_sh->sh_size) return -1;

            const char *name = strtab + symtab[j].st_name;
            if (!memchr(name, '\0', strtab_sh->sh_size - symtab[j].st_name)) return -1;
            if (!is_monitored_symbol(name)) continue;
            if (func_count >= max_funcs) { *truncated = 1; continue; }

            snprintf(funcs[func_count].name, sizeof(funcs[func_count].name), "%s", name);
            funcs[func_count].vaddr = (unsigned long)symtab[j].st_value;

            unsigned long file_off = 0;
            if (vaddr_to_offset64(elf_map, map_size, symtab[j].st_value, &file_off, NULL) < 0 ||
                file_off == 0) return -1;
            funcs[func_count].file_offset = file_off;
            func_count++;
        }
        break; /* only one SHT_DYNSYM section */
    }
    return have_dynsym ? func_count : -1;
}

/* Parse the dynamic symbol table of an already-mapped ELF32 binary. */
static int extract_elf32(void *elf_map, size_t map_size, const char *lib_path,
                          FunctionInfo *funcs, int max_funcs,
                          unsigned long *preferred_base_out, int *arch_out,
                          int verbose, int *truncated) {
    *truncated = 0;
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)elf_map;

    if (!valid_elf32_header(ehdr, map_size) ||
        !elf_runtime_symbols_supported(elf_map, map_size, 0)) {
        if (verbose) fprintf(stderr, "[!] Unsupported or invalid ELF headers in %s (section tables required)\n", lib_path);
        return -1;
    }

    if (ehdr->e_machine != EM_386) {
        if (verbose)
            fprintf(stderr, "[!] Unsupported ELF32 machine type %d in %s\n",
                    ehdr->e_machine, lib_path);
        return -1;
    }
    if (arch_out) *arch_out = (int)ehdr->e_machine;

    if (!range_in_file(map_size, ehdr->e_shoff,
                       (uint64_t)ehdr->e_shnum * sizeof(Elf32_Shdr))) {
        if (verbose) fprintf(stderr, "[!] Invalid section headers in %s\n", lib_path);
        return -1;
    }

    /* Preferred base from first PT_LOAD */
    unsigned long pbase = 0;
    if (range_in_file(map_size, ehdr->e_phoff,
                      (uint64_t)ehdr->e_phnum * sizeof(Elf32_Phdr))) {
        Elf32_Phdr *phdr = (Elf32_Phdr *)((char *)elf_map + ehdr->e_phoff);
        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == PT_LOAD) { pbase = (unsigned long)phdr[i].p_vaddr; break; }
        }
    }
    if (preferred_base_out) *preferred_base_out = pbase;

    Elf32_Shdr *shdr = (Elf32_Shdr *)((char *)elf_map + ehdr->e_shoff);
    int func_count = 0;
    int have_dynsym = 0;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_type != SHT_DYNSYM) continue;
        have_dynsym = 1;
        if (!range_in_file(map_size, shdr[i].sh_offset, shdr[i].sh_size) ||
            shdr[i].sh_offset % _Alignof(Elf32_Sym) != 0 ||
            shdr[i].sh_entsize != sizeof(Elf32_Sym) ||
            shdr[i].sh_size % sizeof(Elf32_Sym) != 0 ||
            shdr[i].sh_link >= ehdr->e_shnum) return -1;

        Elf32_Sym  *symtab    = (Elf32_Sym *)((char *)elf_map + shdr[i].sh_offset);
        size_t      sym_count = shdr[i].sh_size / sizeof(Elf32_Sym);
        Elf32_Shdr *strtab_sh = &shdr[shdr[i].sh_link];
        if (strtab_sh->sh_type != SHT_STRTAB ||
            !range_in_file(map_size, strtab_sh->sh_offset, strtab_sh->sh_size)) return -1;
        char *strtab = (char *)elf_map + strtab_sh->sh_offset;

        for (size_t j = 0; j < sym_count; j++) {
            unsigned char st = ELF32_ST_TYPE(symtab[j].st_info);
            if (st == STT_GNU_IFUNC) continue;
            if (st != STT_FUNC)      continue;
            if (symtab[j].st_value == 0 || symtab[j].st_shndx == SHN_UNDEF) continue;
            if (symtab[j].st_name >= strtab_sh->sh_size) return -1;

            const char *name = strtab + symtab[j].st_name;
            if (!memchr(name, '\0', strtab_sh->sh_size - symtab[j].st_name)) return -1;
            if (!is_monitored_symbol(name)) continue;
            if (func_count >= max_funcs) { *truncated = 1; continue; }

            snprintf(funcs[func_count].name, sizeof(funcs[func_count].name), "%s", name);
            funcs[func_count].vaddr = (unsigned long)symtab[j].st_value;

            unsigned long file_off = 0;
            if (vaddr_to_offset32(elf_map, map_size, symtab[j].st_value, &file_off, NULL) < 0 ||
                file_off == 0) return -1;
            funcs[func_count].file_offset = file_off;
            func_count++;
        }
        break;
    }
    return have_dynsym ? func_count : -1;
}

/* ── Parsed-ELF cache ────────────────────────────────────────────────────── */
/* Dynamic-symbol parses are keyed on (st_dev, st_ino) so each library file is
 * parsed once regardless of how many processes map it. */

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

static int extract_functions_from_fd(int fd, const char *lib_path, FunctionInfo *funcs,
                                int max_funcs, unsigned long *preferred_base_out,
                                int *arch_out, int verbose, int *truncated) {
    if (arch_out) *arch_out = 0;
    *truncated = 0;

    struct stat st;
    if (fstat(fd, &st) < 0) {
        if (verbose) fprintf(stderr, "[!] Cannot stat %s: %s\n", lib_path, strerror(errno));
        return -1;
    }

    /* Cache hit: same file → identical parse, no need to mmap again. */
    const ElfCacheEnt *hit = elf_cache_get(st.st_dev, st.st_ino);
    if (hit) {
        int n = (hit->func_count < max_funcs) ? hit->func_count : max_funcs;
        *truncated = hit->func_count > max_funcs;
        if (n > 0) memcpy(funcs, hit->funcs, (size_t)n * sizeof(FunctionInfo));
        if (preferred_base_out) *preferred_base_out = hit->preferred_base;
        if (arch_out)           *arch_out           = hit->arch;
        return n;
    }

    if (st.st_size < 0 || (uintmax_t)st.st_size > SIZE_MAX ||
        (size_t)st.st_size < EI_NIDENT) { return -1; }

    void *elf_map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (elf_map == MAP_FAILED) {
        if (verbose) fprintf(stderr, "[!] Cannot mmap %s: %s\n", lib_path, strerror(errno));
        return -1;
    }

    int            result = -1;
    unsigned long  pbase  = 0;
    int            arch   = 0;
    const uint8_t *ident  = (const uint8_t *)elf_map;

    if (memcmp(ident, ELFMAG, SELFMAG) != 0) goto done;

    switch (ident[EI_CLASS]) {
        case ELFCLASS64:
            if ((size_t)st.st_size < sizeof(Elf64_Ehdr)) break;
            result = extract_elf64(elf_map, (size_t)st.st_size, lib_path,
                                   funcs, max_funcs, &pbase, &arch, verbose, truncated);
            break;
        case ELFCLASS32:
            if ((size_t)st.st_size < sizeof(Elf32_Ehdr)) break;
            result = extract_elf32(elf_map, (size_t)st.st_size, lib_path,
                                   funcs, max_funcs, &pbase, &arch, verbose, truncated);
            break;
        default:
            if (verbose)
                fprintf(stderr, "[!] Unknown ELF class in %s\n", lib_path);
            break;
    }

done:
    if (preferred_base_out) *preferred_base_out = pbase;
    if (arch_out)           *arch_out           = arch;
    if (!*truncated) elf_cache_put(st.st_dev, st.st_ino, funcs, result, pbase, arch);
    munmap(elf_map, (size_t)st.st_size);
    return result;
}

int extract_functions_from_elf(const char *lib_path, FunctionInfo *funcs,
                                int max_funcs, unsigned long *preferred_base_out,
                                int *arch_out, int verbose) {
    int fd = open(lib_path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) { if (arch_out) *arch_out = 0; return -1; }
    int truncated = 0;
    int result = extract_functions_from_fd(fd, lib_path, funcs, max_funcs,
                                           preferred_base_out, arch_out, verbose, &truncated);
    close(fd);
    return truncated ? -1 : result;
}

/* ── Process / memory helpers ────────────────────────────────────────────── */

/* Parse the pathname as the entire remainder of a maps record. Numeric fields
 * are bounded before conversion; malformed/overlong records are unavailable,
 * never a truncated path that could select another baseline. */
typedef struct {
    unsigned long start, end, offset;
    unsigned int dev_major, dev_minor;
    uintmax_t inode;
    char perms[5];
    char path[512];
} ProcMapEntry;

static int maps_number(const char **cursor, int base, uintmax_t max,
                       uintmax_t *value) {
    const char *s = *cursor;
    if (!((*s >= '0' && *s <= '9') ||
          (base == 16 && ((*s >= 'a' && *s <= 'f') || (*s >= 'A' && *s <= 'F')))))
        return 0;
    errno = 0;
    char *end;
    uintmax_t n = strtoumax(s, &end, base);
    if (errno || end == s || n > max) return 0;
    *cursor = end; *value = n;
    return 1;
}

static int maps_space(const char **cursor) {
    if (**cursor != ' ' && **cursor != '\t') return 0;
    do { (*cursor)++; } while (**cursor == ' ' || **cursor == '\t');
    return 1;
}

static int parse_proc_maps_line(const char *line, ProcMapEntry *entry) {
    memset(entry, 0, sizeof(*entry));
    const char *p = line;
    uintmax_t start, end, offset, major_n, minor_n, inode;
    if (!maps_number(&p, 16, ULONG_MAX, &start) || *p++ != '-' ||
        !maps_number(&p, 16, ULONG_MAX, &end) || end <= start || !maps_space(&p)) return -1;
    if (strlen(p) < 5 || (p[0] != 'r' && p[0] != '-') ||
        (p[1] != 'w' && p[1] != '-') || (p[2] != 'x' && p[2] != '-') ||
        (p[3] != 'p' && p[3] != 's')) return -1;
    memcpy(entry->perms, p, 4); p += 4;
    if (!maps_space(&p) || !maps_number(&p, 16, ULONG_MAX, &offset) || !maps_space(&p) ||
        !maps_number(&p, 16, UINT_MAX, &major_n) || *p++ != ':' ||
        !maps_number(&p, 16, UINT_MAX, &minor_n) || !maps_space(&p) ||
        !maps_number(&p, 10, UINTMAX_MAX, &inode)) return -1;
    if (*p && *p != '\n' && !maps_space(&p)) return -1;
    size_t len = strlen(p);
    if (len && p[len - 1] == '\n') len--;
    if (len >= sizeof(entry->path) || memchr(p, '\n', len)) return -1;
    memcpy(entry->path, p, len);
    entry->path[len] = '\0';
    entry->start = (unsigned long)start; entry->end = (unsigned long)end;
    entry->offset = (unsigned long)offset;
    entry->dev_major = (unsigned int)major_n; entry->dev_minor = (unsigned int)minor_n;
    entry->inode = inode;
    return 1;
}

static int backing_matches(int fd, unsigned int dev_major, unsigned int dev_minor,
                           uintmax_t inode) {
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && inode != 0 &&
           (uintmax_t)st.st_ino == inode &&
           (uintmax_t)major(st.st_dev) == dev_major &&
           (uintmax_t)minor(st.st_dev) == dev_minor;
}

/* Open the map itself first, then a target-root path only if its device/inode
 * still identify that mapping. Retain the returned descriptor for parsing and
 * byte comparison so pathname replacement cannot switch baselines mid-scan. */
static int open_backing_file(pid_t pid, unsigned long start, unsigned long end,
                             unsigned int dev_major, unsigned int dev_minor,
                             uintmax_t inode, const char *raw) {
    char path[640];
    snprintf(path, sizeof(path), "/proc/%d/map_files/%lx-%lx", pid, start, end);
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd >= 0) {
        if (backing_matches(fd, dev_major, dev_minor, inode)) return fd;
        close(fd);
    }
    size_t len = strlen(raw);
    if (raw[0] != '/' || (len >= 10 && !strcmp(raw + len - 10, " (deleted)"))) return -1;
    /* The kernel escapes newline as \012 in maps, indistinguishable from those
     * four literal filename characters. Without map_files, do not guess. */
    if (strstr(raw, "\\012")) return -1;
    int n = snprintf(path, sizeof(path), "/proc/%d/root%s", pid, raw);
    if (n < 0 || (size_t)n >= sizeof(path)) return -1;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return -1;
    if (backing_matches(fd, dev_major, dev_minor, inode)) return fd;
    close(fd);
    return -1;
}

#define INSTANCE_MAX_MAPS 32768

/* Keep file-offset provenance for every segment, including RELRO splits and
 * offset-zero views of later PT_LOAD segments. Partial inventories remain
 * usable, but cannot establish complete process coverage. */
static int read_instance_maps(pid_t pid, ProcMapEntry **out, int *incomplete) {
    *out = NULL;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t capacity = 32;
    ProcMapEntry *maps = malloc(capacity * sizeof(*maps));
    if (!maps) { fclose(f); return -1; }
    char *line = NULL;
    size_t line_capacity = 0;
    ssize_t length;
    int count = 0;
    while ((length = getline(&line, &line_capacity, f)) >= 0) {
        ProcMapEntry entry;
        if (memchr(line, '\0', (size_t)length) || parse_proc_maps_line(line, &entry) < 0) {
            if (incomplete) *incomplete = 1;
            continue;
        }
        if (count == INSTANCE_MAX_MAPS) {
            if (incomplete) *incomplete = 1;
            continue;
        }
        if ((size_t)count == capacity) {
            size_t next_capacity = capacity * 2;
            ProcMapEntry *next = realloc(maps, next_capacity * sizeof(*maps));
            if (!next) {
                if (incomplete) *incomplete = 1;
                break;
            }
            maps = next;
            capacity = next_capacity;
        }
        maps[count++] = entry;
    }
    if (!feof(f) && incomplete) *incomplete = 1;
    free(line);
    fclose(f);
    *out = maps;
    return count;
}

static int same_map_file(const ProcMapEntry *a, const ProcMapEntry *b) {
    return a->inode != 0 && a->inode == b->inode &&
           a->dev_major == b->dev_major && a->dev_minor == b->dev_minor;
}

static int maps_cover_file_bytes(const ProcMapEntry *maps, int count,
                                 const ProcMapEntry *file, uint64_t address,
                                 uint64_t offset, uint64_t length) {
    if (address > ULONG_MAX || length > ULONG_MAX - address ||
        length > UINT64_MAX - offset) return 0;
    while (length) {
        uint64_t covered = 0;
        for (int i = 0; i < count; i++) {
            if (!same_map_file(file, &maps[i]) || address < maps[i].start ||
                address >= maps[i].end) continue;
            uint64_t delta = address - maps[i].start;
            if (delta > UINT64_MAX - maps[i].offset || maps[i].offset + delta != offset)
                continue;
            covered = maps[i].end - address;
            if (covered > length) covered = length;
            break;
        }
        if (!covered) return 0;
        address += covered;
        offset += covered;
        length -= covered;
    }
    return 1;
}

typedef struct {
    void *image;
    size_t size;
    struct elf_reloc_view view;
    unsigned long anchor_address, base;
    uint64_t anchor_vaddr;
    const ProcMapEntry *maps;
    int map_count;
    ProcMapEntry file;
} ElfInstance;

typedef struct {
    unsigned int dev_major, dev_minor;
    uintmax_t inode;
    unsigned long base;
} InstanceKey;

static int instance_already_seen(InstanceKey *seen, int *count,
                                 const ProcMapEntry *map, unsigned long base) {
    for (int i = 0; i < *count; i++)
        if (seen[i].inode == map->inode && seen[i].dev_major == map->dev_major &&
            seen[i].dev_minor == map->dev_minor && seen[i].base == base) return 1;
    seen[*count] = (InstanceKey){map->dev_major, map->dev_minor, map->inode, base};
    (*count)++;
    return 0;
}

/* Translate relative to a proven pair of virtual/runtime anchors. The load
 * displacement can be negative when a DSO is placed below its link address. */
static int instance_translate(uint64_t anchor_vaddr, unsigned long anchor_address,
                               uint64_t vaddr, uint64_t length, unsigned long *out) {
    unsigned long address;
    if (vaddr >= anchor_vaddr) {
        uint64_t delta = vaddr - anchor_vaddr;
        if (delta > ULONG_MAX - anchor_address) return 0;
        address = anchor_address + (unsigned long)delta;
    } else {
        uint64_t delta = anchor_vaddr - vaddr;
        if (delta > anchor_address) return 0;
        address = anchor_address - (unsigned long)delta;
    }
    if (length > ULONG_MAX - address) return 0;
    *out = address;
    return 1;
}

static int instance_segments_match(const struct elf_reloc_view *view,
                                   const ProcMapEntry *file,
                                   const ProcMapEntry *maps, int count,
                                   uint64_t anchor_vaddr, unsigned long anchor_address, uint64_t page_size) {
    int loads = 0;
    for (unsigned int i = 0; i < view->phnum; i++) {
        Elf64_Phdr p = elf_reloc_phdr(view, i);
        if (p.p_type != PT_LOAD) continue;
        unsigned long address;
        if (p.p_filesz > p.p_memsz || p.p_vaddr % page_size != p.p_offset % page_size ||
            !elf_reloc_range(view->size, p.p_offset, p.p_filesz) ||
            !instance_translate(anchor_vaddr, anchor_address, p.p_vaddr, p.p_memsz, &address))
            return 0;
        if (!p.p_filesz) continue;
        loads++;
        if (!maps_cover_file_bytes(maps, count, file, address,
                                    p.p_offset, p.p_filesz)) return 0;
    }
    return loads > 0;
}

/* A small shared-object data segment can map file page zero again, far from
 * its text segment. Resolve each candidate through all PT_LOAD byte ranges;
 * raw maps.start is not itself a module base. Exactly one proven bias is
 * required; device/inode+canonical first-LOAD address distinguishes dlmopen instances. */
static int open_elf_instance(int fd, const ProcMapEntry *candidate,
                             const ProcMapEntry *maps, int count, ElfInstance *out) {
    memset(out, 0, sizeof(*out));
    struct stat st;
    if (candidate->offset != 0 || fstat(fd, &st) < 0 || st.st_size < EI_NIDENT ||
        (uintmax_t)st.st_size > SIZE_MAX) return 0;
    size_t size = (size_t)st.st_size;
    void *image = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (image == MAP_FAILED) return 0;
    const unsigned char *ident = image;
    int is64 = ident[EI_CLASS] == ELFCLASS64;
    int valid = !memcmp(ident, ELFMAG, SELFMAG) &&
        ((is64 && valid_elf64_header(image, size)) ||
         (ident[EI_CLASS] == ELFCLASS32 && valid_elf32_header(image, size)));
    long page = sysconf(_SC_PAGESIZE);
    if (!valid || page <= 0) { munmap(image, size); return 0; }
    uint64_t page_size = (uint64_t)page;
    struct elf_reloc_view view = elf_runtime_view(image, size, is64);
    uint64_t first_page = 0, selected_anchor = 0;
    unsigned long selected_base = 0;
    int have_first = 0, found = 0;
    for (unsigned int i = 0; i < view.phnum; i++) {
        Elf64_Phdr p = elf_reloc_phdr(&view, i);
        if (p.p_type != PT_LOAD) continue;
        uint64_t virtual_page = p.p_vaddr - p.p_vaddr % page_size;
        if (!have_first) { first_page = virtual_page; have_first = 1; }
        if (!p.p_filesz || p.p_offset >= page_size) continue;
        unsigned long base;
        if (!instance_segments_match(&view, candidate, maps, count, virtual_page,
                                      candidate->start, page_size) ||
            !instance_translate(virtual_page, candidate->start, first_page, 0, &base)) continue;
        if (found && selected_base != base) { munmap(image, size); return 0; }
        selected_base = base;
        selected_anchor = virtual_page;
        found = 1;
    }
    if (!found) { munmap(image, size); return 0; }
    out->image = image;
    out->size = size;
    out->view = view;
    out->anchor_vaddr = selected_anchor;
    out->anchor_address = candidate->start;
    out->base = selected_base;
    out->maps = maps;
    out->map_count = count;
    out->file = *candidate;
    return 1;
}

static int instance_zero_fill_mapped(const ElfInstance *instance, uint64_t address,
                                     uint64_t offset, uint64_t length) {
    if (length > UINT64_MAX - offset) return 0;
    while (length) {
        uint64_t covered = 0;
        for (int i = 0; i < instance->map_count; i++) {
            const ProcMapEntry *map = &instance->maps[i];
            if (address < map->start || address >= map->end) continue;
            uint64_t delta = address - map->start;
            int anonymous = map->inode == 0 &&
                (!map->path[0] || !strncmp(map->path, "[anon:", 6) || !strcmp(map->path, "[heap]"));
            int same_file = same_map_file(&instance->file, map) &&
                delta <= UINT64_MAX - map->offset && map->offset + delta == offset;
            if (!anonymous && !same_file) continue;
            covered = map->end - address;
            if (covered > length) covered = length;
            break;
        }
        if (!covered) return 0;
        address += covered; offset += covered; length -= covered;
    }
    return 1;
}

/* Inline comparisons need on-disk bytes. Relocation storage can also occupy
 * the verified segment's zero-fill tail, whose current mapping is checked. */
static int instance_address(const ElfInstance *instance, uint64_t vaddr,
                             uint64_t length, const unsigned long *file_offset,
                             unsigned long *address) {
    unsigned long runtime_address;
    if (!instance_translate(instance->anchor_vaddr, instance->anchor_address,
                             vaddr, length, &runtime_address)) return 0;
    for (unsigned int i = 0; i < instance->view.phnum; i++) {
        Elf64_Phdr p = elf_reloc_phdr(&instance->view, i);
        if (p.p_type != PT_LOAD || vaddr < p.p_vaddr) continue;
        uint64_t delta = vaddr - p.p_vaddr;
        uint64_t limit = file_offset ? p.p_filesz : p.p_memsz;
        if (delta > limit || length > limit - delta || delta > UINT64_MAX - p.p_offset) continue;
        if (file_offset) {
            if (*file_offset != p.p_offset + delta) continue;
        } else if (delta + length > p.p_filesz) {
            uint64_t file_prefix = delta < p.p_filesz ? p.p_filesz - delta : 0;
            if (!instance_zero_fill_mapped(instance, runtime_address + file_prefix,
                                           p.p_offset + delta + file_prefix, length - file_prefix))
                continue;
        }
        *address = runtime_address;
        return 1;
    }
    return 0;
}

int get_loaded_libraries(pid_t pid, LibraryInfo **libs_out, int max_libs, int verbose,
                         int *truncated) {
    *libs_out = NULL;
    if (truncated) *truncated = 0;
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_path, "r");
    if (!f) {
        if (verbose) fprintf(stderr, "[!] Cannot open %s: %s\n", maps_path, strerror(errno));
        return -1;
    }
    if (max_libs <= 0) { fclose(f); return -1; }
    LibraryInfo *libs = calloc((size_t)max_libs, sizeof(LibraryInfo));
    if (!libs) { fclose(f); return -1; }
    char *line = NULL;
    size_t capacity = 0;
    int lib_count = 0;
    ssize_t line_size;
    while ((line_size = getline(&line, &capacity, f)) >= 0) {
        ProcMapEntry map;
        if (memchr(line, '\0', (size_t)line_size) || parse_proc_maps_line(line, &map) < 0) {
            if (truncated) *truncated = 1;
            continue;
        }
        if (map.offset != 0 || map.path[0] != '/' || !strstr(map.path, ".so")) continue;
        const char *lib_name = strrchr(map.path, '/') + 1;
        int is_target = 0;
        for (int i = 0; target_libs[i].lib_pattern != NULL; i++) {
            if (strstr(lib_name, target_libs[i].lib_pattern)) { is_target = 1; break; }
        }
        if (!is_target) continue;
        /* Offset-zero candidates are resolved against PT_LOAD geometry before scanning. */
        if (lib_count >= max_libs) {
            if (truncated) *truncated = 1;
            continue;
        }
        LibraryInfo *lib = &libs[lib_count++];
        memcpy(lib->path, map.path, sizeof(lib->path));
        snprintf(lib->short_name, sizeof(lib->short_name), "%s", lib_name);
        lib->base_addr = map.start; lib->map_end = map.end;
        lib->dev_major = map.dev_major; lib->dev_minor = map.dev_minor; lib->inode = map.inode;
    }
    if (!feof(f) && truncated) *truncated = 1;
    free(line);
    fclose(f);
    *libs_out = libs;
    return lib_count;
}

static int read_fd_bytes(int fd, unsigned long offset, void *buf, size_t size) {
    if ((uintmax_t)offset > INT64_MAX || size > (size_t)SSIZE_MAX) return -1;
    ssize_t got;
    do { got = pread(fd, buf, size, (off_t)offset); } while (got < 0 && errno == EINTR);
    return got == (ssize_t)size ? 0 : -1;
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

/* Read procfs streams without trusting st_size, and reject incomplete input. */
static int read_bounded_stream(FILE *f, size_t limit, char **out, size_t *len) {
    size_t cap = 4096, used = 0;
    char *buf = malloc(cap + 1);
    if (!buf) { fclose(f); errno = ENOMEM; return -1; }
    int error = 0;
    for (;;) {
        errno = 0;
        used += fread(buf + used, 1, cap - used, f);
        if (ferror(f)) { error = errno ? errno : EIO; break; }
        if (feof(f)) break;
        if (used < cap) { error = EIO; break; }
        if (cap == limit) {
            int c = fgetc(f);
            if (c != EOF) error = EFBIG;
            else if (ferror(f)) error = errno ? errno : EIO;
            break;
        }
        size_t next = cap > limit / 2 ? limit : cap * 2;
        char *p = realloc(buf, next + 1);
        if (!p) { error = ENOMEM; break; }
        buf = p;
        cap = next;
    }
    fclose(f);
    if (error) { free(buf); errno = error; return -1; }
    buf[used] = '\0';
    *out = buf;
    *len = used;
    return 0;
}

static int read_bounded_source(const char *path, size_t limit, char **out, size_t *len) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    return read_bounded_stream(f, limit, out, len);
}

/* Pin the process root, and reject symlinks rather than following them in the
 * scanner's namespace. Nonblocking open plus a descriptor type check prevents
 * a target-controlled FIFO/device from stalling a system-wide scan. */
static FILE *open_process_preload(pid_t pid, int *absent) {
    *absent = 0;
    char root[64];
    snprintf(root, sizeof(root), "/proc/%d/root", pid);
    int root_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root_fd < 0) return NULL;
    int etc_fd = openat(root_fd, "etc", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int error = errno;
    close(root_fd);
    if (etc_fd < 0) {
        *absent = error == ENOENT;
        errno = error;
        return NULL;
    }
    int fd = openat(etc_fd, "ld.so.preload", O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    error = errno;
    close(etc_fd);
    if (fd < 0) {
        *absent = error == ENOENT;
        errno = error;
        return NULL;
    }
    struct stat st;
    if (fstat(fd, &st) < 0) { error = errno; close(fd); errno = error; return NULL; }
    if (!S_ISREG(st.st_mode)) { close(fd); errno = EINVAL; return NULL; }
    FILE *f = fdopen(fd, "r");
    if (!f) { error = errno; close(fd); errno = error; }
    return f;
}

static int environment_valid_utf8(const char *value) {
    const unsigned char *p = (const unsigned char *)value;
    while (*p) {
        if (*p < 0x80) { p++; continue; }
        int width = *p >= 0xc2 && *p <= 0xdf ? 2 :
                    *p >= 0xe0 && *p <= 0xef ? 3 :
                    *p >= 0xf0 && *p <= 0xf4 ? 4 : 0;
        if (!width) return 0;
        for (int i = 1; i < width; i++)
            if ((p[i] & 0xc0) != 0x80) return 0;
        if ((*p == 0xe0 && p[1] < 0xa0) || (*p == 0xed && p[1] >= 0xa0) ||
            (*p == 0xf0 && p[1] < 0x90) || (*p == 0xf4 && p[1] >= 0x90)) return 0;
        p += width;
    }
    return 1;
}

/* With encoding=bytes, each decoded JSON code point maps to one input byte. */
static void environment_print_bytes(const char *value) {
    for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
        if (*p < 0x20 || *p >= 0x80) printf("\\u%04x", (unsigned int)*p);
        else {
            if (*p == '\\' || *p == '"') putchar('\\');
            putchar((int)*p);
        }
    }
}

/* A pathname may contain arbitrary Linux filename bytes. Preserve Unicode
 * strings directly; otherwise make every decoded code point recover one byte. */
void json_print_string_field(const char *key, const char *value) {
    if (!value) value = "";
    int utf8 = environment_valid_utf8(value);
    putchar('"');
    json_print_escaped(key);
    printf("\":\"");
    if (utf8) json_print_escaped(value);
    else environment_print_bytes(value);
    putchar('"');
    if (!utf8) {
        printf(",\"");
        json_print_escaped(key);
        printf("_encoding\":\"bytes\"");
    }
}

static void environment_unavailable(const Config *config, pid_t pid,
                                    const char *source, int error,
                                    int *first, int *unavailable) {
    *unavailable = 1;
    if (config->json_output) {
        if (!*first) printf(",");
        *first = 0;
        printf("{\"type\":\"source_unavailable\",\"pid\":%d,\"source\":\"", pid);
        json_print_escaped(source);
        printf("\",\"error\":\"");
        json_print_escaped(strerror(error));
        printf("\"}");
    } else {
        printf("[?] PID %d: cannot inspect %s: %s\n", pid, source, strerror(error));
    }
}

static void environment_indicator(const Config *config, pid_t pid,
                                  const char *type, const char *source,
                                  const char *value, int *first) {
    int utf8 = environment_valid_utf8(value);
    if (config->json_output) {
        if (!*first) printf(",");
        *first = 0;
        printf("{\"type\":\"%s\",\"pid\":%d,\"source\":\"", type, pid);
        json_print_escaped(source);
        if (strcmp(type, "ld.so.preload") == 0)
            printf("\",\"exists\":true,\"content\":\"");
        else
            printf("\",\"value\":\"");
        if (utf8) json_print_escaped(value);
        else environment_print_bytes(value);
        printf("\"");
        if (!utf8) printf(",\"encoding\":\"bytes\"");
        printf("}");
    } else {
        printf("[!] PID %d: %s (%s): ", pid, type, source);
        if (utf8) json_print_escaped(value);
        else environment_print_bytes(value);
        printf("\n");
    }
}

static int check_process_environment(pid_t pid, const Config *config,
                                     int *first, int *unavailable, int *scanned) {
    char path[96];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *maps = fopen(path, "r");
    if (!maps) {
        environment_unavailable(config, pid, path, errno, first, unavailable);
        return 0;
    }
    errno = 0;
    int first_byte = fgetc(maps);
    int maps_error = ferror(maps) ? (errno ? errno : EIO) : 0;
    fclose(maps);
    if (maps_error) {
        environment_unavailable(config, pid, path, maps_error, first, unavailable);
        return 0;
    }
    /* Kernel threads and zombies have no userspace environment to inspect. */
    if (first_byte == EOF) return 0;
    (*scanned)++;

    int indicators = 0;
    char *content = NULL;
    size_t len = 0;
    snprintf(path, sizeof(path), "/proc/%d/environ", pid);
    if (read_bounded_source(path, 16u * 1024u * 1024u, &content, &len) < 0) {
        environment_unavailable(config, pid, path, errno, first, unavailable);
    } else {
        size_t pos = 0;
        while (pos < len) {
            char *end = memchr(content + pos, '\0', len - pos);
            if (!end) {
                environment_unavailable(config, pid, path, EINVAL, first, unavailable);
                break;
            }
            size_t entry_len = (size_t)(end - (content + pos));
            if (entry_len > 11 && memcmp(content + pos, "LD_PRELOAD=", 11) == 0) {
                environment_indicator(config, pid, "LD_PRELOAD", path, content + pos + 11, first);
                indicators++;
            }
            pos += entry_len + 1;
        }
        free(content);
        content = NULL;
    }

    snprintf(path, sizeof(path), "/proc/%d/root/etc/ld.so.preload", pid);
    int absent = 0;
    FILE *preload = open_process_preload(pid, &absent);
    if (!preload) {
        if (!absent) environment_unavailable(config, pid, path, errno, first, unavailable);
    } else if (read_bounded_stream(preload, 64u * 1024u, &content, &len) < 0) {
        environment_unavailable(config, pid, path, errno, first, unavailable);
    } else {
        /* The loader's preload file is text; do not silently hide a suffix. */
        if (memchr(content, '\0', len)) {
            environment_unavailable(config, pid, path, EINVAL, first, unavailable);
        } else {
            if (len > 0 && content[len - 1] == '\n') content[len - 1] = '\0';
            environment_indicator(config, pid, "ld.so.preload", path, content, first);
            indicators++;
        }
        free(content);
    }
    return indicators;
}

void check_environment_hooks(const Config *config, int *incomplete) {
    int first = 1, unavailable = 0, scanned = 0, indicators = 0;
    if (config->json_output) printf("\"warnings\":[");
    else printf("[*] Checking process preload sources...\n");

    if (config->target_pid != 0) {
        indicators += check_process_environment(config->target_pid, config,
                                                &first, &unavailable, &scanned);
    } else {
        DIR *proc = opendir("/proc");
        if (!proc) {
            environment_unavailable(config, 0, "/proc", errno, &first, &unavailable);
        } else {
            struct dirent *entry;
            for (;;) {
                errno = 0;
                entry = readdir(proc);
                if (!entry) {
                    if (errno) environment_unavailable(config, 0, "/proc", errno,
                                                       &first, &unavailable);
                    break;
                }
                if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;
                char *end;
                errno = 0;
                long pid = strtol(entry->d_name, &end, 10);
                if (errno || *end || pid <= 0 || pid > INT32_MAX) continue;
                indicators += check_process_environment((pid_t)pid, config,
                                                        &first, &unavailable, &scanned);
            }
            closedir(proc);
        }
    }
    if (unavailable && incomplete) *incomplete = 1;
    if (config->json_output) printf("]");
    else if (!unavailable && indicators == 0)
        printf("[+] No preload indicators in %d process(es) inspected\n", scanned);
}

/* ── Process scanner ─────────────────────────────────────────────────────── */

int scan_process(pid_t pid, const Config *config, int *first_json, int *incomplete) {
    LibraryInfo *libs = NULL;
    int libraries_truncated = 0;
    int lib_count = get_loaded_libraries(pid, &libs, MAX_LIBRARIES, config->verbose,
                                         &libraries_truncated);
    if (libraries_truncated && incomplete) *incomplete = 1;
    if (lib_count < 0) {
        if (incomplete) *incomplete = 1;
        free(libs);
        return 0;
    }
    if (lib_count == 0) { free(libs); return 0; }

    ProcMapEntry *instance_maps = NULL;
    int map_count = read_instance_maps(pid, &instance_maps, incomplete);
    if (map_count < 0) {
        if (incomplete) *incomplete = 1;
        free(libs);
        return 0;
    }
    InstanceKey seen[MAX_LIBRARIES];
    int seen_count = 0;

    char proc_name[256];
    get_process_name(pid, proc_name, sizeof(proc_name));

    int total_hooks = 0;
    int first_hook  = 1;

    for (int i = 0; i < lib_count; i++) {
        if (config->target_lib[0] != '\0' &&
            !strstr(libs[i].path, config->target_lib))
            continue;

        int fd = open_backing_file(pid, libs[i].base_addr, libs[i].map_end,
                                   libs[i].dev_major, libs[i].dev_minor,
                                   libs[i].inode, libs[i].path);
        if (fd < 0) { if (incomplete) *incomplete = 1; continue; }
        int functions_truncated = 0;
        libs[i].func_count = extract_functions_from_fd(
            fd, libs[i].path, libs[i].functions, MAX_FUNCTIONS,
            &libs[i].preferred_base, &libs[i].arch, config->verbose, &functions_truncated);
        if (functions_truncated && incomplete) *incomplete = 1;

        if (libs[i].func_count < 0) {
            if (incomplete) *incomplete = 1;
            close(fd);
            continue;
        }

        ProcMapEntry candidate = {
            .start = libs[i].base_addr, .end = libs[i].map_end,
            .dev_major = libs[i].dev_major, .dev_minor = libs[i].dev_minor,
            .inode = libs[i].inode
        };
        ElfInstance instance;
        if (!open_elf_instance(fd, &candidate, instance_maps, map_count, &instance)) {
            if (incomplete) *incomplete = 1;
            close(fd);
            continue;
        }
        if (instance_already_seen(seen, &seen_count, &candidate, instance.base)) {
            munmap(instance.image, instance.size);
            close(fd);
            continue;
        }

        int is_x86 = (libs[i].arch == EM_X86_64 || libs[i].arch == EM_386);
        size_t check_size = is_x86
            ? (size_t)CHECK_BYTES_X86
            : (size_t)(CHECK_INSNS * (int)sizeof(uint32_t));

        for (int j = 0; j < libs[i].func_count; j++) {
            if (libs[i].functions[j].file_offset == 0) continue;

            unsigned long mem_addr;
            if (!instance_address(&instance, libs[i].functions[j].vaddr, check_size,
                                   &libs[i].functions[j].file_offset, &mem_addr)) {
                if (incomplete) *incomplete = 1;
                continue;
            }

            uint8_t disk_buf[CHECK_BYTES_X86];
            uint8_t mem_buf[CHECK_BYTES_X86];
            memset(disk_buf, 0, sizeof(disk_buf));
            memset(mem_buf,  0, sizeof(mem_buf));

            if (read_fd_bytes(fd, libs[i].functions[j].file_offset,
                              disk_buf, check_size) < 0)
            {
                if (incomplete) *incomplete = 1;
                continue;
            }

            if (read_mem(pid, mem_addr, mem_buf, check_size, config->verbose) < 0)
            {
                if (incomplete) *incomplete = 1;
                continue;
            }

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
                    printf("{\"pid\":%d,", pid);
                    json_print_string_field("name", proc_name);
                    printf(",\"hooks\":[");
                } else if (config->verbose)
                    printf("\n[!] PID %d (%s):\n", pid, proc_name);
                first_hook = 0;
            }

            if (config->json_output) {
                if (total_hooks > 0) printf(",");
                printf("{\"function\":\"");
                json_print_escaped(libs[i].functions[j].name);
                printf("\",");
                json_print_string_field("library", libs[i].short_name);
                printf(",");
                json_print_string_field("path", libs[i].path);
                printf(",\"base\":\"0x%lx\",\"address\":\"0x%lx\",\"confidence\":\"%s\"}",
                       instance.base, mem_addr, confidence_str(confidence));
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
        munmap(instance.image, instance.size);
        close(fd);
    }

    if (!first_hook && config->json_output) printf("]}");

    free(instance_maps);
    free(libs);
    return total_hooks;
}

/* ── VDSO consistency check ──────────────────────────────────────────────── */
/* Compare byte-identical images within a validated userspace ELF ABI. A
 * strict majority supplies a heuristic reference, never a trusted baseline. */
#define VDSO_MAX_BYTES     (64u * 1024u)
#define VDSO_MAX_VARIANTS  32

typedef struct {
    uint8_t elf_class, data, osabi, abi_version;
    uint16_t machine;
    uint32_t flags;
} VdsoAbi;

static int vdso_abi(const uint8_t *buf, size_t len, VdsoAbi *abi) {
    if (len < EI_NIDENT || memcmp(buf, ELFMAG, SELFMAG) ||
        buf[EI_VERSION] != EV_CURRENT || buf[EI_DATA] != ELFDATA2LSB)
        return 0;
    memset(abi, 0, sizeof(*abi));
    abi->elf_class = buf[EI_CLASS];
    abi->data = buf[EI_DATA];
    abi->osabi = buf[EI_OSABI];
    abi->abi_version = buf[EI_ABIVERSION];
    if (abi->elf_class == ELFCLASS64) {
        Elf64_Ehdr eh;
        if (len < sizeof(eh)) return 0;
        memcpy(&eh, buf, sizeof(eh));
        if (eh.e_ehsize != sizeof(eh) || eh.e_type != ET_DYN ||
            eh.e_version != EV_CURRENT ||
            (eh.e_machine != EM_X86_64 && eh.e_machine != EM_AARCH64)) return 0;
        abi->machine = eh.e_machine;
        abi->flags = eh.e_flags;
    } else if (abi->elf_class == ELFCLASS32) {
        Elf32_Ehdr eh;
        if (len < sizeof(eh)) return 0;
        memcpy(&eh, buf, sizeof(eh));
        if (eh.e_ehsize != sizeof(eh) || eh.e_type != ET_DYN ||
            eh.e_version != EV_CURRENT ||
            (eh.e_machine != EM_386 && eh.e_machine != EM_X86_64)) return 0;
        abi->machine = eh.e_machine; /* EM_X86_64 + ELF32 is the x32 ABI. */
        abi->flags = eh.e_flags;
    } else return 0;
    return 1;
}

static int same_vdso_abi(const VdsoAbi *a, const VdsoAbi *b) {
    return a->elf_class == b->elf_class && a->data == b->data &&
           a->osabi == b->osabi && a->abi_version == b->abi_version &&
           a->machine == b->machine && a->flags == b->flags;
}

static uint64_t fnv1a64(const uint8_t *p, size_t n) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

/* 1 found, 0 absent, -1 unavailable/invalid; filenames containing [vdso]
 * do not identify the kernel's special mapping. */
static int find_vdso_range(pid_t pid, unsigned long *start, unsigned long *end) {
    char maps[64];
    snprintf(maps, sizeof(maps), "/proc/%d/maps", pid);
    FILE *f = fopen(maps, "r");
    if (!f) return -1;
    char *line = NULL;
    size_t cap = 0;
    int found = 0;
    ssize_t length;
    while ((length = getline(&line, &cap, f)) >= 0) {
        if (memchr(line, '\0', (size_t)length)) { found = -1; break; }
        ProcMapEntry entry;
        if (parse_proc_maps_line(line, &entry) < 0) { found = -1; break; }
        if (strcmp(entry.path, "[vdso]") != 0) continue;
        if (found || entry.offset != 0 || entry.perms[0] != 'r' ||
            entry.perms[2] != 'x' || entry.inode != 0) { found = -1; break; }
        *start = entry.start;
        *end = entry.end;
        found = 1;
    }
    if (ferror(f) || !feof(f)) found = -1;
    free(line);
    fclose(f);
    return found;
}

int scan_vdso_consistency(const Config *config, int *incomplete) {
    if (!config->json_output) printf("[*] Checking VDSO consistency (system-wide peers)...\n");
    else printf("\"vdso\":[");

    struct vdso_variant {
        VdsoAbi abi;
        size_t len;
        uint64_t hash;
        uint8_t *bytes;
        int count;
        pid_t pid;
        char name[64];
    } var[VDSO_MAX_VARIANTS];
    int nvar = 0, scanned = 0, unavailable = 0;
    uint8_t *buf = malloc(VDSO_MAX_BYTES);
    DIR *proc = buf ? opendir("/proc") : NULL;
    if (!proc) {
        free(buf);
        if (incomplete) *incomplete = 1;
        if (config->json_output) printf("]");
        else printf("[!] VDSO process inventory unavailable\n");
        return 0;
    }

    for (;;) {
        errno = 0;
        struct dirent *e = readdir(proc);
        if (!e) { if (errno) unavailable++; break; }
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        char *endp;
        errno = 0;
        long v = strtol(e->d_name, &endp, 10);
        if (errno || *endp != '\0' || v <= 0 || v > INT32_MAX) continue;
        pid_t pid = (pid_t)v;
        unsigned long start = 0, end = 0;
        int range = find_vdso_range(pid, &start, &end);
        if (range < 0) { unavailable++; continue; }
        if (!range) continue;
        if (end <= start || end - start > VDSO_MAX_BYTES) { unavailable++; continue; }
        size_t len = (size_t)(end - start);
        VdsoAbi abi;
        if (read_mem(pid, start, buf, len, 0) < 0 || !vdso_abi(buf, len, &abi)) {
            unavailable++;
            continue;
        }
        uint64_t hash = fnv1a64(buf, len);
        int idx = -1;
        for (int i = 0; i < nvar; i++) {
            if (same_vdso_abi(&var[i].abi, &abi) && var[i].len == len &&
                var[i].hash == hash && memcmp(var[i].bytes, buf, len) == 0) {
                idx = i; break;
            }
        }
        if (idx < 0) {
            if (nvar >= VDSO_MAX_VARIANTS) { unavailable++; continue; }
            uint8_t *copy = malloc(len);
            if (!copy) { unavailable++; continue; }
            memcpy(copy, buf, len);
            idx = nvar++;
            var[idx].abi = abi;
            var[idx].len = len;
            var[idx].hash = hash;
            var[idx].bytes = copy;
            var[idx].count = 0;
            var[idx].pid = pid;
            get_process_name(pid, var[idx].name, sizeof(var[idx].name));
        }
        var[idx].count++;
        scanned++;
    }
    closedir(proc);
    free(buf);

    int comparison_incomplete = scanned < 2 || unavailable > 0;
    int flag[VDSO_MAX_VARIANTS] = {0};
    const char *state[VDSO_MAX_VARIANTS];
    int suspicious_procs = 0;
    for (int i = 0; i < nvar; i++) {
        int peers = 0, variants = 0, majority = -1;
        for (int j = 0; j < nvar; j++) {
            if (!same_vdso_abi(&var[i].abi, &var[j].abi)) continue;
            peers += var[j].count;
            variants++;
        }
        for (int j = 0; j < nvar; j++)
            if (same_vdso_abi(&var[i].abi, &var[j].abi) && var[j].count > peers / 2)
                majority = j;
        if (peers < 2 || majority < 0) {
            state[i] = "inconclusive";
            comparison_incomplete = 1;
        } else if (variants == 1) state[i] = "consistent";
        else {
            flag[i] = i != majority;
            state[i] = flag[i] ? "minority" : "majority_reference";
        }
        if (flag[i]) suspicious_procs += var[i].count;
    }
    if (comparison_incomplete && incomplete) *incomplete = 1;

    if (config->json_output) {
        for (int i = 0; i < nvar; i++) {
            if (i) printf(",");
            printf("{\"len\":%zu,\"hash\":\"%016llx\",\"processes\":%d,\"example_pid\":%d,",
                   var[i].len, (unsigned long long)var[i].hash,
                   var[i].count, (int)var[i].pid);
            json_print_string_field("example_name", var[i].name);
            printf(",\"suspicious\":%s,\"comparison\":\"%s\",\"abi\":{"
                   "\"class\":%u,\"data\":%u,\"machine\":%u,\"osabi\":%u,"
                   "\"version\":%u,\"flags\":%u}}", flag[i] ? "true" : "false", state[i],
                   (unsigned)var[i].abi.elf_class, (unsigned)var[i].abi.data,
                   (unsigned)var[i].abi.machine, (unsigned)var[i].abi.osabi,
                   (unsigned)var[i].abi.abi_version, (unsigned)var[i].abi.flags);
        }
        printf("]");
    } else {
        if (suspicious_procs)
            printf("[!] VDSO inconsistency: %d process(es) differ from their ABI's strict majority\n", suspicious_procs);
        else if (!comparison_incomplete)
            printf("[+] VDSO consistent across %d process(es) (%d ABI group(s))\n", scanned, nvar);
        if (comparison_incomplete)
            printf("[?] VDSO comparison incomplete: insufficient peers, conflicting variants without a strict majority, or %d unavailable process(es)\n", unavailable);
        for (int i = 0; i < nvar; i++)
            if (flag[i]) printf("    hash=%016llx len=%zu on %d proc(s), e.g. PID %d (%s)\n",
                (unsigned long long)var[i].hash, var[i].len, var[i].count, (int)var[i].pid, var[i].name);
    }
    for (int i = 0; i < nvar; i++) free(var[i].bytes);
    return suspicious_procs;
}

/* ── GOT / PLT hijack detection ──────────────────────────────────────────── */
/* Overwriting a GOT slot reroutes calls without touching function code, so the
 * inline diff check misses it. We walk each module's JUMP_SLOT/GLOB_DAT
 * relocations, read the live slot via /proc/PID/mem, and flag any target in an
 * executable anonymous mapping (injected code). Normal resolution and
 * LD_PRELOAD always point into file-backed .so regions. */

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
                         GotSlot *out, int max_out, unsigned long *pref_base_out,
                         int *truncated) {
    if (truncated) *truncated = 0;
    Elf64_Ehdr *eh = (Elf64_Ehdr *)map;
    if (!valid_elf64_header(eh, sz) ||
        !range_in_file(sz, eh->e_shoff, (uint64_t)eh->e_shnum * sizeof(Elf64_Shdr)))
        return -1;
    if (!elf_runtime_symbols_supported(map, sz, 1) ||
        !elf_runtime_relocations_supported(map, sz, 1)) return -1;
    Elf64_Shdr *sh = (Elf64_Shdr *)((char *)map + eh->e_shoff);

    unsigned long pbase = 0;
    if (range_in_file(sz, eh->e_phoff, (uint64_t)eh->e_phnum * sizeof(Elf64_Phdr))) {
        Elf64_Phdr *ph = (Elf64_Phdr *)((char *)map + eh->e_phoff);
        for (int i = 0; i < eh->e_phnum; i++)
            if (ph[i].p_type == PT_LOAD) { pbase = (unsigned long)ph[i].p_vaddr; break; }
    }
    if (pref_base_out) *pref_base_out = pbase;

    /* Dynamic modules must expose a usable dynamic symbol table. */
    int dynamic = 0, dynsym = 0;
    Elf64_Phdr *ph = (Elf64_Phdr *)((char *)map + eh->e_phoff);
    for (int i = 0; i < eh->e_phnum; i++)
        if (ph[i].p_type == PT_DYNAMIC) dynamic = 1;
    for (int i = 0; i < eh->e_shnum; i++) {
        if (sh[i].sh_type != SHT_DYNSYM) continue;
        if (sh[i].sh_entsize != sizeof(Elf64_Sym) ||
            sh[i].sh_offset % _Alignof(Elf64_Sym) != 0 ||
            sh[i].sh_size % sizeof(Elf64_Sym) != 0 ||
            !range_in_file(sz, sh[i].sh_offset, sh[i].sh_size) ||
            sh[i].sh_link >= eh->e_shnum) return -1;
        Elf64_Shdr *strings = &sh[sh[i].sh_link];
        if (strings->sh_type != SHT_STRTAB ||
            !range_in_file(sz, strings->sh_offset, strings->sh_size)) return -1;
        dynsym = 1;
    }
    if (dynamic && !dynsym) return -1;

    unsigned long js = (machine == EM_AARCH64) ? R_AARCH64_JUMP_SLOT : R_X86_64_JUMP_SLOT;
    unsigned long gd = (machine == EM_AARCH64) ? R_AARCH64_GLOB_DAT  : R_X86_64_GLOB_DAT;

    int count = 0;
    for (int s = 0; s < eh->e_shnum; s++) {
        if (sh[s].sh_type != SHT_RELA)                      continue;
        if (!(sh[s].sh_flags & SHF_ALLOC)) continue; /* debug relocations are not live GOT slots */
        if (sh[s].sh_entsize != sizeof(Elf64_Rela) ||
            sh[s].sh_offset % _Alignof(Elf64_Rela) != 0 ||
            sh[s].sh_size % sizeof(Elf64_Rela) != 0) return -1;
        if (!range_in_file(sz, sh[s].sh_offset, sh[s].sh_size)) return -1;
        if (sh[s].sh_link >= eh->e_shnum)                   return -1;

        Elf64_Shdr *symsh = &sh[sh[s].sh_link];
        if (symsh->sh_type != SHT_DYNSYM && symsh->sh_type != SHT_SYMTAB) return -1;
        if (symsh->sh_entsize != sizeof(Elf64_Sym) ||
            symsh->sh_offset % _Alignof(Elf64_Sym) != 0 ||
            symsh->sh_size % sizeof(Elf64_Sym) != 0 ||
            !range_in_file(sz, symsh->sh_offset, symsh->sh_size)) return -1;
        if (symsh->sh_link >= eh->e_shnum)                  return -1;
        Elf64_Shdr *strsh = &sh[symsh->sh_link];
        if (strsh->sh_type != SHT_STRTAB ||
            !range_in_file(sz, strsh->sh_offset, strsh->sh_size)) return -1;

        Elf64_Sym  *syms = (Elf64_Sym *)((char *)map + symsh->sh_offset);
        size_t      nsym = symsh->sh_size / sizeof(Elf64_Sym);
        const char *str  = (const char *)map + strsh->sh_offset;
        size_t      strn = strsh->sh_size;

        Elf64_Rela *ra = (Elf64_Rela *)((char *)map + sh[s].sh_offset);
        size_t      nr = sh[s].sh_size / sizeof(Elf64_Rela);
        for (size_t r = 0; r < nr; r++) {
            unsigned long type = (unsigned long)ELF64_R_TYPE(ra[r].r_info);
            if (type != js && type != gd) continue;
            uint64_t si = ELF64_R_SYM(ra[r].r_info);
            if (si == 0) continue; /* STN_UNDEF carries no named import */
            if (si >= nsym) return -1;
            uint32_t no = syms[si].st_name;
            if (no >= strn) return -1;
            const char *nm = str + no;
            if (!memchr(nm, '\0', strn - no)) return -1;
            if (!is_monitored_symbol(nm)) continue;
            if (count >= max_out) {
                if (truncated) *truncated = 1;
                continue;
            }
            snprintf(out[count].name, sizeof(out[count].name), "%s", nm);
            out[count].slot_vaddr = (unsigned long)ra[r].r_offset;
            count++;
        }
    }
    return count;
}

static int got32_collect(void *map, size_t sz, GotSlot *out, int max_out,
                         unsigned long *pref_base_out, int *truncated) {
    if (truncated) *truncated = 0;
    Elf32_Ehdr *eh = (Elf32_Ehdr *)map;
    if (!valid_elf32_header(eh, sz) ||
        !range_in_file(sz, eh->e_shoff, (uint64_t)eh->e_shnum * sizeof(Elf32_Shdr)))
        return -1;
    if (!elf_runtime_symbols_supported(map, sz, 0) ||
        !elf_runtime_relocations_supported(map, sz, 0)) return -1;
    Elf32_Shdr *sh = (Elf32_Shdr *)((char *)map + eh->e_shoff);

    unsigned long pbase = 0;
    if (range_in_file(sz, eh->e_phoff, (uint64_t)eh->e_phnum * sizeof(Elf32_Phdr))) {
        Elf32_Phdr *ph = (Elf32_Phdr *)((char *)map + eh->e_phoff);
        for (int i = 0; i < eh->e_phnum; i++)
            if (ph[i].p_type == PT_LOAD) { pbase = (unsigned long)ph[i].p_vaddr; break; }
    }
    if (pref_base_out) *pref_base_out = pbase;

    /* Dynamic modules must expose a usable dynamic symbol table. */
    int dynamic = 0, dynsym = 0;
    Elf32_Phdr *ph = (Elf32_Phdr *)((char *)map + eh->e_phoff);
    for (int i = 0; i < eh->e_phnum; i++)
        if (ph[i].p_type == PT_DYNAMIC) dynamic = 1;
    for (int i = 0; i < eh->e_shnum; i++) {
        if (sh[i].sh_type != SHT_DYNSYM) continue;
        if (sh[i].sh_entsize != sizeof(Elf32_Sym) ||
            sh[i].sh_offset % _Alignof(Elf32_Sym) != 0 ||
            sh[i].sh_size % sizeof(Elf32_Sym) != 0 ||
            !range_in_file(sz, sh[i].sh_offset, sh[i].sh_size) ||
            sh[i].sh_link >= eh->e_shnum) return -1;
        Elf32_Shdr *strings = &sh[sh[i].sh_link];
        if (strings->sh_type != SHT_STRTAB ||
            !range_in_file(sz, strings->sh_offset, strings->sh_size)) return -1;
        dynsym = 1;
    }
    if (dynamic && !dynsym) return -1;

    int count = 0;
    for (int s = 0; s < eh->e_shnum; s++) {
        if (sh[s].sh_type != SHT_REL)                       continue;
        if (!(sh[s].sh_flags & SHF_ALLOC)) continue; /* debug relocations are not live GOT slots */
        if (sh[s].sh_entsize != sizeof(Elf32_Rel) ||
            sh[s].sh_offset % _Alignof(Elf32_Rel) != 0 ||
            sh[s].sh_size % sizeof(Elf32_Rel) != 0) return -1;
        if (!range_in_file(sz, sh[s].sh_offset, sh[s].sh_size)) return -1;
        if (sh[s].sh_link >= eh->e_shnum)                   return -1;

        Elf32_Shdr *symsh = &sh[sh[s].sh_link];
        if (symsh->sh_type != SHT_DYNSYM && symsh->sh_type != SHT_SYMTAB) return -1;
        if (symsh->sh_entsize != sizeof(Elf32_Sym) ||
            symsh->sh_offset % _Alignof(Elf32_Sym) != 0 ||
            symsh->sh_size % sizeof(Elf32_Sym) != 0 ||
            !range_in_file(sz, symsh->sh_offset, symsh->sh_size)) return -1;
        if (symsh->sh_link >= eh->e_shnum)                  return -1;
        Elf32_Shdr *strsh = &sh[symsh->sh_link];
        if (strsh->sh_type != SHT_STRTAB ||
            !range_in_file(sz, strsh->sh_offset, strsh->sh_size)) return -1;

        Elf32_Sym  *syms = (Elf32_Sym *)((char *)map + symsh->sh_offset);
        size_t      nsym = symsh->sh_size / sizeof(Elf32_Sym);
        const char *str  = (const char *)map + strsh->sh_offset;
        size_t      strn = strsh->sh_size;

        Elf32_Rel  *re = (Elf32_Rel *)((char *)map + sh[s].sh_offset);
        size_t      nr = sh[s].sh_size / sizeof(Elf32_Rel);
        for (size_t r = 0; r < nr; r++) {
            unsigned int type = ELF32_R_TYPE(re[r].r_info);
            if (type != R_386_JMP_SLOT && type != R_386_GLOB_DAT) continue;
            uint32_t si = ELF32_R_SYM(re[r].r_info);
            if (si == 0) continue; /* STN_UNDEF carries no named import */
            if (si >= nsym) return -1;
            uint32_t no = syms[si].st_name;
            if (no >= strn) return -1;
            const char *nm = str + no;
            if (!memchr(nm, '\0', strn - no)) return -1;
            if (!is_monitored_symbol(nm)) continue;
            if (count >= max_out) {
                if (truncated) *truncated = 1;
                continue;
            }
            snprintf(out[count].name, sizeof(out[count].name), "%s", nm);
            out[count].slot_vaddr = (unsigned long)re[r].r_offset;
            count++;
        }
    }
    return count;
}

/* Open+parse a module file, returning its monitored-import GOT slots. */
static int module_gots_fd(int fd, GotSlot *out, int max_out,
                       int *arch_out, unsigned long *pref_out, int *truncated) {
    *arch_out = 0;
    if (truncated) *truncated = 0;
    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size < 0 || (uintmax_t)st.st_size > SIZE_MAX) {
        return -1;
    }
    /* Offset-zero mmap mappings also include databases, locale files, and
     * empty files. Only a confirmed ELF is subject to ELF validation. */
    unsigned char magic[SELFMAG];
    ssize_t magic_len;
    do { magic_len = pread(fd, magic, sizeof(magic), 0); }
    while (magic_len < 0 && errno == EINTR);
    if (magic_len < 0) { return -1; }
    if (magic_len == 0) { return st.st_size == 0 ? 0 : -1; }
    if (memcmp(magic, ELFMAG, (size_t)magic_len) != 0) { return 0; }
    if (magic_len != SELFMAG) { return -1; } /* truncated ELF prefix */
    if ((size_t)st.st_size < EI_NIDENT) { return -1; }
    void *m = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (m == MAP_FAILED) return -1;

    int rc = -1;
    const uint8_t *id = (const uint8_t *)m;
    if (memcmp(id, ELFMAG, SELFMAG) == 0) {
        if (id[EI_CLASS] == ELFCLASS64) {
            if ((size_t)st.st_size < sizeof(Elf64_Ehdr)) goto done;
            Elf64_Ehdr *eh = (Elf64_Ehdr *)m;
            if (eh->e_machine == EM_X86_64 || eh->e_machine == EM_AARCH64) {
                *arch_out = (int)eh->e_machine;
                rc = got64_collect(m, (size_t)st.st_size, eh->e_machine, out, max_out, pref_out, truncated);
            }
        } else if (id[EI_CLASS] == ELFCLASS32) {
            if ((size_t)st.st_size < sizeof(Elf32_Ehdr)) goto done;
            Elf32_Ehdr *eh = (Elf32_Ehdr *)m;
            if (eh->e_machine == EM_386) {
                *arch_out = EM_386;
                rc = got32_collect(m, (size_t)st.st_size, out, max_out, pref_out, truncated);
            }
        }
    }
done:
    munmap(m, (size_t)st.st_size);
    return rc;
}

typedef struct { unsigned long start, end; int legit, exec; char name[32]; } MemRegion;
typedef struct { ProcMapEntry map; } GotModule;

/* Returns a label for executable anonymous code or an invalid/unmapped target.
 * A resolved function pointer must designate mapped executable code; treating an
 * unmapped target as clean turns a corrupted GOT slot into a false negative. */
static const char *classify_got_target(const MemRegion *regs, int n, unsigned long ptr) {
    for (int i = 0; i < n; i++) {
        if (ptr < regs[i].start || ptr >= regs[i].end) continue;
        if (!regs[i].exec)  return NULL;   /* not executable -> not a code hook   */
        if (regs[i].legit)  return NULL;   /* real module / vdso -> legit target  */
        return regs[i].name[0] ? regs[i].name : "anon-exec";
    }
    return "unmapped";
}

static void basename_into(char *dst, size_t dsz, const char *path) {
    if (!dsz) return;
    const char *b = strrchr(path, '/');
    b = b ? b + 1 : path;
    size_t len = strlen(b);
    if (len >= dsz) len = dsz - 1;
    memcpy(dst, b, len);
    dst[len] = '\0';
}

static int scan_got_for_pid(pid_t pid, const Config *config, int *first_json,
                            int *incomplete) {
    ProcMapEntry *instance_maps = NULL;
    int map_count = read_instance_maps(pid, &instance_maps, incomplete);
    if (map_count < 0) {
        if (incomplete) *incomplete = 1;
        return 0;
    }

    MemRegion *regs = malloc((size_t)GOT_MAX_REGIONS * sizeof(*regs));
    GotModule *mods = malloc((size_t)GOT_MAX_MODULES * sizeof(*mods));
    if (!regs || !mods) {
        if (incomplete) *incomplete = 1;
        free(regs); free(mods); free(instance_maps);
        return 0;
    }
    int nreg = 0, nmod = 0;

    for (int i = 0; i < map_count; i++) {
        ProcMapEntry map = instance_maps[i];
        int has_path = map.path[0] != '\0';
        if (nreg < GOT_MAX_REGIONS) {
            regs[nreg].start = map.start;
            regs[nreg].end   = map.end;
            regs[nreg].exec  = map.perms[2] == 'x';
            regs[nreg].legit = has_path &&
                               (map.path[0] == '/' ||
                                strcmp(map.path, "[vdso]") == 0 ||
                                strcmp(map.path, "[vsyscall]") == 0);
            if (has_path) basename_into(regs[nreg].name, sizeof(regs[nreg].name), map.path);
            else          snprintf(regs[nreg].name, sizeof(regs[nreg].name), "anon");
            nreg++;
        } else if (incomplete) {
            *incomplete = 1;
        }
        if (map.offset == 0 && map.path[0] == '/' &&
            (!config->target_lib[0] || strstr(map.path, config->target_lib))) {
            if (nmod < GOT_MAX_MODULES) mods[nmod++].map = map;
            else if (incomplete) *incomplete = 1;
        }
    }

    int  found = 0;
    char proc_name[256];
    int  have_name = 0;
    GotSlot slots[GOT_MAX_SLOTS];
    InstanceKey seen[GOT_MAX_MODULES];
    int seen_count = 0;

    for (int m = 0; m < nmod; m++) {
        int           arch  = 0;
        unsigned long pref  = 0;
        ProcMapEntry *map = &mods[m].map;
        int fd = open_backing_file(pid, map->start, map->end, map->dev_major,
                                   map->dev_minor, map->inode, map->path);
        if (fd < 0) { if (incomplete) *incomplete = 1; continue; }
        int slots_truncated = 0;
        int nslot = module_gots_fd(fd, slots, GOT_MAX_SLOTS, &arch, &pref, &slots_truncated);
        if (slots_truncated && incomplete) *incomplete = 1;
        if (nslot < 0) {
            if (incomplete) *incomplete = 1;
            close(fd);
            continue;
        }
        if (nslot == 0) { close(fd); continue; }
        ElfInstance instance;
        int resolved = open_elf_instance(fd, map, instance_maps, map_count, &instance);
        close(fd);
        if (!resolved) { if (incomplete) *incomplete = 1; continue; }
        if (instance_already_seen(seen, &seen_count, map, instance.base)) {
            munmap(instance.image, instance.size);
            continue;
        }
        int ptrsize = (arch == EM_386) ? 4 : 8;

        for (int k = 0; k < nslot; k++) {
            unsigned long addr;
            if (!instance_address(&instance, slots[k].slot_vaddr, (uint64_t)ptrsize, NULL, &addr)) {
                if (incomplete) *incomplete = 1;
                continue;
            }
            unsigned long ptr  = 0;
            if (ptrsize == 4) {
                uint32_t t;
                if (read_mem(pid, addr, &t, sizeof(t), 0) < 0) {
                    if (incomplete) *incomplete = 1;
                    continue;
                }
                ptr = t;
            } else {
                uint64_t t;
                if (read_mem(pid, addr, &t, sizeof(t), 0) < 0) {
                    if (incomplete) *incomplete = 1;
                    continue;
                }
                ptr = (unsigned long)t;
            }
            if (ptr == 0) continue;     /* unbound weak symbol — not a hook */

            const char *label = classify_got_target(regs, nreg, ptr);
            if (!label) continue;

            if (!have_name) { get_process_name(pid, proc_name, sizeof(proc_name)); have_name = 1; }

            char modbase[64];
            basename_into(modbase, sizeof(modbase), map->path);

            if (config->json_output) {
                if (!*first_json) printf(",");
                *first_json = 0;
                printf("{\"pid\":%d,", pid);
                json_print_string_field("name", proc_name);
                printf(",\"function\":\"");
                json_print_escaped(slots[k].name);
                printf("\",");
                json_print_string_field("module", modbase);
                printf(",");
                json_print_string_field("path", map->path);
                printf(",\"base\":\"0x%lx\",\"slot\":\"0x%lx\",\"target\":\"0x%lx\",\"location\":\"",
                       instance.base, addr, ptr);
                json_print_escaped(label);
                printf("\"}");
            } else {
                printf("  [GOT] PID %d (%s): %s in %s -> 0x%lx (%s)\n",
                       pid, proc_name, slots[k].name, modbase, ptr, label);
            }
            found++;
        }
        munmap(instance.image, instance.size);
    }

    free(instance_maps);
    free(regs);
    free(mods);
    return found;
}

int scan_got_hijacks(const Config *config, int *incomplete) {
    if (!config->json_output)
        printf("[*] Scanning GOT/PLT for hijacks...\n");
    else
        printf("\"got_hijacks\":[");

    int first_json = 1;
    int total      = 0;

    if (config->target_pid != 0) {
        total += scan_got_for_pid(config->target_pid, config, &first_json, incomplete);
    } else {
        DIR *proc = opendir("/proc");
        if (proc) {
            struct dirent *e;
            while ((e = readdir(proc)) != NULL) {
                if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
                char *endp;
                long  v = strtol(e->d_name, &endp, 10);
                if (*endp != '\0' || v <= 0) continue;
                total += scan_got_for_pid((pid_t)v, config, &first_json, incomplete);
            }
            closedir(proc);
        } else if (incomplete) {
            *incomplete = 1;
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
