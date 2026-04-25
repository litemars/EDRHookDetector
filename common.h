#ifndef COMMON_H
#define COMMON_H

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

#define STT_GNU_IFUNC    10
#define MAX_PROCESSES    2048
#define MAX_FUNCTIONS    256
#define MAX_LIBRARIES    32
#define CHECK_INSNS      8       /* ARM64: 8 × 4-byte instructions = 32 bytes */
#define CHECK_BYTES_X86  64      /* x86: enough for ~10–15 variable-length instructions */

typedef enum {
    HOOK_CONFIDENCE_NONE   = 0,
    HOOK_CONFIDENCE_LOW    = 1,
    HOOK_CONFIDENCE_MEDIUM = 2,
    HOOK_CONFIDENCE_HIGH   = 3
} HookConfidence;

typedef struct {
    char          name[128];
    unsigned long vaddr;
    unsigned long file_offset;
} FunctionInfo;

typedef struct {
    char          path[512];
    char          short_name[64];
    unsigned long base_addr;
    unsigned long preferred_base;
    int           arch;          /* e_machine from ELF: EM_AARCH64, EM_X86_64, EM_386 */
    FunctionInfo  functions[MAX_FUNCTIONS];
    int           func_count;
} LibraryInfo;

typedef struct {
    pid_t target_pid;
    char  target_lib[512];
    int   verbose;
    int   json_output;
    int   show_hexdump;
} Config;

typedef struct {
    const char *lib_pattern;
    const char *functions[30];
} TargetLibEntry;

extern const TargetLibEntry target_libs[];

/* ELF and process utilities */
int  extract_functions_from_elf(const char *lib_path, FunctionInfo *funcs,
                                 int max_funcs, unsigned long *preferred_base_out,
                                 int *arch_out, int verbose);
int  get_loaded_libraries(pid_t pid, LibraryInfo **libs_out, int max_libs, int verbose);
int  read_bytes(const char *path, unsigned long offset, void *buf, size_t size, int verbose);
int  read_mem(pid_t pid, unsigned long addr, void *buf, size_t size, int verbose);
int  get_process_name(pid_t pid, char *name, int size);
void check_environment_hooks(const Config *config);
int  scan_process(pid_t pid, const Config *config);

/* Output helpers */
const char *confidence_str(HookConfidence conf);

#endif /* COMMON_H */
