#ifndef ELF_VALIDATION_H
#define ELF_VALIDATION_H

#include "common.h"

/* A small view normalizes the ELF classes without duplicating validation. */
struct elf_reloc_view {
    const unsigned char *data;
    size_t size;
    uint64_t phoff, shoff;
    uint16_t phnum, shnum;
    int is64;
};

static int elf_reloc_range(size_t size, uint64_t offset, uint64_t length) {
    return offset <= size && length <= (uint64_t)size - offset;
}

static Elf64_Phdr elf_reloc_phdr(const struct elf_reloc_view *v, unsigned int i) {
    Elf64_Phdr p = {0};
    if (v->is64) {
        memcpy(&p, v->data + v->phoff + (size_t)i * sizeof(p), sizeof(p));
    } else {
        Elf32_Phdr p32;
        memcpy(&p32, v->data + v->phoff + (size_t)i * sizeof(p32), sizeof(p32));
        p.p_type = p32.p_type;
        p.p_offset = p32.p_offset;
        p.p_vaddr = p32.p_vaddr;
        p.p_filesz = p32.p_filesz;
        p.p_memsz = p32.p_memsz;
    }
    return p;
}

static Elf64_Shdr elf_reloc_shdr(const struct elf_reloc_view *v, unsigned int i) {
    Elf64_Shdr s = {0};
    if (v->is64) {
        memcpy(&s, v->data + v->shoff + (size_t)i * sizeof(s), sizeof(s));
    } else {
        Elf32_Shdr s32;
        memcpy(&s32, v->data + v->shoff + (size_t)i * sizeof(s32), sizeof(s32));
        s.sh_type = s32.sh_type;
        s.sh_flags = s32.sh_flags;
        s.sh_addr = s32.sh_addr;
        s.sh_offset = s32.sh_offset;
        s.sh_size = s32.sh_size;
        s.sh_entsize = s32.sh_entsize;
        s.sh_link = s32.sh_link;
    }
    return s;
}

/* Confirm that the file bytes are the bytes mapped at the runtime address. */
static int elf_reloc_mapped(const struct elf_reloc_view *v, uint64_t addr,
                            uint64_t offset, uint64_t length) {
    if (!elf_reloc_range(v->size, offset, length)) return 0;
    for (unsigned int i = 0; i < v->phnum; i++) {
        Elf64_Phdr p = elf_reloc_phdr(v, i);
        if (p.p_type != PT_LOAD || addr < p.p_vaddr ||
            p.p_filesz > p.p_memsz || !elf_reloc_range(v->size, p.p_offset, p.p_filesz))
            continue;
        uint64_t delta = addr - p.p_vaddr;
        if (delta <= p.p_filesz && length <= p.p_filesz - delta &&
            offset == p.p_offset + delta)
            return 1;
    }
    return 0;
}

static const unsigned char *elf_runtime_bytes(const struct elf_reloc_view *v,
                                              uint64_t addr, uint64_t length) {
    if (length > UINT64_MAX - addr) return NULL;
    for (unsigned int i = 0; i < v->phnum; i++) {
        Elf64_Phdr p = elf_reloc_phdr(v, i);
        if (p.p_type != PT_LOAD || addr < p.p_vaddr ||
            p.p_filesz > p.p_memsz || !elf_reloc_range(v->size, p.p_offset, p.p_filesz))
            continue;
        uint64_t delta = addr - p.p_vaddr;
        if (delta <= p.p_filesz && length <= p.p_filesz - delta)
            return v->data + p.p_offset + delta;
    }
    return NULL;
}

/* Hash metadata supplies bounds that DT_SYMTAB itself lacks. The System V
 * nchain is the symbol count (gABI section 8.5). GNU buckets name the first
 * symbol of each contiguous chain; its low-bit terminator must occur before
 * the section's claimed end. See sourceware.org/gnu-gabi/
 * program-loading-and-dynamic-linking.txt, "Hashes". */
static int elf_symbol_hash_supported(const struct elf_reloc_view *v,
                                     uint64_t addr, uint64_t nsym, int gnu) {
    uint32_t header[4] = {0};
    size_t header_size = gnu ? sizeof(header) : 2 * sizeof(uint32_t);
    const unsigned char *bytes = elf_runtime_bytes(v, addr, header_size);
    if (!bytes) return 0;
    memcpy(header, bytes, header_size);
    uint64_t buckets = header[0];
    if (!buckets) return 0;
    if (!gnu) {
        uint64_t chains = header[1];
        if (chains != nsym) return 0;
        uint64_t words = 2 + buckets + chains;
        bytes = elf_runtime_bytes(v, addr, words * sizeof(uint32_t));
        if (!bytes) return 0;
        for (uint64_t i = 2; i < words; i++) {
            uint32_t index;
            memcpy(&index, bytes + i * sizeof(index), sizeof(index));
            if (index >= nsym) return 0;
        }
        return 1;
    }
    uint64_t first_symbol = header[1], bloom_words = header[2];
    if (first_symbol > nsym || !bloom_words ||
        (bloom_words & (bloom_words - 1)) || header[3] >= 32) return 0;
    uint64_t bucket_offset = sizeof(header) + bloom_words * (v->is64 ? 8u : 4u);
    uint64_t chain_offset = bucket_offset + buckets * sizeof(uint32_t);
    bytes = elf_runtime_bytes(v, addr, chain_offset);
    if (!bytes) return 0;
    uint64_t next_symbol = first_symbol;
    const unsigned char *chains = NULL;
    for (uint64_t i = 0; i < buckets; i++) {
        uint32_t start;
        memcpy(&start, bytes + bucket_offset + i * sizeof(start), sizeof(start));
        if (!start) continue;
        if (start != next_symbol || start >= nsym) return 0;
        if (!chains) {
            if (chain_offset > UINT64_MAX - addr) return 0;
            chains = elf_runtime_bytes(v, addr + chain_offset,
                                        (nsym - first_symbol) * sizeof(uint32_t));
            if (!chains) return 0;
        }
        uint32_t hash = 0;
        do {
            if (next_symbol >= nsym) return 0;
            memcpy(&hash, chains + (next_symbol - first_symbol) * sizeof(hash), sizeof(hash));
            next_symbol++;
        } while (!(hash & 1u));
    }
    /* Empty GNU hash tables can coexist with unhashed imports after symoffset. */
    return !chains || next_symbol == nsym;
}

/* Runtime tables may occupy a section, a subsection, or adjacent sections.
 * Every byte must remain visible to the existing section-based collector. */
static int elf_reloc_table(const struct elf_reloc_view *v, uint64_t addr,
                           uint64_t length, uint32_t type, uint64_t entry_size) {
    if (length % entry_size != 0 || length > UINT64_MAX - addr) return 0;
    while (length) {
        uint64_t covered = 0;
        for (unsigned int i = 0; i < v->shnum; i++) {
            Elf64_Shdr s = elf_reloc_shdr(v, i);
            if (s.sh_type != type || !(s.sh_flags & SHF_ALLOC) || addr < s.sh_addr)
                continue;
            uint64_t delta = addr - s.sh_addr;
            if (delta >= s.sh_size) continue;
            if (s.sh_entsize != entry_size || s.sh_size % entry_size != 0 ||
                delta % entry_size != 0 ||
                !elf_reloc_range(v->size, s.sh_offset, s.sh_size))
                return 0;
            uint64_t chunk = s.sh_size - delta;
            if (chunk > length) chunk = length;
            if (elf_reloc_mapped(v, addr, s.sh_offset + delta, chunk) && chunk > covered)
                covered = chunk;
        }
        if (!covered) return 0;
        addr += covered;
        length -= covered;
    }
    return 1;
}

/* Call only after validating the complete ELF/program/section headers. */
static struct elf_reloc_view elf_runtime_view(void *map, size_t sz, int is64) {
    struct elf_reloc_view v = {.data = map, .size = sz, .is64 = is64};
    if (is64) {
        Elf64_Ehdr eh;
        memcpy(&eh, map, sizeof(eh));
        v.phoff = eh.e_phoff; v.phnum = eh.e_phnum;
        v.shoff = eh.e_shoff; v.shnum = eh.e_shnum;
    } else {
        Elf32_Ehdr eh;
        memcpy(&eh, map, sizeof(eh));
        v.phoff = eh.e_phoff; v.phnum = eh.e_phnum;
        v.shoff = eh.e_shoff; v.shnum = eh.e_shnum;
    }
    return v;
}

static int elf_dynamic_values(const struct elf_reloc_view *v,
                              const int64_t *tags, unsigned int tag_count,
                              uint64_t *values, unsigned int *seen, int *dynamic) {
    *seen = 0;
    *dynamic = 0;
    size_t dyn_size = v->is64 ? sizeof(Elf64_Dyn) : sizeof(Elf32_Dyn);

    for (unsigned int i = 0; i < v->phnum; i++) {
        Elf64_Phdr p = elf_reloc_phdr(v, i);
        if (p.p_type != PT_DYNAMIC) continue;
        if ((*dynamic)++ || p.p_filesz % dyn_size != 0 || p.p_filesz > p.p_memsz ||
            !elf_reloc_mapped(v, p.p_vaddr, p.p_offset, p.p_filesz))
            return 0;
        int terminated = 0;
        for (uint64_t offset = 0; offset < p.p_filesz; offset += dyn_size) {
            int64_t tag;
            uint64_t value;
            if (v->is64) {
                Elf64_Dyn d;
                memcpy(&d, v->data + p.p_offset + offset, sizeof(d));
                tag = d.d_tag; value = d.d_un.d_val;
            } else {
                Elf32_Dyn d;
                memcpy(&d, v->data + p.p_offset + offset, sizeof(d));
                tag = d.d_tag; value = d.d_un.d_val;
            }
            if (tag == DT_NULL) { terminated = 1; break; }
            for (unsigned int t = 0; t < tag_count; t++) {
                if (tag != tags[t]) continue;
                if ((*seen & (1u << t)) && values[t] != value) return 0;
                *seen |= 1u << t;
                values[t] = value;
                break;
            }
        }
        if (!terminated) return 0;
    }
    return 1;
}

/* Section metadata must identify the same symbol names that the loader uses.
 * Otherwise an intact relocation table can be hidden by linking it to dummy
 * symbols/strings, and inline extraction can silently lose its monitored names. */
static int elf_runtime_symbols_supported(void *map, size_t sz, int is64) {
    struct elf_reloc_view v = elf_runtime_view(map, sz, is64);
    enum { SYM_ADDR, STR_ADDR, SYM_ENT, STR_SIZE, SYSV_HASH, GNU_HASH, TAG_COUNT };
    const int64_t tags[TAG_COUNT] = {
        DT_SYMTAB, DT_STRTAB, DT_SYMENT, DT_STRSZ, DT_HASH, DT_GNU_HASH
    };
    uint64_t values[TAG_COUNT] = {0};
    unsigned int seen;
    int dynamic;
    if (!elf_dynamic_values(&v, tags, TAG_COUNT, values, &seen, &dynamic)) return 0;
    if (!dynamic) return 1; /* Static ELF has no runtime dynamic metadata. */
    uint64_t entry_size = is64 ? sizeof(Elf64_Sym) : sizeof(Elf32_Sym);
    if ((seen & 15u) != 15u || values[SYM_ENT] != entry_size ||
        !values[STR_SIZE]) return 0;

    int sym_section = -1;
    uint64_t nsym = 0;
    for (unsigned int i = 0; i < v.shnum; i++) {
        Elf64_Shdr s = elf_reloc_shdr(&v, i);
        if (s.sh_type != SHT_DYNSYM) continue;
        if (sym_section >= 0 || !(s.sh_flags & SHF_ALLOC) ||
            s.sh_addr != values[SYM_ADDR] || s.sh_entsize != entry_size ||
            s.sh_size < entry_size || s.sh_size % entry_size ||
            s.sh_link >= v.shnum ||
            !elf_reloc_mapped(&v, s.sh_addr, s.sh_offset, s.sh_size)) return 0;
        Elf64_Shdr strings = elf_reloc_shdr(&v, s.sh_link);
        if (strings.sh_type != SHT_STRTAB || !(strings.sh_flags & SHF_ALLOC) ||
            strings.sh_addr != values[STR_ADDR] || strings.sh_size != values[STR_SIZE] ||
            !elf_reloc_mapped(&v, strings.sh_addr, strings.sh_offset, strings.sh_size))
            return 0;
        sym_section = (int)i;
        nsym = s.sh_size / entry_size;
    }
    if (sym_section < 0) return 0;
    if ((seen & (1u << SYSV_HASH)) &&
        !elf_symbol_hash_supported(&v, values[SYSV_HASH], nsym, 0)) return 0;
    if ((seen & (1u << GNU_HASH)) &&
        !elf_symbol_hash_supported(&v, values[GNU_HASH], nsym, 1)) return 0;
    for (unsigned int i = 0; i < v.shnum; i++) {
        Elf64_Shdr s = elf_reloc_shdr(&v, i);
        if ((s.sh_type != SHT_REL && s.sh_type != SHT_RELA) ||
            !(s.sh_flags & SHF_ALLOC)) continue;
        size_t rel_size = is64
            ? (s.sh_type == SHT_RELA ? sizeof(Elf64_Rela) : sizeof(Elf64_Rel))
            : (s.sh_type == SHT_RELA ? sizeof(Elf32_Rela) : sizeof(Elf32_Rel));
        if (s.sh_link != (unsigned int)sym_section || s.sh_entsize != rel_size ||
            s.sh_size % rel_size || !elf_reloc_range(v.size, s.sh_offset, s.sh_size)) return 0;
        for (uint64_t offset = 0; offset < s.sh_size; offset += rel_size) {
            uint64_t index;
            if (is64) {
                Elf64_Rel rel;
                memcpy(&rel, v.data + s.sh_offset + offset, sizeof(rel));
                index = ELF64_R_SYM(rel.r_info);
            } else {
                Elf32_Rel rel;
                memcpy(&rel, v.data + s.sh_offset + offset, sizeof(rel));
                index = ELF32_R_SYM(rel.r_info);
            }
            if (index >= nsym) return 0;
        }
    }
    return 1;
}

static int elf_runtime_relocations_supported(void *map, size_t sz, int is64) {
    struct elf_reloc_view v = elf_runtime_view(map, sz, is64);
    enum { REL_ADDR, REL_SIZE, REL_ENT, RELA_ADDR, RELA_SIZE, RELA_ENT,
           PLT_ADDR, PLT_SIZE, PLT_KIND, TAG_COUNT };
    const int64_t tags[TAG_COUNT] = {
        DT_REL, DT_RELSZ, DT_RELENT, DT_RELA, DT_RELASZ, DT_RELAENT,
        DT_JMPREL, DT_PLTRELSZ, DT_PLTREL
    };
    uint64_t values[TAG_COUNT] = {0};
    unsigned int seen;
    int dynamic;
    if (!elf_dynamic_values(&v, tags, TAG_COUNT, values, &seen, &dynamic)) return 0;

    unsigned int supported = is64 ? RELA_ADDR : REL_ADDR;
    uint32_t section_type = is64 ? SHT_RELA : SHT_REL;
    uint64_t entry_size = is64 ? sizeof(Elf64_Rela) : sizeof(Elf32_Rel);
    for (unsigned int t = REL_ADDR; t <= RELA_ADDR; t += 3) {
        if ((seen & (1u << t)) && !(seen & (1u << (t + 1)))) return 0;
        if (!values[t + 1]) continue;
        if (t != supported || !(seen & (1u << t)) ||
            !(seen & (1u << (t + 2))) || values[t + 2] != entry_size ||
            !elf_reloc_table(&v, values[t], values[t + 1], section_type, entry_size))
            return 0;
    }
    if ((seen & (1u << PLT_ADDR)) && !(seen & (1u << PLT_SIZE))) return 0;
    if (values[PLT_SIZE]) {
        if (!(seen & (1u << PLT_ADDR)) || !(seen & (1u << PLT_KIND)) ||
            values[PLT_KIND] != (uint64_t)(is64 ? DT_RELA : DT_REL) ||
            ((seen & (1u << (supported + 2))) && values[supported + 2] != entry_size) ||
            !elf_reloc_table(&v, values[PLT_ADDR], values[PLT_SIZE], section_type, entry_size))
            return 0;
    }
    return 1;
}

#endif /* ELF_VALIDATION_H */
