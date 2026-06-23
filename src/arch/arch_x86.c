#include <string.h>
#include "arch_x86.h"

typedef struct {
    int     length;
    int     is_syscall;
    int     is_direct_jump;
    int     is_call;
    int     is_indirect_branch;
    int     is_ret;
    int     is_nop;
    int32_t branch_offset;
} X86InsnInfo;

static int modrm_extra(const uint8_t *buf, int buf_len, int pos) {
    if (pos >= buf_len) return 1;
    uint8_t modrm = buf[pos];
    int mod = (modrm >> 6) & 3;
    int rm  =  modrm       & 7;
    int len = 1;

    if (mod == 3) return len;

    if (rm == 4) {
        len++;
        if (mod == 0 && pos + 1 < buf_len && (buf[pos + 1] & 7) == 5)
            len += 4;
    } else if (mod == 0 && rm == 5) {
        len += 4;
    }

    if      (mod == 1) len += 1;
    else if (mod == 2) len += 4;

    return len;
}

static int x86_decode_insn(const uint8_t *buf, int buf_len, int is_64bit,
                            X86InsnInfo *out) {
    memset(out, 0, sizeof(*out));
    if (buf_len <= 0) { out->length = 1; return 1; }

    int pos = 0;

    for (;;) {
        if (pos >= buf_len) break;
        uint8_t b = buf[pos];
        if (b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 ||
            b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
            b == 0x64 || b == 0x65) {
            pos++;
        } else {
            break;
        }
    }

    /* REX exists only on x86-64; on i386 0x40-0x4F are INC/DEC opcodes. */
    if (is_64bit && pos < buf_len && (buf[pos] & 0xF0) == 0x40)
        pos++;

    if (pos >= buf_len) { out->length = pos ? pos : 1; return out->length; }

    uint8_t op = buf[pos++];

    if (op == 0x0F) {
        if (pos >= buf_len) { out->length = pos; return pos; }
        uint8_t op2 = buf[pos++];
        switch (op2) {
            case 0x05:
            case 0x34:
                out->is_syscall = 1;
                break;
            case 0x1F:
                out->is_nop = 1;
                pos += modrm_extra(buf, buf_len, pos);
                break;
            case 0x38:
                /* 0F 38 (SSSE3/SSE4/AES-NI): opcode + ModRM, no imm. */
                if (pos < buf_len) pos++;            /* third opcode byte */
                pos += modrm_extra(buf, buf_len, pos);
                break;
            case 0x3A:
                /* 0F 3A (ROUNDSS/PALIGNR…): opcode + ModRM + imm8. */
                if (pos < buf_len) pos++;            /* third opcode byte */
                pos += modrm_extra(buf, buf_len, pos);
                if (pos < buf_len) pos++;            /* imm8 */
                break;
            default:
                break;
        }
        out->length = pos;
        return pos;
    }

    switch (op) {

        case 0x90:
            out->is_nop = 1;
            break;

        case 0xC3: case 0xCB:
            out->is_ret = 1;
            break;

        case 0xC2: case 0xCA:
            out->is_ret = 1;
            pos += 2;
            break;

        case 0xE9:
            if (pos + 4 <= buf_len) {
                memcpy(&out->branch_offset, buf + pos, 4);
                out->is_direct_jump = 1;
                pos += 4;
            }
            break;

        case 0xEB:
            if (pos < buf_len) {
                out->branch_offset = (int32_t)(int8_t)buf[pos++];
                out->is_direct_jump = 1;
            }
            break;

        case 0xE8:
            /* CALL rel32 — kept separate from jumps so the short-jump allowlist
             * doesn't suppress hooks on call-first thunks. */
            if (pos + 4 <= buf_len) {
                memcpy(&out->branch_offset, buf + pos, 4);
                out->is_call = 1;
                pos += 4;
            }
            break;

        case 0xCD:
            if (pos < buf_len && buf[pos] == 0x80)
                out->is_syscall = 1;
            pos += 1;
            break;

        case 0xFF: {
            if (pos >= buf_len) break;
            uint8_t modrm = buf[pos];
            int reg = (modrm >> 3) & 7;
            if (reg == 2 || reg == 4)
                out->is_indirect_branch = 1;
            pos += modrm_extra(buf, buf_len, pos);
            break;
        }

        default:
            break;
    }

    out->length = pos;
    return pos;
}

static int x86_decode_sequence(const uint8_t *buf, int len, int is_64bit,
                                X86InsnInfo *out, int max_out) {
    int pos = 0, n = 0;
    while (pos < len && n < max_out) {
        int consumed = x86_decode_insn(buf + pos, len - pos, is_64bit, &out[n]);
        if (consumed <= 0) consumed = 1;
        out[n].length = consumed;
        n++;
        pos += consumed;
    }
    return n;
}

static int is_endbr64(const uint8_t *buf, int len) {
    return (len >= 4 &&
            buf[0] == 0xF3 && buf[1] == 0x0F &&
            buf[2] == 0x1E && buf[3] == 0xFA);
}

static int is_plt_stub_x86(const uint8_t *buf, int len) {
    return (is_endbr64(buf, len) && len >= 10 &&
            buf[4] == 0xFF && buf[5] == 0x25);
}

static int has_early_ret(const X86InsnInfo *insns, int count) {
    for (int i = 0; i < count && i < 5; i++) {
        if (insns[i].is_ret) return 1;
    }
    return 0;
}

static int disk_has_real_code(const uint8_t *disk, int len) {
    for (int i = 0; i < len && i < 8; i++) {
        if (disk[i] != 0x90 && disk[i] != 0x00) return 1;
    }
    return 0;
}

/* push+ret absolute jump: 6-byte (32-bit) or 14-byte (64-bit). Opens with no
 * branch so the relative-branch scorer misses it. */
static int is_push_ret_tramp(const uint8_t *m, int len) {
    if (len >= 6 && m[0] == 0x68 && m[5] == 0xC3)
        return 1;
    if (len >= 14 && m[0] == 0x68 &&
        m[5] == 0xC7 && m[6] == 0x44 && m[7] == 0x24 && m[8] == 0x04 &&
        m[13] == 0xC3)
        return 1;
    return 0;
}

/* movabs r64,imm64 ; jmp r64 — 12/13-byte absolute jump. mem[0] is the MOV
 * so the indirect-branch check at [0] misses the jump. */
static int is_mov_imm_jmp_tramp(const uint8_t *m, int len) {
    if (len < 12) return 0;
    if ((m[0] & 0xF8) != 0x48) return 0;        /* REX.W (0x48..0x4F) */
    if ((m[1] & 0xF8) != 0xB8) return 0;        /* MOV r64, imm64       */
    /* imm64 occupies m[2..9]; the jmp r64 follows at m[10]. */
    if (m[10] == 0xFF && ((m[11] >> 3) & 7) == 4)            return 1; /* jmp rax..rdi */
    if (len >= 13 && (m[10] & 0xF8) == 0x40 &&              /* REX.B for r8..r15 */
        m[11] == 0xFF && ((m[12] >> 3) & 7) == 4)           return 1;
    return 0;
}

#define MAX_INSNS_X86 24

static HookConfidence x86_score(const uint8_t *disk,
                                const uint8_t *mem, int len,
                                int is_64bit) {
    X86InsnInfo disk_insns[MAX_INSNS_X86];
    X86InsnInfo mem_insns[MAX_INSNS_X86];

    int dn = x86_decode_sequence(disk, len, is_64bit, disk_insns, MAX_INSNS_X86);
    int mn = x86_decode_sequence(mem,  len, is_64bit, mem_insns,  MAX_INSNS_X86);

    if (is_plt_stub_x86(disk, len)) return HOOK_CONFIDENCE_NONE;

    /* No real function opens this way, so any match here is a hook. */
    if (is_64bit && (is_push_ret_tramp(mem, len) || is_mov_imm_jmp_tramp(mem, len)))
        return HOOK_CONFIDENCE_HIGH;

    if (dn > 0 && disk_insns[0].is_direct_jump) {
        int32_t off = disk_insns[0].branch_offset;
        if (off > 0 && off <= 32) return HOOK_CONFIDENCE_NONE;
    }

    if (has_early_ret(mem_insns, mn) && disk_has_real_code(disk, len)) {
        if (!has_early_ret(disk_insns, dn)) return HOOK_CONFIDENCE_NONE;
    }

    if (mn > 0 && mem_insns[0].is_direct_jump) {
        int32_t off = mem_insns[0].branch_offset;
        if (off >= -0x200 && off < 0x200) return HOOK_CONFIDENCE_NONE;
    }

    int score = 0;

    int disk_has_syscall = 0, mem_has_syscall = 0;
    for (int i = 0; i < dn; i++) if (disk_insns[i].is_syscall) { disk_has_syscall = 1; break; }
    for (int i = 0; i < mn; i++) if (mem_insns[i].is_syscall)  { mem_has_syscall  = 1; break; }

    if (disk_has_syscall && !mem_has_syscall) {
        if (mn > 0 && mem_insns[0].is_direct_jump) {
            int32_t off = mem_insns[0].branch_offset;
            if (off > -0x1000 && off < 0x1000) return HOOK_CONFIDENCE_NONE;
        }
        score += 3;
    }

    if (mn > 0 && mem_insns[0].is_direct_jump &&
        (dn == 0 || !disk_insns[0].is_direct_jump)) {
        if (!is_plt_stub_x86(disk, len)) {
            int32_t off = mem_insns[0].branch_offset;
            score += (off > 0x100000 || off < -0x100000) ? 3 : 1;
        }
    }

    if (mn > 0 && mem_insns[0].is_indirect_branch &&
        (dn == 0 || !disk_insns[0].is_indirect_branch)) {
        score += 2;
    }

    if (score >= 3) return HOOK_CONFIDENCE_HIGH;
    if (score >= 2) return HOOK_CONFIDENCE_MEDIUM;
    if (score >= 1) return HOOK_CONFIDENCE_LOW;
    return HOOK_CONFIDENCE_NONE;
}

/* Hooks that preserve endbr64 and patch from byte 5 slip past the entry check.
 * Re-score from the post-pad bytes when both images share the opener. */
HookConfidence detect_hook_confidence_x86(const uint8_t *disk,
                                          const uint8_t *mem, int len,
                                          int is_64bit) {
    HookConfidence c = x86_score(disk, mem, len, is_64bit);
    if (c == HOOK_CONFIDENCE_NONE && is_64bit && len > 4 &&
        is_endbr64(disk, len) && is_endbr64(mem, len))
        c = x86_score(disk + 4, mem + 4, len - 4, is_64bit);
    return c;
}
