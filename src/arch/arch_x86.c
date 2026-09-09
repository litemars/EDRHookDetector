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

static int modrm_extra(const uint8_t *buf, int buf_len, int pos, int adsz16) {
    if (pos >= buf_len) return 1;
    uint8_t modrm = buf[pos];
    int mod = (modrm >> 6) & 3;
    int rm  =  modrm       & 7;
    int len = 1;

    if (mod == 3) return len;

    if (adsz16) {
        if (mod == 0 && rm == 6) len += 2;
        else if (mod == 1) len += 1;
        else if (mod == 2) len += 2;
        return len;
    }

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

enum {
    IMM_NONE  = 0,
    IMM_1     = 1,   /* ib  — imm8                                        */
    IMM_2     = 2,   /* iw  — imm16                                       */
    IMM_Z     = 3,   /* iz  — imm16/32; REX.W forces sign-extended imm32  */
    IMM_V     = 4,   /* iv  — imm16/32/64 (MOV r,imm; REX.W ⇒ 64)         */
    IMM_MOFFS = 5,   /* moffs — address-size immediate (MOV AL/eAX,[imm]) */
    IMM_ENTER = 6,   /* ENTER — iw + ib = 3 bytes                         */
    IMM_GRP3  = 7,   /* F6/F7 — imm only for /0,/1 (TEST); reg-dependent  */
    IMM_REL   = 8,   /* near rel — rel16/32 (64-bit forces rel32)         */
    IMM_PUSH  = 9    /* PUSH imm16/32: 66H applies even with REX.W       */
};

static int imm_len(int cls, int opsz16, int rexw, int is_64bit, int adsz) {
    switch (cls) {
        case IMM_1:     return 1;
        case IMM_2:     return 2;
        case IMM_Z:     return (opsz16 && !rexw) ? 2 : 4;
        case IMM_PUSH:  return opsz16 ? 2 : 4;
        case IMM_V:     return rexw ? 8 : (opsz16 ? 2 : 4);
        case IMM_ENTER: return 3;
        case IMM_REL:   return (opsz16 && !is_64bit) ? 2 : 4;
        case IMM_MOFFS: return is_64bit ? (adsz ? 4 : 8) : (adsz ? 2 : 4);
        default:        return 0;
    }
}
static const uint8_t onebyte_modrm[256] = {
/*        0 1 2 3 4 5 6 7 8 9 A B C D E F */
/*00*/    1,1,1,1,0,0,0,0, 1,1,1,1,0,0,0,0,
/*10*/    1,1,1,1,0,0,0,0, 1,1,1,1,0,0,0,0,
/*20*/    1,1,1,1,0,0,0,0, 1,1,1,1,0,0,0,0,
/*30*/    1,1,1,1,0,0,0,0, 1,1,1,1,0,0,0,0,
/*40*/    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
/*50*/    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
/*60*/    0,0,1,1,0,0,0,0, 0,1,0,1,0,0,0,0,
/*70*/    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
/*80*/    1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,
/*90*/    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
/*A0*/    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
/*B0*/    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
/*C0*/    1,1,0,0,0,0,1,1, 0,0,0,0,0,0,0,0,
/*D0*/    1,1,1,1,0,0,0,0, 1,1,1,1,1,1,1,1,
/*E0*/    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
/*F0*/    0,0,0,0,0,0,1,1, 0,0,0,0,0,0,1,1
};

static const uint8_t onebyte_imm[256] = {
/*        0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F */
/*00*/    0,0,0,0,IMM_1,IMM_Z,0,0, 0,0,0,0,IMM_1,IMM_Z,0,0,
/*10*/    0,0,0,0,IMM_1,IMM_Z,0,0, 0,0,0,0,IMM_1,IMM_Z,0,0,
/*20*/    0,0,0,0,IMM_1,IMM_Z,0,0, 0,0,0,0,IMM_1,IMM_Z,0,0,
/*30*/    0,0,0,0,IMM_1,IMM_Z,0,0, 0,0,0,0,IMM_1,IMM_Z,0,0,
/*40*/    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
/*50*/    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
/*60*/    0,0,0,0,0,0,0,0, IMM_PUSH,IMM_Z,IMM_1,IMM_1,0,0,0,0,
/*70*/    IMM_1,IMM_1,IMM_1,IMM_1,IMM_1,IMM_1,IMM_1,IMM_1, IMM_1,IMM_1,IMM_1,IMM_1,IMM_1,IMM_1,IMM_1,IMM_1,
/*80*/    IMM_1,IMM_Z,IMM_1,IMM_1,0,0,0,0, 0,0,0,0,0,0,0,0,
/*90*/    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
/*A0*/    IMM_MOFFS,IMM_MOFFS,IMM_MOFFS,IMM_MOFFS,0,0,0,0, IMM_1,IMM_Z,0,0,0,0,0,0,
/*B0*/    IMM_1,IMM_1,IMM_1,IMM_1,IMM_1,IMM_1,IMM_1,IMM_1, IMM_V,IMM_V,IMM_V,IMM_V,IMM_V,IMM_V,IMM_V,IMM_V,
/*C0*/    IMM_1,IMM_1,IMM_2,0,0,0,IMM_1,IMM_Z, IMM_ENTER,0,IMM_2,0,0,IMM_1,0,0,
/*D0*/    0,0,0,0,IMM_1,IMM_1,0,0, 0,0,0,0,0,0,0,0,
/*E0*/    IMM_1,IMM_1,IMM_1,IMM_1,IMM_1,IMM_1,IMM_1,IMM_1, IMM_REL,IMM_REL,0,IMM_1,0,0,0,0,
/*F0*/    0,0,0,0,0,0,IMM_GRP3,IMM_GRP3, 0,0,0,0,0,0,0,0
};

/* Two-byte (0F xx) map. 0F 38 / 0F 3A three-byte escapes are handled before
 * these are consulted. Most 0F opcodes take a ModRM and no immediate. */
static int two_has_modrm(uint8_t op2) {
    if (op2 >= 0x80 && op2 <= 0x8F) return 0;      /* Jcc near */
    switch (op2) {
        case 0x05: case 0x06: case 0x07: case 0x08: case 0x09:
        case 0x0B: case 0x0E:
        case 0x30: case 0x31: case 0x32: case 0x33: case 0x34:
        case 0x35: case 0x37:
        case 0x77:
        case 0xA0: case 0xA1: case 0xA2: case 0xA8: case 0xA9: case 0xAA:
        case 0xC8: case 0xC9: case 0xCA: case 0xCB:
        case 0xCC: case 0xCD: case 0xCE: case 0xCF:
            return 0;
        default:
            return 1;
    }
}

static int two_imm_class(uint8_t op2) {
    if (op2 >= 0x80 && op2 <= 0x8F) return IMM_REL;
    switch (op2) {
        case 0x70: case 0x71: case 0x72: case 0x73:   /* pshuf / group shift imm8 */
        case 0xA4: case 0xAC:                         /* SHLD/SHRD imm8            */
        case 0xBA:                                    /* group8 BT imm8            */
        case 0xC2: case 0xC4: case 0xC5: case 0xC6:   /* cmpps/pinsr/pextr/shuf    */
        case 0x0F:                                    /* 3DNow! trailing imm8      */
            return IMM_1;
        default:
            return IMM_NONE;
    }
}

/* Almost every VEX/EVEX opcode takes a ModRM; vzeroupper/vzeroall (0F 77) is
 * the notable exception and must not consume a spurious ModRM byte. */
static int vex_has_modrm(int map, uint8_t op) {
    return !(map == 1 && op == 0x77);
}

/* VEX/EVEX immediate: 0F3A carries an imm8; a handful of 0F ops do too. */
static int vex_imm(int map, uint8_t op) {
    if (map == 3) return 1;                           /* 0F 3A: always imm8 */
    if (map == 1) {
        switch (op) {
            case 0x70: case 0x71: case 0x72: case 0x73:
            case 0xC2: case 0xC4: case 0xC5: case 0xC6:
                return 1;
        }
    }
    return 0;                                          /* 0F 38 and the rest */
}

static int x86_decode_insn(const uint8_t *buf, int buf_len, int is_64bit,
                            X86InsnInfo *out) {
    memset(out, 0, sizeof(*out));
    if (buf_len <= 0) { out->length = 1; return 1; }

    int pos    = 0;
    int opsz16 = 0;   /* 0x66 operand-size override seen */
    int adsz   = 0;   /* 0x67 address-size override seen */
    int rexw   = 0;   /* REX.W                           */

    for (;;) {
        if (pos >= buf_len) break;
        uint8_t b = buf[pos];
        if      (b == 0x66) { opsz16 = 1; pos++; }
        else if (b == 0x67) { adsz   = 1; pos++; }
        else if (b == 0xF0 || b == 0xF2 || b == 0xF3 ||
                 b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
                 b == 0x64 || b == 0x65) {
            pos++;
        } else {
            break;
        }
    }

    /* VEX/EVEX supersede REX and encode their own map + immediate. Only their
     * length matters here (no branch/syscall semantics live behind them). */
    if (pos < buf_len && buf[pos] == 0xC5) {             /* 2-byte VEX (map=0F) */
        pos += 2;
        if (pos < buf_len) {
            uint8_t vop = buf[pos++];
            if (vex_has_modrm(1, vop)) pos += modrm_extra(buf, buf_len, pos, !is_64bit && adsz);
            pos += vex_imm(1, vop);
        }
        out->length = pos ? pos : 1;
        return out->length;
    }
    if (pos < buf_len && buf[pos] == 0xC4) {             /* 3-byte VEX */
        int map = (pos + 1 < buf_len) ? (buf[pos + 1] & 0x1F) : 1;
        pos += 3;
        if (pos < buf_len) {
            uint8_t vop = buf[pos++];
            if (vex_has_modrm(map, vop)) pos += modrm_extra(buf, buf_len, pos, !is_64bit && adsz);
            pos += vex_imm(map, vop);
        }
        out->length = pos ? pos : 1;
        return out->length;
    }
    if (is_64bit && pos < buf_len && buf[pos] == 0x62) { /* EVEX (64-bit) */
        int map = (pos + 1 < buf_len) ? (buf[pos + 1] & 0x07) : 1;
        pos += 4;
        if (pos < buf_len) {
            uint8_t vop = buf[pos++];
            if (vex_has_modrm(map, vop)) pos += modrm_extra(buf, buf_len, pos, !is_64bit && adsz);
            pos += vex_imm(map, vop);
        }
        out->length = pos ? pos : 1;
        return out->length;
    }

    /* REX exists only on x86-64; on i386 0x40-0x4F are INC/DEC opcodes. */
    if (is_64bit && pos < buf_len && (buf[pos] & 0xF0) == 0x40) {
        rexw = (buf[pos] & 0x08) != 0;
        pos++;
    }

    if (pos >= buf_len) { out->length = pos ? pos : 1; return out->length; }

    uint8_t op = buf[pos++];

    if (op == 0x0F) {
        if (pos >= buf_len) { out->length = pos; return pos; }
        uint8_t op2 = buf[pos++];

        /* 0F 38 (SSSE3/SSE4/AES-NI): third opcode byte + ModRM, no imm. */
        if (op2 == 0x38) {
            if (pos < buf_len) pos++;
            pos += modrm_extra(buf, buf_len, pos, !is_64bit && adsz);
            out->length = pos ? pos : 1;
            return out->length;
        }
        /* 0F 3A (ROUNDSS/PALIGNR…): third opcode byte + ModRM + imm8. */
        if (op2 == 0x3A) {
            if (pos < buf_len) pos++;
            pos += modrm_extra(buf, buf_len, pos, !is_64bit && adsz);
            if (pos < buf_len) pos++;
            out->length = pos ? pos : 1;
            return out->length;
        }

        if      (op2 == 0x05 || op2 == 0x34) out->is_syscall = 1;  /* SYSCALL/SYSENTER */
        else if (op2 == 0x1F)                out->is_nop     = 1;  /* multi-byte NOP   */

        if (two_has_modrm(op2))
            pos += modrm_extra(buf, buf_len, pos, !is_64bit && adsz);
        pos += imm_len(two_imm_class(op2), opsz16, rexw, is_64bit, adsz);

        out->length = pos ? pos : 1;
        return out->length;
    }

    /* One-byte opcode. Set the semantics the scorer relies on, then size the
     * ModRM block and immediate from the tables. */
    if      (op == 0x90)                                out->is_nop = 1;
    else if (op == 0xC3 || op == 0xCB ||
             op == 0xC2 || op == 0xCA)                  out->is_ret = 1;

    int reg = -1;
    if (onebyte_modrm[op]) {
        if (pos < buf_len) reg = (buf[pos] >> 3) & 7;
        if (op == 0xFF && (reg == 2 || reg == 4)) {     /* JMP/CALL r/m */
            out->is_indirect_branch = 1;
            out->is_call = reg == 2;
        }
        pos += modrm_extra(buf, buf_len, pos, !is_64bit && adsz);
    }

    int icls = onebyte_imm[op];
    if (icls == IMM_GRP3)                               /* F6/F7: imm only for /0,/1 */
        icls = (reg == 0 || reg == 1)
                 ? (op == 0xF6 ? IMM_1 : IMM_Z)
                 : IMM_NONE;
    int il = imm_len(icls, opsz16, rexw, is_64bit, adsz);

    if (op == 0xE9 && pos + il <= buf_len) {            /* JMP rel */
        if (il >= 4) memcpy(&out->branch_offset, buf + pos, 4);
        out->is_direct_jump = 1;
    } else if (op == 0xE8 && pos + il <= buf_len) {     /* CALL rel — kept
             * separate from jumps so the short-jump allowlist can't suppress
             * hooks on call-first thunks. */
        if (il >= 4) memcpy(&out->branch_offset, buf + pos, 4);
        out->is_call = 1;
    } else if (op == 0xEB && pos < buf_len) {           /* JMP rel8 */
        out->branch_offset = (int32_t)(int8_t)buf[pos];
        out->is_direct_jump = 1;
    } else if (op == 0xCD && pos < buf_len && buf[pos] == 0x80) {
        out->is_syscall = 1;                            /* int 0x80 */
    }

    pos += il;
    out->length = pos ? pos : 1;
    return out->length;
}

static int x86_decode_sequence(const uint8_t *buf, int len, int is_64bit,
                                X86InsnInfo *out, int max_out) {
    int pos = 0, n = 0;
    while (pos < len && n < max_out) {
        int consumed = x86_decode_insn(buf + pos, len - pos, is_64bit, &out[n]);
        if (consumed <= 0 || consumed > len - pos || consumed > 15) break;
        out[n].length = consumed;
        n++;
        pos += consumed;
    }
    return n;
}

static int has_early_ret(const X86InsnInfo *insns, int count) {
    for (int i = 0; i < count && i < 5; i++) {
        if (insns[i].is_ret) return 1;
        if (insns[i].is_direct_jump ||
            (insns[i].is_indirect_branch && !insns[i].is_call)) return 0;
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
    int mov_reg = (m[1] & 7) | ((m[0] & 1) << 3);
    int pos = 10, jump_rex = 0;
    if ((m[pos] & 0xF0) == 0x40) {
        if (len < 13) return 0;
        jump_rex = m[pos++];
    }
    if (m[pos] != 0xFF || (m[pos + 1] & 0xF8) != 0xE0) return 0;
    int jump_reg = (m[pos + 1] & 7) | ((jump_rex & 1) << 3);
    return mov_reg == jump_reg;
}

#define MAX_INSNS_X86 24

static HookConfidence x86_score(const uint8_t *disk,
                                const uint8_t *mem, int len,
                                int is_64bit) {
    X86InsnInfo disk_insns[MAX_INSNS_X86];
    X86InsnInfo mem_insns[MAX_INSNS_X86];

    int dn = x86_decode_sequence(disk, len, is_64bit, disk_insns, MAX_INSNS_X86);
    int mn = x86_decode_sequence(mem,  len, is_64bit, mem_insns,  MAX_INSNS_X86);

    /* No real function opens this way, so any match here is a hook. */
    if (is_64bit && (is_push_ret_tramp(mem, len) || is_mov_imm_jmp_tramp(mem, len)))
        return HOOK_CONFIDENCE_HIGH;

    if (has_early_ret(mem_insns, mn) && disk_has_real_code(disk, len)) {
        if (!has_early_ret(disk_insns, dn)) return HOOK_CONFIDENCE_HIGH;
    }

    int score = 0;

    int disk_has_syscall = 0, mem_has_syscall = 0;
    for (int i = 0; i < dn; i++) if (disk_insns[i].is_syscall) { disk_has_syscall = 1; break; }
    for (int i = 0; i < mn; i++) if (mem_insns[i].is_syscall)  { mem_has_syscall  = 1; break; }

    if (disk_has_syscall && !mem_has_syscall) {
        score += 3;
    }

    if (mn > 0 && mem_insns[0].is_direct_jump &&
        (dn == 0 || !disk_insns[0].is_direct_jump)) {
        int32_t off = mem_insns[0].branch_offset;
        score += (off > 0x100000 || off < -0x100000) ? 3 : 1;
    }

    if (mn > 0 && mem_insns[0].is_indirect_branch &&
        (dn == 0 || !disk_insns[0].is_indirect_branch)) {
        score += 2;
    }

    if (score >= 3) return HOOK_CONFIDENCE_HIGH;
    if (score >= 2) return HOOK_CONFIDENCE_MEDIUM;
    if (score >= 1) return HOOK_CONFIDENCE_LOW;
    return HOOK_CONFIDENCE_LOW;
}

static int is_endbr64(const uint8_t *buf, int len) {
    return (len >= 4 &&
            buf[0] == 0xF3 && buf[1] == 0x0F &&
            buf[2] == 0x1E && buf[3] == 0xFA);
}

HookConfidence detect_hook_confidence_x86(const uint8_t *disk,
                                          const uint8_t *mem, int len,
                                          int is_64bit) {
    HookConfidence c = x86_score(disk, mem, len, is_64bit);
    if (c < HOOK_CONFIDENCE_HIGH && is_64bit && len > 4 &&
        is_endbr64(disk, len) && is_endbr64(mem, len)) {
        HookConfidence c2 = x86_score(disk + 4, mem + 4, len - 4, is_64bit);
        if (c2 > c) c = c2;
    }
    return c;
}
