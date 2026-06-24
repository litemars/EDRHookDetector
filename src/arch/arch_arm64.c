#include "arch_arm64.h"

static int32_t get_branch_offset(uint32_t insn) {
    uint32_t imm26 = insn & 0x03FFFFFFu;
    int32_t offset = (int32_t)(imm26 << 2u);
    if (offset & (int32_t)0x08000000) offset |= (int32_t)0xF0000000;
    return offset;
}

static int is_syscall_cp_stub(const uint32_t *insns) {
    return (insns[0] == ARM64_NOP &&
            (insns[1] & ARM64_MOV_IMM_MASK) == ARM64_MOV_IMM &&
            (insns[2] & ARM64_SVC_MASK) == ARM64_SVC);
}

static int is_plt_stub(const uint32_t *insns) {
    return ((insns[0] & ARM64_ADRP_MASK) == ARM64_ADRP &&
            (insns[1] & ARM64_LDR_MASK)  == ARM64_LDR);
}

static int is_function_epilogue(const uint32_t *insns) {
    for (int i = 0; i < 4; i++) {
        if (insns[i] == ARM64_RET) return 1;
    }
    return 0;
}

static int is_tail_call_optimization(const uint32_t *insns) {
    if ((insns[0] & ARM64_B_MASK) == ARM64_B_OPCODE) {
        int32_t offset = get_branch_offset(insns[0]);
        if (offset < 0 || (offset > 0 && offset < 0x200)) return 1;
    }
    return 0;
}

static int is_wrapper_function(const uint32_t *insns) {
    if ((insns[0] & ARM64_B_MASK) == ARM64_B_OPCODE) {
        int32_t offset = get_branch_offset(insns[0]);
        if (offset > 0 && offset <= 32) return 1;
    }
    return 0;
}

static int is_alternative_implementation(const uint32_t *disk, const uint32_t *mem) {
    int disk_has_code = 0;
    int mem_early_ret = 0;

    for (int i = 0; i < 4; i++) {
        if (disk[i] != ARM64_NOP && disk[i] != 0) { disk_has_code = 1; break; }
    }
    for (int i = 0; i < 3; i++) {
        if (mem[i] == ARM64_RET) { mem_early_ret = 1; break; }
    }
    return (disk_has_code && mem_early_ret);
}

static int is_indirect_branch(uint32_t insn) {
    return ((insn & ARM64_BR_MASK)  == ARM64_BR_OPCODE ||
            (insn & ARM64_BLR_MASK) == ARM64_BLR_OPCODE);
}

static int is_branch_with_link(uint32_t insn) {
    return (insn & ARM64_BL_MASK) == ARM64_BL_OPCODE;
}

static int is_movz(uint32_t insn) { return (insn & ARM64_MOVZ_MASK) == ARM64_MOVZ; }
static int is_movk(uint32_t insn) { return (insn & ARM64_MOVK_MASK) == ARM64_MOVK; }

/* movz/movk.../br(Xn) — canonical 64-bit absolute-address trampoline. Opens
 * with a MOV so the branch scorer misses it; requires a consistent register
 * across the whole chain to keep false positives low. */
static int is_movz_movk_br(const uint32_t *insns) {
    if (!is_movz(insns[0])) return 0;
    uint32_t rd = insns[0] & 0x1Fu;
    for (int i = 1; i < CHECK_INSNS; i++) {
        if (is_indirect_branch(insns[i]))
            return (((insns[i] >> 5) & 0x1Fu) == rd);   /* BR/BLR Xrd */
        if (!is_movk(insns[i]) || (insns[i] & 0x1Fu) != rd) return 0;
    }
    return 0;
}

static int is_landing_pad(uint32_t insn) {
    return ((insn & ARM64_BTI_MASK) == ARM64_BTI) ||       /* bti / bti c/j/jc */
           insn == ARM64_PACIASP || insn == ARM64_PACIBSP;  /* paciasp/pacibsp */
}

static HookConfidence arm64_score(const uint32_t *disk, const uint32_t *mem) {
    if (is_syscall_cp_stub(disk))             return HOOK_CONFIDENCE_NONE;
    if (is_plt_stub(disk))                    return HOOK_CONFIDENCE_NONE;
    if (is_wrapper_function(disk))            return HOOK_CONFIDENCE_NONE;
    if (is_tail_call_optimization(mem))       return HOOK_CONFIDENCE_NONE;
    if (is_function_epilogue(mem))            return HOOK_CONFIDENCE_NONE;
    if (is_alternative_implementation(disk, mem)) return HOOK_CONFIDENCE_NONE;

    /* Absolute-address MOV/BR trampoline introduced in memory. */
    if (is_movz_movk_br(mem) && !is_movz_movk_br(disk))
        return HOOK_CONFIDENCE_HIGH;

    int score = 0;
    int disk_has_svc = 0, mem_has_svc = 0;

    for (int i = 0; i < CHECK_INSNS; i++) {
        if ((disk[i] & ARM64_SVC_MASK) == ARM64_SVC) disk_has_svc = 1;
        if ((mem[i]  & ARM64_SVC_MASK) == ARM64_SVC) mem_has_svc  = 1;
    }

    /* HIGH confidence: syscall removed from memory */
    if (disk_has_svc && !mem_has_svc) {
        if ((mem[0] & ARM64_B_MASK) == ARM64_B_OPCODE) {
            int32_t offset = get_branch_offset(mem[0]);
            if ((offset > 0 && offset < 0x1000) || (offset < 0 && offset > -0x1000))
                return HOOK_CONFIDENCE_NONE;
        }
        score += 3;
    }

    /* Unconditional branch added where there wasn't one */
    if ((mem[0]  & ARM64_B_MASK) == ARM64_B_OPCODE &&
        (disk[0] & ARM64_B_MASK) != ARM64_B_OPCODE) {
        if (disk[0] != ARM64_NOP && !is_plt_stub(disk)) {
            int32_t offset = get_branch_offset(mem[0]);
            score += (offset > 0x100000 || offset < -0x100000) ? 3 : 1;
        }
    }

    if (is_indirect_branch(mem[0]) && !is_indirect_branch(disk[0])) score += 2;
    if (is_branch_with_link(mem[0]) && !is_branch_with_link(disk[0])) score += 2;

    if (score >= 3) return HOOK_CONFIDENCE_HIGH;
    if (score >= 2) return HOOK_CONFIDENCE_MEDIUM;
    if (score >= 1) return HOOK_CONFIDENCE_LOW;
    return HOOK_CONFIDENCE_NONE;
}

/* Hooks that preserve the landing pad and redirect from instruction 2 slip past
 * the entry check. Re-score the post-pad body when both images share the opener. */
HookConfidence detect_hook_confidence_arm64(const uint32_t *disk, const uint32_t *mem) {
    HookConfidence c = arm64_score(disk, mem);
    if (c == HOOK_CONFIDENCE_NONE && disk[0] == mem[0] && is_landing_pad(disk[0])) {
        uint32_t d2[CHECK_INSNS], m2[CHECK_INSNS];
        for (int i = 0; i < CHECK_INSNS - 1; i++) { d2[i] = disk[i + 1]; m2[i] = mem[i + 1]; }
        d2[CHECK_INSNS - 1] = ARM64_NOP;
        m2[CHECK_INSNS - 1] = ARM64_NOP;
        c = arm64_score(d2, m2);
    }
    return c;
}
