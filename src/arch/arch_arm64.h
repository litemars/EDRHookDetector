#ifndef ARCH_ARM64_H
#define ARCH_ARM64_H

#include <stdint.h>
#include "common.h"

/* ARM64 instruction encodings */
#define ARM64_NOP           0xd503201fu
#define ARM64_SVC_MASK      0xFFE0001Fu
#define ARM64_SVC           0xd4000001u
#define ARM64_B_MASK        0xFC000000u
#define ARM64_B_OPCODE      0x14000000u
#define ARM64_BL_MASK       0xFC000000u
#define ARM64_BL_OPCODE     0x94000000u
#define ARM64_BR_MASK       0xFFFFFC1Fu
#define ARM64_BR_OPCODE     0xD61F0000u
#define ARM64_BLR_MASK      0xFFFFFC1Fu
#define ARM64_BLR_OPCODE    0xD63F0000u
#define ARM64_RET           0xd65f03c0u
#define ARM64_ADRP_MASK     0x9F000000u
#define ARM64_ADRP          0x90000000u
#define ARM64_LDR_MASK      0xFFC00000u
#define ARM64_LDR           0xF9400000u
#define ARM64_MOV_IMM_MASK  0xFFE00000u
#define ARM64_MOV_IMM       0xD2800000u
/* 64-bit MOVZ / MOVK (any hw shift): top 9 bits select sf=1 + opc + class. */
#define ARM64_MOVZ_MASK     0xFF800000u
#define ARM64_MOVZ          0xD2800000u
#define ARM64_MOVK_MASK     0xFF800000u
#define ARM64_MOVK          0xF2800000u

HookConfidence detect_hook_confidence_arm64(const uint32_t *disk, const uint32_t *mem);

#endif /* ARCH_ARM64_H */
