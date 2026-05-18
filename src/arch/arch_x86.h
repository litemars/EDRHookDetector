#ifndef ARCH_X86_H
#define ARCH_X86_H

#include <stdint.h>
#include "common.h"

HookConfidence detect_hook_confidence_x86(const uint8_t *disk, const uint8_t *mem,
                                           int len, int is_64bit);

#endif /* ARCH_X86_H */
