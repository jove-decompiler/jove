#pragma once
#include "jove/jove.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__x86_64__)
#if defined(TARGET_X86_64)
#include "../bin/x86_64/qemu.tcg.copy.h"
#elif defined(TARGET_I386)
#include "../bin/x86_64/qemu.tcg.copy.i386.h"
#elif defined(TARGET_AARCH64)
#include "../bin/x86_64/qemu.tcg.copy.aarch64.h"
#elif defined(TARGET_MIPS64)
#include "../bin/x86_64/qemu.tcg.copy.mips64el.h"
#elif defined(TARGET_MIPS32) && defined(TARGET_MIPSEL)
#include "../bin/x86_64/qemu.tcg.copy.mipsel.h"
#elif defined(TARGET_MIPS32) && defined(TARGET_MIPS)
#include "../bin/x86_64/qemu.tcg.copy.mips.h"
#else
#error
#endif
#elif defined(__i386__)
#ifdef TARGET_I386
#include "../bin/i386/qemu.tcg.copy.h"
#else
#error
#endif
#elif defined(__aarch64__)
#ifdef TARGET_AARCH64
#include "../bin/aarch64/qemu.tcg.copy.h"
#else
#error
#endif
#elif defined(__mips64) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#ifdef TARGET_MIPS64
#include "../bin/mips64el/qemu.tcg.copy.h"
#else
#error
#endif
#elif defined(__mips__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#ifdef TARGET_MIPSEL
#include "../bin/mipsel/qemu.tcg.copy.h"
#else
#error
#endif
#else
#error
#endif

#ifdef __cplusplus
}
#endif
