#ifndef IN_JOVE_H
#error "only to be included inline in jove/jove.h"
#endif

constexpr unsigned IsMIPSTarget =
#if defined(TARGET_MIPS32) || defined(TARGET_MIPS64)
    1
#else
    0
#endif
    ;

constexpr unsigned IsMips64elTarget =
#if defined(TARGET_MIPS64)
    1
#else
    0
#endif
    ;

constexpr unsigned IsX86Target =
#if defined(TARGET_I386) || defined(TARGET_X86_64)
    1
#else
    0
#endif
    ;

constexpr bool IsTarget32 = sizeof(taddr_t) == 4;
constexpr bool IsTarget64 = sizeof(taddr_t) == 8;

static_assert(IsTarget32 || IsTarget64);

constexpr bool IsTargetLittleEndian =
#if defined(TARGET_MIPS32) && defined(TARGET_MIPS)
    false
#else
    true
#endif
    ;

#if defined(TARGET_X86_64)
#define TARGET_SHORT_NAME "x64"
#elif defined(TARGET_I386)
#define TARGET_SHORT_NAME "x86"
#elif defined(TARGET_AARCH64)
#define TARGET_SHORT_NAME "arm64"
#elif defined(TARGET_MIPS64)
#define TARGET_SHORT_NAME "mips64el"
#elif defined(TARGET_MIPS32) && defined(TARGET_MIPSEL)
#define TARGET_SHORT_NAME "mipsel"
#elif defined(TARGET_MIPS32) && defined(TARGET_MIPS)
#define TARGET_SHORT_NAME "mips"
#else
#error
#endif

constexpr const char *TargetStaticLinkerEmulation(bool IsCOFF) {
  if (IsCOFF) {
    return
#if defined(TARGET_X86_64)
        "i386pep"
#elif defined(TARGET_I386)
        "i386pe"
#else
        ""
#endif
        ;
  } else {
    return
#if defined(TARGET_X86_64)
        "elf_x86_64"
#elif defined(TARGET_I386)
        "elf_i386"
#elif defined(TARGET_AARCH64)
        "aarch64linux"
#elif defined(TARGET_MIPS64)
        "elf64ltsmip"
#elif defined(TARGET_MIPS32) && defined(TARGET_MIPSEL)
        "elf32ltsmip"
#elif defined(TARGET_MIPS32) && defined(TARGET_MIPS)
        "elf32btsmip"
#else
#error
#endif
        ;
  }
}
