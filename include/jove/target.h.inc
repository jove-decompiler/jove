#ifndef IN_JOVE_H
#error "only to be included inline in jove/jove.h"
#endif

static inline std::string taddr2str(taddr_t x, bool zero_padded = true) {
  std::stringstream stream;
  stream << "0x";
  if (zero_padded)
    stream << std::setfill('0') << std::setw(sizeof(taddr_t) * 2);
  stream << std::hex << x;
  return stream.str();
}

constexpr bool is_taddr_valid(taddr_t Addr) {
#ifdef NDEBUG
  // the following is equivalent to Addr != 0UL && Addr != ~0UL
  return !!((Addr + taddr_t(1)) & taddr_t(~1ull));
#else
  // same as the top except also covers uninit_taddr (and one **)
  return !!((Addr + taddr_t(2)) & taddr_t(~3ull));
#endif
}

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
