#pragma once
#include "jove/jove.h"

namespace jove {

static constexpr const char *glibc_tunables_env =
#if defined(TARGET_X86_64)
    "GLIBC_TUNABLES=glibc.cpu.hwcaps="
    "-AVX,"
    "-AVX2,"
    "-AVX_Usable,"
    "-AVX2_Usable,"
    "-AVX512F_Usable,"
    "-SSE4_1,"
    "-SSE4_2,"
    "-SSSE3,"
    "-Fast_Unaligned_Load,"
    "-ERMS,"
    "-AVX_Fast_Unaligned_Load"
#elif defined(TARGET_I386)
    "GLIBC_TUNABLES=glibc.cpu.hwcaps="
    "-SSE4_1,"
    "-SSE4_2,"
    "-SSSE3,"
    "-Fast_Rep_String,"
    "-Fast_Unaligned_Load,"
    "-SSE2"
#else
    nullptr
#endif
    ;

}
