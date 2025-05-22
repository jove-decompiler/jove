#pragma once

#if defined(__x86_64__)
#if defined(TARGET_X86_64)
#include "../bin/x86_64/tcgconstants.h"
#elif defined(TARGET_I386)
#include "../bin/x86_64/tcgconstants.i386.h"
#elif defined(TARGET_AARCH64)
#include "../bin/x86_64/tcgconstants.aarch64.h"
#elif defined(TARGET_MIPS64)
#include "../bin/x86_64/tcgconstants.mips64el.h"
#elif defined(TARGET_MIPS32) && defined(TARGET_MIPSEL)
#include "../bin/x86_64/tcgconstants.mipsel.h"
#elif defined(TARGET_MIPS32) && defined(TARGET_MIPS)
#include "../bin/x86_64/tcgconstants.mips.h"
#else
#error
#endif
#elif defined(__i386__)
#ifdef TARGET_I386
#include "../bin/i386/tcgconstants.h"
#else
#error
#endif
#elif defined(__aarch64__)
#ifdef TARGET_AARCH64
#include "../bin/aarch64/tcgconstants.h"
#else
#error
#endif
#elif defined(__mips64) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#ifdef TARGET_MIPS64
#include "../bin/mips64el/tcgconstants.h"
#else
#error
#endif
#elif defined(__mips__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#ifdef TARGET_MIPSEL
#include "../bin/mipsel/tcgconstants.h"
#else
#error
#endif
#else
#error
#endif

#ifdef __cplusplus
#include <vector>
#include <cstring>

namespace jove {

static inline void explode_tcg_global_set(std::vector<unsigned> &out,
                                          tcg_global_set_t glbs) {
  if (glbs.none())
    return;

  out.reserve(glbs.count());

  constexpr bool FitsInUnsignedLongLong =
      tcg_num_globals <= sizeof(unsigned long long) * 8;

  if constexpr (FitsInUnsignedLongLong) { /* use ffsll */
    unsigned long long x = glbs.to_ullong();

    int idx = 0;
    do {
      int pos = ffsll(x);
      x >>= pos;
      idx += pos;
      out.push_back(idx - 1);
    } while (x);
  } else {
    for (size_t glb = glbs._Find_first(); glb < glbs.size();
         glb = glbs._Find_next(glb))
      out.push_back(glb);
  }
}

}

#endif
