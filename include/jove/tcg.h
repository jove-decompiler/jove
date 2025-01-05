#pragma once

#if defined(TARGET_AARCH64)
#include <jove/tcgconstants-aarch64.h>
#elif defined(TARGET_X86_64)
#include <jove/tcgconstants-x86_64.h>
#elif defined(TARGET_I386)
#include <jove/tcgconstants-i386.h>
#elif defined(TARGET_MIPS64)
#include <jove/tcgconstants-mips64el.h>
#elif defined(TARGET_MIPSEL)
#include <jove/tcgconstants-mipsel.h>
#elif defined(TARGET_MIPS)
#include <jove/tcgconstants-mips.h>
#define TARGET_WORDS_BIGENDIAN
#else
#error "unknown target"
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
