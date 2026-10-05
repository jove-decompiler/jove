#pragma once

//
// x86_64 and arm64 are the only supported host architectures for
// doing cross-recompilation. The below is a little bit funky.
//

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
#include "../bin/i386/tcgconstants.h"

#elif defined(__aarch64__)
#if defined(TARGET_AARCH64)
#include "../bin/aarch64/tcgconstants.h"
#elif defined(TARGET_X86_64)
#include "../bin/aarch64/tcgconstants.x86_64.h"
#elif defined(TARGET_I386)
#include "../bin/aarch64/tcgconstants.i386.h"
#elif defined(TARGET_AARCH64)
#include "../bin/aarch64/tcgconstants.aarch64.h"
#elif defined(TARGET_MIPS64)
#include "../bin/aarch64/tcgconstants.mips64el.h"
#elif defined(TARGET_MIPS32) && defined(TARGET_MIPSEL)
#include "../bin/aarch64/tcgconstants.mipsel.h"
#elif defined(TARGET_MIPS32) && defined(TARGET_MIPS)
#include "../bin/aarch64/tcgconstants.mips.h"
#else
#error
#endif

#elif defined(__mips64)
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error
#endif

#include "../bin/mips64el/tcgconstants.h"

#elif defined(__mips__)
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error
#endif

#include "../bin/mipsel/tcgconstants.h"

#else
#error
#endif

#ifdef __cplusplus
#include <vector>
#include <cstring>
#include <bit>

namespace jove {

using in_const_tcg_global_set_t =
    std::conditional_t<tcg_bitset,
                       const tcg_global_set_t & /* pass by reference */,
                       const tcg_global_set_t   /* pass by value */>;

static inline bool tcg_global_set_is_none(in_const_tcg_global_set_t set) {
#ifdef TCG_BITSET
  return set.none();
#else
  return set == 0u;
#endif
}

static inline unsigned tcg_global_set_count(in_const_tcg_global_set_t set) {
#ifdef TCG_BITSET
  return set.count();
#else
  return std::popcount(set);
#endif
}

static inline void tcg_global_set_reset(tcg_global_set_t &set) {
#ifdef TCG_BITSET
  set.reset();
#else
  set = 0;
#endif
}

static inline void tcg_global_set_set(tcg_global_set_t &set, unsigned idx) {
#ifdef TCG_BITSET
  set.set(idx);
#else
  set |= (tcg_global_set_t{1} << idx);
#endif
}

static inline bool tcg_global_set_test(in_const_tcg_global_set_t set, unsigned idx) {
#ifdef TCG_BITSET
  return set.test(idx);
#else
  return !!(set & (tcg_global_set_t {1} << idx));
#endif
}

static inline void tcg_global_set_reset(tcg_global_set_t &set, unsigned idx) {
#ifdef TCG_BITSET
  set.reset(idx);
#else
  set &= ~(tcg_global_set_t{1} << idx);
#endif
}

static inline std::string tcg_global_set_to_string(in_const_tcg_global_set_t set) {
#ifdef TCG_BITSET
  return set.to_string();
#else
  std::string res(tcg_num_globals, '0');

  for (unsigned i = 0; i < tcg_num_globals; ++i)
    if (tcg_global_set_test(set, i))
      res[tcg_num_globals - 1 - i] = '1';

  return res;
#endif
}

static inline void explode_tcg_global_set(std::vector<unsigned> &out,
                                          in_const_tcg_global_set_t glbs) {
  if (tcg_global_set_is_none(glbs))
    return;

  out.reserve(tcg_global_set_count(glbs));

#ifdef TCG_BITSET
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
#else
  tcg_global_set_t x(glbs);

#pragma clang loop unroll_count(8)
  while (x) {
    unsigned bit = std::countr_zero(x);
    out.push_back(bit);
    x &= x - 1;
  }
#endif
}

}
#endif
