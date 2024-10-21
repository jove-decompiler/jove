#pragma once
#include <cstdbool>

namespace jove {
namespace racy {

static inline void set(bool &dst) {
#ifdef JOVE_TSAN
  __atomic_store_n(&dst, true, __ATOMIC_RELAXED);
#else
  dst = true;
#endif
}

}
}
