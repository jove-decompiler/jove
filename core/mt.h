#pragma once
#include <algorithm>
#include <functional>
#include <ranges>

namespace jove {
namespace mt {

//
// run fn(i) for i in [0, N).
// propagates the first exception, and stops the rest.
//
#ifdef JOVE_NO_THREADS
static inline void for_n(std::function<void(unsigned)> fn, const unsigned N) {
  std::ranges::for_each(std::views::iota(0u, N), fn);
}
#else
void for_n(std::function<void(unsigned)> fn, const unsigned N);
#endif

} // namespace mt
} // namespace jove
