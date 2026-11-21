#pragma once
#include "except.h"
#include "robust.h"
#include "jove/jove.h"

#include <atomic>
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

template <class Iterator, class Proc>
constexpr bool maybe_par_unseq_for_each(Iterator begin,
                                        Iterator end,
                                        Proc proc) {
  std::atomic_flag Failure = ATOMIC_FLAG_INIT;

  std::for_each(maybe_par_unseq,
                begin, end, [&](auto &elem) -> void {
    std::stringstream ss;
    std::ostream &os = ss;

    std::string exceptmsg;
    const bool threw = jove::handle_exceptions([&] { proc(elem, os); }, exceptmsg);

    auto ss_view = ss.view();
    robust::write(STDOUT_FILENO, ss_view.data(), ss_view.size());
    if (unlikely(threw)) {
      Failure.test_and_set(std::memory_order_relaxed);

      exceptmsg.push_back('\n');
      robust::write(STDERR_FILENO, exceptmsg.c_str(), exceptmsg.size());
    }
  });

  return !Failure.test(std::memory_order_relaxed);
}

} // namespace jove
