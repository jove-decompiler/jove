#ifndef JOVE_NO_THREADS
#include "mt.h"
#include "cpu.h"
#include "likely.h"
#include "assert.h"

#include <atomic>
#include <exception>
#include <stop_token>
#include <thread>
//#include <mutex>

namespace jove {
namespace mt {

void for_n(std::function<void(unsigned)> fn, const unsigned N)
{
  if (unlikely(!N))
    return; /* nothing to do */

  const unsigned worker_count = cpu_count();
  assert(worker_count > 0);

  if (unlikely(worker_count == 1)) {
    for (unsigned i = 0; i < N; ++i)
      fn(i);
    return;
  }

  assert(worker_count >= 2);

  std::atomic<unsigned> next = 0;

  std::stop_source stop_src;
  std::exception_ptr pexcept;
  //std::mutex first_mtx;

  auto body = [&](std::stop_token st) -> void {
    for (;;) {
      if (st.stop_requested())
        return;

      const unsigned i = next.fetch_add(1u, std::memory_order_relaxed);
      if (i >= N)
        return;

      try {
        fn(i);
        continue;
      } catch (...) {
        if (stop_src.request_stop()) {
          //std::scoped_lock lk(first_mtx);
          pexcept = std::current_exception();
        }
      }
      return;
    }
  };

  {
    std::vector<std::jthread> workers;
    workers.reserve(worker_count - 1); /* caller is first worker. */
    for (unsigned i = 0; i < worker_count - 1; ++i)
      workers.emplace_back(body, stop_src.get_token());

    body(stop_src.get_token());
  }

  if (pexcept)
    std::rethrow_exception(pexcept);
}

} // namespace mt
} // namespace jove
#endif
