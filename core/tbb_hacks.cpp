#include "tbb_hacks.h"

#ifndef JOVE_NO_TBB

#include <oneapi/tbb/global_control.h>    // for finalize()
#include <oneapi/tbb/task_arena.h>

namespace jove {
namespace tbb_hacks {

#if 0
struct disabler_t {
  disabler_t() { jove::tbb_hacks::disable(); }
};

//
// disabler must be constructed before anything else, so tbb_hacks.o should come
// first on the command-line when linking jove.
//
static disabler_t disabler;
#endif

void pre_fork(void) {
  oneapi::tbb::task_scheduler_handle handle{oneapi::tbb::attach{}};

  if (!oneapi::tbb::finalize(handle, std::nothrow))
    throw std::runtime_error("tbb_hacks::pre_fork() failed");

  // now it's safe to fork().
}

void post_fork(void) {
  oneapi::tbb::task_scheduler_handle child_or_parent_handle{
      oneapi::tbb::attach{}};
}

void disable(void) {
  tbb::global_control c(tbb::global_control::max_allowed_parallelism, 1);
}

void enable(void) {
  tbb::global_control c(tbb::global_control::max_allowed_parallelism,
                        oneapi::tbb::this_task_arena::max_concurrency());
}

}
}

#endif
