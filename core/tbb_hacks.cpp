#include "tbb_hacks.h"

#include <oneapi/tbb/global_control.h>    // for finalize()

namespace jove {
namespace tbb_hacks {

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

}
}
