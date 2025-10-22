#pragma once
#include "jove/jove.h"

#ifndef JOVE_NO_TBB
#include "tbb_hacks.h"
#endif

#include <unistd.h>

namespace jove {

//
// this is for "long-running forks". if you are calling execve(2) shortly after
// the fork, there should be no chance of deadlocking (so you should just call
// the regular fork() function).
//
static inline pid_t fork(void) {
#ifndef JOVE_NO_TBB
  tbb_hacks::pre_fork();
#endif

  pid_t res = ::fork();

#ifndef JOVE_NO_TBB
  tbb_hacks::post_fork();
#endif

  return res;
}

//
// convenience for long running forks.
//
pid_t long_fork(std::function<int(void)> f);

}
