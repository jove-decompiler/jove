#pragma once
#include <boost/scope/defer.hpp>
#include <functional>

#include <signal.h>

namespace jove {

static inline void block_signals(std::function<void(void)> f) {
  sigset_t sigmask, oldmask;

  ::sigfillset(&sigmask);
  ::sigprocmask(SIG_BLOCK, &sigmask, &oldmask); /* block em */

  BOOST_SCOPE_DEFER [&] { 
    ::sigprocmask(SIG_SETMASK, &oldmask, nullptr); /* unblock em */
  };

  f();
}

}
