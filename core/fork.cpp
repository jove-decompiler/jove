#include "fork.h"
#include "util.h"
#include "fd.h"
#include "pidfd.h"
#include "eintr.h"
#include "assert.h"

#include <poll.h>
#include <linux/prctl.h>  /* Definition of PR_* constants */
#include <sys/prctl.h>

namespace jove {

pid_t long_fork(std::function<int(void)> f) {
  scoped_fd our_pfd(pidfd_open(::getpid(), 0));

  const pid_t child = jove::fork();
  if (!child) {
    (void)::prctl(PR_SET_PDEATHSIG, SIGTERM);

    int poll_ret = ({
      struct pollfd pfd = {.fd = our_pfd.get(), .events = POLLIN};
      sys::retry_eintr(::poll, &pfd, 1, 0);
    });

    aassert(poll_ret >= 0);

    our_pfd.close();
    if (poll_ret != 0) {
      //
      // parent is already gone.
      //
      for (;;)
        _exit(0);
      __builtin_unreachable();
    }

    int rc = 1;
    ignore_exception([&] { rc = f(); });

    for (;;)
      _exit(rc);
    __builtin_unreachable();
  }

  return child;
}

}
