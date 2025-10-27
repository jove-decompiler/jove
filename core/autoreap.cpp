#include "autoreap.h"
#include "assert.h"

#include <cerrno>

#include <signal.h>

namespace jove {

void AutomaticallyReap(void) {
  struct sigaction sa;
  sa.sa_handler = SIG_IGN;
  sa.sa_flags = SA_NOCLDWAIT;
  sigemptyset(&sa.sa_mask);

  aassert(::sigaction(SIGCHLD, &sa, nullptr) == 0);
}


}
