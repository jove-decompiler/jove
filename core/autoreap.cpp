#include "autoreap.h"
#include "jove/assert.h"

#include <cerrno>

#include <signal.h>

namespace jove {

bool SetAutomaticReaping(bool On) {
  struct sigaction sa = {0};

  if (On) {
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = SA_NOCLDWAIT;
  } else {
    sa.sa_handler = SIG_DFL;
  }

  sigemptyset(&sa.sa_mask);

  return ::sigaction(SIGCHLD, &sa, nullptr) == 0;
}


}
