#include "process.h"

#include <cstring>
#include <stdexcept>
#include <string>

namespace jove {

int WaitForProcessToExit(pid_t pid) {
  int res = 1;

  int wstatus = 0;
  do {
    if (::waitpid(pid, &wstatus, WUNTRACED | WCONTINUED) == -1) {
      int err = errno;

      if (err == EINTR)
        continue;

      if (err == ECHILD)
        break;

      throw std::runtime_error(
          std::string("WaitForProcessToExit: waitpid failed: ") +
          strerror(err));
    }

    if (WIFEXITED(wstatus)) {
      res = WEXITSTATUS(wstatus);
    } else if (WIFSIGNALED(wstatus)) {
      ;
    } else if (WIFSTOPPED(wstatus)) {
      ;
    } else if (WIFCONTINUED(wstatus)) {
      ;
    }
  } while (!WIFEXITED(wstatus) && !WIFSIGNALED(wstatus));

  return res;
}

}
