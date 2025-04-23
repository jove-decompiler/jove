#include "process.h"

#include <cassert>
#include <cstring>
#include <list>
#include <string>

using namespace std;

namespace jove {

int WaitForProcessToExit(pid_t pid) {
  for (;;) {
    int wstatus = 0;
    if (::waitpid(pid, &wstatus, WUNTRACED | WCONTINUED) == -1) {
      int err = errno;

      if (err == EINTR)
        continue;

      if (err == ECHILD)
        return 0;

      throw runtime_error(string("WaitForProcessToExit: waitpid failed: ") +
                          strerror(err));
    }

    if (WIFEXITED(wstatus)) {
      return WEXITSTATUS(wstatus);
    } else if (WIFSIGNALED(wstatus)) {
      return 1;
    } else {
      assert(WIFSTOPPED(wstatus) || WIFCONTINUED(wstatus));
    }
  }

  abort();
}

void InitWithEnviron(std::function<void(const char *)> Env) {
  for (char **env = ::environ; *env; ++env)
    Env(*env);
}

}
