#include "process.h"

#include <cassert>
#include <cstring>
#include <list>
#include <string>

#include "jove/assert.h"

using namespace std;

namespace jove {

int WaitForProcessToExit(pid_t pid) {
  for (;;) {
    int wstatus = 0;
    if (::waitpid(pid, &wstatus, 0) < 0) {
      int err = errno;

      if (err == EINTR)
        continue;

      if (err == ECHILD) {
        // lost the exit status. happens if children are automically reaped by
        // the kernel, otherwise some other thread reaped it.
        return 0;
      }

      aassert(false && "waitpid(2) failed");
    }

    if (WIFEXITED(wstatus))
      return WEXITSTATUS(wstatus);
    else if (WIFSIGNALED(wstatus))
      return 128 + WTERMSIG(wstatus);

    aassert(false && "impossible waitpid(2) case");
  }

  __builtin_unreachable();
}

void InitWithEnviron(std::function<void(const char *)> Env) {
  for (char **env = ::environ; *env; ++env)
    Env(*env);
}

}
