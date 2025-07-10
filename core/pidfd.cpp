#include "pidfd.h"
#include <sys/syscall.h>

namespace jove {

int pidfd_open(pid_t pid, unsigned int flags) {
  return ::syscall(SYS_pidfd_open, pid, flags);
}

int pidfd_send_signal(int pidfd, int sig, siginfo_t *info, unsigned int flags) {
  return ::syscall(SYS_pidfd_send_signal, pidfd, sig, info, flags);
}

}
