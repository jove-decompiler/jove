#pragma once
#include <unistd.h>
#include <signal.h>

namespace jove {

int pidfd_open(pid_t, unsigned int flags);
int pidfd_send_signal(int pidfd, int sig, siginfo_t *, unsigned int flags);

}
