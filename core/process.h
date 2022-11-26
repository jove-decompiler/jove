#pragma once
#include <sys/wait.h>

namespace jove {

int WaitForProcessToExit(pid_t);

}
