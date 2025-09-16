#pragma once
#include "tool.h"

namespace jove {

typedef std::function<int(void)> get_redirectee_proc_t;

void SetupRedirectSignal(int no, Tool &, get_redirectee_proc_t);

}
