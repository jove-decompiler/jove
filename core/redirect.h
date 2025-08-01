#pragma once
#include "tool.h"

namespace jove {

typedef std::function<int(void)> get_redirectee_proc_t;

void setup_to_redirect_signal(int no, Tool &, get_redirectee_proc_t);

}
