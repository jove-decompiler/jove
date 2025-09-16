#pragma once
#include "tool.h"

#include <span>

namespace jove {

typedef std::function<int(void)> get_redirectee_proc_t;

void SetupSignalsRedirection(std::span<const int> signals, Tool &,
                             get_redirectee_proc_t);
}
