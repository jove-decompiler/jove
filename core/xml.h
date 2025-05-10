#pragma once
#include "jove/jove.h"
#include <sstream>

namespace jove {

template <bool MT, bool MinSize>
void jv2xml(const jv_base_t<MT, MinSize> &, std::ostringstream &);

}
