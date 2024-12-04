#pragma once
#include "jove/jove.h"
#include <sstream>

namespace jove {

template <bool MT>
void jv2xml(const jv_base_t<MT> &, std::ostringstream &);

}
