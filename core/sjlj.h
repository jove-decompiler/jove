#pragma once
#include "jove/jove.h"
#include "explore.h"

namespace jove {

template <bool MT, bool MinSize>
void ScanForSjLj(binary_base_t<MT, MinSize> &,
                 B::cached::type<> &,
                 explorer_t<MT, MinSize> &);
}
