#pragma once
#include <jove/jove.h>

namespace jove {

template <bool MT, bool MinSize>
double compute_score(const jv_base_t<MT, MinSize> &,
                     const binary_base_t<MT, MinSize> &);
}
