#pragma once
#include <jove/jove.h>

namespace jove {

template <bool MT>
double compute_score(const jv_base_t<MT> &, const binary_base_t<MT> &);

}
