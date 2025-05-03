#pragma once
#include "jove/jove.h"
#include "explore.h"

namespace jove {

template <bool MT>
void ScanForSjLj(binary_base_t<MT> &, llvm::object::Binary &, explorer_t<MT> &);

}
