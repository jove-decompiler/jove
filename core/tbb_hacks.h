#pragma once
#include "jove/jove.h"

#ifndef JOVE_NO_TBB

namespace jove {
namespace tbb_hacks {

//
// According to doc, oneTBB does not support ``fork()``. The following is our
// work-around.
//
void pre_fork(void);
void post_fork(void);

}
}

#endif
