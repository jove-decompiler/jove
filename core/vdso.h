#pragma once
#include <utility>

namespace jove {

std::pair<void *, unsigned> GetVDSO(void);

const void *VDSOStandIn(void);
unsigned VDSOStandInLen(void);

}
