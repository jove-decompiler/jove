#pragma once
#include "jove/jove.h"

namespace jove {

std::string addr2line(const binary_t &, tcg_uintptr_t Addr);
std::string addr2desc(const binary_t &, tcg_uintptr_t Addr);

}
