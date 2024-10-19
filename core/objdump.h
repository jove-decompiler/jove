#pragma once
#include "jove/jove.h"

namespace jove {

template <typename T>
int run_objdump_and_parse_addresses(const char *filename,
                                    llvm::object::Binary &, T &out);
}
