#pragma once
#include "jove/jove.h"

namespace jove {

int run_objdump_and_parse_addresses(const char *filename,
                                    llvm::object::Binary &,
                                    binary_t::Analysis_t::objdump_t &out);
}
