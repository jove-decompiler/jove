#pragma once
#include "types.h"
#include <llvm/Object/ObjectFile.h>
#include <llvm/ADT/ArrayRef.h>
#include <boost/icl/interval_map.hpp>

namespace jove {
void address_to_section_map_of_coff_binary(
    const llvm::object::ObjectFile &,
    boost::icl::interval_map<address_t, section_number_t> &);

llvm::ArrayRef<uint8_t>
section_contents_of_coff_binary(const llvm::object::ObjectFile &,
                                section_number_t);
}
