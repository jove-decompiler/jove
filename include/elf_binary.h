#pragma once
#include "types.h"
#include <boost/icl/interval_map.hpp>
#include <llvm/ADT/ArrayRef.h>
#include <llvm/Object/ObjectFile.h>

namespace jove {

void imported_functions_of_elf_binary(const llvm::object::ObjectFile &,
                                      std::vector<symbol_t> &);

void exported_functions_of_elf_binary(const llvm::object::ObjectFile &,
                                      std::vector<symbol_t> &);

void address_to_section_map_of_elf_binary(
    const llvm::object::ObjectFile &,
    boost::icl::interval_map<address_t, section_number_t> &);

llvm::ArrayRef<uint8_t>
section_contents_of_elf_binary(const llvm::object::ObjectFile &,
                               section_number_t);
}
