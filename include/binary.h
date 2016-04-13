#pragma once
#include "coff_binary.h"
#include "elf_binary.h"
#include "types.h"
#include <boost/icl/interval_map.hpp>
#include <llvm/Object/ObjectFile.h>
#include <llvm/ADT/ArrayRef.h>

namespace jove {

static void address_to_section_map_of_binary(
    const llvm::object::ObjectFile &O,
    boost::icl::interval_map<address_t, section_number_t> &res) {
  if (O.isELF())
    address_to_section_map_of_elf_binary(O, res);
  else if (O.isCOFF())
    address_to_section_map_of_coff_binary(O, res);
  else
    exit(78);
}

static llvm::ArrayRef<uint8_t>
section_contents_of_binary(const llvm::object::ObjectFile &O,
                           section_number_t S) {
  if (O.isELF())
    return section_contents_of_elf_binary(O, S);
  else if (O.isCOFF())
    return section_contents_of_coff_binary(O, S);
  else
    exit(78);
}
}
