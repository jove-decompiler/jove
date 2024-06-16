#pragma once
#include <llvm/Object/COFF.h>

namespace jove {

typedef llvm::object::COFFObjectFile COFFO;

constexpr bool isCode(COFFO &O, uint64_t RVA) {
  uint64_t BaseOfCode = 0, SizeOfCode = 0;

  if (const llvm::object::pe32plus_header *PEPlusHeader = O.getPE32PlusHeader()) {
    BaseOfCode = PEPlusHeader->BaseOfCode;
    SizeOfCode = PEPlusHeader->SizeOfCode;
  } else if (const llvm::object::pe32_header *PEHeader = O.getPE32Header()) {
    BaseOfCode = PEHeader->BaseOfCode;
    SizeOfCode = PEHeader->SizeOfCode;
  }

  if (!BaseOfCode || !SizeOfCode)
    return false;

  return RVA >= BaseOfCode && RVA < BaseOfCode + SizeOfCode;
}

}
