#include "coff.h"

namespace jove {
namespace coff {

bool isCode(COFFO &O, uint64_t RVA) {
  for (const llvm::object::SectionRef &S : O.sections()) {
    const llvm::object::coff_section *Section = O.getCOFFSection(S);
    uint32_t SectionStart = Section->VirtualAddress;
    uint32_t SectionEnd = Section->VirtualAddress + Section->VirtualSize;
    if (SectionStart <= RVA && RVA < SectionEnd) {
      if (Section->SizeOfRawData < Section->VirtualSize &&
          RVA >= SectionStart + Section->SizeOfRawData)
        return false;

      return Section->Characteristics & llvm::COFF::IMAGE_SCN_MEM_EXECUTE;
    }
  }

  return false;
}

addr_pair bounds_of_binary(COFFO &O) {
  return std::make_pair(0, 0);
}

}
}
