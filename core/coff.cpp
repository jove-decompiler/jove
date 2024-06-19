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
  uint64_t SectsStartAddr = std::numeric_limits<uint64_t>::max();
  uint64_t SectsEndAddr = 0;

  for (const llvm::object::SectionRef &S : O.sections()) {
    const llvm::object::coff_section *Section = O.getCOFFSection(S);
    assert(Section);

    SectsStartAddr = std::min<uint64_t>(SectsStartAddr,
        O.getImageBase() + Section->VirtualAddress);
    SectsEndAddr   = std::max<uint64_t>(SectsEndAddr,
        O.getImageBase() + Section->VirtualAddress + Section->VirtualSize);
  }

  return {SectsStartAddr, SectsEndAddr};
}

}
}
