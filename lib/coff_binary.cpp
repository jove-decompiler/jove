#include "coff_binary.h"
#include <llvm/Object/COFF.h>

using namespace llvm;
using namespace object;

namespace jove {

void exported_functions_of_coff_binary(const llvm::object::ObjectFile &O,
                                       std::vector<symbol_t> &res) {
  const COFFObjectFile *COFF = cast<COFFObjectFile>(&O);

  for (const ExportDirectoryEntryRef &E : COFF->export_directories()) {
    StringRef Name;
    E.getSymbolName(Name);

    uint32_t RVA;
    E.getExportRVA(RVA);
    uint64_t VA = COFF->getImageBase() + RVA;

    res.push_back({VA, Name.str()});
  }
}

ArrayRef<uint8_t>
section_contents_of_coff_binary(const llvm::object::ObjectFile &O,
                                section_number_t S) {
  const COFFObjectFile *COFF = cast<COFFObjectFile>(&O);

  section_number_t SectionNumber = 0;
  for (const auto &Shdr : COFF->sections()) {
    ++SectionNumber;
    if (++SectionNumber == S) {
      const coff_section *S = COFF->getCOFFSection(Shdr);

      ArrayRef<uint8_t> res;

      if (S->Characteristics & COFF::IMAGE_SCN_CNT_UNINITIALIZED_DATA)
        return res;

      COFF->getSectionContents(S, res);

      return res;
    }
  }

  exit(142);
}

void address_to_section_map_of_coff_binary(
    const llvm::object::ObjectFile &O,
    boost::icl::interval_map<address_t, section_number_t> &res) {
  const COFFObjectFile *COFF = cast<COFFObjectFile>(&O);

  section_number_t SectionNumber = 0;
  for (const auto &Shdr : COFF->sections()) {
    ++SectionNumber;

    const coff_section *S = COFF->getCOFFSection(Shdr);

    uint64_t RVA = S->VirtualAddress;
    uint64_t VA = COFF->getImageBase() + RVA;
    boost::icl::discrete_interval<uint64_t> intervl =
        boost::icl::discrete_interval<uint64_t>::right_open(
            VA, VA + COFF->getSectionSize(S));

    res.add(make_pair(intervl, SectionNumber));
  }
}
}
