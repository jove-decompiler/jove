#include "translator.h"
#include "qemutcg.h"
#include "mc.h"
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Object/Binary.h>
#include <llvm/Object/COFF.h>

using namespace llvm;
using namespace llvm::object;
using namespace std;

namespace jove {

translator::translator(ObjectFile &O, LLVMContext &C, Module &M)
    : O(O), C(C), M(M), DL(M.getDataLayout()) {
  //
  // init TCG translator
  //
  libqemutcg_init();

  //
  // init LLVM-MC for machine code analysis
  //
  libmc_init(&O);

  //
  // build address space mapping to sections
  //
  build_address_space_section_map();
}

translator::~translator() {}

void translator::translate(address_t a) {
  //
  // find section containing address
  //
  auto sectit = sectaddrmap.find(a);
  if (sectit == sectaddrmap.end())
    exit(45);
  unsigned sectidx = (*sectit).second - 1;

  libqemutcg_set_code(sectdata.at(sectidx).data(), sectdata.at(sectidx).size(),
                      (*sectit).first.lower());
  //
  // translate to TCG code
  //
  libqemutcg_translate(a);
}

template <class T>
static T errorOrDefault(ErrorOr<T> Val, T Default = T()) {
  return Val ? *Val : Default;
}

template <typename ELFT>
static void build_section_data_map_from_elf(
    const ELFFile<ELFT> *Elf, vector<ArrayRef<uint8_t>> &sectdata,
    boost::icl::interval_map<uint64_t, unsigned> &sectaddrmap) {
  unsigned SectionNumber = 0;
  for (const auto &Shdr : Elf->sections()) {
    ++SectionNumber;
    boost::icl::discrete_interval<uint64_t> intervl =
        boost::icl::discrete_interval<uint64_t>::right_open(
            Shdr.sh_addr, Shdr.sh_addr + Shdr.sh_size);

#if 0
    cout << errorOrDefault(Elf->getSectionName(&Shdr)).str() << '[' << hex << Shdr.sh_addr
         << ", " << Shdr.sh_addr + Shdr.sh_size << ')' << endl;
#endif

    sectdata.push_back(errorOrDefault(Elf->getSectionContents(&Shdr)));
    sectaddrmap.add(make_pair(intervl, SectionNumber));
  }
}

static void build_section_data_map_from_coff(
    const COFFObjectFile *COFF, vector<ArrayRef<uint8_t>> &sectdata,
    boost::icl::interval_map<uint64_t, unsigned> &sectaddrmap) {
  unsigned SectionNumber = 0;
  for (const auto &Shdr : COFF->sections()) {
    ++SectionNumber;
    const coff_section *S = COFF->getCOFFSection(Shdr);

    if (S->Characteristics & COFF::IMAGE_SCN_CNT_UNINITIALIZED_DATA)
      continue;

    uint64_t RVA = S->VirtualAddress;
    uint64_t VA = COFF->getImageBase() + RVA;
    boost::icl::discrete_interval<uint64_t> intervl =
        boost::icl::discrete_interval<uint64_t>::right_open(
            VA, VA + COFF->getSectionSize(S));

#if 0
    StringRef SectNm;
    if (COFF->getSectionName(S, SectNm))
      abort();
    cout << SectNm.str() << " : " << '[' << hex << intervl.lower() << ", "
         << intervl.upper() << ')' << endl;
#endif

    ArrayRef<uint8_t> SectContents;
    if (COFF->getSectionContents(S, SectContents))
      abort();
    sectdata.push_back(SectContents);
    sectaddrmap.add(make_pair(intervl, SectionNumber));
  }
}

void translator::build_address_space_section_map() {
  if (O.isELF()) {
    if (const ELF32LEObjectFile *ELFObj = dyn_cast<ELF32LEObjectFile>(&O))
      build_section_data_map_from_elf(ELFObj->getELFFile(), sectdata,
                                      sectaddrmap);
    else if (const ELF32BEObjectFile *ELFObj = dyn_cast<ELF32BEObjectFile>(&O))
      build_section_data_map_from_elf(ELFObj->getELFFile(), sectdata,
                                      sectaddrmap);
    else if (const ELF64LEObjectFile *ELFObj = dyn_cast<ELF64LEObjectFile>(&O))
      build_section_data_map_from_elf(ELFObj->getELFFile(), sectdata,
                                      sectaddrmap);
    else if (const ELF64BEObjectFile *ELFObj = dyn_cast<ELF64BEObjectFile>(&O))
      build_section_data_map_from_elf(ELFObj->getELFFile(), sectdata,
                                      sectaddrmap);
    else
      abort();
  } else if (O.isCOFF()) {
    const COFFObjectFile *COFFObj = dyn_cast<COFFObjectFile>(&O);
    assert(COFFObj);
    build_section_data_map_from_coff(COFFObj, sectdata, sectaddrmap);
  } else {
    exit(44);
  }
}

}
