#include "elf_binary.h"
#include <llvm/Object/ELFObjectFile.h>

using namespace llvm;
using namespace object;

namespace jove {

template <class T> static T errorOrDefault(ErrorOr<T> Val, T Default = T()) {
  return Val ? *Val : Default;
}

template <typename ELFT>
static ArrayRef<uint8_t> section_contents_of_elf(const ELFFile<ELFT> *ELF,
                                                 section_number_t S) {
  section_number_t SectionNumber = 0;
  for (const auto &Shdr : ELF->sections()) {
    ++SectionNumber;
    if (SectionNumber == S)
      return errorOrDefault(ELF->getSectionContents(&Shdr));
  }

  return ArrayRef<uint8_t>();
}

ArrayRef<uint8_t>
section_contents_of_elf_binary(const llvm::object::ObjectFile & O,
                               section_number_t S) {
  if (const ELF32LEObjectFile *ELFObj = dyn_cast<ELF32LEObjectFile>(&O))
    return section_contents_of_elf(ELFObj->getELFFile(), S);
  else if (const ELF32BEObjectFile *ELFObj = dyn_cast<ELF32BEObjectFile>(&O))
    return section_contents_of_elf(ELFObj->getELFFile(), S);
  else if (const ELF64LEObjectFile *ELFObj = dyn_cast<ELF64LEObjectFile>(&O))
    return section_contents_of_elf(ELFObj->getELFFile(), S);
  else if (const ELF64BEObjectFile *ELFObj = dyn_cast<ELF64BEObjectFile>(&O))
    return section_contents_of_elf(ELFObj->getELFFile(), S);
  else
    exit(94);
}

template <typename ELFT>
static void address_to_section_map_of_elf(const ELFFile<ELFT> *ELF,
    boost::icl::interval_map<address_t, section_number_t> &res) {
  section_number_t SectionNumber = 0;
  for (const auto &Shdr : ELF->sections()) {
    ++SectionNumber;
    boost::icl::discrete_interval<address_t> intervl =
        boost::icl::discrete_interval<address_t>::right_open(
            Shdr.sh_addr, Shdr.sh_addr + Shdr.sh_size);
    res.add(make_pair(intervl, SectionNumber));
  }
}

void address_to_section_map_of_elf_binary(
    const llvm::object::ObjectFile &O,
    boost::icl::interval_map<address_t, section_number_t> &res) {
  if (const ELF32LEObjectFile *ELFObj = dyn_cast<ELF32LEObjectFile>(&O))
    address_to_section_map_of_elf(ELFObj->getELFFile(), res);
  else if (const ELF32BEObjectFile *ELFObj = dyn_cast<ELF32BEObjectFile>(&O))
    address_to_section_map_of_elf(ELFObj->getELFFile(), res);
  else if (const ELF64LEObjectFile *ELFObj = dyn_cast<ELF64LEObjectFile>(&O))
    address_to_section_map_of_elf(ELFObj->getELFFile(), res);
  else if (const ELF64BEObjectFile *ELFObj = dyn_cast<ELF64BEObjectFile>(&O))
    address_to_section_map_of_elf(ELFObj->getELFFile(), res);
  else
    exit(94);
}
}
