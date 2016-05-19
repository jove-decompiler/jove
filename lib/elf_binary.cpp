#include "binary.h"
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Object/ELF.h>
#include <unordered_map>
#include <iostream>

using namespace std;
using namespace llvm;
using namespace object;

namespace jove {

template <class T> static T errorOrDefault(ErrorOr<T> Val, T Default = T()) {
  return Val ? *Val : Default;
}

template <typename ELFT>
static bool parse_elf(const ELFFile<ELFT> *ELF, section_table_t &secttbl,
                      symbol_table_t &symtbl, relocation_table_t &reloctbl) {
  typedef typename ELFFile<ELFT>::Elf_Shdr Elf_Shdr;
  typedef typename ELFFile<ELFT>::Elf_Sym Elf_Sym;
  typedef typename ELFFile<ELFT>::Elf_Rel Elf_Rel;
  typedef typename ELFFile<ELFT>::Elf_Rela Elf_Rela;

  const Elf_Shdr *DotSymTblSec = nullptr; // Symbol table section.

  //
  // gather sections
  //
  secttbl.reserve(ELF->getNumSections());
  for (const Elf_Shdr &Sec : ELF->sections()) {
    // while iterating sections, look for the symbol table
    if (Sec.sh_type == ELF::SHT_SYMTAB)
      DotSymTblSec = &Sec;

    if (!(Sec.sh_flags & ELF::SHF_ALLOC) || !Sec.sh_size)
      continue;

    section_t res;

    res.name = errorOrDefault(ELF->getSectionName(&Sec)).str();
    res.addr = Sec.sh_addr;
    res.size = Sec.sh_size;

    res.contents = errorOrDefault(ELF->getSectionContents(&Sec));

    res.align = Sec.sh_addralign;

    res.flags.read = 1;
    res.flags.write = Sec.sh_flags & ELF::SHF_WRITE;
    res.flags.exec = Sec.sh_flags & ELF::SHF_EXECINSTR;
    res.flags.tls = Sec.sh_flags & ELF::SHF_TLS;

    secttbl.push_back(res);
  }

  //
  // gather symbols
  //
  auto process_elf_sym = [&](const Elf_Shdr *SymTab,
                             const Elf_Sym *Sym) -> void {
    symbol_t res;

    StringRef StrTable = errorOrDefault(ELF->getStringTableForSymtab(*SymTab));
    res.name = errorOrDefault(Sym->getName(StrTable)).str();

    res.addr = Sym->isUndefined() ? 0 : Sym->st_value;

    constexpr symbol_t::TYPE elf_symbol_type_mapping[] = {
        symbol_t::NOTYPE,   // STT_NOTYPE              = 0
        symbol_t::DATA,     // STT_OBJECT              = 1
        symbol_t::FUNCTION, // STT_FUNC                = 2
        symbol_t::DATA,     // STT_SECTION             = 3
        symbol_t::DATA,     // STT_FILE                = 4
        symbol_t::DATA,     // STT_COMMON              = 5
        symbol_t::TLSDATA,  // STT_TLS                 = 6
        symbol_t::NOTYPE,   // N/A                     = 7
        symbol_t::NOTYPE,   // N/A                     = 8
        symbol_t::NOTYPE,   // N/A                     = 9
        symbol_t::NOTYPE,   // STT_GNU_IFUNC, STT_LOOS = 10
        symbol_t::NOTYPE,   // N/A                     = 11
        symbol_t::NOTYPE,   // STT_HIOS                = 12
        symbol_t::NOTYPE,   // STT_LOPROC              = 13
        symbol_t::NOTYPE,   // N/A                     = 14
        symbol_t::NOTYPE    // STT_HIPROC              = 15
    };

    res.ty = elf_symbol_type_mapping[Sym->getType()];

    res.size = Sym->st_size;

    constexpr symbol_t::BINDING elf_symbol_binding_mapping[] = {
        symbol_t::LOCAL,     // STT_LOCAL      = 0
        symbol_t::GLOBAL,    // STB_GLOBAL     = 1
        symbol_t::WEAK,      // STB_WEAK       = 2
        symbol_t::NOBINDING, // N/A            = 3
        symbol_t::NOBINDING, // N/A            = 4
        symbol_t::NOBINDING, // N/A            = 5
        symbol_t::NOBINDING, // N/A            = 6
        symbol_t::NOBINDING, // N/A            = 7
        symbol_t::NOBINDING, // N/A            = 8
        symbol_t::NOBINDING, // N/A            = 9
        symbol_t::NOBINDING, // STB_GNU_UNIQUE = 10
        symbol_t::NOBINDING, // N/A            = 11
        symbol_t::NOBINDING, // STB_HIOS       = 12
        symbol_t::NOBINDING, // STB_LOPROC     = 13
        symbol_t::NOBINDING, // N/A            = 14
        symbol_t::NOBINDING  // STB_HIPROC     = 15
    };

    res.bind = elf_symbol_binding_mapping[Sym->getBinding()];

    if (res.ty == symbol_t::NOTYPE && res.bind == symbol_t::WEAK)
      res.ty = symbol_t::FUNCTION; // XXX

    symtbl.push_back(res);
  };

  symtbl.reserve(DotSymTblSec->sh_size / sizeof(Elf_Sym));
  for (const Elf_Sym &Sym : ELF->symbols(DotSymTblSec))
    process_elf_sym(DotSymTblSec, &Sym);

  //
  // gather relocations
  //
  for (const Elf_Shdr &Sec : ELF->sections()) {
    if (Sec.sh_type != ELF::SHT_REL && Sec.sh_type != ELF::SHT_RELA)
      continue;

    auto relocation_type_of_elf_rela_type =
        [](uint64_t elf_rela_ty) -> relocation_t::TYPE {
      switch (elf_rela_ty) {
#if defined(TARGET_AARCH64)
#include "elf_relocs_aarch64.cpp"
#elif defined(TARGET_ARM)
#include "elf_relocs_arm.cpp"
#elif defined(TARGET_X86_64)
#include "elf_relocs_x86_64.cpp"
#elif defined(TARGET_I386)
#include "elf_relocs_i386.cpp"
#elif defined(TARGET_MIPS)
#include "elf_relocs_mips.cpp"
#endif
      default:
        return relocation_t::NONE;
      }
    };

    const Elf_Shdr *SymTab = errorOrDefault(ELF->getSection(Sec.sh_link));

    auto process_rela = [&](const Elf_Rela &R) -> void {
      relocation_t res;

      const Elf_Sym *Sym = ELF->getRelocationSymbol(&R, SymTab);
      if (Sym) {
        res.symidx = symtbl.size();
        process_elf_sym(SymTab, Sym);
      } else {
        res.symidx = numeric_limits<unsigned int>::max();
      }

      res.ty = relocation_type_of_elf_rela_type(R.getType(ELF->isMips64EL()));
      res.addr = R.r_offset;
      res.addend = R.r_addend;

      reloctbl.push_back(res);
    };

    if (Sec.sh_type == ELF::SHT_REL) {
      reloctbl.reserve(reloctbl.size() +
                       distance(ELF->rel_begin(&Sec), ELF->rel_end(&Sec)));

      for (const Elf_Rel &R : ELF->rels(&Sec)) {
        Elf_Rela Rela;
        Rela.r_offset = R.r_offset;
        Rela.r_info = R.r_info;
        Rela.r_addend = 0;
        process_rela(Rela);
      }
    } else { // ELF::SHT_RELA
      reloctbl.reserve(reloctbl.size() +
                       distance(ELF->rela_begin(&Sec), ELF->rela_end(&Sec)));

      for (const Elf_Rela &Rela : ELF->relas(&Sec))
        process_rela(Rela);
    }
  }

  return true;
}

bool parse_elf_binary(const llvm::object::ObjectFile &O,
                      section_table_t &secttbl, symbol_table_t &symtbl,
                      relocation_table_t &reloctbl) {
  if (const ELF32LEObjectFile *ELFObj = dyn_cast<ELF32LEObjectFile>(&O))
    return parse_elf(ELFObj->getELFFile(), secttbl, symtbl, reloctbl);
  else if (const ELF32BEObjectFile *ELFObj = dyn_cast<ELF32BEObjectFile>(&O))
    return parse_elf(ELFObj->getELFFile(), secttbl, symtbl, reloctbl);
  else if (const ELF64LEObjectFile *ELFObj = dyn_cast<ELF64LEObjectFile>(&O))
    return parse_elf(ELFObj->getELFFile(), secttbl, symtbl, reloctbl);
  else if (const ELF64BEObjectFile *ELFObj = dyn_cast<ELF64BEObjectFile>(&O))
    return parse_elf(ELFObj->getELFFile(), secttbl, symtbl, reloctbl);

  return false;
}
}
