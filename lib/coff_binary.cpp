#include "binary.h"
#include <llvm/Object/COFF.h>

using namespace llvm;
using namespace object;

namespace jove {

bool parse_coff_binary(const llvm::object::ObjectFile &O,
                      section_table_t &secttbl, symbol_table_t &symtbl,
                      relocation_table_t &reloctbl) {
  const COFFObjectFile *COFF = cast<COFFObjectFile>(&O);

  //
  // gather sections
  //
  secttbl.reserve(COFF->getNumberOfSections());
  for (const auto &Shdr : COFF->sections()) {
    const coff_section *S = COFF->getCOFFSection(Shdr);

    if (S->Characteristics & COFF::IMAGE_SCN_CNT_UNINITIALIZED_DATA)
      continue;

    section_t res;

    StringRef name;
    COFF->getSectionName(S, name);
    res.name = name.str();

    res.addr = COFF->getImageBase() + S->VirtualAddress;
    res.size = COFF->getSectionSize(S);

    COFF->getSectionContents(S, res.contents);

    res.align = uint64_t(1) << (((S->Characteristics & 0x00F00000) >> 20) - 1);

    res.flags.read = S->Characteristics & COFF::IMAGE_SCN_MEM_READ;
    res.flags.write = S->Characteristics & COFF::IMAGE_SCN_MEM_WRITE;
    res.flags.exec = S->Characteristics & COFF::IMAGE_SCN_MEM_EXECUTE;
    res.flags.tls = 0;

    secttbl.push_back(res);
  }

  //
  // gather symbols
  //
  symtbl.reserve(
      distance(COFF->export_directory_begin(), COFF->export_directory_end()) +
      distance(COFF->import_directory_begin(), COFF->import_directory_end()));
  for (const ExportDirectoryEntryRef &E : COFF->export_directories()) {
    symbol_t res;

    uint32_t RVA;
    E.getExportRVA(RVA);
    if (!RVA)
      continue;

    res.addr = COFF->getImageBase() + RVA;

    res.ty = symbol_t::FUNCTION;

    StringRef name;
    E.getSymbolName(name);
    res.name = name.str();

    res.size = 0;
    res.bind = symbol_t::GLOBAL;

    symtbl.push_back(res);
  }

  //
  // gather relocations
  //
  for (const ImportDirectoryEntryRef &I : COFF->import_directories()) {
    uint32_t IAT_RVA;
    I.getImportAddressTableRVA(IAT_RVA);
    if (!IAT_RVA)
      continue;

    unsigned entry_size = COFF->is64() ? sizeof(uint64_t) : sizeof(uint32_t);
    unsigned off = 0;
    for (const ImportedSymbolRef& S : I.imported_symbols()) {
      relocation_t res1;

      res1.addr = COFF->getImageBase() + IAT_RVA + off;
      res1.ty = relocation_t::FUNCTION;
      res1.symidx = symtbl.size();

      symbol_t res2;

      StringRef name;
      S.getSymbolName(name);

      res2.name = name.str();
      res2.addr = 0; // undefined
      res2.ty = symbol_t::FUNCTION;
      res2.bind = symbol_t::GLOBAL;
      res2.size = 0;

      symtbl.push_back(res2);

      off += entry_size;
    }
  }
}

}
