#include "B.h"
#include "win.h"
#include "util.h"

#include <unordered_set>

namespace obj = llvm::object;

namespace jove {
namespace coff {

uint64_t va_of_offset(COFFO &O, uint64_t off) {
  for (const llvm::object::SectionRef &Section : O.sections()) {
    const llvm::object::coff_section *Sec = O.getCOFFSection(Section);

    uint64_t SectionOffset = Sec->PointerToRawData;
    uint64_t SectionSize = Sec->SizeOfRawData;

    if (off >= SectionOffset && off < SectionOffset + SectionSize) {
      uint64_t RVA = Sec->VirtualAddress + (off - SectionOffset);
      return va_of_rva(O, RVA);
    }
  }

  throw std::runtime_error("va_of_offset: no section for given offset (" +
                           std::to_string(off) + ")");
}

bool isCode(COFFO &O, uint64_t va) {
  uint64_t RVA = rva_of_va(O, va);

  for (const obj::SectionRef &S : O.sections()) {
    const obj::coff_section *Section = O.getCOFFSection(S);
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

bool needed_libs(COFFO &O, std::vector<std::string> &out) {
  std::unordered_set<std::string> needed_set;

  for (const obj::ImportDirectoryEntryRef &DirRef : O.import_directories()) {
    llvm::StringRef Needed;
    if (llvm::errorToBool(DirRef.getName(Needed)))
      continue;

    std::string needed(Needed.str());
    if (const char *dll = win::dll_of_apiset(needed.c_str()))
      needed_set.insert(dll);
    else
      needed_set.insert(lowered_string(needed));
  }

  out.clear();
  for (const std::string &needed : needed_set)
    out.push_back(needed);

  return true;
}

void for_each_imported_function(
    COFFO &O, std::function<void(llvm::StringRef DLL, uint32_t Ordinal,
                                 llvm::StringRef Name, uint64_t RVA)> proc) {
  for (const llvm::object::ImportDirectoryEntryRef &I : O.import_directories()) {
    llvm::StringRef DLL;
    if (llvm::errorToBool(I.getName(DLL)))
      continue;

    auto processImportedSymbols = [&](uint64_t RVA,
        llvm::iterator_range<llvm::object::imported_symbol_iterator> Range) -> void {
      unsigned i = 0;
      for (auto it = Range.begin(); it != Range.end(); ++it, ++i) {
        const llvm::object::ImportedSymbolRef &I = *it;

        llvm::StringRef SymName;
        (void)llvm::errorToBool(I.getSymbolName(SymName));

        uint16_t Ordinal = UINT16_MAX;
        if (llvm::errorToBool(I.getOrdinal(Ordinal)))
          continue;

        proc(DLL, Ordinal, SymName, RVA + i*O.getBytesInAddress());
      }
    };

    uint32_t ILTAddr = 0;
    if (false && !llvm::errorToBool(I.getImportLookupTableRVA(ILTAddr)) && ILTAddr)
      processImportedSymbols(ILTAddr, I.lookup_table_symbols());

    uint32_t IATAddr = 0;
    if (!llvm::errorToBool(I.getImportAddressTableRVA(IATAddr)) && IATAddr)
      processImportedSymbols(IATAddr, I.imported_symbols());
  }
}

void for_each_base_relocation(COFFO &O,
  std::function<void(uint8_t Type, uint64_t RVA)> proc) {
  for (const obj::BaseRelocRef &I : O.base_relocs()) {
    uint8_t RelocType;
    uint32_t RVA;

    if (llvm::errorToBool(I.getRVA(RVA)))
      continue;
    if (llvm::errorToBool(I.getType(RelocType)))
      continue;

    proc(RelocType, RVA);
  }
}

void for_each_exported_function(
    COFFO &O, std::function<void(uint32_t Ordinal,
                                 llvm::StringRef Name, uint64_t RVA)> proc) {
  for (const llvm::object::ExportDirectoryEntryRef &Exp : O.export_directories()) {
    uint32_t RVA = 0x0;
    uint32_t Ordinal = UINT32_MAX;
    llvm::StringRef Name("");
    bool IsForwarder;

    if (llvm::errorToBool(Exp.getOrdinal(Ordinal)) ||
        llvm::errorToBool(Exp.isForwarder(IsForwarder)) || IsForwarder ||
        llvm::errorToBool(Exp.getSymbolName(Name)) ||
        llvm::errorToBool(Exp.getExportRVA(RVA)))
      continue;

    proc(Ordinal, Name, RVA);
  }
}

void gen_module_definition_for_dll(COFFO &O, llvm::StringRef DLL, std::ostream &out) {
  const bool IsI386 = O.getMachine() == llvm::COFF::IMAGE_FILE_MACHINE_I386;

  out << "NAME " << DLL.str() << '\n';
  out << "EXPORTS\n";

  //
  // named exports
  //
  for (const llvm::object::ExportDirectoryEntryRef &Exp : O.export_directories()) {
    uint32_t Ordinal = UINT32_MAX;
    llvm::StringRef Name("");

    if (llvm::errorToBool(Exp.getOrdinal(Ordinal)) ||
        llvm::errorToBool(Exp.getSymbolName(Name)) ||
        Name.empty())
      continue;

    out << "    ";
    if (IsI386)
      out << "_";
    out << Name.str() << " @" << Ordinal << '\n';
  }

  //
  // provide a way to call any exported function given its ordinal
  //
  for (const llvm::object::ExportDirectoryEntryRef &Exp : O.export_directories()) {
    uint32_t Ordinal = UINT32_MAX;

    if (llvm::errorToBool(Exp.getOrdinal(Ordinal)))
      continue;

    out << "    ";
    if (IsI386)
      out << "_";
    out << unique_symbol_for_ordinal_in_dll(DLL, Ordinal) << " @" << Ordinal
        << " NONAME" << '\n';
  }
}

std::string unique_symbol_for_ordinal_in_dll(llvm::StringRef DLL,
                                             uint16_t Ordinal) {
  std::string res("jjvv_");
  res.append(DLL.str());

  std::replace_if(
      res.begin(), res.end(),
      [](char c) { return !std::isalnum(static_cast<unsigned char>(c)); }, '_');

  res.append("_");
  res.append(std::to_string(Ordinal));

  return res;
}

static std::string link_subsystem_of_image_subsystem(unsigned sub) {
  switch (sub) {
  case llvm::COFF::IMAGE_SUBSYSTEM_WINDOWS_GUI:
    return "windows";
  case llvm::COFF::IMAGE_SUBSYSTEM_WINDOWS_CUI:
    return "console";
  }

  throw std::runtime_error("msvc_subsystem_of_image_subsystem: unimplemented");
}

std::string link_subsystem(COFFO &O) {
  if (const obj::pe32plus_header *PEPlusHeader = O.getPE32PlusHeader())
    return link_subsystem_of_image_subsystem(PEPlusHeader->Subsystem);

  if (const obj::pe32_header *PEHeader = O.getPE32Header())
    return link_subsystem_of_image_subsystem(PEHeader->Subsystem);

  return "";
}

}
}
