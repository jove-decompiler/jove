#include "jove/jove.h"
#include "B.h"
#include "hash.h"
#include "explore.h"
#include "sjlj.h"

#include <boost/filesystem.hpp>
#include <boost/range/adaptor/reversed.hpp>

#include <llvm/Support/WithColor.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/raw_ostream.h>

using llvm::WithColor;

namespace fs = boost::filesystem;
namespace obj = llvm::object;

namespace jove {

#include "relocs_common.hpp"

template <bool MT>
template <bool MT2>
void jv_base_t<MT>::DoAdd(binary_base_t<MT2> &b,
                          explorer_t &explorer,
                          llvm::object::Binary &Bin,
                          const AddOptions_t &Options) {
  auto IsVerbose = [&](void) -> bool { return Options.VerbosityLevel >= 1; };
  auto IsVeryVerbose = [&](void) -> bool { return Options.VerbosityLevel >= 2; };

  b.IsDynamicLinker = false;
  b.IsExecutable = false;
  b.IsVDSO = false;

  b.IsPIC = true;
  b.IsDynamicallyLoaded = false;

  auto BasicBlockAtAddress = [&](uint64_t Entrypoint) -> basic_block_index_t {
    if (!Entrypoint)
      return invalid_basic_block_index;

    if (Options.Objdump && b.Analysis.objdump.is_addr_bad(Entrypoint)) {
      if (IsVeryVerbose())
        llvm::errs() << llvm::formatv("objdump rejects {0}:{1:x}\n",
                                      b.Name.c_str(), Entrypoint);
      return invalid_basic_block_index;
    }

    try {
      if (IsVeryVerbose())
        llvm::errs() << llvm::formatv("exploring {0}:{1:x}\n", b.Name.c_str(),
                                      Entrypoint);

      return explorer.explore_basic_block(b, Bin, Entrypoint);
    } catch (...) {
      return invalid_basic_block_index;
    }
  };
  auto FunctionAtAddress = [&](uint64_t Entrypoint) -> function_index_t {
    if (!Entrypoint)
      return invalid_function_index;

    // let's be extra careful.
    if (unlikely(!is_basic_block_index_valid(BasicBlockAtAddress(Entrypoint))))
      return invalid_function_index;

    return explorer.explore_function(b, Bin, Entrypoint);
  };
  auto ABIAtAddress = [&](uint64_t Entrypoint) -> void {
    function_index_t FIdx = FunctionAtAddress(Entrypoint);

    if (unlikely(!is_function_index_valid(FIdx)))
      return;

    b.Analysis.Functions.at(FIdx).IsABI = true;
  };

  B::_elf(Bin,
    [&](ELFO &O) {
  const ELFF &Elf = O.getELFFile();

  switch (Elf.getHeader().e_type) {
  case llvm::ELF::ET_NONE:
    throw std::runtime_error("given binary has unknown type");

  case llvm::ELF::ET_REL:
    throw std::runtime_error("given binary is object file");

  case llvm::ELF::ET_EXEC:
    b.IsPIC = false;
    break;

  case llvm::ELF::ET_DYN:
    break;

  case llvm::ELF::ET_CORE:
    throw std::runtime_error("given binary is core file");

  default:
    abort();
    break;
  }

  elf::DynRegionInfo DynamicTable(O);
  elf::loadDynamicTable(O, DynamicTable);

  //assert(DynamicTable.Addr);

  auto dynamic_table = [&](void) -> Elf_Dyn_Range {
    if (DynamicTable.Addr)
      return DynamicTable.getAsArrayRef<Elf_Dyn>();
    else
      return {};
  };

#if 0
  bool IsStaticallyLinked = true;
#endif

  //
  // examine dynamic table
  //
  for (const Elf_Dyn &Dyn : dynamic_table()) {
    if (unlikely(Dyn.getTag() == llvm::ELF::DT_NULL))
      break; /* marks end of dynamic table. */

    switch (Dyn.d_tag) {
#if 0
    case llvm::ELF::DT_NEEDED:
      IsStaticallyLinked = false;
      break;
#endif
    case llvm::ELF::DT_INIT:
      ABIAtAddress(Dyn.getVal());
      break;
    }
  }

  llvm::Expected<Elf_Phdr_Range> ExpectedPrgHdrs = Elf.program_headers();
  if (!ExpectedPrgHdrs)
    throw std::runtime_error("no program headers in ELF. bug?");

  auto PrgHdrs = *ExpectedPrgHdrs;

  //
  // if the ELF has a PT_INTERP program header, then we'll explore the entry
  // point. if not, we'll only consider it if it's statically-linked (i.Elf. it's
  // the dynamic linker)
  //
  bool HasInterpreter =
    std::any_of(PrgHdrs.begin(),
                PrgHdrs.end(),
                [](const Elf_Phdr &Phdr) -> bool{ return Phdr.p_type == llvm::ELF::PT_INTERP; });
  uint64_t EntryAddr = Elf.getHeader().e_entry;
  if (EntryAddr) {
#if 0
    llvm::outs() << llvm::formatv("entry point @ {0:x}\n", EntryAddr);
#endif

    b.Analysis.EntryFunction = FunctionAtAddress(EntryAddr);
  } else {
    b.Analysis.EntryFunction = invalid_function_index;
  }

  //
  // search local symbols (if they exist)
  //
  {
    llvm::Expected<Elf_Shdr_Range> ExpectedSections = Elf.sections();

    if (ExpectedSections) {
      const Elf_Shdr *SymTab = nullptr;

      for (const Elf_Shdr &Sect : *ExpectedSections) {
        if (Sect.sh_type == llvm::ELF::SHT_SYMTAB) {
          SymTab = &Sect;
          break;
        }
      }

      if (SymTab) {
        llvm::Expected<Elf_Sym_Range> ExpectedLocalSyms = Elf.symbols(SymTab);

        if (ExpectedLocalSyms) {
          auto LocalSyms = *ExpectedLocalSyms;

          for_each_if(std::execution::seq,
                      LocalSyms.begin(),
                      LocalSyms.end(),
                      [](const Elf_Sym &Sym) -> bool {
                        return !Sym.isUndefined() &&
                                Sym.getType() == llvm::ELF::STT_FUNC;
                      },
                      [&](const Elf_Sym &Sym) -> void {
                        BasicBlockAtAddress(Sym.st_value);
                      });
        }
      }
    }
  }

  //
  // look for split debug information
  //
  std::optional<llvm::ArrayRef<uint8_t>> optionalBuildID = elf::getBuildID(Elf);
  if (optionalBuildID) {
    llvm::ArrayRef<uint8_t> BuildID = *optionalBuildID;

    fs::path splitDbgInfo =
        fs::path("/usr/lib/debug") / ".build-id" /
        llvm::toHex(BuildID[0], /*LowerCase=*/true) /
        (llvm::toHex(BuildID.slice(1), /*LowerCase=*/true) + ".debug");

    if (fs::exists(splitDbgInfo)) {
#if 0
      WithColor::note() << llvm::formatv("found split debug info file {0}\n",
                                         splitDbgInfo.c_str());
#endif

      std::vector<uint8_t> SplitBinBytes;
      auto SplitBin = B::CreateFromFile(splitDbgInfo.c_str(), SplitBinBytes);

      assert(llvm::isa<ELFO>(SplitBin.get()));

      ELFO &split_Obj = *llvm::cast<ELFO>(SplitBin.get());
      const ELFF &split_Elf = split_Obj.getELFFile();

      //
      // examine local symbols (if they exist)
      //
      llvm::Expected<Elf_Shdr_Range> ExpectedSections = split_Elf.sections();
      if (ExpectedSections && !(*ExpectedSections).empty()) {
        const Elf_Shdr *SymTab = nullptr;

        for (const Elf_Shdr &Sec : *ExpectedSections) {
          if (Sec.sh_type == llvm::ELF::SHT_SYMTAB) {
            SymTab = &Sec;
            break;
          }
        }

        if (SymTab) {
          llvm::Expected<Elf_Sym_Range> ExpectedLocalSyms =
              split_Elf.symbols(SymTab);

          if (ExpectedLocalSyms) {
            auto LocalSyms = *ExpectedLocalSyms;

            for_each_if(std::execution::seq,
                        LocalSyms.begin(),
                        LocalSyms.end(),
                        [](const Elf_Sym &Sym) -> bool {
                          return !Sym.isUndefined() &&
                                  Sym.getType() == llvm::ELF::STT_FUNC;
                        },
                        [&](const Elf_Sym &Sym) -> void {
                          BasicBlockAtAddress(Sym.st_value);
                        });
          }
        }
      }
    } else {
      //WithColor::note() << llvm::formatv("build ID is {0}, no split debug found at {1}\n", llvm::toHex(BuildID, /*LowerCase=*/true), splitDbgInfo.string());
    }
  } else {
    //WithColor::note() << "no build ID\n";
  }

  llvm::StringRef DynamicStringTable;
  const Elf_Shdr *SymbolVersionSection = nullptr;
  std::vector<elf::VersionMapEntry> VersionMap;
  std::optional<elf::DynRegionInfo> OptionalDynSymRegion;

  if (DynamicTable.Addr)
    OptionalDynSymRegion =
        loadDynamicSymbols(O,
                           DynamicTable,
                           DynamicStringTable,
                           SymbolVersionSection,
                           VersionMap);

  //
  // examine exported functions
  //
  if (OptionalDynSymRegion) {
    auto DynSyms = OptionalDynSymRegion->getAsArrayRef<Elf_Sym>();

    for_each_if(std::execution::seq,
                DynSyms.begin(),
                DynSyms.end(),
                [](const Elf_Sym &Sym) -> bool {
                  return !Sym.isUndefined() &&
                          Sym.getType() == llvm::ELF::STT_FUNC;
                },
                [&](const Elf_Sym &Sym) -> void {
                  FunctionAtAddress(Sym.st_value);
                });

    for_each_if(std::execution::seq,
                DynSyms.begin(),
                DynSyms.end(),
                [](const Elf_Sym &Sym) -> bool {
                  return !Sym.isUndefined() &&
                          Sym.getType() == llvm::ELF::STT_GNU_IFUNC;
                },
                [&](const Elf_Sym &Sym) -> void {
                  ABIAtAddress(Sym.st_value);
                });

    //
    // XXX __libc_early_init (glibc)
    //
    if (SymbolVersionSection) {
      for_each_if(
          std::execution::seq,
          DynSyms.begin(),
          DynSyms.end(),
          [](const Elf_Sym &Sym) -> bool {
            return !Sym.isUndefined() &&
                   Sym.getType() == llvm::ELF::STT_FUNC;
          },
          [&](const Elf_Sym &Sym) -> void {
            llvm::Expected<llvm::StringRef> ExpectedSymName =
                Sym.getName(DynamicStringTable);

            if (!ExpectedSymName)
              return;

            llvm::StringRef SymName = *ExpectedSymName;
            llvm::StringRef SymVers;

            // Determine the position in the symbol table of this entry.
            size_t EntryIndex = (reinterpret_cast<uintptr_t>(&Sym) -
                                 reinterpret_cast<uintptr_t>(OptionalDynSymRegion->Addr)) /
                                sizeof(Elf_Sym);

            // Get the corresponding version index entry.
            llvm::Expected<const Elf_Versym *> ExpectedVersym =
                Elf.getEntry<Elf_Versym>(*SymbolVersionSection, EntryIndex);

            bool IsDefault;
            if (ExpectedVersym)
              SymVers = getSymbolVersionByIndex(VersionMap,
                                                DynamicStringTable,
                                                (*ExpectedVersym)->vs_index,
                                                IsDefault);

            if (SymName == "__libc_early_init" &&
                SymVers == "GLIBC_PRIVATE")
              ABIAtAddress(Sym.st_value);
          });
    }
  }

  //
  // search for constructor/deconstructor array
  //
  struct {
    uint64_t Beg, End;
  } InitArray = {0u, 0u};

  struct {
    uint64_t Beg, End;
  } FiniArray = {0u, 0u};

  {
    llvm::Expected<Elf_Shdr_Range> ExpectedSections = Elf.sections();

    if (ExpectedSections) {
      for (const Elf_Shdr &Sect : *ExpectedSections) {
        switch (Sect.sh_type) {
        case llvm::ELF::SHT_INIT_ARRAY:
          InitArray.Beg = Sect.sh_addr;
          InitArray.End = Sect.sh_addr + Sect.sh_size;
          break;
        case llvm::ELF::SHT_FINI_ARRAY:
          FiniArray.Beg = Sect.sh_addr;
          FiniArray.End = Sect.sh_addr + Sect.sh_size;
          break;
        }
      }
    }
  }

  //
  // examine relocations
  //
  elf::DynRegionInfo DynRelRegion(O);
  elf::DynRegionInfo DynRelaRegion(O);
  elf::DynRegionInfo DynRelrRegion(O);
  elf::DynRegionInfo DynPLTRelRegion(O);

  if (DynamicTable.Addr)
    loadDynamicRelocations(O,
                           DynamicTable,
                           DynRelRegion,
                           DynRelaRegion,
                           DynRelrRegion,
                           DynPLTRelRegion);

  //
  // Search for IFunc relocations and make their resolver functions be ABIs
  //
  {
    auto processDynamicReloc = [&](const elf::Relocation &R) -> void {
      //
      // ifunc resolvers are ABIs
      //
      if (elf_is_irelative_relocation(R)) {
        uint64_t resolverAddr = R.Addend ? *R.Addend : 0;

        if (!resolverAddr) {
          llvm::Expected<const uint8_t *> ExpectedPtr = Elf.toMappedAddr(R.Offset);
          if (ExpectedPtr)
            resolverAddr = B::extractAddress(Bin, *ExpectedPtr);
        }

        if (resolverAddr)
          ABIAtAddress(resolverAddr);
      }
    };

    for_each_dynamic_relocation(Elf,
                                DynRelRegion,
                                DynRelaRegion,
                                DynRelrRegion,
                                DynPLTRelRegion,
                                processDynamicReloc);
  }

  //
  // Search for relocations in .init_array/.fini_array and make the
  // constructor/deconstructor functions be ABIs
  //
  {
    auto processDynamicReloc = [&](const elf::Relocation &R) -> void {
      bool Contained = (R.Offset >= InitArray.Beg &&
                        R.Offset < InitArray.End) ||
                       (R.Offset >= FiniArray.Beg &&
                        R.Offset < FiniArray.End);
      if (!Contained)
        return;

      if (!elf_is_relative_relocation(R)) {
#if 0
        WithColor::warning() << llvm::formatv(
            "unrecognized relocation {0} in .init_array/.fini_array\n",
            Elf.getRelocationTypeName(R.Type));
#endif
        return;
      }

      //
      // constructors/deconstructors are ABIs
      //
      uint64_t Addr = R.Addend ? *R.Addend : 0;
      if (!Addr) {
        llvm::Expected<const uint8_t *> ExpectedPtr = Elf.toMappedAddr(R.Offset);

        if (ExpectedPtr)
          Addr = B::extractAddress(Bin, *ExpectedPtr);
      }

#if 0
      if (IsVerbose())
        WithColor::note() << llvm::formatv("ctor/dtor: off={0:x} Addr={1:x}\n",
                                           R.Offset, Addr);
#endif

      if (Addr)
        ABIAtAddress(Addr);
    };

    for_each_dynamic_relocation(Elf,
                                DynRelRegion,
                                DynRelaRegion,
                                DynRelrRegion,
                                DynPLTRelRegion,
                                processDynamicReloc);
  }
    });

  B::_coff(Bin,
    [&](COFFO &O) {
      //b.IsExecutable = O.getCharacteristics() & llvm::COFF::IMAGE_FILE_DLL;

      uint64_t entryRVA = 0;
      if (const obj::pe32plus_header *PEPlusHeader = O.getPE32PlusHeader()) {
        entryRVA = PEPlusHeader->AddressOfEntryPoint;
        b.IsPIC = PEPlusHeader->DLLCharacteristics &
                  llvm::COFF::IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE;
      } else if (const obj::pe32_header *PEHeader = O.getPE32Header()) {
        entryRVA = PEHeader->AddressOfEntryPoint;
        b.IsPIC = PEHeader->DLLCharacteristics &
                  llvm::COFF::IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE;
      }

      if (entryRVA)
        b.Analysis.EntryFunction = FunctionAtAddress(coff::va_of_rva(O, entryRVA));

      auto exp_itr = O.export_directories();
      for_each_if(std::execution::seq,
                  exp_itr.begin(),
                  exp_itr.end(),
                  [&](const obj::ExportDirectoryEntryRef &Exp) -> bool {
                    llvm::StringRef Name;
                    uint32_t Ordinal;
                    bool IsForwarder;
                    uint32_t RVA;

                    return !llvm::errorToBool(Exp.getSymbolName(Name)) &&
                           !llvm::errorToBool(Exp.getOrdinal(Ordinal)) &&
                           !llvm::errorToBool(Exp.isForwarder(IsForwarder)) &&
                           !IsForwarder &&
                           !llvm::errorToBool(Exp.getExportRVA(RVA)) &&
                           coff::isCode(O, coff::va_of_rva(O, RVA));
                  },
                  [&](const obj::ExportDirectoryEntryRef &Exp) -> void {
                      uint32_t RVA;
                      bool iserr = llvm::errorToBool(Exp.getExportRVA(RVA));
                      assert(!iserr);

                      ABIAtAddress(coff::va_of_rva(O, RVA));
                  });

      for_each_if(std::execution::seq,
                  O.symbol_begin(),
                  O.symbol_end(),
                  [&](obj::SymbolRef SymbolRef) -> bool {
                    llvm::Expected<uint64_t> AddrOrErr = SymbolRef.getAddress();
                    if (!AddrOrErr) {
                      llvm::consumeError(AddrOrErr.takeError());
                      return false;
                    }

                    obj::COFFSymbolRef Symbol = O.getCOFFSymbol(SymbolRef);

                    if (Symbol.getNumberOfAuxSymbols() > 0)
                      return false;

                    llvm::Expected<llvm::StringRef> NameOrErr = O.getSymbolName(Symbol);
                    if (!NameOrErr) {
                      llvm::consumeError(NameOrErr.takeError());
                      return false;
                    }

                    llvm::Expected<obj::section_iterator> ItOrErr = SymbolRef.getSection();

                    if (!ItOrErr) {
                      llvm::consumeError(ItOrErr.takeError());
                      return false;
                    }

                    obj::section_iterator it = *ItOrErr;
                    if (it == O.section_end())
                      return false;

                    const obj::coff_section *Section = O.getCOFFSection(*it);
                    return Section && Section->Characteristics & llvm::COFF::IMAGE_SCN_MEM_EXECUTE;
                  },
                  [&](obj::SymbolRef SymbolRef) -> void {
                    obj::COFFSymbolRef Symbol = O.getCOFFSymbol(SymbolRef);

#if 0
                    llvm::Expected<llvm::StringRef> NameOrErr = O.getSymbolName(Symbol);
                    assert(NameOrErr);

                    llvm::errs() << "exploring " << *NameOrErr << ' ' << Symbol.getValue() <<  " @ " << taddr2str(coff::va_of_rva(O, Symbol.getValue())) << '\n';
#endif

                    auto AddrOrErr = SymbolRef.getAddress();
                    assert(AddrOrErr);

                    ABIAtAddress(*AddrOrErr);
                  });

      // XXX we cannot completely rely on isCode() to tell us whether something
      // is code, so the following is #ifdef'd out- none of these addresses are
      // necessarily functions.
#if 0
      coff::for_each_base_relocation(
          O, [&](uint8_t RelocType, uint64_t RVA) -> void {
            if (!coff_is_dir_relocation(RelocType))
              return;

            const void *Ptr = coff::toMappedAddr(O, coff::va_of_rva(O, RVA));
            if (!Ptr)
              return;
            uint64_t Addr = B::extractAddress(O, Ptr);
            if (coff::isCode(O, Addr))
              ABIAtAddress(Addr);
          });
#endif
    }
  );

  ScanForSjLj(b, Bin, explorer);
}

#define VALUES_TO_INSTANTIATE_WITH                                             \
    ((true))                                                                   \
    ((false))

#define GET_VALUE(x) BOOST_PP_TUPLE_ELEM(0, x)
#define DO_INSTANTIATE(r, MT2, elem)                                           \
  template void jv_base_t<GET_VALUE(elem)>::DoAdd<MT2>(                        \
      binary_base_t<MT2> &, explorer_t &, llvm::object::Binary &,              \
      const AddOptions_t &);
BOOST_PP_SEQ_FOR_EACH(DO_INSTANTIATE, true, VALUES_TO_INSTANTIATE_WITH)
BOOST_PP_SEQ_FOR_EACH(DO_INSTANTIATE, false, VALUES_TO_INSTANTIATE_WITH)

}
