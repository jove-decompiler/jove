#include "jove/jove.h"
#include "B.h"
#include "hash.h"
#include "explore.h"

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

void jv_t::DoAdd(binary_t &b, explorer_t &E) {
  std::unique_ptr<obj::Binary> Bin = B::Create(b.data());

  b.IsDynamicLinker = false;
  b.IsExecutable = false;
  b.IsVDSO = false;

  b.IsPIC = true;
  b.IsDynamicallyLoaded = false;

  auto BasicBlockAtAddress = [&](uint64_t Entrypoint) -> void {
    E.explore_basic_block(b, *Bin, Entrypoint);
  };
  auto FunctionAtAddress = [&](uint64_t Entrypoint) -> function_index_t {
    return E.explore_function(b, *Bin, Entrypoint);
  };
  auto ABIAtAddress = [&](uint64_t Entrypoint) -> void {
    function_index_t FIdx = FunctionAtAddress(Entrypoint);

    if (unlikely(!is_function_index_valid(FIdx)))
      return;

    b.Analysis.Functions.at(FIdx).IsABI = true;
  };

  return B::_X(*Bin,
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
    llvm::outs() << llvm::formatv("entry point @ {0:x}\n", EntryAddr);

    b.Analysis.EntryFunction = E.explore_function(b, O, EntryAddr);
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

          for_each_if(std::execution::par_unseq,
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
      WithColor::note() << llvm::formatv("found split debug info file {0}\n",
                                         splitDbgInfo.c_str());

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

            for_each_if(std::execution::par_unseq,
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

    for_each_if(std::execution::par_unseq,
                DynSyms.begin(),
                DynSyms.end(),
                [](const Elf_Sym &Sym) -> bool {
                  return !Sym.isUndefined() &&
                          Sym.getType() == llvm::ELF::STT_FUNC;
                },
                [&](const Elf_Sym &Sym) -> void {
                  FunctionAtAddress(Sym.st_value);
                });

    for_each_if(std::execution::par_unseq,
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
          std::execution::par_unseq,
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
            resolverAddr = B::extractAddress(*Bin, *ExpectedPtr);
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
        WithColor::warning() << llvm::formatv(
            "unrecognized relocation {0} in .init_array/.fini_array\n",
            Elf.getRelocationTypeName(R.Type));
        return;
      }

      //
      // constructors/deconstructors are ABIs
      //
      uint64_t Addr = R.Addend ? *R.Addend : 0;
      if (!Addr) {
        llvm::Expected<const uint8_t *> ExpectedPtr = Elf.toMappedAddr(R.Offset);

        if (ExpectedPtr)
          Addr = B::extractAddress(*Bin, *ExpectedPtr);
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

  //
  // setjmp/longjmp hunting
  //
  std::vector<llvm::StringRef> LjPatterns;
  std::vector<llvm::StringRef> SjPatterns;

#if defined(TARGET_X86_64)
  {
    // glibc
    static const uint8_t pattern[] = {
      0x4c, 0x8b, 0x47, 0x30,                   // mov    0x30(%rdi),%r8
      0x4c, 0x8b, 0x4f, 0x08,                   // mov    0x8(%rdi),%r9
      0x48, 0x8b, 0x57, 0x38,                   // mov    0x38(%rdi),%rdx
      0x49, 0xc1, 0xc8, 0x11,                   // ror    $0x11,%r8
      0x64, 0x4c, 0x33, 0x04, 0x25, 0x30, 0x00, // xor    %fs:0x30,%r8
      0x00, 0x00,
      0x49, 0xc1, 0xc9, 0x11,                   // ror    $0x11,%r9
      0x64, 0x4c, 0x33, 0x0c, 0x25, 0x30, 0x00, // xor    %fs:0x30,%r9
      0x00, 0x00,
      0x48, 0xc1, 0xca, 0x11,                   // ror    $0x11,%rdx
      0x64, 0x48, 0x33, 0x14, 0x25, 0x30, 0x00, // xor    %fs:0x30,%rdx
      0x00, 0x00,
      0x48, 0x8b, 0x1f,                         // mov    (%rdi),%rbx
      0x4c, 0x8b, 0x67, 0x10,                   // mov    0x10(%rdi),%r12
      0x4c, 0x8b, 0x6f, 0x18,                   // mov    0x18(%rdi),%r13
      0x4c, 0x8b, 0x77, 0x20,                   // mov    0x20(%rdi),%r14
      0x4c, 0x8b, 0x7f, 0x28,                   // mov    0x28(%rdi),%r15
      0x89, 0xf0,                               // mov    %esi,%eax
      0x4c, 0x89, 0xc4,                         // mov    %r8,%rsp
      0x4c, 0x89, 0xcd,                         // mov    %r9,%rbp
      0xff, 0xe2,                               // jmp    *%rdx
    };

    LjPatterns.emplace_back(reinterpret_cast<const char *>(&pattern[0]),
                            sizeof(pattern));
  }

  {
    // glibc
    static const uint8_t pattern[] = {
      0x48, 0x89, 0x1f,                         // mov    %rbx,(%rdi)
      0x48, 0x89, 0xe8,                         // mov    %rbp,%rax
      0x64, 0x48, 0x33, 0x04, 0x25, 0x30, 0x00, // xor    %fs:0x30,%rax
      0x00, 0x00,
      0x48, 0xc1, 0xc0, 0x11,                   // rol    $0x11,%rax
      0x48, 0x89, 0x47, 0x08,                   // mov    %rax,0x8(%rdi)
      0x4c, 0x89, 0x67, 0x10,                   // mov    %r12,0x10(%rdi)
      0x4c, 0x89, 0x6f, 0x18,                   // mov    %r13,0x18(%rdi)
      0x4c, 0x89, 0x77, 0x20,                   // mov    %r14,0x20(%rdi)
      0x4c, 0x89, 0x7f, 0x28,                   // mov    %r15,0x28(%rdi)
      0x48, 0x8d, 0x54, 0x24, 0x08,             // lea    0x8(%rsp),%rdx
      0x64, 0x48, 0x33, 0x14, 0x25, 0x30, 0x00, // xor    %fs:0x30,%rdx
      0x00, 0x00,
      0x48, 0xc1, 0xc2, 0x11,                   // rol    $0x11,%rdx
      0x48, 0x89, 0x57, 0x30,                   // mov    %rdx,0x30(%rdi)
      0x48, 0x8b, 0x04, 0x24,                   // mov    (%rsp),%rax
      0x64, 0x48, 0x33, 0x04, 0x25, 0x30, 0x00, // xor    %fs:0x30,%rax
      0x00, 0x00,
      0x48, 0xc1, 0xc0, 0x11,                   // rol    $0x11,%rax
      0x48, 0x89, 0x47, 0x38,                   // mov    %rax,0x38(%rdi)

    };

    SjPatterns.emplace_back(reinterpret_cast<const char *>(&pattern[0]),
                            sizeof(pattern));
  }
#elif defined(TARGET_I386)
  {
    // glibc
    static const uint8_t pattern[] = {
      0x8b, 0x44, 0x24, 0x04,                   //  mov    0x4(%esp),%eax
      0x8b, 0x50, 0x14,                         //  mov    0x14(%eax),%edx
      0x8b, 0x48, 0x10,                         //  mov    0x10(%eax),%ecx
      0xc1, 0xca, 0x09,                         //  ror    $0x9,%edx
      0x65, 0x33, 0x15, 0x18, 0x00, 0x00, 0x00, //  xor    %gs:0x18,%edx
      0xc1, 0xc9, 0x09,                         //  ror    $0x9,%ecx
      0x65, 0x33, 0x0d, 0x18, 0x00, 0x00, 0x00, //  xor    %gs:0x18,%ecx
      0x8b, 0x18,                               //  mov    (%eax),%ebx
      0x8b, 0x70, 0x04,                         //  mov    0x4(%eax),%esi
      0x8b, 0x78, 0x08,                         //  mov    0x8(%eax),%edi
      0x8b, 0x68, 0x0c,                         //  mov    0xc(%eax),%ebp
      0x8b, 0x44, 0x24, 0x08,                   //  mov    0x8(%esp),%eax
      0x89, 0xcc,                               //  mov    %ecx,%esp
      0xff, 0xe2,                               //  jmp    *%edx
    };

    LjPatterns.emplace_back(reinterpret_cast<const char *>(&pattern[0]),
                            sizeof(pattern));
  }

  {
    // glibc
    static const uint8_t pattern[] = {
      0x8b, 0x44, 0x24, 0x04,                   // mov    0x4(%esp),%eax
      0x89, 0x18,                               // mov    %ebx,(%eax)
      0x89, 0x70, 0x04,                         // mov    %esi,0x4(%eax)
      0x89, 0x78, 0x08,                         // mov    %edi,0x8(%eax)
      0x8d, 0x4c, 0x24, 0x04,                   // lea    0x4(%esp),%ecx
      0x65, 0x33, 0x0d, 0x18, 0x00, 0x00, 0x00, // xor    %gs:0x18,%ecx
      0xc1, 0xc1, 0x09,                         // rol    $0x9,%ecx
      0x89, 0x48, 0x10,                         // mov    %ecx,0x10(%eax)
      0x8b, 0x0c, 0x24,                         // mov    (%esp),%ecx
      0x65, 0x33, 0x0d, 0x18, 0x00, 0x00, 0x00, // xor    %gs:0x18,%ecx
      0xc1, 0xc1, 0x09,                         // rol    $0x9,%ecx
      0x89, 0x48, 0x14,                         // mov    %ecx,0x14(%eax)
      0x89, 0x68, 0x0c,                         // mov    %ebp,0xc(%eax)
    };

    SjPatterns.emplace_back(reinterpret_cast<const char *>(&pattern[0]),
                            sizeof(pattern));
  }

  {
    // glibc
    static const uint8_t pattern[] = {
      0x31, 0xc0,                               // xor    %eax,%eax
      0x8b, 0x54, 0x24, 0x04,                   // mov    0x4(%esp),%edx
      0x89, 0x1a,                               // mov    %ebx,(%edx)
      0x89, 0x72, 0x04,                         // mov    %esi,0x4(%edx)
      0x89, 0x7a, 0x08,                         // mov    %edi,0x8(%edx)
      0x8d, 0x4c, 0x24, 0x04,                   // lea    0x4(%esp),%ecx
      0x65, 0x33, 0x0d, 0x18, 0x00, 0x00, 0x00, // xor    %gs:0x18,%ecx
      0xc1, 0xc1, 0x09,                         // rol    $0x9,%ecx
      0x89, 0x4a, 0x10,                         // mov    %ecx,0x10(%edx)
      0x8b, 0x0c, 0x24,                         // mov    (%esp),%ecx
      0x65, 0x33, 0x0d, 0x18, 0x00, 0x00, 0x00, // xor    %gs:0x18,%ecx
      0xc1, 0xc1, 0x09,                         // rol    $0x9,%ecx
      0x89, 0x4a, 0x14,                         // mov    %ecx,0x14(%edx)
      0x89, 0x6a, 0x0c,                         // mov    %ebp,0xc(%edx)
      0x89, 0x42, 0x18,                         // mov    %eax,0x18(%edx)
      0xc3                                      // ret
    };

    SjPatterns.emplace_back(reinterpret_cast<const char *>(&pattern[0]),
                            sizeof(pattern));
  }

#elif defined(TARGET_MIPS32)
  {
    // glibc
    static const uint32_t pattern[] = {
      0xd4940038,                               // ldc1    $f20,56(a0)
      0xd4960040,                               // ldc1    $f22,64(a0)
      0xd4980048,                               // ldc1    $f24,72(a0)
      0xd49a0050,                               // ldc1    $f26,80(a0)
      0xd49c0058,                               // ldc1    $f28,88(a0)
      0xd49e0060,                               // ldc1    $f30,96(a0)
      0x8c9c002c,                               // lw      gp,44(a0)
      0x8c900008,                               // lw      s0,8(a0)
      0x8c91000c,                               // lw      s1,12(a0)
      0x8c920010,                               // lw      s2,16(a0)
      0x8c930014,                               // lw      s3,20(a0)
      0x8c940018,                               // lw      s4,24(a0)
      0x8c95001c,                               // lw      s5,28(a0)
      0x8c960020,                               // lw      s6,32(a0)
      0x8c970024,                               // lw      s7,36(a0)
      0x8c990000,                               // lw      t9,0(a0)
      0x8c9d0004,                               // lw      sp,4(a0)
      0x14a00005,                               // bnez    a1,354ec
      0x8c9e0028,                               // lw      s8,40(a0)
      0x03200008,                               // jr      t9
      0x24020001,                               // li      v0,1
      0x1000ffff,                               // b       354e4
      0x00000000,                               // nop
      0x03200008,                               // jr      t9
      0x00a01025,                               // move    v0,a1
    };

    LjPatterns.emplace_back(reinterpret_cast<const char *>(&pattern[0]),
                            sizeof(pattern));
  }

  {
    // libuClibc
    static const uint32_t pattern[] = {
      0xc4940038,                               // lwc1    $f20,56(a0)
      0xc495003c,                               // lwc1    $f21,60(a0)
      0xc4960040,                               // lwc1    $f22,64(a0)
      0xc4970044,                               // lwc1    $f23,68(a0)
      0xc4980048,                               // lwc1    $f24,72(a0)
      0xc499004c,                               // lwc1    $f25,76(a0)
      0xc49a0050,                               // lwc1    $f26,80(a0)
      0xc49b0054,                               // lwc1    $f27,84(a0)
      0xc49c0058,                               // lwc1    $f28,88(a0)
      0xc49d005c,                               // lwc1    $f29,92(a0)
      0xc49e0060,                               // lwc1    $f30,96(a0)
      0xc49f0064,                               // lwc1    $f31,100(a0)
      0x8c820030,                               // lw      v0,48(a0)
      0x00000000,                               // nop
      0x44c2f800,                               // ctc1    v0,c1_fcsr
      0x8c9c002c,                               // lw      gp,44(a0)
      0x8c900008,                               // lw      s0,8(a0)
      0x8c91000c,                               // lw      s1,12(a0)
      0x8c920010,                               // lw      s2,16(a0)
      0x8c930014,                               // lw      s3,20(a0)
      0x8c940018,                               // lw      s4,24(a0)
      0x8c95001c,                               // lw      s5,28(a0)
      0x8c960020,                               // lw      s6,32(a0)
      0x8c970024,                               // lw      s7,36(a0)
      0x8c990000,                               // lw      t9,0(a0)
      0x8c9d0004,                               // lw      sp,4(a0)
      0x8c9e0028,                               // lw      s8,40(a0)
      0x14a00003,                               // bnez    a1,4cbfc
      0x00000000,                               // nop
      0x10000002,                               // b       4cc00
      0x24020001,                               // li      v0,1
      0x00a01021,                               // move    v0,a1
      0x03200008,                               // jr      t9
      0x00000000,                               // nop
    };

    LjPatterns.emplace_back(reinterpret_cast<const char *>(&pattern[0]),
                            sizeof(pattern));
  }
  {
    // glibc
    static const uint32_t pattern[] = {
      0xf4940038,                               // sdc1    $f20,56(a0)
      0xf4960040,                               // sdc1    $f22,64(a0)
      0xf4980048,                               // sdc1    $f24,72(a0)
      0xf49a0050,                               // sdc1    $f26,80(a0)
      0xf49c0058,                               // sdc1    $f28,88(a0)
      0xf49e0060,                               // sdc1    $f30,96(a0)
      0xac9f0000,                               // sw      ra,0(a0)
      0xac860004,                               // sw      a2,4(a0)
      0xac870028,                               // sw      a3,40(a0)
      0xac9c002c,                               // sw      gp,44(a0)
      0xac900008,                               // sw      s0,8(a0)
      0xac91000c,                               // sw      s1,12(a0)
      0xac920010,                               // sw      s2,16(a0)
      0xac930014,                               // sw      s3,20(a0)
      0xac940018,                               // sw      s4,24(a0)
      0xac95001c,                               // sw      s5,28(a0)
      0xac960020,                               // sw      s6,32(a0)
      0xac970024,                               // sw      s7,36(a0)
    };

    SjPatterns.emplace_back(reinterpret_cast<const char *>(&pattern[0]),
                            sizeof(pattern));
  }
  {
    // libuClibc
    static const uint32_t pattern[] = {
      0x00801021,                               // move    v0,a0
      0xe4940038,                               // swc1    $f20,56(a0)
      0xe495003c,                               // swc1    $f21,60(a0)
      0xe4960040,                               // swc1    $f22,64(a0)
      0xe4970044,                               // swc1    $f23,68(a0)
      0xe4980048,                               // swc1    $f24,72(a0)
      0xe499004c,                               // swc1    $f25,76(a0)
      0xe49a0050,                               // swc1    $f26,80(a0)
      0xe49b0054,                               // swc1    $f27,84(a0)
      0xe49c0058,                               // swc1    $f28,88(a0)
      0xe49d005c,                               // swc1    $f29,92(a0)
      0xe49e0060,                               // swc1    $f30,96(a0)
      0xe49f0064,                               // swc1    $f31,100(a0)
      0xac9f0000,                               // sw      ra,0(a0)
      0xac860004,                               // sw      a2,4(a0)
      0xac870028,                               // sw      a3,40(a0)
      0xac9c002c,                               // sw      gp,44(a0)
      0xac900008,                               // sw      s0,8(a0)
      0xac91000c,                               // sw      s1,12(a0)
      0xac920010,                               // sw      s2,16(a0)
      0xac930014,                               // sw      s3,20(a0)
      0xac940018,                               // sw      s4,24(a0)
      0xac95001c,                               // sw      s5,28(a0)
      0xac960020,                               // sw      s6,32(a0)
      0xac970024,                               // sw      s7,36(a0)
    };

    SjPatterns.emplace_back(reinterpret_cast<const char *>(&pattern[0]),
                            sizeof(pattern));
  }
#endif

  auto ProgramHeadersOrError = Elf.program_headers();
  if (ProgramHeadersOrError) {
    llvm::SmallVector<const Elf_Phdr *, 4> LoadSegments;

    for (const Elf_Phdr &Phdr : *ProgramHeadersOrError)
      if (Phdr.p_type == llvm::ELF::PT_LOAD)
        LoadSegments.push_back(const_cast<Elf_Phdr *>(&Phdr));

    for (const Elf_Phdr *P : LoadSegments) {
      llvm::StringRef SectionStr(
          reinterpret_cast<const char *>(Elf.base() + P->p_offset), P->p_filesz);

      for (llvm::StringRef pattern : LjPatterns) {
        size_t idx = SectionStr.find(pattern);
        if (idx == llvm::StringRef::npos)
          continue;

        uint64_t A = P->p_vaddr + idx;

        basic_block_index_t BBIdx = E.explore_basic_block(b, O, A);
        if (!is_basic_block_index_valid(BBIdx))
          continue;

        auto &ICFG = b.Analysis.ICFG;

        std::vector<basic_block_t> bbvec;
        std::map<basic_block_t, boost::default_color_type> color;

        struct bb_visitor : public boost::default_dfs_visitor {
          basic_block_vec_t &out;

          bb_visitor(basic_block_vec_t &out) : out(out) {}

          void discover_vertex(basic_block_t bb, const icfg_t &) const {
            out.push_back(bb);
          }
        };

        bb_visitor vis(bbvec);
        depth_first_visit(
            ICFG, basic_block_of_index(BBIdx, ICFG), vis,
            boost::associative_property_map<
                std::map<basic_block_t, boost::default_color_type>>(color));

        for_each_if(
            bbvec.begin(),
            bbvec.end(),
            [&](basic_block_t bb) -> bool {
              return ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP &&
                     boost::out_degree(bb, ICFG) == 0;
            },
            [&](basic_block_t bb) {
              WithColor::note()
                  << llvm::formatv("found longjmp @ {0:x}\n", ICFG[bb].Addr);

              ICFG[bb].Term._indirect_jump.IsLj = true;
            });
      }

      for (llvm::StringRef pattern : SjPatterns) {
        size_t idx = SectionStr.find(pattern);
        if (idx == llvm::StringRef::npos)
          continue;

        uint64_t A = P->p_vaddr + idx;

        basic_block_index_t BBIdx = E.explore_basic_block(b, O, A);
        if (!is_basic_block_index_valid(BBIdx))
          continue;

        auto &ICFG = b.Analysis.ICFG;

        WithColor::note() << llvm::formatv("found setjmp @ {0:x}\n", A);

        ICFG[basic_block_of_index(BBIdx, ICFG)].Sj = true;
      }
    }
  }
    },

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
        E.explore_function(b, O, coff::va_of_rva(O, entryRVA));

      auto exp_itr = O.export_directories();
      for_each_if(std::execution::par_unseq,
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
                           coff::isCode(O, RVA);
                  },
                  [&](const obj::ExportDirectoryEntryRef &Exp) -> void {
                      uint32_t RVA;
                      bool iserr = llvm::errorToBool(Exp.getExportRVA(RVA));
                      assert(!iserr);

                      ABIAtAddress(coff::va_of_rva(O, RVA));
                  });

      for_each_if(std::execution::par_unseq,
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

      coff::for_each_base_relocation(O,
                                    [&](uint8_t RelocType, uint64_t RVA) -> void {
                                    if (!coff_is_dir_relocation(RelocType))
                                    return;

                                    const void *Ptr = coff::toMappedAddr(
                                        O, coff::va_of_rva(O, RVA));
                                    if (!Ptr)
                                      return;
                                    uint64_t Addr = B::extractAddress(O, Ptr);
                                    if (coff::isCode(O, coff::offset_of_va(O, Addr)))
                                      ABIAtAddress(Addr);
                                    });
    }
  );
}

}
