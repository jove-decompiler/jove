#include <llvm/Object/ELFObjectFile.h>
#include <boost/icl/split_interval_map.hpp>

#define JOVE_EXTRA_BIN_PROPERTIES                                              \
  boost::icl::split_interval_map<tcg_uintptr_t, basic_block_index_t> BBMap;    \
  std::unordered_map<tcg_uintptr_t, function_index_t> FuncMap;                 \
                                                                               \
  std::unique_ptr<llvm::object::Binary> ObjectFile;

#include "tcgcommon.hpp"
#include "sha3.hpp"

#include <tuple>
#include <memory>
#include <sstream>
#include <fstream>
#include <boost/filesystem.hpp>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCObjectFileInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/Object/ELF.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/WithColor.h>
#include <llvm/Support/FormatVariadic.h>

#include "jove/jove.h"
#include <boost/range/adaptor/reversed.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/bitset.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/graph/adj_list_serialize.hpp>
#include <boost/graph/depth_first_search.hpp>
#include <boost/icl/split_interval_map.hpp>
#include <boost/format.hpp>

#include <signal.h>

#ifdef __mips64
#include <unistd.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#endif

extern "C" {
void __attribute__((noinline))
     __attribute__((visibility("default")))
UserBreakPoint(void) {
  puts(__func__);
}
}

#include "jove_macros.h"

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace opts {
static cl::OptionCategory JoveCategory("Specific Options");

static cl::opt<std::string> Input("input",
                                  cl::desc("Path to DSO"),
                                  cl::Required, cl::value_desc("filename"),
                                  cl::cat(JoveCategory));

static cl::alias InputAlias("i", cl::desc("Alias for -input."),
                            cl::aliasopt(Input), cl::cat(JoveCategory));

static cl::opt<std::string> Output("output", cl::desc("Jove decompilation"),
                                   cl::Required, cl::value_desc("filename"),
                                   cl::cat(JoveCategory));

static cl::alias OutputAlias("o", cl::desc("Alias for -output."),
                             cl::aliasopt(Output), cl::cat(JoveCategory));

static cl::opt<bool>
    Verbose("verbose",
            cl::desc("Print extra information for debugging purposes"),
            cl::cat(JoveCategory));

static cl::alias VerboseAlias("v", cl::desc("Alias for -verbose."),
                              cl::aliasopt(Verbose), cl::cat(JoveCategory));

static cl::opt<std::string> BreakOnAddr(
    "break-on-addr",
    cl::desc("Allow user to set a debugger breakpoint on TCGDumpBreakPoint, "
             "and triggered when basic block address matches given address"),
    cl::cat(JoveCategory));
} // namespace opts

namespace jove {
static int add(void);
}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::HideUnrelatedOptions({&opts::JoveCategory, &llvm::ColorCategory});
  cl::AddExtraVersionPrinter([](llvm::raw_ostream &OS) -> void {
    OS << "jove version " JOVE_VERSION "\n";
  });
  cl::ParseCommandLineOptions(argc, argv, "Jove Add\n");

  if (!fs::exists(opts::Input)) {
    WithColor::error() << "input binary does not exist\n";
    return 1;
  }

#ifndef __mips64
  return jove::add();
#else
  long rc = jove::add();
  syscall(__NR_exit_group, rc);
  __builtin_trap();
  __builtin_unreachable();
#endif
}

namespace jove {

typedef boost::format fmt;

typedef std::tuple<llvm::MCDisassembler &,
                   const llvm::MCSubtargetInfo &,
                   llvm::MCInstPrinter &> disas_t;

static decompilation_t decompilation;

static function_index_t translate_function(binary_t &, tiny_code_generator_t &,
                                           disas_t &, target_ulong Addr);

static basic_block_index_t translate_basic_block(binary_t &,
                                                 tiny_code_generator_t &,
                                                 disas_t &,
                                                 const target_ulong Addr);

#include "elf.hpp"

template <typename GraphTy>
struct dfs_visitor : public boost::default_dfs_visitor {
  typedef typename GraphTy::vertex_descriptor VertTy;

  std::vector<VertTy> &out;

  dfs_visitor(std::vector<VertTy> &out) : out(out) {}

  void discover_vertex(VertTy v, const GraphTy &) const { out.push_back(v); }
};

static struct {
  target_ulong Addr;
  bool Active;
} BreakOn = {.Active = false};

static void IgnoreCtrlC(void);

int add(void) {
  if (!opts::BreakOnAddr.empty()) {
    BreakOn.Active = true;
    BreakOn.Addr = std::stoi(opts::BreakOnAddr.c_str(), 0, 16);
  }

  tiny_code_generator_t tcg;

  llvm::InitializeAllTargets();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllAsmPrinters();
  llvm::InitializeAllAsmParsers();
  llvm::InitializeAllDisassemblers();

  llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> FileOrErr =
      llvm::MemoryBuffer::getFileOrSTDIN(opts::Input);

  if (std::error_code EC = FileOrErr.getError()) {
    WithColor::error() << "failed to open " << opts::Input << '\n';
    return 1;
  }

  std::unique_ptr<llvm::MemoryBuffer> &Buffer = FileOrErr.get();

  llvm::Expected<std::unique_ptr<obj::Binary>> BinOrErr =
      obj::createBinary(Buffer->getMemBufferRef());

  binary_t &b = decompilation.Binaries.emplace_back();

  if (!BinOrErr) {
    //
    // interpret as a raw stream of instructions
    //
    {
      b.IsDynamicLinker = false;
      b.IsExecutable = false;
      b.IsVDSO = false;

      b.IsPIC = true;
      b.IsDynamicallyLoaded = false;

      b.Path = fs::canonical(opts::Input).string();
      b.Data.resize(Buffer->getBufferSize());
      memcpy(&b.Data[0], Buffer->getBufferStart(), b.Data.size());
    }

    IgnoreCtrlC(); /* user probably doesn't want to interrupt the following */

    {
      std::ofstream ofs(opts::Output);

      boost::archive::text_oarchive oa(ofs);
      oa << decompilation;
    }

    return 0;
  }

  std::unique_ptr<obj::Binary> &BinRef = BinOrErr.get();

  if (!llvm::isa<ELFO>(BinRef.get())) {
    WithColor::error() << "is not ELF of expected type\n";
    return 1;
  }

  ELFO &O = *llvm::cast<ELFO>(BinRef.get());

  std::string ArchName;
  llvm::Triple TheTriple = O.makeTriple();
  std::string Error;

  const llvm::Target *TheTarget =
      llvm::TargetRegistry::lookupTarget(ArchName, TheTriple, Error);
  if (!TheTarget) {
    WithColor::error() << "failed to lookup target: " << Error << '\n';
    return 1;
  }

  std::string TripleName = TheTriple.getTriple();
  std::string MCPU;
  llvm::SubtargetFeatures Features = O.getFeatures();

  std::unique_ptr<const llvm::MCRegisterInfo> MRI(
      TheTarget->createMCRegInfo(TripleName));
  if (!MRI) {
    WithColor::error() << "no register info for target\n";
    return 1;
  }

  llvm::MCTargetOptions Options;
  std::unique_ptr<const llvm::MCAsmInfo> AsmInfo(
      TheTarget->createMCAsmInfo(*MRI, TripleName, Options));
  if (!AsmInfo) {
    WithColor::error() << "no assembly info\n";
    return 1;
  }

  std::unique_ptr<const llvm::MCSubtargetInfo> STI(
      TheTarget->createMCSubtargetInfo(TripleName, MCPU, Features.getString()));
  if (!STI) {
    WithColor::error() << "no subtarget info\n";
    return 1;
  }

  std::unique_ptr<const llvm::MCInstrInfo> MII(TheTarget->createMCInstrInfo());
  if (!MII) {
    WithColor::error() << "no instruction info\n";
    return 1;
  }

  llvm::MCObjectFileInfo MOFI;
  llvm::MCContext Ctx(AsmInfo.get(), MRI.get(), &MOFI);
  // FIXME: for now initialize MCObjectFileInfo with default values
  MOFI.InitMCObjectFileInfo(llvm::Triple(TripleName), false, Ctx);

  std::unique_ptr<llvm::MCDisassembler> DisAsm(
      TheTarget->createMCDisassembler(*STI, Ctx));
  if (!DisAsm) {
    WithColor::error() << "no disassembler for target\n";
    return 1;
  }

  int AsmPrinterVariant = AsmInfo->getAssemblerDialect();
  std::unique_ptr<llvm::MCInstPrinter> IP(TheTarget->createMCInstPrinter(
      llvm::Triple(TripleName), AsmPrinterVariant, *AsmInfo, *MII, *MRI));
  if (!IP) {
    WithColor::error() << "no instruction printer\n";
    return 1;
  }

  //
  // initialize the decompilation of the given binary by exploring every defined
  // exported function
  //
  if (fs::exists(opts::Output)) {
    std::ifstream ifs(opts::Output);

    boost::archive::text_iarchive ia(ifs);
    ia >> decompilation;
  }

  b.ObjectFile = std::move(BinRef);

  b.IsDynamicLinker = false;
  b.IsExecutable = false;
  b.IsVDSO = false;

  b.IsPIC = true;
  b.IsDynamicallyLoaded = false;

  b.Path = fs::canonical(opts::Input).string();
  b.Data.resize(Buffer->getBufferSize());
  memcpy(&b.Data[0], Buffer->getBufferStart(), b.Data.size());

  const ELFF &E = *O.getELFFile();

  switch (E.getHeader()->e_type) {
  case llvm::ELF::ET_NONE:
    WithColor::error() << "given binary has unknown type\n";
    return 1;

  case llvm::ELF::ET_REL:
    WithColor::error() << "given binary is object file?\n";
    return 1;

  case llvm::ELF::ET_EXEC:
    b.IsPIC = false;
    break;

  case llvm::ELF::ET_DYN:
    break;

  case llvm::ELF::ET_CORE:
    WithColor::error() << "given binary is core file\n";
    return 1;

  default:
    abort();
    break;
  }

  disas_t dis(*DisAsm, std::cref(*STI), *IP);

  DynRegionInfo DynamicTable(O.getFileName());
  loadDynamicTable(&E, &O, DynamicTable);

  assert(DynamicTable.Addr);

  auto dynamic_table = [&DynamicTable](void) -> Elf_Dyn_Range {
    return DynamicTable.getAsArrayRef<Elf_Dyn>();
  };

  bool IsStaticallyLinked = true;

  struct {
    std::set<target_ulong> FunctionEntrypoints, ABIs;
    std::set<target_ulong> BasicBlockAddresses;
  } Known;

  auto BasicBlockAtAddress = [&](target_ulong A) -> void {
    Known.BasicBlockAddresses.insert(A);
  };
  auto FunctionAtAddress = [&](target_ulong A) -> void {
    Known.FunctionEntrypoints.insert(A);
  };
  auto ABIAtAddress = [&](target_ulong A) -> void {
    Known.FunctionEntrypoints.insert(A);
    Known.ABIs.insert(A);
  };

  //
  // examine dynamic table
  //
  for (const Elf_Dyn &Dyn : dynamic_table()) {
    if (unlikely(Dyn.getTag() == llvm::ELF::DT_NULL))
      break; /* marks end of dynamic table. */

    switch (Dyn.d_tag) {
    case llvm::ELF::DT_NEEDED:
      IsStaticallyLinked = false;
      break;
    case llvm::ELF::DT_INIT:
      ABIAtAddress(Dyn.getVal());
      break;
    }
  }

  llvm::Expected<Elf_Phdr_Range> ExpectedPrgHdrs = E.program_headers();
  if (!ExpectedPrgHdrs) {
    WithColor::error() << "no program headers in ELF. bug?\n";
    return 1;
  }

  auto PrgHdrs = *ExpectedPrgHdrs;

  //
  // if the ELF has a PT_INTERP program header, then we'll explore the entry
  // point. if not, we'll only consider it if it's statically-linked (i.e. it's
  // the dynamic linker)
  //
  bool HasInterpreter =
    std::any_of(PrgHdrs.begin(),
                PrgHdrs.end(),
                [](const Elf_Phdr &Phdr) -> bool{ return Phdr.p_type == llvm::ELF::PT_INTERP; });
  target_ulong EntryAddr = E.getHeader()->e_entry;
  if (HasInterpreter && EntryAddr) {
    llvm::outs() << llvm::formatv("entry point @ {0:x}\n", EntryAddr);

    b.Analysis.EntryFunction = translate_function(b, tcg, dis, EntryAddr);
  } else {
    b.Analysis.EntryFunction = invalid_function_index;
  }

  //
  // search local symbols (if they exist)
  //
  {
    llvm::Expected<Elf_Shdr_Range> ExpectedSections = E.sections();

    if (ExpectedSections) {
      const Elf_Shdr *SymTab = nullptr;

      for (const Elf_Shdr &Sect : *ExpectedSections) {
        if (Sect.sh_type == llvm::ELF::SHT_SYMTAB) {
          SymTab = &Sect;
          break;
        }
      }

      if (SymTab) {
        llvm::Expected<Elf_Sym_Range> ExpectedLocalSyms = E.symbols(SymTab);

        if (ExpectedLocalSyms) {
          auto LocalSyms = *ExpectedLocalSyms;

          for_each_if(LocalSyms.begin(),
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
  llvm::Optional<llvm::ArrayRef<uint8_t>> optionalBuildID = getBuildID(E);
  if (optionalBuildID) {
    llvm::ArrayRef<uint8_t> BuildID = *optionalBuildID;

    fs::path splitDbgInfo =
        fs::path("/usr/lib/debug") / ".build-id" /
        llvm::toHex(BuildID[0], /*LowerCase=*/true) /
        (llvm::toHex(BuildID.slice(1), /*LowerCase=*/true) + ".debug");

    if (fs::exists(splitDbgInfo)) {
      WithColor::note() << llvm::formatv("found split debug info file {0}\n",
                                         splitDbgInfo.c_str());

      llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> FileOrErr =
          llvm::MemoryBuffer::getFileOrSTDIN(splitDbgInfo.c_str());

      if (std::error_code EC = FileOrErr.getError()) {
        WithColor::error() << "failed to open debug info file " << opts::Input
                           << '\n';
        return 1;
      }

      std::unique_ptr<llvm::MemoryBuffer> &Buffer = FileOrErr.get();

      llvm::Expected<std::unique_ptr<obj::Binary>> split_BinOrErr =
          obj::createBinary(Buffer->getMemBufferRef());

      if (!split_BinOrErr) {
        WithColor::error() << "failed to create binary from split debug info "
                           << splitDbgInfo.c_str() << '\n';
        return 1;
      }

      std::unique_ptr<obj::Binary> &split_Bin = split_BinOrErr.get();

      if (!llvm::isa<ELFO>(split_Bin.get())) {
        WithColor::error() << "split debug info is not ELF of expected type\n";
        return 1;
      }

      ELFO &split_O = *llvm::cast<ELFO>(split_Bin.get());

      const ELFF &split_E = *split_O.getELFFile();

      //
      // examine local symbols (if they exist)
      //
      llvm::Expected<Elf_Shdr_Range> ExpectedSections = split_E.sections();
      if (ExpectedSections && !(*ExpectedSections).empty()) {
        const Elf_Shdr *SymTab = nullptr;

        for (const Elf_Shdr &Sec : *ExpectedSections) {
          if (Sec.sh_type == llvm::ELF::SHT_SYMTAB) {
            SymTab = &Sec;
            break;
          }
        }

        if (SymTab) {
          llvm::Expected<Elf_Sym_Range> ExpectedLocalSyms = split_E.symbols(SymTab);

          if (ExpectedLocalSyms) {
            auto LocalSyms = *ExpectedLocalSyms;

            for_each_if(LocalSyms.begin(),
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
  }

  llvm::StringRef DynamicStringTable;
  const Elf_Shdr *SymbolVersionSection;
  std::vector<VersionMapEntry> VersionMap;
  llvm::Optional<DynRegionInfo> OptionalDynSymRegion =
      loadDynamicSymbols(&E, &O,
                         DynamicTable,
                         DynamicStringTable,
                         SymbolVersionSection,
                         VersionMap);

  //
  // examine exported functions
  //
  if (OptionalDynSymRegion) {
    auto DynSyms = OptionalDynSymRegion->getAsArrayRef<Elf_Sym>();

    for_each_if(DynSyms.begin(),
                DynSyms.end(),
                [](const Elf_Sym &Sym) -> bool {
                  return !Sym.isUndefined() &&
                          Sym.getType() == llvm::ELF::STT_FUNC;
                },
                [&](const Elf_Sym &Sym) -> void {
                  FunctionAtAddress(Sym.st_value);
                });

    for_each_if(DynSyms.begin(),
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
                E.getEntry<Elf_Versym>(SymbolVersionSection, EntryIndex);

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
    target_ulong Beg, End;
  } InitArray = {0u, 0u};

  struct {
    target_ulong Beg, End;
  } FiniArray = {0u, 0u};

  {
    llvm::Expected<Elf_Shdr_Range> ExpectedSections = E.sections();

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
  DynRegionInfo DynRelRegion(O.getFileName());
  DynRegionInfo DynRelaRegion(O.getFileName());
  DynRegionInfo DynRelrRegion(O.getFileName());
  DynRegionInfo DynPLTRelRegion(O.getFileName());

  loadDynamicRelocations(&E, &O,
                         DynamicTable,
                         DynRelRegion,
                         DynRelaRegion,
                         DynRelrRegion,
                         DynPLTRelRegion);

  //
  // Search for IFunc relocations and make their resolver functions be ABIs
  //
  {
    auto processDynamicReloc = [&](const Relocation &R) -> void {
      constexpr unsigned Ty =
#if defined(TARGET_X86_64)
          llvm::ELF::R_X86_64_IRELATIVE
#elif defined(TARGET_I386)
          llvm::ELF::R_386_IRELATIVE
#elif defined(TARGET_AARCH64)
          llvm::ELF::R_AARCH64_IRELATIVE
#elif defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
          std::numeric_limits<unsigned>::max()
#else
#error
#endif
          ;
      //
      // ifunc resolvers are ABIs
      //
      if (R.Type == Ty) {
        target_ulong resolverAddr = R.Addend ? *R.Addend : 0;

        if (!resolverAddr) {
          llvm::Expected<const uint8_t *> ExpectedPtr =
              E.toMappedAddr(R.Offset);

          if (ExpectedPtr)
            resolverAddr =
                *reinterpret_cast<const target_ulong *>(*ExpectedPtr);
        }

        if (resolverAddr)
          ABIAtAddress(resolverAddr);
      }
    };

    for_each_dynamic_relocation(E,
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
    auto processDynamicReloc = [&](const Relocation &R) -> void {
      constexpr unsigned Ty =
#if defined(TARGET_X86_64)
          llvm::ELF::R_X86_64_RELATIVE
#elif defined(TARGET_I386)
          llvm::ELF::R_386_RELATIVE
#elif defined(TARGET_AARCH64)
          llvm::ELF::R_AARCH64_RELATIVE
#elif defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
          llvm::ELF::R_MIPS_REL32
#else
#error
#endif
          ;

      bool Contained = (R.Offset >= InitArray.Beg &&
                        R.Offset < InitArray.End) ||
                       (R.Offset >= FiniArray.Beg &&
                        R.Offset < FiniArray.End);
      if (!Contained)
        return;

      if (R.Type != Ty) {
        llvm::SmallString<32> RelocationTypeName;
        E.getRelocationTypeName(R.Type, RelocationTypeName);
        WithColor::warning() << llvm::formatv(
            "unrecognized relocation {0} in .init_array/.fini_array\n",
            RelocationTypeName);
        return;
      }

      //
      // constructors/deconstructors are ABIs
      //
      target_ulong Addr = R.Addend ? *R.Addend : 0;
      if (!Addr) {
        llvm::Expected<const uint8_t *> ExpectedPtr = E.toMappedAddr(R.Offset);

        if (ExpectedPtr)
          Addr = *reinterpret_cast<const target_ulong *>(*ExpectedPtr);
      }

      if (opts::Verbose)
        WithColor::note() << llvm::formatv("ctor/dtor: off={0:x} Addr={1:x}\n",
                                           R.Offset, Addr);

      if (Addr)
        ABIAtAddress(Addr);
    };

    for_each_dynamic_relocation(E,
                                DynRelRegion,
                                DynRelaRegion,
                                DynRelrRegion,
                                DynPLTRelRegion,
                                processDynamicReloc);
  }

  //
  // explore known code
  //
  for (target_ulong Entrypoint : boost::adaptors::reverse(Known.BasicBlockAddresses)) {
#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
    Entrypoint &= ~1UL;
#endif

    translate_basic_block(b, tcg, dis, Entrypoint);
  }

  for (target_ulong Entrypoint : boost::adaptors::reverse(Known.FunctionEntrypoints)) {
#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
    Entrypoint &= ~1UL;
#endif

    function_index_t FIdx = translate_function(b, tcg, dis, Entrypoint);

    if (!is_function_index_valid(FIdx))
      continue;

    if (Known.ABIs.find(Entrypoint) != Known.ABIs.end())
      b.Analysis.Functions[FIdx].IsABI = true;
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

  auto ProgramHeadersOrError = E.program_headers();
  if (ProgramHeadersOrError) {
    llvm::SmallVector<const Elf_Phdr *, 4> LoadSegments;

    for (const Elf_Phdr &Phdr : *ProgramHeadersOrError)
      if (Phdr.p_type == llvm::ELF::PT_LOAD)
        LoadSegments.push_back(const_cast<Elf_Phdr *>(&Phdr));

    for (const Elf_Phdr *P : LoadSegments) {
      llvm::StringRef SectionStr(
          reinterpret_cast<const char *>(E.base() + P->p_offset), P->p_filesz);

      for (llvm::StringRef pattern : LjPatterns) {
        size_t idx = SectionStr.find(pattern);
        if (idx == llvm::StringRef::npos)
          continue;

        uint64_t A = P->p_vaddr + idx;

        basic_block_index_t BBIdx = translate_basic_block(b, tcg, dis, A);
        if (!is_basic_block_index_valid(BBIdx))
          continue;

        auto &ICFG = b.Analysis.ICFG;

        std::vector<basic_block_t> bbvec;
        std::map<basic_block_t, boost::default_color_type> color;
        dfs_visitor<interprocedural_control_flow_graph_t> vis(bbvec);
        depth_first_visit(
            ICFG, boost::vertex(BBIdx, ICFG), vis,
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

        basic_block_index_t BBIdx = translate_basic_block(b, tcg, dis, A);
        if (!is_basic_block_index_valid(BBIdx))
          continue;

        auto &ICFG = b.Analysis.ICFG;

        WithColor::note() << llvm::formatv("found setjmp @ {0:x}\n", A);

        ICFG[boost::vertex(BBIdx, ICFG)].Sj = true;
      }
    }
  }

  IgnoreCtrlC(); /* user probably doesn't want to interrupt the following */

  //
  // Write output
  //
  {
    std::ofstream ofs(opts::Output);

    boost::archive::text_oarchive oa(ofs);
    oa << decompilation;
  }

  return 0;
}

static function_index_t translate_function(binary_t &b,
                                           tiny_code_generator_t &tcg,
                                           disas_t &dis,
                                           target_ulong Addr) {
#if defined(TARGET_MIPS32) || defined(TARGET_MIPS64)
  assert((Addr & 1) == 0);
#endif

  {
    auto it = b.FuncMap.find(Addr);
    if (it != b.FuncMap.end())
      return (*it).second;
  }

  const function_index_t res = b.Analysis.Functions.size();
  (void)b.Analysis.Functions.emplace_back();

  b.FuncMap.insert({Addr, res});

  basic_block_index_t Entry = translate_basic_block(b, tcg, dis, Addr);

  WARN_ON(!is_basic_block_index_valid(Entry));

  {
    function_t &f = b.Analysis.Functions[res];

    f.Analysis.Stale = true;
    f.IsABI = false;
    f.IsSignalHandler = false;
    f.Entry = Entry;
  }

  return res;
}

static bool does_function_definitely_return(binary_t &,
                                            function_index_t FIdx);

basic_block_index_t translate_basic_block(binary_t &b,
                                          tiny_code_generator_t &tcg,
                                          disas_t &dis,
                                          const target_ulong Addr) {
#if defined(TARGET_MIPS32) || defined(TARGET_MIPS64)
  assert((Addr & 1) == 0);
#endif

  auto &ICFG = b.Analysis.ICFG;
  auto &ObjectFile = b.ObjectFile;

  //
  // does this new basic block start in the middle of a previously-created
  // basic block?
  //
  {
    auto it = b.BBMap.find(Addr);
    if (it != b.BBMap.end()) {
      basic_block_index_t bbidx = (*it).second - 1;
      basic_block_t bb = boost::vertex(bbidx, ICFG);

      assert(bbidx < boost::num_vertices(ICFG));

      target_ulong beg = ICFG[bb].Addr;

      if (beg == Addr) {
        assert(ICFG[bb].Addr == (*it).first.lower());
        return bbidx;
      }

      //
      // before splitting the basic block, let's check to make sure that the
      // new block doesn't start in the middle of an instruction. if that would
      // occur, then we will assume the control-flow is invalid
      //
      {
        llvm::MCDisassembler &DisAsm = std::get<0>(dis);
        const llvm::MCSubtargetInfo &STI = std::get<1>(dis);
        llvm::MCInstPrinter &IP = std::get<2>(dis);

        const ELFF &E = *llvm::cast<ELFO>(ObjectFile.get())->getELFFile();

        uint64_t InstLen = 0;
        for (target_ulong A = beg; A < beg + ICFG[bb].Size; A += InstLen) {
          llvm::MCInst Inst;

          std::string errmsg;
          bool Disassembled;
          {
            llvm::raw_string_ostream ErrorStrStream(errmsg);

            llvm::Expected<const uint8_t *> ExpectedPtr = E.toMappedAddr(A);
            if (!ExpectedPtr)
              abort();

            Disassembled = DisAsm.getInstruction(
                Inst, InstLen,
                llvm::ArrayRef<uint8_t>(*ExpectedPtr, ICFG[bb].Size), A,
                ErrorStrStream);
          }

          if (!Disassembled)
            WithColor::error() << llvm::formatv(
                "failed to disassemble {0:x} {1}\n", A, errmsg);

          //assert(Disassembled);

          if (A == Addr)
            goto on_insn_boundary;
        }

        WithColor::error() << llvm::formatv(
            "control flow to {0:x} in {1} doesn't lie on instruction boundary\n",
            Addr, b.Path);

        return invalid_basic_block_index;

on_insn_boundary:
        //
        // proceed.
        //
        ;
      }

      unsigned deg = boost::out_degree(bb, ICFG);

      std::vector<basic_block_t> out_verts;
      {
        icfg_t::out_edge_iterator e_it, e_it_end;
        for (std::tie(e_it, e_it_end) = boost::out_edges(bb, ICFG);
             e_it != e_it_end; ++e_it)
          out_verts.push_back(boost::target(*e_it, ICFG));
      }

      // if we get here, we know that beg != Addr
      assert(Addr > beg);

      ptrdiff_t off = Addr - beg;
      assert(off > 0);

      boost::icl::interval<target_ulong>::type orig_intervl = (*it).first;

      basic_block_index_t newbbidx = boost::num_vertices(ICFG);
      basic_block_t newbb = boost::add_vertex(ICFG);
      {
        basic_block_properties_t &newbbprop = ICFG[newbb];
        newbbprop.Addr = beg;
        newbbprop.Size = off;
        newbbprop.Term.Type = TERMINATOR::NONE;
        newbbprop.Term.Addr = 0; /* XXX? */
        newbbprop.DynTargetsComplete = false;
        newbbprop.Term._call.Target = invalid_function_index;
        newbbprop.Term._call.Returns = false;
        newbbprop.Term._indirect_jump.IsLj = false;
        newbbprop.Sj = false;
        newbbprop.Term._indirect_call.Returns = false;
        newbbprop.Term._return.Returns = false;
        newbbprop.InvalidateAnalysis();
      }

      ICFG[bb].InvalidateAnalysis();

      std::swap(ICFG[bb], ICFG[newbb]);
      ICFG[newbb].Addr = Addr;
      ICFG[newbb].Size -= off;

      assert(ICFG[newbb].Addr + ICFG[newbb].Size == orig_intervl.upper());

      boost::clear_out_edges(bb, ICFG);
      assert(boost::out_degree(bb, ICFG) == 0);

      boost::add_edge(bb, newbb, ICFG);

      for (basic_block_t out_vert : out_verts) {
        boost::add_edge(newbb, out_vert, ICFG);
      }

      assert(ICFG[bb].Term.Type == TERMINATOR::NONE);
      assert(boost::out_degree(bb, ICFG) == 1);

      assert(boost::out_degree(newbb, ICFG) == deg);

      boost::icl::interval<target_ulong>::type intervl1 =
          boost::icl::interval<target_ulong>::right_open(
              ICFG[bb].Addr, ICFG[bb].Addr + ICFG[bb].Size);

      boost::icl::interval<target_ulong>::type intervl2 =
          boost::icl::interval<target_ulong>::right_open(
              ICFG[newbb].Addr, ICFG[newbb].Addr + ICFG[newbb].Size);

      assert(boost::icl::disjoint(intervl1, intervl2));

      if (opts::Verbose) {
        llvm::outs() << "intervl1: [" << (fmt("%#lx") % intervl1.lower()).str()
                     << ", " << (fmt("%#lx") % intervl1.upper()).str() << ")\n";

        llvm::outs() << "intervl2: [" << (fmt("%#lx") % intervl2.lower()).str()
                     << ", " << (fmt("%#lx") % intervl2.upper()).str() << ")\n";

        llvm::outs() << "orig_intervl: ["
                     << (fmt("%#lx") % orig_intervl.lower()).str() << ", "
                     << (fmt("%#lx") % orig_intervl.upper()).str() << ")\n";
      }
     
      unsigned n = b.BBMap.iterative_size();
      b.BBMap.erase((*it).first);
      assert(b.BBMap.iterative_size() == n - 1);

      assert(b.BBMap.find(intervl1) == b.BBMap.end());
      assert(b.BBMap.find(intervl2) == b.BBMap.end());

      {
        auto _it = b.BBMap.find(intervl1);
        if (_it != b.BBMap.end()) {
          const auto &intervl = (*_it).first;
          WithColor::error() << "can't add interval1 to b.BBMap: ["
                             << (fmt("%#lx") % intervl1.lower()).str() << ", "
                             << (fmt("%#lx") % intervl1.upper()).str()
                             << "), b.BBMap already contains ["
                             << (fmt("%#lx") % intervl.lower()).str() << ", "
                             << (fmt("%#lx") % intervl.upper()).str() << ")\n";
          abort();
        }
      }

      {
        auto _it = b.BBMap.find(intervl2);
        if (_it != b.BBMap.end()) {
          const auto &intervl = (*_it).first;
          llvm::errs() << " Addr=" << (fmt("%#lx") % Addr).str() << '\n';

          WithColor::error() << "can't add interval2 to b.BBMap: ["
                             << (fmt("%#lx") % intervl2.lower()).str() << ", "
                             << (fmt("%#lx") % intervl2.upper()).str()
                             << "), b.BBMap already contains ["
                             << (fmt("%#lx") % intervl.lower()).str() << ", "
                             << (fmt("%#lx") % intervl.upper()).str() << ")\n";
          abort();
        }
      }

      b.BBMap.add({intervl1, 1 + bbidx});
      b.BBMap.add({intervl2, 1 + newbbidx});

      {
        auto _it = b.BBMap.find(intervl1);
        assert(_it != b.BBMap.end());
        assert((*_it).second == 1 + bbidx);
      }

      {
        auto _it = b.BBMap.find(intervl2);
        assert(_it != b.BBMap.end());
        assert((*_it).second == 1 + newbbidx);
      }

      return newbbidx;
    }
  }

  tcg.set_elf(llvm::cast<ELFO>(b.ObjectFile.get())->getELFFile());

  unsigned Size = 0;
  jove::terminator_info_t T;
  do {
    if (BreakOn.Active) {
      if (Addr == BreakOn.Addr) {
        ::UserBreakPoint();
      }
    }

    unsigned size;
    std::tie(size, T) = tcg.translate(Addr + Size);

    Size += size;

    {
      boost::icl::interval<target_ulong>::type intervl =
          boost::icl::interval<target_ulong>::right_open(Addr, Addr + Size);
      auto it = b.BBMap.find(intervl);
      if (it == b.BBMap.end())
        continue; /* proceed */

      const boost::icl::interval<target_ulong>::type &_intervl = (*it).first;

      if (opts::Verbose)
        WithColor::error() << "can't translate further ["
                           << (fmt("%#lx") % intervl.lower()).str() << ", "
                           << (fmt("%#lx") % intervl.upper()).str()
                           << "), b.BBMap already contains ["
                           << (fmt("%#lx") % _intervl.lower()).str() << ", "
                           << (fmt("%#lx") % _intervl.upper()).str() << ")\n";

      assert(intervl.lower() < _intervl.lower());

      // assert(intervl.upper() == _intervl.upper());

      if (intervl.upper() != _intervl.upper() && opts::Verbose) {
        WithColor::warning() << "we've translated into another basic block:"
                             << (fmt("%#lx") % intervl.lower()).str() << ", "
                             << (fmt("%#lx") % intervl.upper()).str()
                             << "), b.BBMap already contains ["
                             << (fmt("%#lx") % _intervl.lower()).str() << ", "
                             << (fmt("%#lx") % _intervl.upper()).str() << ")\n";
      }

      //
      // solution here is to prematurely end the basic block with a NONE
      // terminator, and with a next_insn address of _intervl.lower()
      //
      Size = _intervl.lower() - intervl.lower();
      T.Type = TERMINATOR::NONE;
      T.Addr = 0; /* XXX? */
      T._none.NextPC = _intervl.lower();
      break;
    }
  } while (T.Type == TERMINATOR::NONE);

  if (T.Type == TERMINATOR::UNKNOWN) {
    WithColor::error() << llvm::formatv("unknown terminator @ {0:x}\n", Addr);

    llvm::MCDisassembler &DisAsm = std::get<0>(dis);
    const llvm::MCSubtargetInfo &STI = std::get<1>(dis);
    llvm::MCInstPrinter &IP = std::get<2>(dis);

    const ELFF &E = *llvm::cast<ELFO>(ObjectFile.get())->getELFFile();

    uint64_t InstLen;
    for (target_ulong A = Addr; A < Addr + Size; A += InstLen) {
      llvm::Expected<const uint8_t *> ExpectedPtr = E.toMappedAddr(A);
      if (!ExpectedPtr)
        abort();

      llvm::MCInst Inst;
      bool Disassembled = DisAsm.getInstruction(
          Inst, InstLen, llvm::ArrayRef<uint8_t>(*ExpectedPtr, Size), A,
          llvm::nulls());

      if (!Disassembled) {
        WithColor::error() << llvm::formatv("failed to disassemble {0:x}\n",
                                            Addr);
        break;
      }

      IP.printInst(&Inst, A, "", STI, llvm::errs());
      llvm::errs() << '\n';
    }

#if 0
    tcg.dump_operations();
    fputc('\n', stdout);
#endif

    return invalid_basic_block_index;
  }

  basic_block_index_t bbidx = boost::num_vertices(ICFG);
  basic_block_t bb = boost::add_vertex(ICFG);
  {
    basic_block_properties_t &bbprop = ICFG[bb];
    bbprop.Addr = Addr;
    bbprop.Size = Size;
    bbprop.Term.Type = T.Type;
    bbprop.Term.Addr = T.Addr;
    bbprop.DynTargetsComplete = false;
    bbprop.Term._call.Target = invalid_function_index;
    bbprop.Term._call.Returns = false;
    bbprop.Term._indirect_jump.IsLj = false;
    bbprop.Sj = false;
    bbprop.Term._indirect_call.Returns = false;
    bbprop.Term._return.Returns = false;
    bbprop.InvalidateAnalysis();

    boost::icl::interval<target_ulong>::type intervl =
        boost::icl::interval<target_ulong>::right_open(bbprop.Addr,
                                                    bbprop.Addr + bbprop.Size);
    assert(b.BBMap.find(intervl) == b.BBMap.end());

    b.BBMap.add({intervl, 1 + bbidx});
  }

  //
  // conduct analysis of last instruction (the terminator of the block) and
  // (recursively) descend into branch targets, translating basic blocks
  //
  auto control_flow = [&](target_ulong Target) -> void {
    assert(Target);

#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
    Target &= ~1UL;
#endif

    basic_block_index_t succidx = translate_basic_block(b, tcg, dis, Target);

    if (succidx == invalid_basic_block_index) {
      WithColor::note() << llvm::formatv(
          "control_flow: invalid edge {0:x} -> {1:x}\n", T.Addr, Target);
      return;
    }

    basic_block_t _bb;
    {
      auto it = T.Addr ? b.BBMap.find(T.Addr) : b.BBMap.find(Addr);
      assert(it != b.BBMap.end());

      basic_block_index_t _bbidx = (*it).second - 1;
      _bb = boost::vertex(_bbidx, ICFG);
      assert(T.Type == ICFG[_bb].Term.Type);
    }

    basic_block_t succ = boost::vertex(succidx, ICFG);
    bool isNewTarget = boost::add_edge(_bb, succ, ICFG).second;

    (void)isNewTarget;
  };

  switch (T.Type) {
  case TERMINATOR::UNCONDITIONAL_JUMP:
    control_flow(T._unconditional_jump.Target);
    break;

  case TERMINATOR::CONDITIONAL_JUMP:
    control_flow(T._conditional_jump.Target);
    control_flow(T._conditional_jump.NextPC);
    break;

  case TERMINATOR::CALL: {
    target_ulong CalleeAddr = T._call.Target;

#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
    CalleeAddr &= ~1UL;
#endif

    function_index_t FIdx = translate_function(b, tcg, dis, CalleeAddr);

    basic_block_t _bb;
    {
      auto it = T.Addr ? b.BBMap.find(T.Addr) : b.BBMap.find(Addr);
      assert(it != b.BBMap.end());
      basic_block_index_t _bbidx = (*it).second - 1;
      _bb = boost::vertex(_bbidx, ICFG);
    }

    assert(ICFG[_bb].Term.Type == TERMINATOR::CALL);
    ICFG[_bb].Term._call.Target = FIdx;

    if (is_function_index_valid(FIdx) &&
        does_function_definitely_return(b, FIdx))
      control_flow(T._call.NextPC);

    break;
  }

  case TERMINATOR::INDIRECT_CALL:
    //control_flow(T._indirect_call.NextPC);
    break;

  case TERMINATOR::INDIRECT_JUMP:
  case TERMINATOR::RETURN:
  case TERMINATOR::UNREACHABLE:
    break;

  case TERMINATOR::NONE:
    control_flow(T._none.NextPC);
    break;

  default:
    abort();
  }

  return bbidx;
}

bool does_function_definitely_return(binary_t &b,
                                     function_index_t FIdx) {
  assert(is_function_index_valid(FIdx));

  function_t &f = b.Analysis.Functions.at(FIdx);
  auto &ICFG = b.Analysis.ICFG;

  assert(is_basic_block_index_valid(f.Entry));

  std::vector<basic_block_t> BasicBlocks;
  std::vector<basic_block_t> ExitBasicBlocks;

  std::map<basic_block_t, boost::default_color_type> color;
  dfs_visitor<interprocedural_control_flow_graph_t> vis(BasicBlocks);
  boost::depth_first_visit(
      ICFG, boost::vertex(f.Entry, ICFG), vis,
      boost::associative_property_map<
          std::map<basic_block_t, boost::default_color_type>>(color));

  //
  // ExitBasicBlocks
  //
  std::copy_if(BasicBlocks.begin(),
               BasicBlocks.end(),
               std::back_inserter(ExitBasicBlocks),
               [&](basic_block_t bb) -> bool {
                 return IsExitBlock(ICFG, bb);
               });

  return !ExitBasicBlocks.empty();
}

void IgnoreCtrlC(void) {
  auto sighandler = [](int no) -> void {
    ; // do nothing
  };

  struct sigaction sa;

  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = sighandler;

  if (sigaction(SIGINT, &sa, nullptr) < 0) {
    int err = errno;
    WithColor::error() << llvm::formatv("{0}: sigaction failed ({1})\n",
                                        __func__, strerror(err));
  }
}

void _qemu_log(const char *cstr) { llvm::outs() << cstr; }

} // namespace jove
