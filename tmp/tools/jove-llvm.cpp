#include "jove/tcgconstants.h"

#define JOVE_EXTRA_BB_PROPERTIES                                               \
  struct {                                                                     \
    /* let def_B be the set of variables defined (i.e. definitely assigned */  \
    /* values) in B prior to any use of that variable in B */                  \
    tcg_global_set_t def;                                                      \
                                                                               \
    /* let use_B be the set of variables whose values may be used in B */      \
    /* prior to any definition of the variable */                              \
    tcg_global_set_t use;                                                      \
                                                                               \
    tcg_global_set_t IN;                                                       \
    tcg_global_set_t OUT;                                                      \
  } Analysis;

#define JOVE_EXTRA_FN_PROPERTIES                                               \
  std::vector<basic_block_t> BasicBlocks;                                      \
  struct {                                                                     \
    tcg_global_set_t live;                                                     \
  } Analysis;

#include "tcgcommon.hpp"

#include <tuple>
#include <numeric>
#include <memory>
#include <sstream>
#include <fstream>
#include <boost/filesystem.hpp>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/Bitcode/BitcodeReader.h>
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
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/Host.h>
#include <llvm/Support/DataTypes.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/ScopedPrinter.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/ToolOutputFile.h>
#include <llvm/Support/WithColor.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/IRBuilder.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "jove/jove.h"
#include <boost/icl/interval_set.hpp>
#include <boost/icl/split_interval_map.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/graph/adj_list_serialize.hpp>
#include <boost/graph/depth_first_search.hpp>
#include <boost/range/adaptor/reversed.hpp>
#include <boost/dynamic_bitset.hpp>
#include <boost/format.hpp>
#include <boost/algorithm/string/replace.hpp>

#define GET_INSTRINFO_ENUM
#include "LLVMGenInstrInfo.hpp"

#define GET_REGINFO_ENUM
#include "LLVMGenRegisterInfo.hpp"

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace opts {
  static cl::opt<std::string> jv("decompilation",
    cl::desc("Jove decompilation"),
    cl::Required);

  static cl::opt<std::string> Binary("binary",
    cl::desc("Binary to decompile"),
    cl::Required);

  static cl::opt<std::string> Output("output",
    cl::desc("LLVM bitcode"),
    cl::Required);

  static cl::opt<bool> PrintDefAndUse("print-def-and-use",
    cl::desc("Print use_B and def_B for every basic block B"));

  static cl::opt<bool> PrintLiveness("print-liveness",
    cl::desc("Print liveness for every function"));

  static cl::opt<bool> Verbose("verbose",
    cl::desc("Print extra information for debugging purposes"));
}

namespace jove {
static int llvm(void);
}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::ParseCommandLineOptions(argc, argv, "Jove LLVM\n");

  if (!fs::exists(opts::jv)) {
    llvm::errs() << "decompilation does not exist\n";
    return 1;
  }

  return jove::llvm();
}

namespace jove {

//
// Types
//

typedef boost::format fmt;

struct section_properties_t {
  llvm::StringRef name;
  llvm::ArrayRef<uint8_t> contents;

  bool w, x;

  bool operator==(const section_properties_t &sect) const {
    return name == sect.name;
  }

  bool operator<(const section_properties_t &sect) const {
    return name < sect.name;
  }
};
typedef std::set<section_properties_t> section_properties_set_t;

struct binary_state_t {
  std::unordered_map<uintptr_t, function_index_t> FuncMap;
  std::unordered_map<uintptr_t, basic_block_index_t> BBMap;
  boost::icl::split_interval_map<uintptr_t, section_properties_set_t> SectMap;
};

typedef std::tuple<llvm::MCDisassembler &, const llvm::MCSubtargetInfo &,
                   llvm::MCInstPrinter &>
    disas_t;

//
// a symbol is basically a name and a value. in a program compiled from C, the
// value of a symbol is roughly the address of a global. Each defined symbol has
// an address, and the dynamic linker will resolve each undefined symbol by
// finding a defined symbol with the same name.
//
struct symbol_t {
  llvm::StringRef Name;
  uintptr_t Addr;

  enum class TYPE {
    NONE,
    DATA,
    FUNCTION,
    TLSDATA,
  } Type;

  unsigned Size;

  enum class BINDING {
    NONE,
    LOCAL,
    WEAK,
    GLOBAL
  } Bind;

  bool IsUndefined() const { return Addr == 0; }
  bool IsDefined() const { return !IsUndefined(); }
};

//
// a relocation is a computation to perform on the contents; it is defined by a
// type, symbol, offset into the contents, and addend. Most relocations refer to
// a symbol and to an offset within the contents. A commonly used relocation is
// "set this location in the contents to the value of this symbol plus this
// addend". A relocation may refer to an undefined symbol.
//
struct relocation_t {
  enum class TYPE {
    //
    // This relocation is unimplemented or has irrelevant semantics
    //
    NONE,

    //
    // set the location specified to be the address plus the addend
    //
    RELATIVE,

    //
    // set the location specified to be the absolute address of the addend
    //
    ABSOLUTE,

    //
    // Copies the data from resolved symbol to address
    //
    COPY,

    //
    // address of a function or variable.
    //
    ADDRESSOF
  } Type;

  uintptr_t Addr;
  unsigned SymbolIndex;
  uintptr_t Addend;
};

//
// Globals
//
static decompilation_t Decompilation;
static binary_index_t BinaryIndex = invalid_binary_index;

static std::vector<binary_state_t> BinStateVec;

static llvm::Triple TheTriple;
static llvm::SubtargetFeatures Features;

static const llvm::Target *TheTarget;
static std::unique_ptr<const llvm::MCRegisterInfo> MRI;
static std::unique_ptr<const llvm::MCAsmInfo> AsmInfo;
static std::unique_ptr<const llvm::MCSubtargetInfo> STI;
static std::unique_ptr<const llvm::MCInstrInfo> MII;
static std::unique_ptr<llvm::MCObjectFileInfo> MOFI;
static std::unique_ptr<llvm::MCContext> MCCtx;
static std::unique_ptr<llvm::MCDisassembler> DisAsm;
static std::unique_ptr<llvm::MCInstPrinter> IP;

static std::unique_ptr<tiny_code_generator_t> TCG;

static std::unique_ptr<llvm::LLVMContext> Context;
static std::unique_ptr<llvm::Module> Module;

static std::vector<symbol_t> SymbolTable;
static std::vector<relocation_t> RelocationTable;

static llvm::GlobalVariable *SectsGlobal;
static uintptr_t SectsStartAddr, SectsEndAddr;

static llvm::DataLayout DL("");

//
// Stages
//
static int ParseDecompilation(void);
static int FindBinary(void);
static int InitStateForBinaries(void);
static int ProcessBinarySymbolsAndRelocations(void);
static int PrepareToTranslateCode(void);
static int CreateModule(void);
static int CreateSectionGlobalVariables(void);
static int ConductLivenessAnalysis(void);
static int TranslateFunctions(void);
static int WriteModule(void);

int llvm(void) {
  return ParseDecompilation()
      || FindBinary()
      || InitStateForBinaries()
      || ProcessBinarySymbolsAndRelocations()
      || PrepareToTranslateCode()
      || CreateModule()
      || CreateSectionGlobalVariables()
      || ConductLivenessAnalysis()
      || TranslateFunctions()
      || WriteModule();
}

int ParseDecompilation(void) {
  std::ifstream ifs(
      fs::is_directory(opts::jv) ? (opts::jv + "/decompilation.jv") : opts::jv);

  boost::archive::binary_iarchive ia(ifs);
  ia >> Decompilation;

  return 0;
}

int FindBinary(void) {
  for (unsigned idx = 0; idx < Decompilation.Binaries.size(); ++idx) {
    binary_t &binary = Decompilation.Binaries[idx];

    if (fs::path(binary.Path).filename().string() == opts::Binary) {
      BinaryIndex = idx;
      return 0;
    }
  }

  WithColor::error() << "binary " << opts::Binary
                     << " not found in given decompilation\n";
  return 1;
}

#if defined(__x86_64__) || defined(__aarch64__)
typedef typename obj::ELF64LEObjectFile ELFO;
typedef typename obj::ELF64LEFile ELFT;
#endif

int InitStateForBinaries(void) {
  BinStateVec.resize(Decompilation.Binaries.size());
  for (binary_index_t bin_idx = 0;
       bin_idx < Decompilation.Binaries.size();
       ++bin_idx) {
    const binary_t &Binary = Decompilation.Binaries[bin_idx];
    const interprocedural_control_flow_graph_t &ICFG = Binary.Analysis.ICFG;

    binary_state_t &st = BinStateVec[bin_idx];

    //
    // FuncMap
    //
    for (function_index_t f_idx = 0;
         f_idx < Binary.Analysis.Functions.size();
         ++f_idx) {
      const function_t &f = Binary.Analysis.Functions[f_idx];

      st.FuncMap[ICFG[boost::vertex(f.Entry, ICFG)].Addr] = f_idx;
    }

    //
    // BBMap
    //
    for (basic_block_index_t bb_idx = 0;
         bb_idx < boost::num_vertices(ICFG);
         ++bb_idx) {
      basic_block_t bb = boost::vertex(bb_idx, ICFG);

      st.BBMap[ICFG[bb].Addr] = bb_idx;
    }

    //
    // build section map
    //
    llvm::StringRef Buffer(reinterpret_cast<const char *>(&Binary.Data[0]),
                           Binary.Data.size());
    llvm::StringRef Identifier(Binary.Path);
    llvm::MemoryBufferRef MemBuffRef(Buffer, Identifier);

    llvm::Expected<std::unique_ptr<obj::Binary>> BinOrErr =
        obj::createBinary(MemBuffRef);
    if (!BinOrErr) {
      WithColor::error() << "failed to create binary from " << Binary.Path
                         << '\n';
      return 1;
    }

    std::unique_ptr<obj::Binary> &Bin = BinOrErr.get();

    assert(llvm::isa<ELFO>(Bin.get()));
    ELFO &O = *llvm::cast<ELFO>(Bin.get());

    TheTriple = O.makeTriple();
    Features = O.getFeatures();

    const ELFT &E = *O.getELFFile();

    typedef typename ELFT::Elf_Shdr Elf_Shdr;
    typedef typename ELFT::Elf_Shdr_Range Elf_Shdr_Range;

    llvm::Expected<Elf_Shdr_Range> sections = E.sections();
    if (!sections) {
      WithColor::error() << "error: could not get ELF sections for binary "
                         << Binary.Path << '\n';
      return 1;
    }

    if (opts::Verbose)
      llvm::outs() << Binary.Path << '\n';

    for (const Elf_Shdr &Sec : *sections) {
      if (!(Sec.sh_flags & llvm::ELF::SHF_ALLOC))
        continue;

      if (!(Sec.sh_flags & llvm::ELF::SHF_ALLOC))
        continue;

      llvm::Expected<llvm::ArrayRef<uint8_t>> contents =
          E.getSectionContents(&Sec);

      if (!contents)
        continue;

      llvm::Expected<llvm::StringRef> name = E.getSectionName(&Sec);

      if (!name)
        continue;

      boost::icl::interval<uintptr_t>::type intervl =
          boost::icl::interval<uintptr_t>::right_open(
              Sec.sh_addr, Sec.sh_addr + Sec.sh_size);

      section_properties_t sectprop;
      sectprop.name = *name;
      sectprop.contents = *contents;

      section_properties_set_t sectprops = {sectprop};
      st.SectMap.add(std::make_pair(intervl, sectprops));
    }

    if (bin_idx == BinaryIndex) {
      llvm::outs() << "Address Space:\n";
      for (const auto &pair : st.SectMap) {
        const section_properties_t &sect = *pair.second.begin();

        llvm::outs() <<
          (boost::format("%-20s [%x, %x)")
           % sect.name.str()
           % pair.first.lower()
           % pair.first.upper()).str()
          << '\n';
      }
    }
  }

  return 0;
}

template <class T>
T unwrapOrError(llvm::Expected<T> EO) {
  if (EO)
    return *EO;

  std::string Buf;
  {
    llvm::raw_string_ostream OS(Buf);
    llvm::logAllUnhandledErrors(EO.takeError(), OS, "");
  }
  WithColor::error() << Buf << '\n';
  exit(1);
}

int ProcessBinarySymbolsAndRelocations(void) {
  binary_t &Binary = Decompilation.Binaries[BinaryIndex];

  llvm::StringRef Buffer(reinterpret_cast<const char *>(&Binary.Data[0]),
                         Binary.Data.size());
  llvm::StringRef Identifier(Binary.Path);
  llvm::MemoryBufferRef MemBuffRef(Buffer, Identifier);

  llvm::Expected<std::unique_ptr<obj::Binary>> BinOrErr =
      obj::createBinary(MemBuffRef);
  if (!BinOrErr) {
    WithColor::error() << "failed to create binary from " << Binary.Path
                       << '\n';
    return 1;
  }

  std::unique_ptr<obj::Binary> &Bin = BinOrErr.get();

  assert(llvm::isa<ELFO>(Bin.get()));
  ELFO &O = *llvm::cast<ELFO>(Bin.get());

  TheTriple = O.makeTriple();
  Features = O.getFeatures();

  const ELFT &E = *O.getELFFile();

  typedef typename ELFT::Elf_Shdr Elf_Shdr;
  typedef typename ELFT::Elf_Sym Elf_Sym;
  typedef typename ELFT::Elf_Rel Elf_Rel;
  typedef typename ELFT::Elf_Rela Elf_Rela;

  auto process_elf_sym = [&](const Elf_Shdr &Sec, const Elf_Sym &Sym) -> void {
    symbol_t res;

    llvm::StringRef StrTable = unwrapOrError(E.getStringTableForSymtab(Sec));

    constexpr symbol_t::TYPE elf_symbol_type_mapping[] = {
        symbol_t::TYPE::NONE,     // STT_NOTYPE              = 0
        symbol_t::TYPE::DATA,     // STT_OBJECT              = 1
        symbol_t::TYPE::FUNCTION, // STT_FUNC                = 2
        symbol_t::TYPE::DATA,     // STT_SECTION             = 3
        symbol_t::TYPE::DATA,     // STT_FILE                = 4
        symbol_t::TYPE::DATA,     // STT_COMMON              = 5
        symbol_t::TYPE::TLSDATA,  // STT_TLS                 = 6
        symbol_t::TYPE::NONE,     // N/A                     = 7
        symbol_t::TYPE::NONE,     // N/A                     = 8
        symbol_t::TYPE::NONE,     // N/A                     = 9
        symbol_t::TYPE::NONE,     // STT_GNU_IFUNC, STT_LOOS = 10
        symbol_t::TYPE::NONE,     // N/A                     = 11
        symbol_t::TYPE::NONE,     // STT_HIOS                = 12
        symbol_t::TYPE::NONE,     // STT_LOPROC              = 13
        symbol_t::TYPE::NONE,     // N/A                     = 14
        symbol_t::TYPE::NONE      // STT_HIPROC              = 15
    };

    constexpr symbol_t::BINDING elf_symbol_binding_mapping[] = {
        symbol_t::BINDING::LOCAL,     // STT_LOCAL      = 0
        symbol_t::BINDING::GLOBAL,    // STB_GLOBAL     = 1
        symbol_t::BINDING::WEAK,      // STB_WEAK       = 2
        symbol_t::BINDING::NONE,      // N/A            = 3
        symbol_t::BINDING::NONE,      // N/A            = 4
        symbol_t::BINDING::NONE,      // N/A            = 5
        symbol_t::BINDING::NONE,      // N/A            = 6
        symbol_t::BINDING::NONE,      // N/A            = 7
        symbol_t::BINDING::NONE,      // N/A            = 8
        symbol_t::BINDING::NONE,      // N/A            = 9
        symbol_t::BINDING::NONE,      // STB_GNU_UNIQUE = 10
        symbol_t::BINDING::NONE,      // N/A            = 11
        symbol_t::BINDING::NONE,      // STB_HIOS       = 12
        symbol_t::BINDING::NONE,      // STB_LOPROC     = 13
        symbol_t::BINDING::NONE,      // N/A            = 14
        symbol_t::BINDING::NONE       // STB_HIPROC     = 15
    };

    res.Name = unwrapOrError(Sym.getName(StrTable));
    res.Addr = Sym.isUndefined() ? 0 : Sym.st_value;
    res.Type = elf_symbol_type_mapping[Sym.getType()];
    res.Size = Sym.st_size;
    res.Bind = elf_symbol_binding_mapping[Sym.getBinding()];

    if (res.Type == symbol_t::TYPE::NONE &&
        res.Bind == symbol_t::BINDING::WEAK && !res.Addr) {
      // XXX FIXME
#if 0
      cout << "WARNING: making " << res.name << " into function symbol!"
           << endl;
#endif
      res.Type = symbol_t::TYPE::FUNCTION;
    }

    SymbolTable.push_back(res);
  };

  auto process_elf_rel = [&](const Elf_Shdr &Sec, const Elf_Rel &R) -> void {
    relocation_t res;

    const Elf_Shdr *SymTab = unwrapOrError(E.getSection(Sec.sh_link));
    const Elf_Sym *Sym = unwrapOrError(E.getRelocationSymbol(&R, SymTab));
    if (Sym) {
      res.SymbolIndex = SymbolTable.size();
      process_elf_sym(*SymTab, *Sym);
    } else {
      res.SymbolIndex = std::numeric_limits<unsigned>::max();
    }

    auto relocation_type_of_elf_rel_type =
        [](uint64_t elf_rela_ty) -> relocation_t::TYPE {
      switch (elf_rela_ty) {
#include "relocs.hpp"
      default:
        return relocation_t::TYPE::NONE;
      }
    };

    res.Type = relocation_type_of_elf_rel_type(R.getType(E.isMips64EL()));
    res.Addr = R.r_offset;
    res.Addend = 0;

    RelocationTable.push_back(res);
  };

  auto process_elf_rela = [&](const Elf_Shdr &Sec, const Elf_Rela &R) -> void {
    relocation_t res;

    const Elf_Shdr *SymTab = unwrapOrError(E.getSection(Sec.sh_link));
    const Elf_Sym *Sym = unwrapOrError(E.getRelocationSymbol(&R, SymTab));
    if (Sym) {
      res.SymbolIndex = SymbolTable.size();
      process_elf_sym(*SymTab, *Sym);
    } else {
      res.SymbolIndex = std::numeric_limits<unsigned>::max();
    }

    auto relocation_type_of_elf_rela_type =
        [](uint64_t elf_rela_ty) -> relocation_t::TYPE {
      switch (elf_rela_ty) {
#include "relocs.hpp"
      default:
        return relocation_t::TYPE::NONE;
      }
    };

    res.Type = relocation_type_of_elf_rela_type(R.getType(E.isMips64EL()));
    res.Addr = R.r_offset;
    res.Addend = R.r_addend;

    RelocationTable.push_back(res);
  };

  for (const Elf_Shdr &Sec : unwrapOrError(E.sections())) {
    if (Sec.sh_type == llvm::ELF::SHT_REL) {
      for (const Elf_Rel &Rel : unwrapOrError(E.rels(&Sec)))
        process_elf_rel(Sec, Rel);
    } else if (Sec.sh_type == llvm::ELF::SHT_RELA) {
      for (const Elf_Rela &Rela : unwrapOrError(E.relas(&Sec)))
        process_elf_rela(Sec, Rela);
    }
  }

  //
  // print relocations & symbols
  //
  auto string_of_reloc_type = [](relocation_t::TYPE ty) -> const char * {
    switch (ty) {
    case relocation_t::TYPE::NONE:
      return "NONE";
    case relocation_t::TYPE::RELATIVE:
      return "RELATIVE";
    case relocation_t::TYPE::ABSOLUTE:
      return "ABSOLUTE";
    case relocation_t::TYPE::COPY:
      return "COPY";
    case relocation_t::TYPE::ADDRESSOF:
      return "ADDRESSOF";
    }
  };

  auto string_of_sym_type = [](symbol_t::TYPE ty) -> const char * {
    switch (ty) {
    case symbol_t::TYPE::NONE:
      return "NONE";
    case symbol_t::TYPE::DATA:
      return "DATA";
    case symbol_t::TYPE::FUNCTION:
      return "FUNCTION";
    case symbol_t::TYPE::TLSDATA:
      return "TLSDATA";
    }
  };

  auto string_of_sym_binding = [](symbol_t::BINDING b) -> const char * {
    switch (b) {
    case symbol_t::BINDING::NONE:
      return "NONE";
    case symbol_t::BINDING::LOCAL:
      return "LOCAL";
    case symbol_t::BINDING::WEAK:
      return "WEAK";
    case symbol_t::BINDING::GLOBAL:
      return "GLOBAL";
    }
  };

  llvm::outs() << "\nRelocations:\n\n";
  for (const relocation_t &reloc : RelocationTable) {
    llvm::outs() << "  " <<
      (boost::format("%-12s @ %-16x +%-16x") % string_of_reloc_type(reloc.Type)
                                             % reloc.Addr
                                             % reloc.Addend).str();

    if (reloc.SymbolIndex < SymbolTable.size()) {
      symbol_t &sym = SymbolTable[reloc.SymbolIndex];
      llvm::outs() <<
        (boost::format("%-30s *%-10s *%-8s @ %x {%d}")
         % sym.Name.str()
         % string_of_sym_type(sym.Type)
         % string_of_sym_binding(sym.Bind)
         % sym.Addr
         % sym.Size).str();
    }
    llvm::outs() << '\n';
  }

  return 0;
}

int PrepareToTranslateCode(void) {
  TCG.reset(new tiny_code_generator_t);

  llvm::InitializeNativeTarget();
  llvm::InitializeNativeTargetDisassembler();

  std::string ArchName;
  std::string Error;

  TheTarget = llvm::TargetRegistry::lookupTarget(ArchName, TheTriple, Error);
  if (!TheTarget) {
    WithColor::error() << "failed to lookup target: " << Error << '\n';
    return 1;
  }

  std::string TripleName = TheTriple.getTriple();

  MRI.reset(TheTarget->createMCRegInfo(TripleName));
  if (!MRI) {
    WithColor::error() << "no register info for target\n";
    return 1;
  }

  AsmInfo.reset(TheTarget->createMCAsmInfo(*MRI, TripleName));
  if (!AsmInfo) {
    WithColor::error() << "no assembly info\n";
    return 1;
  }

  std::string MCPU;

  STI.reset(
      TheTarget->createMCSubtargetInfo(TripleName, MCPU, Features.getString()));
  if (!STI) {
    WithColor::error() << "no subtarget info\n";
    return 1;
  }

  MII.reset(TheTarget->createMCInstrInfo());
  if (!MII) {
    WithColor::error() << "no instruction info\n";
    return 1;
  }

  MOFI.reset(new llvm::MCObjectFileInfo);
  MCCtx.reset(new llvm::MCContext(AsmInfo.get(), MRI.get(), MOFI.get()));

  // FIXME: for now initialize MCObjectFileInfo with default values
  MOFI->InitMCObjectFileInfo(TheTriple, false, *MCCtx);

  DisAsm.reset(TheTarget->createMCDisassembler(*STI, *MCCtx));
  if (!DisAsm) {
    WithColor::error() << "no disassembler for target\n";
    return 1;
  }

  int AsmPrinterVariant =
#if defined(__x86_64__)
      1
#else
      AsmInfo->getAssemblerDialect()
#endif
      ;
  IP.reset(TheTarget->createMCInstPrinter(
      llvm::Triple(TripleName), AsmPrinterVariant, *AsmInfo, *MII, *MRI));
  if (!IP) {
    WithColor::error() << "no instruction printer\n";
    return 1;
  }

  return 0;
}

static const uint8_t bcbytes[] = {
#include "jove/jove.bc.inc"
};

int CreateModule(void) {
  Context.reset(new llvm::LLVMContext);

  llvm::StringRef Buffer(reinterpret_cast<const char *>(&bcbytes[0]),
                         sizeof(bcbytes));
  llvm::StringRef Identifier(opts::Binary);
  llvm::MemoryBufferRef MemBuffRef(Buffer, Identifier);

  llvm::Expected<std::unique_ptr<llvm::Module>> ModuleOr =
      llvm::parseBitcodeFile(MemBuffRef, *Context);
  if (!ModuleOr) {
    WithColor::error() << "failed to parse bitcode\n";
    return 1;
  }

  std::unique_ptr<llvm::Module> &ModuleRef = ModuleOr.get();
  Module = std::move(ModuleRef);

  DL = Module->getDataLayout();
  return 0;
}

struct section_t {
  llvm::StringRef name;
  llvm::ArrayRef<uint8_t> contents;
  uintptr_t Addr;
  unsigned Size;
};

} // namespace jove

namespace llvm {

using IRBuilderTy = IRBuilder<ConstantFolder, IRBuilderDefaultInserter>;

/// Get a natural GEP from a base pointer to a particular offset and
/// resulting in a particular type.
///
/// The goal is to produce a "natural" looking GEP that works with the existing
/// composite types to arrive at the appropriate offset and element type for
/// a pointer. TargetTy is the element type the returned GEP should point-to if
/// possible. We recurse by decreasing Offset, adding the appropriate index to
/// Indices, and setting Ty to the result subtype.
///
/// If no natural GEP can be constructed, this function returns null.
static Value *getNaturalGEPWithOffset(IRBuilderTy &IRB, const DataLayout &DL,
                                      Value *Ptr, APInt Offset, Type *TargetTy,
                                      SmallVectorImpl<Value *> &Indices,
                                      Twine NamePrefix);
}

namespace jove {

llvm::Constant *SectionPointer(uintptr_t addr) {
  if (addr < SectsStartAddr || addr >= SectsEndAddr)
    return nullptr;

  unsigned off = addr - SectsStartAddr;

  llvm::IRBuilderTy IRB(*Context);
  llvm::SmallVector<llvm::Value *, 4> Indices;
  llvm::Value *res = getNaturalGEPWithOffset(
      IRB, DL, SectsGlobal, llvm::APInt(64, off), nullptr, Indices, "");
  assert(llvm::isa<llvm::Constant>(res));
  return llvm::cast<llvm::Constant>(res);
}

int CreateSectionGlobalVariables(void) {
  const auto &SectMap = BinStateVec[BinaryIndex].SectMap;
  const unsigned NumSections = SectMap.iterative_size();

  //
  // create sections table and address -> section index map
  //
  boost::icl::interval_map<uintptr_t, unsigned> SectIdxMap;

  std::vector<section_t> SectTable;
  std::vector<boost::icl::split_interval_set<uintptr_t>> SectsStuff;

  SectTable.resize(NumSections);
  SectsStuff.resize(NumSections);

  {
    uintptr_t minAddr = std::numeric_limits<uintptr_t>::max(), maxAddr = 0;
    unsigned i = 0;
    for (const auto &pair : SectMap) {
      minAddr = std::min(minAddr, pair.first.lower());
      maxAddr = std::max(maxAddr, pair.first.upper());

      SectIdxMap.add({pair.first, i});

      const section_properties_t &prop = *pair.second.begin();
      SectTable[i].Addr = pair.first.lower();
      SectTable[i].Size = pair.first.upper() - pair.first.lower();
      SectTable[i].name = prop.name;
      SectTable[i].contents = prop.contents;

      SectsStuff[i].insert(
          boost::icl::interval<uintptr_t>::right_open(0, SectTable[i].Size));

      ++i;
    }

    SectsStartAddr = minAddr;
    SectsEndAddr = maxAddr;
  }

  //
  // allocate local data structures
  //
  std::vector<llvm::StructType *> SectGVTypes;
  std::vector<std::unordered_map<unsigned, llvm::Type *>> SectRelocTypes;
  std::vector<std::unordered_map<unsigned, llvm::Constant *>> SectRelocs;

  SectGVTypes.resize(NumSections);
  SectRelocTypes.resize(NumSections);
  SectRelocs.resize(NumSections);

  auto type_for_relocation = [&](const relocation_t &R,
                                 llvm::Type *ty) -> void {
    assert(ty);

    unsigned sectidx = (*SectIdxMap.find(R.Addr)).second;
    unsigned off = R.Addr - SectTable[sectidx].Addr;

    SectRelocTypes[sectidx].insert({off, ty});
    SectsStuff[sectidx].insert(boost::icl::interval<uintptr_t>::right_open(
        off, off + sizeof(uintptr_t)));
  };

  auto process_addressof_relocation_type = [&](const relocation_t &R) -> void {
    if (!(R.SymbolIndex < SymbolTable.size()))
      return;

    symbol_t& S = SymbolTable[R.SymbolIndex];

    llvm::Type *T;

    switch (S.Type) {
    case symbol_t::TYPE::FUNCTION:
      T = llvm::PointerType::get(
          llvm::FunctionType::get(llvm::Type::getVoidTy(*Context), false), 0);
      break;

    case symbol_t::TYPE::DATA:
      T = llvm::PointerType::get(
          S.Size ? llvm::IntegerType::get(*Context, S.Size * 8)
                 : llvm::IntegerType::get(*Context, sizeof(uintptr_t) * 8),
          0);
      break;

    default:
      abort();
    }

    type_for_relocation(R, T);
  };

  auto process_relative_relocation_type = [&](const relocation_t &R) -> void {
    type_for_relocation(
        R, llvm::PointerType::get(
               llvm::IntegerType::get(*Context, sizeof(uintptr_t) * 8), 0));
  };

  for (const relocation_t &R : RelocationTable) {
    if (SectMap.find(R.Addr) == SectMap.end()) {
      WithColor::warning() << "invalid relocation\n";
      continue;
    }

    switch (R.Type) {
    case relocation_t::TYPE::ADDRESSOF:
      process_addressof_relocation_type(R);
      break;
    case relocation_t::TYPE::RELATIVE:
      process_relative_relocation_type(R);
      break;
    }
  }

  //
  // create global variable for sections
  //
  std::vector<llvm::Type *> fieldtys;
  for (unsigned i = 0; i < NumSections; ++i) {
    section_t &sect = SectTable[i];

    //
    // check if there's space between the start of this section and the previous
    //
    if (i > 0) {
      section_t &prevsect = SectTable[i - 1];
      ptrdiff_t space = sect.Addr - (prevsect.Addr + prevsect.Size);
      if (space > 0) {
        // zero padding between sections
        fieldtys.push_back(
            llvm::ArrayType::get(llvm::IntegerType::get(*Context, 8), space));
      }
    }

    std::vector<llvm::Type *> structfieldtys;

    //llvm::outs() << "SectsStuff[" << i << "]\n";
    for (const auto &intvl : SectsStuff[i]) {
      //llvm::outs() << (fmt("[%#lx, %#lx)") % intvl.lower() % intvl.upper()).str() << '\n';

      auto relocit = SectRelocTypes[i].find(intvl.lower());
      llvm::Type *ty = relocit != SectRelocTypes[i].end()
                     ? (*relocit).second
                     : llvm::ArrayType::get(llvm::IntegerType::get(*Context, 8),
                                            intvl.upper() - intvl.lower());

      structfieldtys.push_back(ty);
    }

    std::string sectnm = sect.name;
    sectnm.erase(std::remove(sectnm.begin(), sectnm.end(), '.'), sectnm.end());

    SectGVTypes[i] = llvm::StructType::create(*Context, structfieldtys,
                                              "section." + sectnm, true);

    fieldtys.push_back(SectGVTypes[i]);
  }

  llvm::StructType *sectsgvty =
      llvm::StructType::create(*Context, fieldtys, "struct.sections", true);
  SectsGlobal = new llvm::GlobalVariable(*Module, sectsgvty, false,
                                         llvm::GlobalValue::InternalLinkage,
                                         nullptr, "sections");
  SectsGlobal->setAlignment(4096);

  //
  // initialize section global variables
  //
  auto constant_for_relocation = [&](const relocation_t &R,
                                     llvm::Constant *C) -> void {
    assert(C);

    unsigned sectidx = (*SectIdxMap.find(R.Addr)).second;
    unsigned off = R.Addr - SectTable[sectidx].Addr;
    SectRelocs[sectidx].insert({off, C});
  };

  auto process_addressof_function_relocation =
      [&](const relocation_t &R) -> void {
    const symbol_t &S = SymbolTable[R.SymbolIndex];

    llvm::Function *F = Module->getFunction(S.Name);
    if (!F) {
      assert(S.IsUndefined());

      F = llvm::Function::Create(
          llvm::FunctionType::get(llvm::Type::getVoidTy(*Context), false),
          S.Bind == symbol_t::BINDING::WEAK
              ? llvm::GlobalValue::ExternalWeakLinkage
              : llvm::GlobalValue::ExternalLinkage,
          S.Name, Module.get());
    }

    constant_for_relocation(R, F);
  };

  auto process_addressof_data_relocation = [&](const relocation_t &R) -> void {
    symbol_t &S = SymbolTable[R.SymbolIndex];

    llvm::GlobalVariable *GV = Module->getGlobalVariable(S.Name);
    if (!GV) {
      assert(S.IsUndefined());

      GV = new llvm::GlobalVariable(
          *Module,
          llvm::IntegerType::get(*Context,
                                 S.Size ? S.Size * 8 : sizeof(uintptr_t) * 8),
          false,
          S.Bind == symbol_t::BINDING::WEAK
              ? llvm::GlobalValue::ExternalWeakLinkage
              : llvm::GlobalValue::ExternalLinkage,
          nullptr, S.Name);
    }

    constant_for_relocation(R, GV);
  };

  auto process_addressof_relocation = [&](const relocation_t &R) -> void {
    if (!(R.SymbolIndex < SymbolTable.size()))
      return;

    symbol_t &S = SymbolTable[R.SymbolIndex];

    switch (S.Type) {
    case symbol_t::TYPE::FUNCTION:
      process_addressof_function_relocation(R);
      break;
    case symbol_t::TYPE::DATA:
      process_addressof_data_relocation(R);
      break;
    }
  };

  auto process_relative_relocation = [&](const relocation_t &R) -> void {
    assert(SectMap.find(R.Addend) != SectMap.end());

    constant_for_relocation(R, SectionPointer(R.Addend));
  };

  for (const relocation_t &R : RelocationTable) {
    if (SectMap.find(R.Addr) == SectMap.end()) {
      WithColor::warning() << "invalid relocation\n";
      continue;
    }

    switch (R.Type) {
    case relocation_t::TYPE::ADDRESSOF:
      process_addressof_relocation(R);
      break;
    case relocation_t::TYPE::RELATIVE:
      process_relative_relocation(R);
      break;
    }
  }

  //
  // create initializers
  //
  std::vector<llvm::Constant *> fieldinits;
  for (unsigned i = 0; i < NumSections; ++i) {
    section_t &sect = SectTable[i];

    //
    // check if there's space between the start of this section and the previous
    //
    if (i > 0) {
      section_t &prevsect = SectTable[i - 1];
      ptrdiff_t space = sect.Addr - (prevsect.Addr + prevsect.Size);
      if (space > 0) {
        // zero padding between sections
        fieldinits.push_back(llvm::Constant::getNullValue(
            llvm::ArrayType::get(llvm::IntegerType::get(*Context, 8), space)));
      }
    }

    std::vector<llvm::Constant *> structfieldconsts;
    llvm::StructType *sectgvty = SectGVTypes[i];

    llvm::StructType::element_iterator sectgvty_elem_it = sectgvty->element_begin();
    for (const auto &intvl : SectsStuff[i]) {
      llvm::Type *ty;
      {
        auto relocit = SectRelocTypes[i].find(intvl.lower());
        ty = relocit != SectRelocTypes[i].end()
                 ? (*relocit).second
                 : llvm::ArrayType::get(llvm::IntegerType::get(*Context, 8),
                                        intvl.upper() - intvl.lower());
      }

      llvm::Constant *C;

      {
        auto relocit = SectRelocs[i].find(intvl.lower());
        C = relocit != SectRelocs[i].end()
                ? llvm::ConstantExpr::getPointerCast((*relocit).second, ty)
                : llvm::ConstantDataArray::get(
                      *Context, llvm::ArrayRef<uint8_t>(
                                    sect.contents.begin() + intvl.lower(),
                                    sect.contents.begin() + intvl.upper()));
      }

      structfieldconsts.push_back(C);
    }

    fieldinits.push_back(llvm::ConstantStruct::get(sectgvty, structfieldconsts));
  }

  SectsGlobal->setInitializer(llvm::ConstantStruct::get(sectsgvty, fieldinits));

  return 0;
}

struct dfs_visitor : public boost::default_dfs_visitor {
  std::vector<basic_block_t> &out;

  dfs_visitor(std::vector<basic_block_t> &out) : out(out) {}

  void discover_vertex(basic_block_t bb,
                       const interprocedural_control_flow_graph_t &) const {
    out.push_back(bb);
  }
};

int ConductLivenessAnalysis(void) {
  //
  // first we compute def_B and use_B for each basic block B
  //
  for (unsigned i = 0; i < Decompilation.Binaries.size(); ++i) {
    binary_t &binary = Decompilation.Binaries[i];
    binary_state_t &st = BinStateVec[i];
    interprocedural_control_flow_graph_t &ICFG = binary.Analysis.ICFG;

    auto it_pair = boost::vertices(ICFG);
    for (auto it = it_pair.first; it != it_pair.second; ++it) {
      basic_block_t bb = *it;
      const uintptr_t Addr = ICFG[bb].Addr;
      const unsigned Size = ICFG[bb].Size;

      auto sectit = st.SectMap.find(Addr);
      if (sectit == st.SectMap.end()) {
        WithColor::error() << "no section @ " << (fmt("%#lx") % Addr).str()
                           << '\n';
        return 1;
      }

      const section_properties_t &sectprop = *(*sectit).second.begin();
      TCG->set_section((*sectit).first.lower(), sectprop.contents.data());

      tcg_global_set_t &def = ICFG[bb].Analysis.def;
      tcg_global_set_t &use = ICFG[bb].Analysis.use;

      TCGContext *s = &TCG->_ctx;

      unsigned size = 0;
      jove::terminator_info_t T;
      do {
        unsigned len;
        std::tie(len, T) = TCG->translate(Addr + size);

        TCGOp *op, *op_next;
        QTAILQ_FOREACH_SAFE(op, &s->ops, link, op_next) {
          TCGOpcode opc = op->opc;

          int nb_oargs, nb_iargs;
          if (opc == INDEX_op_call) {
            nb_oargs = TCGOP_CALLO(op);
            nb_iargs = TCGOP_CALLI(op);
          } else {
            const TCGOpDef &opdef = tcg_op_defs[opc];

            nb_iargs = opdef.nb_iargs;
            nb_oargs = opdef.nb_oargs;
          }

          tcg_global_set_t iglbs;
          for (int i = 0; i < nb_iargs; ++i) {
            TCGTemp* ts = arg_temp(op->args[nb_oargs + i]);
            if (!ts->temp_global)
              continue;

            unsigned glb_idx = ts - &s->temps[0];
            iglbs.set(glb_idx);
          }

          tcg_global_set_t oglbs;
          for (int i = 0; i < nb_oargs; ++i) {
            TCGTemp* ts = arg_temp(op->args[i]);
            if (!ts->temp_global)
              continue;

            unsigned glb_idx = ts - &s->temps[0];
            oglbs.set(glb_idx);
          }

          use |= (iglbs & ~def);
          def |= (oglbs & ~use);
        }

        size += len;
      } while (size < Size);

      if (opts::PrintDefAndUse) {
        uint64_t InstLen;
        for (uintptr_t A = Addr; A < Addr + Size; A += InstLen) {
          std::ptrdiff_t Offset = A - (*sectit).first.lower();

          llvm::MCInst Inst;
          bool Disassembled = DisAsm->getInstruction(
              Inst, InstLen, sectprop.contents.slice(Offset), A, llvm::nulls(),
              llvm::nulls());

          if (!Disassembled) {
            WithColor::error() << "failed to disassemble "
                               << (fmt("%#lx") % Addr).str() << '\n';
            break;
          }

          IP->printInst(&Inst, llvm::outs(), "", *STI);
          llvm::outs() << '\n';
        }

        llvm::outs() << '\n';
        llvm::outs() << "def:";
        for (unsigned i = 0; i < def.size(); ++i)
          if (def[i])
            llvm::outs() << ' ' << s->temps[i].name;
        llvm::outs() << '\n';

        llvm::outs() << "use:";
        for (unsigned i = 0; i < use.size(); ++i)
          if (use[i])
            llvm::outs() << ' ' << s->temps[i].name;
        llvm::outs() << '\n';

        llvm::outs() << '\n';
      }
    }
  }

  //
  // next we conduct backwards data-flow analysis for each function
  //
  for (unsigned i = 0; i < Decompilation.Binaries.size(); ++i) {
    binary_t &Binary = Decompilation.Binaries[i];
    interprocedural_control_flow_graph_t &ICFG = Binary.Analysis.ICFG;
    for (function_t &Func : Binary.Analysis.Functions) {
      basic_block_t entryBB = boost::vertex(Func.Entry, ICFG);

      {
        std::map<basic_block_t, boost::default_color_type> color;
        dfs_visitor vis(Func.BasicBlocks);
        depth_first_visit(
            ICFG, entryBB, vis,
            boost::associative_property_map<
                std::map<basic_block_t, boost::default_color_type>>(color));
      }

      for (basic_block_t bb : Func.BasicBlocks) {
        ICFG[bb].Analysis.IN.reset();
        ICFG[bb].Analysis.OUT.reset();
      }

      bool change;
      do {
        change = false;

        for (basic_block_t bb : boost::adaptors::reverse(Func.BasicBlocks)) {
          const tcg_global_set_t _IN = ICFG[bb].Analysis.IN;

          auto eit_pair = boost::out_edges(bb, ICFG);
          ICFG[bb].Analysis.OUT = std::accumulate(
              eit_pair.first, eit_pair.second, tcg_global_set_t(),
              [&](tcg_global_set_t glbs, control_flow_t cf) {
                return glbs | ICFG[boost::target(cf, ICFG)].Analysis.IN;
              });
          ICFG[bb].Analysis.IN =
              ICFG[bb].Analysis.use |
              (ICFG[bb].Analysis.OUT & ~(ICFG[bb].Analysis.def));

          change = change || _IN != ICFG[bb].Analysis.IN;
        }
      } while (change);

      Func.Analysis.live = ICFG[entryBB].Analysis.IN;

      if (opts::PrintLiveness) {
        llvm::outs() << (fmt("%#lx") % ICFG[entryBB].Addr).str() << ' ';
        for (unsigned i = 0; i < Func.Analysis.live.size(); ++i)
          if (Func.Analysis.live[i])
            llvm::outs() << ' ' << TCG->_ctx.temps[i].name;
        llvm::outs() << '\n';
      }
    }
  }

  return 0;
}

int TranslateFunctions(void) {
  binary_t &Binary = Decompilation.Binaries[BinaryIndex];
  for (function_t &Func : Binary.Analysis.Functions) {
  }

  return 0;
}

int WriteModule(void) {
  if (llvm::verifyModule(*Module, &llvm::errs()))
    return 1;

  std::error_code EC;
  llvm::ToolOutputFile Out(opts::Output, EC, llvm::sys::fs::F_None);
  if (EC) {
    WithColor::error() << EC.message() << '\n';
    return 1;
  }

  llvm::WriteBitcodeToFile(*Module, Out.os());

  // Declare success.
  Out.keep();

  return 0;
}

} // namespace jove

namespace llvm {

/// Build a GEP out of a base pointer and indices.
///
/// This will return the BasePtr if that is valid, or build a new GEP
/// instruction using the IRBuilder if GEP-ing is needed.
static Value *buildGEP(IRBuilderTy &IRB, Value *BasePtr,
                       SmallVectorImpl<Value *> &Indices, Twine NamePrefix) {
  if (Indices.empty())
    return BasePtr;

  // A single zero index is a no-op, so check for this and avoid building a GEP
  // in that case.
  if (Indices.size() == 1 && cast<ConstantInt>(Indices.back())->isZero())
    return BasePtr;

  assert(isa<Constant>(BasePtr));
  return ConstantExpr::getInBoundsGetElementPtr(
      nullptr, cast<Constant>(BasePtr), Indices);
}

/// Get a natural GEP off of the BasePtr walking through Ty toward
/// TargetTy without changing the offset of the pointer.
///
/// This routine assumes we've already established a properly offset GEP with
/// Indices, and arrived at the Ty type. The goal is to continue to GEP with
/// zero-indices down through type layers until we find one the same as
/// TargetTy. If we can't find one with the same type, we at least try to use
/// one with the same size. If none of that works, we just produce the GEP as
/// indicated by Indices to have the correct offset.
static Value *getNaturalGEPWithType(IRBuilderTy &IRB, const DataLayout &DL,
                                    Value *BasePtr, Type *Ty, Type *TargetTy,
                                    SmallVectorImpl<Value *> &Indices,
                                    Twine NamePrefix) {
  if (Ty == TargetTy)
    return buildGEP(IRB, BasePtr, Indices, NamePrefix);

  // Pointer size to use for the indices.
  unsigned PtrSize = DL.getPointerTypeSizeInBits(BasePtr->getType());

  // See if we can descend into a struct and locate a field with the correct
  // type.
  unsigned NumLayers = 0;
  Type *ElementTy = Ty;
  do {
    if (ElementTy->isPointerTy())
      break;

    if (ArrayType *ArrayTy = dyn_cast<ArrayType>(ElementTy)) {
      ElementTy = ArrayTy->getElementType();
      Indices.push_back(IRB.getIntN(PtrSize, 0));
    } else if (VectorType *VectorTy = dyn_cast<VectorType>(ElementTy)) {
      ElementTy = VectorTy->getElementType();
      Indices.push_back(IRB.getInt32(0));
    } else if (StructType *STy = dyn_cast<StructType>(ElementTy)) {
      if (STy->element_begin() == STy->element_end())
        break; // Nothing left to descend into.
      ElementTy = *STy->element_begin();
      Indices.push_back(IRB.getInt32(0));
    } else {
      break;
    }
    ++NumLayers;
  } while (ElementTy != TargetTy);
  if (ElementTy != TargetTy)
    Indices.erase(Indices.end() - NumLayers, Indices.end());

  return buildGEP(IRB, BasePtr, Indices, NamePrefix);
}

/// Recursively compute indices for a natural GEP.
///
/// This is the recursive step for getNaturalGEPWithOffset that walks down the
/// element types adding appropriate indices for the GEP.
static Value *getNaturalGEPRecursively(IRBuilderTy &IRB, const DataLayout &DL,
                                       Value *Ptr, Type *Ty, APInt &Offset,
                                       Type *TargetTy,
                                       SmallVectorImpl<Value *> &Indices,
                                       Twine NamePrefix) {
  if (Offset == 0)
    return getNaturalGEPWithType(IRB, DL, Ptr, Ty, TargetTy, Indices,
                                 NamePrefix);

  // We can't recurse through pointer types.
  if (Ty->isPointerTy())
    return nullptr;

  // We try to analyze GEPs over vectors here, but note that these GEPs are
  // extremely poorly defined currently. The long-term goal is to remove GEPing
  // over a vector from the IR completely.
  if (VectorType *VecTy = dyn_cast<VectorType>(Ty)) {
    unsigned ElementSizeInBits = DL.getTypeSizeInBits(VecTy->getScalarType());
    if (ElementSizeInBits % 8 != 0) {
      // GEPs over non-multiple of 8 size vector elements are invalid.
      return nullptr;
    }
    APInt ElementSize(Offset.getBitWidth(), ElementSizeInBits / 8);
    APInt NumSkippedElements = Offset.sdiv(ElementSize);
    if (NumSkippedElements.ugt(VecTy->getNumElements()))
      return nullptr;
    Offset -= NumSkippedElements * ElementSize;
    Indices.push_back(IRB.getInt(NumSkippedElements));
    return getNaturalGEPRecursively(IRB, DL, Ptr, VecTy->getElementType(),
                                    Offset, TargetTy, Indices, NamePrefix);
  }

  if (ArrayType *ArrTy = dyn_cast<ArrayType>(Ty)) {
    Type *ElementTy = ArrTy->getElementType();
    APInt ElementSize(Offset.getBitWidth(), DL.getTypeAllocSize(ElementTy));
    APInt NumSkippedElements = Offset.sdiv(ElementSize);
    if (NumSkippedElements.ugt(ArrTy->getNumElements()))
      return nullptr;

    Offset -= NumSkippedElements * ElementSize;
    Indices.push_back(IRB.getInt(NumSkippedElements));
    return getNaturalGEPRecursively(IRB, DL, Ptr, ElementTy, Offset, TargetTy,
                                    Indices, NamePrefix);
  }

  StructType *STy = dyn_cast<StructType>(Ty);
  if (!STy)
    return nullptr;

  const StructLayout *SL = DL.getStructLayout(STy);
  uint64_t StructOffset = Offset.getZExtValue();
  if (StructOffset >= SL->getSizeInBytes())
    return nullptr;
  unsigned Index = SL->getElementContainingOffset(StructOffset);
  Offset -= APInt(Offset.getBitWidth(), SL->getElementOffset(Index));
  Type *ElementTy = STy->getElementType(Index);
  if (Offset.uge(DL.getTypeAllocSize(ElementTy)))
    return nullptr; // The offset points into alignment padding.

  Indices.push_back(IRB.getInt32(Index));
  return getNaturalGEPRecursively(IRB, DL, Ptr, ElementTy, Offset, TargetTy,
                                  Indices, NamePrefix);
}

Value *getNaturalGEPWithOffset(IRBuilderTy &IRB, const DataLayout &DL,
                               Value *Ptr, APInt Offset, Type *TargetTy,
                               SmallVectorImpl<Value *> &Indices,
                               Twine NamePrefix) {
  PointerType *Ty = cast<PointerType>(Ptr->getType());

  // Don't consider any GEPs through an i8* as natural unless the TargetTy is
  // an i8.
  if (Ty == IRB.getInt8PtrTy(Ty->getAddressSpace()) && TargetTy->isIntegerTy(8))
    return nullptr;

  Type *ElementTy = Ty->getElementType();
  if (!ElementTy->isSized())
    return nullptr; // We can't GEP through an unsized element.
  APInt ElementSize(Offset.getBitWidth(), DL.getTypeAllocSize(ElementTy));
  if (ElementSize == 0)
    return nullptr; // Zero-length arrays can't help us build a natural GEP.
  APInt NumSkippedElements = Offset.sdiv(ElementSize);

  Offset -= NumSkippedElements * ElementSize;
  Indices.push_back(IRB.getInt(NumSkippedElements));
  return getNaturalGEPRecursively(IRB, DL, Ptr, ElementTy, Offset, TargetTy,
                                  Indices, NamePrefix);
}
}
