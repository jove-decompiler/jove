#include "jove/tcgconstants.h"

namespace llvm {
class Function;
class BasicBlock;
class AllocaInst;
class Type;
class LoadInst;
}

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
    /* let defined_B be the set of variables defined in B */                   \
    tcg_global_set_t defined;                                                  \
                                                                               \
    /* let globals_B be the set of TCG globals referenced in B */              \
    tcg_global_set_t globals;                                                  \
                                                                               \
    /* data-flow analysis */                                                   \
    tcg_global_set_t IN, OUT;                                                  \
  } Analysis;                                                                  \
                                                                               \
  llvm::BasicBlock *B;

#define JOVE_EXTRA_FN_PROPERTIES                                               \
  std::vector<basic_block_t> BasicBlocks;                                      \
  std::vector<llvm::AllocaInst *> GlobalAllocaVec;                             \
  llvm::AllocaInst *PCAlloca;                                                  \
  llvm::LoadInst *PCRelVal;                                                    \
                                                                               \
  struct {                                                                     \
    tcg_global_set_t live;                                                     \
    tcg_global_set_t defined;                                                  \
    tcg_global_set_t globals;                                                  \
                                                                               \
    bool IsThunk;                                                              \
  } Analysis;                                                                  \
                                                                               \
  llvm::Function *F;                                                           \
  llvm::Type *retTy;

#include "tcgcommon.hpp"

#include <tuple>
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
#include <llvm/InitializePasses.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Linker/Linker.h>
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
#include <boost/dll/runtime_symbol_info.hpp>

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

  static cl::opt<bool> DumpTCG("dump-tcg",
    cl::desc("Dump TCG operations when translating basic blocks"));

  static cl::opt<bool> NoOpt1("no-opt1",
    cl::desc("Don't optimize bitcode (1)"));

  static cl::opt<bool> NoFixupPcrel("no-fixup-pcrel",
    cl::desc("Don't fixup pc-relative references"));

  static cl::opt<bool> NoOpt2("no-opt2",
    cl::desc("Don't optimize bitcode (2)"));
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

static std::unordered_map<std::string,
                          std::pair<binary_index_t, function_index_t>>
    ExportedFunctions;

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

static llvm::GlobalVariable *CPUStateGlobal;
static llvm::Type *CPUStateType;

static llvm::GlobalVariable *SectsGlobal;
static uintptr_t SectsStartAddr, SectsEndAddr;

static llvm::GlobalVariable *PCRelGlobal;

static llvm::DataLayout DL("");

struct helper_function_t {
  llvm::Function *F;
  int EnvArgNo;

  struct {
    bool Simple;
    tcg_global_set_t InGlbs, OutGlbs;
  } Analysis;
};
static std::unordered_map<void *, helper_function_t> HelperFuncMap;

//
// Stages
//
static int ParseDecompilation(void);
static int FindBinary(void);
static int InitStateForBinaries(void);
static int ProcessDynamicSymbols(void);
static int ProcessBinarySymbolsAndRelocations(void);
static int PrepareToTranslateCode(void);
static int ConductLivenessAnalysis(void);
static int ConductInterproceduralLivenessAnalysis(void);
static int InferLivenessFromCallingConvention(void);
static int CreateModule(void);
static int CreateFunctions(void);
static int CreateSectionGlobalVariables(void);
static int CreateCPUStateGlobal(void);
static int CreatePCRelGlobal(void);
static int FixupHelperStubs(void);
static int IdentifyThunks(void);
static int TranslateFunctions(void);
static int PrepareToOptimize(void);
static int Optimize1(void);
static int FixupPCRelativeAddrs(void);
static int Optimize2(void);
static int RenameFunctionLocals(void);
static int WriteModule(void);

int llvm(void) {
  return ParseDecompilation()
      || FindBinary()
      || InitStateForBinaries()
      || ProcessDynamicSymbols()
      || ProcessBinarySymbolsAndRelocations()
      || PrepareToTranslateCode()
      || ConductLivenessAnalysis()
      || ConductInterproceduralLivenessAnalysis()
      || InferLivenessFromCallingConvention()
      || CreateModule()
      || CreateFunctions()
      || CreateSectionGlobalVariables()
      || CreateCPUStateGlobal()
      || CreatePCRelGlobal()
      || FixupHelperStubs()
      || IdentifyThunks()
      || TranslateFunctions()
      || PrepareToOptimize()
      || Optimize1()
      || FixupPCRelativeAddrs()
      || Optimize2()
      || RenameFunctionLocals()
      || WriteModule();
}

void _qemu_log(const char *cstr) {
  llvm::errs() << cstr;
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
#elif defined(__i386__)
typedef typename obj::ELF32LEObjectFile ELFO;
typedef typename obj::ELF32LEFile ELFT;
#endif

template <class T>
static T unwrapOrError(llvm::Expected<T> EO) {
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
    // parse the ELF
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

    //
    // build section map
    //
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

      sectprop.w = !!(Sec.sh_flags & llvm::ELF::SHF_WRITE);
      sectprop.x = !!(Sec.sh_flags & llvm::ELF::SHF_EXECINSTR);

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

/// Represents a contiguous uniform range in the file. We cannot just create a
/// range directly because when creating one of these from the .dynamic table
/// the size, entity size and virtual address are different entries in arbitrary
/// order (DT_REL, DT_RELSZ, DT_RELENT for example).
struct DynRegionInfo {
  DynRegionInfo() = default;
  DynRegionInfo(const void *A, uint64_t S, uint64_t ES)
      : Addr(A), Size(S), EntSize(ES) {}

  /// Address in current address space.
  const void *Addr = nullptr;
  /// Size in bytes of the region.
  uint64_t Size = 0;
  /// Size of each entity in the region.
  uint64_t EntSize = 0;

  template <typename Type>
    llvm::ArrayRef<Type> getAsArrayRef() const {
    const Type *Start = reinterpret_cast<const Type *>(Addr);
    if (!Start)
      return {Start, Start};
    if (EntSize != sizeof(Type) || Size % EntSize)
      abort();
    return {Start, Start + (Size / EntSize)};
  }
};

int ProcessDynamicSymbols(void) {
  for (binary_index_t i = 0; i < Decompilation.Binaries.size(); ++i) {
    const binary_t &Binary = Decompilation.Binaries[i];
    const binary_state_t &st = BinStateVec[i];

    //
    // parse the ELF
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
    const ELFT &E = *O.getELFFile();

    typedef typename ELFT::Elf_Phdr Elf_Phdr;
    typedef typename ELFT::Elf_Dyn Elf_Dyn;
    typedef typename ELFT::Elf_Dyn_Range Elf_Dyn_Range;
    typedef typename ELFT::Elf_Sym_Range Elf_Sym_Range;
    typedef typename ELFT::Elf_Shdr Elf_Shdr;
    typedef typename ELFT::Elf_Sym Elf_Sym;

    auto checkDRI = [&E](DynRegionInfo DRI) -> DynRegionInfo {
      if (DRI.Addr < E.base() ||
          (const uint8_t *)DRI.Addr + DRI.Size > E.base() + E.getBufSize())
        abort();
      return DRI;
    };

    llvm::SmallVector<const Elf_Phdr *, 4> LoadSegments;
    DynRegionInfo DynamicTable;
    {
      auto createDRIFrom = [&E, &checkDRI](const Elf_Phdr *P,
                                           uint64_t EntSize) -> DynRegionInfo {
        return checkDRI({E.base() + P->p_offset, P->p_filesz, EntSize});
      };

      for (const Elf_Phdr &Phdr : unwrapOrError(E.program_headers())) {
        if (Phdr.p_type == llvm::ELF::PT_DYNAMIC) {
          DynamicTable = createDRIFrom(&Phdr, sizeof(Elf_Dyn));
          continue;
        }
        if (Phdr.p_type != llvm::ELF::PT_LOAD || Phdr.p_filesz == 0)
          continue;
        LoadSegments.push_back(&Phdr);
      }
    }

    assert(DynamicTable.Addr);

    DynRegionInfo DynSymRegion;
    llvm::StringRef DynSymtabName;
    llvm::StringRef DynamicStringTable;

    {
      auto createDRIFrom = [&E, &checkDRI](const Elf_Shdr *S) -> DynRegionInfo {
        return checkDRI({E.base() + S->sh_offset, S->sh_size, S->sh_entsize});
      };

      for (const Elf_Shdr &Sec : unwrapOrError(E.sections())) {
        switch (Sec.sh_type) {
        case llvm::ELF::SHT_DYNSYM:
          DynSymRegion = createDRIFrom(&Sec);
          DynSymtabName = unwrapOrError(E.getSectionName(&Sec));
          DynamicStringTable = unwrapOrError(E.getStringTableForSymtab(Sec));
          break;
        }
      }
    }

    //
    // parse dynamic table
    //
    {
      auto dynamic_table = [&DynamicTable](void) -> Elf_Dyn_Range {
        return DynamicTable.getAsArrayRef<Elf_Dyn>();
      };

      auto toMappedAddr = [&](uint64_t VAddr) -> const uint8_t * {
        const Elf_Phdr *const *I =
            std::upper_bound(LoadSegments.begin(), LoadSegments.end(), VAddr,
                             [](uint64_t VAddr, const Elf_Phdr *Phdr) {
                               return VAddr < Phdr->p_vaddr;
                             });
        if (I == LoadSegments.begin())
          abort();
        --I;
        const Elf_Phdr &Phdr = **I;
        uint64_t Delta = VAddr - Phdr.p_vaddr;
        if (Delta >= Phdr.p_filesz)
          abort();
        return E.base() + Phdr.p_offset + Delta;
      };

      const char *StringTableBegin = nullptr;
      uint64_t StringTableSize = 0;
      for (const Elf_Dyn &Dyn : dynamic_table()) {
        switch (Dyn.d_tag) {
        case llvm::ELF::DT_STRTAB:
          StringTableBegin = (const char *)toMappedAddr(Dyn.getPtr());
          break;
        case llvm::ELF::DT_STRSZ:
          StringTableSize = Dyn.getVal();
          break;
        }
      };

      if (StringTableBegin)
        DynamicStringTable = llvm::StringRef(StringTableBegin, StringTableSize);
    }

    auto dynamic_symbols = [&DynSymRegion](void) -> Elf_Sym_Range {
      return DynSymRegion.getAsArrayRef<Elf_Sym>();
    };

    for (const Elf_Sym &Sym : dynamic_symbols()) {
      if (Sym.isUndefined())
        continue;

      function_index_t FuncIdx;
      {
        auto it = st.FuncMap.find(Sym.st_value);
        if (it == st.FuncMap.end())
          continue;

        FuncIdx = (*it).second;
      }

      llvm::StringRef SymName = unwrapOrError(Sym.getName(DynamicStringTable));

#if 0
      llvm::outs() << (fmt("%#lx") % Sym.st_value).str() << ' ' << SymName
                   << '\n';
#endif

      auto it = ExportedFunctions.find(SymName);
      if (it != ExportedFunctions.end())
        WithColor::warning()
            << "multiple symbols with the name " << SymName << " found\n";

      ExportedFunctions[SymName] = {i, FuncIdx};
    }
  }
  return 0;
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
      (fmt("%-12s @ %-16x +%-16x") % string_of_reloc_type(reloc.Type)
                                   % reloc.Addr
                                   % reloc.Addend).str();

    if (reloc.SymbolIndex < SymbolTable.size()) {
      symbol_t &sym = SymbolTable[reloc.SymbolIndex];
      llvm::outs() <<
        (fmt("%-30s *%-10s *%-8s @ %x {%d}")
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
      tcg_global_set_t &defined = ICFG[bb].Analysis.defined;
      tcg_global_set_t &globals = ICFG[bb].Analysis.globals;

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

            unsigned glb_idx = temp_idx(ts);
            iglbs.set(glb_idx);
          }

          tcg_global_set_t oglbs;
          for (int i = 0; i < nb_oargs; ++i) {
            TCGTemp* ts = arg_temp(op->args[i]);
            if (!ts->temp_global)
              continue;

            unsigned glb_idx = temp_idx(ts);
            oglbs.set(glb_idx);
          }

          use |= (iglbs & ~def);
          def |= (oglbs & ~use);

          defined |= oglbs;

          globals |= oglbs;
          globals |= iglbs;
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

      Func.Analysis.defined = std::accumulate(
          Func.BasicBlocks.begin(), Func.BasicBlocks.end(), tcg_global_set_t(),
          [&](tcg_global_set_t glbs, basic_block_t bb) {
            return glbs | ICFG[bb].Analysis.defined;
          });

      Func.Analysis.globals = std::accumulate(
          Func.BasicBlocks.begin(), Func.BasicBlocks.end(), tcg_global_set_t(),
          [&](tcg_global_set_t glbs, basic_block_t bb) {
            return glbs | ICFG[bb].Analysis.globals;
          });

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

int ConductInterproceduralLivenessAnalysis(void) {
  for (unsigned k = 0; k < 2; ++k) {
  for (unsigned i = 0; i < Decompilation.Binaries.size(); ++i) {
    binary_t &Binary = Decompilation.Binaries[i];
    interprocedural_control_flow_graph_t &ICFG = Binary.Analysis.ICFG;

    auto it_pair = boost::vertices(ICFG);
    for (auto it = it_pair.first; it != it_pair.second; ++it) {
      basic_block_t bb = *it;

      tcg_global_set_t iglbs;
      tcg_global_set_t oglbs;

      switch (ICFG[bb].Term.Type) {
      case TERMINATOR::CALL: {
        function_t &callee =
            Binary.Analysis.Functions.at(ICFG[bb].Term._call.Target);

        iglbs = callee.Analysis.live;
        oglbs = callee.Analysis.defined;
        break;
      }

      case TERMINATOR::INDIRECT_JUMP:
      case TERMINATOR::INDIRECT_CALL: {
        auto &DynTargets = ICFG[bb].DynTargets;
        if (DynTargets.empty())
          continue;

        binary_index_t BinIdx;
        function_index_t FuncIdx;

        std::tie(BinIdx, FuncIdx) = *DynTargets.begin();

        function_t &callee =
            Decompilation.Binaries.at(BinIdx).Analysis.Functions.at(FuncIdx);

        iglbs = callee.Analysis.live;
        oglbs = callee.Analysis.defined;
        break;
      }

      default:
        continue;
      }

      tcg_global_set_t &def = ICFG[bb].Analysis.def;
      tcg_global_set_t &use = ICFG[bb].Analysis.use;
      tcg_global_set_t &defined = ICFG[bb].Analysis.defined;
      tcg_global_set_t &globals = ICFG[bb].Analysis.globals;

      use |= (iglbs & ~def);
      def |= (oglbs & ~use);

      defined |= oglbs;

      globals |= oglbs;
      globals |= iglbs;
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

      Func.Analysis.defined = std::accumulate(
          Func.BasicBlocks.begin(), Func.BasicBlocks.end(), tcg_global_set_t(),
          [&](tcg_global_set_t glbs, basic_block_t bb) {
            return glbs | ICFG[bb].Analysis.defined;
          });

      Func.Analysis.globals = std::accumulate(
          Func.BasicBlocks.begin(), Func.BasicBlocks.end(), tcg_global_set_t(),
          [&](tcg_global_set_t glbs, basic_block_t bb) {
            return glbs | ICFG[bb].Analysis.globals;
          });

      if (opts::PrintLiveness) {
        llvm::outs() << (fmt("%#lx") % ICFG[entryBB].Addr).str() << ' ';
        for (unsigned i = 0; i < Func.Analysis.live.size(); ++i)
          if (Func.Analysis.live[i])
            llvm::outs() << ' ' << TCG->_ctx.temps[i].name;
        llvm::outs() << '\n';
      }
    }
  }
  }

  return 0;
}

static void explode_tcg_global_set(std::vector<unsigned> &out,
                                   tcg_global_set_t glbs) {
  if (glbs.none())
    return;

  out.reserve(glbs.size());

  unsigned long long x = glbs.to_ullong();
  int idx = 0;
  do {
    int pos = ffsll(x);
    x >>= pos;
    idx += pos;
    out.push_back(idx - 1);
  } while (x);
}

int InferLivenessFromCallingConvention(void) {
  for (unsigned BinIdx = 0; BinIdx < Decompilation.Binaries.size(); ++BinIdx) {
    binary_t &Binary = Decompilation.Binaries[BinIdx];
    interprocedural_control_flow_graph_t &ICFG = Binary.Analysis.ICFG;
    for (function_t &Func : Binary.Analysis.Functions) {
      std::vector<unsigned> glbv;
      explode_tcg_global_set(glbv, Func.Analysis.live);

      auto rit = std::accumulate(
          glbv.begin(), glbv.end(), CallConvArgArray.crend(),
          [](CallConvArgArrayTy::const_reverse_iterator res, unsigned glb) {
            return std::min(res, std::find(CallConvArgArray.crbegin(),
                                           CallConvArgArray.crend(), glb));
          });

      if (rit == CallConvArgArray.crend())
        continue;

      unsigned idx = std::distance(CallConvArgArray.cbegin(), rit.base()) - 1;
      for (unsigned i = 0; i <= idx; ++i)
        Func.Analysis.live.set(CallConvArgArray[i]);
    }
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

static llvm::Type *WordType(void) {
  return llvm::Type::getIntNTy(*Context, sizeof(uintptr_t) * 8);
}

static unsigned WordBits(void) {
  return sizeof(uintptr_t) * 8;
}

static llvm::Type *VoidType(void) {
  return llvm::Type::getVoidTy(*Context);
}

static llvm::FunctionType *DetermineFunctionType(binary_index_t BinIdx,
                                                 function_index_t FuncIdx) {
  binary_t &b = Decompilation.Binaries[BinIdx];
  function_t &f = b.Analysis.Functions[FuncIdx];

  tcg_global_set_t inputs = f.Analysis.live & CallConvArgs;
  tcg_global_set_t outputs = f.Analysis.defined & CallConvRets;

  std::vector<llvm::Type *> argTypes(inputs.count(), WordType());

  llvm::Type *&retTy = f.retTy;
  if (outputs.count() == 0) {
    retTy = VoidType();
  } else if (outputs.count() == 1) {
    retTy = WordType();
  } else {
    std::vector<llvm::Type *> retTypes(outputs.count(), WordType());
    retTy = llvm::StructType::get(*Context, retTypes);
  }

  return llvm::FunctionType::get(retTy, argTypes, false);
}

int CreateFunctions(void) {
  binary_t &Binary = Decompilation.Binaries[BinaryIndex];
  interprocedural_control_flow_graph_t &ICFG = Binary.Analysis.ICFG;

  for (function_index_t FuncIdx = 0; FuncIdx < Binary.Analysis.Functions.size();
       ++FuncIdx) {
    function_t &f = Binary.Analysis.Functions[FuncIdx];
    f.F = llvm::Function::Create(DetermineFunctionType(BinaryIndex, FuncIdx),
                                 llvm::GlobalValue::ExternalLinkage,
                                 (fmt("%#lx") % ICFG[f.Entry].Addr).str(),
                                 Module.get());
    std::vector<unsigned> glbv;
    explode_tcg_global_set(glbv, f.Analysis.live & CallConvArgs);
    std::sort(glbv.begin(), glbv.end(), [](unsigned a, unsigned b) {
      return std::find(CallConvArgArray.begin(), CallConvArgArray.end(), a) <
             std::find(CallConvArgArray.begin(), CallConvArgArray.end(), b);
    });

    unsigned i = 0;
    for (llvm::Argument &A : f.F->args()) {
      A.setName(TCG->_ctx.temps[glbv[i]].name);
      ++i;
    }
  }

  return 0;
}

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
} // namespace llvm

namespace jove {

struct section_t {
  llvm::StringRef Name;
  llvm::ArrayRef<uint8_t> Contents;
  uintptr_t Addr;
  unsigned Size;

  struct {
    boost::icl::split_interval_set<uintptr_t> Intervals;
    std::map<unsigned, llvm::Constant *> Constants;
    std::map<unsigned, llvm::Type *> Types;
  } Stuff;

  llvm::StructType *T;
};

llvm::Constant *SectionPointer(uintptr_t Addr) {
  assert(Addr >= SectsStartAddr && Addr < SectsEndAddr);

  unsigned off = Addr - SectsStartAddr;

  llvm::IRBuilderTy IRB(*Context);
  llvm::SmallVector<llvm::Value *, 4> Indices;
  llvm::Value *res = llvm::getNaturalGEPWithOffset(
      IRB, DL, SectsGlobal, llvm::APInt(64, off), nullptr, Indices, "");

  assert(llvm::isa<llvm::Constant>(res));
  return llvm::cast<llvm::Constant>(res);
}

int CreateSectionGlobalVariables(void) {
  const auto &SectMap = BinStateVec[BinaryIndex].SectMap;
  const auto &FuncMap = BinStateVec[BinaryIndex].FuncMap;
  const unsigned NumSections = SectMap.iterative_size();

  //
  // create sections table and address -> section index map
  //
  std::vector<section_t> SectTable;
  SectTable.resize(NumSections);

  boost::icl::interval_map<uintptr_t, unsigned> SectIdxMap;

  {
    uintptr_t minAddr = std::numeric_limits<uintptr_t>::max(), maxAddr = 0;
    unsigned i = 0;
    for (const auto &pair : SectMap) {
      section_t &Sect = SectTable[i];

      minAddr = std::min(minAddr, pair.first.lower());
      maxAddr = std::max(maxAddr, pair.first.upper());

      SectIdxMap.add({pair.first, i});

      const section_properties_t &prop = *pair.second.begin();
      Sect.Addr = pair.first.lower();
      Sect.Size = pair.first.upper() - pair.first.lower();
      Sect.Name = prop.name;
      Sect.Contents = prop.contents;
      Sect.Stuff.Intervals.insert(
          boost::icl::interval<uintptr_t>::right_open(0, Sect.Size));

      ++i;
    }

    SectsStartAddr = minAddr;
    SectsEndAddr = maxAddr;
  }

  auto type_at_address = [&](uintptr_t Addr, llvm::Type *T) -> void {
    auto it = SectIdxMap.find(Addr);
    assert(it != SectIdxMap.end());

    section_t &Sect = SectTable[(*it).second];
    unsigned Off = Addr - Sect.Addr;

    Sect.Stuff.Intervals.insert(boost::icl::interval<uintptr_t>::right_open(
        Off, Off + sizeof(uintptr_t)));
    Sect.Stuff.Types[Off] = T;
  };

  auto type_of_addressof_function_relocation =
      [&](const relocation_t &R, const symbol_t &S) -> llvm::Type * {
    assert(S.IsUndefined());
    llvm::FunctionType *FTy;

    auto it = ExportedFunctions.find(S.Name);
    if (it == ExportedFunctions.end()) {
      WithColor::warning() << " no exported function found by the name "
                           << S.Name << '\n';

      FTy = llvm::FunctionType::get(VoidType(), false);
    } else {
      FTy = DetermineFunctionType((*it).second.first, (*it).second.second);
    }

    return llvm::PointerType::get(FTy, 0);
  };

  auto type_of_addressof_data_relocation =
      [&](const relocation_t &R, const symbol_t &S) -> llvm::Type * {
    llvm::Type *intTy = llvm::Type::getIntNTy(
        *Context, S.Size ? S.Size * 8 : sizeof(uintptr_t) * 8);
    return llvm::PointerType::get(intTy, 0);
  };

  auto type_of_relative_relocation =
      [&](const relocation_t &R) -> llvm::Type * {
    uintptr_t Addr = R.Addend ? R.Addend : R.Addr;

    auto it = FuncMap.find(Addr);
    if (it == FuncMap.end()) {
      return llvm::PointerType::get(llvm::Type::getInt8Ty(*Context), 0);
    } else {
      llvm::FunctionType *FTy =
          DetermineFunctionType(BinaryIndex, (*it).second);

      return llvm::PointerType::get(FTy, 0);
    }
  };

  auto type_of_relocation = [&](const relocation_t &R) -> llvm::Type * {
    switch (R.Type) {
    case relocation_t::TYPE::ADDRESSOF: {
      const symbol_t &S = SymbolTable[R.SymbolIndex];

      switch (S.Type) {
      case symbol_t::TYPE::FUNCTION:
        return type_of_addressof_function_relocation(R, S);
      case symbol_t::TYPE::DATA:
        return type_of_addressof_data_relocation(R, S);
      }
    }

    case relocation_t::TYPE::RELATIVE:
      return type_of_relative_relocation(R);
    }

    abort();
  };

  // puncture the interval set for each section by intervals which represent
  // relocations
  for (const relocation_t &R : RelocationTable)
    type_at_address(R.Addr, type_of_relocation(R));

  //
  // create global variable for sections
  //
  std::vector<llvm::Type *> SectsGlobalFieldTys;
  for (unsigned i = 0; i < NumSections; ++i) {
    section_t &Sect = SectTable[i];

    //
    // check if there's space between the start of this section and the previous
    //
    if (i > 0) {
      section_t &PrevSect = SectTable[i - 1];
      ptrdiff_t space = Sect.Addr - (PrevSect.Addr + PrevSect.Size);
      if (space > 0) {
        // zero padding between sections
        SectsGlobalFieldTys.push_back(
            llvm::ArrayType::get(llvm::Type::getInt8Ty(*Context), space));
      }
    }

    std::vector<llvm::Type *> SectFieldTys;

    for (const auto &intvl : Sect.Stuff.Intervals) {
      auto it = Sect.Stuff.Types.find(intvl.lower());

      llvm::Type *T;
      if (it == Sect.Stuff.Types.end())
        T = llvm::ArrayType::get(llvm::IntegerType::get(*Context, 8),
                                 intvl.upper() - intvl.lower());
      else
        T = (*it).second;

      SectFieldTys.push_back(T);
    }

    std::string SectNm = Sect.Name;
    SectNm.erase(std::remove(SectNm.begin(), SectNm.end(), '.'), SectNm.end());

    SectTable[i].T = llvm::StructType::create(*Context, SectFieldTys,
                                              "section." + SectNm, true);

    SectsGlobalFieldTys.push_back(SectTable[i].T);
  }

  llvm::StructType *SectsGlobalTy = llvm::StructType::create(
      *Context, SectsGlobalFieldTys, "struct.sections", true);
  SectsGlobal = new llvm::GlobalVariable(*Module, SectsGlobalTy, false,
                                         llvm::GlobalValue::InternalLinkage,
                                         nullptr, "sections");
  SectsGlobal->setAlignment(4096);

  auto constant_at_address = [&](uintptr_t Addr, llvm::Constant *C) -> void {
    auto it = SectIdxMap.find(Addr);
    assert(it != SectIdxMap.end());

    section_t &Sect = SectTable[(*it).second];
    unsigned Off = Addr - Sect.Addr;

    Sect.Stuff.Intervals.insert(boost::icl::interval<uintptr_t>::right_open(
        Off, Off + sizeof(uintptr_t)));
    Sect.Stuff.Constants[Off] = C;
  };

  auto constant_of_addressof_function_relocation =
      [&](const relocation_t &R, const symbol_t &S) -> llvm::Constant * {
    assert(S.IsUndefined());

    llvm::Function *F = Module->getFunction(S.Name);

    if (F)
      return F;

    auto it = ExportedFunctions.find(S.Name);
    if (it == ExportedFunctions.end()) {
      WithColor::warning() << "no exported function found by the name "
                           << S.Name << '\n';

      F = llvm::Function::Create(llvm::FunctionType::get(VoidType(), false),
                                 S.Bind == symbol_t::BINDING::WEAK
                                     ? llvm::GlobalValue::ExternalWeakLinkage
                                     : llvm::GlobalValue::ExternalLinkage,
                                 S.Name, Module.get());
    } else {
      F = llvm::Function::Create(
          DetermineFunctionType((*it).second.first, (*it).second.second),
          S.Bind == symbol_t::BINDING::WEAK
              ? llvm::GlobalValue::ExternalWeakLinkage
              : llvm::GlobalValue::ExternalLinkage,
          S.Name, Module.get());
    }

    return F;
  };

  auto constant_of_addressof_data_relocation =
      [&](const relocation_t &R, const symbol_t &S) -> llvm::Constant * {
    assert(S.IsUndefined());

    llvm::GlobalVariable *GV = Module->getGlobalVariable(S.Name);

    if (GV)
      return GV;

    GV = new llvm::GlobalVariable(
        *Module,
        llvm::Type::getIntNTy(*Context,
                              S.Size ? S.Size * 8 : sizeof(uintptr_t) * 8),
        false,
        S.Bind == symbol_t::BINDING::WEAK
            ? llvm::GlobalValue::ExternalWeakLinkage
            : llvm::GlobalValue::ExternalLinkage,
        nullptr, S.Name);

    return GV;
  };

  auto constant_of_relative_relocation =
      [&](const relocation_t &R) -> llvm::Constant * {
    uintptr_t Addr = R.Addend ? R.Addend : R.Addr;

    auto it = FuncMap.find(Addr);
    if (it == FuncMap.end()) {
      return llvm::ConstantExpr::getPointerCast(
          SectionPointer(Addr),
          llvm::PointerType::get(llvm::Type::getInt8Ty(*Context), 0));
    } else {
      binary_t &Binary = Decompilation.Binaries[BinaryIndex];
      return Binary.Analysis.Functions[(*it).second].F;
    }
  };

  auto constant_of_relocation = [&](const relocation_t &R) -> llvm::Constant * {
    switch (R.Type) {
    case relocation_t::TYPE::ADDRESSOF: {
      const symbol_t &S = SymbolTable[R.SymbolIndex];

      switch (S.Type) {
      case symbol_t::TYPE::FUNCTION:
        return constant_of_addressof_function_relocation(R, S);
      case symbol_t::TYPE::DATA:
        return constant_of_addressof_data_relocation(R, S);
      }
    }

    case relocation_t::TYPE::RELATIVE:
      return constant_of_relative_relocation(R);
    }

    abort();
  };

  // puncture the interval set for each section by intervals which represent
  // relocations
  for (const relocation_t &R : RelocationTable)
    constant_at_address(R.Addr, constant_of_relocation(R));

  //
  // create global variable initializer for sections
  //
  std::vector<llvm::Constant *> SectsGlobalFieldInits;
  for (unsigned i = 0; i < NumSections; ++i) {
    section_t &Sect = SectTable[i];

    //
    // check if there's space between the start of this section and the previous
    //
    if (i > 0) {
      section_t &PrevSect = SectTable[i - 1];
      ptrdiff_t space = Sect.Addr - (PrevSect.Addr + PrevSect.Size);
      if (space > 0) {
        // zero padding between sections
        SectsGlobalFieldInits.push_back(llvm::Constant::getNullValue(
            llvm::ArrayType::get(llvm::Type::getInt8Ty(*Context), space)));
      }
    }

    std::vector<llvm::Constant *> SectFieldInits;

    for (const auto &intvl : Sect.Stuff.Intervals) {
      auto it = Sect.Stuff.Constants.find(intvl.lower());

      llvm::Constant *C;
      if (it == Sect.Stuff.Constants.end())
        C = llvm::ConstantDataArray::get(
            *Context,
            llvm::ArrayRef<uint8_t>(Sect.Contents.begin() + intvl.lower(),
                                    Sect.Contents.begin() + intvl.upper()));
      else
        C = (*it).second;

      SectFieldInits.push_back(C);
    }

    SectsGlobalFieldInits.push_back(
        llvm::ConstantStruct::get(SectTable[i].T, SectFieldInits));
  }

  SectsGlobal->setInitializer(
      llvm::ConstantStruct::get(SectsGlobalTy, SectsGlobalFieldInits));

  return 0;
}

int CreateCPUStateGlobal() {
  llvm::Function *joveF = Module->getFunction("jove");
  llvm::FunctionType *joveFTy = joveF->getFunctionType();
  assert(joveFTy->getNumParams() == 1);
  llvm::Type *cpuStatePtrTy = joveFTy->getParamType(0);
  assert(llvm::isa<llvm::PointerType>(cpuStatePtrTy));
  CPUStateType = llvm::cast<llvm::PointerType>(cpuStatePtrTy)->getElementType();

  constexpr unsigned StackLen = 10 * 4096;

  llvm::Type *StackTy =
      llvm::ArrayType::get(llvm::Type::getInt8Ty(*Context), StackLen);
  llvm::GlobalVariable *Stack = new llvm::GlobalVariable(
      *Module, StackTy, false, llvm::GlobalValue::InternalLinkage,
      llvm::Constant::getNullValue(StackTy), "stack", nullptr,
      llvm::GlobalValue::NotThreadLocal
      /* llvm::GlobalValue::GeneralDynamicTLSModel */);

  llvm::IRBuilderTy IRB(*Context);
  llvm::Constant *StackStart = llvm::ConstantExpr::getIntToPtr(
      llvm::ConstantExpr::getAdd(
          llvm::ConstantExpr::getPtrToInt(Stack, WordType()),
          IRB.getIntN(sizeof(uintptr_t) * 8, StackLen - 512)),
      IRB.getInt8PtrTy());
  llvm::Constant *StackEnd = llvm::ConstantExpr::getIntToPtr(
      llvm::ConstantExpr::getAdd(
          llvm::ConstantExpr::getPtrToInt(Stack, WordType()),
          IRB.getIntN(sizeof(uintptr_t) * 8, StackLen)),
      IRB.getInt8PtrTy());

  assert(CPUStateType->isStructTy());
  llvm::StructType *CPUStateSType = llvm::cast<llvm::StructType>(CPUStateType);

  std::vector<llvm::Constant *> CPUStateGlobalFieldInits;
  CPUStateGlobalFieldInits.resize(CPUStateSType->getNumElements());
  std::transform(CPUStateSType->element_begin(), CPUStateSType->element_end(),
                 CPUStateGlobalFieldInits.begin(),
                 [&](llvm::Type *Ty) -> llvm::Constant * {
                   return llvm::Constant::getNullValue(Ty);
                 });

#if defined(__x86_64__) || defined(__i386__)
  llvm::Constant *&regsFieldInit = CPUStateGlobalFieldInits[0];
  unsigned mem_offset_bias = __builtin_offsetof(CPUX86State, regs[0]);
#elif defined(__aarch64__)
  llvm::Constant *&regsFieldInit = CPUStateGlobalFieldInits[1];
  unsigned mem_offset_bias = __builtin_offsetof(CPUARMState, xregs[0]);
#endif

  assert(regsFieldInit->getType()->isArrayTy());

  llvm::ArrayType *regsFieldTy =
      llvm::cast<llvm::ArrayType>(regsFieldInit->getType());

  std::vector<llvm::Constant *> regsFieldInits(
      regsFieldTy->getNumElements(),
      llvm::Constant::getNullValue(regsFieldTy->getElementType()));

  regsFieldInits.at(
      (TCG->_ctx.temps[tcg_stack_pointer_index].mem_offset - mem_offset_bias) /
      sizeof(uintptr_t)) =
      llvm::ConstantExpr::getPtrToInt(StackStart,
                                      regsFieldTy->getElementType());
  regsFieldInits.at(
      (TCG->_ctx.temps[tcg_frame_pointer_index].mem_offset - mem_offset_bias) /
      sizeof(uintptr_t)) =
      llvm::ConstantExpr::getPtrToInt(StackEnd, regsFieldTy->getElementType());

  regsFieldInit = llvm::ConstantArray::get(regsFieldTy, regsFieldInits);

  CPUStateGlobal = new llvm::GlobalVariable(
      *Module, CPUStateSType, false, llvm::GlobalValue::InternalLinkage,
      llvm::ConstantStruct::get(CPUStateSType, CPUStateGlobalFieldInits), "env",
      nullptr, llvm::GlobalValue::NotThreadLocal
      /* llvm::GlobalValue::GeneralDynamicTLSModel */);

  //
  // no longer need jove(CPUState*)
  //
  joveF->replaceAllUsesWith(llvm::UndefValue::get(joveF->getType()));
  joveF->eraseFromParent();
  return 0;
}

int CreatePCRelGlobal(void) {
  PCRelGlobal = new llvm::GlobalVariable(*Module, WordType(), false,
                                         llvm::GlobalValue::ExternalLinkage,
                                         nullptr, "__jove_pcrel");

  return 0;
}

static unsigned bitsOfTCGType(TCGType ty) {
  switch (ty) {
  case TCG_TYPE_I32:
    return 32;
  case TCG_TYPE_I64:
    return 64;
  default:
    abort();
  }
}

int FixupHelperStubs(void) {
  //
  // we assume that the user is decompiling an executable (i.e. an ELF which
  // requests an interpreter such as /lib64/ld-linux-x86-64.so.2). this code
  // will change when support for decompiling shared libraries is established.
  // TODO
  //

  llvm::Function *GetGlobalCPUStateF =
      Module->getFunction("_jove_get_global_cpu_state");
  assert(GetGlobalCPUStateF);

  {
    llvm::BasicBlock *BB =
        llvm::BasicBlock::Create(*Context, "", GetGlobalCPUStateF);

    llvm::IRBuilderTy IRB(BB);
    IRB.CreateRet(CPUStateGlobal);
  }

  GetGlobalCPUStateF->setLinkage(llvm::GlobalValue::InternalLinkage);

  llvm::Function *CallEntryF =
      Module->getFunction("_jove_call_entry");
  assert(CallEntryF);

  {
    llvm::BasicBlock *BB = llvm::BasicBlock::Create(*Context, "", CallEntryF);

    llvm::IRBuilderTy IRB(BB);

    binary_t &Binary = Decompilation.Binaries[BinaryIndex];
    function_index_t fidx = Binary.Analysis.EntryFunction;

    assert(function_index_is_valid(fidx));

    function_t &callee = Binary.Analysis.Functions[fidx];

    std::vector<llvm::Value *> ArgVec;
    {
      std::vector<unsigned> glbv;
      explode_tcg_global_set(glbv, callee.Analysis.live & CallConvArgs);
      std::sort(glbv.begin(), glbv.end(), [](unsigned a, unsigned b) {
        return std::find(CallConvArgArray.begin(), CallConvArgArray.end(), a) <
               std::find(CallConvArgArray.begin(), CallConvArgArray.end(), b);
      });

      ArgVec.resize(glbv.size());
      std::transform(
          glbv.begin(), glbv.end(), ArgVec.begin(),
          [&](unsigned glb) -> llvm::Value * {
            llvm::SmallVector<llvm::Value *, 4> Indices;
            return IRB.CreateLoad(llvm::getNaturalGEPWithOffset(
                IRB, DL, CPUStateGlobal,
                llvm::APInt(64, TCG->_ctx.temps[glb].mem_offset),
                IRB.getIntNTy(bitsOfTCGType(TCG->_ctx.temps[glb].type)),
                Indices, ""));
          });
    }

    llvm::CallInst *Ret = IRB.CreateCall(callee.F, ArgVec);
    Ret->setIsNoInline();

    IRB.CreateUnreachable();
  }

  CallEntryF->setLinkage(llvm::GlobalValue::InternalLinkage);

  return 0;
}

int IdentifyThunks(void) {
  binary_t &Binary = Decompilation.Binaries[BinaryIndex];
  auto &ICFG = Binary.Analysis.ICFG;
  const auto &SectMap = BinStateVec[BinaryIndex].SectMap;

  for (function_t &f : Binary.Analysis.Functions) {
    f.Analysis.IsThunk = false;

#if defined(__i386__)
    if (f.BasicBlocks.size() != 1)
      continue;

    basic_block_t bb = f.BasicBlocks.front();

    if (ICFG[bb].Term.Type != TERMINATOR::RETURN)
      continue;

    const uintptr_t Addr = ICFG[bb].Addr;
    const unsigned Size = ICFG[bb].Size;

    auto sectit = SectMap.find(Addr);
    assert(sectit != SectMap.end());

    const section_properties_t &sectprop = *(*sectit).second.begin();

    const uintptr_t Base = (*sectit).first.lower();

    std::vector<unsigned> opc_vec;

    uint64_t InstLen;
    for (uintptr_t A = Addr; A < Addr + Size; A += InstLen) {
      llvm::MCInst Inst;

      ptrdiff_t Offset = A - Base;
      bool Disassembled =
          DisAsm->getInstruction(Inst, InstLen, sectprop.contents.slice(Offset),
                                 A, llvm::nulls(), llvm::nulls());
      if (!Disassembled) {
        WithColor::error() << "failed to disassemble "
                           << (fmt("%#lx") % A).str() << '\n';
        return 1;
      }

      opc_vec.push_back(Inst.getOpcode());

      if (opc_vec.size() > 2)
        break;
    }

    if (opc_vec.size() > 2)
      continue;

    if (opc_vec[0] != llvm::X86::MOV32rm ||
        opc_vec[1] != llvm::X86::RETL)
      continue;

    f.Analysis.IsThunk = true;

    WithColor::note() << "thunk @ " << (fmt("%#lx") % Addr).str() << '\n';
#endif
  }

  return 0;
}

static int TranslateBasicBlock(binary_t &, function_t &, basic_block_t,
                               llvm::IRBuilderTy &);

static llvm::Constant *CPUStateGlobalPointer(unsigned glb) {
  assert(glb < tcg_num_globals);
  assert(temp_idx(TCG->_ctx.temps[glb].mem_base) == tcg_env_index);

  unsigned off = TCG->_ctx.temps[glb].mem_offset;

  llvm::IRBuilderTy IRB(*Context);
  llvm::SmallVector<llvm::Value *, 4> Indices;
  llvm::Value *res = llvm::getNaturalGEPWithOffset(
      IRB, DL, CPUStateGlobal, llvm::APInt(64, off),
      IRB.getIntNTy(bitsOfTCGType(TCG->_ctx.temps[glb].type)), Indices, "");

  assert(llvm::isa<llvm::Constant>(res));
  return llvm::cast<llvm::Constant>(res);
}

static int TranslateFunction(binary_t &Binary, function_t &f) {
  interprocedural_control_flow_graph_t &ICFG = Binary.Analysis.ICFG;
  llvm::Function *F = f.F;

  for (basic_block_t bb : f.BasicBlocks)
    ICFG[bb].B = llvm::BasicBlock::Create(
        *Context, (fmt("%#lx") % ICFG[bb].Addr).str(), F);

  f.GlobalAllocaVec.resize(tcg_num_globals);
  std::fill(f.GlobalAllocaVec.begin(), f.GlobalAllocaVec.end(), nullptr);

  {
    basic_block_t bb = f.BasicBlocks.front();
    llvm::IRBuilderTy IRB(ICFG[bb].B);

    tcg_global_set_t glbs = f.Analysis.globals;
    glbs.reset(tcg_env_index);

    if (tcg_program_counter_index >= 0)
      glbs.set(tcg_program_counter_index);

    {
      std::vector<unsigned> glbv;
      explode_tcg_global_set(glbv, glbs);

      for (unsigned glb : glbv)
        f.GlobalAllocaVec[glb] = IRB.CreateAlloca(
            IRB.getIntNTy(bitsOfTCGType(TCG->_ctx.temps[glb].type)), 0,
            std::string(TCG->_ctx.temps[glb].name) + "_ptr");
    }

    f.PCAlloca = tcg_program_counter_index < 0
                     ? f.PCAlloca = IRB.CreateAlloca(WordType(), 0, "pc_ptr")
                     : f.GlobalAllocaVec[tcg_program_counter_index];
    f.PCRelVal = IRB.CreateLoad(PCRelGlobal, "pcrel");

    {
      std::vector<unsigned> glbv;
      explode_tcg_global_set(glbv, f.Analysis.live & CallConvArgs);
      std::sort(glbv.begin(), glbv.end(), [](unsigned a, unsigned b) {
        return std::find(CallConvArgArray.begin(), CallConvArgArray.end(), a) <
               std::find(CallConvArgArray.begin(), CallConvArgArray.end(), b);
      });

      llvm::Function::arg_iterator arg_it = F->arg_begin();
      for (unsigned glb : glbv) {
        assert(arg_it != F->arg_end());
        llvm::Argument *Val = &*arg_it++;
        llvm::Value *Ptr = f.GlobalAllocaVec[glb];
        IRB.CreateStore(Val, Ptr);
      }
    }

    {
      std::vector<unsigned> glbv;
      explode_tcg_global_set(glbv, glbs & ~(f.Analysis.live & CallConvArgs));

      for (unsigned glb : glbv) {
        llvm::Value *Val = IRB.CreateLoad(CPUStateGlobalPointer(glb));
        llvm::Value *Ptr = f.GlobalAllocaVec[glb];
        IRB.CreateStore(Val, Ptr);
      }
    }

    if (int ret = TranslateBasicBlock(Binary, f, bb, IRB))
      return ret;
  }

  for (unsigned i = 1; i < f.BasicBlocks.size(); ++i) {
    basic_block_t bb = f.BasicBlocks[i];
    llvm::IRBuilderTy IRB(ICFG[bb].B);

    if (int ret = TranslateBasicBlock(Binary, f, bb, IRB))
      return ret;
  }

  if (llvm::verifyFunction(*F, &llvm::errs())) {
    llvm::errs() << *F << '\n';
    return 1;
  }

  return 0;
}

int TranslateFunctions(void) {
  binary_t &Binary = Decompilation.Binaries[BinaryIndex];
  for (function_t &f : Binary.Analysis.Functions) {
    if (int ret = TranslateFunction(Binary, f))
      return ret;
  }

  return 0;
}

int PrepareToOptimize(void) {
  // Initialize passes
  llvm::PassRegistry &Registry = *llvm::PassRegistry::getPassRegistry();
  llvm::initializeCore(Registry);
  llvm::initializeCoroutines(Registry);
  llvm::initializeScalarOpts(Registry);
  llvm::initializeObjCARCOpts(Registry);
  llvm::initializeVectorization(Registry);
  llvm::initializeIPO(Registry);
  llvm::initializeAnalysis(Registry);
  llvm::initializeTransformUtils(Registry);
  llvm::initializeInstCombine(Registry);
  llvm::initializeAggressiveInstCombine(Registry);
  llvm::initializeInstrumentation(Registry);
  llvm::initializeTarget(Registry);
  // For codegen passes, only passes that do IR to IR transformation are
  // supported.
  llvm::initializeExpandMemCmpPassPass(Registry);
  llvm::initializeScalarizeMaskedMemIntrinPass(Registry);
  llvm::initializeCodeGenPreparePass(Registry);
  llvm::initializeAtomicExpandPass(Registry);
  llvm::initializeRewriteSymbolsLegacyPassPass(Registry);
  llvm::initializeWinEHPreparePass(Registry);
  llvm::initializeDwarfEHPreparePass(Registry);
  llvm::initializeSafeStackLegacyPassPass(Registry);
  llvm::initializeSjLjEHPreparePass(Registry);
  llvm::initializePreISelIntrinsicLoweringLegacyPassPass(Registry);
  llvm::initializeGlobalMergePass(Registry);
  llvm::initializeIndirectBrExpandPassPass(Registry);
  llvm::initializeInterleavedAccessPass(Registry);
  llvm::initializeEntryExitInstrumenterPass(Registry);
  llvm::initializePostInlineEntryExitInstrumenterPass(Registry);
  llvm::initializeUnreachableBlockElimLegacyPassPass(Registry);
  llvm::initializeExpandReductionsPass(Registry);
  llvm::initializeWasmEHPreparePass(Registry);
  llvm::initializeWriteBitcodePassPass(Registry);

  return 0;
}

static void DoOptimize(void) {
  llvm::legacy::PassManager MPM;
  llvm::legacy::FunctionPassManager FPM(Module.get());

  llvm::PassManagerBuilder Builder;
  Builder.OptLevel = 2;
  Builder.SizeLevel = 2;

  Builder.populateFunctionPassManager(FPM);
  Builder.populateModulePassManager(MPM);

  FPM.doInitialization();
  for (llvm::Function &F : *Module)
    FPM.run(F);
  FPM.doFinalization();

  MPM.run(*Module);
}

int Optimize1(void) {
  if (opts::NoOpt1)
    return 0;

  DoOptimize();
  return 0;
}

int FixupPCRelativeAddrs(void) {
  if (opts::NoFixupPcrel)
    return 0;

  PCRelGlobal = Module->getGlobalVariable("__jove_pcrel");
  if (!PCRelGlobal)
    return 0;

  binary_state_t &st = BinStateVec[BinaryIndex];
  binary_t &Binary = Decompilation.Binaries[BinaryIndex];

  std::vector<std::pair<llvm::Instruction *, llvm::Constant *>> ToReplace;

  for (llvm::User *U : PCRelGlobal->users()) {
    assert(llvm::isa<llvm::LoadInst>(U));
    llvm::LoadInst *L = llvm::cast<llvm::LoadInst>(U);

    for (llvm::User *LU : L->users()) {
      assert(llvm::isa<llvm::Instruction>(LU));
      unsigned opc = llvm::cast<llvm::Instruction>(LU)->getOpcode();

      if (opc == llvm::Instruction::Add) {
        llvm::Value *RHS = LU->getOperand(1);

        if (llvm::isa<llvm::ConstantInt>(RHS)) {
          uintptr_t Addr = llvm::cast<llvm::ConstantInt>(RHS)->getZExtValue();

          llvm::Constant *C;

          auto it = st.FuncMap.find(Addr);
          if (it == st.FuncMap.end())
            C = SectionPointer(Addr);
          else
            C = Binary.Analysis.Functions[(*it).second].F;

          if (C) {
            C = llvm::ConstantExpr::getPtrToInt(C, WordType());

            ToReplace.push_back({llvm::cast<llvm::Instruction>(LU), C});
          }
        }
      }
    }
  }

  for (auto &TR : ToReplace) {
    llvm::Instruction *I;
    llvm::Constant *C;
    std::tie(I, C) = TR;

    assert(I->getType() == C->getType());
    I->replaceAllUsesWith(C);
  }

  return 0;
}

int Optimize2(void) {
  if (opts::NoOpt2)
    return 0;

  DoOptimize();

  PCRelGlobal = Module->getGlobalVariable("__jove_pcrel");
  if (PCRelGlobal) {
    if (PCRelGlobal->user_begin() == PCRelGlobal->user_end())
      PCRelGlobal->eraseFromParent();
    else
      WithColor::warning() << "PCRel global not eliminated\n";
  }

  return 0;
}

int RenameFunctionLocals(void) {
  CPUStateGlobal = Module->getGlobalVariable("env", true);
  if (!CPUStateGlobal)
    return 0;

  for (llvm::User *U : CPUStateGlobal->users()) {
    int glb = -1;

    if (llvm::ConstantExpr *CE = llvm::dyn_cast<llvm::ConstantExpr>(U)) {
      llvm::Instruction *I = CE->getAsInstruction();
      llvm::GetElementPtrInst *GEP = llvm::dyn_cast<llvm::GetElementPtrInst>(I);

      if (GEP) {
        llvm::APInt Off(DL.getPointerTypeSizeInBits(GEP->getType()), 0);
        llvm::cast<llvm::GEPOperator>(GEP)->accumulateConstantOffset(DL, Off);
        unsigned off = Off.getZExtValue();

        if (off < sizeof(tcg_global_by_offset_lookup_table))
          glb = tcg_global_by_offset_lookup_table[off];
      }

      I->deleteValue();
    }

    if (glb < 0)
      continue;

    const char *nm = TCG->_ctx.temps[glb].name;
    for (llvm::User *UU : U->users()) {
      if (llvm::isa<llvm::LoadInst>(UU))
        UU->setName(nm);
    }
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

  if (isa<Constant>(BasePtr))
    return ConstantExpr::getInBoundsGetElementPtr(
        nullptr, cast<Constant>(BasePtr), Indices);
  else
    return IRB.CreateInBoundsGEP(nullptr, BasePtr, Indices, NamePrefix);
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

} // namespace llvm

namespace jove {

static int TranslateTCGOp(TCGOp *op, TCGOp *op_next,
                          binary_t &, function_t &, basic_block_t,
                          std::vector<llvm::AllocaInst *> &,
                          std::vector<llvm::BasicBlock *> &,
                          llvm::BasicBlock *,
                          llvm::IRBuilderTy &);

int TranslateBasicBlock(binary_t &Binary, function_t &f, basic_block_t bb,
                        llvm::IRBuilderTy &IRB) {
  const auto &ICFG = Binary.Analysis.ICFG;

  const uintptr_t Addr = ICFG[bb].Addr;
  const unsigned Size = ICFG[bb].Size;

  binary_state_t &st = BinStateVec[BinaryIndex];

  {
    auto sectit = st.SectMap.find(Addr);
    assert(sectit != st.SectMap.end());

    const section_properties_t &sectprop = *(*sectit).second.begin();
    TCG->set_section((*sectit).first.lower(), sectprop.contents.data());
  }

  llvm::BasicBlock *ExitBB =
      llvm::BasicBlock::Create(*Context, (fmt("%#lx_exit") % Addr).str(), f.F);

  TCGContext *s = &TCG->_ctx;

  unsigned size = 0;
  jove::terminator_info_t T;
  do {
    unsigned len;
    std::tie(len, T) = TCG->translate(Addr + size);

    std::vector<llvm::AllocaInst *> TempAllocaVec(s->nb_temps, nullptr);
    std::vector<llvm::BasicBlock *> LabelVec(s->nb_labels, nullptr);

    //
    // create temp alloca's up-front
    //
    {
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

        for (int i = 0; i < nb_iargs; ++i) {
          TCGTemp *ts = arg_temp(op->args[nb_oargs + i]);
          if (ts->temp_global)
            continue;

          unsigned idx = temp_idx(ts);
          if (TempAllocaVec.at(idx))
            continue;

          TempAllocaVec.at(idx) =
            IRB.CreateAlloca(IRB.getIntNTy(bitsOfTCGType(ts->type)), 0,
                            (fmt("%#lx_%s%u")
                             % ICFG[bb].Addr
                             % (ts->temp_local ? "loc" : "tmp")
                             % (idx - tcg_num_globals)).str());
        }

        for (int i = 0; i < nb_oargs; ++i) {
          TCGTemp *ts = arg_temp(op->args[i]);
          if (ts->temp_global)
            continue;

          unsigned idx = temp_idx(ts);
          if (TempAllocaVec.at(idx))
            continue;

          TempAllocaVec.at(idx) =
            IRB.CreateAlloca(IRB.getIntNTy(bitsOfTCGType(ts->type)), 0,
                            (fmt("%#lx_%s%u")
                             % ICFG[bb].Addr
                             % (ts->temp_local ? "loc" : "tmp")
                             % (idx - tcg_num_globals)).str());
        }
      }
    }

    if (opts::DumpTCG)
      TCG->dump_operations();

    TCGOp *op, *op_next;
    QTAILQ_FOREACH_SAFE(op, &s->ops, link, op_next) {
      if (int ret = TranslateTCGOp(op, op_next, Binary, f, bb, TempAllocaVec,
                                   LabelVec,
                                   size + len < Size ? nullptr : ExitBB, IRB)) {
        TCG->dump_operations();
        return ret;
      }
    }

    size += len;
  } while (size < Size);

  IRB.SetInsertPoint(ExitBB);

  //
  // if this basic block calls a thunk, then we'll translate the thunk in-place
  //
  bool TranslatedThunk = false;
  if (T.Type == TERMINATOR::CALL) {
    function_t &callee = Binary.Analysis.Functions[ICFG[bb].Term._call.Target];
    if (callee.Analysis.IsThunk) {
      TranslatedThunk = true;

      assert(callee.BasicBlocks.size() == 1);
      basic_block_t thunkbb = callee.BasicBlocks.front();
      uintptr_t ThunkAddr = ICFG[thunkbb].Addr;

      auto sectit = st.SectMap.find(ThunkAddr);
      assert(sectit != st.SectMap.end());

      const section_properties_t &sectprop = *(*sectit).second.begin();
      TCG->set_section((*sectit).first.lower(), sectprop.contents.data());

      TCG->translate(ThunkAddr);

      std::vector<llvm::AllocaInst *> TempAllocaVec(s->nb_temps, nullptr);
      std::vector<llvm::BasicBlock *> LabelVec(s->nb_labels, nullptr);

      //
      // create temp alloca's up-front
      //
      {
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

          for (int i = 0; i < nb_iargs; ++i) {
            TCGTemp *ts = arg_temp(op->args[nb_oargs + i]);
            if (ts->temp_global)
              continue;

            unsigned idx = temp_idx(ts);
            if (TempAllocaVec.at(idx))
              continue;

            TempAllocaVec.at(idx) = IRB.CreateAlloca(
                IRB.getIntNTy(bitsOfTCGType(ts->type)), 0,
                (fmt("%#lx_%s%u") % ICFG[bb].Addr %
                 (ts->temp_local ? "loc" : "tmp") % (idx - tcg_num_globals))
                    .str());
          }

          for (int i = 0; i < nb_oargs; ++i) {
            TCGTemp *ts = arg_temp(op->args[i]);
            if (ts->temp_global)
              continue;

            unsigned idx = temp_idx(ts);
            if (TempAllocaVec.at(idx))
              continue;

            TempAllocaVec.at(idx) = IRB.CreateAlloca(
                IRB.getIntNTy(bitsOfTCGType(ts->type)), 0,
                (fmt("%#lx_%s%u") % ICFG[bb].Addr %
                 (ts->temp_local ? "loc" : "tmp") % (idx - tcg_num_globals))
                    .str());
          }
        }
      }

      ExitBB = llvm::BasicBlock::Create(
          *Context, (fmt("%#lx_thunk_exit") % Addr).str(), f.F);

      TCGOp *op, *op_next;
      QTAILQ_FOREACH_SAFE(op, &s->ops, link, op_next) {
        if (int ret = TranslateTCGOp(op, op_next, Binary, f, bb, TempAllocaVec,
                                     LabelVec, ExitBB, IRB)) {
          TCG->dump_operations();
          return ret;
        }
      }

      IRB.SetInsertPoint(ExitBB);
    }
  }

  //
  // examine terminator
  //
  switch (T.Type) {
  case TERMINATOR::CALL: {
    if (TranslatedThunk)
      break;

    function_t &callee = Binary.Analysis.Functions[ICFG[bb].Term._call.Target];

    std::vector<llvm::Value *> ArgVec;
    {
      std::vector<unsigned> glbv;
      explode_tcg_global_set(glbv, callee.Analysis.live & CallConvArgs);
      std::sort(glbv.begin(), glbv.end(), [](unsigned a, unsigned b) {
        return std::find(CallConvArgArray.begin(), CallConvArgArray.end(), a) <
               std::find(CallConvArgArray.begin(), CallConvArgArray.end(), b);
      });

      ArgVec.resize(glbv.size());
      std::transform(glbv.begin(), glbv.end(), ArgVec.begin(),
                     [&](unsigned glb) -> llvm::Value * {
                       return IRB.CreateLoad(f.GlobalAllocaVec[glb]);
                     });
    }

    llvm::CallInst *Ret = IRB.CreateCall(callee.F, ArgVec);
    Ret->setIsNoInline();

    if (!callee.retTy->isVoidTy()) {
      std::vector<unsigned> glbv;
      explode_tcg_global_set(glbv, callee.Analysis.defined & CallConvRets);
      std::sort(glbv.begin(), glbv.end(), [](unsigned a, unsigned b) {
        return std::find(CallConvRetArray.begin(), CallConvRetArray.end(), a) <
               std::find(CallConvRetArray.begin(), CallConvRetArray.end(), b);
      });

      if (glbv.size() == 1) {
        assert(callee.retTy->isIntegerTy());
        IRB.CreateStore(Ret, f.GlobalAllocaVec[glbv.front()]);
      } else {
        for (unsigned i = 0; i < glbv.size(); ++i) {
          llvm::AllocaInst *Ptr = f.GlobalAllocaVec[glbv[i]];
          llvm::Value *Val =
              IRB.CreateExtractValue(Ret, llvm::ArrayRef<unsigned>(i));
          IRB.CreateStore(Val, Ptr);
        }
      }
    }
    break;
  }

  case TERMINATOR::INDIRECT_JUMP: {
    //
    // if      pc == target_1 ; goto target_1
    // else if pc == target_2 ; goto target_2
    // else if pc == target_3 ; goto target_3
    //       ...
    // else if pc == target_n ; goto target_n
    // else                   ; goto (*pc)            [fallthrough case]
    //
    auto eit_pair = boost::out_edges(bb, ICFG);
    for (auto it = eit_pair.first; it != eit_pair.second; ++it) {
      basic_block_t succ = boost::target(*it, ICFG);

      llvm::Value *PC = IRB.CreateLoad(f.PCAlloca);
      llvm::Value *EQV = IRB.CreateICmpEQ(
          PC, llvm::ConstantExpr::getPtrToInt(SectionPointer(ICFG[succ].Addr),
                                              WordType()));

      llvm::BasicBlock *NextB = llvm::BasicBlock::Create(*Context, "", f.F);

      IRB.CreateCondBr(EQV, ICFG[succ].B, NextB);
      IRB.SetInsertPoint(NextB);
    }
  }

  case TERMINATOR::INDIRECT_CALL: {
    llvm::Value *PC = IRB.CreateLoad(f.PCAlloca);

    const auto &DynTargets = ICFG[bb].DynTargets;
    if (DynTargets.empty()) {
      IRB.CreateCall(IRB.CreateIntToPtr(
          PC, llvm::PointerType::get(llvm::FunctionType::get(VoidType(), false),
                                     0)));
      break;
    }

    function_index_t BinIdx = (*DynTargets.begin()).first;
    function_index_t FuncIdx = (*DynTargets.begin()).second;

    function_t &callee =
        Decompilation.Binaries[BinIdx].Analysis.Functions[FuncIdx];

    std::vector<llvm::Value *> ArgVec;
    {
      std::vector<unsigned> glbv;
      explode_tcg_global_set(glbv, callee.Analysis.live & CallConvArgs);
      std::sort(glbv.begin(), glbv.end(), [](unsigned a, unsigned b) {
        return std::find(CallConvArgArray.begin(), CallConvArgArray.end(), a) <
               std::find(CallConvArgArray.begin(), CallConvArgArray.end(), b);
      });

      ArgVec.resize(glbv.size());
      std::transform(glbv.begin(), glbv.end(), ArgVec.begin(),
                     [&](unsigned glb) -> llvm::Value * {
                       return IRB.CreateLoad(f.GlobalAllocaVec[glb]);
                     });
    }

    llvm::CallInst *Ret = IRB.CreateCall(
        IRB.CreateIntToPtr(PC, llvm::PointerType::get(
                                   DetermineFunctionType(BinIdx, FuncIdx), 0)),
        ArgVec);
    Ret->setIsNoInline();

    if (!callee.retTy->isVoidTy()) {
      std::vector<unsigned> glbv;
      explode_tcg_global_set(glbv, callee.Analysis.defined & CallConvRets);
      std::sort(glbv.begin(), glbv.end(), [](unsigned a, unsigned b) {
        return std::find(CallConvRetArray.begin(), CallConvRetArray.end(), a) <
               std::find(CallConvRetArray.begin(), CallConvRetArray.end(), b);
      });

      if (glbv.size() == 1) {
        assert(callee.retTy->isIntegerTy());
        IRB.CreateStore(Ret, f.GlobalAllocaVec[glbv.front()]);
      } else {
        for (unsigned i = 0; i < glbv.size(); ++i) {
          llvm::AllocaInst *Ptr = f.GlobalAllocaVec[glbv[i]];
          if (!Ptr) {
            WithColor::error() << "no alloca for global "
                               << TCG->_ctx.temps[glbv[i]].name << '\n';
            return 1;
          }
          llvm::Value *Val =
              IRB.CreateExtractValue(Ret, llvm::ArrayRef<unsigned>(i));
          IRB.CreateStore(Val, Ptr);
        }
      }
    }
    break;
  }

  default:
    break;
  }

  switch (T.Type) {
  case TERMINATOR::CONDITIONAL_JUMP: {
    auto eit_pair = boost::out_edges(bb, ICFG);
    assert(eit_pair.first != eit_pair.second &&
           std::next(std::next(eit_pair.first)) == eit_pair.second);

    control_flow_t cf1 = *eit_pair.first;
    control_flow_t cf2 = *std::next(eit_pair.first);

    basic_block_t succ1 = boost::target(cf1, ICFG);
    basic_block_t succ2 = boost::target(cf2, ICFG);

    llvm::Value *PC = IRB.CreateLoad(f.PCAlloca);
    llvm::Value *EQV = IRB.CreateICmpEQ(
        PC, IRB.getIntN(sizeof(uintptr_t) * 8, ICFG[succ1].Addr));
    IRB.CreateCondBr(EQV, ICFG[succ1].B, ICFG[succ2].B);
    break;
  }

  case TERMINATOR::CALL:
  case TERMINATOR::UNCONDITIONAL_JUMP:
  case TERMINATOR::INDIRECT_CALL: {
    auto eit_pair = boost::out_edges(bb, ICFG);
    assert(eit_pair.first != eit_pair.second &&
           std::next(eit_pair.first) == eit_pair.second);
    control_flow_t cf = *eit_pair.first;
    basic_block_t succ = boost::target(cf, ICFG);
    IRB.CreateBr(ICFG[succ].B);
    break;
  }

  case TERMINATOR::INDIRECT_JUMP:
  case TERMINATOR::RETURN: {
    if (f.retTy->isVoidTy()) {
      IRB.CreateRetVoid();
      break;
    }

    std::vector<unsigned> glbv;
    {
      explode_tcg_global_set(glbv, f.Analysis.defined & CallConvRets);
      std::sort(glbv.begin(), glbv.end(), [](unsigned a, unsigned b) {
        return std::find(CallConvRetArray.begin(), CallConvRetArray.end(), a) <
               std::find(CallConvRetArray.begin(), CallConvRetArray.end(), b);
      });
    }

    if (f.retTy->isIntegerTy()) {
      assert(glbv.size() == 1);
      IRB.CreateRet(IRB.CreateLoad(f.GlobalAllocaVec[glbv.front()]));
      break;
    }

    assert(f.retTy->isStructTy());
    assert(glbv.size() > 1);
    llvm::Value *retVal =
        accumulate(
            glbv.begin(), glbv.end(),
            std::pair<unsigned, llvm::Value *>(0u, nullptr),
            [&](std::pair<unsigned, llvm::Value *> respair, unsigned glbidx) {
              unsigned idx;
              llvm::Value *res;
              std::tie(idx, res) = respair;

              return std::make_pair(
                  idx + 1, IRB.CreateInsertValue(
                               res ? res : llvm::UndefValue::get(f.retTy),
                               IRB.CreateLoad(f.GlobalAllocaVec[glbidx]),
                               llvm::ArrayRef<unsigned>(idx)));
            })
            .second;
    IRB.CreateRet(retVal);
    break;
  }

  case TERMINATOR::UNREACHABLE:
    IRB.CreateUnreachable();
    break;

  default:
    break;
  }

  return 0;
}

static void AnalyzeTCGHelper(helper_function_t &hf) {
  hf.Analysis.Simple = true;

  if (hf.EnvArgNo < 0)
    return;

  llvm::Function::arg_iterator arg_it = hf.F->arg_begin();
  std::advance(arg_it, hf.EnvArgNo);
  llvm::Argument &A = *arg_it;

  for (llvm::User *EnvU : A.users()) {
    if (llvm::isa<llvm::GetElementPtrInst>(EnvU)) {
      llvm::GetElementPtrInst *EnvGEP =
          llvm::cast<llvm::GetElementPtrInst>(EnvU);

      if (!llvm::cast<llvm::GEPOperator>(EnvGEP)->hasAllConstantIndices()) {
        hf.Analysis.Simple = false;
        continue;
      }

      llvm::APInt Off(DL.getPointerTypeSizeInBits(EnvGEP->getType()), 0);
      llvm::cast<llvm::GEPOperator>(EnvGEP)->accumulateConstantOffset(DL, Off);
      unsigned off = Off.getZExtValue();

      if (!(off < sizeof(tcg_global_by_offset_lookup_table)) ||
          tcg_global_by_offset_lookup_table[off] < 0) {
        hf.Analysis.Simple = false;
        continue;
      }

      unsigned glb =
          static_cast<unsigned>(tcg_global_by_offset_lookup_table[off]);

      for (llvm::User *GEPU : EnvGEP->users()) {
        if (llvm::isa<llvm::LoadInst>(GEPU)) {
          hf.Analysis.InGlbs.set(glb);
        } else if (llvm::isa<llvm::StoreInst>(GEPU)) {
          hf.Analysis.OutGlbs.set(glb);
        } else {
          WithColor::warning() << "unknown global GEP user " << *GEPU << '\n';

          hf.Analysis.Simple = false;
        }
      }
    } else {
      WithColor::warning() << "unknown env user " << *EnvU << '\n';

      hf.Analysis.Simple = false;
    }
  }
}

static const unsigned bits_of_memop_lookup_table[] = {8, 16, 32, 64};

static unsigned bits_of_memop(TCGMemOp op) {
  return bits_of_memop_lookup_table[op & MO_SIZE];
}

int TranslateTCGOp(TCGOp *op, TCGOp *next_op,
                   binary_t &Binary, function_t &f, basic_block_t bb,
                   std::vector<llvm::AllocaInst *> &TempAllocaVec,
                   std::vector<llvm::BasicBlock *> &LabelVec,
                   llvm::BasicBlock *ExitBB, llvm::IRBuilderTy &IRB) {
  const auto &ICFG = Binary.Analysis.ICFG;
  std::vector<llvm::AllocaInst *> &GlobalAllocaVec = f.GlobalAllocaVec;
  llvm::AllocaInst *PCAlloca = f.PCAlloca;
  TCGContext *s = &TCG->_ctx;

  auto set = [&](llvm::Value *V, TCGTemp *ts) -> void {
    unsigned idx = temp_idx(ts);

    llvm::AllocaInst *Ptr =
        ts->temp_global ? GlobalAllocaVec.at(idx) : TempAllocaVec.at(idx);
    assert(Ptr);
    IRB.CreateStore(V, Ptr);
  };

  auto get = [&](TCGTemp *ts) -> llvm::Value * {
    unsigned idx = temp_idx(ts);

    if (ts->temp_global && idx == tcg_env_index)
      return llvm::ConstantExpr::getPtrToInt(CPUStateGlobal, WordType());

    llvm::AllocaInst *Ptr =
        ts->temp_global ? GlobalAllocaVec.at(idx) : TempAllocaVec.at(idx);
    assert(Ptr);

    return IRB.CreateLoad(Ptr);
  };

  static bool pcrel_flag = false;

  auto immediate_constant = [&](unsigned bits, TCGArg a) -> llvm::Value * {
    if (pcrel_flag && bits == sizeof(uintptr_t) * 8) {
      pcrel_flag = false;

      if (!(a >= SectsStartAddr && a < SectsEndAddr))
        WithColor::warning() << "immediate_constant: out-of-bounds pcrel\n";

#if 0
      binary_state_t &st = BinStateVec[BinaryIndex];
      auto it = st.FuncMap.find(a);
      return llvm::ConstantExpr::getPtrToInt(it == st.FuncMap.end() ?
                                             SectionPointer(a) :
                                             Binary.Analysis.Functions[(*it).second].F, WordType());
#else
      return IRB.CreateAdd(f.PCRelVal, IRB.getIntN(sizeof(uintptr_t) * 8, a));
#endif
    }

    switch (bits) {
    case 64:
      return IRB.getInt64(a);
    case 32:
      return IRB.getInt32(a);
    default:
      abort();
    }
  };

  const TCGOpcode opc = op->opc;
  const TCGOpDef &def = tcg_op_defs[opc];

  int nb_oargs = def.nb_oargs;
  int nb_iargs = def.nb_iargs;
  int nb_cargs = def.nb_cargs;

#if 0
  llvm::errs() << def.name << ' '
               << nb_oargs << ' '
               << nb_iargs << ' '
               << nb_cargs << '\n';
#endif

  switch (opc) {
  case INDEX_op_insn_start:
    static uint64_t lstaddr = 0;
    if (op->args[0] == JOVE_PCREL_MAGIC && op->args[1] == JOVE_PCREL_MAGIC) {
      pcrel_flag = true;

      WithColor::note() << "PC-relative expression @ "
                        << (fmt("%#lx") % lstaddr).str() << '\n';
    } else {
      pcrel_flag = false;

      lstaddr = op->args[0];
    }
    break;

  case INDEX_op_discard:
  case INDEX_op_goto_tb:
    break;

  case INDEX_op_set_label: {
    if (!IRB.GetInsertBlock()->getTerminator()) {
      WithColor::warning() << "INDEX_op_set_label: no terminator in block\n";
      assert(ExitBB);
      IRB.CreateBr(ExitBB);
    }

    llvm::BasicBlock* lblBB = LabelVec[arg_label(op->args[0])->id];
    assert(lblBB);
    IRB.SetInsertPoint(lblBB);
    break;
  }

  case INDEX_op_goto_ptr:
  case INDEX_op_exit_tb:
    if (ExitBB)
      IRB.CreateBr(ExitBB);
    break;

  case INDEX_op_call: {
    nb_oargs = TCGOP_CALLO(op);
    nb_iargs = TCGOP_CALLI(op);
    uintptr_t helper_addr = op->args[nb_oargs + nb_iargs];
    void *helper_ptr = reinterpret_cast<void *>(helper_addr);

    //
    // some helper functions are special-cased
    //
#if defined(__x86_64__) || defined(__i386__)
    if (helper_ptr == helper_raise_exception) {
      assert(!next_op);
      assert(ExitBB);

      IRB.CreateBr(ExitBB);
      break;
    }
#endif

    if (helper_ptr == helper_lookup_tb_ptr)
      break;

    const char *helper_nm = tcg_find_helper(s, helper_addr);
    assert(helper_nm);

    //
    // does the helper function take the CPUState as input?
    //
    auto it = HelperFuncMap.find(helper_ptr);
    if (it == HelperFuncMap.end()) {
      WithColor::note() << "helper " << helper_nm << '\n';

      std::string helperModulePath =
          (boost::dll::program_location().parent_path() /
           (std::string(helper_nm) + ".bc"))
              .string();

      llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> BufferOr =
          llvm::MemoryBuffer::getFile(helperModulePath);
      if (!BufferOr) {
        WithColor::error() << "could not open bitcode for helper_" << helper_nm
                           << " (" << BufferOr.getError().message() << ")\n";
        return 1;
      }

      llvm::MemoryBuffer *Buffer = BufferOr.get().get();
      llvm::Expected<std::unique_ptr<llvm::Module>> helperModuleOr =
          llvm::parseBitcodeFile(Buffer->getMemBufferRef(), *Context);
      if (!helperModuleOr) {
        llvm::logAllUnhandledErrors(helperModuleOr.takeError(), llvm::errs(),
                                    "could not parse helper bitcode: ");
        return 1;
      }

      llvm::Linker::linkModules(*Module, std::move(helperModuleOr.get()));

      llvm::Function *helperF =
          Module->getFunction(std::string("helper_") + helper_nm);

      assert(helperF);
      assert(helperF->arg_size() == nb_iargs);
      assert(nb_oargs == 0 || nb_oargs == 1);

      //
      // analyze helper
      //
      int EnvArgNo = -1;
      {
        TCGTemp *env_temp = &s->temps[tcg_env_index];
        TCGArg *inputs_beg = &op->args[nb_oargs + 0];
        TCGArg *inputs_end = &op->args[nb_oargs + nb_iargs];
        TCGArg *it = std::find(inputs_beg, inputs_end,
                               reinterpret_cast<TCGArg>(env_temp));

        if (it != inputs_end)
          EnvArgNo = std::distance(inputs_beg, it);
      }

      helper_function_t hf;
      hf.F = helperF;
      hf.EnvArgNo = EnvArgNo;

      AnalyzeTCGHelper(hf);

      it = HelperFuncMap.insert({helper_ptr, hf}).first;
    }

    const helper_function_t &hf = (*it).second;

    //
    // build the vector of arguments to pass
    //
    std::vector<llvm::Value *> ArgVec;
    ArgVec.resize(nb_iargs);

    // we'll need this in case a parameter is a pointer type
    llvm::FunctionType *FTy = hf.F->getFunctionType();

    for (int i = 0; i < nb_iargs; ++i) {
      TCGTemp *ts = arg_temp(op->args[nb_oargs + i]);
      unsigned idx = temp_idx(ts);

      auto ArgVal = [&](void) -> llvm::Value * {
        if (idx == tcg_env_index) {
          if (hf.Analysis.Simple)
            return IRB.CreateAlloca(CPUStateType, 0, "env");
          else
            return CPUStateGlobal;
        } else {
          llvm::Value *res = get(ts);

          llvm::Type *ArgTy = FTy->getParamType(i);
          if (ArgTy->isPointerTy())
            res = IRB.CreateIntToPtr(res, ArgTy);

          return res;
        }
      };

      ArgVec[i] = ArgVal();
    }

    //
    // does the helper function take a CPUState* parameter?
    //
    if (hf.EnvArgNo >= 0) {
      llvm::Value *Env = ArgVec[hf.EnvArgNo];

      //
      // store our globals to the local env
      //
      std::vector<unsigned> glbv;
      explode_tcg_global_set(glbv, hf.Analysis.InGlbs);
      for (unsigned glb : glbv) {
        llvm::SmallVector<llvm::Value *, 4> Indices;
        llvm::Value *GlobPtr = llvm::getNaturalGEPWithOffset(
            IRB, DL, Env, llvm::APInt(64, s->temps[glb].mem_offset),
            IRB.getIntNTy(bitsOfTCGType(TCG->_ctx.temps[glb].type)), Indices,
            std::string(s->temps[glb].name) + "_ptr_");
        IRB.CreateStore(get(&s->temps[glb]), GlobPtr);
      }
    }

    llvm::CallInst *Ret = IRB.CreateCall(hf.F, ArgVec);
    if (!hf.Analysis.Simple)
      Ret->setIsNoInline();

    //
    // does the helper function take a CPUState* parameter?
    //
    if (hf.EnvArgNo >= 0) {
      llvm::Value *Env = ArgVec[hf.EnvArgNo];

      //
      // load the altered globals
      //
      std::vector<unsigned> glbv;
      explode_tcg_global_set(glbv, hf.Analysis.OutGlbs);
      for (unsigned glb : glbv) {
        llvm::SmallVector<llvm::Value *, 4> Indices;
        llvm::Value *GlobPtr = llvm::getNaturalGEPWithOffset(
            IRB, DL, Env, llvm::APInt(64, s->temps[glb].mem_offset),
            IRB.getIntNTy(bitsOfTCGType(TCG->_ctx.temps[glb].type)), Indices,
            std::string(s->temps[glb].name) + "_ptr_");
        set(IRB.CreateLoad(GlobPtr), &s->temps[glb]);
      }
    }

    //
    // does the helper have an output?
    //
    if (nb_oargs > 0) {
      assert(nb_oargs == 1);
      set(Ret, arg_temp(op->args[0]));
    }

    break;
  }

  case INDEX_op_movi_i64:
    set(immediate_constant(64, op->args[1]), arg_temp(op->args[0]));
    break;

  case INDEX_op_movi_i32:
    set(immediate_constant(32, op->args[1]), arg_temp(op->args[0]));
    break;

  case INDEX_op_mov_i32: {
    TCGTemp *dst = arg_temp(op->args[0]);
    TCGTemp *src = arg_temp(op->args[1]);

    assert(dst->type == TCG_TYPE_I32);

    llvm::Value *Val = get(src);

    if (src->type == TCG_TYPE_I64)
      Val = IRB.CreateTrunc(Val, IRB.getInt32Ty());
    else
      assert(src->type == TCG_TYPE_I32);

    set(Val, dst);
    break;
  }

  case INDEX_op_mov_i64: {
    TCGTemp *dst = arg_temp(op->args[0]);
    TCGTemp *src = arg_temp(op->args[1]);

    assert(dst->type == TCG_TYPE_I64);
    assert(src->type == TCG_TYPE_I64);

    set(get(src), dst);
    break;
  }

#define __EXT_OP(opc_name, truncBits, opBits, signE)                           \
  case opc_name:                                                               \
    set(IRB.Create##signE##Ext(                                                \
            IRB.CreateTrunc(get(arg_temp(op->args[1])),                        \
                            IRB.getIntNTy(truncBits)),                         \
            IRB.getIntNTy(opBits)),                                            \
        arg_temp(op->args[0]));                                                \
    break;

    __EXT_OP(INDEX_op_ext8s_i32, 8, 32, S)
    __EXT_OP(INDEX_op_ext8u_i32, 8, 32, Z)
    __EXT_OP(INDEX_op_ext16s_i32, 16, 32, S)
    __EXT_OP(INDEX_op_ext16u_i32, 16, 32, Z)

    __EXT_OP(INDEX_op_ext8s_i64, 8, 64, S)
    __EXT_OP(INDEX_op_ext8u_i64, 8, 64, Z)
    __EXT_OP(INDEX_op_ext16s_i64, 16, 64, S)
    __EXT_OP(INDEX_op_ext16u_i64, 16, 64, Z)
    __EXT_OP(INDEX_op_ext32s_i64, 32, 64, S)
    __EXT_OP(INDEX_op_ext32u_i64, 32, 64, Z)

#undef __EXT_OP

#define __OP_QEMU_LD(opc_name, bits)                                           \
  case opc_name: {                                                             \
    TCGMemOpIdx moidx = op->args[nb_oargs + nb_iargs];                         \
    TCGMemOp mop = get_memop(moidx);                                           \
                                                                               \
    llvm::Value *Addr = get(arg_temp(op->args[nb_oargs]));                     \
    Addr = IRB.CreateZExt(Addr, WordType());                                   \
    Addr = IRB.CreateIntToPtr(                                                 \
        Addr, llvm::PointerType::get(IRB.getIntNTy(bits_of_memop(mop)), 0));   \
                                                                               \
    llvm::Value *Val = IRB.CreateLoad(Addr);                                   \
    if (bits > bits_of_memop(mop))                                             \
      Val = mop & MO_SIGN ? IRB.CreateSExt(Val, IRB.getIntNTy(bits))           \
                          : IRB.CreateZExt(Val, IRB.getIntNTy(bits));          \
                                                                               \
    if (nb_oargs == 1) {                                                       \
      set(Val, arg_temp(op->args[0]));                                         \
      break;                                                                   \
    }                                                                          \
                                                                               \
    assert(nb_oargs == 2);                                                     \
    assert(WordBits() == 32);                                                  \
    assert(bits == 64);                                                        \
                                                                               \
    llvm::Value *ValLow = IRB.CreateTrunc(Val, IRB.getInt32Ty());              \
    llvm::Value *ValHigh = IRB.CreateTrunc(                                    \
        IRB.CreateLShr(Val, IRB.getInt64(32)), IRB.getInt32Ty());              \
                                                                               \
    set(ValLow, arg_temp(op->args[0]));                                        \
    set(ValHigh, arg_temp(op->args[1]));                                       \
    break;                                                                     \
  }

    __OP_QEMU_LD(INDEX_op_qemu_ld_i32, 32)
    __OP_QEMU_LD(INDEX_op_qemu_ld_i64, 64)

#undef __OP_QEMU_LD

#define __OP_QEMU_ST(opc_name, bits)                                           \
  case opc_name: {                                                             \
    TCGMemOpIdx moidx = op->args[nb_oargs + nb_iargs];                         \
    TCGMemOp mop = get_memop(moidx);                                           \
                                                                               \
    llvm::Value *Addr = get(arg_temp(op->args[1]));                            \
    Addr = IRB.CreateZExt(Addr, WordType());                                   \
    Addr = IRB.CreateIntToPtr(                                                 \
        Addr, llvm::PointerType::get(IRB.getIntNTy(bits_of_memop(mop)), 0));   \
                                                                               \
    llvm::Value *Val = get(arg_temp(op->args[0]));                             \
    Val = IRB.CreateIntCast(Val, IRB.getIntNTy(bits_of_memop(mop)),            \
                            mop & MO_SIGN ? true : false);                     \
                                                                               \
    IRB.CreateStore(Val, Addr);                                                \
    break;                                                                     \
  }

    __OP_QEMU_ST(INDEX_op_qemu_st_i32, 32)
    __OP_QEMU_ST(INDEX_op_qemu_st_i64, 64)

#undef __OP_QEMU_ST

#define __ARITH_OP(opc_name, LLVMOp, bits)                                     \
  case opc_name: {                                                             \
    llvm::Value *v1 = get(arg_temp(op->args[1]));                              \
    llvm::Value *v2 = get(arg_temp(op->args[2]));                              \
                                                                               \
    set(IRB.Create##LLVMOp(v1, v2), arg_temp(op->args[0]));                    \
  } break;

    __ARITH_OP(INDEX_op_add_i32, Add, 32)
    __ARITH_OP(INDEX_op_sub_i32, Sub, 32)
    __ARITH_OP(INDEX_op_mul_i32, Mul, 32)

    __ARITH_OP(INDEX_op_div_i32, SDiv, 32)
    __ARITH_OP(INDEX_op_divu_i32, UDiv, 32)
    __ARITH_OP(INDEX_op_rem_i32, SRem, 32)
    __ARITH_OP(INDEX_op_remu_i32, URem, 32)

    __ARITH_OP(INDEX_op_and_i32, And, 32)
    __ARITH_OP(INDEX_op_or_i32, Or, 32)
    __ARITH_OP(INDEX_op_xor_i32, Xor, 32)

    __ARITH_OP(INDEX_op_shl_i32, Shl, 32)
    __ARITH_OP(INDEX_op_shr_i32, LShr, 32)
    __ARITH_OP(INDEX_op_sar_i32, AShr, 32)

    __ARITH_OP(INDEX_op_add_i64, Add, 64)
    __ARITH_OP(INDEX_op_sub_i64, Sub, 64)
    __ARITH_OP(INDEX_op_mul_i64, Mul, 64)

    __ARITH_OP(INDEX_op_div_i64, SDiv, 64)
    __ARITH_OP(INDEX_op_divu_i64, UDiv, 64)
    __ARITH_OP(INDEX_op_rem_i64, SRem, 64)
    __ARITH_OP(INDEX_op_remu_i64, URem, 64)

    __ARITH_OP(INDEX_op_and_i64, And, 64)
    __ARITH_OP(INDEX_op_or_i64, Or, 64)
    __ARITH_OP(INDEX_op_xor_i64, Xor, 64)

    __ARITH_OP(INDEX_op_shl_i64, Shl, 64)
    __ARITH_OP(INDEX_op_shr_i64, LShr, 64)
    __ARITH_OP(INDEX_op_sar_i64, AShr, 64)

#undef __ARITH_OP

//
// load from host memory
//
#define __LD_OP(opc_name, memBits, regBits, signE)                             \
  case opc_name: {                                                             \
    unsigned baseidx = temp_idx(arg_temp(op->args[1]));                        \
    assert(baseidx == tcg_env_index);                                          \
                                                                               \
    TCGArg off = op->args[2];                                                  \
                                                                               \
    llvm::SmallVector<llvm::Value *, 4> Indices;                               \
    llvm::Value *Ptr = llvm::getNaturalGEPWithOffset(                          \
        IRB, DL, CPUStateGlobal, llvm::APInt(64, off), IRB.getIntNTy(memBits), \
        Indices, "");                                                          \
    llvm::Value *Val = IRB.CreateLoad(Ptr);                                    \
    if (memBits != regBits)                                                    \
      Val = IRB.Create##signE##Ext(Val, IRB.getIntNTy(regBits));               \
                                                                               \
    set(Val, arg_temp(op->args[0]));                                           \
    break;                                                                     \
  }

    __LD_OP(INDEX_op_ld8u_i32, 8, 32, Z)
    __LD_OP(INDEX_op_ld8s_i32, 8, 32, S)
    __LD_OP(INDEX_op_ld16u_i32, 16, 32, Z)
    __LD_OP(INDEX_op_ld16s_i32, 16, 32, S)
    __LD_OP(INDEX_op_ld_i32, 32, 32, Z)

#undef __LD_OP

//
// store to host memory
//
#define __ST_OP(opc_name, memBits, regBits)                                    \
  case opc_name: {                                                             \
    unsigned baseidx = temp_idx(arg_temp(op->args[1]));                        \
    assert(baseidx == tcg_env_index);                                          \
                                                                               \
    llvm::Value *Val = get(arg_temp(op->args[0]));                             \
                                                                               \
    TCGArg off = op->args[2];                                                  \
    if (off == tcg_program_counter_env_offset) {                               \
      IRB.CreateStore(Val, PCAlloca);                                          \
      break;                                                                   \
    }                                                                          \
                                                                               \
    llvm::SmallVector<llvm::Value *, 4> Indices;                               \
    llvm::Value *Ptr = llvm::getNaturalGEPWithOffset(                          \
        IRB, DL, CPUStateGlobal, llvm::APInt(64, off), IRB.getIntNTy(memBits), \
        Indices, "");                                                          \
    IRB.CreateStore(Val, Ptr);                                                 \
    break;                                                                     \
  }

#if 0
    __ST_OP(INDEX_op_st8_i64, 8, 64)
    __ST_OP(INDEX_op_st16_i64, 16, 64)
    __ST_OP(INDEX_op_st32_i64, 32, 64)
#endif
    __ST_OP(INDEX_op_st_i64, 64, 64)
    __ST_OP(INDEX_op_st_i32, 32, 32)

#undef __ST_OP

#define __OP_BRCOND_COND(tcg_cond, cond)                                       \
  case tcg_cond:                                                               \
    V = IRB.CreateICmp##cond(get(arg_temp(op->args[0])),                       \
                             get(arg_temp(op->args[1])));                      \
    break;

#define __OP_BRCOND(opc_name, bits)                                            \
  case opc_name: {                                                             \
    llvm::Value *V;                                                            \
    switch (op->args[2]) {                                                     \
      __OP_BRCOND_COND(TCG_COND_EQ, EQ)                                        \
      __OP_BRCOND_COND(TCG_COND_NE, NE)                                        \
      __OP_BRCOND_COND(TCG_COND_LT, SLT)                                       \
      __OP_BRCOND_COND(TCG_COND_GE, SGE)                                       \
      __OP_BRCOND_COND(TCG_COND_LE, SLE)                                       \
      __OP_BRCOND_COND(TCG_COND_GT, SGT)                                       \
      __OP_BRCOND_COND(TCG_COND_LTU, ULT)                                      \
      __OP_BRCOND_COND(TCG_COND_GEU, UGE)                                      \
      __OP_BRCOND_COND(TCG_COND_LEU, ULE)                                      \
      __OP_BRCOND_COND(TCG_COND_GTU, UGT)                                      \
    default:                                                                   \
      abort();                                                                 \
    }                                                                          \
    unsigned lblidx = arg_label(op->args[3])->id;                              \
    llvm::BasicBlock *&lblBB = LabelVec.at(lblidx);                            \
    if (!lblBB)                                                                \
      lblBB = llvm::BasicBlock::Create(                                        \
          *Context,                                                            \
          (boost::format("%#lx_L%u") % ICFG[bb].Addr % lblidx).str(), f.F);    \
    llvm::BasicBlock *fallthruBB = llvm::BasicBlock::Create(                   \
        *Context, (boost::format("%#lx_fallthru") % ICFG[bb].Addr).str(),      \
        f.F);                                                                  \
    IRB.CreateCondBr(V, lblBB, fallthruBB);                                    \
    IRB.SetInsertPoint(fallthruBB);                                            \
  } break;

    __OP_BRCOND(INDEX_op_brcond_i32, 32)
    __OP_BRCOND(INDEX_op_brcond_i64, 64)

#undef __OP_BRCOND_COND
#undef __OP_BRCOND

#define __OP_SETCOND_COND(tcg_cond, cond)                                      \
  case tcg_cond:                                                               \
    Val = IRB.CreateICmp##cond(get(arg_temp(op->args[1])),                     \
                               get(arg_temp(op->args[2])));                    \
    break;

#define __OP_SETCOND(opc_name, bits)                                           \
  case opc_name: {                                                             \
    llvm::Value *Val;                                                          \
    switch (op->args[3]) {                                                     \
      __OP_SETCOND_COND(TCG_COND_EQ, EQ)                                       \
      __OP_SETCOND_COND(TCG_COND_NE, NE)                                       \
      __OP_SETCOND_COND(TCG_COND_LT, SLT)                                      \
      __OP_SETCOND_COND(TCG_COND_GE, SGE)                                      \
      __OP_SETCOND_COND(TCG_COND_LE, SLE)                                      \
      __OP_SETCOND_COND(TCG_COND_GT, SGT)                                      \
      __OP_SETCOND_COND(TCG_COND_LTU, ULT)                                     \
      __OP_SETCOND_COND(TCG_COND_GEU, UGE)                                     \
      __OP_SETCOND_COND(TCG_COND_LEU, ULE)                                     \
      __OP_SETCOND_COND(TCG_COND_GTU, UGT)                                     \
    default:                                                                   \
      assert(false);                                                           \
    }                                                                          \
    set(IRB.CreateZExt(Val, IRB.getIntNTy(bits)), arg_temp(op->args[0]));      \
  } break;

    __OP_SETCOND(INDEX_op_setcond_i32, 32)
    __OP_SETCOND(INDEX_op_setcond_i64, 64)

#undef __OP_SETCOND_COND
#undef __OP_SETCOND

#define __ARITH_OP_MUL2(opc_name, signE, bits)                                 \
  case opc_name: {                                                             \
    llvm::Value *t1 = get(arg_temp(op->args[2]));                              \
    llvm::Value *t2 = get(arg_temp(op->args[3]));                              \
                                                                               \
    assert(t1->getType() == IRB.getIntNTy(bits));                              \
    assert(t2->getType() == IRB.getIntNTy(bits));                              \
                                                                               \
    llvm::Value *t0 =                                                          \
        IRB.CreateMul(IRB.Create##signE##Ext(t1, IRB.getIntNTy(bits * 2)),     \
                      IRB.Create##signE##Ext(t2, IRB.getIntNTy(bits * 2)));    \
                                                                               \
    llvm::Value *t0_low = IRB.CreateTrunc(t0, IRB.getIntNTy(bits));            \
    llvm::Value *t0_high = IRB.CreateTrunc(                                    \
        IRB.CreateLShr(t0, IRB.getIntN(bits * 2, bits)), IRB.getIntNTy(bits)); \
                                                                               \
    set(t0_low, arg_temp(op->args[0]));                                        \
    set(t0_high, arg_temp(op->args[1]));                                       \
  } break;

    __ARITH_OP_MUL2(INDEX_op_mulu2_i32, Z, 32)
    __ARITH_OP_MUL2(INDEX_op_muls2_i32, S, 32)
    __ARITH_OP_MUL2(INDEX_op_mulu2_i64, Z, 64)
    __ARITH_OP_MUL2(INDEX_op_muls2_i64, S, 64)

#undef __ARITH_OP_MUL2

#define __ARITH_OP_I(opc_name, LLVMOp, i, bits)                                \
  case opc_name: {                                                             \
    llvm::Value *v1 = get(arg_temp(op->args[1]));                              \
    assert(v1->getType() == IRB.getIntNTy(bits));                              \
    set(IRB.Create##LLVMOp(IRB.getIntN(bits, i), v1), arg_temp(op->args[0]));  \
  } break;

    __ARITH_OP_I(INDEX_op_not_i32, Xor, 0xffffffff, 32)
    __ARITH_OP_I(INDEX_op_neg_i32, Sub, 0, 32)

    __ARITH_OP_I(INDEX_op_not_i64, Xor, 0xffffffffffffffff, 64)
    __ARITH_OP_I(INDEX_op_neg_i64, Sub, 0, 64)

#undef __ARITH_OP_I

  case INDEX_op_deposit_i64: {
    TCGTemp *dst = arg_temp(op->args[0]);
    TCGTemp *src1 = arg_temp(op->args[1]);
    TCGTemp *src2 = arg_temp(op->args[2]);

    llvm::Value *arg1 = get(src1);
    llvm::Value *arg2 = get(src2);
    arg2 = IRB.CreateTrunc(arg2, IRB.getInt64Ty());

    uint32_t ofs = op->args[3];
    uint32_t len = op->args[4];

    if (0 == ofs && 64 == len) {
      set(arg2, dst);
      break;
    }

    uint64_t mask = (1u << len) - 1;
    llvm::Value *t1, *ret;

    if (ofs + len < 64) {
      t1 = IRB.CreateAnd(arg2, llvm::APInt(64, mask));
      t1 = IRB.CreateShl(t1, llvm::APInt(64, ofs));
    } else {
      t1 = IRB.CreateShl(arg2, llvm::APInt(64, ofs));
    }

    ret = IRB.CreateAnd(arg1, llvm::APInt(64, ~(mask << ofs)));
    ret = IRB.CreateOr(ret, t1);
    set(ret, dst);
    break;
  }

  case INDEX_op_muluh_i64: {
    TCGTemp *dst = arg_temp(op->args[0]);
    TCGTemp *src1 = arg_temp(op->args[1]);
    TCGTemp *src2 = arg_temp(op->args[2]);

    assert(dst->type == TCG_TYPE_I64);
    assert(src1->type == TCG_TYPE_I64);
    assert(src2->type == TCG_TYPE_I64);

    llvm::Value *x =
        IRB.CreateMul(IRB.CreateZExt(get(src1), IRB.getInt128Ty()),
                      IRB.CreateZExt(get(src2), IRB.getInt128Ty()));

    llvm::Value *y = IRB.CreateTrunc(IRB.CreateLShr(x, IRB.getIntN(128, 64)),
                                     IRB.getInt64Ty());

    set(y, dst);
    break;
  }

  default:
    WithColor::error() << "unhandled TCG instruction (" << def.name << ")\n";
    TCG->dump_operations();
    llvm::errs() << *f.F << '\n';
    return 1;
  }

  return 0;
}

}
