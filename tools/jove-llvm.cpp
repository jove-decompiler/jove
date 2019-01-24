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
    struct {                                                                   \
      /* let def_B be the set of variables defined (i.e. definitely */         \
      /* assigned values) in B prior to any use of that variable in B */       \
      tcg_global_set_t def;                                                    \
                                                                               \
      /* let use_B be the set of variables whose values may be used in B */    \
      /* prior to any definition of the variable */                            \
      tcg_global_set_t use;                                                    \
    } live;                                                                    \
                                                                               \
    struct {                                                                   \
      /* the set of globals assigned values in B */                            \
      tcg_global_set_t def;                                                    \
    } reach;                                                                   \
  } Analysis;                                                                  \
                                                                               \
  tcg_global_set_t IN, OUT;                                                    \
                                                                               \
  bool Analyzed;                                                               \
                                                                               \
  basic_block_properties_t() : Analyzed(false) {}                              \
                                                                               \
  void Analyze(binary_index_t);                                                \
                                                                               \
  llvm::BasicBlock *B;

#define JOVE_EXTRA_FN_PROPERTIES                                               \
  binary_index_t BIdx;                                                         \
  function_index_t FIdx;                                                       \
  std::vector<basic_block_t> BasicBlocks;                                      \
  std::set<basic_block_t> BasicBlocksSet;                                      \
  std::vector<basic_block_t> ExitBasicBlocks;                                  \
  std::array<llvm::AllocaInst *, tcg_num_globals> GlobalAllocaVec;             \
  llvm::AllocaInst *PCAlloca;                                                  \
  llvm::LoadInst *PCRelVal;                                                    \
  llvm::LoadInst *FSBaseVal;                                                   \
                                                                               \
  bool IsThunk, IsABI;                                                         \
                                                                               \
  struct {                                                                     \
    tcg_global_set_t args, rets;                                               \
  } Analysis;                                                                  \
                                                                               \
  bool Analyzed;                                                               \
                                                                               \
  function_t() : IsThunk(false), IsABI(false), Analyzed(false) {}              \
                                                                               \
  void Analyze(void);                                                          \
                                                                               \
  llvm::Function *F;

#include "tcgcommon.hpp"

#include <tuple>
#include <memory>
#include <sstream>
#include <fstream>
#include <boost/filesystem.hpp>
#include <boost/graph/graphviz.hpp>
#include <llvm/Analysis/TargetTransformInfo.h>
#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/GlobalIFunc.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/MDBuilder.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/InitializePasses.h>
#include <llvm/LinkAllPasses.h>
#include <llvm/Linker/Linker.h>
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
#include <llvm/Support/DataTypes.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/Host.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/ScopedPrinter.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/ToolOutputFile.h>
#include <llvm/Support/WithColor.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Target/TargetOptions.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "jove/jove.h"
#include <boost/algorithm/string/replace.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/dll/runtime_symbol_info.hpp>
#include <boost/dynamic_bitset.hpp>
#include <boost/format.hpp>
#include <boost/graph/adj_list_serialize.hpp>
#include <boost/graph/copy.hpp>
#include <boost/graph/depth_first_search.hpp>
#include <boost/graph/filtered_graph.hpp>
#include <boost/icl/interval_set.hpp>
#include <boost/icl/split_interval_map.hpp>
#include <boost/range/adaptor/reversed.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>

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

  static cl::opt<bool> NoFixupFSBase("no-fixup-fsbase",
    cl::desc("Don't fixup FS-relative references"));

  static cl::opt<bool> PrintPCRel("pcrel",
    cl::desc("Print pc-relative references"));

  static cl::opt<bool> Emu("emu",
    cl::desc("Code operates on TLS globals which represent the CPU state"));

  static cl::opt<bool> NoInline("noinline",
    cl::desc("Prevents inlining internal functions"));

  static cl::opt<bool> PrintDefAndUse("print-def-and-use",
    cl::desc("Print use_B and def_B for every basic block B"));

  static cl::opt<bool> PrintLiveness("print-liveness",
    cl::desc("Print liveness for every function"));

  static cl::opt<bool> PrintFunctionSignatures("print-function-types",
    cl::desc("Print type of every function"));

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

  static cl::opt<bool> Graphviz("graphviz",
    cl::desc("Dump graphviz of flow graphs"));
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
    // similar to RELATIVE except that the value used in this relocation is the
    // program address returned by the so-called resolver function
    //
    IRELATIVE,

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
    ADDRESSOF,

    TPOFF
  } Type;

  uintptr_t Addr;
  unsigned SymbolIndex;
  uintptr_t Addend;
};

typedef boost::keep_all edge_predicate_t;
typedef boost::is_in_subset<std::set<basic_block_t>> vertex_predicate_t;
typedef boost::filtered_graph<interprocedural_control_flow_graph_t,
                              edge_predicate_t, vertex_predicate_t>
    control_flow_graph_t;

//
// Globals
//
static decompilation_t Decompilation;
static binary_index_t BinaryIndex = invalid_binary_index;

static std::vector<binary_state_t> BinStateVec;

static std::unordered_map<std::string,
                          std::set<std::pair<binary_index_t, function_index_t>>>
    ExportedFunctions;

static std::set<std::pair<binary_index_t, function_index_t>>
    BinaryDynamicTargets;

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
static std::unique_ptr<llvm::TargetMachine> TM;

static std::unique_ptr<tiny_code_generator_t> TCG;

static std::unique_ptr<llvm::LLVMContext> Context;
static std::unique_ptr<llvm::Module> Module;

static llvm::DataLayout DL("");

static std::vector<symbol_t> SymbolTable;
static std::vector<relocation_t> RelocationTable;
static std::unordered_set<uintptr_t> RelocationsAt;

static llvm::GlobalVariable *CPUStateGlobal;
static llvm::Type *CPUStateType;

static llvm::GlobalVariable *SectsGlobal;
static llvm::GlobalVariable *ConstSectsGlobal;
static uintptr_t SectsStartAddr, SectsEndAddr;

static llvm::GlobalVariable *PCRelGlobal;

#if defined(__x86_64__)
static llvm::GlobalVariable *FSBaseGlobal;
#endif

static llvm::MDNode *AliasScopeMetadata;

struct helper_function_t {
  llvm::Function *F;
  int EnvArgNo;

  struct {
    bool Simple;
    tcg_global_set_t InGlbs, OutGlbs;
  } Analysis;
};
static std::unordered_map<uintptr_t, helper_function_t> HelperFuncMap;
static std::unordered_map<std::string, unsigned> GlobalSymbolDefinedSizeMap;

static std::unordered_map<uintptr_t, std::string> TLSValueToSymbolMap;

//
// Stages
//
static int ParseDecompilation(void);
static int FindBinary(void);
static int InitStateForBinaries(void);
static int CreateModule(void);
static int ProcessSymbols(void);
static int ProcessDynamicTargets(void);
static int ProcessBinarySymbolsAndRelocations(void);
static int ProcessIFuncResolvers(void);
static int PrepareToTranslateCode(void);
static int CreateFunctions(void);
static int CreateSectionGlobalVariables(void);
static int CreateCPUStateGlobal(void);
static int CreatePCRelGlobal(void);
#if defined(__x86_64__)
static int CreateFSBaseGlobal(void);
#endif
static int FixupHelperStubs(void);
static int IdentifyThunks(void);
static int CreateNoAliasMetadata(void);
static int TranslateFunctions(void);
static int PrepareToOptimize(void);
static int Optimize1(void);
static int FixupPCRelativeAddrs(void);
#if defined(__x86_64__)
static int FixupFSBaseAddrs(void);
#endif
static int InternalizeStaticFunctions(void);
static int InternalizeSections(void);
static int Optimize2(void);
static int ReplaceAllRemainingUsesOfConstSections(void);
static int ReplaceAllRemainingUsesOfPCRel(void);
static int RenameFunctionLocals(void);
static int RenameFunctions(void);
static int WriteModule(void);

int llvm(void) {
  return ParseDecompilation()
      || FindBinary()
      || InitStateForBinaries()
      || CreateModule()
      || ProcessSymbols()
      || ProcessDynamicTargets()
      || ProcessBinarySymbolsAndRelocations()
      || ProcessIFuncResolvers()
      || PrepareToTranslateCode()
      || CreateFunctions()
      || CreateSectionGlobalVariables()
      || CreateCPUStateGlobal()
      || CreatePCRelGlobal()
#if defined(__x86_64__)
      || CreateFSBaseGlobal()
#endif
      || FixupHelperStubs()
      || IdentifyThunks()
      || CreateNoAliasMetadata()
      || TranslateFunctions()
      || PrepareToOptimize()
      || Optimize1()
      || FixupPCRelativeAddrs()
#if defined(__x86_64__)
      || FixupFSBaseAddrs()
#endif
      || InternalizeStaticFunctions()
      || InternalizeSections()
      || Optimize2()
      || ReplaceAllRemainingUsesOfConstSections()
      || ReplaceAllRemainingUsesOfPCRel()
      || RenameFunctionLocals()
      || RenameFunctions()
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
      if (binary.IsDynamicLinker) {
        WithColor::error() << "given binary is dynamic linker\n";
        return 1;
      }

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

template <typename GraphTy>
struct dfs_visitor : public boost::default_dfs_visitor {
  typedef typename GraphTy::vertex_descriptor VertTy;

  std::vector<VertTy> &out;

  dfs_visitor(std::vector<VertTy> &out) : out(out) {}

  void discover_vertex(VertTy v, const GraphTy &) const { out.push_back(v); }
};

int InitStateForBinaries(void) {
  BinStateVec.resize(Decompilation.Binaries.size());

  for (binary_index_t BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx) {
    auto &Binary = Decompilation.Binaries[BIdx];
    auto &ICFG = Binary.Analysis.ICFG;
    auto &st = BinStateVec[BIdx];

    //
    // FuncMap
    //
    for (function_index_t FIdx = 0; FIdx < Binary.Analysis.Functions.size();
         ++FIdx) {
      function_t &f = Binary.Analysis.Functions[FIdx];
      f.BIdx = BIdx;
      f.FIdx = FIdx;

      st.FuncMap[ICFG[boost::vertex(f.Entry, ICFG)].Addr] = FIdx;

      //
      // BasicBlocks (in DFS order)
      //
      std::map<basic_block_t, boost::default_color_type> color;
      dfs_visitor<interprocedural_control_flow_graph_t> vis(f.BasicBlocks);
      depth_first_visit(
          ICFG, boost::vertex(f.Entry, ICFG), vis,
          boost::associative_property_map<
              std::map<basic_block_t, boost::default_color_type>>(color));

      //
      // BasicBlocksSet
      //
      std::copy(f.BasicBlocks.begin(),
                f.BasicBlocks.end(),
                std::inserter(f.BasicBlocksSet, f.BasicBlocksSet.end()));

      //
      // ExitBasicBlocks
      //
      std::copy_if(f.BasicBlocks.begin(),
                   f.BasicBlocks.end(),
                   std::back_inserter(f.ExitBasicBlocks),
                   [&](basic_block_t bb) -> bool {
                     return boost::out_degree(bb, ICFG) == 0 &&
                            ICFG[bb].Term.Type != TERMINATOR::UNREACHABLE;
                   });
    }

    //
    // BBMap
    //
    for (basic_block_index_t BBIdx = 0; BBIdx < boost::num_vertices(ICFG);
         ++BBIdx) {
      basic_block_t bb = boost::vertex(BBIdx, ICFG);

      st.BBMap[ICFG[bb].Addr] = BBIdx;
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

    if (BIdx == BinaryIndex) {
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

int ProcessSymbols(void) {
  for (binary_index_t BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx) {
    auto &Binary = Decompilation.Binaries[BIdx];
    auto &st = BinStateVec[BIdx];

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

      llvm::StringRef SymName = unwrapOrError(Sym.getName(DynamicStringTable));

      if (Sym.getType() == llvm::ELF::STT_OBJECT ||
          Sym.getType() == llvm::ELF::STT_TLS) {
        if (!Sym.st_size) {
          WithColor::warning()
              << "symbol '" << SymName << "' defined but size is unknown\n";
          continue;
        }

        auto it = GlobalSymbolDefinedSizeMap.find(SymName);
        if (it != GlobalSymbolDefinedSizeMap.end()) {
          WithColor::warning()
              << "data symbol \"" << SymName << "\" has multiple definitions ("
              << (*it).second << ", " << Sym.st_size << ")\n";
        }

        GlobalSymbolDefinedSizeMap[SymName] = Sym.st_size;

        if (BIdx == BinaryIndex) {
          //
          // if this symbol is TLS, update the TLSValueToSymbolMap
          //
          if (Sym.getType() == llvm::ELF::STT_TLS) {
            auto it = TLSValueToSymbolMap.find(Sym.st_value);
            if (it != TLSValueToSymbolMap.end()) {
              WithColor::warning()
                  << "multiple TLS symbols at "
                  << (fmt("%#lx") % Sym.st_value).str() << " : " << SymName
                  << ", " << (*it).second << "\n";
            } else {
              TLSValueToSymbolMap.insert({Sym.st_value, SymName});
            }
          }

          //
          // create the global variable if it does not already exist
          //
          llvm::GlobalVariable *GV = Module->getGlobalVariable(SymName, true);
          if (GV)
            continue;

          auto is_integral_size = [](unsigned n) -> bool {
            switch (n) {
            case 1:
              return true;
            case 2:
              return true;
            case 4:
              return true;
            case 8:
              return true;
            default:
              return false;
            }
          };

          llvm::Type *T;
          llvm::Constant *Init;

          if (is_integral_size(Sym.st_size)) {
            T = llvm::Type::getIntNTy(*Context, Sym.st_size * 8);
          } else {
            T = llvm::ArrayType::get(llvm::Type::getInt8Ty(*Context),
                                     Sym.st_size);
          }

          GV = new llvm::GlobalVariable(
              *Module, T, false, llvm::GlobalValue::ExternalLinkage,
              llvm::Constant::getNullValue(T), SymName, nullptr,
              Sym.getType() == llvm::ELF::STT_TLS
                  ? llvm::GlobalValue::GeneralDynamicTLSModel
                  : llvm::GlobalValue::NotThreadLocal);
        }
      } else if (Sym.getType() == llvm::ELF::STT_FUNC) {
        function_index_t FuncIdx;
        {
          auto it = st.FuncMap.find(Sym.st_value);
          if (it == st.FuncMap.end()) {
            WithColor::warning()
                << "no function for symbol " << SymName << " found\n";
            continue;
          }

          FuncIdx = (*it).second;
        }

        Binary.Analysis.Functions[FuncIdx].IsABI = true;

        if (!ExportedFunctions[SymName].empty())
          WithColor::note() << ' ' << SymName << '\n';

        ExportedFunctions[SymName].insert({BIdx, FuncIdx});
      }
    }

    if (BIdx != BinaryIndex)
      continue;

    llvm::StringRef StrTable;
    const Elf_Shdr *DotSymtabSec = nullptr;
    auto symbols = [&](void) -> Elf_Sym_Range {
      return unwrapOrError(E.symbols(DotSymtabSec));
    };

    for (const Elf_Shdr &Sec : unwrapOrError(E.sections())) {
      if (Sec.sh_type == llvm::ELF::SHT_SYMTAB) {
        assert(!DotSymtabSec);
        DotSymtabSec = &Sec;
      }
    }

    if (!DotSymtabSec)
      continue;

    StrTable = unwrapOrError(E.getStringTableForSymtab(*DotSymtabSec));

    for (const Elf_Sym &Sym : symbols()) {
      if (Sym.getType() != llvm::ELF::STT_TLS)
        continue;

      llvm::StringRef SymName = unwrapOrError(Sym.getName(StrTable));

      auto it = TLSValueToSymbolMap.find(Sym.st_value);
      if (it != TLSValueToSymbolMap.end()) {
        WithColor::warning()
            << "multiple TLS symbols at " << (fmt("%#lx") % Sym.st_value).str()
            << " : " << SymName << ", " << (*it).second << "\n";
      } else {
        TLSValueToSymbolMap.insert({Sym.st_value, SymName});
      }

      llvm::GlobalVariable *GV = Module->getGlobalVariable(SymName, true);
      if (GV)
        continue;

      auto is_integral_size = [](unsigned n) -> bool {
        switch (n) {
        case 1:
          return true;
        case 2:
          return true;
        case 4:
          return true;
        case 8:
          return true;
        default:
          return false;
        }
      };

      llvm::Type *T;
      llvm::Constant *Init;

      if (is_integral_size(Sym.st_size)) {
        T = llvm::Type::getIntNTy(*Context, Sym.st_size * 8);
      } else {
        T = llvm::ArrayType::get(llvm::Type::getInt8Ty(*Context), Sym.st_size);
      }

      new llvm::GlobalVariable(
          *Module, T, false, llvm::GlobalValue::InternalLinkage,
          llvm::Constant::getNullValue(T), SymName, nullptr,
          llvm::GlobalValue::GeneralDynamicTLSModel);
    }
  }

  for (const auto &entry : TLSValueToSymbolMap) {
    llvm::outs() << "TLS symbol " << entry.second << " @ +" << entry.first
                 << '\n';
  }

  return 0;
}

int ProcessDynamicTargets(void) {
  //
  // Note that every function which is seen to be the target of an indirect
  // branch must conform to the system ABI calling convention
  //
  for (binary_index_t BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx) {
    auto &Binary = Decompilation.Binaries[BIdx];
    auto &ICFG = Binary.Analysis.ICFG;

    for (basic_block_index_t BBIdx = 0; BBIdx < boost::num_vertices(ICFG);
         ++BBIdx) {
      basic_block_t bb = boost::vertex(BBIdx, ICFG);

      for (const auto &dyn_targ : ICFG[bb].DynTargets) {
        function_t &callee = Decompilation.Binaries[dyn_targ.first]
                                 .Analysis.Functions[dyn_targ.second];

        callee.IsABI = true;
      }
    }
  }

  //
  // for the binary under consideration, we'll build a set of dynamic
  // targets that can be used for the purposes of dynamic symbol resolution
  //
  auto &Binary = Decompilation.Binaries[BinaryIndex];
  auto &ICFG = Binary.Analysis.ICFG;

  auto it_pair = boost::vertices(ICFG);
  for (auto it = it_pair.first; it != it_pair.second; ++it) {
    auto &DynTargets = ICFG[*it].DynTargets;
    BinaryDynamicTargets.insert(DynTargets.begin(), DynTargets.end());
  }

  //
  // dynamic ifunc resolver targets are ABIs
  //
  for (binary_index_t BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx) {
    auto &IFuncRelocDynTargets =
        Decompilation.Binaries[BIdx].Analysis.IFuncRelocDynTargets;
    for (const auto &pair : IFuncRelocDynTargets)
      for (function_index_t FIdx : pair.second)
        Decompilation.Binaries[BIdx].Analysis.Functions[FIdx].IsABI = true;
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
    case relocation_t::TYPE::IRELATIVE:
      return "IRELATIVE";
    case relocation_t::TYPE::ABSOLUTE:
      return "ABSOLUTE";
    case relocation_t::TYPE::COPY:
      return "COPY";
    case relocation_t::TYPE::ADDRESSOF:
      return "ADDRESSOF";
    case relocation_t::TYPE::TPOFF:
      return "TPOFF";
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

int ProcessIFuncResolvers(void) {
  auto &Binary = Decompilation.Binaries[BinaryIndex];
  auto &FuncMap = BinStateVec[BinaryIndex].FuncMap;

  for (const relocation_t &R : RelocationTable) {
    if (R.Type != relocation_t::TYPE::IRELATIVE)
      continue;

    auto it = FuncMap.find(R.Addend);
    assert(it != FuncMap.end());

    function_t &resolver = Binary.Analysis.Functions[(*it).second];
    resolver.IsABI = true;
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

  std::string CPUStr;

  STI.reset(
      TheTarget->createMCSubtargetInfo(TripleName, CPUStr, Features.getString()));
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

  llvm::TargetOptions Options;

  std::string FeaturesStr;
  TM.reset(TheTarget->createTargetMachine(TheTriple.getTriple(), CPUStr,
                                          Features.getString(), Options,
                                          llvm::None));

  return 0;
}

static void AnalyzeTCGHelper(helper_function_t &hf);

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

template <typename Graph>
struct graphviz_label_writer {
  const Graph &G;

  graphviz_label_writer(const Graph &G) : G(G) {}

  template <typename Vertex>
  void operator()(std::ostream &out, Vertex V) const {
    std::string str;

    str += (fmt("%#lx") % G[V].Addr).str();

    str.push_back('\n');
    str.push_back('[');
    {
      std::vector<unsigned> glbv;
      explode_tcg_global_set(glbv, G[V].IN);
      bool first = true;
      for (unsigned glb : glbv) {
        if (!first)
          str.push_back(' ');

        str += TCG->_ctx.temps[glb].name;

        first = false;
      }
    }
    str.push_back(']');

    str.push_back('\n');

    str.push_back('[');
    {
      std::vector<unsigned> glbv;
      explode_tcg_global_set(glbv, G[V].OUT);
      bool first = true;
      for (unsigned glb : glbv) {
        if (!first)
          str.push_back(' ');

        str += TCG->_ctx.temps[glb].name;

        first = false;
      }
    }
    str.push_back(']');

    boost::replace_all(str, "\\", "\\\\");
    boost::replace_all(str, "\r\n", "\\l");
    boost::replace_all(str, "\n", "\\l");
    boost::replace_all(str, "\"", "\\\"");
    boost::replace_all(str, "{", "\\{");
    boost::replace_all(str, "}", "\\}");
    boost::replace_all(str, "|", "\\|");
    boost::replace_all(str, "|", "\\|");
    boost::replace_all(str, "<", "\\<");
    boost::replace_all(str, ">", "\\>");
    boost::replace_all(str, "(", "\\(");
    boost::replace_all(str, ")", "\\)");
    boost::replace_all(str, ",", "\\,");
    boost::replace_all(str, ";", "\\;");
    boost::replace_all(str, ":", "\\:");
    boost::replace_all(str, " ", "\\ ");

    out << "[shape=box label=\"";
    out << str;
    out << "\"]";
  }
};

void function_t::Analyze(void) {
  if (this->Analyzed)
    return;

  this->Analyzed = true;

  //
  // using boost::filtered_graph we can efficiently construct a
  // control-flow-graph for the current function
  //
  auto &ICFG = Decompilation.Binaries[this->BIdx].Analysis.ICFG;

  edge_predicate_t EdgePred;
  vertex_predicate_t VertPred(this->BasicBlocksSet);

  control_flow_graph_t CFG(ICFG, EdgePred, VertPred);

  //
  // analyze basic blocks
  //
  for (basic_block_t bb : this->BasicBlocks)
    CFG[bb].Analyze(this->BIdx);

  //
  // data-flow analysis
  //
  bool change;

  //
  // liveness
  //
  for (basic_block_t bb : this->BasicBlocks) {
    CFG[bb].IN.reset();
    CFG[bb].OUT.reset();
  }

  do {
    change = false;

    for (basic_block_t bb : boost::adaptors::reverse(this->BasicBlocks)) {
      const tcg_global_set_t _IN = CFG[bb].IN;

      auto eit_pair = boost::out_edges(bb, CFG);
      CFG[bb].OUT = std::accumulate(
          eit_pair.first, eit_pair.second, tcg_global_set_t(),
          [&](tcg_global_set_t glbs, control_flow_t E) {
            return glbs | CFG[boost::target(E, CFG)].IN;
          });
      CFG[bb].IN = CFG[bb].Analysis.live.use |
                    (CFG[bb].OUT & ~(CFG[bb].Analysis.live.def));

      change = change || _IN != CFG[bb].IN;
    }
  } while (change);

  if (opts::Graphviz) {
    std::ofstream ofs(
        (fmt("/tmp/%#lx.live.dot") % CFG[this->BasicBlocks.front()].Addr)
            .str());

    graphviz_label_writer<control_flow_graph_t> vertPropWriter(CFG);
    boost::write_graphviz(ofs, CFG, vertPropWriter);
  }

  this->Analysis.args = CFG[this->BasicBlocks.front()].IN;
  this->Analysis.args.reset(tcg_env_index);
#if defined(__x86_64__)
  this->Analysis.args.reset(tcg_fs_base_index);
#endif

  //
  // for ABI's, if we need a register parameter whose index > 0, then we will
  // infer that all the preceeding paramter registers are live as well
  //
  if (this->IsABI) {
    this->Analysis.args &= CallConvArgs;

    std::vector<unsigned> glbv;
    explode_tcg_global_set(glbv, this->Analysis.args);
    std::sort(glbv.begin(), glbv.end(), [](unsigned a, unsigned b) {
      return std::find(CallConvArgArray.begin(), CallConvArgArray.end(), a) <
             std::find(CallConvArgArray.begin(), CallConvArgArray.end(), b);
    });

    auto rit = std::accumulate(
        glbv.begin(), glbv.end(), CallConvArgArray.crend(),
        [](CallConvArgArrayTy::const_reverse_iterator res, unsigned glb) {
          return std::min(res, std::find(CallConvArgArray.crbegin(),
                                         CallConvArgArray.crend(), glb));
        });

    if (rit != CallConvArgArray.crend()) {
      unsigned idx = std::distance(CallConvArgArray.cbegin(), rit.base()) - 1;
      for (unsigned i = 0; i <= idx; ++i)
        this->Analysis.args.set(CallConvArgArray[i]);
    }
  } else {
#if 0
    if (opts::Emu)
      if (!this->IsSimple)
        this->Analysis.args.reset();
#endif
  }

  //
  // reaching definitions
  //
  for (basic_block_t bb : this->BasicBlocks) {
    CFG[bb].IN.reset();
    CFG[bb].OUT.reset();
  }

  do {
    change = false;

    for (basic_block_t bb : this->BasicBlocks) {
      const tcg_global_set_t _OUT = CFG[bb].OUT;

      auto eit_pair = boost::in_edges(bb, CFG);
      CFG[bb].IN = std::accumulate(
          eit_pair.first, eit_pair.second, tcg_global_set_t(),
          [&](tcg_global_set_t glbs, control_flow_t E) {
            return glbs | CFG[boost::source(E, CFG)].OUT;
          });
      CFG[bb].OUT = CFG[bb].Analysis.reach.def | CFG[bb].IN;

      change = change || _OUT != CFG[bb].OUT;
    }
  } while (change);

  if (opts::Graphviz) {
    std::ofstream ofs(
        (fmt("/tmp/%#lx.reach.dot") % CFG[this->BasicBlocks.front()].Addr)
            .str());

    graphviz_label_writer<control_flow_graph_t> vertPropWriter(CFG);

    boost::write_graphviz(ofs, CFG, vertPropWriter);
  }

#if 1
  if (this->ExitBasicBlocks.empty()) {
    this->Analysis.rets.reset();
  } else {
    this->Analysis.rets = std::accumulate(
        std::next(this->ExitBasicBlocks.begin()), this->ExitBasicBlocks.end(),
        CFG[this->ExitBasicBlocks.front()].OUT,
        [&](tcg_global_set_t res, basic_block_t bb) {
          return res & CFG[bb].OUT;
        });
  }
#else
  this->Analysis.rets = std::accumulate(
      this->ExitBasicBlocks.begin(), this->ExitBasicBlocks.end(),
      tcg_global_set_t(), [&](tcg_global_set_t res, basic_block_t bb) {
        return res | CFG[bb].OUT;
      });
#endif

#if defined(__x86_64__)
  this->Analysis.rets.reset(tcg_fs_base_index);
#endif

  if (this->IsABI) {
#if 0
    this->Analysis.rets &= CallConvRets;

    //
    // for ABI's, if we need a return register whose index > 0, then we will
    // infer that all the preceeding return registers are live as well
    //
    std::vector<unsigned> glbv;
    explode_tcg_global_set(glbv, this->Analysis.rets);
    std::sort(glbv.begin(), glbv.end(), [](unsigned a, unsigned b) {
      return std::find(CallConvRetArray.begin(), CallConvRetArray.end(), a) <
             std::find(CallConvRetArray.begin(), CallConvRetArray.end(), b);
    });

    auto rit = std::accumulate(
        glbv.begin(), glbv.end(), CallConvRetArray.crend(),
        [](CallConvArgArrayTy::const_reverse_iterator res, unsigned glb) {
          return std::min(res, std::find(CallConvRetArray.crbegin(),
                                         CallConvRetArray.crend(), glb));
        });

    if (rit != CallConvRetArray.crend()) {
      unsigned idx = std::distance(CallConvRetArray.cbegin(), rit.base()) - 1;
      for (unsigned i = 0; i <= idx; ++i)
        this->Analysis.rets.set(CallConvRetArray[i]);
    }
#else
    // XXX TODO
    assert(!CallConvRetArray.empty());
    if (this->Analysis.rets[CallConvRetArray.front()]) {
      this->Analysis.rets.reset();
      this->Analysis.rets.set(CallConvRetArray.front());
    } else {
      this->Analysis.rets.reset();
    }
#endif
  } else {
#if 0
    if (opts::Emu)
      if (!this->IsSimple)
        this->Analysis.rets.reset();
#endif
  }

  if (opts::PrintFunctionSignatures) {
    llvm::outs() << "Function @ "
                 << (fmt("%#lx") % CFG[this->BasicBlocks.front()].Addr).str()
                 << '\n';
    llvm::outs() << "  args:";
    {
      std::vector<unsigned> glbv;
      explode_tcg_global_set(glbv, this->Analysis.args);
      for (unsigned glb : glbv)
        llvm::outs() << ' ' << TCG->_ctx.temps[glb].name;
    }
    llvm::outs() << '\n';
    llvm::outs() << "  rets:";
    {
      std::vector<unsigned> glbv;
      explode_tcg_global_set(glbv, this->Analysis.rets);
      for (unsigned glb : glbv)
        llvm::outs() << ' ' << TCG->_ctx.temps[glb].name;
    }
    llvm::outs() << '\n';
  }
}

const helper_function_t &LookupHelper(TCGOp *op);

static tcg_global_set_t DetermineFunctionArgs(function_t &);
static tcg_global_set_t DetermineFunctionRets(function_t &);

void basic_block_properties_t::Analyze(binary_index_t BIdx) {
  if (this->Analyzed)
    return;

  this->Analyzed = true;

  auto &SectMap = BinStateVec[BIdx].SectMap;

  const uintptr_t Addr = this->Addr;
  const unsigned Size = this->Size;

  auto sectit = SectMap.find(Addr);
  assert(sectit != SectMap.end());

  const section_properties_t &sectprop = *(*sectit).second.begin();
  TCG->set_section((*sectit).first.lower(), sectprop.contents.data());

  TCGContext *s = &TCG->_ctx;

  unsigned size = 0;
  jove::terminator_info_t T;
  do {
    unsigned len;
    std::tie(len, T) = TCG->translate(Addr + size);

    TCGOp *op, *op_next;
    QTAILQ_FOREACH_SAFE(op, &s->ops, link, op_next) {
      TCGOpcode opc = op->opc;

      tcg_global_set_t iglbs, oglbs;

      int nb_oargs, nb_iargs;
      if (opc == INDEX_op_call) {
        nb_oargs = TCGOP_CALLO(op);
        nb_iargs = TCGOP_CALLI(op);

        const helper_function_t &hf = LookupHelper(op);

        iglbs = hf.Analysis.InGlbs;
        oglbs = hf.Analysis.OutGlbs;
      } else {
        const TCGOpDef &opdef = tcg_op_defs[opc];

        nb_iargs = opdef.nb_iargs;
        nb_oargs = opdef.nb_oargs;
      }

      for (int i = 0; i < nb_iargs; ++i) {
        TCGTemp *ts = arg_temp(op->args[nb_oargs + i]);
        if (!ts->temp_global)
          continue;

        unsigned glb_idx = temp_idx(ts);
        if (glb_idx == tcg_env_index)
          continue;

        iglbs.set(glb_idx);
      }

      for (int i = 0; i < nb_oargs; ++i) {
        TCGTemp *ts = arg_temp(op->args[i]);
        if (!ts->temp_global)
          continue;

        unsigned glb_idx = temp_idx(ts);
        if (glb_idx == tcg_env_index)
          continue;

        oglbs.set(glb_idx);
      }

      this->Analysis.live.use |= (iglbs & ~this->Analysis.live.def);
      this->Analysis.live.def |= (oglbs & ~this->Analysis.live.use);

      this->Analysis.reach.def |= oglbs;
    }

    size += len;
  } while (size < Size);

  if (this->Term.Type == TERMINATOR::INDIRECT_JUMP &&
      !this->DynTargets.empty()) {
    binary_index_t BinIdx;
    function_index_t FuncIdx;
    std::tie(BinIdx, FuncIdx) = *this->DynTargets.begin();

    function_t &callee =
        Decompilation.Binaries[BinIdx].Analysis.Functions[FuncIdx];

    tcg_global_set_t iglbs, oglbs;

    iglbs = DetermineFunctionArgs(callee);
    oglbs = DetermineFunctionRets(callee);

    this->Analysis.live.use |= (iglbs & ~this->Analysis.live.def);
    this->Analysis.live.def |= (oglbs & ~this->Analysis.live.use);

    this->Analysis.reach.def |= oglbs;
  }

  if (opts::PrintDefAndUse) {
    llvm::outs() << (fmt("%#lx") % Addr).str() << '\n';

    uint64_t InstLen;
    for (uintptr_t A = Addr; A < Addr + Size; A += InstLen) {
      std::ptrdiff_t Offset = A - (*sectit).first.lower();

      llvm::MCInst Inst;
      bool Disassembled =
          DisAsm->getInstruction(Inst, InstLen, sectprop.contents.slice(Offset),
                                 A, llvm::nulls(), llvm::nulls());

      if (!Disassembled) {
        WithColor::error() << "failed to disassemble "
                           << (fmt("%#lx") % Addr).str() << '\n';
        break;
      }

      IP->printInst(&Inst, llvm::outs(), "", *STI);
      llvm::outs() << '\n';
    }

    llvm::outs() << '\n';

    llvm::outs() << "live.def:";
    {
      std::vector<unsigned> glbv;
      explode_tcg_global_set(glbv, this->Analysis.live.def);
      for (unsigned glb : glbv)
        llvm::outs() << ' ' << s->temps[glb].name;
    }
    llvm::outs() << '\n';

    llvm::outs() << "live.use:";
    {
      std::vector<unsigned> glbv;
      explode_tcg_global_set(glbv, this->Analysis.live.use);
      for (unsigned glb : glbv)
        llvm::outs() << ' ' << s->temps[glb].name;
    }
    llvm::outs() << '\n';

    llvm::outs() << "reach.def:";
    {
      std::vector<unsigned> glbv;
      explode_tcg_global_set(glbv, this->Analysis.reach.def);
      for (unsigned glb : glbv)
        llvm::outs() << ' ' << s->temps[glb].name;
    }
    llvm::outs() << '\n';
  }
}

const helper_function_t &LookupHelper(TCGOp *op) {
  int nb_oargs = TCGOP_CALLO(op);
  int nb_iargs = TCGOP_CALLI(op);
  uintptr_t addr = op->args[nb_oargs + nb_iargs];

  auto it = HelperFuncMap.find(addr);
  if (it == HelperFuncMap.end()) {
    TCGContext *s = &TCG->_ctx;
    const char *helper_nm = tcg_find_helper(s, addr);
    assert(helper_nm);

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
      exit(1);
    }

    llvm::MemoryBuffer *Buffer = BufferOr.get().get();
    llvm::Expected<std::unique_ptr<llvm::Module>> helperModuleOr =
        llvm::parseBitcodeFile(Buffer->getMemBufferRef(), *Context);
    if (!helperModuleOr) {
      llvm::logAllUnhandledErrors(helperModuleOr.takeError(), llvm::errs(),
                                  "could not parse helper bitcode: ");
      exit(1);
    }

    for (llvm::Function &F : *helperModuleOr.get()) {
      if (!F.empty() && F.getName() != std::string("helper_") + helper_nm)
        F.setLinkage(llvm::GlobalValue::InternalLinkage);
    }

    llvm::Linker::linkModules(*Module, std::move(helperModuleOr.get()));

    llvm::Function *helperF =
        Module->getFunction(std::string("helper_") + helper_nm);

    assert(helperF);
    assert(helperF->arg_size() == nb_iargs);

    helperF->setLinkage(llvm::GlobalValue::InternalLinkage);

    //
    // analyze helper
    //
    int EnvArgNo = -1;
    {
      TCGArg *const inputs_beg = &op->args[nb_oargs + 0];
      TCGArg *const inputs_end = &op->args[nb_oargs + nb_iargs];
      TCGArg *it =
          std::find(inputs_beg, inputs_end,
                    reinterpret_cast<TCGArg>(&s->temps[tcg_env_index]));

      if (it != inputs_end)
        EnvArgNo = std::distance(inputs_beg, it);
    }

    helper_function_t hf;
    hf.F = helperF;
    hf.EnvArgNo = EnvArgNo;

    AnalyzeTCGHelper(hf);

    it = HelperFuncMap.insert({addr, hf}).first;
  }

  return (*it).second;
}

tcg_global_set_t DetermineFunctionArgs(function_t &f) {
  f.Analyze();

  tcg_global_set_t res = f.Analysis.args;

  if (f.IsABI) /* XXX shouldn't be necessary */
    res &= CallConvArgs;

  return res;
}

tcg_global_set_t DetermineFunctionRets(function_t &f) {
  f.Analyze();

  tcg_global_set_t res = f.Analysis.rets;

  if (f.IsABI) /* XXX shouldn't be necessary */
    res &= CallConvRets;

  return res;
}

void ExplodeFunctionArgs(function_t &f, std::vector<unsigned> &glbv) {
  tcg_global_set_t args = DetermineFunctionArgs(f);

  explode_tcg_global_set(glbv, args);

  if (f.IsABI)
    std::sort(glbv.begin(), glbv.end(), [](unsigned a, unsigned b) {
      return std::find(CallConvArgArray.begin(), CallConvArgArray.end(), a) <
             std::find(CallConvArgArray.begin(), CallConvArgArray.end(), b);
    });
  else
    std::sort(glbv.begin(), glbv.end());
}

void ExplodeFunctionRets(function_t &f, std::vector<unsigned> &glbv) {
  tcg_global_set_t rets = DetermineFunctionRets(f);

  explode_tcg_global_set(glbv, rets);

  if (f.IsABI)
    std::sort(glbv.begin(), glbv.end(), [](unsigned a, unsigned b) {
      return std::find(CallConvRetArray.begin(), CallConvRetArray.end(), a) <
             std::find(CallConvRetArray.begin(), CallConvRetArray.end(), b);
    });
  else
    std::sort(glbv.begin(), glbv.end());
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

static llvm::FunctionType *DetermineFunctionType(function_t &f) {
  f.Analyze();

  std::vector<llvm::Type *> argTypes;

  {
    std::vector<unsigned> glbv;
    ExplodeFunctionArgs(f, glbv);

    argTypes.resize(glbv.size());
    std::transform(glbv.begin(), glbv.end(), argTypes.begin(),
                   [&](unsigned glb) -> llvm::Type * {
                     return llvm::Type::getIntNTy(
                         *Context, bitsOfTCGType(TCG->_ctx.temps[glb].type));
                   });
  }

  llvm::Type *retTy;

  {
    std::vector<unsigned> glbv;
    ExplodeFunctionRets(f, glbv);

    if (glbv.empty()) {
      retTy = VoidType();
    } else if (glbv.size() == 1) {
      retTy = llvm::Type::getIntNTy(
          *Context, bitsOfTCGType(TCG->_ctx.temps[glbv.front()].type));
    } else {
      std::vector<llvm::Type *> retTypes;
      retTypes.resize(glbv.size());
      std::transform(glbv.begin(), glbv.end(), retTypes.begin(),
                     [&](unsigned glb) -> llvm::Type * {
                       return llvm::Type::getIntNTy(
                           *Context, bitsOfTCGType(TCG->_ctx.temps[glb].type));
                     });

      retTy = llvm::StructType::get(*Context, retTypes);
    }
  }

  return llvm::FunctionType::get(retTy, argTypes, false);
}

static llvm::FunctionType *DetermineFunctionType(binary_index_t BinIdx,
                                                 function_index_t FuncIdx) {
  return DetermineFunctionType(
      Decompilation.Binaries[BinIdx].Analysis.Functions[FuncIdx]);
}

int CreateFunctions(void) {
  binary_t &Binary = Decompilation.Binaries[BinaryIndex];
  interprocedural_control_flow_graph_t &ICFG = Binary.Analysis.ICFG;

  for (function_index_t FuncIdx = 0; FuncIdx < Binary.Analysis.Functions.size();
       ++FuncIdx) {
    function_t &f = Binary.Analysis.Functions[FuncIdx];

    std::string name;
    name.push_back(f.IsABI ? 'J' : 'j');
    name.append((fmt("%lx") % ICFG[f.Entry].Addr).str());

    f.F = llvm::Function::Create(DetermineFunctionType(f),
                                 llvm::GlobalValue::ExternalLinkage, name,
                                 Module.get());

    std::vector<unsigned> glbv;
    ExplodeFunctionArgs(f, glbv);

    unsigned i = 0;
    for (llvm::Argument &A : f.F->args()) {
      A.setName(TCG->_ctx.temps[glbv.at(i)].name);
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

  llvm::GlobalVariable *SectsGV =
      RelocationsAt.find(Addr) != RelocationsAt.end() ? ConstSectsGlobal
                                                      : SectsGlobal;

  assert(SectsGV);

  unsigned off = Addr - SectsStartAddr;

  llvm::IRBuilderTy IRB(*Context);
  llvm::SmallVector<llvm::Value *, 4> Indices;
  llvm::Value *res = llvm::getNaturalGEPWithOffset(
      IRB, DL, SectsGV, llvm::APInt(64, off), nullptr, Indices, "");

  if (!res)
    res = llvm::ConstantExpr::getIntToPtr(
        llvm::ConstantExpr::getAdd(
            llvm::ConstantExpr::getPtrToInt(SectsGV, WordType()),
            llvm::ConstantInt::get(llvm::IntegerType::get(*Context, WordBits()),
                                   off)),
        llvm::PointerType::get(llvm::IntegerType::get(*Context, 8), 0));

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

  auto type_of_addressof_undefined_function_relocation =
      [&](const relocation_t &R, const symbol_t &S) -> llvm::Type * {
    assert(S.IsUndefined());
    llvm::FunctionType *FTy;

    auto it = ExportedFunctions.find(S.Name);
    if (it == ExportedFunctions.end()) {
      WithColor::warning() << "no exported function found by the name "
                           << S.Name << '\n';

      FTy = llvm::FunctionType::get(VoidType(), false);
    } else {
      std::pair<binary_index_t, function_index_t> resolved;

      {
        std::vector<std::pair<binary_index_t, function_index_t>> intersect;
        std::set_intersection((*it).second.begin(),
                              (*it).second.end(),
                              BinaryDynamicTargets.begin(),
                              BinaryDynamicTargets.end(),
                              std::back_inserter(intersect));

        if (intersect.empty()) {
          WithColor::warning()
              << "no dynamic target found to symbol " << S.Name << '\n';

          resolved = *(*it).second.begin();
        } else {
          resolved = intersect.front();
        }
      }

      FTy = DetermineFunctionType(resolved.first, resolved.second);
    }

    return llvm::PointerType::get(FTy, 0);
  };

  auto type_of_addressof_defined_function_relocation =
      [&](const relocation_t &R, const symbol_t &S) -> llvm::Type * {
    assert(!S.IsUndefined());

    auto it = FuncMap.find(S.Addr);
    assert(it != FuncMap.end());

    llvm::FunctionType *FTy = DetermineFunctionType(BinaryIndex, (*it).second);
    return llvm::PointerType::get(FTy, 0);
  };

  auto type_of_addressof_undefined_data_relocation =
      [&](const relocation_t &R, const symbol_t &S) -> llvm::Type * {
    assert(S.IsUndefined());
    assert(!S.Size);

    auto it = GlobalSymbolDefinedSizeMap.find(S.Name);
    if (it == GlobalSymbolDefinedSizeMap.end()) {
      llvm::outs() << "fucked because we don't have the size for " << S.Name
                   << '\n';
      return nullptr;
    }

    unsigned Size = (*it).second;

    auto is_integral_size = [](unsigned n) -> bool {
      switch (n) {
      case 1:
        return true;
      case 2:
        return true;
      case 4:
        return true;
      case 8:
        return true;
      default:
        return false;
      }
    };

    llvm::Type *T;
    if (is_integral_size(Size)) {
      T = llvm::Type::getIntNTy(*Context, Size * 8);
    } else {
      T = llvm::ArrayType::get(llvm::Type::getInt8Ty(*Context), Size);
    }

    return llvm::PointerType::get(T, 0);
  };

  auto type_of_addressof_defined_data_relocation =
      [&](const relocation_t &R, const symbol_t &S) -> llvm::Type * {
    assert(!S.IsUndefined());

    llvm::GlobalVariable *GV = Module->getGlobalVariable(S.Name, true);
    assert(GV);
    return GV->getType();
  };

  auto type_of_relative_relocation =
      [&](const relocation_t &R) -> llvm::Type * {
    uintptr_t Addr;

    {
      auto it = SectIdxMap.find(R.Addr);
      assert(it != SectIdxMap.end());
      section_t &Sect = SectTable[(*it).second];
      unsigned Off = R.Addr - Sect.Addr;

      Addr = *reinterpret_cast<const uintptr_t *>(&Sect.Contents[Off]);
    }

    //llvm::outs() << "RELATIVE! " << (fmt("%#lx") % Addr).str() << '\n';

    auto it = FuncMap.find(Addr);
    if (it == FuncMap.end()) {
      return llvm::PointerType::get(llvm::Type::getInt8Ty(*Context), 0);
    } else {
      llvm::FunctionType *FTy =
          DetermineFunctionType(BinaryIndex, (*it).second);

      return llvm::PointerType::get(FTy, 0);
    }
  };

  auto type_of_irelative_relocation =
      [&](const relocation_t &R) -> llvm::Type * {
    llvm::FunctionType *FTy;

    auto &IFuncRelocDynTargets =
        Decompilation.Binaries[BinaryIndex].Analysis.IFuncRelocDynTargets;
    auto it = IFuncRelocDynTargets.find(R.Addr);
    if (it == IFuncRelocDynTargets.end() || (*it).second.empty())
      FTy = llvm::FunctionType::get(VoidType(), false);
    else
      FTy = DetermineFunctionType(BinaryIndex, *(*it).second.begin());

    return llvm::PointerType::get(FTy, 0);
  };

  auto type_of_tpoff_relocation = [&](const relocation_t &R) -> llvm::Type * {
    auto it = TLSValueToSymbolMap.find(R.Addend);
    if (it == TLSValueToSymbolMap.end()) {
      WithColor::error() << "no sym found for tpoff relocation\n";
      return nullptr;
    }

    const std::string &SymName = (*it).second;
    llvm::GlobalVariable *GV = Module->getGlobalVariable(SymName, true);
    if (!GV) {
      WithColor::error() << "no global variable for '" << SymName
                         << "' in tpoff relocation\n";
      return nullptr;
    }

    return GV->getType();
  };

  auto type_of_relocation = [&](const relocation_t &R) -> llvm::Type * {
    switch (R.Type) {
    case relocation_t::TYPE::ADDRESSOF: {
      const symbol_t &S = SymbolTable[R.SymbolIndex];

      switch (S.Type) {
      case symbol_t::TYPE::FUNCTION:
        if (S.IsUndefined())
          return type_of_addressof_undefined_function_relocation(R, S);
        else
          return type_of_addressof_defined_function_relocation(R, S);
      case symbol_t::TYPE::DATA:
        if (S.IsUndefined())
          return type_of_addressof_undefined_data_relocation(R, S);
        else
          return type_of_addressof_defined_data_relocation(R, S);
      }
    }

    case relocation_t::TYPE::RELATIVE:
      return type_of_relative_relocation(R);

    case relocation_t::TYPE::IRELATIVE:
      return type_of_irelative_relocation(R);

    case relocation_t::TYPE::TPOFF:
      return type_of_tpoff_relocation(R);
    }

    // XXX TODO
    return nullptr;
  };

  // puncture the interval set for each section by intervals which represent
  // relocations
  for (const relocation_t &R : RelocationTable)
    if (llvm::Type *Ty = type_of_relocation(R))
      type_at_address(R.Addr, Ty);

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
                                         llvm::GlobalValue::ExternalLinkage,
                                         nullptr, "sections");
  SectsGlobal->setAlignment(4096);

  ConstSectsGlobal = new llvm::GlobalVariable(
      *Module, SectsGlobalTy, false, llvm::GlobalValue::ExternalLinkage,
      nullptr, "const_sections");
  ConstSectsGlobal->setAlignment(4096);

  auto constant_at_address = [&](uintptr_t Addr, llvm::Constant *C) -> void {
    auto it = SectIdxMap.find(Addr);
    assert(it != SectIdxMap.end());

    section_t &Sect = SectTable[(*it).second];
    unsigned Off = Addr - Sect.Addr;

    Sect.Stuff.Intervals.insert(boost::icl::interval<uintptr_t>::right_open(
        Off, Off + sizeof(uintptr_t)));
    Sect.Stuff.Constants[Off] = C;
  };

  auto constant_of_addressof_undefined_function_relocation =
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
      std::pair<binary_index_t, function_index_t> resolved;

      {
        std::vector<std::pair<binary_index_t, function_index_t>> intersect;
        std::set_intersection((*it).second.begin(),
                              (*it).second.end(),
                              BinaryDynamicTargets.begin(),
                              BinaryDynamicTargets.end(),
                              std::back_inserter(intersect));

        if (intersect.empty()) {
          WithColor::warning()
              << "no dynamic target found to symbol " << S.Name << '\n';

          resolved = *(*it).second.begin();
        } else {
          resolved = intersect.front();
        }
      }

      F = llvm::Function::Create(
          DetermineFunctionType(resolved.first, resolved.second),
          S.Bind == symbol_t::BINDING::WEAK
              ? llvm::GlobalValue::ExternalWeakLinkage
              : llvm::GlobalValue::ExternalLinkage,
          S.Name, Module.get());
    }

    return F;
  };

  auto constant_of_addressof_defined_function_relocation =
      [&](const relocation_t &R, const symbol_t &S) -> llvm::Constant * {
    assert(!S.IsUndefined());

    auto it = FuncMap.find(S.Addr);
    assert(it != FuncMap.end());

    return Decompilation.Binaries[BinaryIndex]
        .Analysis.Functions[(*it).second]
        .F;
  };

  auto constant_of_addressof_undefined_data_relocation =
      [&](const relocation_t &R, const symbol_t &S) -> llvm::Constant * {
    assert(S.IsUndefined());
    assert(!S.Size);

    llvm::GlobalVariable *GV = Module->getGlobalVariable(S.Name, true);

    if (GV)
      return GV;

    auto it = GlobalSymbolDefinedSizeMap.find(S.Name);
    if (it == GlobalSymbolDefinedSizeMap.end()) {
      llvm::outs() << "fucked because we don't have the size for " << S.Name
                   << '\n';
      return nullptr;
    }

    unsigned Size = (*it).second;

    auto is_integral_size = [](unsigned n) -> bool {
      switch (n) {
      case 1:
        return true;
      case 2:
        return true;
      case 4:
        return true;
      case 8:
        return true;
      default:
        return false;
      }
    };

    llvm::Type *T;
    if (is_integral_size(Size)) {
      T = llvm::Type::getIntNTy(*Context, Size * 8);
    } else {
      T = llvm::ArrayType::get(llvm::Type::getInt8Ty(*Context), Size);
    }

    GV = new llvm::GlobalVariable(*Module, T, false,
                                  S.Bind == symbol_t::BINDING::WEAK
                                      ? llvm::GlobalValue::ExternalWeakLinkage
                                      : llvm::GlobalValue::ExternalLinkage,
                                  nullptr, S.Name);

    return GV;
  };

  auto constant_of_addressof_defined_data_relocation =
      [&](const relocation_t &R, const symbol_t &S) -> llvm::Constant * {
    assert(!S.IsUndefined());

    llvm::GlobalVariable *GV = Module->getGlobalVariable(S.Name, true);
    assert(GV);
    return GV;
  };

  auto constant_of_relative_relocation =
      [&](const relocation_t &R) -> llvm::Constant * {
    uintptr_t Addr;

    {
      auto it = SectIdxMap.find(R.Addr);
      assert(it != SectIdxMap.end());
      section_t &Sect = SectTable[(*it).second];
      unsigned Off = R.Addr - Sect.Addr;

      Addr = *reinterpret_cast<const uintptr_t *>(&Sect.Contents[Off]);
    }

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

  auto constant_of_irelative_relocation =
      [&](const relocation_t &R) -> llvm::Constant * {
    llvm::FunctionType *FTy;

    {
      auto &IFuncRelocDynTargets =
          Decompilation.Binaries[BinaryIndex].Analysis.IFuncRelocDynTargets;
      auto it = IFuncRelocDynTargets.find(R.Addr);
      if (it == IFuncRelocDynTargets.end() || (*it).second.empty())
        FTy = llvm::FunctionType::get(VoidType(), false);
      else
        FTy = DetermineFunctionType(BinaryIndex, *(*it).second.begin());
    }

    auto it = FuncMap.find(R.Addend);
    assert(it != FuncMap.end());

    function_t &resolver =
        Decompilation.Binaries[BinaryIndex].Analysis.Functions[(*it).second];

    return llvm::GlobalIFunc::create(FTy, 0, llvm::GlobalValue::InternalLinkage,
                                     "", resolver.F, Module.get());
  };

  auto constant_of_tpoff_relocation =
      [&](const relocation_t &R) -> llvm::Constant * {
    auto it = TLSValueToSymbolMap.find(R.Addend);
    if (it == TLSValueToSymbolMap.end()) {
      WithColor::error() << "no sym found for tpoff relocation\n";
      return nullptr;
    }

    const std::string &SymName = (*it).second;
    llvm::GlobalVariable *GV = Module->getGlobalVariable(SymName, true);
    if (!GV) {
      WithColor::error() << "no global variable for '" << SymName
                         << "' in tpoff relocation\n";
      return nullptr;
    }

    return GV;
  };

  auto constant_of_relocation = [&](const relocation_t &R) -> llvm::Constant * {
    switch (R.Type) {
    case relocation_t::TYPE::ADDRESSOF: {
      const symbol_t &S = SymbolTable[R.SymbolIndex];

      switch (S.Type) {
      case symbol_t::TYPE::FUNCTION:
        if (S.IsUndefined())
          return constant_of_addressof_undefined_function_relocation(R, S);
        else
          return constant_of_addressof_defined_function_relocation(R, S);
      case symbol_t::TYPE::DATA:
        if (S.IsUndefined())
          return constant_of_addressof_undefined_data_relocation(R, S);
        else
          return constant_of_addressof_defined_data_relocation(R, S);
      }
    }

    case relocation_t::TYPE::RELATIVE:
      return constant_of_relative_relocation(R);

    case relocation_t::TYPE::IRELATIVE:
      return constant_of_irelative_relocation(R);

    case relocation_t::TYPE::TPOFF:
      return constant_of_tpoff_relocation(R);
    }

    // XXX TODO
    return nullptr;
  };

  // puncture the interval set for each section by intervals which represent
  // relocations
  for (const relocation_t &R : RelocationTable)
    if (llvm::Constant *C = constant_of_relocation(R))
      constant_at_address(R.Addr, C);

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

  ConstSectsGlobal->setInitializer(
      llvm::ConstantStruct::get(SectsGlobalTy, SectsGlobalFieldInits));
  ConstSectsGlobal->setConstant(true);

  //
  // it's important that we do this here, after creating the section globals
  //
  for (const relocation_t &R : RelocationTable) {
    if (!type_of_relocation(R))
      continue;

    RelocationsAt.insert(R.Addr);
  }

  return 0;
}

int CreateCPUStateGlobal() {
  llvm::Function *joveF = Module->getFunction("jove");
  llvm::FunctionType *joveFTy = joveF->getFunctionType();
  assert(joveFTy->getNumParams() == 1);
  llvm::Type *cpuStatePtrTy = joveFTy->getParamType(0);
  assert(llvm::isa<llvm::PointerType>(cpuStatePtrTy));
  CPUStateType = llvm::cast<llvm::PointerType>(cpuStatePtrTy)->getElementType();

  llvm::Constant *CPUStateGlobalInitializer = nullptr;

  binary_t &Binary = Decompilation.Binaries[BinaryIndex];
  if (Binary.IsExecutable) {
    constexpr unsigned StackLen = 10 * 4096;

    llvm::Type *StackTy =
        llvm::ArrayType::get(llvm::Type::getInt8Ty(*Context), StackLen);
    llvm::GlobalVariable *Stack = new llvm::GlobalVariable(
        *Module, StackTy, false, llvm::GlobalValue::ExternalLinkage,
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
    llvm::StructType *CPUStateSType =
        llvm::cast<llvm::StructType>(CPUStateType);

    std::vector<llvm::Constant *> CPUStateGlobalFieldInits;
    CPUStateGlobalFieldInits.resize(CPUStateSType->getNumElements());
    std::transform(CPUStateSType->element_begin(),
                   CPUStateSType->element_end(),
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
    CPUStateGlobalInitializer =
        llvm::ConstantStruct::get(CPUStateSType, CPUStateGlobalFieldInits);
  }

  CPUStateGlobal = new llvm::GlobalVariable(
      *Module, CPUStateType, false, llvm::GlobalValue::ExternalLinkage,
      CPUStateGlobalInitializer, "env", nullptr,
      llvm::GlobalValue::NotThreadLocal
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

#if defined(__x86_64__)
int CreateFSBaseGlobal(void) {
  FSBaseGlobal = new llvm::GlobalVariable(*Module, WordType(), false,
                                          llvm::GlobalValue::ExternalLinkage,
                                          nullptr, "__jove_fs_base");
  return 0;
}
#endif

int FixupHelperStubs(void) {
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

  binary_t &Binary = Decompilation.Binaries[BinaryIndex];
  if (!is_function_index_valid(Binary.Analysis.EntryFunction))
    return 0;

  llvm::Function *CallEntryF =
      Module->getFunction("_jove_call_entry");
  assert(CallEntryF);

  {
    llvm::BasicBlock *BB = llvm::BasicBlock::Create(*Context, "", CallEntryF);

    llvm::IRBuilderTy IRB(BB);

    function_t &f = Binary.Analysis.Functions[Binary.Analysis.EntryFunction];

    std::vector<llvm::Value *> ArgVec;
    {
      std::vector<unsigned> glbv;
      ExplodeFunctionArgs(f, glbv);

      ArgVec.resize(glbv.size());
      std::transform(
          glbv.begin(), glbv.end(), ArgVec.begin(),
          [&](unsigned glb) -> llvm::Value * {
            llvm::SmallVector<llvm::Value *, 4> Indices;
            llvm::Value *res = IRB.CreateLoad(llvm::getNaturalGEPWithOffset(
                IRB, DL, CPUStateGlobal,
                llvm::APInt(64, TCG->_ctx.temps[glb].mem_offset),
                IRB.getIntNTy(bitsOfTCGType(TCG->_ctx.temps[glb].type)),
                Indices, ""));
            res->setName(TCG->_ctx.temps[glb].name);
            return res;
          });
    }

    llvm::CallInst *Ret = IRB.CreateCall(f.F, ArgVec);
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
#if defined(__i386__)
    if (f.BasicBlocks.size() != 1)
      continue;

    basic_block_t bb = f.BasicBlocks.front();

    if (ICFG[bb].Term.Type != TERMINATOR::INDIRECT_JUMP &&
        ICFG[bb].Term.Type != TERMINATOR::RETURN)
      continue;

    const uintptr_t Addr = ICFG[bb].Addr;
    const unsigned Size = ICFG[bb].Size;

    auto disassemble_block = [&](std::vector<llvm::MCInst> &out) -> int {
      auto sectit = SectMap.find(Addr);
      assert(sectit != SectMap.end());

      const section_properties_t &sectprop = *(*sectit).second.begin();

      const uintptr_t Base = (*sectit).first.lower();

      uint64_t InstLen;
      for (uintptr_t A = Addr; A < Addr + Size; A += InstLen) {
        llvm::MCInst Inst;

        ptrdiff_t Offset = A - Base;
        bool Disassembled = DisAsm->getInstruction(
            Inst, InstLen, sectprop.contents.slice(Offset), A, llvm::nulls(),
            llvm::nulls());
        if (!Disassembled) {
          WithColor::error()
              << "failed to disassemble " << (fmt("%#lx") % A).str() << '\n';
          return 1;
        }

        out.push_back(Inst);
      }

      return 0;
    };

    std::vector<llvm::MCInst> InstVec;
    if (int ret = disassemble_block(InstVec))
      return ret;

    auto is_thunk = [&](void) -> bool {
      if (ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP)
        return InstVec.size() == 1 &&
               InstVec[0].getOpcode() == llvm::X86::JMP32m &&
               InstVec[0].getOperand(0).getReg() == llvm::X86::EBX;

      if (ICFG[bb].Term.Type == TERMINATOR::RETURN)
        return InstVec.size() == 2 &&
               InstVec[0].getOpcode() == llvm::X86::MOV32rm &&
               InstVec[1].getOpcode() == llvm::X86::RETL;

      abort();
    };

    if (is_thunk()) {
      f.Analysis.IsThunk = true;

      WithColor::note() << "thunk @ " << (fmt("%#lx") % Addr).str() << '\n';
    }
#endif
  }

  return 0;
}

int CreateNoAliasMetadata(void) {
  //
  // create noalias metadata
  //
  llvm::MDBuilder MDB(*Context);
  llvm::MDNode *aliasScopeDomain = MDB.createAliasScopeDomain("JoveDomain");
  llvm::MDNode *aliasScope =
      MDB.createAliasScope("JoveScope", aliasScopeDomain);

  AliasScopeMetadata =
      llvm::MDNode::get(*Context, llvm::ArrayRef<llvm::Metadata *>(aliasScope));

  return 0;
}

static int TranslateBasicBlock(binary_t &, function_t &, basic_block_t,
                               llvm::IRBuilderTy &);

static llvm::Constant *CPUStateGlobalPointer(unsigned glb) {
  if (glb == tcg_env_index)
    return CPUStateGlobal;

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

  basic_block_t entry_bb = f.BasicBlocks.front();
  llvm::BasicBlock *EntryB = llvm::BasicBlock::Create(*Context, "", F);

  for (basic_block_t bb : f.BasicBlocks)
    ICFG[bb].B = llvm::BasicBlock::Create(
        *Context, (fmt("%#lx") % ICFG[bb].Addr).str(), F);

  {
    llvm::IRBuilderTy IRB(EntryB);
    IRB.CreateBr(ICFG[entry_bb].B);
  }

  std::fill(f.GlobalAllocaVec.begin(), f.GlobalAllocaVec.end(), nullptr);

  //
  // create the AllocaInst's for each global referenced at the start of the
  // entry basic block of the function
  //
  {
    llvm::IRBuilderTy IRB(ICFG[entry_bb].B);

    for (unsigned glb = 0; glb < f.GlobalAllocaVec.size(); ++glb)
      f.GlobalAllocaVec[glb] = IRB.CreateAlloca(
          IRB.getIntNTy(bitsOfTCGType(TCG->_ctx.temps[glb].type)), 0,
          std::string(TCG->_ctx.temps[glb].name) + "_ptr");

    f.PCAlloca = tcg_program_counter_index < 0
                     ? IRB.CreateAlloca(WordType(), 0, "pc_ptr")
                     : f.GlobalAllocaVec[tcg_program_counter_index];

    f.PCRelVal = IRB.CreateLoad(PCRelGlobal, "pcrel");

#if defined(__x86_64__)
    f.FSBaseVal = IRB.CreateLoad(FSBaseGlobal, "fs_base");
#endif

    //
    // initialize the globals which are passed as parameters
    //
    {
      std::vector<unsigned> glbv;
      ExplodeFunctionArgs(f, glbv);

      llvm::Function::arg_iterator arg_it = F->arg_begin();
      for (unsigned glb : glbv) {
        assert(arg_it != F->arg_end());
        llvm::Argument *Val = &*arg_it++;
        llvm::Value *Ptr = f.GlobalAllocaVec[glb];
        IRB.CreateStore(Val, Ptr);
      }
    }

    //
    // for globals not passed as parameters, they are either loaded from the
    // GlobalCPUState *or*, if this function conforms to the ABI specification
    // they are initialized to UndefValue
    //
    {
      tcg_global_set_t glbs = ~DetermineFunctionArgs(f);
      glbs.reset(tcg_env_index);

      std::vector<unsigned> glbv;
      explode_tcg_global_set(glbv, glbs);

      for (unsigned glb : glbv) {
        switch (glb) {
        case tcg_frame_pointer_index:
        case tcg_stack_pointer_index: {
          llvm::Value *Val = IRB.CreateLoad(CPUStateGlobalPointer(glb));
          llvm::Value *Ptr = f.GlobalAllocaVec[glb];
          IRB.CreateStore(Val, Ptr);
          break;
        }

#if defined(__x86_64__)
        case tcg_fs_base_index:
          IRB.CreateStore(f.FSBaseVal, f.GlobalAllocaVec[glb]);
          break;
#endif

        default:
          continue;
        }
      }
    }

    if (int ret = TranslateBasicBlock(Binary, f, entry_bb, IRB))
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
    if (f.IsThunk)
      continue;

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

static int DoOptimize(void) {
  if (llvm::verifyModule(*Module, &llvm::errs())) {
    WithColor::error() << "DoOptimize: [pre] failed to verify module\n";
    llvm::errs() << *Module << '\n';
    return 1;
  }

  constexpr unsigned OptLevel = 2;
  constexpr unsigned SizeLevel = 2;

  llvm::legacy::PassManager MPM;
  llvm::legacy::FunctionPassManager FPM(Module.get());

  // Add an appropriate TargetLibraryInfo pass for the module's triple.
  llvm::Triple ModuleTriple(Module->getTargetTriple());
  llvm::TargetLibraryInfoImpl TLII(ModuleTriple);

  // The -disable-simplify-libcalls flag actually disables all builtin optzns.
  if (false /* DisableSimplifyLibCalls */)
    TLII.disableAllFunctions();
  MPM.add(new llvm::TargetLibraryInfoWrapperPass(TLII));

  // Add internal analysis passes from the target machine.
  MPM.add(llvm::createTargetTransformInfoWrapperPass(
      TM ? TM->getTargetIRAnalysis() : llvm::TargetIRAnalysis()));

  FPM.add(llvm::createTargetTransformInfoWrapperPass(
      TM ? TM->getTargetIRAnalysis() : llvm::TargetIRAnalysis()));

  llvm::PassManagerBuilder Builder;
  Builder.OptLevel = OptLevel;
  Builder.SizeLevel = SizeLevel;

  Builder.Inliner =
      llvm::createFunctionInliningPass(OptLevel, SizeLevel, false);

  Builder.populateFunctionPassManager(FPM);
  Builder.populateModulePassManager(MPM);

  FPM.doInitialization();
  for (llvm::Function &F : *Module)
    FPM.run(F);
  FPM.doFinalization();

  MPM.run(*Module);

  if (llvm::verifyModule(*Module, &llvm::errs())) {
    WithColor::error() << "DoOptimize: [post] failed to verify module\n";
    llvm::errs() << *Module << '\n';
    return 1;
  }

  //
  // reload global variables which might have been optimized away
  //
  PCRelGlobal = Module->getGlobalVariable("__jove_pcrel", true);
#if defined(__x86_64__)
  FSBaseGlobal = Module->getGlobalVariable("__jove_fs_base", true);
#endif
  CPUStateGlobal = Module->getGlobalVariable("env", true);
  SectsGlobal = Module->getGlobalVariable("sections", true);
  ConstSectsGlobal = Module->getGlobalVariable("const_sections", true);

  return 0;
}

int Optimize1(void) {
  if (opts::NoOpt1)
    return 0;

  if (int ret = DoOptimize())
    return ret;

  return 0;
}

static llvm::Constant *ConstantForAddress(uintptr_t Addr) {
  binary_state_t &st = BinStateVec[BinaryIndex];
  binary_t &Binary = Decompilation.Binaries[BinaryIndex];

  auto it = st.FuncMap.find(Addr);
  llvm::Constant *res = it == st.FuncMap.end()
                            ? SectionPointer(Addr)
                            : Binary.Analysis.Functions[(*it).second].F;

  res = llvm::ConstantExpr::getPtrToInt(res, WordType());

  return res;
}

int FixupPCRelativeAddrs(void) {
  if (opts::NoFixupPcrel)
    return 0;

  if (!PCRelGlobal)
    return 0;

  std::vector<std::pair<llvm::Instruction *, llvm::Value *>> ToReplace;

  for (llvm::User *U : PCRelGlobal->users()) {
    assert(llvm::isa<llvm::LoadInst>(U));
    llvm::LoadInst *L = llvm::cast<llvm::LoadInst>(U);

    for (llvm::User *_U : L->users()) {
      assert(llvm::isa<llvm::Instruction>(_U));
      llvm::Instruction *Inst = llvm::cast<llvm::Instruction>(_U);

      switch (Inst->getOpcode()) {
      case llvm::Instruction::Add: {
        llvm::Value *LHS = Inst->getOperand(0);
        llvm::Value *RHS = Inst->getOperand(1);

        llvm::Value *Other = LHS == L ? RHS : LHS;

        if (llvm::isa<llvm::ConstantInt>(Other)) {
          llvm::ConstantInt *CI = llvm::cast<llvm::ConstantInt>(Other);
          ToReplace.push_back({Inst, ConstantForAddress(CI->getZExtValue())});
          continue;
        }

        if (!llvm::isa<llvm::Instruction>(Other))
          break;

        unsigned OtherOpc = llvm::cast<llvm::Instruction>(Other)->getOpcode();
        llvm::Instruction *OtherInst = llvm::cast<llvm::Instruction>(Other);

        if (OtherOpc == llvm::Instruction::Add) {
          llvm::Value *LHS = OtherInst->getOperand(0);
          llvm::Value *RHS = OtherInst->getOperand(1);

          if (!llvm::isa<llvm::ConstantInt>(LHS) &&
              !llvm::isa<llvm::ConstantInt>(RHS))
            break;

          if (llvm::isa<llvm::ConstantInt>(LHS) &&
              llvm::isa<llvm::ConstantInt>(RHS))
            break;

          unsigned operandIdx = llvm::isa<llvm::ConstantInt>(LHS) ? 0 : 1;
          llvm::ConstantInt *CI = llvm::isa<llvm::ConstantInt>(LHS)
                                      ? llvm::cast<llvm::ConstantInt>(LHS)
                                      : llvm::cast<llvm::ConstantInt>(RHS);

          OtherInst->setOperand(operandIdx, ConstantForAddress(CI->getZExtValue()));

          ToReplace.push_back({Inst, Other});
          continue;
        } else if (OtherOpc == llvm::Instruction::Select) {
          llvm::SelectInst *SI = llvm::cast<llvm::SelectInst>(Other);

          llvm::Value *TrueV = SI->getTrueValue();
          llvm::Value *FalseV = SI->getFalseValue();

          if (llvm::isa<llvm::ConstantInt>(TrueV) &&
              llvm::isa<llvm::ConstantInt>(FalseV)) {
            {
              llvm::ConstantInt *CI = llvm::cast<llvm::ConstantInt>(TrueV);
              SI->setTrueValue(ConstantForAddress(CI->getZExtValue()));
            }

            {
              llvm::ConstantInt *CI = llvm::cast<llvm::ConstantInt>(FalseV);
              SI->setFalseValue(ConstantForAddress(CI->getZExtValue()));
            }

            ToReplace.push_back({Inst, Other});
            continue;
          }
        } else if (OtherOpc == llvm::Instruction::PHI) {
          llvm::PHINode *PI = llvm::cast<llvm::PHINode>(Other);

          auto phi_node_has_all_const_int = [&](void) -> bool {
            for (unsigned i = 0; i < PI->getNumIncomingValues(); ++i) {
              if (!llvm::isa<llvm::ConstantInt>(PI->getIncomingValue(i)))
                return false;
            }

            return true;
          };

          if (phi_node_has_all_const_int()) {
            for (unsigned i = 0; i < PI->getNumIncomingValues(); ++i) {
              PI->setIncomingValue(
                  i, ConstantForAddress(
                         llvm::cast<llvm::ConstantInt>(PI->getIncomingValue(i))
                             ->getZExtValue()));
            }

            ToReplace.push_back({Inst, Other});
            continue;
          }

          auto phi_node_has_all_select_const_int = [&](void) -> bool {
            for (unsigned i = 0; i < PI->getNumIncomingValues(); ++i) {
              llvm::Value *V = PI->getIncomingValue(i);

              if (!llvm::isa<llvm::SelectInst>(V))
                return false;

              llvm::SelectInst *SI = llvm::cast<llvm::SelectInst>(V);

              if (!llvm::isa<llvm::ConstantInt>(SI->getTrueValue()))
                return false;

              if (!llvm::isa<llvm::ConstantInt>(SI->getFalseValue()))
                return false;
            }

            return true;
          };

          if (phi_node_has_all_select_const_int()) {
            for (unsigned i = 0; i < PI->getNumIncomingValues(); ++i) {
              llvm::Value *V = PI->getIncomingValue(i);
              llvm::SelectInst *SI = llvm::cast<llvm::SelectInst>(V);

              llvm::ConstantInt *TV = llvm::cast<llvm::ConstantInt>(SI->getTrueValue());
              llvm::ConstantInt *FV = llvm::cast<llvm::ConstantInt>(SI->getFalseValue());

              SI->setTrueValue(ConstantForAddress(TV->getZExtValue()));
              SI->setFalseValue(ConstantForAddress(FV->getZExtValue()));
            }

            ToReplace.push_back({Inst, Other});
            continue;
          }

          for (llvm::Use &incomingVal : PI->incoming_values()) {
            llvm::errs() << *incomingVal.get() << '\n';
          }
        }

        WithColor::warning() << "Other: " << *Other << '\n';
        break;
      }

      case llvm::Instruction::Sub: {
        llvm::Value *LHS = Inst->getOperand(0);
        llvm::Value *RHS = Inst->getOperand(1);

        llvm::Value *Other = LHS == L ? RHS : LHS;

        if (llvm::isa<llvm::ConstantInt>(Other)) {
          llvm::ConstantInt *CI = llvm::cast<llvm::ConstantInt>(Other);
          llvm::APInt x = CI->getValue();
          if (x.isNegative())
            x.negate();

          ToReplace.push_back({Inst, ConstantForAddress(x.getZExtValue())});
          continue;
        }

        break;
      }

      default:
        break;
      }

      WithColor::warning() << "unhandled PCRelGlobal user " << *Inst << '\n';
    }
  }

  for (auto &TR : ToReplace) {
    llvm::Instruction *I;
    llvm::Value *V;
    std::tie(I, V) = TR;

    I->replaceAllUsesWith(V);
  }

  return 0;
}

#if defined(__x86_64__)
int FixupFSBaseAddrs(void) {
  if (opts::NoFixupFSBase)
    return 0;

  if (!FSBaseGlobal)
    return 0;

  std::vector<std::pair<llvm::Instruction *, llvm::Value *>> ToReplace;

  for (llvm::User *U : FSBaseGlobal->users()) {
    if (!llvm::isa<llvm::LoadInst>(U)) {
      WithColor::warning() << "unknown user of FSBaseGlobal " << *U << '\n';
      continue;
    }

    assert(llvm::isa<llvm::LoadInst>(U));
    llvm::LoadInst *L = llvm::cast<llvm::LoadInst>(U);
    ToReplace.push_back(
        {L, llvm::ConstantInt::get(llvm::IntegerType::get(*Context, WordBits()),
                                   0)});

    for (llvm::User *_U : L->users()) {
      assert(llvm::isa<llvm::Instruction>(_U));
      llvm::Instruction *Inst = llvm::cast<llvm::Instruction>(_U);


      switch (Inst->getOpcode()) {
      case llvm::Instruction::Add: {
        llvm::Value *LHS = Inst->getOperand(0);
        llvm::Value *RHS = Inst->getOperand(1);

        //
        // is one of the operands a constant int?
        //
        if (!llvm::isa<llvm::ConstantInt>(LHS) &&
            !llvm::isa<llvm::ConstantInt>(RHS))
          break;

        if (llvm::isa<llvm::ConstantInt>(LHS) &&
            llvm::isa<llvm::ConstantInt>(RHS))
          break;

        llvm::ConstantInt *CI = llvm::isa<llvm::ConstantInt>(LHS)
                                    ? llvm::cast<llvm::ConstantInt>(LHS)
                                    : llvm::cast<llvm::ConstantInt>(RHS);

        auto it = TLSValueToSymbolMap.find(CI->getZExtValue());
        if (it == TLSValueToSymbolMap.end()) {
          WithColor::warning() << "unable to find TLS symbol for offset "
                               << CI->getZExtValue() << '\n';
          continue;
        }

        llvm::GlobalVariable *GV =
            Module->getGlobalVariable((*it).second, true);
        assert(GV);

        ToReplace.push_back(
            {Inst, llvm::ConstantExpr::getPtrToInt(GV, WordType())});

        break;
      }

      default:
        break;
      }
    }
  }

  for (auto &TR : boost::adaptors::reverse(ToReplace)) {
    llvm::Instruction *I;
    llvm::Value *V;
    std::tie(I, V) = TR;

    I->replaceAllUsesWith(V);
  }

  return 0;
}
#endif

int InternalizeStaticFunctions(void) {
  binary_t &b = Decompilation.Binaries[BinaryIndex];

  for (function_t &f : b.Analysis.Functions) {
    if (f.IsABI)
      continue;

    if (!f.F->empty())
      f.F->setLinkage(llvm::GlobalValue::InternalLinkage);
  }

  return 0;
}

int InternalizeSections(void) {
  assert(SectsGlobal);
  assert(ConstSectsGlobal);

  SectsGlobal->setLinkage(llvm::GlobalValue::InternalLinkage);
  ConstSectsGlobal->setLinkage(llvm::GlobalValue::InternalLinkage);

  return 0;
}

int Optimize2(void) {
  if (opts::NoOpt2)
    return 0;

  if (int ret = DoOptimize())
    return ret;

  return 0;
}

int ReplaceAllRemainingUsesOfConstSections(void) {
  if (!ConstSectsGlobal)
    return 0;

  assert(SectsGlobal);

  assert(ConstSectsGlobal->user_begin() != ConstSectsGlobal->user_end());
  ConstSectsGlobal->replaceAllUsesWith(SectsGlobal);
  assert(ConstSectsGlobal->user_begin() == ConstSectsGlobal->user_end());
  ConstSectsGlobal->eraseFromParent();

  return 0;
}

int ReplaceAllRemainingUsesOfPCRel(void) {
  if (opts::NoFixupPcrel)
    return 0;

  if (!PCRelGlobal)
    return 0;

  binary_state_t &st = BinStateVec[BinaryIndex];
  binary_t &Binary = Decompilation.Binaries[BinaryIndex];

  std::vector<std::pair<llvm::Instruction *, llvm::Constant *>> ToReplace;

  for (llvm::User *U : PCRelGlobal->users()) {
    assert(llvm::isa<llvm::LoadInst>(U));
    llvm::LoadInst *L = llvm::cast<llvm::LoadInst>(U);
    ToReplace.push_back(
        {L, llvm::ConstantExpr::getPtrToInt(SectsGlobal, WordType())});
  }

  for (auto &TR : ToReplace) {
    llvm::Instruction *I;
    llvm::Constant *C;
    std::tie(I, C) = TR;

    assert(I->getType() == C->getType());
    I->replaceAllUsesWith(C);
  }

  std::vector<llvm::Instruction *> ToErase;

  for (llvm::User *U : PCRelGlobal->users()) {
    assert(llvm::isa<llvm::LoadInst>(U));
    llvm::LoadInst *L = llvm::cast<llvm::LoadInst>(U);
    assert(L->user_begin() == L->user_end());
    ToErase.push_back(L);
  }

  for (llvm::Instruction *I : ToErase)
    I->eraseFromParent();

  assert(PCRelGlobal->user_begin() == PCRelGlobal->user_end());
  PCRelGlobal->eraseFromParent();

  return 0;
}

int RenameFunctionLocals(void) {
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

int RenameFunctions(void) {
  for (const auto &pair : ExportedFunctions) {
    assert(!pair.second.empty());

    binary_index_t BinIdx;
    function_index_t FuncIdx;
    std::tie(BinIdx, FuncIdx) = *pair.second.begin();

    if (BinIdx != BinaryIndex)
      continue;

    Decompilation.Binaries[BinIdx].Analysis.Functions[FuncIdx].F->setName(
        pair.first);

    // XXX TODO symbol versions
  }

  return 0;
}

int WriteModule(void) {
  if (llvm::verifyModule(*Module, &llvm::errs())) {
    WithColor::error() << "WriteModule: failed to verify module\n";
    llvm::errs() << *Module << '\n';
    return 1;
  }

#if 0
  {
    std::error_code ec;
    llvm::raw_fd_ostream rfo(
        fs::path(opts::Output).replace_extension("ll").string(), ec);

    rfo << *Module;
  }
#endif

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
  if (TargetTy && ElementTy != TargetTy)
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

int TranslateBasicBlock(binary_t &Binary,
                        function_t &f,
                        basic_block_t bb,
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

    //
    // create label basic blocks up-front
    //
    for (unsigned i = 0; i < LabelVec.size(); ++i)
      LabelVec[i] = llvm::BasicBlock::Create(
          *Context, (boost::format("%#lx_L%u") % ICFG[bb].Addr % i).str(), f.F);

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
#if 0
  if (T.Type == TERMINATOR::CALL) {
    function_t &callee = Binary.Analysis.Functions[ICFG[bb].Term._call.Target];
    if (callee.IsThunk) {
      basic_block_t thunkbb = callee.BasicBlocks.front();
      uintptr_t ThunkAddr = ICFG[thunkbb].Addr;

      auto sectit = st.SectMap.find(ThunkAddr);
      assert(sectit != st.SectMap.end());

      const section_properties_t &sectprop = *(*sectit).second.begin();
      TCG->set_section((*sectit).first.lower(), sectprop.contents.data());

      jove::terminator_info_t ThunkT;
      unsigned len;
      std::tie(len, ThunkT) = TCG->translate(ThunkAddr);

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
                (fmt("%#lx_%s%u") % ICFG[thunkbb].Addr %
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
                (fmt("%#lx_%s%u") % ICFG[thunkbb].Addr %
                 (ts->temp_local ? "loc" : "tmp") % (idx - tcg_num_globals))
                    .str());
          }
        }
      }

      ExitBB = llvm::BasicBlock::Create(
          *Context, (fmt("%#lx_thunk_exit") % Addr).str(), f.F);

      TCGOp *op, *op_next;
      QTAILQ_FOREACH_SAFE(op, &s->ops, link, op_next) {
        if (int ret =
                TranslateTCGOp(op, op_next, Binary, f /* callee */, thunkbb,
                               TempAllocaVec, LabelVec, ExitBB, IRB)) {
          TCG->dump_operations();
          return ret;
        }
      }

      IRB.SetInsertPoint(ExitBB);

      if (ThunkT.Type == TERMINATOR::INDIRECT_JUMP) {
        llvm::Value *PC = IRB.CreateLoad(f.PCAlloca);

        const auto &DynTargets = ICFG[thunkbb].DynTargets;
        if (DynTargets.empty()) {
          // apparently this is necessary
          IRB.CreateCall(IRB.CreateIntToPtr(
              PC, llvm::PointerType::get(
                      llvm::FunctionType::get(VoidType(), false), 0)));
        } else {
          function_index_t BinIdx = (*DynTargets.begin()).first;
          function_index_t FuncIdx = (*DynTargets.begin()).second;

          function_t &callee =
              Decompilation.Binaries[BinIdx].Analysis.Functions[FuncIdx];

          std::vector<llvm::Value *> ArgVec;
          {
            std::vector<unsigned> glbv;
            explode_tcg_global_set(glbv, callee.live & CallConvArgs);
            std::sort(glbv.begin(), glbv.end(), [](unsigned a, unsigned b) {
              return std::find(CallConvArgArray.begin(), CallConvArgArray.end(),
                               a) < std::find(CallConvArgArray.begin(),
                                              CallConvArgArray.end(), b);
            });

            ArgVec.resize(glbv.size());
            std::transform(glbv.begin(), glbv.end(), ArgVec.begin(),
                           [&](unsigned glb) -> llvm::Value * {
                             return IRB.CreateLoad(f.GlobalAllocaVec[glb]);
                           });
          }

          llvm::CallInst *Ret = IRB.CreateCall(
              IRB.CreateIntToPtr(
                  PC, llvm::PointerType::get(
                          DetermineFunctionType(BinIdx, FuncIdx), 0)),
              ArgVec);
          Ret->setIsNoInline();

          if (!callee.retTy->isVoidTy()) {
            std::vector<unsigned> glbv;
            explode_tcg_global_set(glbv,
                                   callee.Analysis.defined & CallConvRets);
            std::sort(glbv.begin(), glbv.end(), [](unsigned a, unsigned b) {
              return std::find(CallConvRetArray.begin(), CallConvRetArray.end(),
                               a) < std::find(CallConvRetArray.begin(),
                                              CallConvRetArray.end(), b);
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
        }
      }

      auto eit_pair = boost::out_edges(bb, ICFG);
      assert(eit_pair.first != eit_pair.second &&
             std::next(eit_pair.first) == eit_pair.second);
      control_flow_t cf = *eit_pair.first;
      basic_block_t succ = boost::target(cf, ICFG);
      IRB.CreateBr(ICFG[succ].B);

      return 0;
    }
  }
#endif

  auto store = [&](unsigned glb) -> void {
    llvm::LoadInst *LI = IRB.CreateLoad(f.GlobalAllocaVec[glb]);
    LI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);

    llvm::StoreInst *SI = IRB.CreateStore(LI, CPUStateGlobalPointer(glb));
    SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
  };

  auto reload = [&](unsigned glb) -> void {
    llvm::LoadInst *LI = IRB.CreateLoad(CPUStateGlobalPointer(glb));
    LI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);

    llvm::StoreInst *SI = IRB.CreateStore(LI, f.GlobalAllocaVec[glb]);
    SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
  };

  auto store_stack_pointers = [&](void) -> void {
    store(tcg_frame_pointer_index);
    store(tcg_stack_pointer_index);
  };

  auto reload_stack_pointers = [&](void) -> void {
    reload(tcg_frame_pointer_index);
    reload(tcg_stack_pointer_index);
  };

  //
  // examine terminator multiple times
  //
  if (T.Type == TERMINATOR::UNREACHABLE) {
    IRB.CreateUnreachable();
    return 0;
  }

  switch (T.Type) {
  case TERMINATOR::CALL: {
    function_t &callee = Binary.Analysis.Functions[ICFG[bb].Term._call.Target];
    if (callee.IsABI)
      store_stack_pointers();
    break;
  }

  case TERMINATOR::RETURN:
    if (f.IsABI)
      store_stack_pointers();
    break;

  case TERMINATOR::INDIRECT_JUMP:
  case TERMINATOR::INDIRECT_CALL:
    store_stack_pointers();
    break;

  default:
    break;
  }

  switch (T.Type) {
  case TERMINATOR::CALL: {
    function_t &callee = Binary.Analysis.Functions[ICFG[bb].Term._call.Target];

    std::vector<llvm::Value *> ArgVec;
    {
      std::vector<unsigned> glbv;
      ExplodeFunctionArgs(callee, glbv);

      ArgVec.resize(glbv.size());
      std::transform(glbv.begin(), glbv.end(), ArgVec.begin(),
                     [&](unsigned glb) -> llvm::Value * {
                       if (f.GlobalAllocaVec[glb])
                         return IRB.CreateLoad(f.GlobalAllocaVec[glb]);
                       else
                         return IRB.CreateLoad(CPUStateGlobalPointer(glb));
                     });
    }

    llvm::CallInst *Ret = IRB.CreateCall(callee.F, ArgVec);

    if (!opts::NoInline &&
        callee.BasicBlocks.size() == 1 &&
        ICFG[callee.BasicBlocks.front()].IsSingleInstruction())
      ; /* allow this call to be inlined */
    else
      Ret->setIsNoInline();

    if (!DetermineFunctionType(callee)->getReturnType()->isVoidTy()) {
      std::vector<unsigned> glbv;
      ExplodeFunctionRets(callee, glbv);

      if (glbv.size() == 1) {
        assert(DetermineFunctionType(callee)->getReturnType()->isIntegerTy());
        IRB.CreateStore(Ret, f.GlobalAllocaVec[glbv.front()]);
      } else {
        for (unsigned i = 0; i < glbv.size(); ++i) {
          unsigned glb = glbv[i];

          llvm::Value *Ptr = f.GlobalAllocaVec[glb];
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
    // else                   ; trap
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

    // does the indirect jump have dynamic targets within the current function?
    if (eit_pair.first != eit_pair.second) {
      IRB.CreateCall(
          llvm::Intrinsic::getDeclaration(Module.get(), llvm::Intrinsic::trap));
      break; /* otherwise fallthrough */
    }
  }

  case TERMINATOR::INDIRECT_CALL: {
    llvm::Value *PC = IRB.CreateLoad(f.PCAlloca);

    const auto &DynTargets = ICFG[bb].DynTargets;
    if (DynTargets.empty()) {
      if (opts::Verbose)
        WithColor::warning() << "indirect branch has zero dyn targets\n";

      // apparently this is necessary
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
      ExplodeFunctionArgs(callee, glbv);

      ArgVec.resize(glbv.size());
      std::transform(glbv.begin(), glbv.end(), ArgVec.begin(),
                     [&](unsigned glb) -> llvm::Value * {
                       llvm::Value *Ptr = f.GlobalAllocaVec[glb];

                       if (!Ptr)
                         Ptr = CPUStateGlobalPointer(glb);

                       return IRB.CreateLoad(Ptr);
                     });
    }

    llvm::CallInst *Ret = IRB.CreateCall(
        IRB.CreateIntToPtr(
            PC, llvm::PointerType::get(DetermineFunctionType(callee), 0)),
        ArgVec);
    Ret->setIsNoInline();

    if (!DetermineFunctionType(callee)->getReturnType()->isVoidTy()) {
      std::vector<unsigned> glbv;
      ExplodeFunctionRets(callee, glbv);

      if (glbv.size() == 1) {
        assert(DetermineFunctionType(callee)->getReturnType()->isIntegerTy());
        if (f.GlobalAllocaVec[glbv.front()])
          IRB.CreateStore(Ret, f.GlobalAllocaVec[glbv.front()]);
      } else {
        for (unsigned i = 0; i < glbv.size(); ++i) {
          llvm::Value *Val =
              IRB.CreateExtractValue(Ret, llvm::ArrayRef<unsigned>(i));

          llvm::Value *Ptr = f.GlobalAllocaVec[glbv[i]];
          if (!Ptr)
            Ptr = CPUStateGlobalPointer(glbv[i]);

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
  case TERMINATOR::CALL: {
    function_t &callee = Binary.Analysis.Functions[ICFG[bb].Term._call.Target];
    if (callee.IsABI)
      reload_stack_pointers();
    break;
  }

  case TERMINATOR::INDIRECT_JUMP:
  case TERMINATOR::INDIRECT_CALL:
    reload_stack_pointers();
    break;

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
    if (DetermineFunctionType(f)->getReturnType()->isVoidTy()) {
      IRB.CreateRetVoid();
      break;
    }

    std::vector<unsigned> glbv;
    ExplodeFunctionRets(f, glbv);

    if (DetermineFunctionType(f)->getReturnType()->isIntegerTy()) {
      assert(glbv.size() == 1);
      assert(f.GlobalAllocaVec[glbv.front()]);

      IRB.CreateRet(IRB.CreateLoad(f.GlobalAllocaVec[glbv.front()]));
      break;
    }

    assert(DetermineFunctionType(f)->getReturnType()->isStructTy());
    assert(glbv.size() > 1);

    {
      unsigned idx = 0;
      llvm::Value *init =
          llvm::UndefValue::get(DetermineFunctionType(f)->getReturnType());
      llvm::Value *retVal = std::accumulate(
          glbv.begin(), glbv.end(), init,
          [&](llvm::Value *res, unsigned glb) -> llvm::Value * {
            return IRB.CreateInsertValue(res,
                                         IRB.CreateLoad(f.GlobalAllocaVec[glb]),
                                         llvm::ArrayRef<unsigned>(idx++));
          });
      IRB.CreateRet(retVal);
    }
    break;
  }

  default:
    break;
  }

  return 0;
}

void AnalyzeTCGHelper(helper_function_t &hf) {
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
  auto &GlobalAllocaVec = f.GlobalAllocaVec;
  auto &PCAlloca = f.PCAlloca;
  TCGContext *s = &TCG->_ctx;

  auto set = [&](llvm::Value *V, TCGTemp *ts) -> void {
    unsigned idx = temp_idx(ts);

    llvm::AllocaInst *Ptr =
        ts->temp_global ? GlobalAllocaVec.at(idx) : TempAllocaVec.at(idx);
    assert(Ptr);

    llvm::StoreInst *SI = IRB.CreateStore(V, Ptr);
    SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
  };

  auto get = [&](TCGTemp *ts) -> llvm::Value * {
    unsigned idx = temp_idx(ts);

    if (ts->temp_global && idx == tcg_env_index)
      return llvm::ConstantExpr::getPtrToInt(CPUStateGlobal, WordType());

    llvm::AllocaInst *Ptr =
        ts->temp_global ? GlobalAllocaVec.at(idx) : TempAllocaVec.at(idx);
    assert(Ptr);

    llvm::LoadInst *LI = IRB.CreateLoad(Ptr);
    LI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
    return LI;
  };

  static bool pcrel_flag = false;

  auto immediate_constant = [&](unsigned bits, TCGArg a) -> llvm::Value * {
    llvm::Value *res = [&]() {
      if (bits == 64)
        return IRB.getInt64(a);
      if (bits == 32)
        return IRB.getInt32(a);

      abort();
    }();

    if (pcrel_flag && bits == WordBits()) {
      pcrel_flag = false;

      return IRB.CreateAdd(res, f.PCRelVal);
    }

    return res;
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

      if (opts::PrintPCRel)
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
      if (opts::Verbose)
        WithColor::warning() << "INDEX_op_set_label: no terminator in block\n";
      assert(ExitBB);
      IRB.CreateBr(ExitBB);
    }

    llvm::BasicBlock* lblB = LabelVec.at(arg_label(op->args[0])->id);
    assert(lblB);
    IRB.SetInsertPoint(lblB);
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

    const helper_function_t &hf = LookupHelper(op);

    //
    // build the vector of arguments to pass
    //
    std::vector<llvm::Value *> ArgVec;
    ArgVec.resize(nb_iargs);

    // we'll need this in case a parameter is a pointer type
    llvm::FunctionType *FTy = hf.F->getFunctionType();

    TCGArg *const iargs_begin = &op->args[nb_oargs + 0];
    TCGArg *const iargs_end = &op->args[nb_oargs + nb_iargs];

    std::transform(iargs_begin,
                   iargs_end,
                   ArgVec.begin(),
                   [&](TCGArg &a) -> llvm::Value * {
                     TCGTemp *ts = arg_temp(a);
                     unsigned idx = temp_idx(ts);

                     if (idx == tcg_env_index) {
                       if (hf.Analysis.Simple)
                         return IRB.CreateAlloca(CPUStateType, 0, "env");
                       else
                         return CPUStateGlobal;
                     }

                     llvm::Value *res = get(ts);

                     unsigned i = &a - iargs_begin;
                     llvm::Type *ArgTy = FTy->getParamType(i);
                     if (ArgTy->isPointerTy())
                       res = IRB.CreateIntToPtr(res, ArgTy);

                     return res;
                   });

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

// Convert 32 bit to 64 bit and does sign/zero extension
#define __EXT_OP(opc_name, signE)                                              \
  case opc_name: {                                                             \
    llvm::Value *V = get(arg_temp(op->args[1]));                               \
    set(IRB.Create##signE##Ext(V, llvm::IntegerType::get(*Context, 64)),       \
        arg_temp(op->args[0]));                                                \
    break;                                                                     \
  }

    __EXT_OP(INDEX_op_extu_i32_i64, Z)
    __EXT_OP(INDEX_op_ext_i32_i64, S)

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
    llvm::LoadInst *Li = IRB.CreateLoad(Addr);                                 \
    Li->setMetadata(llvm::LLVMContext::MD_noalias, AliasScopeMetadata);        \
    llvm::Value *Val = Li;                                                     \
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
    llvm::StoreInst *St = IRB.CreateStore(Val, Addr);                          \
    St->setMetadata(llvm::LLVMContext::MD_noalias, AliasScopeMetadata);        \
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

#define __ARITH_OP_ROT(opc_name, op1, op2, bits)                               \
  case opc_name: {                                                             \
    llvm::Value *v1 = get(arg_temp(op->args[1]));                              \
    llvm::Value *v2 = get(arg_temp(op->args[2]));                              \
                                                                               \
    llvm::Value *v = IRB.CreateSub(                                            \
        llvm::ConstantInt::get(llvm::IntegerType::get(*Context, bits), bits),  \
        v2);                                                                   \
                                                                               \
    set(IRB.CreateOr(IRB.Create##op1(v1, v2), IRB.Create##op2(v1, v)),         \
        arg_temp(op->args[0]));                                                \
  } break;

    __ARITH_OP_ROT(INDEX_op_rotl_i32, Shl, LShr, 32)
    __ARITH_OP_ROT(INDEX_op_rotr_i32, LShr, Shl, 32)

    __ARITH_OP_ROT(INDEX_op_rotl_i64, Shl, LShr, 64)
    __ARITH_OP_ROT(INDEX_op_rotr_i64, LShr, Shl, 64)

#undef __ARITH_OP_ROT

#define __ANDC_OP(opc_name, bits)                                              \
  case opc_name: {                                                             \
    llvm::Value *v1 = get(arg_temp(op->args[1]));                              \
    llvm::Value *v2 = get(arg_temp(op->args[2]));                              \
                                                                               \
    llvm::Value *notv2 =                                                       \
        IRB.CreateXor(bits == 32 ? IRB.getInt32(0xffffffff)                    \
                                 : IRB.getInt64(0xffffffffffffffff),           \
                      v2);                                                     \
                                                                               \
    set(IRB.CreateAnd(v1, notv2), arg_temp(op->args[0]));                      \
  } break;

    __ANDC_OP(INDEX_op_andc_i32, 32)
    __ANDC_OP(INDEX_op_andc_i64, 64)

#undef __ANDC_OP

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
        IRB, DL, CPUStateGlobal, llvm::APInt(64, off), nullptr, Indices, "");  \
                                                                               \
    if (!Ptr)                                                                  \
      Ptr = IRB.CreateIntToPtr(                                                \
          IRB.CreateAdd(                                                       \
              llvm::ConstantExpr::getPtrToInt(CPUStateGlobal, WordType()),     \
              IRB.getIntN(WordBits(), off)),                                   \
          llvm::PointerType::get(IRB.getIntNTy(memBits), 0));                  \
                                                                               \
    assert(Ptr->getType()->isPointerTy());                                     \
                                                                               \
    Ptr = IRB.CreatePointerCast(                                               \
        Ptr, llvm::PointerType::get(IRB.getIntNTy(memBits), 0));               \
                                                                               \
    llvm::Value *Val = IRB.CreateLoad(Ptr);                                    \
    if (memBits < regBits)                                                     \
      Val = IRB.Create##signE##Ext(Val, IRB.getIntNTy(regBits));               \
                                                                               \
    set(Val, arg_temp(op->args[0]));                                           \
    break;                                                                     \
  }

    __LD_OP(INDEX_op_ld8u_i32,  8,  32, Z)
    __LD_OP(INDEX_op_ld8s_i32,  8,  32, S)
    __LD_OP(INDEX_op_ld16u_i32, 16, 32, Z)
    __LD_OP(INDEX_op_ld16s_i32, 16, 32, S)
    __LD_OP(INDEX_op_ld_i32,    32, 32, Z)

    __LD_OP(INDEX_op_ld8u_i64,  8,  64, Z)
    __LD_OP(INDEX_op_ld8s_i64,  8,  64, S)
    __LD_OP(INDEX_op_ld16u_i64, 16, 64, Z)
    __LD_OP(INDEX_op_ld16s_i64, 16, 64, S)
    __LD_OP(INDEX_op_ld32u_i64, 32, 64, Z)
    __LD_OP(INDEX_op_ld32s_i64, 32, 64, S)
    __LD_OP(INDEX_op_ld_i64,    64, 64, Z)

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
    if (regBits > memBits)                                                     \
      Val = IRB.CreateTrunc(Val, IRB.getIntNTy(memBits));                      \
                                                                               \
    llvm::SmallVector<llvm::Value *, 4> Indices;                               \
    llvm::Value *Ptr = llvm::getNaturalGEPWithOffset(                          \
        IRB, DL, CPUStateGlobal, llvm::APInt(64, off), nullptr, Indices, "");  \
    if (!Ptr)                                                                  \
      Ptr = IRB.CreateIntToPtr(                                                \
          IRB.CreateAdd(                                                       \
              llvm::ConstantExpr::getPtrToInt(CPUStateGlobal, WordType()),     \
              IRB.getIntN(WordBits(), off)),                                   \
          llvm::PointerType::get(IRB.getIntNTy(memBits), 0));                  \
                                                                               \
    assert(Ptr->getType()->isPointerTy());                                     \
                                                                               \
    Ptr = IRB.CreatePointerCast(                                               \
        Ptr, llvm::PointerType::get(IRB.getIntNTy(memBits), 0));               \
    IRB.CreateStore(Val, Ptr);                                                 \
    break;                                                                     \
  }

    __ST_OP(INDEX_op_st8_i64, 8, 64)
    __ST_OP(INDEX_op_st16_i64, 16, 64)
    __ST_OP(INDEX_op_st32_i64, 32, 64)
    __ST_OP(INDEX_op_st_i64, 64, 64)
    __ST_OP(INDEX_op_st_i32, 32, 32)

#undef __ST_OP

  case INDEX_op_br: {
    llvm::BasicBlock* lblB = LabelVec.at(arg_label(op->args[0])->id);
    IRB.CreateBr(lblB);
    break;
  }

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
    llvm::BasicBlock *lblBB = LabelVec.at(lblidx);                             \
    assert(lblBB);                                                             \
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

#undef __OP_MOVCOND_COND
#undef __OP_MOVCOND

#define __OP_MOVCOND_COND(tcg_cond, cond)                                      \
  case tcg_cond:                                                               \
    CondV = IRB.CreateICmp##cond(get(arg_temp(op->args[1])),                   \
                                 get(arg_temp(op->args[2])));                  \
    break;

#define __OP_MOVCOND(opc_name, bits)                                           \
  case opc_name: {                                                             \
    llvm::Value *CondV;                                                        \
    switch (op->args[5]) {                                                     \
      __OP_MOVCOND_COND(TCG_COND_EQ, EQ)                                       \
      __OP_MOVCOND_COND(TCG_COND_NE, NE)                                       \
      __OP_MOVCOND_COND(TCG_COND_LT, SLT)                                      \
      __OP_MOVCOND_COND(TCG_COND_GE, SGE)                                      \
      __OP_MOVCOND_COND(TCG_COND_LE, SLE)                                      \
      __OP_MOVCOND_COND(TCG_COND_GT, SGT)                                      \
      __OP_MOVCOND_COND(TCG_COND_LTU, ULT)                                     \
      __OP_MOVCOND_COND(TCG_COND_GEU, UGE)                                     \
      __OP_MOVCOND_COND(TCG_COND_LEU, ULE)                                     \
      __OP_MOVCOND_COND(TCG_COND_GTU, UGT)                                     \
    default:                                                                   \
      assert(false);                                                           \
    }                                                                          \
    llvm::Value *SelV = IRB.CreateSelect(CondV,                                \
                                         get(arg_temp(op->args[3])),           \
                                         get(arg_temp(op->args[4])));          \
    set(SelV, arg_temp(op->args[0]));                                          \
  } break;

    __OP_MOVCOND(INDEX_op_movcond_i32, 32)
    __OP_MOVCOND(INDEX_op_movcond_i64, 64)

#undef __OP_MOVCOND_COND
#undef __OP_MOVCOND

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

#define __ARITH_OP_BSWAP(opc_name, sBits, bits)                                \
  case opc_name: {                                                             \
    llvm::Value *v1 = get(arg_temp(op->args[1]));                              \
    assert(v1->getType() == llvm::IntegerType::get(*Context, bits));           \
    llvm::Type *Tys[] = {llvm::IntegerType::get(*Context, sBits)};             \
    llvm::Function *bswap =                                                    \
        llvm::Intrinsic::getDeclaration(Module.get(), llvm::Intrinsic::bswap,  \
                                        llvm::ArrayRef<llvm::Type *>(Tys, 1)); \
    llvm::Value *v =                                                           \
        IRB.CreateTrunc(v1, llvm::IntegerType::get(*Context, sBits));          \
    set(IRB.CreateZExt(IRB.CreateCall(bswap, v),                               \
                       llvm::IntegerType::get(*Context, bits)),                \
        arg_temp(op->args[0]));                                                \
  } break;

    __ARITH_OP_BSWAP(INDEX_op_bswap16_i32, 16, 32)
    __ARITH_OP_BSWAP(INDEX_op_bswap32_i32, 32, 32)

    __ARITH_OP_BSWAP(INDEX_op_bswap16_i64, 16, 64)
    __ARITH_OP_BSWAP(INDEX_op_bswap32_i64, 32, 64)
    __ARITH_OP_BSWAP(INDEX_op_bswap64_i64, 64, 64)

#undef __ARITH_OP_BSWAP

#define __CLZ_OP(opc_name, bits)                                               \
  case opc_name: {                                                             \
    llvm::Type *Tys[] = {llvm::IntegerType::get(*Context, bits)};              \
    llvm::Function *ctlzF =                                                    \
        llvm::Intrinsic::getDeclaration(Module.get(), llvm::Intrinsic::ctlz,   \
                                        llvm::ArrayRef<llvm::Type *>(Tys, 1)); \
    llvm::Value *v1 = get(arg_temp(op->args[1]));                              \
    llvm::Value *v2 = get(arg_temp(op->args[2]));                              \
                                                                               \
    llvm::Value *CondV = IRB.CreateICmpNE(v1, IRB.getIntN(bits, 0));           \
    llvm::Value *ctlzArgs[] = {v1, IRB.getTrue()};                             \
    llvm::Value *v =                                                           \
        IRB.CreateSelect(CondV, IRB.CreateCall(ctlzF, ctlzArgs), v2);          \
                                                                               \
    set(v, arg_temp(op->args[0]));                                             \
    break;                                                                     \
  }

    __CLZ_OP(INDEX_op_clz_i32, 32)
    __CLZ_OP(INDEX_op_clz_i64, 64)

#undef __CLZ_OP

#define __CTZ_OP(opc_name, bits)                                               \
  case opc_name: {                                                             \
    llvm::Type *Tys[] = {llvm::IntegerType::get(*Context, bits)};              \
    llvm::Function *cttzF =                                                    \
        llvm::Intrinsic::getDeclaration(Module.get(), llvm::Intrinsic::cttz,   \
                                        llvm::ArrayRef<llvm::Type *>(Tys, 1)); \
    llvm::Value *v1 = get(arg_temp(op->args[1]));                              \
    llvm::Value *v2 = get(arg_temp(op->args[2]));                              \
                                                                               \
    llvm::Value *CondV = IRB.CreateICmpNE(v1, IRB.getIntN(bits, 0));           \
    llvm::Value *ctlzArgs[] = {v1, IRB.getTrue()};                             \
    llvm::Value *v =                                                           \
        IRB.CreateSelect(CondV, IRB.CreateCall(cttzF, ctlzArgs), v2);          \
                                                                               \
    set(v, arg_temp(op->args[0]));                                             \
    break;                                                                     \
  }

    __CTZ_OP(INDEX_op_ctz_i32, 32)
    __CTZ_OP(INDEX_op_ctz_i64, 64)

#undef __CTZ_OP

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
