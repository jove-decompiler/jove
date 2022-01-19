#include <boost/icl/interval_set.hpp>
#include <boost/icl/split_interval_map.hpp>
#include <llvm/ADT/StringRef.h>
#include <llvm/ADT/ArrayRef.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/WithColor.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Object/ELFObjectFile.h>
#include <set>

struct section_properties_t {
  std::string name;
  llvm::ArrayRef<uint8_t> contents;

  bool w, x;
  bool initArray;
  bool finiArray;

  bool operator==(const section_properties_t &sect) const {
    return name == sect.name;
  }

  bool operator<(const section_properties_t &sect) const {
    return name < sect.name;
  }
};
typedef std::set<section_properties_t> section_properties_set_t;

//
// forward decls
//
namespace llvm {
class Function;
class BasicBlock;
class AllocaInst;
class Type;
class Value;
class LoadInst;
class CallInst;
class DISubprogram;
class GlobalIFunc;
class GlobalVariable;
namespace object {
class Binary;
}
}

namespace jove {

//
// a symbol is basically a name and a value. in a program compiled from C, the
// value of a symbol is roughly the address of a global. Each defined symbol has
// an address, and the dynamic linker will resolve each undefined symbol by
// finding a defined symbol with the same name.
//
struct symbol_t {
  std::string Name;
  std::string Vers;
  uint64_t Addr;

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

  struct {
    bool IsDefault;
  } Visibility;

  bool IsUndefined() const { return Addr == 0; }
  bool IsDefined() const { return !IsUndefined(); }
};

struct hook_t;

#include "elf.hpp"

}

#define JOVE_EXTRA_BB_PROPERTIES                                               \
  tcg_global_set_t IN, OUT;                                                    \
                                                                               \
  void Analyze(binary_index_t);                                                \
                                                                               \
  llvm::BasicBlock *B = nullptr;

#define JOVE_EXTRA_FN_PROPERTIES                                               \
  binary_index_t BIdx;                                                         \
  function_index_t FIdx;                                                       \
  std::vector<basic_block_t> BasicBlocks;                                      \
  std::set<basic_block_t> BasicBlocksSet;                                      \
  std::vector<basic_block_t> ExitBasicBlocks;                                  \
  const hook_t *hook = nullptr;                                                \
  llvm::Function *PreHook = nullptr;                                           \
  llvm::GlobalVariable *PreHookClunk = nullptr;                                \
  llvm::Function *PostHook = nullptr;                                          \
  llvm::GlobalVariable *PostHookClunk = nullptr;                               \
                                                                               \
  struct {                                                                     \
    llvm::GlobalIFunc *IFunc = nullptr;                                        \
  } _resolver;                                                                 \
                                                                               \
  struct {                                                                     \
    llvm::AllocaInst *SavedCPUState = nullptr;                                 \
  } _signal_handler;                                                           \
                                                                               \
  bool IsNamed = false;                                                        \
                                                                               \
  std::vector<symbol_t> Syms;                                                  \
                                                                               \
  bool IsLeaf;                                                                 \
                                                                               \
  void Analyze(void);                                                          \
                                                                               \
  llvm::Function *F = nullptr;

#define JOVE_EXTRA_BIN_PROPERTIES                                              \
  std::unique_ptr<llvm::object::Binary> ObjectFile;                            \
  struct {                                                                     \
    DynRegionInfo DynamicTable;                                                \
    llvm::StringRef DynamicStringTable;                                        \
    const Elf_Shdr *SymbolVersionSection;                                      \
    std::vector<VersionMapEntry> VersionMap;                                   \
    llvm::Optional<DynRegionInfo> OptionalDynSymRegion;                        \
  } _elf;                                                                      \
  llvm::GlobalVariable *FunctionsTable = nullptr;                              \
  llvm::Function *SectsF = nullptr;                                            \
  std::unordered_map<tcg_uintptr_t, function_index_t> FuncMap;                 \
  tcg_uintptr_t SectsStartAddr = 0;                                            \
  tcg_uintptr_t SectsEndAddr = 0;

#include "tcgcommon.hpp"

#include <cctype>
#include <tuple>
#include <memory>
#include <sstream>
#include <fstream>
#include <unordered_set>
#include <random>
#include <boost/filesystem.hpp>
#include <boost/graph/graphviz.hpp>
#include <llvm/Analysis/TargetTransformInfo.h>
#include <llvm/ADT/Statistic.h>
#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DIBuilder.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/GlobalAlias.h>
#include <llvm/IR/GlobalIFunc.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/MDBuilder.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PatternMatch.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IR/IntrinsicInst.h>
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
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/DataTypes.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Host.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/ScopedPrinter.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/ToolOutputFile.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Target/TargetOptions.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/Transforms/Utils/ModuleUtils.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/LowerMemIntrinsics.h>
#include <llvm/Analysis/Passes.h>
#include <llvm/Support/Error.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "jove/jove.h"
#include <boost/algorithm/string/replace.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/dll/runtime_symbol_info.hpp>
#include <boost/dynamic_bitset.hpp>
#include <boost/format.hpp>
#include <boost/graph/adj_list_serialize.hpp>
#include <boost/graph/copy.hpp>
#include <boost/graph/depth_first_search.hpp>
#include <boost/graph/filtered_graph.hpp>
#include <boost/range/adaptor/reversed.hpp>
#include <boost/serialization/bitset.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/container_hash/extensions.hpp>

#include "jove_macros.h"

#define GET_INSTRINFO_ENUM
#include "LLVMGenInstrInfo.hpp"

#define GET_REGINFO_ENUM
#include "LLVMGenRegisterInfo.hpp"

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

#include "analyze.hpp"

namespace opts {
static cl::OptionCategory JoveCategory("Specific Options");

static cl::opt<std::string> jv("decompilation", cl::desc("Jove decompilation"),
                               cl::Required, cl::value_desc("filename"),
                               cl::cat(JoveCategory));

static cl::alias jvAlias("d", cl::desc("Alias for -decompilation."),
                         cl::aliasopt(jv), cl::cat(JoveCategory));

static cl::opt<std::string> Binary("binary", cl::desc("Binary to translate"),
                                   cl::value_desc("path"),
                                   cl::cat(JoveCategory));

static cl::alias BinaryAlias("b", cl::desc("Alias for -binary."),
                             cl::aliasopt(Binary), cl::cat(JoveCategory));

static cl::opt<std::string> BinaryIndex("binary-index",
                                        cl::desc("Index of binary to translate"),
                                        cl::cat(JoveCategory));

static cl::opt<std::string> Output("output", cl::desc("Output bitcode"),
                                   cl::Required, cl::value_desc("filename"),
                                   cl::cat(JoveCategory));

static cl::alias OutputAlias("o", cl::desc("Alias for -output."),
                             cl::aliasopt(Output), cl::cat(JoveCategory));

static cl::opt<std::string> VersionScript(
    "version-script", cl::desc("Output version script file for use with ld"),
    cl::Required, cl::value_desc("filename"), cl::cat(JoveCategory));

static cl::opt<bool>
    Trace("trace",
          cl::desc("Instrument code to output basic block execution trace"),
          cl::cat(JoveCategory));

static cl::opt<bool>
    NoFixupFSBase("no-fixup-fsbase",
                  cl::desc("Don't fixup FS-relative references"),
                  cl::cat(JoveCategory));

static cl::opt<bool> PrintPCRel("pcrel",
                                cl::desc("Print pc-relative references"),
                                cl::cat(JoveCategory));

static cl::opt<bool>
    PrintDefAndUse("print-def-and-use",
                   cl::desc("Print use_B and def_B for every basic block B"),
                   cl::cat(JoveCategory));

static cl::opt<bool>
    PrintLiveness("print-liveness",
                  cl::desc("Print liveness for every function"),
                  cl::cat(JoveCategory));

static cl::opt<bool>
    Verbose("verbose",
            cl::desc("Print extra information for debugging purposes"),
            cl::cat(JoveCategory));

static cl::alias VerboseAlias("v", cl::desc("Alias for -verbose."),
                              cl::aliasopt(Verbose), cl::cat(JoveCategory));

static cl::opt<bool>
    DumpTCG("dump-tcg",
            cl::desc("Dump TCG operations when translating basic blocks"),
            cl::cat(JoveCategory));
static cl::opt<std::string> ForAddr("for-addr",
                                    cl::desc("Do stuff for the given address"),
                                    cl::cat(JoveCategory));

#if defined(LLVM_ENABLE_STATS) && LLVM_ENABLE_STATS
static cl::opt<bool>
    OptStats("opt-stats",
             cl::desc("Print statistics during bitcode optimization"),
             cl::cat(JoveCategory));
#endif

static cl::opt<bool> Optimize("optimize", cl::desc("Optimize bitcode"),
                              cl::cat(JoveCategory));

static cl::opt<bool>
    VerifyBitcode("verify-bitcode",
                  cl::desc("run llvm::verifyModule on the bitcode"),
                  cl::cat(JoveCategory));

static cl::opt<bool> Graphviz("graphviz",
                              cl::desc("Dump graphviz of flow graphs"),
                              cl::cat(JoveCategory));

static cl::opt<bool> DumpPreOpt1("dump-pre-opt",
                                 cl::desc("Dump bitcode before DoOptimize()"),
                                 cl::cat(JoveCategory));

static cl::opt<bool> DumpPostOpt1("dump-post-opt",
                                  cl::desc("Dump bitcode after DoOptimize()"),
                                  cl::cat(JoveCategory));

static cl::opt<bool>
    DumpPreFSBaseFixup("dump-pre-fsbase-fixup",
                       cl::desc("Dump bitcode after fsbase fixup"),
                       cl::cat(JoveCategory));

static cl::opt<bool>
    DumpPostFSBaseFixup("dump-post-fsbase-fixup",
                        cl::desc("Dump bitcode after fsbase fixup"),
                        cl::cat(JoveCategory));

static cl::opt<bool> DFSan("dfsan",
                           cl::desc("Instrument code with DataFlowSanitizer"),
                           cl::cat(JoveCategory));

static cl::opt<std::string>
    DFSanOutputModuleID("dfsan-output-module-id",
                        cl::desc("Write to file containing module ID (which is "
                                 "found from DFSanModuleID metadata"),
                        cl::value_desc("filename"), cl::cat(JoveCategory));

static bool CallStack, CheckEmulatedReturnAddress;

static cl::opt<bool>
    ForeignLibs("foreign-libs",
                cl::desc("only recompile the executable itself; "
                         "treat all other binaries as \"foreign\""),
                cl::cat(JoveCategory));

#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
static cl::opt<bool>
    MipsT9Hack("mips-t9-hack",
               cl::desc("Assume t9 is the address of the "
                        "function for all functions, not "
                        "just ABI's. Can result in easier-to-read bitcode"),
               cl::cat(JoveCategory));
#endif

static cl::list<std::string>
    PinnedGlobals("pinned-globals", cl::CommaSeparated,
                  cl::value_desc("glb_1,glb_2,...,glb_n"),
                  cl::desc("force specified TCG globals to always go through CPUState"),
                  cl::cat(JoveCategory));

} // namespace opts

namespace jove {
static int llvm(void);

static struct {
  char **argv;
} cmdline;

}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::HideUnrelatedOptions({&opts::JoveCategory, &llvm::ColorCategory});
  cl::AddExtraVersionPrinter([](llvm::raw_ostream &OS) -> void {
    OS << "jove version " JOVE_VERSION "\n";
  });
  cl::ParseCommandLineOptions(argc, argv, "Jove LLVM\n");

  if (!fs::exists(opts::jv)) {
    llvm::errs() << "decompilation does not exist\n";
    return 1;
  }

  jove::cmdline.argv = argv;
  opts::CallStack = opts::DFSan;
  opts::CheckEmulatedReturnAddress = opts::DFSan;

  return jove::llvm();
}


namespace llvm {

using IRBuilderTy = IRBuilder<ConstantFolder, IRBuilderDefaultInserter>;

}

namespace jove {

//
// Types
//

typedef boost::format fmt;

struct binary_state_t {
};

struct section_t {
  std::string Name;
  llvm::ArrayRef<uint8_t> Contents;
  target_ulong Addr;
  unsigned Size;

  bool initArray;
  bool finiArray;

  struct {
    boost::icl::split_interval_set<target_ulong> Intervals;
    std::map<unsigned, llvm::Constant *> Constants;
    std::map<unsigned, llvm::Type *> Types;
  } Stuff;

  llvm::StructType *T;
};

typedef std::tuple<llvm::MCDisassembler &, const llvm::MCSubtargetInfo &,
                   llvm::MCInstPrinter &>
    disas_t;

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

    TPOFF,
    TPMOD
  } Type;

  target_ulong Addr;
  unsigned SymbolIndex;
  target_ulong Addend;

  llvm::Type *T; /* XXX */
  llvm::Constant *C; /* XXX */

  llvm::SmallString<32> RelocationTypeName;
};

static relocation_t::TYPE
relocation_type_of_elf_rela_type(uint64_t elf_rela_ty) {
  switch (elf_rela_ty) {
#include "relocs.hpp"
  default:
    return relocation_t::TYPE::NONE;
  }
};

static const char *string_of_reloc_type(relocation_t::TYPE ty) {
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
  case relocation_t::TYPE::TPMOD:
    return "TPMOD";
  }

  __builtin_trap();
  __builtin_unreachable();
};

static const char *string_of_sym_type(symbol_t::TYPE ty) {
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

  __builtin_trap();
  __builtin_unreachable();
}

static const char *string_of_sym_binding(symbol_t::BINDING b) {
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

  __builtin_trap();
  __builtin_unreachable();
}

static symbol_t::TYPE sym_type_of_elf_sym_type(unsigned ty) {
  switch (ty) {
  case llvm::ELF::STT_NOTYPE:  return symbol_t::TYPE::NONE;
  case llvm::ELF::STT_OBJECT:  return symbol_t::TYPE::DATA;
  case llvm::ELF::STT_FUNC:    return symbol_t::TYPE::FUNCTION;
  case llvm::ELF::STT_SECTION: return symbol_t::TYPE::DATA;
  case llvm::ELF::STT_FILE:    return symbol_t::TYPE::DATA;
  case llvm::ELF::STT_COMMON:  return symbol_t::TYPE::DATA;
  case llvm::ELF::STT_TLS:     return symbol_t::TYPE::TLSDATA;

  default:
    return symbol_t::TYPE::NONE;
  }
}

static symbol_t::BINDING sym_binding_of_elf_sym_binding(unsigned ty) {
  switch (ty) {
  case llvm::ELF::STB_LOCAL:  return symbol_t::BINDING::LOCAL;
  case llvm::ELF::STB_GLOBAL: return symbol_t::BINDING::GLOBAL;
  case llvm::ELF::STB_WEAK:   return symbol_t::BINDING::WEAK;

  default:
    return symbol_t::BINDING::NONE;
  }
}

static int tcg_global_index_of_name(const char *nm) {
  for (int i = 0; i < TCG->_ctx.nb_globals; i++) {
    if (strcmp(TCG->_ctx.temps[i].name, nm) == 0)
      return i;
  }

  return -1;
}

//
// Globals
//
static binary_index_t BinaryIndex = invalid_binary_index;

static std::unordered_map<std::string,
                          std::set<std::pair<binary_index_t, function_index_t>>>
    ExportedFunctions;

//static std::vector<llvm::CallInst *> MemCopiesToExpand;

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

static std::vector<symbol_t> SymbolTable;
static std::vector<relocation_t> RelocationTable;
static std::unordered_set<target_ulong> ConstantRelocationLocs;
static target_ulong libcEarlyInitAddr;

static llvm::GlobalVariable *CPUStateGlobal;
static llvm::Type *CPUStateType;

static llvm::GlobalVariable *TraceGlobal;
static llvm::GlobalVariable *CallStackGlobal;
static llvm::GlobalVariable *CallStackBeginGlobal;

static llvm::GlobalVariable *JoveFunctionTablesGlobal;
static llvm::GlobalVariable *JoveForeignFunctionTablesGlobal;
static llvm::Function *JoveRecoverDynTargetFunc;
static llvm::Function *JoveRecoverBasicBlockFunc;
static llvm::Function *JoveRecoverReturnedFunc;
static llvm::Function *JoveRecoverFunctionFunc;

static llvm::Function *JoveInstallForeignFunctionTables;

#define __THUNK(n, i, data)                                                    \
  static llvm::Function *JoveThunk##i##Func;

#if defined(TARGET_X86_64)
BOOST_PP_REPEAT(7, __THUNK, void)
#elif defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
BOOST_PP_REPEAT(5, __THUNK, void)
#elif defined(TARGET_I386)
BOOST_PP_REPEAT(4, __THUNK, void)
#elif defined(TARGET_AARCH64)
BOOST_PP_REPEAT(9, __THUNK, void)
#else
#error
#endif

#undef __THUNK

static llvm::Function *JoveFail1Func;

static llvm::Function *JoveAllocStackFunc;
static llvm::Function *JoveFreeStackFunc;

//
// DFSan
//
static llvm::Function *JoveCheckReturnAddrFunc;
static llvm::Function *JoveLogFunctionStart;
static llvm::GlobalVariable *JoveLogFunctionStartClunk;
static llvm::Function *DFSanFiniFunc;
static llvm::GlobalVariable *DFSanFiniClunk;

static llvm::GlobalVariable *SectsGlobal;
static llvm::GlobalVariable *ConstSectsGlobal;
static llvm::GlobalVariable *TLSSectsGlobal;

static llvm::GlobalVariable *TLSModGlobal;

static llvm::MDNode *AliasScopeMetadata;

static std::unique_ptr<llvm::DIBuilder> DIBuilder;

static std::map<target_ulong, llvm::Constant *> TPOFFHack;

static struct {
  struct {
    // in memory, the .tbss section is allocated directly following the .tdata
    // section, with the aligment obeyed
    unsigned Size;
  } Data;

  target_ulong Beg, End;

  bool Present;
} ThreadLocalStorage;

static struct {
  llvm::DIFile *File;
  llvm::DICompileUnit *CompileUnit;
} DebugInformation;

static std::unordered_map<std::string, unsigned> GlobalSymbolDefinedSizeMap;

static std::unordered_map<target_ulong, std::set<llvm::StringRef>>
    TLSValueToSymbolMap;
static std::unordered_map<target_ulong, unsigned>
    TLSValueToSizeMap;

static boost::icl::split_interval_set<target_ulong> AddressSpaceObjects;

static std::unordered_map<target_ulong, std::set<llvm::StringRef>>
    AddrToSymbolMap;
static std::unordered_map<target_ulong, unsigned>
    AddrToSizeMap;
static std::unordered_set<target_ulong>
    TLSObjects; // XXX

static std::unordered_map<llvm::Function *, llvm::Function *> CtorStubMap;

static std::unordered_set<target_ulong> ExternGlobalAddrs;

static std::unordered_set<llvm::Function *> FunctionsToInline;

static struct {
  std::unordered_map<std::string, std::unordered_set<std::string>> Table;
} VersionScript;

// set {int}0x08053ebc = 0xf7fa83f0
static std::map<std::pair<target_ulong, unsigned>,
                std::pair<binary_index_t, std::pair<target_ulong, unsigned>>>
    CopyRelocMap;

static std::map<target_ulong, dynamic_target_t> IRELATIVEHack;

#define JOVE_PAGE_SIZE 4096
#define JOVE_STACK_SIZE (512 * JOVE_PAGE_SIZE)

//
// Stages
//
static int InitStateForBinaries(void);
static int CreateModule(void);
static int PrepareToTranslateCode(void);
static int ProcessDynamicTargets(void);
static int ProcessBinaryRelocations(void);
static int ProcessIFuncResolvers(void);
static int ProcessExportedFunctions(void);
static int CreateFunctions(void);
static int CreateFunctionTables(void);
static int ProcessBinaryTLSSymbols(void);
static int ProcessDynamicSymbols(void);
static int LocateHooks(void);
static int CreateTLSModGlobal(void);
static int CreateSectionGlobalVariables(void);
static int ProcessDynamicSymbols2(void);
static int CreateFunctionTable(void);
static int FixupHelperStubs(void);
static int CreateNoAliasMetadata(void);
static int CreateTPOFFCtorHack(void);
static int CreateIRELATIVECtorHack(void);
static int CreateCopyRelocationHack(void);
static int TranslateFunctions(void);
static int InlineCalls(void);
static int PrepareToOptimize(void);
static int ConstifyRelocationSectionPointers(void);
static int InternalizeStaticFunctions(void);
static int InternalizeSections(void);
static int ExpandMemoryIntrinsicCalls(void);
static int ReplaceAllRemainingUsesOfConstSections(void);
static int DFSanInstrument(void);
static int RenameFunctionLocals(void);
static int WriteVersionScript(void);
static int WriteModule(void);

static int DoOptimize(void);
static void DumpModule(const char *);

int llvm(void) {
  //
  // parse decompilation
  //
  {
    std::string path = fs::is_directory(opts::jv)
                           ? (opts::jv + "/decompilation.jv")
                           : opts::jv;

    std::ifstream ifs(path);

    boost::archive::text_iarchive ia(ifs);
    ia >> Decompilation;
  }

  //
  // binary index (cmdline)
  //
  if (!opts::Binary.empty()) {
    for (binary_index_t BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx) {
      binary_t &b = Decompilation.Binaries[BIdx];

      if (fs::path(b.Path).filename().string() == opts::Binary) {
        if (b.IsDynamicLinker) {
          WithColor::error() << "given binary is dynamic linker\n";
          return 1;
        }

        if (b.IsVDSO) {
          WithColor::error() << "given binary is [vdso]\n";
          return 1;
        }

        BinaryIndex = BIdx;
      }
    }

    WithColor::error() << "no binary associated with given path\n";
    return 1;
  }
  if (!opts::BinaryIndex.empty()) {
    int idx = atoi(opts::BinaryIndex.c_str());

    if (idx < 0 || idx >= Decompilation.Binaries.size()) {
      WithColor::error() << "invalid binary index supplied\n";
      return 1;
    }

    BinaryIndex = idx;
  }

  if (opts::ForeignLibs) {
    if (!Decompilation.Binaries[BinaryIndex].IsExecutable) {
      WithColor::error() << "--foreign-libs specified but given binary is not "
                            "the executable\n";
      return 1;
    }
  }

  if (int rc = InitStateForBinaries())
    return rc;

  if (int rc = CreateModule())
    return rc;

  if (int rc = PrepareToTranslateCode())
    return rc;

  //
  // pinned globals (cmdline)
  //
  for (const std::string &PinnedGlobalName : opts::PinnedGlobals) {
    int idx = tcg_global_index_of_name(PinnedGlobalName.c_str());
    if (idx < 0) {
      WithColor::warning() << llvm::formatv(
          "unknown global {0} (--pinned-globals); ignoring\n", idx);
      continue;
    }

    CmdlinePinnedEnvGlbs.set(idx);
  }

  return ProcessDynamicTargets()
      || ProcessBinaryRelocations()
      || ProcessIFuncResolvers()
      || ProcessExportedFunctions()
      || CreateFunctions()
      || CreateFunctionTables()
      || ProcessBinaryTLSSymbols()
      || ProcessDynamicSymbols()
      || (opts::DFSan ? LocateHooks() : 0)
      || CreateTLSModGlobal()
      || CreateSectionGlobalVariables()
      || ProcessDynamicSymbols2()
      || CreateFunctionTable()
      || FixupHelperStubs()
      || CreateNoAliasMetadata()
      || CreateTPOFFCtorHack()
      || CreateIRELATIVECtorHack()
      || CreateCopyRelocationHack()
      || TranslateFunctions()
      || InternalizeSections()
      || (opts::Optimize ? PrepareToOptimize() : 0)
      || (opts::DumpPreOpt1 ? (RenameFunctionLocals(), DumpModule("pre.opt1"), 1) : 0)
      || (opts::Optimize ? DoOptimize() : 0)
      || (opts::DumpPostOpt1 ? (RenameFunctionLocals(), DumpModule("post.opt1"), 1) : 0)
      || ExpandMemoryIntrinsicCalls()
      || ReplaceAllRemainingUsesOfConstSections()
      || (opts::DFSan ? DFSanInstrument() : 0)
      || RenameFunctionLocals()
      || (!opts::VersionScript.empty() ? WriteVersionScript() : 0)
      || WriteModule();
}

static void DumpModule(const char *suffix) {
  //
  // deliberately do not try and verify the module since it may be in an
  // undefined state
  //
  std::string s;
  {
    llvm::raw_string_ostream os(s);
    os << *Module << '\n';
  }

  {
    fs::path dumpOutputPath =
        fs::path(opts::Output).replace_extension(std::string(suffix) + ".ll");

    WithColor::note() << llvm::formatv("dumping module to {0} ({1})\n",
                                       dumpOutputPath.c_str(), suffix);

    std::ofstream ofs(dumpOutputPath.c_str());
    ofs << s;
  }

  {
    fs::path dumpOutputPath =
        fs::path(opts::Output).replace_extension(std::string(suffix) + ".bc");

    WithColor::note() << llvm::formatv("dumping module to {0} ({1})\n",
                                       dumpOutputPath.c_str(), suffix);

    std::error_code EC;
    llvm::ToolOutputFile Out(dumpOutputPath.c_str(), EC, llvm::sys::fs::F_None);
    if (EC) {
      WithColor::error() << EC.message() << '\n';
      return;
    }

    llvm::WriteBitcodeToFile(*Module, Out.os());

    // Declare success.
    Out.keep();
  }
}

void _qemu_log(const char *cstr) {
  llvm::errs() << cstr;
}

static bool isDFSan(void) {
  return opts::DFSan;
}

static bool is_integral_size(unsigned n) {
  return n == 1 || n == 2 || n == 4 || n == 8;
}

static constexpr unsigned WordBytes(void) {
  return sizeof(target_ulong);
}

static constexpr unsigned WordBits(void) {
  return WordBytes() * 8;
}

static llvm::IntegerType *WordType(void) {
  return llvm::Type::getIntNTy(*Context, WordBits());
}

static llvm::Type *PointerToWordType(void) {
  return llvm::PointerType::get(WordType(), 0);
}

static llvm::Type *PPointerType(void) {
  return llvm::PointerType::get(PointerToWordType(), 0);
}

static llvm::Type *VoidType(void) {
  return llvm::Type::getVoidTy(*Context);
}

static llvm::Type *VoidFunctionPointer(void) {
  llvm::FunctionType *FTy = llvm::FunctionType::get(VoidType(), false);
  return llvm::PointerType::get(FTy, 0);
}

static bool
DynTargetNeedsThunkPred(std::pair<binary_index_t, function_index_t> DynTarget) {
  binary_index_t BIdx = DynTarget.first;
  const binary_t &binary = Decompilation.Binaries[BIdx];

  if (opts::ForeignLibs)
    return !binary.IsExecutable;

  return binary.IsDynamicLinker || binary.IsVDSO;
}

static llvm::Constant *SectionPointer(target_ulong Addr);

template <bool Callable>
static llvm::Value *
GetDynTargetAddress(llvm::IRBuilderTy &IRB,
                    std::pair<binary_index_t, function_index_t> IdxPair,
                    llvm::BasicBlock *FailBlock = nullptr) {
  struct {
    binary_index_t BIdx;
    function_index_t FIdx;
  } DynTarget;

  std::tie(DynTarget.BIdx, DynTarget.FIdx) = IdxPair;

  binary_t &binary = Decompilation.Binaries[DynTarget.BIdx];

  if (DynTarget.BIdx == BinaryIndex) {
    const function_t &f = binary.Analysis.Functions[DynTarget.FIdx];
    if (Callable) {
      assert(f.F);
      return llvm::ConstantExpr::getPtrToInt(f.F, WordType());
    } else {
      auto &ICFG = binary.Analysis.ICFG;
      return SectionPointer(ICFG[boost::vertex(f.Entry, ICFG)].Addr);
    }
  }

  if (DynTargetNeedsThunkPred(IdxPair)) {
    llvm::Value *FnsTbl = IRB.CreateLoad(IRB.CreateConstInBoundsGEP2_64(
        JoveForeignFunctionTablesGlobal, 0, DynTarget.BIdx));
    return IRB.CreateLoad(IRB.CreateConstGEP1_64(FnsTbl, DynTarget.FIdx));
  }

#if !defined(TARGET_MIPS32) &&                                                 \
    !defined(TARGET_MIPS64) /* FIXME old mips systems don't support COPY reloc */
  if (!binary.IsDynamicallyLoaded) {
    llvm::Value *FnsTbl = Decompilation.Binaries[DynTarget.BIdx].FunctionsTable;
    assert(FnsTbl);

    return IRB.CreateLoad(IRB.CreateConstGEP2_64(
        FnsTbl, 0, 2 * DynTarget.FIdx + (Callable ? 1 : 0)));
  }
#endif

  //
  // check if the functions table pointer is NULL. this can happen if a DSO
  // hasn't been loaded yet
  //
  llvm::Value *FnsTbl = IRB.CreateLoad(IRB.CreateConstInBoundsGEP2_64(
      JoveFunctionTablesGlobal, 0, DynTarget.BIdx));
  if (FailBlock) {
    assert(IRB.GetInsertBlock()->getParent());
    llvm::BasicBlock *fallthroughB = llvm::BasicBlock::Create(
        IRB.getContext(), "", IRB.GetInsertBlock()->getParent());

    llvm::Value *EQNullV = IRB.CreateICmpEQ(
        FnsTbl, llvm::Constant::getNullValue(FnsTbl->getType()));
    IRB.CreateCondBr(EQNullV, FailBlock, fallthroughB);

    IRB.SetInsertPoint(fallthroughB);
  }

  return IRB.CreateLoad(
      IRB.CreateConstGEP1_64(FnsTbl, 2 * DynTarget.FIdx + (Callable ? 1 : 0)));
}

// XXX duplicated code
int InitStateForBinaries(void) {
  for (binary_index_t BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx) {
    auto &binary = Decompilation.Binaries[BIdx];
    auto &ICFG = binary.Analysis.ICFG;
    auto &FuncMap = binary.FuncMap;

    //
    // FuncMap
    //
    for (function_index_t FIdx = 0; FIdx < binary.Analysis.Functions.size();
         ++FIdx) {
      function_t &f = binary.Analysis.Functions[FIdx];
      f.BIdx = BIdx;
      f.FIdx = FIdx;

      if (!is_basic_block_index_valid(f.Entry))
        continue;

      FuncMap[ICFG[boost::vertex(f.Entry, ICFG)].Addr] = FIdx;

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
                     return IsExitBlock(ICFG, bb);
                   });

      //
      // Is it a leaf?
      //
      f.IsLeaf = std::all_of(f.ExitBasicBlocks.begin(),
                             f.ExitBasicBlocks.end(),
                             [&](basic_block_t bb) -> bool {
                               auto T = ICFG[bb].Term.Type;
                               return T == TERMINATOR::RETURN
                                   || T == TERMINATOR::UNREACHABLE;
                             }) &&

                 std::none_of(f.BasicBlocks.begin(),
                              f.BasicBlocks.end(),
                     [&](basic_block_t bb) -> bool {
                       auto T = ICFG[bb].Term.Type;
                       return (T == TERMINATOR::INDIRECT_JUMP &&
                               boost::out_degree(bb, ICFG) == 0)
                            || T == TERMINATOR::INDIRECT_CALL
                            || T == TERMINATOR::CALL;
                     });
    }

    //
    // parse the ELF
    //
    llvm::StringRef Buffer(reinterpret_cast<const char *>(&binary.Data[0]),
                           binary.Data.size());
    llvm::StringRef Identifier(binary.Path);
    llvm::MemoryBufferRef MemBuffRef(Buffer, Identifier);

    llvm::Expected<std::unique_ptr<obj::Binary>> BinOrErr =
        obj::createBinary(MemBuffRef);
    if (!BinOrErr) {
      if (!binary.IsVDSO)
        WithColor::error() << llvm::formatv(
            "failed to create binary from {0}\n", binary.Path);
    } else {
      std::unique_ptr<obj::Binary> &BinRef = BinOrErr.get();

      binary.ObjectFile = std::move(BinRef);

      assert(llvm::isa<ELFO>(binary.ObjectFile.get()));
      ELFO &O = *llvm::cast<ELFO>(binary.ObjectFile.get());

      TheTriple = O.makeTriple();
      Features = O.getFeatures();

      const ELFF &E = *O.getELFFile();

      auto &SectsStartAddr = binary.SectsStartAddr;
      auto &SectsEndAddr   = binary.SectsEndAddr;

      llvm::Expected<Elf_Shdr_Range> ExpectedSections = E.sections();
      if (ExpectedSections && !(*ExpectedSections).empty()) {
        target_ulong minAddr = std::numeric_limits<target_ulong>::max(),
                     maxAddr = 0;

        for (const Elf_Shdr &Sec : *ExpectedSections) {
          if (!(Sec.sh_flags & llvm::ELF::SHF_ALLOC))
            continue;

          llvm::Expected<llvm::StringRef> name = E.getSectionName(&Sec);

          if (!name)
            continue;

          if ((Sec.sh_flags & llvm::ELF::SHF_TLS) &&
              *name == std::string(".tbss"))
            continue;

          if (!Sec.sh_size)
            continue;

          minAddr = std::min<target_ulong>(minAddr, Sec.sh_addr);
          maxAddr = std::max<target_ulong>(maxAddr, Sec.sh_addr + Sec.sh_size);
        }

        SectsStartAddr = minAddr;
        SectsEndAddr = maxAddr;
      } else {
        llvm::SmallVector<const Elf_Phdr *, 4> LoadSegments;

        auto ProgramHeadersOrError = E.program_headers();
        if (!ProgramHeadersOrError)
          abort();

        for (const Elf_Phdr &Phdr : *ProgramHeadersOrError) {
          if (Phdr.p_type != llvm::ELF::PT_LOAD)
            continue;

          LoadSegments.push_back(&Phdr);
        }

        assert(!LoadSegments.empty());

        std::stable_sort(LoadSegments.begin(),
                         LoadSegments.end(),
                         [](const Elf_Phdr *A,
                            const Elf_Phdr *B) {
                           return A->p_vaddr < B->p_vaddr;
                         });

        SectsStartAddr = LoadSegments.front()->p_vaddr;
        SectsEndAddr = LoadSegments.back()->p_vaddr + LoadSegments.back()->p_memsz;
      }

      WithColor::note() << llvm::formatv("SectsStartAddr for {0} is {1:x}\n",
                                         binary.Path,
                                         SectsStartAddr);

      loadDynamicTable(&E, &O, binary._elf.DynamicTable);

      assert(binary._elf.DynamicTable.Addr);

      binary._elf.OptionalDynSymRegion =
          loadDynamicSymbols(&E, &O,
                             binary._elf.DynamicTable,
                             binary._elf.DynamicStringTable,
                             binary._elf.SymbolVersionSection,
                             binary._elf.VersionMap);
    }
  }

  return 0;
}

int CreateModule(void) {
  Context.reset(new llvm::LLVMContext);

  const char *bootstrap_mod_name = opts::DFSan ? "jove.dfsan" : "jove";

  std::string bootstrap_mod_path =
      (boost::dll::program_location().parent_path() /
       (std::string(bootstrap_mod_name) + ".bc"))
          .string();

  llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> BufferOr =
      llvm::MemoryBuffer::getFile(bootstrap_mod_path);
  if (!BufferOr) {
    WithColor::error() << "failed to open bitcode " << bootstrap_mod_path
                       << ": " << BufferOr.getError().message() << '\n';
    return 1;
  }

  llvm::Expected<std::unique_ptr<llvm::Module>> moduleOr =
      llvm::parseBitcodeFile(BufferOr.get()->getMemBufferRef(), *Context);
  if (!moduleOr) {
    llvm::logAllUnhandledErrors(moduleOr.takeError(), llvm::errs(),
                                "could not parse helper bitcode: ");
    return 1;
  }

  std::unique_ptr<llvm::Module> &ModuleRef = moduleOr.get();
  Module = std::move(ModuleRef);

  DL = Module->getDataLayout();

  CPUStateGlobal = Module->getGlobalVariable("__jove_env", true);
  assert(CPUStateGlobal);

  CPUStateType = CPUStateGlobal->getType()->getElementType();

  TraceGlobal = Module->getGlobalVariable("__jove_trace", true);
  assert(TraceGlobal);

  CallStackGlobal = Module->getGlobalVariable("__jove_callstack", true);
  assert(CallStackGlobal);

  CallStackBeginGlobal = Module->getGlobalVariable("__jove_callstack_begin", true);
  assert(CallStackBeginGlobal);

  JoveInstallForeignFunctionTables =
      Module->getFunction("_jove_install_foreign_function_tables");
  assert(JoveInstallForeignFunctionTables);

#define __THUNK(n, i, data)                                                    \
  JoveThunk##i##Func = Module->getFunction("_jove_thunk" #i);                  \
  assert(JoveThunk##i##Func);                                                  \
  assert(!JoveThunk##i##Func->empty());                                        \
  JoveThunk##i##Func->setLinkage(llvm::GlobalValue::InternalLinkage);

#if defined(TARGET_X86_64)
BOOST_PP_REPEAT(7, __THUNK, void)
#elif defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
BOOST_PP_REPEAT(5, __THUNK, void)
#elif defined(TARGET_I386)
BOOST_PP_REPEAT(4, __THUNK, void)
#elif defined(TARGET_AARCH64)
BOOST_PP_REPEAT(9, __THUNK, void)
#else
#error
#endif

#undef __THUNK

  JoveFail1Func = Module->getFunction("_jove_fail1");
  assert(JoveFail1Func && !JoveFail1Func->empty());
  JoveFail1Func->setLinkage(llvm::GlobalValue::InternalLinkage);

  JoveFunctionTablesGlobal =
      Module->getGlobalVariable("__jove_function_tables", true);
  assert(JoveFunctionTablesGlobal);

  JoveForeignFunctionTablesGlobal =
      Module->getGlobalVariable("__jove_foreign_function_tables", true);
  assert(JoveForeignFunctionTablesGlobal);
  JoveForeignFunctionTablesGlobal->setLinkage(
      llvm::GlobalValue::InternalLinkage);

  JoveRecoverDynTargetFunc = Module->getFunction("_jove_recover_dyn_target");
  assert(JoveRecoverDynTargetFunc && !JoveRecoverDynTargetFunc->empty());

  JoveRecoverBasicBlockFunc = Module->getFunction("_jove_recover_basic_block");
  assert(JoveRecoverBasicBlockFunc && !JoveRecoverBasicBlockFunc->empty());

  JoveRecoverReturnedFunc = Module->getFunction("_jove_recover_returned");
  assert(JoveRecoverReturnedFunc && !JoveRecoverReturnedFunc->empty());

  JoveRecoverFunctionFunc = Module->getFunction("_jove_recover_function");
  assert(JoveRecoverFunctionFunc && !JoveRecoverFunctionFunc->empty());

  JoveAllocStackFunc = Module->getFunction("_jove_alloc_stack");
  assert(JoveAllocStackFunc);

  JoveFreeStackFunc = Module->getFunction("_jove_free_stack");
  assert(JoveFreeStackFunc);

  JoveCheckReturnAddrFunc = Module->getFunction("_jove_check_return_address");
  if (opts::CheckEmulatedReturnAddress) {
    assert(JoveCheckReturnAddrFunc);
    JoveCheckReturnAddrFunc->setLinkage(llvm::GlobalValue::InternalLinkage);
  }

  if (opts::DFSan) {
    {
      assert(!Module->getFunction("dfsan_log_jove_fn_start"));

      llvm::Type *ArgArr[1] = {llvm::IntegerType::get(*Context, 64)};
      llvm::FunctionType *JoveLogFunctionStartFnTy = llvm::FunctionType::get(
          llvm::Type::getVoidTy(*Context), ArgArr, /*isVarArg=*/false);

      JoveLogFunctionStart = llvm::Function::Create(
          JoveLogFunctionStartFnTy,
          llvm::GlobalValue::ExternalLinkage,
          "dfsan_log_jove_fn_start",
          Module.get());

      JoveLogFunctionStartClunk = new llvm::GlobalVariable(
            *Module,
            WordType(),
            false,
            llvm::GlobalValue::ExternalLinkage,
            llvm::ConstantExpr::getPtrToInt(JoveLogFunctionStart, WordType()),
            "dfsan_log_jove_fn_start_clunk");
      JoveLogFunctionStartClunk->setVisibility(llvm::GlobalValue::HiddenVisibility);
    }

    {
      assert(!Module->getFunction("dfsan_fini"));

      llvm::FunctionType *DFSanFiniFnTy = llvm::FunctionType::get(
          llvm::Type::getVoidTy(*Context), /*isVarArg=*/false);
      DFSanFiniFunc = llvm::Function::Create(
          DFSanFiniFnTy,
          llvm::GlobalValue::ExternalLinkage,
          "dfsan_fini",
          Module.get());
      DFSanFiniClunk = new llvm::GlobalVariable(
            *Module,
            WordType(),
            false,
            llvm::GlobalValue::ExternalLinkage,
            llvm::ConstantExpr::getPtrToInt(DFSanFiniFunc, WordType()),
            "dfsan_fini_clunk");
      DFSanFiniClunk->setVisibility(llvm::GlobalValue::HiddenVisibility);
    }
  }

  return 0;
}

typedef std::unordered_set<
    std::pair<binary_index_t, function_index_t>,
    boost::hash<std::pair<binary_index_t, function_index_t>>>
    hooks_t;

struct hook_t {
  struct arg_info_t {
    unsigned Size;
    bool isPointer;
  };

  const char *Sym;
  std::vector<arg_info_t> Args;
  arg_info_t Ret;

  bool Pre;
  bool Post;
  bool Syscall; // is this a wrapper for performing a system call?
};

static constexpr unsigned NumHooks = 0
#define ___HOOK0(hook_kind, rett, sym)                         +1
#define ___HOOK1(hook_kind, rett, sym, t1)                     +1
#define ___HOOK2(hook_kind, rett, sym, t1, t2)                 +1
#define ___HOOK3(hook_kind, rett, sym, t1, t2, t3)             +1
#define ___HOOK4(hook_kind, rett, sym, t1, t2, t3, t4)         +1
#define ___HOOK5(hook_kind, rett, sym, t1, t2, t3, t4, t5)     +1
#define ___HOOK6(hook_kind, rett, sym, t1, t2, t3, t4, t5, t6) +1
#include "dfsan_hooks.inc.h"
#undef ___HOOK0
#undef ___HOOK1
#undef ___HOOK2
#undef ___HOOK3
#undef ___HOOK4
#undef ___HOOK5
#undef ___HOOK6
  ;

#if defined(PRE) \
 || defined(POST) \
 || defined(SYSCALL)
#error
#endif

#define PRE 1
#define POST 2
#define SYSCALL 4

static const std::array<hook_t, NumHooks> HookArray{{
#define ___HOOK0(hook_kind, rett, sym)                                         \
  {                                                                            \
      .Sym = #sym,                                                             \
      .Ret = {.Size = sizeof(target_ulong),                                    \
              .isPointer = std::is_pointer<rett>::value},                      \
      .Pre = !!((hook_kind) & PRE),                                            \
      .Post = !!((hook_kind) & POST),                                          \
      .Syscall = !!((hook_kind) & SYSCALL),                                    \
  },
#define ___HOOK1(hook_kind, rett, sym, t1)                                     \
  {                                                                            \
      .Sym = #sym,                                                             \
      .Args = {{.Size = sizeof(target_ulong),                                  \
                .isPointer = std::is_pointer<t1>::value}},                     \
      .Ret = {.Size = sizeof(target_ulong),                                    \
              .isPointer = std::is_pointer<rett>::value},                      \
      .Pre = !!((hook_kind) & PRE),                                            \
      .Post = !!((hook_kind) & POST),                                          \
      .Syscall = !!((hook_kind) & SYSCALL),                                    \
  },
#define ___HOOK2(hook_kind, rett, sym, t1, t2)                                 \
  {                                                                            \
      .Sym = #sym,                                                             \
      .Args = {{.Size = sizeof(target_ulong),                                  \
                .isPointer = std::is_pointer<t1>::value},                      \
               {.Size = sizeof(target_ulong),                                  \
                .isPointer = std::is_pointer<t2>::value}},                     \
      .Ret = {.Size = sizeof(rett),                                            \
              .isPointer = std::is_pointer<rett>::value},                      \
      .Pre = !!((hook_kind) & PRE),                                            \
      .Post = !!((hook_kind) & POST),                                          \
      .Syscall = !!((hook_kind) & SYSCALL),                                    \
  },
#define ___HOOK3(hook_kind, rett, sym, t1, t2, t3)                             \
  {                                                                            \
      .Sym = #sym,                                                             \
      .Args = {{.Size = sizeof(target_ulong),                                  \
                .isPointer = std::is_pointer<t1>::value},                      \
               {.Size = sizeof(target_ulong),                                  \
                .isPointer = std::is_pointer<t2>::value},                      \
               {.Size = sizeof(target_ulong),                                  \
                .isPointer = std::is_pointer<t3>::value}},                     \
      .Ret = {.Size = sizeof(target_ulong),                                    \
              .isPointer = std::is_pointer<rett>::value},                      \
      .Pre = !!((hook_kind) & PRE),                                            \
      .Post = !!((hook_kind) & POST),                                          \
      .Syscall = !!((hook_kind) & SYSCALL),                                    \
  },
#define ___HOOK4(hook_kind, rett, sym, t1, t2, t3, t4)                         \
  {                                                                            \
      .Sym = #sym,                                                             \
      .Args = {{.Size = sizeof(target_ulong),                                  \
                .isPointer = std::is_pointer<t1>::value},                      \
               {.Size = sizeof(target_ulong),                                  \
                .isPointer = std::is_pointer<t2>::value},                      \
               {.Size = sizeof(target_ulong),                                  \
                .isPointer = std::is_pointer<t3>::value},                      \
               {.Size = sizeof(target_ulong),                                  \
                .isPointer = std::is_pointer<t4>::value}},                     \
      .Ret = {.Size = sizeof(target_ulong),                                    \
              .isPointer = std::is_pointer<rett>::value},                      \
      .Pre = !!((hook_kind) & PRE),                                            \
      .Post = !!((hook_kind) & POST),                                          \
      .Syscall = !!((hook_kind) & SYSCALL),                                    \
  },
#define ___HOOK5(hook_kind, rett, sym, t1, t2, t3, t4, t5)                     \
  {                                                                            \
      .Sym = #sym,                                                             \
      .Args = {{.Size = sizeof(target_ulong),                                  \
                .isPointer = std::is_pointer<t1>::value},                      \
               {.Size = sizeof(target_ulong),                                  \
                .isPointer = std::is_pointer<t2>::value},                      \
               {.Size = sizeof(target_ulong),                                  \
                .isPointer = std::is_pointer<t3>::value},                      \
               {.Size = sizeof(target_ulong),                                  \
                .isPointer = std::is_pointer<t4>::value},                      \
               {.Size = sizeof(target_ulong),                                  \
                .isPointer = std::is_pointer<t5>::value}},                     \
      .Ret = {.Size = sizeof(target_ulong),                                    \
              .isPointer = std::is_pointer<rett>::value},                      \
      .Pre = !!((hook_kind) & PRE),                                            \
      .Post = !!((hook_kind) & POST),                                          \
      .Syscall = !!((hook_kind) & SYSCALL),                                    \
  },
#define ___HOOK6(hook_kind, rett, sym, t1, t2, t3, t4, t5, t6)                 \
  {                                                                            \
      .Sym = #sym,                                                             \
      .Args = {{.Size = sizeof(target_ulong),                                  \
                .isPointer = std::is_pointer<t1>::value},                      \
               {.Size = sizeof(target_ulong),                                  \
                .isPointer = std::is_pointer<t2>::value},                      \
               {.Size = sizeof(target_ulong),                                  \
                .isPointer = std::is_pointer<t3>::value},                      \
               {.Size = sizeof(target_ulong),                                  \
                .isPointer = std::is_pointer<t4>::value},                      \
               {.Size = sizeof(target_ulong),                                  \
                .isPointer = std::is_pointer<t5>::value},                      \
               {.Size = sizeof(target_ulong),                                  \
                .isPointer = std::is_pointer<t6>::value}},                     \
      .Ret = {.Size = sizeof(target_ulong),                                    \
              .isPointer = std::is_pointer<rett>::value},                      \
      .Pre = !!((hook_kind) & PRE),                                            \
      .Post = !!((hook_kind) & POST),                                          \
      .Syscall = !!((hook_kind) & SYSCALL),                                    \
  },
#include "dfsan_hooks.inc.h"

#undef ___HOOK0
#undef ___HOOK1
#undef ___HOOK2
#undef ___HOOK3
#undef ___HOOK4
#undef ___HOOK5
#undef ___HOOK6
}};

#undef PRE
#undef POST
#undef SYSCALL

static llvm::Type *type_of_arg_info(const hook_t::arg_info_t &info) {
  if (info.isPointer)
    return llvm::PointerType::get(llvm::Type::getInt8Ty(*Context), 0);

  return llvm::Type::getIntNTy(*Context, info.Size * 8);
}

template <bool IsPreOrPost>
static std::pair<llvm::GlobalVariable *, llvm::Function *> declareHook(const hook_t &h) {
  const char *namePrefix =
    IsPreOrPost ? "__dfs_pre_hook_" : "__dfs_post_hook_";
  const char *clunkNamePrefix =
    IsPreOrPost ? "__dfs_pre_hook_clunk_" : "__dfs_post_hook_clunk_";

  std::string name(namePrefix);
  name.append(h.Sym);

  std::string clunkName(clunkNamePrefix);
  clunkName.append(h.Sym);

  // first check if it already exists
  if (llvm::Function *F = Module->getFunction(name)) {
    assert(F->empty());

    llvm::GlobalVariable *GV = Module->getGlobalVariable(clunkName, true);
    assert(GV);

    return std::make_pair(GV, F);
  }

  std::vector<llvm::Type *> argTypes;
  argTypes.resize(h.Args.size());
  std::transform(h.Args.begin(),
                 h.Args.end(),
                 argTypes.begin(),
                 type_of_arg_info);

  if (!IsPreOrPost /* POST */) {
    llvm::Type *retTy = type_of_arg_info(h.Ret);

    argTypes.insert(argTypes.begin(), retTy);
  }

  llvm::FunctionType *FTy =
      !IsPreOrPost /* POST */ ? llvm::FunctionType::get(type_of_arg_info(h.Ret), argTypes, false)
                              : llvm::FunctionType::get(VoidType(), argTypes, false);

  llvm::Function *F = llvm::Function::Create(
      FTy, llvm::GlobalValue::ExternalLinkage, name, Module.get());

  llvm::GlobalVariable *GV = new llvm::GlobalVariable(
        *Module,
        WordType(),
        false,
        llvm::GlobalValue::ExternalLinkage,
        llvm::ConstantExpr::getPtrToInt(F, WordType()),
        clunkName);
  GV->setVisibility(llvm::GlobalValue::HiddenVisibility);

  return std::make_pair(GV, F);
}

static std::pair<llvm::GlobalVariable *, llvm::Function *> declarePreHook(const hook_t &h) {
  return declareHook<true>(h);
}

static std::pair<llvm::GlobalVariable *, llvm::Function *> declarePostHook(const hook_t &h) {
  return declareHook<false>(h);
}

static std::string dyn_target_desc(dynamic_target_t IdxPair);

//
// the duty of this function is to map symbol names to (BIdx, FIdx) pairs
//
int LocateHooks(void) {
  assert(opts::DFSan);

  const bool ForeignLibs = opts::ForeignLibs;

  for (const hook_t &h : HookArray) {
    if (!ForeignLibs && h.Syscall) {
      WithColor::note() << llvm::formatv("not planting hooks for {0}\n", h.Sym);
      continue; // we will see the system call; no need for a hook
    }

    auto it = ExportedFunctions.find(h.Sym);
    if (it == ExportedFunctions.end()) {
      WithColor::warning() << llvm::formatv("failed to find hook for {0}\n", h.Sym);
      continue;
    }

    assert(!(*it).second.empty());

    for (dynamic_target_t IdxPair : (*it).second) {
      function_t &f = Decompilation.Binaries.at(IdxPair.first)
                         .Analysis.Functions.at(IdxPair.second);

      if (f.hook) {
        WithColor::warning() << llvm::formatv("hook already installed for {0}\n", h.Sym);
        continue;
      }

      llvm::outs() << llvm::formatv("[hook] {0} @ {1}\n",
                                    h.Sym,
                                    dyn_target_desc(IdxPair));

      f.hook = &h;

      if (h.Pre)
        std::tie(f.PreHookClunk, f.PreHook) = declarePreHook(h);

      if (h.Post)
        std::tie(f.PostHookClunk, f.PostHook) = declarePostHook(h);
    }
  }

  return 0;
}

int ProcessBinaryTLSSymbols(void) {
  binary_index_t BIdx = BinaryIndex;
  auto &b = Decompilation.Binaries[BIdx];

  assert(b.ObjectFile);
  assert(llvm::isa<ELFO>(b.ObjectFile.get()));
  ELFO &O = *llvm::cast<ELFO>(b.ObjectFile.get());
  const ELFF &E = *O.getELFFile();

  //
  // To set up the memory for the thread-local storage the dynamic linker gets
  // the information about each module's thread-local storage requirements from
  // the PT TLS program header entry
  //
  const Elf_Phdr *tlsPhdr = nullptr;
  for (const Elf_Phdr &Phdr : unwrapOrError(E.program_headers())) {
    if (Phdr.p_type == llvm::ELF::PT_TLS) {
      tlsPhdr = &Phdr;
      break;
    }
  }

  if (!tlsPhdr) {
    ThreadLocalStorage.Present = false;

    WithColor::note() << llvm::formatv("{0}: No thread local storage\n",
                                       __func__);
    return 0;
  }

  ThreadLocalStorage.Present = true;
  ThreadLocalStorage.Beg = tlsPhdr->p_vaddr;
  ThreadLocalStorage.Data.Size = tlsPhdr->p_filesz;
  ThreadLocalStorage.End = tlsPhdr->p_vaddr + tlsPhdr->p_memsz;

  WithColor::note() << llvm::formatv("Thread-local storage: [{0:x}, {1:x})\n",
                                     ThreadLocalStorage.Beg,
                                     ThreadLocalStorage.End);

  //
  // XXX explain this
  //
  {
    const Elf_Shdr *SymTab = nullptr;
    llvm::ArrayRef<Elf_Word> ShndxTable;

    for (const Elf_Shdr &Sect : unwrapOrError(E.sections())) {
      if (Sect.sh_type == llvm::ELF::SHT_SYMTAB) {
        assert(!SymTab);
        SymTab = &Sect;
      } else if (Sect.sh_type == llvm::ELF::SHT_SYMTAB_SHNDX) {
        ShndxTable = unwrapOrError(E.getSHNDXTable(Sect));
      }
    }

    if (SymTab) {
      llvm::StringRef StrTable = unwrapOrError(E.getStringTableForSymtab(*SymTab));

      for (const Elf_Sym &Sym : unwrapOrError(E.symbols(SymTab))) {
        if (Sym.getType() != llvm::ELF::STT_TLS)
          continue;

        if (Sym.isUndefined())
          continue;

        llvm::StringRef SymName = unwrapOrError(Sym.getName(StrTable));
        WithColor::note() << llvm::formatv("{0}: {1} [{2}]\n", __func__, SymName,
                                           __LINE__);

        if (Sym.st_value >= tlsPhdr->p_memsz) {
          WithColor::error() << llvm::formatv("bad TLS offset {0} for symbol {1}",
                                              Sym.st_value, SymName)
                             << '\n';
          continue;
        }

        target_ulong Addr = ThreadLocalStorage.Beg + Sym.st_value;
        AddrToSymbolMap[Addr].insert(SymName);
        AddrToSizeMap[Addr] = Sym.st_size;

        TLSObjects.insert(Addr);

        TLSValueToSizeMap[Sym.st_value] = Sym.st_size;
        TLSValueToSymbolMap[Sym.st_value].insert(SymName);
      }
    }
  }

  //
  // iterate dynamic symbols
  //
  auto OptionalDynSymRegion = b._elf.OptionalDynSymRegion;
  if (!OptionalDynSymRegion)
    return 0; /* no dynamic symbols */

  const DynRegionInfo &DynSymRegion = *OptionalDynSymRegion;

  auto dynamic_symbols = [&](void) -> Elf_Sym_Range {
    return DynSymRegion.getAsArrayRef<Elf_Sym>();
  };

  for (const Elf_Sym &Sym : dynamic_symbols()) {
    if (Sym.getType() != llvm::ELF::STT_TLS)
      continue;

    if (Sym.isUndefined())
      continue;

    llvm::StringRef SymName = unwrapOrError(Sym.getName(b._elf.DynamicStringTable));

    WithColor::note() << llvm::formatv("{0}: {1} [{2}]\n", __func__, SymName,
                                       __LINE__);

    if (Sym.st_value >= tlsPhdr->p_memsz) {
      WithColor::error() << llvm::formatv("bad TLS offset {0} for symbol {1}",
                                          Sym.st_value, SymName)
                         << '\n';
      continue;
    }

    target_ulong Addr = ThreadLocalStorage.Beg + Sym.st_value;
    AddrToSymbolMap[Addr].insert(SymName);
    AddrToSizeMap[Addr] = Sym.st_size;

    TLSObjects.insert(Addr);

    TLSValueToSizeMap[Sym.st_value] = Sym.st_size;
    TLSValueToSymbolMap[Sym.st_value].insert(SymName);
  }

  // The names of the sections, as is in theory the case for all sections in ELF
  // files, are not important. Instead the linker will treat all sections of
  // type SHT PROGBITS with the SHF TLS flags set as .tdata sections, and all
  // sections of type SHT NOBITS with SHF TLS set as .tbss sections.

  return 0;
}

static llvm::FunctionType *DetermineFunctionType(function_t &);
static llvm::FunctionType *DetermineFunctionType(binary_index_t BinIdx,
                                                 function_index_t FuncIdx);
static llvm::FunctionType *DetermineFunctionType(
    const std::pair<binary_index_t, function_index_t> &FuncIdxPair);

int ProcessExportedFunctions(void) {
  for (binary_index_t BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx) {
    auto &b = Decompilation.Binaries[BIdx];
    auto &FuncMap = b.FuncMap;

    if (!b.ObjectFile)
      continue;

    assert(llvm::isa<ELFO>(b.ObjectFile.get()));
    ELFO &O = *llvm::cast<ELFO>(b.ObjectFile.get());
    const ELFF &E = *O.getELFFile();

    if (!b._elf.OptionalDynSymRegion)
      continue; /* no dynamic symbols */

    auto DynSyms = b._elf.OptionalDynSymRegion->getAsArrayRef<Elf_Sym>();

    for (unsigned SymNo = 0; SymNo < DynSyms.size(); ++SymNo) {
      const Elf_Sym &Sym = DynSyms[SymNo];

      if (Sym.isUndefined())
        continue;
      if (Sym.getType() != llvm::ELF::STT_FUNC)
        continue;

      llvm::Expected<llvm::StringRef> ExpectedSymName = Sym.getName(b._elf.DynamicStringTable);
      if (!ExpectedSymName)
        continue;

      llvm::StringRef SymName = *ExpectedSymName;

      auto it = FuncMap.find(Sym.st_value);
      if (it == FuncMap.end())
        continue;

      function_t &f = b.Analysis.Functions[(*it).second];

      symbol_t &res = f.Syms.emplace_back();
      res.Name = SymName;

      //
      // symbol versioning
      //
      if (!b._elf.SymbolVersionSection) {
        res.Visibility.IsDefault = false;
      } else {
        const Elf_Versym *Versym = unwrapOrError(
            E.getEntry<Elf_Versym>(b._elf.SymbolVersionSection, SymNo));

        res.Vers = getSymbolVersionByIndex(b._elf.VersionMap,
                                           b._elf.DynamicStringTable,
                                           Versym->vs_index,
                                           res.Visibility.IsDefault);
      }

      res.Addr = Sym.isUndefined() ? 0 : Sym.st_value;
      res.Type = sym_type_of_elf_sym_type(Sym.getType());
      res.Size = Sym.st_size;
      res.Bind = sym_binding_of_elf_sym_binding(Sym.getBinding());
    }
  }

  return 0;
}

static llvm::Constant *CPUStateGlobalPointer(unsigned glb);
static llvm::Value *BuildCPUStatePointer(llvm::IRBuilderTy &IRB, llvm::Value *Env, unsigned glb);
static llvm::GlobalIFunc *buildGlobalIFunc(function_t &f, dynamic_target_t IdxPair);

int ProcessDynamicSymbols(void) {
  std::set<std::pair<uintptr_t, unsigned>> gdefs;

  for (binary_index_t BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx) {
    auto &b = Decompilation.Binaries[BIdx];
    auto &FuncMap = b.FuncMap;

    if (!b.ObjectFile)
      continue;

    assert(llvm::isa<ELFO>(b.ObjectFile.get()));
    ELFO &O = *llvm::cast<ELFO>(b.ObjectFile.get());
    const ELFF &E = *O.getELFFile();

    auto OptionalDynSymRegion = b._elf.OptionalDynSymRegion;
    if (!OptionalDynSymRegion)
      continue; /* no dynamic symbols */

    auto DynSyms = b._elf.OptionalDynSymRegion->getAsArrayRef<Elf_Sym>();

    for (unsigned SymNo = 0; SymNo < DynSyms.size(); ++SymNo) {
      const Elf_Sym &Sym = DynSyms[SymNo];

      const bool is_undefined = Sym.isUndefined() ||
                                Sym.st_shndx == llvm::ELF::SHN_UNDEF;
      if (is_undefined)
        continue;

      llvm::Expected<llvm::StringRef> ExpectedSymName = Sym.getName(b._elf.DynamicStringTable);
      if (!ExpectedSymName)
        continue;

      llvm::StringRef SymName = *ExpectedSymName;

      symbol_t sym;

      sym.Name = SymName;

      //
      // symbol versioning
      //
      if (!b._elf.SymbolVersionSection) {
        sym.Visibility.IsDefault = false;
      } else {
        const Elf_Versym *Versym = unwrapOrError(
            E.getEntry<Elf_Versym>(b._elf.SymbolVersionSection, SymNo));

        sym.Vers = getSymbolVersionByIndex(b._elf.VersionMap,
                                           b._elf.DynamicStringTable,
                                           Versym->vs_index,
                                           sym.Visibility.IsDefault);
      }

      sym.Addr = Sym.isUndefined() ? 0 : Sym.st_value;
      sym.Type = sym_type_of_elf_sym_type(Sym.getType());
      sym.Size = Sym.st_size;
      sym.Bind = sym_binding_of_elf_sym_binding(Sym.getBinding());

      if (Sym.getType() == llvm::ELF::STT_OBJECT ||
          Sym.getType() == llvm::ELF::STT_TLS) {
        if (!Sym.st_size) {
          if (opts::Verbose)
            WithColor::warning() << "symbol '" << SymName
                                 << "' defined but size is unknown; ignoring\n";
          continue;
        }

        {
          auto it = GlobalSymbolDefinedSizeMap.find(SymName);
          if (it == GlobalSymbolDefinedSizeMap.end()) {
            GlobalSymbolDefinedSizeMap.insert({SymName, Sym.st_size});
          } else {
            if ((*it).second != Sym.st_size) {
              if (opts::Verbose)
                WithColor::warning()
                    << llvm::formatv("global symbol {0} is defined with "
                                     "multiple distinct sizes: {1}, {2}\n",
                                     SymName, Sym.st_size, (*it).second);
              (*it).second = std::max<unsigned>((*it).second, Sym.st_size);
            }
          }
        }

        if (BIdx == BinaryIndex) {
          //
          // if this symbol is TLS, update the TLSValueToSymbolMap
          //
          if (Sym.getType() == llvm::ELF::STT_TLS) {
            TLSValueToSymbolMap[Sym.st_value].insert(SymName);

            auto it = TLSValueToSizeMap.find(Sym.st_value);
            if (it == TLSValueToSizeMap.end()) {
              TLSValueToSizeMap.insert({Sym.st_value, Sym.st_size});
            } else {
              if ((*it).second != Sym.st_size) {
                WithColor::warning()
                    << llvm::formatv("binary TLS symbol {0} is defined with "
                                     "multiple distinct sizes: {1}, {2}\n",
                                     SymName, Sym.st_size, (*it).second);
                (*it).second = std::max<unsigned>((*it).second, Sym.st_size);
              }
            }
          } else {
            ;
          }
        }
      } else if (Sym.getType() == llvm::ELF::STT_FUNC) {
        function_index_t FuncIdx;
        {
          auto it = FuncMap.find(Sym.st_value);
          if (it == FuncMap.end()) {
            WithColor::warning()
                << llvm::formatv("no function for {0} exists at {1:x}\n",
                                 SymName, Sym.st_value);
            continue;
          }

          FuncIdx = (*it).second;
        }

        Decompilation.Binaries[BIdx].Analysis.Functions[FuncIdx].Syms.push_back(sym);

        ExportedFunctions[SymName].insert({BIdx, FuncIdx});

        if (BIdx == BinaryIndex) {
          //
          // XXX hack for glibc 2.32+
          //
          if (sym.Name == "__libc_early_init" &&
              sym.Vers == "GLIBC_PRIVATE") {
            Module->appendModuleInlineAsm(
                ".symver "
                "_jove__libc_early_init,__libc_early_init@@GLIBC_PRIVATE");
            VersionScript.Table["GLIBC_PRIVATE"];

            libcEarlyInitAddr = Sym.st_value;
          }
        }
      } else if (Sym.getType() == llvm::ELF::STT_GNU_IFUNC) {
        std::pair<binary_index_t, function_index_t> IdxPair(invalid_dynamic_target);

        {
          auto &IFuncDynTargets = b.Analysis.IFuncDynTargets;
          auto it = IFuncDynTargets.find(Sym.st_value);
          if (it == IFuncDynTargets.end()) {
            for (const auto &_binary : Decompilation.Binaries) {
              auto &_SymDynTargets = _binary.Analysis.SymDynTargets;
              auto _it = _SymDynTargets.find(SymName);
              if (_it != _SymDynTargets.end()) {
                IdxPair = *(*_it).second.begin();
                break;
              }
            }
          } else {
            IdxPair = *(*it).second.begin();
          }
        }

        if (is_dynamic_target_valid(IdxPair))
          ExportedFunctions[SymName].insert(IdxPair);

        if (BIdx == BinaryIndex) {
          auto it = FuncMap.find(Sym.st_value);
          assert(it != FuncMap.end());

          function_t &f = b.Analysis.Functions.at((*it).second);

          f.Syms.push_back(sym);

          llvm::FunctionType *FTy =
              is_dynamic_target_valid(IdxPair)
                  ? DetermineFunctionType(IdxPair)
                  : llvm::FunctionType::get(VoidType(), false);

          if (f._resolver.IFunc) {
#if 0
            llvm::GlobalAlias::create(SymName, f._resolver.IFunc);
#else
            llvm::GlobalIFunc *IFunc = llvm::GlobalIFunc::create(
                FTy, 0, llvm::GlobalValue::ExternalLinkage, SymName,
                f._resolver.IFunc->getResolver(), Module.get());

            if (!sym.Vers.empty()) {
#if 0
              Module->appendModuleInlineAsm(
                  (llvm::Twine(".symver ") + SymName + "," + SymName +
                   (sym.Visibility.IsDefault ? "@@" : "@") + sym.Vers)
                      .str());
#endif

              VersionScript.Table[sym.Vers].insert(SymName);

#if 0
              Module->appendModuleInlineAsm(
                  (llvm::Twine(".type ") + SymName + " STT_GNU_IFUNC").str());
#endif
            }
#endif
          } else {
            f._resolver.IFunc = buildGlobalIFunc(f, IdxPair);
          }
        }
      }
    }
  }

  return 0;
}

llvm::GlobalIFunc *buildGlobalIFunc(function_t &f, dynamic_target_t IdxPair) {
  llvm::FunctionType *FTy = is_dynamic_target_valid(IdxPair)
                                ? DetermineFunctionType(IdxPair)
                                : llvm::FunctionType::get(VoidType(), false);

  llvm::Function *CallsF = llvm::Function::Create(
      llvm::FunctionType::get(llvm::PointerType::get(FTy, 0), false),
      llvm::GlobalValue::ExternalLinkage,
      std::string(f.F->getName()) + "_ifunc", Module.get());
  CallsF->setVisibility(llvm::GlobalValue::HiddenVisibility);

  llvm::DIBuilder &DIB = *DIBuilder;
  llvm::DISubprogram::DISPFlags SubProgFlags =
      llvm::DISubprogram::SPFlagDefinition |
      llvm::DISubprogram::SPFlagOptimized;

  if (CallsF->hasPrivateLinkage() || CallsF->hasInternalLinkage())
    SubProgFlags |= llvm::DISubprogram::SPFlagLocalToUnit;

  llvm::DISubroutineType *SubProgType =
      DIB.createSubroutineType(DIB.getOrCreateTypeArray(llvm::None));

  struct {
    llvm::DISubprogram *Subprogram;
  } DebugInfo;

  DebugInfo.Subprogram = DIB.createFunction(
      /* Scope       */ DebugInformation.CompileUnit,
      /* Name        */ CallsF->getName(),
      /* LinkageName */ CallsF->getName(),
      /* File        */ DebugInformation.File,
      /* LineNo      */ 0,
      /* Ty          */ SubProgType,
      /* ScopeLine   */ 0,
      /* Flags       */ llvm::DINode::FlagZero,
      /* SPFlags     */ SubProgFlags);

  CallsF->setSubprogram(DebugInfo.Subprogram);

  llvm::BasicBlock *EntryB =
      llvm::BasicBlock::Create(*Context, "", CallsF);

  {
    llvm::IRBuilderTy IRB(EntryB);

    IRB.SetCurrentDebugLocation(
        llvm::DILocation::get(*Context, /* Line */ 0, /* Column */ 0,
                              DebugInfo.Subprogram));

    if (is_dynamic_target_valid(IdxPair) && IdxPair.first == BinaryIndex) {
      llvm::Constant *Res = llvm::ConstantExpr::getPtrToInt(
          Decompilation.Binaries[BinaryIndex]
              .Analysis.Functions.at(IdxPair.second)
              .F,
          WordType());

      //
      // FIXME we can't only look at the SectionPointer when translating an
      // indirect jump because of this. Unfortunately, at the moment we cannot
      // just return SectionPointer() here because this function is called
      // *before* CreateSectionGlobalVariables.
      //

      IRB.CreateRet(IRB.CreateIntToPtr(
          Res, CallsF->getFunctionType()->getReturnType()));
    } else if (is_dynamic_target_valid(IdxPair) && DynTargetNeedsThunkPred(IdxPair)) {
      IRB.CreateCall(JoveInstallForeignFunctionTables)
          ->setIsNoInline();

      llvm::Value *Res = GetDynTargetAddress<false>(IRB, IdxPair);

      IRB.CreateRet(IRB.CreateIntToPtr(
          Res, CallsF->getFunctionType()->getReturnType()));
    } else if (is_dynamic_target_valid(IdxPair) && !Decompilation.Binaries.at(IdxPair.first).IsDynamicallyLoaded) {
      llvm::Value *Res = GetDynTargetAddress<false>(IRB, IdxPair);

      IRB.CreateRet(IRB.CreateIntToPtr(
          Res, CallsF->getFunctionType()->getReturnType()));
    } else {
      IRB.CreateCall(JoveInstallForeignFunctionTables)
          ->setIsNoInline();

      llvm::Value *SPPtr =
          CPUStateGlobalPointer(tcg_stack_pointer_index);

      llvm::Value *SavedSP = IRB.CreateLoad(SPPtr);
      SavedSP->setName("saved_sp");

      llvm::Value *TemporaryStack = nullptr;
      {
        TemporaryStack = IRB.CreateCall(JoveAllocStackFunc);
        llvm::Value *NewSP = IRB.CreateAdd(
            TemporaryStack,
            llvm::ConstantInt::get(WordType(),
                                   JOVE_STACK_SIZE - JOVE_PAGE_SIZE));

        llvm::Value *AlignedNewSP =
            IRB.CreateAnd(IRB.CreatePtrToInt(NewSP, WordType()),
                          IRB.getIntN(sizeof(target_ulong) * 8, ~15UL));

        llvm::Value *SPVal = AlignedNewSP;

#if defined(TARGET_X86_64) || defined(TARGET_I386)
        SPVal = IRB.CreateSub(
            SPVal, IRB.getIntN(sizeof(target_ulong) * 8,
                               sizeof(target_ulong)));
#endif

        IRB.CreateStore(SPVal, SPPtr);
      }

      llvm::Value *SavedTraceP = nullptr;
      if (opts::Trace) {
        SavedTraceP = IRB.CreateLoad(TraceGlobal);
        SavedTraceP->setName("saved_tracep");

        {
          constexpr unsigned TraceAllocaSize = 4096;

          llvm::AllocaInst *TraceAlloca =
              IRB.CreateAlloca(llvm::ArrayType::get(IRB.getInt64Ty(),
                                                    TraceAllocaSize));

          llvm::Value *NewTraceP =
              IRB.CreateConstInBoundsGEP2_64(TraceAlloca, 0, 0);

          IRB.CreateStore(NewTraceP, TraceGlobal);
        }
      }

      std::vector<llvm::Value *> ArgVec;
      ArgVec.resize(f.F->getFunctionType()->getNumParams());

      for (unsigned i = 0; i < ArgVec.size(); ++i)
        ArgVec[i] = llvm::UndefValue::get(
            f.F->getFunctionType()->getParamType(i));

      // llvm::ValueToValueMapTy Map;
      // ResolverF = llvm::CloneFunction(f.F, Map);

      llvm::CallInst *Call = IRB.CreateCall(f.F, ArgVec);

      IRB.CreateStore(SavedSP, SPPtr);

      IRB.CreateCall(JoveFreeStackFunc, {TemporaryStack});

      if (opts::Trace)
        IRB.CreateStore(SavedTraceP, TraceGlobal);

      if (f.F->getFunctionType()->getReturnType()->isVoidTy()) {
        WithColor::warning() << llvm::formatv(
            "ifunc resolver {0} returns void\n", *f.F);

        IRB.CreateRet(llvm::Constant::getNullValue(
            CallsF->getFunctionType()->getReturnType()));
      } else {
        if (f.F->getFunctionType()->getReturnType()->isIntegerTy()) {
          IRB.CreateRet(IRB.CreateIntToPtr(
              Call, CallsF->getFunctionType()->getReturnType()));
        } else {
          assert(f.F->getFunctionType()->getReturnType()->isStructTy());

          llvm::Value *Val = IRB.CreateExtractValue(
              Call, llvm::ArrayRef<unsigned>(0), "");

          IRB.CreateRet(IRB.CreateIntToPtr(
              Val, CallsF->getFunctionType()->getReturnType()));
        }
      }
    }
  }

  DIB.finalizeSubprogram(DebugInfo.Subprogram);

  assert(!f.Syms.empty());
  symbol_t &sym = f.Syms.back();

  llvm::GlobalIFunc *res = llvm::GlobalIFunc::create(
      FTy, 0, llvm::GlobalValue::ExternalLinkage, sym.Name, CallsF,
      Module.get());

  if (!sym.Vers.empty())
    VersionScript.Table[sym.Vers].insert(sym.Name);

  return res;
}

int ProcessDynamicTargets(void) {
  for (binary_index_t BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx) {
    auto &binary = Decompilation.Binaries[BIdx];
    auto &ICFG = binary.Analysis.ICFG;

    for (basic_block_index_t BBIdx = 0; BBIdx < boost::num_vertices(ICFG);
         ++BBIdx) {
      basic_block_t bb = boost::vertex(BBIdx, ICFG);

      for (const auto &DynTarget : ICFG[bb].DynTargets) {
        if (DynTarget.first == BIdx)
          continue;

        function_t &callee = Decompilation.Binaries[DynTarget.first]
                                .Analysis.Functions[DynTarget.second];

        callee.IsABI = true;
      }
    }
  }

  //
  // dynamic ifunc resolver targets are ABIs
  //
  for (const binary_t &binary : Decompilation.Binaries) {
    for (const auto &pair : binary.Analysis.IFuncDynTargets) {
      for (const auto &IdxPair : pair.second) {
        binary_index_t BIdx;
        function_index_t FIdx;
        std::tie(BIdx, FIdx) = IdxPair;

        function_t &f =
            Decompilation.Binaries.at(BIdx).Analysis.Functions.at(FIdx);

        f.IsABI = true;
      }
    }
  }

#if 0
  //
  // resolved symbols are ABIs
  //
  for (const binary_t &binary : Decompilation.Binaries) {
    for (const auto &pair : binary.Analysis.SymDynTargets) {
      for (const auto &IdxPair : pair.second) {
        binary_index_t BIdx;
        function_index_t FIdx;
        std::tie(BIdx, FIdx) = IdxPair;

        function_t &f =
            Decompilation.Binaries.at(BIdx).Analysis.Functions.at(FIdx);

        f.IsABI = true;
      }
    }
  }
#endif

#if 0
  //
  // _start is *not* an ABI XXX
  //
  for (auto &binary : Decompilation.Binaries) {
    auto &A = binary.Analysis;
    if (binary.IsExecutable) {
      if (is_function_index_valid(A.EntryFunction))
        A.Functions.at(A.EntryFunction).IsABI = false;

      break;
    }
  }
#endif

  return 0;
}

int ProcessBinaryRelocations(void) {
  binary_t &b = Decompilation.Binaries[BinaryIndex];

  assert(llvm::isa<ELFO>(b.ObjectFile.get()));
  ELFO &O = *llvm::cast<ELFO>(b.ObjectFile.get());

  TheTriple = O.makeTriple();
  Features = O.getFeatures();

  const ELFF &E = *O.getELFFile();

  auto dynamic_table = [&](void) -> Elf_Dyn_Range {
    return b._elf.DynamicTable.getAsArrayRef<Elf_Dyn>();
  };

  auto OptionalDynSymRegion = b._elf.OptionalDynSymRegion;

  if (!OptionalDynSymRegion)
    return 0; /* no dynamic symbols */

  const DynRegionInfo &DynSymRegion = *OptionalDynSymRegion;

  auto dynamic_symbols = [&](void) -> Elf_Sym_Range {
    return DynSymRegion.getAsArrayRef<Elf_Sym>();
  };

  DynRegionInfo DynRelRegion(O.getFileName());
  DynRegionInfo DynRelaRegion(O.getFileName());
  DynRegionInfo DynRelrRegion(O.getFileName());
  DynRegionInfo DynPLTRelRegion(O.getFileName());

  loadDynamicRelocations(&E, &O,
                         b._elf.DynamicTable,
                         DynRelRegion,
                         DynRelaRegion,
                         DynRelrRegion,
                         DynPLTRelRegion);

  auto processDynamicReloc = [&](const Relocation &R) -> void {
    RelSymbol RelSym =
        getSymbolForReloc(O, dynamic_symbols(), b._elf.DynamicStringTable, R);

    if (RelSym.Sym)
      WithColor::note() << llvm::formatv("processDynamicReloc: RelSym: {0}\n", RelSym.Name);
    else
      WithColor::note() << "processDynamicReloc: no symbol\n";

    relocation_t &res = RelocationTable.emplace_back();

    res.Addr = R.Offset;
    res.Addend = R.Addend ? *R.Addend : 0;
    res.Type = relocation_type_of_elf_rela_type(R.Type);
    E.getRelocationTypeName(R.Type, res.RelocationTypeName);
    res.T = nullptr;
    res.C = nullptr;

    if (const Elf_Sym *Sym = RelSym.Sym) {
      res.SymbolIndex = SymbolTable.size();
      symbol_t &sym = SymbolTable.emplace_back();

      bool is_undefined = Sym->isUndefined() ||
                          Sym->st_shndx == llvm::ELF::SHN_UNDEF;

      sym.Name = RelSym.Name;
      sym.Addr = is_undefined ? 0 : Sym->st_value;
      sym.Visibility.IsDefault = false;

      sym.Type = sym_type_of_elf_sym_type(Sym->getType());
      sym.Size = Sym->st_size;
      sym.Bind = sym_binding_of_elf_sym_binding(Sym->getBinding());

      if (sym.Type == symbol_t::TYPE::NONE &&
          sym.Bind == symbol_t::BINDING::WEAK && !sym.Addr) {
        WithColor::warning() << llvm::formatv("making {0} into function symbol\n",
                                              sym.Name);
        sym.Type = symbol_t::TYPE::FUNCTION;
      }

      if (b._elf.SymbolVersionSection && b._elf.OptionalDynSymRegion) {
        // Determine the position in the symbol table of this entry.
        size_t EntryIndex =
            (reinterpret_cast<uintptr_t>(Sym) -
             reinterpret_cast<uintptr_t>(b._elf.OptionalDynSymRegion->Addr)) /
            sizeof(Elf_Sym);

        // Get the corresponding version index entry.
        llvm::Expected<const Elf_Versym *> ExpectedVersym =
            E.getEntry<Elf_Versym>(b._elf.SymbolVersionSection, EntryIndex);

        if (ExpectedVersym) {
          sym.Vers = getSymbolVersionByIndex(b._elf.VersionMap,
                                             b._elf.DynamicStringTable,
                                             (*ExpectedVersym)->vs_index,
                                             sym.Visibility.IsDefault);
        }
      }
    } else {
      res.SymbolIndex = std::numeric_limits<unsigned>::max();
    }
  };

  for_each_dynamic_relocation(E,
                              DynRelRegion,
                              DynRelaRegion,
                              DynRelrRegion,
                              DynPLTRelRegion,
                              processDynamicReloc);

#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
  MipsGOTParser Parser(E, b.Path);
  if (llvm::Error Err = Parser.findGOT(dynamic_table(),
                                       dynamic_symbols())) {
    WithColor::warning() << llvm::formatv("Parser.findGOT failed: {0}\n", Err);
    return 1;
  }

  if (Parser.isGotEmpty())
    WithColor::note() << "Parser.isGotEmpty()\n";

  for (const MipsGOTParser::Entry &Ent : Parser.getLocalEntries()) {
    const target_ulong Addr = Parser.getGotAddress(&Ent);

    llvm::outs() << llvm::formatv("LocalEntry: {0:x}\n", Addr);

    relocation_t &res = RelocationTable.emplace_back();
    res.Type = relocation_t::TYPE::RELATIVE;
    res.Addr = Addr;
    res.Addend = 0;
    res.SymbolIndex = std::numeric_limits<unsigned>::max();
    res.T = nullptr;
    res.C = nullptr;
    res.RelocationTypeName = "LocalGOTEntry";
  }

  for (const MipsGOTParser::Entry &Ent : Parser.getGlobalEntries()) {
    const target_ulong Addr = Parser.getGotAddress(&Ent);

    const Elf_Sym *Sym = Parser.getGotSym(&Ent);

    assert(Sym);

    bool is_undefined =
        Sym->isUndefined() || Sym->st_shndx == llvm::ELF::SHN_UNDEF;

    if (!Ent)
      assert(is_undefined);

    if (!is_undefined) {
      assert(Sym->st_size);
      assert(Sym->st_value);
      assert(Ent);
    }


    llvm::Expected<llvm::StringRef> ExpectedSymName = Sym->getName(b._elf.DynamicStringTable);
    if (!ExpectedSymName)
      continue;

    llvm::StringRef SymName = *ExpectedSymName;

    llvm::outs() << llvm::formatv("GlobalEntry: {0} {1}\n", Ent,
                                  SymName);

    relocation_t &res = RelocationTable.emplace_back();
    res.Type = relocation_t::TYPE::ADDRESSOF;
    res.Addr = Addr;
    res.Addend = 0;
    res.SymbolIndex = SymbolTable.size();
    {
      symbol_t &sym = SymbolTable.emplace_back();

      sym.Name = SymName;
      sym.Addr = is_undefined ? 0 : Sym->st_value;
      sym.Visibility.IsDefault = false;

      sym.Type = sym_type_of_elf_sym_type(Sym->getType());
      sym.Size = Sym->st_size;
      sym.Bind = sym_binding_of_elf_sym_binding(Sym->getBinding());
    }

    res.T = nullptr;
    res.C = nullptr;
    res.RelocationTypeName = "GlobalGOTEntry";
  }
#endif

  //
  // print relocations & symbols
  //
  llvm::outs() << "\nRelocations:\n\n";
  for (relocation_t &reloc : RelocationTable) {
    llvm::outs() << "  " <<
      (fmt("%-12s [%-12s] @ %-16x +%-16x") % string_of_reloc_type(reloc.Type)
                                           % reloc.RelocationTypeName.c_str()
                                           % reloc.Addr
                                           % reloc.Addend).str();

    if (reloc.SymbolIndex < SymbolTable.size()) {
      symbol_t &sym = SymbolTable[reloc.SymbolIndex];
      llvm::outs() <<
        (fmt("%-30s *%-10s *%-8s @ %x {%d}")
         % sym.Name
         % string_of_sym_type(sym.Type)
         % string_of_sym_binding(sym.Bind)
         % sym.Addr
         % sym.Size).str();
    }
    llvm::outs() << '\n';
  }

  for (const relocation_t &R : RelocationTable) {
    switch (R.Type) {
#if 0
    case relocation_t::TYPE::RELATIVE:
#endif
    case relocation_t::TYPE::IRELATIVE:
    case relocation_t::TYPE::ABSOLUTE:
    case relocation_t::TYPE::ADDRESSOF:
#if 0
    case relocation_t::TYPE::TPOFF:
#endif
    case relocation_t::TYPE::TPMOD:
      ConstantRelocationLocs.insert(R.Addr);
      break;

    default:
      break;
    }
  }

  return 0;
}

int ProcessIFuncResolvers(void) {
  auto &FuncMap = Decompilation.Binaries[BinaryIndex].FuncMap;
  auto &binary = Decompilation.Binaries[BinaryIndex];

  assert(llvm::isa<ELFO>(binary.ObjectFile.get()));
  ELFO &O = *llvm::cast<ELFO>(binary.ObjectFile.get());
  const ELFF &E = *O.getELFFile();

  for (const relocation_t &R : RelocationTable) {
    if (R.Type != relocation_t::TYPE::IRELATIVE)
      continue;

    target_ulong ifunc_resolver_addr = R.Addend;
    if (!ifunc_resolver_addr) {
      llvm::Expected<const uint8_t *> ExpectedPtr = E.toMappedAddr(R.Addr);
      if (ExpectedPtr) {
        ifunc_resolver_addr = *reinterpret_cast<const target_ulong *>(*ExpectedPtr);
      } else {
        WARN();
        continue;
      }
    }

    assert(ifunc_resolver_addr);

    auto it = FuncMap.find(ifunc_resolver_addr);
    assert(it != FuncMap.end());

    function_t &resolver = binary.Analysis.Functions[(*it).second];
    assert(resolver.IsABI);
    resolver.IsABI = true;
  }

  auto dynamic_table = [&](void) -> Elf_Dyn_Range {
    return binary._elf.DynamicTable.getAsArrayRef<Elf_Dyn>();
  };

  if (!binary._elf.OptionalDynSymRegion)
    return 0; /* no dynamic symbols */

  const DynRegionInfo &DynSymRegion = *binary._elf.OptionalDynSymRegion;

  auto dynamic_symbols = [&](void) -> Elf_Sym_Range {
    return DynSymRegion.getAsArrayRef<Elf_Sym>();
  };

  for (const Elf_Sym &Sym : dynamic_symbols()) {
    if (Sym.isUndefined()) /* defined */
      continue;
    if (Sym.getType() != llvm::ELF::STT_GNU_IFUNC)
      continue;

    auto it = FuncMap.find(Sym.st_value);
    if (it == FuncMap.end()) {
      WithColor::error() << llvm::formatv("Sym.st_value={0:x}\n",
                                          Sym.st_value);
    }
    assert(it != FuncMap.end());

    function_t &resolver = binary.Analysis.Functions.at((*it).second);
    resolver.IsABI = true;
  }

  //
  // DT_INIT
  //
  target_ulong initFunctionAddr = 0;

  for (const Elf_Dyn &Dyn : dynamic_table()) {
    if (unlikely(Dyn.d_tag == llvm::ELF::DT_NULL))
      break; /* marks end of dynamic table. */

    if (Dyn.d_tag == llvm::ELF::DT_INIT) {
      if (opts::Verbose)
        WithColor::note() << llvm::formatv("DT_INIT: {0}\n", Dyn.getVal());

      if (uint64_t X = Dyn.getVal()) {
        initFunctionAddr = Dyn.getVal();
        break;
      }
    }
  }

  if (initFunctionAddr) {
    WithColor::note() << llvm::formatv("we think initFunctionAddr is {0:x}\n", initFunctionAddr);

    auto it = FuncMap.find(initFunctionAddr);
    assert(it != FuncMap.end());

    function_t &f =
        Decompilation.Binaries[BinaryIndex].Analysis.Functions[(*it).second];
    assert(f.IsABI);
  }

  return 0;
}

int PrepareToTranslateCode(void) {
  TCG.reset(new tiny_code_generator_t);

  llvm::InitializeAllTargets();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllAsmPrinters();
  llvm::InitializeAllAsmParsers();
  llvm::InitializeAllDisassemblers();

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

  {
    llvm::MCTargetOptions Options;
    AsmInfo.reset(TheTarget->createMCAsmInfo(*MRI, TripleName, Options));
  }
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
#if defined(TARGET_X86_64)
      1 /* intel please */
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

  binary_t &Binary = Decompilation.Binaries[BinaryIndex];

  DIBuilder.reset(new llvm::DIBuilder(*Module));

  llvm::DIBuilder &DIB = *DIBuilder;

  DebugInformation.File =
      DIB.createFile(fs::path(Binary.Path).filename().string() + ".fake",
                     fs::path(Binary.Path).parent_path().string());

  DebugInformation.CompileUnit = DIB.createCompileUnit(
      /* Lang        */ llvm::dwarf::DW_LANG_C,
      /* File        */ DebugInformation.File,
      /* Producer    */ "jove",
      /* isOptimized */ true,
      /* Flags       */ "",
      /* RunTimeVer  */ 0);

  return 0;
}

static bool shouldExpandOperationWithSize(llvm::Value *Size) {
  if (opts::DFSan) /* erase all notions of contiguous memory */
    return true;

  constexpr unsigned MaxStaticSize = 32;

  llvm::ConstantInt *CI = llvm::dyn_cast<llvm::ConstantInt>(Size);
  return !CI || (CI->getZExtValue() > MaxStaticSize);
}

// from AMDGPULowerIntrinsics.cpp
static void expandMemIntrinsicUses(llvm::Function &F) {
  llvm::Intrinsic::ID ID = F.getIntrinsicID();

  for (auto I = F.user_begin(), E = F.user_end(); I != E;) {
    llvm::Instruction *Inst = llvm::cast<llvm::Instruction>(*I);
    ++I;

    switch (ID) {
    case llvm::Intrinsic::memcpy: {
      auto *Memcpy = llvm::cast<llvm::MemCpyInst>(Inst);
      if (shouldExpandOperationWithSize(Memcpy->getLength())) {
#if 0
        llvm::Function *ParentFunc = Memcpy->getParent()->getParent();
        const TargetTransformInfo &TTI =
            getAnalysis<llvm::TargetTransformInfoWrapperPass>().getTTI(*ParentFunc);
#else
        llvm::TargetTransformInfo TTI(DL);
#endif
        llvm::expandMemCpyAsLoop(Memcpy, TTI);
        Memcpy->eraseFromParent();
      }

      break;
    }
    case llvm::Intrinsic::memmove: {
      auto *Memmove = llvm::cast<llvm::MemMoveInst>(Inst);
      if (shouldExpandOperationWithSize(Memmove->getLength())) {
        llvm::expandMemMoveAsLoop(Memmove);
        Memmove->eraseFromParent();
      }

      break;
    }
    case llvm::Intrinsic::memset: {
      auto *Memset = llvm::cast<llvm::MemSetInst>(Inst);
      if (shouldExpandOperationWithSize(Memset->getLength())) {
        llvm::expandMemSetAsLoop(Memset);
        Memset->eraseFromParent();
      }

      break;
    }
    default:
      break;
    }
  }
}

static tcg_global_set_t DetermineFunctionArgs(function_t &f) {
  f.Analyze();

  return f.Analysis.args;
}

static tcg_global_set_t DetermineFunctionRets(function_t &f) {
  f.Analyze();

  return f.Analysis.rets;
}

void ExplodeFunctionArgs(function_t &f, std::vector<unsigned> &glbv) {
  tcg_global_set_t args = DetermineFunctionArgs(f);

  if (f.IsABI)
    args &= CallConvArgs;

  explode_tcg_global_set(glbv, args);

  if (f.IsABI) {
    std::sort(glbv.begin(), glbv.end(), [](unsigned a, unsigned b) {
      return std::find(CallConvArgArray.begin(), CallConvArgArray.end(), a) <
             std::find(CallConvArgArray.begin(), CallConvArgArray.end(), b);
    });

    return;
  }

  // otherwise, the order we want to impose is
  // CallConvArgs [sorted as CallConvArgs] ... !(CallConvArgs) [sorted by index]
  std::sort(glbv.begin(), glbv.end(), [](unsigned a, unsigned b) {
    CallConvArgArrayTy::const_iterator a_it =
        std::find(CallConvArgArray.begin(), CallConvArgArray.end(), a);
    CallConvArgArrayTy::const_iterator b_it =
        std::find(CallConvArgArray.begin(), CallConvArgArray.end(), b);

    bool A = a_it != CallConvArgArray.end();
    bool B = b_it != CallConvArgArray.end();

    if (A && B)
      return a_it < b_it;

    if (A && !B)
      return 0 < 1;

    if (!A && B)
      return 1 < 0;

    if (!A && !B)
      return a < b;

    __builtin_trap();
    __builtin_unreachable();
  });
}

void ExplodeFunctionRets(function_t &f, std::vector<unsigned> &glbv) {
  tcg_global_set_t rets = DetermineFunctionRets(f);

  if (f.IsABI)
    rets &= CallConvRets;

  explode_tcg_global_set(glbv, rets);

  if (f.IsABI) {
    std::sort(glbv.begin(), glbv.end(), [](unsigned a, unsigned b) {
      return std::find(CallConvRetArray.begin(), CallConvRetArray.end(), a) <
             std::find(CallConvRetArray.begin(), CallConvRetArray.end(), b);
    });

    return;
  }

  // otherwise, the order we want to impose is
  // CallConvRets [sorted as CallConvRets] ... !(CallConvRets) [sorted by index]
  std::sort(glbv.begin(), glbv.end(), [](unsigned a, unsigned b) {
    CallConvRetArrayTy::const_iterator a_it =
        std::find(CallConvRetArray.begin(), CallConvRetArray.end(), a);
    CallConvRetArrayTy::const_iterator b_it =
        std::find(CallConvRetArray.begin(), CallConvRetArray.end(), b);

    bool A = a_it != CallConvRetArray.end();
    bool B = b_it != CallConvRetArray.end();

    if (A && B)
      return a_it < b_it;

    if (A && !B)
      return 0 < 1;

    if (!A && B)
      return 1 < 0;

    if (!A && !B)
      return a < b;

    __builtin_trap();
    __builtin_unreachable();
  });
}

static unsigned bitsOfTCGType(TCGType ty) {
  switch (ty) {
  case TCG_TYPE_I32:
    return 32;
  case TCG_TYPE_I64:
    return 64;

  case TCG_TYPE_V64:
  case TCG_TYPE_V128:
  case TCG_TYPE_V256:
    WithColor::error() << "vector TCGType\n";
    abort();

  default:
    WithColor::error() << "unknown TCGType\n";
    abort();
  }
}

llvm::FunctionType *DetermineFunctionType(function_t &f) {
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

llvm::FunctionType *DetermineFunctionType(binary_index_t BinIdx,
                                          function_index_t FuncIdx) {
  return DetermineFunctionType(
      Decompilation.Binaries[BinIdx].Analysis.Functions[FuncIdx]);
}

llvm::FunctionType *DetermineFunctionType(
    const std::pair<binary_index_t, function_index_t> &FuncIdxPair) {
  return DetermineFunctionType(FuncIdxPair.first, FuncIdxPair.second);
}

int CreateFunctions(void) {
  binary_t &Binary = Decompilation.Binaries[BinaryIndex];
  interprocedural_control_flow_graph_t &ICFG = Binary.Analysis.ICFG;

  for (function_index_t FuncIdx = 0; FuncIdx < Binary.Analysis.Functions.size();
       ++FuncIdx) {
    function_t &f = Binary.Analysis.Functions[FuncIdx];

    if (!is_basic_block_index_valid(f.Entry))
      continue;

    if (!f.IsABI && !f.Syms.empty())
      WithColor::warning() << llvm::formatv(
          "!f.IsABI && !f.Syms.empty() where f.Syms[0] is {0} {1}\n",
          f.Syms.front().Name, f.Syms.front().Vers);

    std::string jove_name = (fmt("%c%lx") % (f.IsABI ? 'J' : 'j') %
                             ICFG[boost::vertex(f.Entry, ICFG)].Addr)
                                .str();

    f.F = llvm::Function::Create(DetermineFunctionType(f),
                                 f.IsABI ? llvm::GlobalValue::ExternalLinkage
                                         : llvm::GlobalValue::InternalLinkage,
                                 jove_name, Module.get());
#if defined(TARGET_I386)
    if (f.IsABI) {
      for (unsigned i = 0; i < f.F->arg_size(); ++i) {
        f.F->addParamAttr(i, llvm::Attribute::InReg);
      }
    }
#endif

    //f.F->addFnAttr(llvm::Attribute::UWTable);

    target_ulong Addr = ICFG[boost::vertex(f.Entry, ICFG)].Addr;
    unsigned off = Addr - Binary.SectsStartAddr;

    for (const symbol_t &sym : f.Syms) {
      // XXX hack for glibc 2.32+
      if (sym.Name == "__libc_early_init" &&
          sym.Vers == "GLIBC_PRIVATE")
        continue;

      if (sym.Vers.empty()) {
#if 0
        llvm::GlobalAlias::create(sym.Name, f.F);
#else
        Module->appendModuleInlineAsm(
            (fmt(".globl %s\n"
                 ".type  %s,@function\n"
                 ".set   %s, __jove_sections_%u + %u")
             % sym.Name
             % sym.Name
             % sym.Name % BinaryIndex % off).str());
#endif
      } else {
         // make sure version node is defined
        VersionScript.Table[sym.Vers];

#if 0
        Module->appendModuleInlineAsm(
            (llvm::Twine(".symver ") + jove_name + "," + sym.Name +
             (sym.Visibility.IsDefault ? "@@" : "@") + sym.Vers)
                .str());
#else
        std::string dummy_name = (fmt("_dummy_%lx_%d") % Addr % rand()).str();

        Module->appendModuleInlineAsm(
            (fmt(".globl %s\n"
                 ".hidden %s\n"
                 ".type  %s,@function\n"
                 ".set   %s, __jove_sections_%u + %u")
             % dummy_name
             % dummy_name
             % dummy_name
             % dummy_name % BinaryIndex % off).str());

        Module->appendModuleInlineAsm(
            (llvm::Twine(".symver ") + dummy_name + "," + sym.Name +
             (sym.Visibility.IsDefault ? "@@" : "@") + sym.Vers)
                .str());
#endif
      }
    }

    if (f.IsABI)
      f.F->setVisibility(llvm::GlobalValue::HiddenVisibility);

    //
    // assign names to the arguments, the registers they represent
    //
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

int CreateFunctionTables(void) {
  for (binary_index_t BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx) {
    binary_t &binary = Decompilation.Binaries[BIdx];
    if (binary.IsDynamicLinker)
      continue;
    if (binary.IsVDSO)
      continue;
    if (binary.IsDynamicallyLoaded)
      continue;
    if (opts::ForeignLibs && !binary.IsExecutable)
      continue;

    binary.SectsF = llvm::Function::Create(
        llvm::FunctionType::get(WordType(), false),
        llvm::GlobalValue::ExternalLinkage,
        (fmt("__jove_b%u_sects") % BIdx).str(), Module.get());

    if (BIdx == BinaryIndex)
      continue;

    binary.FunctionsTable = new llvm::GlobalVariable(
        *Module,
        llvm::ArrayType::get(WordType(),
                             2 * binary.Analysis.Functions.size() + 1),
        false, llvm::GlobalValue::ExternalLinkage, nullptr,
        (fmt("__jove_b%u") % BIdx).str());
  }

  return 0;
}

int CreateFunctionTable(void) {
  binary_t &Binary = Decompilation.Binaries[BinaryIndex];
  auto &ICFG = Binary.Analysis.ICFG;

  if (Binary.SectsF) {
    //
    // define SectsF
    //
#if 1
    llvm::DIBuilder &DIB = *DIBuilder;
    llvm::DISubprogram::DISPFlags SubProgFlags =
        llvm::DISubprogram::SPFlagDefinition |
        llvm::DISubprogram::SPFlagOptimized;

    SubProgFlags |= llvm::DISubprogram::SPFlagLocalToUnit;

    llvm::DISubroutineType *SubProgType =
        DIB.createSubroutineType(DIB.getOrCreateTypeArray(llvm::None));

    struct {
      llvm::DISubprogram *Subprogram;
    } DebugInfo;

    DebugInfo.Subprogram = DIB.createFunction(
        /* Scope       */ DebugInformation.CompileUnit,
        /* Name        */ Binary.SectsF->getName(),
        /* LinkageName */ Binary.SectsF->getName(),
        /* File        */ DebugInformation.File,
        /* LineNo      */ 0,
        /* Ty          */ SubProgType,
        /* ScopeLine   */ 0,
        /* Flags       */ llvm::DINode::FlagZero,
        /* SPFlags     */ SubProgFlags);
#endif
    Binary.SectsF->setSubprogram(DebugInfo.Subprogram);

    llvm::BasicBlock *BB =
        llvm::BasicBlock::Create(*Context, "", Binary.SectsF);
    {
      llvm::IRBuilderTy IRB(BB);
#if 1
      IRB.SetCurrentDebugLocation(llvm::DILocation::get(
          *Context, 0 /* Line */, 0 /* Column */, DebugInfo.Subprogram));
#endif

      IRB.CreateRet(llvm::ConstantExpr::getPtrToInt(SectsGlobal, WordType()));
    }
  }

  std::vector<llvm::Constant *> constantTable;
  constantTable.resize(2 * Binary.Analysis.Functions.size());

  for (unsigned i = 0; i < Binary.Analysis.Functions.size(); ++i) {
    const function_t &f = Binary.Analysis.Functions[i];

    llvm::Constant *&C1 = constantTable[2 * i + 0];
    llvm::Constant *&C2 = constantTable[2 * i + 1];

    if (unlikely(!is_basic_block_index_valid(f.Entry))) {
      C1 = llvm::Constant::getNullValue(WordType());
      C2 = llvm::Constant::getNullValue(WordType());
      continue;
    }

    C1 = SectionPointer(ICFG[boost::vertex(f.Entry, ICFG)].Addr);
    C2 = llvm::ConstantExpr::getPtrToInt(f.F, WordType());
  }

  constantTable.push_back(llvm::Constant::getNullValue(WordType()));

  llvm::ArrayType *T = llvm::ArrayType::get(WordType(), constantTable.size());
  llvm::Constant *Init = llvm::ConstantArray::get(T, constantTable);
  llvm::GlobalVariable *ConstantTableGV = new llvm::GlobalVariable(
      *Module, T, true, llvm::GlobalValue::ExternalLinkage, Init,
      (fmt("__jove_b%u") % BinaryIndex).str());

  llvm::GlobalVariable *ConstantTableInternalGV = new llvm::GlobalVariable(
      *Module, T, true, llvm::GlobalValue::InternalLinkage, Init,
      (fmt("__jove_internal_b%u") % BinaryIndex).str());

  llvm::Function *GetFunctionTableF =
      Module->getFunction("_jove_get_function_table");
  assert(GetFunctionTableF && GetFunctionTableF->empty());

  llvm::DIBuilder &DIB = *DIBuilder;
  llvm::DISubprogram::DISPFlags SubProgFlags =
      llvm::DISubprogram::SPFlagDefinition |
      llvm::DISubprogram::SPFlagOptimized;

  SubProgFlags |= llvm::DISubprogram::SPFlagLocalToUnit;

  llvm::DISubroutineType *SubProgType =
      DIB.createSubroutineType(DIB.getOrCreateTypeArray(llvm::None));

  struct {
    llvm::DISubprogram *Subprogram;
  } DebugInfo;

  DebugInfo.Subprogram = DIB.createFunction(
      /* Scope       */ DebugInformation.CompileUnit,
      /* Name        */ GetFunctionTableF->getName(),
      /* LinkageName */ GetFunctionTableF->getName(),
      /* File        */ DebugInformation.File,
      /* LineNo      */ 0,
      /* Ty          */ SubProgType,
      /* ScopeLine   */ 0,
      /* Flags       */ llvm::DINode::FlagZero,
      /* SPFlags     */ SubProgFlags);
  GetFunctionTableF->setSubprogram(DebugInfo.Subprogram);

  llvm::BasicBlock *BB =
      llvm::BasicBlock::Create(*Context, "", GetFunctionTableF);

  {
    llvm::IRBuilderTy IRB(BB);

    IRB.SetCurrentDebugLocation(llvm::DILocation::get(
        *Context, 0 /* Line */, 0 /* Column */, DebugInfo.Subprogram));

    IRB.CreateRet(IRB.CreateConstInBoundsGEP2_64(ConstantTableInternalGV, 0, 0));
  }

  GetFunctionTableF->setLinkage(llvm::GlobalValue::InternalLinkage);

  return 0;
}

} // namespace jove

namespace llvm {

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

llvm::Constant *SectionPointer(target_ulong Addr) {
  auto &Binary = Decompilation.Binaries[BinaryIndex];

  int64_t off =
      static_cast<int64_t>(Addr) -
      static_cast<int64_t>(Binary.SectsStartAddr);

  return llvm::ConstantExpr::getAdd(
      llvm::ConstantExpr::getPtrToInt(SectsGlobal, WordType()),
      llvm::ConstantInt::getSigned(WordType(), off));
}

int CreateTLSModGlobal(void) {
  TLSModGlobal = new llvm::GlobalVariable(
      *Module, WordType(), true, llvm::GlobalValue::InternalLinkage,
      llvm::ConstantInt::get(WordType(), 0x12345678), "__jove_tpmod");
  return 0;
}

static std::pair<binary_index_t, std::pair<target_ulong, unsigned>>
decipher_copy_relocation(const symbol_t &S);

int CreateSectionGlobalVariables(void) {
  binary_t &Binary = Decompilation.Binaries[BinaryIndex];
  auto &ObjectFile = Binary.ObjectFile;
  auto &FuncMap = Binary.FuncMap;

  assert(llvm::isa<ELFO>(ObjectFile.get()));
  ELFO &O = *llvm::cast<ELFO>(ObjectFile.get());

  const ELFF &E = *O.getELFFile();

#if defined(TARGET_MIPS32) || defined(TARGET_MIPS64)
  //
  // on mips, we cannot rely on the SectionsGlobal to be not placed in
  // non executable memory (see READ_IMPLIES_EXEC)
  //
  struct PatchContents {
    std::vector<uint32_t> FunctionOrigInsnTable;

    PatchContents() {
      auto &Binary = Decompilation.Binaries[BinaryIndex];
      auto &ICFG = Binary.Analysis.ICFG;

      FunctionOrigInsnTable.resize(Binary.Analysis.Functions.size());

      for (function_index_t FIdx = 0; FIdx <  Binary.Analysis.Functions.size(); ++FIdx) {
        function_t &f = Binary.Analysis.Functions[FIdx];
        if (!is_basic_block_index_valid(f.Entry))
          continue;

        target_ulong Addr = ICFG[boost::vertex(f.Entry, ICFG)].Addr;

        uint32_t &insn = *((uint32_t *)binary_data_ptr_of_addr(Addr));

        FunctionOrigInsnTable[FIdx] = insn;
      }

      for (function_index_t FIdx = 0; FIdx <  Binary.Analysis.Functions.size(); ++FIdx) {
        function_t &f = Binary.Analysis.Functions[FIdx];
        if (!is_basic_block_index_valid(f.Entry))
          continue;

        target_ulong Addr = ICFG[boost::vertex(f.Entry, ICFG)].Addr;

        uint32_t &insn = *((uint32_t *)binary_data_ptr_of_addr(Addr));

        insn = 0x8c010000; /* lw at,0(zero) ; <- guaranteed to SIGSEGV */
      }
    }
    ~PatchContents() {
      auto &Binary = Decompilation.Binaries[BinaryIndex];
      auto &ICFG = Binary.Analysis.ICFG;

      //
      // restore original insns
      //
      for (function_index_t FIdx = 0; FIdx <  Binary.Analysis.Functions.size(); ++FIdx) {
        function_t &f = Binary.Analysis.Functions[FIdx];
        if (!is_basic_block_index_valid(f.Entry))
          continue;

        target_ulong Addr = ICFG[boost::vertex(f.Entry, ICFG)].Addr;

        uint32_t &insn = *((uint32_t *)binary_data_ptr_of_addr(Addr));

        insn = FunctionOrigInsnTable[FIdx];
      }
    }

    void *binary_data_ptr_of_addr(target_ulong Addr) {
      auto &Binary = Decompilation.Binaries[BinaryIndex];
      auto &ObjectFile = Binary.ObjectFile;

      const ELFF &E = *llvm::cast<ELFO>(ObjectFile.get())->getELFFile();

      llvm::Expected<const uint8_t *> ExpectedPtr = E.toMappedAddr(Addr);

      if (!ExpectedPtr) {
        WithColor::warning() << llvm::formatv(
            "{0}: Could not get binary contents for {1:x}\n", __func__, Addr);
        return nullptr;
      }

      return const_cast<uint8_t *>(*ExpectedPtr);
    }
  } __PatchContents;
#endif

  unsigned NumSections = 0;
  boost::icl::split_interval_map<tcg_uintptr_t, section_properties_set_t> SectMap;
  std::vector<section_t> SectTable;
  boost::icl::interval_map<target_ulong, unsigned> SectIdxMap;

  std::vector<std::vector<uint8_t>> SegContents;

  const tcg_uintptr_t SectsStartAddr = Binary.SectsStartAddr;
  const tcg_uintptr_t SectsEndAddr = Binary.SectsEndAddr;

  llvm::Expected<Elf_Shdr_Range> ExpectedSections = E.sections();
  if (ExpectedSections && !(*ExpectedSections).empty()) {
    //
    // build section map
    //
    for (const Elf_Shdr &Sec : *ExpectedSections) {
      if (!(Sec.sh_flags & llvm::ELF::SHF_ALLOC))
        continue;

      llvm::Expected<llvm::StringRef> name = E.getSectionName(&Sec);

      if (!name)
        continue;

      if ((Sec.sh_flags & llvm::ELF::SHF_TLS) &&
          *name == std::string(".tbss"))
        continue;

      if (!Sec.sh_size)
        continue;

      section_properties_t sectprop;
      sectprop.name = *name;

      if (Sec.sh_type == llvm::ELF::SHT_NOBITS) {
        sectprop.contents = llvm::ArrayRef<uint8_t>();
      } else {
        llvm::Expected<llvm::ArrayRef<uint8_t>> contents =
            E.getSectionContents(&Sec);
        assert(contents);
        sectprop.contents = *contents;
      }

      sectprop.w = !!(Sec.sh_flags & llvm::ELF::SHF_WRITE);
      sectprop.x = !!(Sec.sh_flags & llvm::ELF::SHF_EXECINSTR);

      sectprop.initArray = Sec.sh_type == llvm::ELF::SHT_INIT_ARRAY;
      sectprop.finiArray = Sec.sh_type == llvm::ELF::SHT_FINI_ARRAY;

      boost::icl::interval<target_ulong>::type intervl =
          boost::icl::interval<target_ulong>::right_open(
              Sec.sh_addr, Sec.sh_addr + Sec.sh_size);

      {
        auto it = SectMap.find(intervl);
        if (it != SectMap.end()) {
          WithColor::error() << "the following sections intersect: "
                             << (*(*it).second.begin()).name << " and "
                             << sectprop.name << '\n';
          return 1;
        }
      }

      SectMap.add({intervl, {sectprop}});
    }

    NumSections = SectMap.iterative_size();
    SectTable.resize(NumSections);

    unsigned i = 0;
    for (const auto &pair : SectMap) {
      section_t &Sect = SectTable[i];

      SectIdxMap.add({pair.first, 1+i});

      const section_properties_t &prop = *pair.second.begin();
      Sect.Addr = pair.first.lower();
      Sect.Size = pair.first.upper() - pair.first.lower();
      Sect.Name = prop.name;
      Sect.Contents = prop.contents;
      Sect.Stuff.Intervals.insert(
          boost::icl::interval<target_ulong>::right_open(0, Sect.Size));
      Sect.initArray = prop.initArray;
      Sect.finiArray = prop.finiArray;

      ++i;
    }
  } else {
    llvm::SmallVector<const Elf_Phdr *, 4> LoadSegments;

    auto ProgramHeadersOrError = E.program_headers();
    if (!ProgramHeadersOrError)
      abort();

    for (const Elf_Phdr &Phdr : *ProgramHeadersOrError) {
      if (Phdr.p_type != llvm::ELF::PT_LOAD)
        continue;

      LoadSegments.push_back(&Phdr);
    }

    assert(!LoadSegments.empty());

    std::stable_sort(LoadSegments.begin(),
                     LoadSegments.end(),
                     [](const Elf_Phdr *A,
                        const Elf_Phdr *B) {
                       return A->p_vaddr < B->p_vaddr;
                     });

    /* XXX */
    NumSections = LoadSegments.size();
    SectTable.resize(NumSections);
    SegContents.resize(NumSections);
    for (unsigned i = 0; i < NumSections; ++i) {
      assert(LoadSegments[i]->p_filesz <= LoadSegments[i]->p_memsz);

      std::vector<uint8_t> &vec = SegContents[i];
      vec.resize(LoadSegments[i]->p_memsz);
      memset(&vec[0], 0, vec.size());
      memcpy(&vec[0], E.base() + LoadSegments[i]->p_offset, LoadSegments[i]->p_filesz);

      boost::icl::interval<target_ulong>::type intervl =
          boost::icl::interval<target_ulong>::right_open(
              LoadSegments[i]->p_vaddr,
              LoadSegments[i]->p_vaddr + LoadSegments[i]->p_memsz);

      SectIdxMap.add({intervl, 1+i});

      {
        section_properties_t sectprop;

        sectprop.name = (fmt(".seg.%u") % i).str();
        sectprop.contents = vec;
        sectprop.w = true;
        sectprop.x = false;
        sectprop.initArray = false;
        sectprop.finiArray = false;

        SectMap.add({intervl, {sectprop}});
      }

      {
        section_t &s = SectTable[i];

        s.Addr = LoadSegments[i]->p_vaddr;
        s.Size = LoadSegments[i]->p_memsz;
        s.Name = (fmt(".seg.%u") % i).str();
        s.Contents = vec;
        s.Stuff.Intervals.insert(
            boost::icl::interval<target_ulong>::right_open(0, s.Size));
        s.initArray = false;
        s.finiArray = false;
        s.T = nullptr;
      }
    }
  }

  auto type_at_address = [&](target_ulong Addr, llvm::Type *T) -> void {
    auto it = SectIdxMap.find(Addr);
    assert(it != SectIdxMap.end());

    section_t &Sect = SectTable[(*it).second - 1];
    unsigned Off = Addr - Sect.Addr;

    Sect.Stuff.Intervals.insert(boost::icl::interval<target_ulong>::right_open(
        Off, Off + sizeof(target_ulong)));
    Sect.Stuff.Types[Off] = T;
  };

  auto type_of_addressof_undefined_function_relocation =
      [&](const relocation_t &R, const symbol_t &S) -> llvm::Type * {
    return WordType();
  };

  auto type_of_addressof_defined_function_relocation =
      [&](const relocation_t &R, const symbol_t &S) -> llvm::Type * {
    assert(!S.IsUndefined());

    return WordType();
  };

  auto type_of_addressof_undefined_data_relocation =
      [&](const relocation_t &R, const symbol_t &S) -> llvm::Type * {
    assert(S.IsUndefined());
#if 0
    assert(!S.Size);
#else
    if (!S.Size) {
      if (opts::Verbose)
        WithColor::warning() <<
          llvm::formatv("type_of_addressof_undefined_data_relocation: S.Name={0} S.Size={1}\n",
                        S.Name, S.Size);
    }
#endif

    unsigned Size;

    auto it = GlobalSymbolDefinedSizeMap.find(S.Name);
    if (it == GlobalSymbolDefinedSizeMap.end()) {
      WithColor::error() << llvm::formatv(
          "{0}: unknown size for {1}\n",
          "type_of_addressof_undefined_data_relocation", S.Name);
      Size = sizeof(target_ulong);
    } else {
      Size = (*it).second;
    }

    llvm::Type *T;
    if (is_integral_size(Size))
      T = llvm::Type::getIntNTy(*Context, Size * 8);
    else
      T = llvm::ArrayType::get(llvm::Type::getInt8Ty(*Context), Size);

    return llvm::PointerType::get(T, 0);
  };

  auto type_of_addressof_defined_data_relocation =
      [&](const relocation_t &R, const symbol_t &S) -> llvm::Type * {
    assert(!S.IsUndefined());

    return WordType();
  };

  auto type_of_relative_relocation =
      [&](const relocation_t &R) -> llvm::Type * {
    return WordType();
  };

  auto type_of_irelative_relocation =
      [&](const relocation_t &R) -> llvm::Type * {
    return WordType();
  };

  auto type_of_tpoff_relocation = [&](const relocation_t &R) -> llvm::Type * {
    return WordType();
  };

  auto type_of_tpmod_relocation = [&](const relocation_t &R) -> llvm::Type * {
    return TLSModGlobal->getType();
  };

  auto type_of_copy_relocation = [&](const relocation_t &R,
                                     const symbol_t &S) -> llvm::Type * {
    assert(R.Addr == S.Addr);

#if defined(TARGET_X86_64)
    const char *CopyRelocName = "R_X86_64_COPY";
#elif defined(TARGET_I386)
    const char *CopyRelocName = "R_386_COPY";
#elif defined(TARGET_AARCH64)
    const char *CopyRelocName = "R_AARCH64_COPY";
#elif defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
    const char *CopyRelocName = "R_MIPS_COPY";
#else
#error
#endif

    if (!S.Size) {
      WithColor::error() << llvm::formatv(
          "copy relocation @ {0:x} specifies symbol {1} with size 0\n",
          R.Addr, S.Name);
      abort();
    }

    WithColor::error() << llvm::formatv(
        "copy relocation @ {0:x} specifies symbol {1} with size {2}\n"
        "was prog compiled as position-independant (i.e. -fPIC)?\n",
        R.Addr, S.Name, S.Size);
    //abort();

    if (CopyRelocMap.find(std::pair<target_ulong, unsigned>(S.Addr, S.Size)) !=
        CopyRelocMap.end())
      return VoidType();

    //
    // the dreaded copy relocation. we have to figure out who really defines
    // the given symbol, and then insert an entry into a map we will read later
    // to generate code that copies bytes from said symbol located in shared
    // library to said symbol in executable
    //
    struct {
      binary_index_t BIdx;
      std::pair<target_ulong, unsigned> OffsetPair;
    } CopyFrom;

    //
    // find out who to copy from
    //
    std::tie(CopyFrom.BIdx, CopyFrom.OffsetPair) = decipher_copy_relocation(S);

    if (is_binary_index_valid(CopyFrom.BIdx))
      CopyRelocMap.emplace(std::pair<target_ulong, unsigned>(S.Addr, S.Size),
                           std::pair<binary_index_t, std::pair<target_ulong, unsigned>>(
                               CopyFrom.BIdx, CopyFrom.OffsetPair));

    return VoidType();
  };

  auto type_of_relocation = [&](const relocation_t &R) -> llvm::Type * {
    switch (R.Type) {
    case relocation_t::TYPE::ADDRESSOF: {
      assert(R.SymbolIndex < SymbolTable.size());
      const symbol_t &S = SymbolTable[R.SymbolIndex];

      switch (S.Type) {
      case symbol_t::TYPE::FUNCTION:
        if (S.IsUndefined())
          return type_of_addressof_undefined_function_relocation(R, S);
        else
          return type_of_addressof_defined_function_relocation(R, S);

#if 1
      default:
        WithColor::warning() << llvm::formatv(
            "addressof {0} has unknown symbol type; treating as data\n",
            S.Name);
#endif

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

    case relocation_t::TYPE::TPMOD:
      return type_of_tpmod_relocation(R);

    case relocation_t::TYPE::COPY: {
      assert(R.SymbolIndex < SymbolTable.size());
      const symbol_t &S = SymbolTable[R.SymbolIndex];

      return type_of_copy_relocation(R, S);
    }

    case relocation_t::TYPE::NONE:
      return VoidType();

    default:
      WithColor::error() << llvm::formatv(
          "type_of_relocation: unhandled relocation type {0}\n",
          string_of_reloc_type(R.Type));
      abort();
    }
  };

  auto constant_at_address = [&](target_ulong Addr, llvm::Constant *C) -> void {
    auto it = SectIdxMap.find(Addr);
    assert(it != SectIdxMap.end());

    section_t &Sect = SectTable[(*it).second - 1];
    unsigned Off = Addr - Sect.Addr;

#if 0
    Sect.Stuff.Intervals.insert(boost::icl::interval<uintptr_t>::right_open(
        Off, Off + sizeof(uintptr_t)));
#endif

    if (Sect.Stuff.Types.find(Off) == Sect.Stuff.Types.end())
      WithColor::warning() << llvm::formatv("%s:%d\n", __FILE__, __LINE__);

    Sect.Stuff.Constants[Off] = C;
  };

  auto constant_of_addressof_undefined_function_relocation =
      [&](const relocation_t &R, const symbol_t &S) -> llvm::Constant * {
    assert(S.IsUndefined());

    if (llvm::Function *F = Module->getFunction(S.Name))
      return llvm::ConstantExpr::getPtrToInt(F, WordType());

    llvm::FunctionType *FTy = nullptr;
    {
      auto &RelocDynTargets =
          Decompilation.Binaries[BinaryIndex].Analysis.RelocDynTargets;

      auto it = RelocDynTargets.find(R.Addr);
      if (it != RelocDynTargets.end() && !(*it).second.empty()) {
        auto &DynTargets = (*it).second;

        for (std::pair<binary_index_t, function_index_t> pair : DynTargets) {
          if (pair.first == BinaryIndex)
            continue;

          function_t &f = Decompilation.Binaries[pair.first].Analysis.Functions[pair.second];
          bool SavedIsABI = f.IsABI;
          if (!f.IsABI)
            f.IsABI = true; /* XXX */

          FTy = DetermineFunctionType(f);

          f.IsABI = SavedIsABI; /* undo the temporary change */
          break;
        }

        if (!FTy)
          FTy = llvm::FunctionType::get(VoidType(), false);
      } else {
        FTy = llvm::FunctionType::get(VoidType(), false);
      }
    }

    assert(FTy);

    llvm::Function *F =
        llvm::Function::Create(FTy,
                               S.Bind == symbol_t::BINDING::WEAK
                                   ? llvm::GlobalValue::ExternalWeakLinkage
                                   : llvm::GlobalValue::ExternalLinkage,
                               S.Name, Module.get());

    if (!S.Vers.empty()) {
      Module->appendModuleInlineAsm(
          (llvm::Twine(".symver ") + S.Name + "," + S.Name +
           (S.Visibility.IsDefault ? "@@" : "@") + S.Vers)
              .str());

      VersionScript.Table[S.Vers];
    }

    return llvm::ConstantExpr::getPtrToInt(F, WordType());
  };

  auto constant_of_addressof_defined_function_relocation =
      [&](const relocation_t &R, const symbol_t &S) -> llvm::Constant * {
    assert(!S.IsUndefined());

    return SectionPointer(S.Addr);
  };

  auto constant_of_addressof_undefined_data_relocation =
      [&](const relocation_t &R, const symbol_t &S) -> llvm::Constant * {
    assert(S.IsUndefined());
    WARN_ON(S.Size);

    llvm::GlobalVariable *GV = Module->getGlobalVariable(S.Name, false);

    if (GV)
      return GV;

    unsigned Size;

    auto it = GlobalSymbolDefinedSizeMap.find(S.Name);
    if (it == GlobalSymbolDefinedSizeMap.end()) {
      WithColor::error() << llvm::formatv(
          "{0}: unknown size for {1}\n",
          "constant_of_addressof_undefined_data_relocation", S.Name);

      Size = sizeof(target_ulong);
    } else {
      Size = (*it).second;
    }

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

    if (!S.Vers.empty()) {
      Module->appendModuleInlineAsm(
          (llvm::Twine(".symver ") + S.Name + "," + S.Name +
           (S.Visibility.IsDefault ? "@@" : "@") + S.Vers)
              .str());
    }

    return GV;
  };

  std::set<std::pair<uintptr_t, unsigned>> gdefs;

  auto constant_of_addressof_defined_data_relocation =
      [&](const relocation_t &R, const symbol_t &S) -> llvm::Constant * {
    assert(!S.IsUndefined());

#if !defined(TARGET_MIPS64) && !defined(TARGET_MIPS32)
    //
    // XXX XXX XXX this is unsound because it breaks assumptions of where a global
    // variable would exist in the sections, but we *need* it for COPY
    // relocations. FIXME
    //
    if (llvm::GlobalValue *GV = Module->getNamedValue(S.Name))
      return llvm::ConstantExpr::getPtrToInt(GV, WordType());

    AddrToSymbolMap[S.Addr].insert(S.Name);
    AddrToSizeMap[S.Addr] = S.Size;

    return nullptr;
#else
    unsigned off = S.Addr - SectsStartAddr;

    if (gdefs.find({S.Addr, S.Size}) == gdefs.end()) {
      Module->appendModuleInlineAsm(
          (fmt(".globl  %s\n"
               ".type   %s,@object\n"
               ".size   %s, %u\n"
               ".set    %s, __jove_sections_%u + %u")
           % S.Name
           % S.Name
           % S.Name % S.Size
           % S.Name % BinaryIndex % off).str());

      gdefs.insert({S.Addr, S.Size});
    }

    return SectionPointer(S.Addr);
#endif
  };

  auto constant_of_relative_relocation =
      [&](const relocation_t &R) -> llvm::Constant * {
#ifdef TARGET_MIPS32
    if (R.SymbolIndex < SymbolTable.size()) {
      const symbol_t &S = SymbolTable[R.SymbolIndex];
      if (!S.IsUndefined()) {
        if (llvm::GlobalValue *GV = Module->getNamedValue(S.Name))
          return llvm::ConstantExpr::getPtrToInt(GV, WordType());

        AddrToSymbolMap[S.Addr].insert(S.Name);
        AddrToSizeMap[S.Addr] = S.Size;

        return nullptr;
      } else {
        if (S.Type == symbol_t::TYPE::FUNCTION) {
          if (llvm::Function *F = Module->getFunction(S.Name))
            return llvm::ConstantExpr::getPtrToInt(F, WordType());

          return nullptr;
        } else if (S.Type == symbol_t::TYPE::DATA) {
          //
          // from constant_of_addressof_undefined_data_relocation XXX
          //
          llvm::GlobalVariable *GV = Module->getGlobalVariable(S.Name, false);

          if (GV)
            return llvm::ConstantExpr::getPtrToInt(GV, WordType());

          return nullptr;
        } else {
          WARN();
          return nullptr;
        }
      }
    }
#endif

    target_ulong Addr;
    if (R.Addend) {
      Addr = R.Addend;
    } else {
      llvm::Expected<const uint8_t *> ExpectedPtr = E.toMappedAddr(R.Addr);
      if (!ExpectedPtr)
        abort();

      Addr = *reinterpret_cast<const target_ulong *>(*ExpectedPtr);
    }

    if (opts::Verbose)
      WithColor::note() << llvm::formatv(
          "constant_of_relative_relocation: Addr is {0:x}\n", Addr);

#if 0
    auto it = FuncMap.find(Addr);
    if (it == FuncMap.end()) {
      llvm::Constant *C = SectionPointer(Addr);
      assert(C);
      return llvm::ConstantExpr::getPointerCast(
          C, llvm::PointerType::get(llvm::Type::getInt8Ty(*Context), 0));
    } else {
      binary_t &Binary = Decompilation.Binaries[BinaryIndex];
      return Binary.Analysis.Functions[(*it).second].F;
    }
#else
    llvm::Constant *C = SectionPointer(Addr);
    assert(C);
    return C;
#endif
  };

  auto constant_of_irelative_relocation =
      [&](const relocation_t &R) -> llvm::Constant * {
    std::pair<binary_index_t, function_index_t> IdxPair;

    {
      auto &RelocDynTargets =
          Decompilation.Binaries[BinaryIndex].Analysis.RelocDynTargets;

      auto it = RelocDynTargets.find(R.Addr);
      if (it == RelocDynTargets.end() || (*it).second.empty()) {
        WithColor::error() << llvm::formatv(
          "constant_of_irelative_relocation: no RelocDynTarget found (R.Addr={0:x},R.Addend={1:x}\n", R.Addr, R.Addend);

        target_ulong resolverAddr = R.Addend;
        if (!resolverAddr) {
          llvm::Expected<const uint8_t *> ExpectedPtr = E.toMappedAddr(R.Addr);
          if (!ExpectedPtr)
            abort();

          resolverAddr = *reinterpret_cast<const target_ulong *>(*ExpectedPtr);
        }

        auto resolver_f_it = FuncMap.find(resolverAddr);
        if (resolver_f_it == FuncMap.end()) {
          llvm::errs() << "constant_of_irelative_relocation: no function for resolver!\n";
          abort();
        } else {
          IRELATIVEHack.insert({R.Addr, {BinaryIndex, (*resolver_f_it).second}});
        }
        return llvm::Constant::getNullValue(WordType());
      } else {
        WithColor::error() << llvm::formatv(
          "constant_of_irelative_relocation: RelocDynTarget found (R.Addr={0:x},R.Addend={1:x}\n", R.Addr, R.Addend);
      }

      IdxPair = *(*it).second.begin();
    }

    binary_t &binary = Decompilation.Binaries.at(IdxPair.first);
    auto &ICFG = binary.Analysis.ICFG;
    function_t &f = binary.Analysis.Functions.at(IdxPair.second);
    target_ulong Addr = ICFG[boost::vertex(f.Entry, ICFG)].Addr;

    return SectionPointer(Addr);
  };

  auto constant_of_tpoff_relocation =
      [&](const relocation_t &R) -> llvm::Constant * {
    if (R.SymbolIndex < SymbolTable.size()) {
      const symbol_t &S = SymbolTable[R.SymbolIndex];

      assert(S.IsUndefined());
      assert(!S.Size);

      llvm::GlobalVariable *GV = Module->getGlobalVariable(S.Name, true);

      if (GV) {
        assert(TPOFFHack.find(R.Addr) != TPOFFHack.end());
        return llvm::ConstantExpr::getPtrToInt(GV, WordType());
      }

      auto it = GlobalSymbolDefinedSizeMap.find(S.Name);
      if (it == GlobalSymbolDefinedSizeMap.end()) {
        llvm::outs() << "fucked because we don't have the size for " << S.Name
                     << '\n';
        return nullptr;
      }

      unsigned Size = (*it).second;

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
                                    nullptr, S.Name, nullptr,
                                    llvm::GlobalValue::GeneralDynamicTLSModel);

      TPOFFHack[R.Addr] = GV;

#if 1
      return llvm::ConstantExpr::getPtrToInt(GV, WordType());
#else
      return llvm::ConstantInt::get(llvm::Type::getIntNTy(*Context, WordBits()), 0x12345678);
#endif
    }

#if defined(TARGET_I386) || defined(TARGET_MIPS32)
    unsigned tpoff;
    {
      llvm::Expected<const uint8_t *> ExpectedPtr = E.toMappedAddr(R.Addr);
      if (!ExpectedPtr)
        abort();

      tpoff = *reinterpret_cast<const target_ulong *>(*ExpectedPtr);
    }
    //WithColor::note() << llvm::formatv("TPOFF off={0}\n", off);
#else
    unsigned tpoff = R.Addend;
#endif

    auto it = TLSValueToSymbolMap.find(tpoff);
    if (it == TLSValueToSymbolMap.end()) {
      if (!TLSSectsGlobal) {
        WithColor::warning()
            << "constant_of_tpoff_relocation: !TLSSectsGlobal\n";
        return nullptr;
      }

#if 0
      WithColor::error() << llvm::formatv("no sym found for tpoff {0}; TLSValueToSymbolMap: {1}\n",
                                          tpoff,
                                          std::accumulate(
                                            TLSValueToSymbolMap.begin(),
                                            TLSValueToSymbolMap.end(),
                                            std::string(),
                                            [](const std::string &res, const std::pair<const uintptr_t, std::set<llvm::StringRef>>& pair) -> std::string {
                                                std::string s = std::string("{") + std::to_string(pair.first) + std::string(", {") +
                                                  std::accumulate(pair.second.begin(),
                                                                  pair.second.end(),
                                                                  std::string(),
                                                                  [](const std::string &res, llvm::StringRef Str) -> std::string {
                                                                    return res + (res.empty() ? std::string() : std::string(", ")) + Str.str();
                                                                  }) + std::string("}}");

                                                return res + (res.empty() ? std::string() : std::string(", ")) + s;
                                            }));
#endif

      llvm::Constant *res = llvm::ConstantExpr::getAdd(
          llvm::ConstantExpr::getPtrToInt(TLSSectsGlobal, WordType()),
          llvm::ConstantInt::get(WordType(), tpoff));

      TPOFFHack[R.Addr] = res;

      return res;
    }

    llvm::GlobalVariable *GV = nullptr;
    for (auto sym_it = (*it).second.begin(); sym_it != (*it).second.end(); ++sym_it) {
      GV = Module->getGlobalVariable(*sym_it);
      if (GV)
        break;
    }

    if (!GV) {
      WithColor::warning() << llvm::formatv(
          "constant_of_tpoff_relocation: {0}:{1} [{2}]\n", __FILE__, __LINE__,
          *(*it).second.begin());
      return nullptr;
    }

    TPOFFHack[R.Addr] = GV;

#if 1
    return llvm::ConstantExpr::getPtrToInt(GV, WordType());
#else
    return llvm::ConstantInt::get(llvm::Type::getIntNTy(*Context, WordBits()), 0x12345678);
#endif
  };

  auto constant_of_tpmod_relocation =
      [&](const relocation_t &R) -> llvm::Constant * {
    return TLSModGlobal;
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

      default:
        WithColor::warning() << llvm::formatv(
            "addressof {0} has unknown symbol type; treating as data\n",
            S.Name);
        /* fallthrough */

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

    case relocation_t::TYPE::TPMOD:
      return constant_of_tpmod_relocation(R);

    case relocation_t::TYPE::NONE:
      return nullptr;

    default:
      WithColor::error() << "constant_of_relocation: unhandled relocation type "
                         << string_of_reloc_type(R.Type) << '\n';
      abort();
    }
  };

  llvm::StructType *SectsGlobalTy;

  auto declare_sections = [&](void) -> void {
    //
    // create global variable for sections
    //
    std::vector<llvm::Type *> SectsGlobalFieldTys;
    for (unsigned i = 0; i < NumSections; ++i) {
      section_t &Sect = SectTable[i];

      //
      // check if there's space between the start of this section and the
      // previous
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
        if (it == Sect.Stuff.Types.end() || !(*it).second)
          T = llvm::ArrayType::get(llvm::IntegerType::get(*Context, 8),
                                   intvl.upper() - intvl.lower());
        else
          T = (*it).second;

        SectFieldTys.push_back(T);
      }

      std::string SectNm = Sect.Name;
      SectNm.erase(std::remove(SectNm.begin(), SectNm.end(), '.'),
                   SectNm.end());

      SectTable[i].T = llvm::StructType::create(
          *Context, SectFieldTys, "section." + SectNm, true /* isPacked */);

      SectsGlobalFieldTys.push_back(SectTable[i].T);
    }

    SectsGlobalTy = llvm::StructType::create(*Context, SectsGlobalFieldTys,
                                             "struct.sections", true);
    struct {
      llvm::GlobalVariable *SectsGlobal;
      llvm::GlobalVariable *ConstSectsGlobal;
    } Old = {SectsGlobal, ConstSectsGlobal};

    if (Old.SectsGlobal && Old.ConstSectsGlobal) {
      Old.SectsGlobal->setName("");
      Old.ConstSectsGlobal->setName("");
    }

    SectsGlobal = new llvm::GlobalVariable(*Module, SectsGlobalTy, false,
                                           llvm::GlobalValue::ExternalLinkage,
                                           nullptr, (fmt("__jove_sections_%u") % BinaryIndex).str());

    ConstSectsGlobal = new llvm::GlobalVariable(
        *Module, SectsGlobalTy, false, llvm::GlobalValue::ExternalLinkage,
        nullptr, "__jove_sections_const");

    if (Decompilation.Binaries[BinaryIndex].IsExecutable &&
        !Decompilation.Binaries[BinaryIndex].IsPIC) {
      SectsGlobal->setAlignment(llvm::MaybeAlign(1));
      ConstSectsGlobal->setAlignment(llvm::MaybeAlign(1));
    }

    if (!Old.SectsGlobal || !Old.ConstSectsGlobal)
      return;

    Old.SectsGlobal->replaceAllUsesWith(llvm::ConstantExpr::getPointerCast(
        SectsGlobal, Old.SectsGlobal->getType()));

    Old.ConstSectsGlobal->replaceAllUsesWith(llvm::ConstantExpr::getPointerCast(
        ConstSectsGlobal, Old.ConstSectsGlobal->getType()));

    assert(Old.SectsGlobal->user_begin() == Old.SectsGlobal->user_end());
    assert(Old.ConstSectsGlobal->user_begin() == Old.ConstSectsGlobal->user_end());

    Old.SectsGlobal->eraseFromParent();
    Old.ConstSectsGlobal->eraseFromParent();
  };

  auto define_sections = [&](void) -> void {
    //
    // create global variable initializer for sections
    //
    std::vector<llvm::Constant *> SectsGlobalFieldInits;
    for (unsigned i = 0; i < NumSections; ++i) {
      section_t &Sect = SectTable[i];

      //
      // check if there's space between the start of this section and the
      // previous
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
        if (it == Sect.Stuff.Constants.end() || !(*it).second) {
          ptrdiff_t len = intvl.upper() - intvl.lower();
          assert(len > 0);

          if (Sect.Contents.size() >= len) {
            C = llvm::ConstantDataArray::get(
                *Context,
                llvm::ArrayRef<uint8_t>(Sect.Contents.begin() + intvl.lower(),
                                        Sect.Contents.begin() + intvl.upper()));
          } else {
            C = llvm::Constant::getNullValue(
                llvm::ArrayType::get(llvm::Type::getInt8Ty(*Context), len));
          }
        } else {
          C = (*it).second;
        }

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
  };

  auto create_global_variable = [&](target_ulong Addr, unsigned Size,
                                    llvm::StringRef SymName,
                                    llvm::GlobalValue::ThreadLocalMode tlsMode)
      -> llvm::GlobalVariable * {
    if (tlsMode != llvm::GlobalValue::NotThreadLocal) {
      unsigned tlsOff = Addr - ThreadLocalStorage.Beg;
      bool isZero = !(tlsOff < ThreadLocalStorage.Data.Size);

      if (isZero) {
        //
        // initialize to zero
        //
        llvm::Type *T;
        if (is_integral_size(Size))
          T = llvm::Type::getIntNTy(*Context, Size * 8);
        else
          T = llvm::ArrayType::get(llvm::IntegerType::get(*Context, 8), Size);

        return new llvm::GlobalVariable(
            *Module, T, false, llvm::GlobalValue::ExternalLinkage,
            llvm::Constant::getNullValue(T), SymName, nullptr, tlsMode);
      }
    }

    auto it = SectIdxMap.find(Addr);
    assert(it != SectIdxMap.end());
    section_t &Sect = SectTable[(*it).second - 1];
    unsigned Off = Addr - Sect.Addr;

    if (ExternGlobalAddrs.find(Addr) != ExternGlobalAddrs.end()) {
      if (is_integral_size(Size)) {
        return new llvm::GlobalVariable(
            *Module, llvm::Type::getIntNTy(*Context, Size * 8), false,
            llvm::GlobalValue::ExternalLinkage, nullptr, SymName, nullptr,
            tlsMode);
      } else {
        // TODO weak linkage
        return new llvm::GlobalVariable(
            *Module,
            llvm::ArrayType::get(llvm::IntegerType::get(*Context, 8), Size),
            false, llvm::GlobalValue::ExternalLinkage, nullptr, SymName,
            nullptr, tlsMode);
      }
    }

    if (is_integral_size(Size)) {
      if (Size == sizeof(target_ulong)) {
        auto typeit = Sect.Stuff.Types.find(Off);
        auto constit = Sect.Stuff.Constants.find(Off);

        if (typeit != Sect.Stuff.Types.end() &&
            constit != Sect.Stuff.Constants.end()) {
          llvm::Constant *Initializer = (*constit).second;

          if (!Initializer)
            return nullptr;

          return new llvm::GlobalVariable(
              *Module, Initializer->getType(), false,
              llvm::GlobalValue::ExternalLinkage, Initializer, SymName, nullptr,
              tlsMode);
        }
      }

      llvm::Type *T = llvm::Type::getIntNTy(*Context, Size * 8);
      llvm::Constant *Initializer;

      if (Sect.Contents.size() >= Size) {
        uint64_t X;

        const unsigned char *p = Sect.Contents.begin() + Off;
        switch (Size) {
        case 1:
          X = *reinterpret_cast<const int8_t *>(p);
          break;

        case 2:
          X = *reinterpret_cast<const int16_t *>(p);
          break;

        case 4:
          X = *reinterpret_cast<const int32_t *>(p);
          break;

        case 8:
          X = *reinterpret_cast<const int64_t *>(p);
          break;

        default:
          __builtin_trap();
          __builtin_unreachable();
        }

        Initializer = llvm::ConstantInt::get(T, X);
      } else {
        Initializer = llvm::ConstantInt::get(T, 0);
      }

      return new llvm::GlobalVariable(*Module, T, false,
                                      llvm::GlobalValue::ExternalLinkage,
                                      Initializer, SymName, nullptr, tlsMode);
    }

    std::vector<llvm::Type *> GVFieldTys;
    std::vector<llvm::Constant *> GVFieldInits;

    int Left = Size;

    for (const auto &_intvl : Sect.Stuff.Intervals) {
      target_ulong lower = _intvl.lower();
      target_ulong upper = _intvl.upper();

      if (upper <= Off)
        continue;

      if (lower >= Off + Size)
        break;

      if (lower < Off)
        lower = Off;
      if (upper > Off + Size)
        upper = Off + Size;

      auto typeit = Sect.Stuff.Types.find(lower);
      auto constit = Sect.Stuff.Constants.find(lower);

      llvm::Type *T;
      llvm::Constant *C;

      if (typeit == Sect.Stuff.Types.end() ||
          constit == Sect.Stuff.Constants.end()) {
        ptrdiff_t len = upper - lower;

        T = llvm::ArrayType::get(llvm::IntegerType::get(*Context, 8), len);
        if (Sect.Contents.size() >= len) {
          C = llvm::ConstantDataArray::get(
              *Context, llvm::ArrayRef<uint8_t>(Sect.Contents.begin() + lower,
                                                Sect.Contents.begin() + upper));
        } else {
          C = llvm::Constant::getNullValue(T);
        }

        Left -= len;
      } else {
        T = (*typeit).second;
        C = (*constit).second;

        assert(T->isIntegerTy(WordBits()) || T->isPointerTy());
        Left -= sizeof(target_ulong);
      }

      if (!T)
        return nullptr;

      GVFieldTys.push_back(T);
      GVFieldInits.push_back(C);
    }
    assert(Left >= 0);

    if (Left > 0) {
      llvm::Type *T =
          llvm::ArrayType::get(llvm::IntegerType::get(*Context, 8), Left);
      llvm::Constant *C = llvm::Constant::getNullValue(T);

      GVFieldTys.push_back(T);
      GVFieldInits.push_back(C);
    }

    assert(std::all_of(GVFieldTys.cbegin(),
                       GVFieldTys.cend(),
                       [](llvm::Type *T) -> bool { return T != nullptr; }));

    llvm::StructType *ST = llvm::StructType::create(
        *Context, GVFieldTys, "struct." + SymName.str(), true /* isPacked */);

    llvm::GlobalVariable *GV = Module->getGlobalVariable(SymName, true);
    if (GV) {
      assert(!GV->hasInitializer());
      assert(std::all_of(GVFieldInits.cbegin(),
                         GVFieldInits.cend(),
                         [](llvm::Constant *C) -> bool { return C != nullptr; }));

      assert(llvm::isa<llvm::PointerType>(GV->getType()));

      llvm::Type *Ty =
          llvm::cast<llvm::PointerType>(GV->getType())->getElementType();

      assert(llvm::isa<llvm::StructType>(Ty));

      GV->setInitializer(llvm::ConstantStruct::get(
          llvm::cast<llvm::StructType>(Ty), GVFieldInits));

      return GV;
    } else {
      if (std::all_of(GVFieldInits.cbegin(),
                      GVFieldInits.cend(),
                      [](llvm::Constant *C) -> bool { return C != nullptr; }))
        return new llvm::GlobalVariable(
            *Module, ST, false, llvm::GlobalValue::ExternalLinkage,
            llvm::ConstantStruct::get(ST, GVFieldInits), SymName, nullptr,
            tlsMode);
      else
        return new llvm::GlobalVariable(*Module, ST, false,
                                        llvm::GlobalValue::ExternalLinkage,
                                        nullptr, SymName, nullptr, tlsMode);
    }
  };

  auto clear_section_stuff = [&](void) -> void {
    for (section_t &Sect : SectTable) {
      Sect.Stuff.Constants.clear();
      Sect.Stuff.Types.clear();
      Sect.Stuff.Intervals.clear();
      Sect.Stuff.Intervals.insert(
          boost::icl::interval<target_ulong>::right_open(0, Sect.Size));
    }
  };

  ConstSectsGlobal = nullptr;
  SectsGlobal = nullptr;

  // iterative algorithm to create the sections
  bool done;
  do {
    done = true;

    clear_section_stuff();

    for (relocation_t &R : RelocationTable) {
      R.T = type_of_relocation(R);
      if (R.T && R.T->isVoidTy())
        continue;

      type_at_address(R.Addr, R.T); /* note: R.T can be nullptr */

      if (!R.T) {
        done = false;

        llvm::outs() << "!type_of_relocation(R): " <<
          (fmt("%-12s [%-12s] @ %-16x +%-16x")
           % string_of_reloc_type(R.Type)
           % R.RelocationTypeName.c_str()
           % R.Addr
           % R.Addend).str();

        if (R.SymbolIndex < SymbolTable.size()) {
          symbol_t &sym = SymbolTable[R.SymbolIndex];

          llvm::outs() <<
            (fmt("%-30s *%-10s *%-8s @ %x {%d}")
             % sym.Name
             % string_of_sym_type(sym.Type)
             % string_of_sym_binding(sym.Bind)
             % sym.Addr
             % sym.Size).str();
        }

        llvm::outs() << '\n';
      }
    }

    declare_sections();

    for (relocation_t &R : RelocationTable) {
      if (R.T && R.T->isVoidTy())
        continue;
      R.C = constant_of_relocation(R);

      constant_at_address(R.Addr, R.C); /* note: R.C can be nullptr */

      if (!R.C) {
        done = false;

        llvm::outs() << "!constant_of_relocation(R): " <<
          (fmt("%-12s [%-12s] @ %-16x +%-16x")
           % string_of_reloc_type(R.Type)
           % R.RelocationTypeName.c_str()
           % R.Addr
           % R.Addend).str();

        if (R.SymbolIndex < SymbolTable.size()) {
          symbol_t &sym = SymbolTable[R.SymbolIndex];

          llvm::outs() <<
            (fmt("%-30s *%-10s *%-8s @ %x {%d}")
             % sym.Name
             % string_of_sym_type(sym.Type)
             % string_of_sym_binding(sym.Bind)
             % sym.Addr
             % sym.Size).str();
        }

        llvm::outs() << '\n';
      } else {
        assert(R.T);
        if (R.T != R.C->getType()) {
          WithColor::error()
              << llvm::formatv("{0}: bug? [{1}] ({2}) ({3})\n", __func__,
                               string_of_reloc_type(R.Type), *R.T, *R.C);
        }
      }
    }

    define_sections();

    //
    // global variables
    //
    for (const auto &pair : AddrToSymbolMap) {
      const std::set<llvm::StringRef> &Syms = pair.second;

      llvm::StringRef SymName = *Syms.begin();
      assert(!Syms.empty());

      llvm::errs() << llvm::formatv("iterating AddrToSymbolMap ({0})\n", SymName);

      if (llvm::GlobalVariable *GV = Module->getGlobalVariable(SymName, true)) {
        if (GV->hasInitializer())
          continue;
      }

      target_ulong Addr = pair.first;

      unsigned Size;
      {
        auto it = AddrToSizeMap.find(Addr);
        assert(it != AddrToSizeMap.end());
        Size = (*it).second;
      }

      llvm::GlobalVariable *GV =
          create_global_variable(Addr, Size, SymName,
                                 TLSObjects.find(Addr) != TLSObjects.end()
                                     ? llvm::GlobalValue::GeneralDynamicTLSModel
                                     : llvm::GlobalValue::NotThreadLocal);

      if (!GV) {
        done = false;

        llvm::outs() << "!create_global_variable(...): " << SymName << '\n';
        continue;
      } else {
        WithColor::note() << llvm::formatv("new GV: {0}\n", *GV);
      }

      for (auto it = std::next(Syms.begin()); it != Syms.end(); ++it) {
        if (!GV->hasInitializer()) {
          WithColor::warning() << llvm::formatv(
              "global variable {0} has alias {1} but is extern\n", SymName,
              *it);
          break;
        }

        llvm::GlobalAlias::create(*it, GV);
      }
    }

    if (ThreadLocalStorage.Present) {
      if (!TLSSectsGlobal || !TLSSectsGlobal->hasInitializer())
        TLSSectsGlobal = create_global_variable(
            ThreadLocalStorage.Beg,
            ThreadLocalStorage.End - ThreadLocalStorage.Beg,
            "__jove_tls_sections",
            llvm::GlobalValue::GeneralDynamicTLSModel);

      if (!TLSSectsGlobal) {
        done = false;

        llvm::outs() << "!TLSSectsGlobal\n";
      }
    }
  } while (!done);

  if (TLSSectsGlobal)
    TLSSectsGlobal->setLinkage(llvm::GlobalValue::InternalLinkage);

  //
  // Binary DT_INIT
  //
  // XXX this should go somewhere else
  {
    auto &binary = Decompilation.Binaries[BinaryIndex];

    assert(llvm::isa<ELFO>(binary.ObjectFile.get()));
    ELFO &O = *llvm::cast<ELFO>(binary.ObjectFile.get());
    const ELFF &E = *O.getELFFile();

    //
    // parse dynamic table
    //
    auto dynamic_table = [&](void) -> Elf_Dyn_Range {
      return binary._elf.DynamicTable.getAsArrayRef<Elf_Dyn>();
    };

    target_ulong initFunctionAddr = 0;

    for (const Elf_Dyn &Dyn : dynamic_table()) {
      if (unlikely(Dyn.d_tag == llvm::ELF::DT_NULL))
        break; /* marks end of dynamic table. */

      switch (Dyn.d_tag) {
      case llvm::ELF::DT_INIT:
        initFunctionAddr = Dyn.getVal();
        break;
      }
    };

#if 0
    if (initFunctionAddr) {
      llvm::appendToGlobalCtors(
          *Module,
          (llvm::Function *)llvm::ConstantExpr::getIntToPtr(
              SectionPointer(initFunctionAddr), VoidFunctionPointer()),
          0);
    }

    initFunctionAddr = 0;
#endif

    if (llvm::Function *F = Module->getFunction("_jove_get_init_fn")) {
      assert(F && F->empty());

      llvm::DIBuilder &DIB = *DIBuilder;
      llvm::DISubprogram::DISPFlags SubProgFlags =
          llvm::DISubprogram::SPFlagDefinition |
          llvm::DISubprogram::SPFlagOptimized;

      SubProgFlags |= llvm::DISubprogram::SPFlagLocalToUnit;

      llvm::DISubroutineType *SubProgType =
          DIB.createSubroutineType(DIB.getOrCreateTypeArray(llvm::None));

      struct {
        llvm::DISubprogram *Subprogram;
      } DebugInfo;

      DebugInfo.Subprogram = DIB.createFunction(
          /* Scope       */ DebugInformation.CompileUnit,
          /* Name        */ F->getName(),
          /* LinkageName */ F->getName(),
          /* File        */ DebugInformation.File,
          /* LineNo      */ 0,
          /* Ty          */ SubProgType,
          /* ScopeLine   */ 0,
          /* Flags       */ llvm::DINode::FlagZero,
          /* SPFlags     */ SubProgFlags);
      F->setSubprogram(DebugInfo.Subprogram);

      llvm::BasicBlock *BB = llvm::BasicBlock::Create(*Context, "", F);
      {
        llvm::IRBuilderTy IRB(BB);

        IRB.SetCurrentDebugLocation(llvm::DILocation::get(
            *Context, 0 /* Line */, 0 /* Column */, DebugInfo.Subprogram));

        llvm::Value *Ret = nullptr;
        if (initFunctionAddr) {
          auto it = FuncMap.find(initFunctionAddr);

          assert(it != FuncMap.end());

          function_t &initfn_f = Decompilation.Binaries[BinaryIndex]
                                     .Analysis.Functions[(*it).second];

          Ret = llvm::ConstantExpr::getPtrToInt(initfn_f.F, WordType());
        } else {
          Ret = llvm::Constant::getNullValue(WordType());
        }
        IRB.CreateRet(Ret);

        F->setLinkage(llvm::GlobalValue::ExternalLinkage);
        F->setVisibility(llvm::GlobalValue::HiddenVisibility);
      }
    }

    if (llvm::Function *F = Module->getFunction("_jove_get_init_fn_sect_ptr")) {
      assert(F->empty());

      llvm::DIBuilder &DIB = *DIBuilder;
      llvm::DISubprogram::DISPFlags SubProgFlags =
          llvm::DISubprogram::SPFlagDefinition |
          llvm::DISubprogram::SPFlagOptimized;

      SubProgFlags |= llvm::DISubprogram::SPFlagLocalToUnit;

      llvm::DISubroutineType *SubProgType =
          DIB.createSubroutineType(DIB.getOrCreateTypeArray(llvm::None));

      struct {
        llvm::DISubprogram *Subprogram;
      } DebugInfo;

      DebugInfo.Subprogram = DIB.createFunction(
          /* Scope       */ DebugInformation.CompileUnit,
          /* Name        */ F->getName(),
          /* LinkageName */ F->getName(),
          /* File        */ DebugInformation.File,
          /* LineNo      */ 0,
          /* Ty          */ SubProgType,
          /* ScopeLine   */ 0,
          /* Flags       */ llvm::DINode::FlagZero,
          /* SPFlags     */ SubProgFlags);
      F->setSubprogram(DebugInfo.Subprogram);

      llvm::BasicBlock *BB = llvm::BasicBlock::Create(*Context, "", F);
      {
        llvm::IRBuilderTy IRB(BB);

        IRB.SetCurrentDebugLocation(llvm::DILocation::get(
            *Context, 0 /* Line */, 0 /* Column */, DebugInfo.Subprogram));

        IRB.CreateRet(initFunctionAddr
                          ? SectionPointer(initFunctionAddr)
                          : llvm::Constant::getNullValue(WordType()));
      }

      F->setLinkage(llvm::GlobalValue::ExternalLinkage);
      F->setVisibility(llvm::GlobalValue::HiddenVisibility);
    }
  }

  if (llvm::Function *F = Module->getFunction("_jove_get_libc_early_init_fn")) {
    assert(F && F->empty());

    llvm::DIBuilder &DIB = *DIBuilder;
    llvm::DISubprogram::DISPFlags SubProgFlags =
        llvm::DISubprogram::SPFlagDefinition |
        llvm::DISubprogram::SPFlagOptimized;

    SubProgFlags |= llvm::DISubprogram::SPFlagLocalToUnit;

    llvm::DISubroutineType *SubProgType =
        DIB.createSubroutineType(DIB.getOrCreateTypeArray(llvm::None));

    struct {
      llvm::DISubprogram *Subprogram;
    } DebugInfo;

    DebugInfo.Subprogram = DIB.createFunction(
        /* Scope       */ DebugInformation.CompileUnit,
        /* Name        */ F->getName(),
        /* LinkageName */ F->getName(),
        /* File        */ DebugInformation.File,
        /* LineNo      */ 0,
        /* Ty          */ SubProgType,
        /* ScopeLine   */ 0,
        /* Flags       */ llvm::DINode::FlagZero,
        /* SPFlags     */ SubProgFlags);
    F->setSubprogram(DebugInfo.Subprogram);

    llvm::BasicBlock *BB = llvm::BasicBlock::Create(*Context, "", F);
    {
      llvm::IRBuilderTy IRB(BB);

      IRB.SetCurrentDebugLocation(llvm::DILocation::get(
          *Context, 0 /* Line */, 0 /* Column */, DebugInfo.Subprogram));

      llvm::Value *Ret = nullptr;
      if (libcEarlyInitAddr) {
        auto it = FuncMap.find(libcEarlyInitAddr);

        assert(it != FuncMap.end());

        function_t &f = Decompilation.Binaries[BinaryIndex]
                           .Analysis.Functions[(*it).second];

        Ret = llvm::ConstantExpr::getPtrToInt(f.F, WordType());
      } else {
        Ret = llvm::Constant::getNullValue(WordType());
      }
      IRB.CreateRet(Ret);

      F->setLinkage(llvm::GlobalValue::ExternalLinkage);
      F->setVisibility(llvm::GlobalValue::HiddenVisibility);
    }
  }

  if (llvm::Function *F = Module->getFunction("_jove_get_libc_early_init_fn_sect_ptr")) {
    assert(F && F->empty());

    llvm::DIBuilder &DIB = *DIBuilder;
    llvm::DISubprogram::DISPFlags SubProgFlags =
        llvm::DISubprogram::SPFlagDefinition |
        llvm::DISubprogram::SPFlagOptimized;

    SubProgFlags |= llvm::DISubprogram::SPFlagLocalToUnit;

    llvm::DISubroutineType *SubProgType =
        DIB.createSubroutineType(DIB.getOrCreateTypeArray(llvm::None));

    struct {
      llvm::DISubprogram *Subprogram;
    } DebugInfo;

    DebugInfo.Subprogram = DIB.createFunction(
        /* Scope       */ DebugInformation.CompileUnit,
        /* Name        */ F->getName(),
        /* LinkageName */ F->getName(),
        /* File        */ DebugInformation.File,
        /* LineNo      */ 0,
        /* Ty          */ SubProgType,
        /* ScopeLine   */ 0,
        /* Flags       */ llvm::DINode::FlagZero,
        /* SPFlags     */ SubProgFlags);
    F->setSubprogram(DebugInfo.Subprogram);

    llvm::BasicBlock *BB = llvm::BasicBlock::Create(*Context, "", F);
    {
      llvm::IRBuilderTy IRB(BB);

      IRB.SetCurrentDebugLocation(llvm::DILocation::get(
          *Context, 0 /* Line */, 0 /* Column */, DebugInfo.Subprogram));

      IRB.CreateRet(libcEarlyInitAddr
                        ? SectionPointer(libcEarlyInitAddr)
                        : llvm::Constant::getNullValue(WordType()));

      F->setLinkage(llvm::GlobalValue::ExternalLinkage);
      F->setVisibility(llvm::GlobalValue::HiddenVisibility);
    }
  }

  //
  // Global Ctors/Dtors
  //
  // XXX this should go somewhere else
  for (section_t &Sect : SectTable) {
    if (!Sect.initArray && !Sect.finiArray)
      continue;

    assert(!(Sect.initArray && Sect.finiArray));

    for (const auto &pair : Sect.Stuff.Constants) {
      llvm::Constant *C = pair.second;
      llvm::Function *F = nullptr;

      llvm::ConstantInt *matched_Addend = nullptr;
      if (llvm::PatternMatch::match(
              C, llvm::PatternMatch::m_Add(
                     llvm::PatternMatch::m_PtrToInt(
                         llvm::PatternMatch::m_Specific(SectsGlobal)),
                     llvm::PatternMatch::m_ConstantInt(matched_Addend)))) {
        assert(matched_Addend);
        uintptr_t off = matched_Addend->getValue().getZExtValue();
        uintptr_t FileAddr = off + SectsStartAddr;

        binary_t &Binary = Decompilation.Binaries[BinaryIndex];
        auto &FuncMap = Binary.FuncMap;
        auto it = FuncMap.find(FileAddr);
        assert(it != FuncMap.end());
        function_t &f = Binary.Analysis.Functions[(*it).second];

        if (!f.IsABI) {
          WithColor::error() << llvm::formatv(
              "!IsABI for {0}; did you run jove-bootstrap -s?\n",
              f.F->getName());
          abort();
        }

        // casting to a llvm::Function* is a complete hack here.
        // https://reviews.llvm.org/D64962
        if (Sect.initArray)
          llvm::appendToGlobalCtors(
              *Module,
              (llvm::Function *)llvm::ConstantExpr::getIntToPtr(
                  C, VoidFunctionPointer()),
              0);
        else
          llvm::appendToGlobalDtors(
              *Module,
              (llvm::Function *)llvm::ConstantExpr::getIntToPtr(
                  C, VoidFunctionPointer()),
              0);

      } else {
        WithColor::warning() << llvm::formatv(
            "unable to match against constant expression in init array\n");
        continue;
      }
    }
  }

  if (Decompilation.Binaries[BinaryIndex].IsExecutable &&
      !Decompilation.Binaries[BinaryIndex].IsPIC)
    SectsGlobal->setSection(".jove"); /* we will refer to this later with ld,
                                       * placing the section at the executable's
                                       * original base address in memory */

  return 0;
}

int ProcessDynamicSymbols2(void) {
  std::set<std::pair<uintptr_t, unsigned>> gdefs;

  for (binary_index_t BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx) {
    auto &b = Decompilation.Binaries[BIdx];
    auto &FuncMap = b.FuncMap;

    if (!b.ObjectFile)
      continue;

    assert(llvm::isa<ELFO>(b.ObjectFile.get()));
    ELFO &O = *llvm::cast<ELFO>(b.ObjectFile.get());
    const ELFF &E = *O.getELFFile();

    if (!b._elf.OptionalDynSymRegion)
      continue; /* no dynamic symbols */

    auto DynSyms = b._elf.OptionalDynSymRegion->getAsArrayRef<Elf_Sym>();

    for (unsigned SymNo = 0; SymNo < DynSyms.size(); ++SymNo) {
      const Elf_Sym &Sym = DynSyms[SymNo];

      if (Sym.isUndefined()) /* defined */
        continue;

      llvm::Expected<llvm::StringRef> ExpectedSymName = Sym.getName(b._elf.DynamicStringTable);
      if (!ExpectedSymName)
        continue;

      llvm::StringRef SymName = *ExpectedSymName;

      symbol_t sym;

      sym.Name = SymName;

      //
      // symbol versioning
      //
      if (!b._elf.SymbolVersionSection) {
        sym.Visibility.IsDefault = false;
      } else {
        const Elf_Versym *Versym = unwrapOrError(
            E.getEntry<Elf_Versym>(b._elf.SymbolVersionSection, SymNo));

        sym.Vers = getSymbolVersionByIndex(b._elf.VersionMap,
                                           b._elf.DynamicStringTable,
                                           Versym->vs_index,
                                           sym.Visibility.IsDefault);
      }

      sym.Addr = Sym.isUndefined() ? 0 : Sym.st_value;
      sym.Type = sym_type_of_elf_sym_type(Sym.getType());
      sym.Size = Sym.st_size;
      sym.Bind = sym_binding_of_elf_sym_binding(Sym.getBinding());

      if (Sym.getType() == llvm::ELF::STT_OBJECT ||
          Sym.getType() == llvm::ELF::STT_TLS) {
        if (!Sym.st_size) {
          if (opts::Verbose)
            WithColor::warning() << "symbol '" << SymName
                                 << "' defined but size is unknown; ignoring\n";
          continue;
        }

        if (BIdx == BinaryIndex) {
          //
          // if this symbol is TLS, update the TLSValueToSymbolMap
          //
          if (Sym.getType() == llvm::ELF::STT_TLS) {
            ;
          } else {
            auto it = AddrToSymbolMap.find(Sym.st_value);
            if (it == AddrToSymbolMap.end()) {
              unsigned off = Sym.st_value - b.SectsStartAddr;

              if (sym.Vers.empty()) {
                Module->appendModuleInlineAsm(
                    (fmt(".globl %s\n"
                         ".type  %s,@object\n"
                         ".size  %s, %u\n"
                         ".set   %s, __jove_sections_%u + %u")
                     % sym.Name
                     % sym.Name
                     % sym.Name % Sym.st_size
                     % sym.Name % BinaryIndex % off).str());
              } else {
                if (gdefs.find({Sym.st_value, Sym.st_size}) == gdefs.end()) {
                  Module->appendModuleInlineAsm(
                      (fmt(".hidden g%lx_%u\n"
                           ".globl  g%lx_%u\n"
                           ".type   g%lx_%u,@object\n"
                           ".size   g%lx_%u, %u\n"
                           ".set    g%lx_%u, __jove_sections_%u + %u")
                       % Sym.st_value % Sym.st_size
                       % Sym.st_value % Sym.st_size
                       % Sym.st_value % Sym.st_size
                       % Sym.st_value % Sym.st_size % Sym.st_size
                       % Sym.st_value % Sym.st_size % BinaryIndex % off).str());

                  gdefs.insert({Sym.st_value, Sym.st_size});
                }

                Module->appendModuleInlineAsm(
                    (fmt(".symver g%lx_%u, %s%s%s")
                     % Sym.st_value % Sym.st_size
                     % sym.Name
                     % (sym.Visibility.IsDefault ? "@@" : "@")
                     % sym.Vers).str());

                // make sure version node is defined
                VersionScript.Table[sym.Vers];
              }
            } else {
              if (Module->getNamedValue(sym.Name)) {
                if (!sym.Vers.empty())
                  VersionScript.Table[sym.Vers].insert(sym.Name);

                continue;
              }

              llvm::GlobalVariable *GV =
                  Module->getGlobalVariable(*(*it).second.begin(), true);
              assert(GV);

              llvm::GlobalAlias::create(sym.Name, GV);
              if (!sym.Vers.empty())
                VersionScript.Table[sym.Vers].insert(sym.Name);
            }
          }
        }
      } else if (Sym.getType() == llvm::ELF::STT_FUNC) {
        ;
      } else if (Sym.getType() == llvm::ELF::STT_GNU_IFUNC) {
        ;
      }
    }
  }

  return 0;
}

std::pair<binary_index_t, std::pair<target_ulong, unsigned>>
decipher_copy_relocation(const symbol_t &S) {
  assert(Decompilation.Binaries[BinaryIndex].IsExecutable); /* XXX? */

  for (binary_index_t BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx) {
    if (BIdx == BinaryIndex)
      continue;

    auto &b = Decompilation.Binaries[BIdx];
    if (b.IsVDSO)
      continue;
    if (b.IsDynamicLinker)
      continue;

    if (!b.ObjectFile)
      continue;

    assert(llvm::isa<ELFO>(b.ObjectFile.get()));
    ELFO &O = *llvm::cast<ELFO>(b.ObjectFile.get());
    const ELFF &E = *O.getELFFile();

    if (!b._elf.OptionalDynSymRegion)
      continue; /* no dynamic symbols */

    auto DynSyms = b._elf.OptionalDynSymRegion->getAsArrayRef<Elf_Sym>();

    for (unsigned SymNo = 0; SymNo < DynSyms.size(); ++SymNo) {
      const Elf_Sym &Sym = DynSyms[SymNo];

      if (Sym.isUndefined())
        continue;

      if (Sym.getType() != llvm::ELF::STT_OBJECT)
        continue;

      llvm::StringRef SymName = unwrapOrError(Sym.getName(b._elf.DynamicStringTable));

      symbol_t sym;

      sym.Name = SymName;

      //
      // symbol versioning
      //
      if (!b._elf.SymbolVersionSection) {
        sym.Visibility.IsDefault = false;
      } else {
        const Elf_Versym *Versym = unwrapOrError(
            E.getEntry<Elf_Versym>(b._elf.SymbolVersionSection, SymNo));

        sym.Vers = getSymbolVersionByIndex(b._elf.VersionMap,
                                           b._elf.DynamicStringTable,
                                           Versym->vs_index,
                                           sym.Visibility.IsDefault);
      }

      if ((sym.Name == S.Name &&
           sym.Vers == S.Vers)) {
        //
        // we have a match.
        //
        assert(Sym.st_value > b.SectsStartAddr);

        return {BIdx, {Sym.st_value, Sym.st_value - b.SectsStartAddr}};
      }
    }
  }

  WithColor::warning() << llvm::formatv(
      "failed to decipher copy relocation {0} {1}\n", S.Name, S.Vers);

  return {invalid_binary_index, {0, 0}};
}

static llvm::Value *insertThreadPointerInlineAsm(llvm::IRBuilderTy &);

int CreateTPOFFCtorHack(void) {
  auto &Binary = Decompilation.Binaries[BinaryIndex];

  llvm::Function *F = Module->getFunction("_jove_do_tpoff_hack");
  assert(F && F->empty());

#if 1
  llvm::DIBuilder &DIB = *DIBuilder;
  llvm::DISubprogram::DISPFlags SubProgFlags =
      llvm::DISubprogram::SPFlagDefinition |
      llvm::DISubprogram::SPFlagOptimized;

  SubProgFlags |= llvm::DISubprogram::SPFlagLocalToUnit;

  llvm::DISubroutineType *SubProgType =
      DIB.createSubroutineType(DIB.getOrCreateTypeArray(llvm::None));

  struct {
    llvm::DISubprogram *Subprogram;
  } DebugInfo;

  DebugInfo.Subprogram = DIB.createFunction(
      /* Scope       */ DebugInformation.CompileUnit,
      /* Name        */ F->getName(),
      /* LinkageName */ F->getName(),
      /* File        */ DebugInformation.File,
      /* LineNo      */ 0,
      /* Ty          */ SubProgType,
      /* ScopeLine   */ 0,
      /* Flags       */ llvm::DINode::FlagZero,
      /* SPFlags     */ SubProgFlags);
#endif

  F->setSubprogram(DebugInfo.Subprogram);

  llvm::BasicBlock *BB = llvm::BasicBlock::Create(*Context, "", F);
  {
    llvm::IRBuilderTy IRB(BB);
#if 1
    IRB.SetCurrentDebugLocation(llvm::DILocation::get(
        *Context, 0 /* Line */, 0 /* Column */, DebugInfo.Subprogram));
#endif

    llvm::Value *TP = nullptr;
    if (!TPOFFHack.empty())
      TP = insertThreadPointerInlineAsm(IRB);

    for (const auto &pair : TPOFFHack) {
      uintptr_t off = pair.first - Binary.SectsStartAddr;

      assert(pair.second->getType()->isPointerTy() ||
             pair.second->getType()->isIntegerTy());

      llvm::SmallVector<llvm::Value *, 4> Indices;
      llvm::Value *gep = llvm::getNaturalGEPWithOffset(
          IRB, DL, SectsGlobal, llvm::APInt(64, off), nullptr, Indices, "");

      llvm::Value *Val = pair.second;

      if (Val->getType()->isPointerTy())
        Val = IRB.CreatePtrToInt(Val, WordType());

      assert(TP);

      llvm::Value *TPOffset = IRB.CreateSub(Val, TP);

      IRB.CreateStore(TPOffset, gep, true /* Volatile */);
    }

    IRB.CreateRetVoid();
  }

  F->setLinkage(llvm::GlobalValue::InternalLinkage);
  assert(!F->empty());

  return 0;
}

int CreateIRELATIVECtorHack(void) {
  auto &Binary = Decompilation.Binaries[BinaryIndex];

  llvm::Function *F = Module->getFunction("_jove_do_irelative_hack");
  assert(F && F->empty());

#if 1
  llvm::DIBuilder &DIB = *DIBuilder;
  llvm::DISubprogram::DISPFlags SubProgFlags =
      llvm::DISubprogram::SPFlagDefinition |
      llvm::DISubprogram::SPFlagOptimized;

  SubProgFlags |= llvm::DISubprogram::SPFlagLocalToUnit;

  llvm::DISubroutineType *SubProgType =
      DIB.createSubroutineType(DIB.getOrCreateTypeArray(llvm::None));

  struct {
    llvm::DISubprogram *Subprogram;
  } DebugInfo;

  DebugInfo.Subprogram = DIB.createFunction(
      /* Scope       */ DebugInformation.CompileUnit,
      /* Name        */ F->getName(),
      /* LinkageName */ F->getName(),
      /* File        */ DebugInformation.File,
      /* LineNo      */ 0,
      /* Ty          */ SubProgType,
      /* ScopeLine   */ 0,
      /* Flags       */ llvm::DINode::FlagZero,
      /* SPFlags     */ SubProgFlags);
#endif

  F->setSubprogram(DebugInfo.Subprogram);

  llvm::BasicBlock *BB = llvm::BasicBlock::Create(*Context, "", F);
  {
    llvm::IRBuilderTy IRB(BB);
    IRB.SetCurrentDebugLocation(llvm::DILocation::get(
        *Context, 0 /* Line */, 0 /* Column */, DebugInfo.Subprogram));

    for (const auto &pair : IRELATIVEHack) {
      assert(pair.second.first == BinaryIndex);

      llvm::Value *SPPtr = CPUStateGlobalPointer(tcg_stack_pointer_index);

      llvm::Value *TemporaryStack = nullptr;
      {
        TemporaryStack = IRB.CreateCall(JoveAllocStackFunc);
        llvm::Value *NewSP = IRB.CreateAdd(
            TemporaryStack, llvm::ConstantInt::get(
                                WordType(), JOVE_STACK_SIZE - JOVE_PAGE_SIZE));

        llvm::Value *AlignedNewSP =
            IRB.CreateAnd(IRB.CreatePtrToInt(NewSP, WordType()),
                          IRB.getIntN(sizeof(target_ulong) * 8, ~15UL));

        llvm::Value *SPVal = AlignedNewSP;

#if defined(TARGET_X86_64) || defined(TARGET_I386)
        SPVal = IRB.CreateSub(
            SPVal, IRB.getIntN(sizeof(target_ulong) * 8,
                               sizeof(target_ulong)));
#endif

        IRB.CreateStore(SPVal, SPPtr);
      }

      function_t &f = Binary.Analysis.Functions[pair.second.second];
      llvm::Function *resolverF = f.F;

      std::vector<llvm::Value *> ArgVec(
          resolverF->getFunctionType()->getNumParams(),
          llvm::Constant::getNullValue(WordType()));

      llvm::CallInst *Call = IRB.CreateCall(resolverF, ArgVec);

      llvm::Value *Val = nullptr;

      if (f.F->getFunctionType()->getReturnType()->isIntegerTy()) {
        Val = Call;
      } else {
        assert(f.F->getFunctionType()->getReturnType()->isStructTy());

        Val = IRB.CreateExtractValue(Call, llvm::ArrayRef<unsigned>(0), "");
      }

      uintptr_t off = pair.first - Binary.SectsStartAddr;

      llvm::SmallVector<llvm::Value *, 4> Indices;
      llvm::Value *gep = llvm::getNaturalGEPWithOffset(
          IRB, DL, SectsGlobal, llvm::APInt(64, off), nullptr, Indices, "");

      IRB.CreateStore(Val, gep, true /* Volatile */);

      IRB.CreateCall(JoveFreeStackFunc, {TemporaryStack});

      IRB.CreateStore(llvm::Constant::getNullValue(WordType()), SPPtr);
    }

    IRB.CreateRetVoid();
  }

  F->setLinkage(llvm::GlobalValue::InternalLinkage);
  assert(!F->empty());

  return 0;
}

int CreateCopyRelocationHack(void) {
  llvm::Function *F = Module->getFunction("_jove_do_emulate_copy_relocations");
  assert(F && F->empty());

  binary_t &Binary = Decompilation.Binaries[BinaryIndex];

#if 1
  llvm::DIBuilder &DIB = *DIBuilder;
  llvm::DISubprogram::DISPFlags SubProgFlags =
      llvm::DISubprogram::SPFlagDefinition |
      llvm::DISubprogram::SPFlagOptimized;

  SubProgFlags |= llvm::DISubprogram::SPFlagLocalToUnit;

  llvm::DISubroutineType *SubProgType =
      DIB.createSubroutineType(DIB.getOrCreateTypeArray(llvm::None));

  struct {
    llvm::DISubprogram *Subprogram;
  } DebugInfo;

  DebugInfo.Subprogram = DIB.createFunction(
      /* Scope       */ DebugInformation.CompileUnit,
      /* Name        */ F->getName(),
      /* LinkageName */ F->getName(),
      /* File        */ DebugInformation.File,
      /* LineNo      */ 0,
      /* Ty          */ SubProgType,
      /* ScopeLine   */ 0,
      /* Flags       */ llvm::DINode::FlagZero,
      /* SPFlags     */ SubProgFlags);
#endif

  F->setSubprogram(DebugInfo.Subprogram);

  llvm::BasicBlock *BB = llvm::BasicBlock::Create(*Context, "", F);
  {
    llvm::IRBuilderTy IRB(BB);
#if 1
    IRB.SetCurrentDebugLocation(llvm::DILocation::get(
        *Context, 0 /* Line */, 0 /* Column */, DebugInfo.Subprogram));
#endif

    if (!Binary.IsExecutable) {
      assert(CopyRelocMap.empty());
    }

    for (const auto &pair : CopyRelocMap) {
      binary_index_t BIdxFrom = pair.second.first;
      auto &BinaryFrom = Decompilation.Binaries.at(BIdxFrom);

      WARN_ON(pair.second.first < 3);

      if (BinaryFrom.SectsF) {
        IRB.CreateMemCpy(
            IRB.CreateIntToPtr(SectionPointer(pair.first.first),
                               IRB.getInt8PtrTy()),
            llvm::MaybeAlign(),
            IRB.CreateIntToPtr(
                IRB.CreateAdd(IRB.CreateCall(BinaryFrom.SectsF),
                              IRB.getIntN(WordBits(), pair.second.second.second)),
                IRB.getInt8PtrTy()),
            llvm::MaybeAlign(), pair.first.second, true /* Volatile */);
      } else {
        assert(opts::ForeignLibs);

        auto &ICFG = BinaryFrom.Analysis.ICFG;

        assert(!BinaryFrom.Analysis.Functions.empty());

        //
        // get the load address
        //
        llvm::Value *FnsTbl = IRB.CreateLoad(IRB.CreateConstInBoundsGEP2_64(
            JoveForeignFunctionTablesGlobal, 0, BIdxFrom));

        llvm::Value *FirstEntry = IRB.CreateLoad(FnsTbl);

        llvm::Value *LoadBias = IRB.CreateSub(FirstEntry,
          IRB.getIntN(WordBits(), ICFG[boost::vertex(BinaryFrom.Analysis.Functions[0].Entry, ICFG)].Addr));

        llvm::errs() << llvm::formatv("FnsTbl: {0} Type: {1}\n", *FnsTbl,
                                      *FnsTbl->getType());

        IRB.CreateMemCpy(
            IRB.CreateIntToPtr(SectionPointer(pair.first.first),
                               IRB.getInt8PtrTy()),
            llvm::MaybeAlign(),
            IRB.CreateIntToPtr(
                IRB.CreateAdd(LoadBias,
                              IRB.getIntN(WordBits(), pair.second.second.first)),
                IRB.getInt8PtrTy()),
            llvm::MaybeAlign(), pair.first.second, true /* Volatile */);
      }

#if 1
      WithColor::note() << llvm::formatv("COPY RELOC HACK {0} {1} {2} {3}\n",
                                         pair.first.first,
                                         pair.first.second,
                                         pair.second.second.first,
                                         pair.second.second.second);
#endif
    }

    IRB.CreateRetVoid();
  }

  F->setLinkage(llvm::GlobalValue::InternalLinkage);
  assert(!F->empty());

  return 0;
}

int FixupHelperStubs(void) {
  binary_t &Binary = Decompilation.Binaries[BinaryIndex];

  {
    llvm::Function *F = Module->getFunction("_jove_sections_start_file_addr");
    assert(F && F->empty());

    llvm::DIBuilder &DIB = *DIBuilder;
    llvm::DISubprogram::DISPFlags SubProgFlags =
        llvm::DISubprogram::SPFlagDefinition |
        llvm::DISubprogram::SPFlagOptimized;

    SubProgFlags |= llvm::DISubprogram::SPFlagLocalToUnit;

    llvm::DISubroutineType *SubProgType =
        DIB.createSubroutineType(DIB.getOrCreateTypeArray(llvm::None));

    struct {
      llvm::DISubprogram *Subprogram;
    } DebugInfo;

    DebugInfo.Subprogram = DIB.createFunction(
        /* Scope       */ DebugInformation.CompileUnit,
        /* Name        */ F->getName(),
        /* LinkageName */ F->getName(),
        /* File        */ DebugInformation.File,
        /* LineNo      */ 0,
        /* Ty          */ SubProgType,
        /* ScopeLine   */ 0,
        /* Flags       */ llvm::DINode::FlagZero,
        /* SPFlags     */ SubProgFlags);
    F->setSubprogram(DebugInfo.Subprogram);

    llvm::BasicBlock *BB = llvm::BasicBlock::Create(*Context, "", F);
    {
      llvm::IRBuilderTy IRB(BB);

      IRB.SetCurrentDebugLocation(llvm::DILocation::get(
          *Context, 0 /* Line */, 0 /* Column */, DebugInfo.Subprogram));

      IRB.CreateRet(llvm::ConstantInt::get(WordType(), Binary.SectsStartAddr));
    }

    F->setLinkage(llvm::GlobalValue::InternalLinkage);
  }

  {
    llvm::Function *F = Module->getFunction("_jove_sections_global_beg_addr");
    assert(F && F->empty());

    llvm::DIBuilder &DIB = *DIBuilder;
    llvm::DISubprogram::DISPFlags SubProgFlags =
        llvm::DISubprogram::SPFlagDefinition |
        llvm::DISubprogram::SPFlagOptimized;

    SubProgFlags |= llvm::DISubprogram::SPFlagLocalToUnit;

    llvm::DISubroutineType *SubProgType =
        DIB.createSubroutineType(DIB.getOrCreateTypeArray(llvm::None));

    struct {
      llvm::DISubprogram *Subprogram;
    } DebugInfo;

    DebugInfo.Subprogram = DIB.createFunction(
        /* Scope       */ DebugInformation.CompileUnit,
        /* Name        */ F->getName(),
        /* LinkageName */ F->getName(),
        /* File        */ DebugInformation.File,
        /* LineNo      */ 0,
        /* Ty          */ SubProgType,
        /* ScopeLine   */ 0,
        /* Flags       */ llvm::DINode::FlagZero,
        /* SPFlags     */ SubProgFlags);
    F->setSubprogram(DebugInfo.Subprogram);


    llvm::BasicBlock *BB = llvm::BasicBlock::Create(*Context, "", F);
    {
      llvm::IRBuilderTy IRB(BB);

      IRB.SetCurrentDebugLocation(llvm::DILocation::get(
          *Context, 0 /* Line */, 0 /* Column */, DebugInfo.Subprogram));

      IRB.CreateRet(llvm::ConstantExpr::getPtrToInt(SectsGlobal, WordType()));
    }

    F->setLinkage(llvm::GlobalValue::InternalLinkage);
  }

  {
    llvm::Function *F = Module->getFunction("_jove_sections_global_end_addr");
    assert(F && F->empty());

    llvm::DIBuilder &DIB = *DIBuilder;
    llvm::DISubprogram::DISPFlags SubProgFlags =
        llvm::DISubprogram::SPFlagDefinition |
        llvm::DISubprogram::SPFlagOptimized;

    SubProgFlags |= llvm::DISubprogram::SPFlagLocalToUnit;

    llvm::DISubroutineType *SubProgType =
        DIB.createSubroutineType(DIB.getOrCreateTypeArray(llvm::None));

    struct {
      llvm::DISubprogram *Subprogram;
    } DebugInfo;

    DebugInfo.Subprogram = DIB.createFunction(
        /* Scope       */ DebugInformation.CompileUnit,
        /* Name        */ F->getName(),
        /* LinkageName */ F->getName(),
        /* File        */ DebugInformation.File,
        /* LineNo      */ 0,
        /* Ty          */ SubProgType,
        /* ScopeLine   */ 0,
        /* Flags       */ llvm::DINode::FlagZero,
        /* SPFlags     */ SubProgFlags);
    F->setSubprogram(DebugInfo.Subprogram);

    llvm::BasicBlock *BB = llvm::BasicBlock::Create(*Context, "", F);
    {
      llvm::IRBuilderTy IRB(BB);

      IRB.SetCurrentDebugLocation(llvm::DILocation::get(
          *Context, 0 /* Line */, 0 /* Column */, DebugInfo.Subprogram));

      // TODO call DL.getAllocSize and verify the numbers are the same
      target_ulong SectsGlobalSize = Binary.SectsEndAddr - Binary.SectsStartAddr;

      IRB.CreateRet(llvm::ConstantExpr::getAdd(
          llvm::ConstantExpr::getPtrToInt(SectsGlobal, WordType()),
          llvm::ConstantInt::get(WordType(), SectsGlobalSize)));
    }

    F->setLinkage(llvm::GlobalValue::InternalLinkage);
  }

  {
    llvm::Function *F = Module->getFunction("_jove_binary_index");
    assert(F && F->empty());

    llvm::DIBuilder &DIB = *DIBuilder;
    llvm::DISubprogram::DISPFlags SubProgFlags =
        llvm::DISubprogram::SPFlagDefinition |
        llvm::DISubprogram::SPFlagOptimized;

    SubProgFlags |= llvm::DISubprogram::SPFlagLocalToUnit;

    llvm::DISubroutineType *SubProgType =
        DIB.createSubroutineType(DIB.getOrCreateTypeArray(llvm::None));

    struct {
      llvm::DISubprogram *Subprogram;
    } DebugInfo;

    DebugInfo.Subprogram = DIB.createFunction(
        /* Scope       */ DebugInformation.CompileUnit,
        /* Name        */ F->getName(),
        /* LinkageName */ F->getName(),
        /* File        */ DebugInformation.File,
        /* LineNo      */ 0,
        /* Ty          */ SubProgType,
        /* ScopeLine   */ 0,
        /* Flags       */ llvm::DINode::FlagZero,
        /* SPFlags     */ SubProgFlags);
    F->setSubprogram(DebugInfo.Subprogram);

    llvm::BasicBlock *BB = llvm::BasicBlock::Create(*Context, "", F);
    {
      llvm::IRBuilderTy IRB(BB);

      IRB.SetCurrentDebugLocation(llvm::DILocation::get(
          *Context, 0 /* Line */, 0 /* Column */, DebugInfo.Subprogram));

      IRB.CreateRet(IRB.getInt32(BinaryIndex));
    }

    F->setLinkage(llvm::GlobalValue::InternalLinkage);
  }

  {
    llvm::Function *F = Module->getFunction("_jove_dynl_path");
    assert(F && F->empty());

    llvm::DIBuilder &DIB = *DIBuilder;
    llvm::DISubprogram::DISPFlags SubProgFlags =
        llvm::DISubprogram::SPFlagDefinition |
        llvm::DISubprogram::SPFlagOptimized;

    SubProgFlags |= llvm::DISubprogram::SPFlagLocalToUnit;

    llvm::DISubroutineType *SubProgType =
        DIB.createSubroutineType(DIB.getOrCreateTypeArray(llvm::None));

    struct {
      llvm::DISubprogram *Subprogram;
    } DebugInfo;

    DebugInfo.Subprogram = DIB.createFunction(
        /* Scope       */ DebugInformation.CompileUnit,
        /* Name        */ F->getName(),
        /* LinkageName */ F->getName(),
        /* File        */ DebugInformation.File,
        /* LineNo      */ 0,
        /* Ty          */ SubProgType,
        /* ScopeLine   */ 0,
        /* Flags       */ llvm::DINode::FlagZero,
        /* SPFlags     */ SubProgFlags);
    F->setSubprogram(DebugInfo.Subprogram);

    llvm::BasicBlock *BB = llvm::BasicBlock::Create(*Context, "", F);
    {
      llvm::IRBuilderTy IRB(BB);

      IRB.SetCurrentDebugLocation(llvm::DILocation::get(
          *Context, 0 /* Line */, 0 /* Column */, DebugInfo.Subprogram));

      std::string dynl_path;
      for (binary_t &binary : Decompilation.Binaries) {
        if (binary.IsDynamicLinker) {
          dynl_path = binary.Path;
          break;
        }
      }
      assert(!dynl_path.empty());

      IRB.CreateRet(IRB.CreateGlobalStringPtr(dynl_path));
    }

    F->setLinkage(llvm::GlobalValue::InternalLinkage);
  }

  {
    llvm::Function *TraceEnabledF = Module->getFunction("_jove_trace_enabled");
    assert(TraceEnabledF && TraceEnabledF->empty());

    llvm::DIBuilder &DIB = *DIBuilder;
    llvm::DISubprogram::DISPFlags SubProgFlags =
        llvm::DISubprogram::SPFlagDefinition |
        llvm::DISubprogram::SPFlagOptimized;

    SubProgFlags |= llvm::DISubprogram::SPFlagLocalToUnit;

    llvm::DISubroutineType *SubProgType =
        DIB.createSubroutineType(DIB.getOrCreateTypeArray(llvm::None));

    struct {
      llvm::DISubprogram *Subprogram;
    } DebugInfo;

    DebugInfo.Subprogram = DIB.createFunction(
        /* Scope       */ DebugInformation.CompileUnit,
        /* Name        */ TraceEnabledF->getName(),
        /* LinkageName */ TraceEnabledF->getName(),
        /* File        */ DebugInformation.File,
        /* LineNo      */ 0,
        /* Ty          */ SubProgType,
        /* ScopeLine   */ 0,
        /* Flags       */ llvm::DINode::FlagZero,
        /* SPFlags     */ SubProgFlags);
    TraceEnabledF->setSubprogram(DebugInfo.Subprogram);


    llvm::BasicBlock *BB =
        llvm::BasicBlock::Create(*Context, "", TraceEnabledF);
    {
      llvm::IRBuilderTy IRB(BB);

      IRB.SetCurrentDebugLocation(llvm::DILocation::get(
          *Context, 0 /* Line */, 0 /* Column */, DebugInfo.Subprogram));

      IRB.CreateRet(IRB.getInt1(opts::Trace));
    }

    TraceEnabledF->setLinkage(llvm::GlobalValue::InternalLinkage);
  }

  {
    llvm::Function *F = Module->getFunction("_jove_dfsan_enabled");
    assert(F && F->empty());

    llvm::DIBuilder &DIB = *DIBuilder;
    llvm::DISubprogram::DISPFlags SubProgFlags =
        llvm::DISubprogram::SPFlagDefinition |
        llvm::DISubprogram::SPFlagOptimized;

    SubProgFlags |= llvm::DISubprogram::SPFlagLocalToUnit;

    llvm::DISubroutineType *SubProgType =
        DIB.createSubroutineType(DIB.getOrCreateTypeArray(llvm::None));

    struct {
      llvm::DISubprogram *Subprogram;
    } DebugInfo;

    DebugInfo.Subprogram = DIB.createFunction(
        /* Scope       */ DebugInformation.CompileUnit,
        /* Name        */ F->getName(),
        /* LinkageName */ F->getName(),
        /* File        */ DebugInformation.File,
        /* LineNo      */ 0,
        /* Ty          */ SubProgType,
        /* ScopeLine   */ 0,
        /* Flags       */ llvm::DINode::FlagZero,
        /* SPFlags     */ SubProgFlags);
    F->setSubprogram(DebugInfo.Subprogram);

    llvm::BasicBlock *BB =
        llvm::BasicBlock::Create(*Context, "", F);
    {
      llvm::IRBuilderTy IRB(BB);

      IRB.SetCurrentDebugLocation(llvm::DILocation::get(
          *Context, 0 /* Line */, 0 /* Column */, DebugInfo.Subprogram));

      IRB.CreateRet(IRB.getInt1(opts::DFSan));
    }

    F->setLinkage(llvm::GlobalValue::InternalLinkage);
  }

  if (Binary.IsExecutable)
    assert(is_function_index_valid(Binary.Analysis.EntryFunction));

  {
    llvm::Function *CallEntryF = Module->getFunction("_jove_call_entry");
    assert(CallEntryF && CallEntryF->empty());

    llvm::DIBuilder &DIB = *DIBuilder;
    llvm::DISubprogram::DISPFlags SubProgFlags =
        llvm::DISubprogram::SPFlagDefinition |
        llvm::DISubprogram::SPFlagOptimized;

    SubProgFlags |= llvm::DISubprogram::SPFlagLocalToUnit;

    llvm::DISubroutineType *SubProgType =
      DIB.createSubroutineType(DIB.getOrCreateTypeArray(llvm::None));

    struct {
      llvm::DISubprogram *Subprogram;
    } DebugInfo;

    DebugInfo.Subprogram = DIB.createFunction(
      /* Scope       */ DebugInformation.CompileUnit,
      /* Name        */ CallEntryF->getName(),
      /* LinkageName */ CallEntryF->getName(),
      /* File        */ DebugInformation.File,
      /* LineNo      */ 0,
      /* Ty          */ SubProgType,
      /* ScopeLine   */ 0,
      /* Flags       */ llvm::DINode::FlagZero,
      /* SPFlags     */ SubProgFlags);

    CallEntryF->setSubprogram(DebugInfo.Subprogram);

    llvm::BasicBlock *BB = llvm::BasicBlock::Create(*Context, "", CallEntryF);
    {
      llvm::IRBuilderTy IRB(BB);

      IRB.SetCurrentDebugLocation(llvm::DILocation::get(
          *Context, 0 /* Line */, 0 /* Column */, DebugInfo.Subprogram));

      if (is_function_index_valid(Binary.Analysis.EntryFunction)) {
        function_t &f =
            Binary.Analysis.Functions[Binary.Analysis.EntryFunction];

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

        IRB.CreateCall(f.F, ArgVec)->setIsNoInline();
      }

      IRB.CreateCall(
          llvm::Intrinsic::getDeclaration(Module.get(), llvm::Intrinsic::trap));
      IRB.CreateUnreachable();
    }

    CallEntryF->setLinkage(llvm::GlobalValue::InternalLinkage);
  }

  {
    binary_t &dynl_binary = Decompilation.Binaries.at(1);
    assert(dynl_binary.IsDynamicLinker);
    auto &ICFG = dynl_binary.Analysis.ICFG;

    std::vector<llvm::Constant *> constantTable;
    constantTable.resize(dynl_binary.Analysis.Functions.size());

    std::transform(dynl_binary.Analysis.Functions.begin(),
                   dynl_binary.Analysis.Functions.end(), constantTable.begin(),
                   [&](const function_t &f) -> llvm::Constant * {
                     uintptr_t Addr = ICFG[boost::vertex(f.Entry, ICFG)].Addr;
                     return llvm::ConstantInt::get(WordType(), Addr);
                   });

    constantTable.push_back(llvm::Constant::getNullValue(WordType()));

    llvm::ArrayType *T = llvm::ArrayType::get(WordType(), constantTable.size());

    llvm::Constant *Init = llvm::ConstantArray::get(T, constantTable);
    llvm::GlobalVariable *ConstantTableGV = new llvm::GlobalVariable(
        *Module, T, false, llvm::GlobalValue::InternalLinkage, Init,
        "__jove_dynl_function_table");

    llvm::Function *GetDynlFunctionTableF =
        Module->getFunction("_jove_get_dynl_function_table");
    assert(GetDynlFunctionTableF && GetDynlFunctionTableF->empty());

    llvm::DIBuilder &DIB = *DIBuilder;
    llvm::DISubprogram::DISPFlags SubProgFlags =
        llvm::DISubprogram::SPFlagDefinition |
        llvm::DISubprogram::SPFlagOptimized;

    SubProgFlags |= llvm::DISubprogram::SPFlagLocalToUnit;

    llvm::DISubroutineType *SubProgType =
      DIB.createSubroutineType(DIB.getOrCreateTypeArray(llvm::None));

    struct {
      llvm::DISubprogram *Subprogram;
    } DebugInfo;

    DebugInfo.Subprogram = DIB.createFunction(
      /* Scope       */ DebugInformation.CompileUnit,
      /* Name        */ GetDynlFunctionTableF->getName(),
      /* LinkageName */ GetDynlFunctionTableF->getName(),
      /* File        */ DebugInformation.File,
      /* LineNo      */ 0,
      /* Ty          */ SubProgType,
      /* ScopeLine   */ 0,
      /* Flags       */ llvm::DINode::FlagZero,
      /* SPFlags     */ SubProgFlags);

    GetDynlFunctionTableF->setSubprogram(DebugInfo.Subprogram);

    llvm::BasicBlock *BB =
        llvm::BasicBlock::Create(*Context, "", GetDynlFunctionTableF);

    {
      llvm::IRBuilderTy IRB(BB);

      IRB.SetCurrentDebugLocation(llvm::DILocation::get(
          *Context, 0 /* Line */, 0 /* Column */, DebugInfo.Subprogram));

      IRB.CreateRet(IRB.CreateConstInBoundsGEP2_64(ConstantTableGV, 0, 0));
    }

    GetDynlFunctionTableF->setLinkage(llvm::GlobalValue::InternalLinkage);
  }

  {
    binary_t &vdso_binary = Decompilation.Binaries.at(2);
    auto &ICFG = vdso_binary.Analysis.ICFG;

    std::vector<llvm::Constant *> constantTable;
    constantTable.resize(vdso_binary.Analysis.Functions.size());

    std::transform(vdso_binary.Analysis.Functions.begin(),
                   vdso_binary.Analysis.Functions.end(), constantTable.begin(),
                   [&](const function_t &f) -> llvm::Constant * {
                     uintptr_t Addr = ICFG[boost::vertex(f.Entry, ICFG)].Addr;
                     return llvm::ConstantInt::get(WordType(), Addr);
                   });

    constantTable.push_back(llvm::Constant::getNullValue(WordType()));

    llvm::ArrayType *T = llvm::ArrayType::get(WordType(), constantTable.size());

    llvm::Constant *Init = llvm::ConstantArray::get(T, constantTable);
    llvm::GlobalVariable *ConstantTableGV = new llvm::GlobalVariable(
        *Module, T, false, llvm::GlobalValue::InternalLinkage, Init,
        "__jove_vdso_function_table");

    llvm::Function *GetVDSOFunctionTableF =
        Module->getFunction("_jove_get_vdso_function_table");
    assert(GetVDSOFunctionTableF && GetVDSOFunctionTableF->empty());

    llvm::DIBuilder &DIB = *DIBuilder;
    llvm::DISubprogram::DISPFlags SubProgFlags =
        llvm::DISubprogram::SPFlagDefinition |
        llvm::DISubprogram::SPFlagOptimized;

    SubProgFlags |= llvm::DISubprogram::SPFlagLocalToUnit;

    llvm::DISubroutineType *SubProgType =
        DIB.createSubroutineType(DIB.getOrCreateTypeArray(llvm::None));

    struct {
      llvm::DISubprogram *Subprogram;
    } DebugInfo;

    DebugInfo.Subprogram = DIB.createFunction(
        /* Scope       */ DebugInformation.CompileUnit,
        /* Name        */ GetVDSOFunctionTableF->getName(),
        /* LinkageName */ GetVDSOFunctionTableF->getName(),
        /* File        */ DebugInformation.File,
        /* LineNo      */ 0,
        /* Ty          */ SubProgType,
        /* ScopeLine   */ 0,
        /* Flags       */ llvm::DINode::FlagZero,
        /* SPFlags     */ SubProgFlags);
    GetVDSOFunctionTableF->setSubprogram(DebugInfo.Subprogram);

    llvm::BasicBlock *BB =
        llvm::BasicBlock::Create(*Context, "", GetVDSOFunctionTableF);

    {
      llvm::IRBuilderTy IRB(BB);

      IRB.SetCurrentDebugLocation(llvm::DILocation::get(
          *Context, 0 /* Line */, 0 /* Column */, DebugInfo.Subprogram));

      IRB.CreateRet(IRB.CreateConstInBoundsGEP2_64(ConstantTableGV, 0, 0));
    }

    GetVDSOFunctionTableF->setLinkage(llvm::GlobalValue::InternalLinkage);
  }

  {
    llvm::Function *F = Module->getFunction("_jove_foreign_lib_count");
    assert(F && F->empty());

    llvm::DIBuilder &DIB = *DIBuilder;
    llvm::DISubprogram::DISPFlags SubProgFlags =
        llvm::DISubprogram::SPFlagDefinition |
        llvm::DISubprogram::SPFlagOptimized;

    SubProgFlags |= llvm::DISubprogram::SPFlagLocalToUnit;

    llvm::DISubroutineType *SubProgType =
        DIB.createSubroutineType(DIB.getOrCreateTypeArray(llvm::None));

    struct {
      llvm::DISubprogram *Subprogram;
    } DebugInfo;

    DebugInfo.Subprogram = DIB.createFunction(
        /* Scope       */ DebugInformation.CompileUnit,
        /* Name        */ F->getName(),
        /* LinkageName */ F->getName(),
        /* File        */ DebugInformation.File,
        /* LineNo      */ 0,
        /* Ty          */ SubProgType,
        /* ScopeLine   */ 0,
        /* Flags       */ llvm::DINode::FlagZero,
        /* SPFlags     */ SubProgFlags);
    F->setSubprogram(DebugInfo.Subprogram);

    llvm::BasicBlock *BB = llvm::BasicBlock::Create(*Context, "", F);
    {
      llvm::IRBuilderTy IRB(BB);

      IRB.SetCurrentDebugLocation(llvm::DILocation::get(
          *Context, 0 /* Line */, 0 /* Column */, DebugInfo.Subprogram));

      uint32_t res =
          opts::ForeignLibs ? (Decompilation.Binaries.size()
                               - 1 /* rtld */
                               - 1 /* vdso */
                               - 1 /* exe  */) : 0;

      IRB.CreateRet(llvm::ConstantInt::get(IRB.getInt32Ty(), res));
    }

    F->setLinkage(llvm::GlobalValue::InternalLinkage);
  }

  {
    llvm::Function *F = Module->getFunction("_jove_foreign_lib_path");
    assert(F && F->empty());

    llvm::DIBuilder &DIB = *DIBuilder;
    llvm::DISubprogram::DISPFlags SubProgFlags =
        llvm::DISubprogram::SPFlagDefinition |
        llvm::DISubprogram::SPFlagOptimized;

    SubProgFlags |= llvm::DISubprogram::SPFlagLocalToUnit;

    llvm::DISubroutineType *SubProgType =
        DIB.createSubroutineType(DIB.getOrCreateTypeArray(llvm::None));

    struct {
      llvm::DISubprogram *Subprogram;
    } DebugInfo;

    DebugInfo.Subprogram = DIB.createFunction(
        /* Scope       */ DebugInformation.CompileUnit,
        /* Name        */ F->getName(),
        /* LinkageName */ F->getName(),
        /* File        */ DebugInformation.File,
        /* LineNo      */ 0,
        /* Ty          */ SubProgType,
        /* ScopeLine   */ 0,
        /* Flags       */ llvm::DINode::FlagZero,
        /* SPFlags     */ SubProgFlags);
    F->setSubprogram(DebugInfo.Subprogram);

    llvm::BasicBlock *BB = llvm::BasicBlock::Create(*Context, "", F);
    llvm::BasicBlock *DefaultBB = llvm::BasicBlock::Create(*Context, "", F);
    {
      llvm::IRBuilderTy IRB(DefaultBB);

      IRB.SetCurrentDebugLocation(llvm::DILocation::get(
          *Context, 7 /* Line */, 7 /* Column */, DebugInfo.Subprogram));

      IRB.CreateRet(llvm::Constant::getNullValue(F->getFunctionType()->getReturnType()));
    }

    {
      llvm::IRBuilderTy IRB(BB);

      IRB.SetCurrentDebugLocation(llvm::DILocation::get(
          *Context, 0 /* Line */, 0 /* Column */, DebugInfo.Subprogram));

      assert(F->arg_begin() != F->arg_end());
      llvm::SwitchInst *SI = IRB.CreateSwitch(F->arg_begin(), DefaultBB,
                                              Decompilation.Binaries.size() - 3);
      if (opts::ForeignLibs) {
        for (binary_index_t BIdx = 3; BIdx < Decompilation.Binaries.size(); ++BIdx) {
          llvm::BasicBlock *CaseBB = llvm::BasicBlock::Create(*Context, "", F);
          {
            llvm::IRBuilderTy CaseIRB(CaseBB);

            CaseIRB.SetCurrentDebugLocation(llvm::DILocation::get(
                *Context, 0 /* Line */, 0 /* Column */, DebugInfo.Subprogram));

            CaseIRB.CreateRet(
                CaseIRB.CreateGlobalStringPtr(Decompilation.Binaries[BIdx].Path));
          }

          SI->addCase(llvm::ConstantInt::get(IRB.getInt32Ty(), BIdx - 3),  CaseBB);
        }
      }
    }

    F->setLinkage(llvm::GlobalValue::InternalLinkage);
  }

  {
    llvm::Function *F = Module->getFunction("_jove_foreign_lib_function_table");
    assert(F && F->empty());

    llvm::DIBuilder &DIB = *DIBuilder;
    llvm::DISubprogram::DISPFlags SubProgFlags =
        llvm::DISubprogram::SPFlagDefinition |
        llvm::DISubprogram::SPFlagOptimized;

    SubProgFlags |= llvm::DISubprogram::SPFlagLocalToUnit;

    llvm::DISubroutineType *SubProgType =
        DIB.createSubroutineType(DIB.getOrCreateTypeArray(llvm::None));

    struct {
      llvm::DISubprogram *Subprogram;
    } DebugInfo;

    DebugInfo.Subprogram = DIB.createFunction(
        /* Scope       */ DebugInformation.CompileUnit,
        /* Name        */ F->getName(),
        /* LinkageName */ F->getName(),
        /* File        */ DebugInformation.File,
        /* LineNo      */ 0,
        /* Ty          */ SubProgType,
        /* ScopeLine   */ 0,
        /* Flags       */ llvm::DINode::FlagZero,
        /* SPFlags     */ SubProgFlags);
    F->setSubprogram(DebugInfo.Subprogram);

    llvm::BasicBlock *BB = llvm::BasicBlock::Create(*Context, "", F);
    llvm::BasicBlock *DefaultBB = llvm::BasicBlock::Create(*Context, "", F);
    {
      llvm::IRBuilderTy IRB(DefaultBB);

      IRB.SetCurrentDebugLocation(llvm::DILocation::get(
          *Context, 7 /* Line */, 7 /* Column */, DebugInfo.Subprogram));

      IRB.CreateRet(llvm::Constant::getNullValue(F->getFunctionType()->getReturnType()));
    }

    {
      llvm::IRBuilderTy IRB(BB);

      IRB.SetCurrentDebugLocation(llvm::DILocation::get(
          *Context, 0 /* Line */, 0 /* Column */, DebugInfo.Subprogram));

      assert(F->arg_begin() != F->arg_end());
      llvm::SwitchInst *SI = IRB.CreateSwitch(F->arg_begin(), DefaultBB,
                                              Decompilation.Binaries.size() - 3);
      if (opts::ForeignLibs) {
        for (binary_index_t BIdx = 3; BIdx < Decompilation.Binaries.size(); ++BIdx) {
          binary_t &binary = Decompilation.Binaries[BIdx];
          auto &ICFG = binary.Analysis.ICFG;

          llvm::ArrayType *TblTy =
            llvm::ArrayType::get(WordType(),
                                 binary.Analysis.Functions.size() + 1);

          std::vector<llvm::Constant *> constantTable;
          constantTable.resize(binary.Analysis.Functions.size() + 1);

          for (function_index_t FIdx = 0; FIdx < binary.Analysis.Functions.size(); ++FIdx) {
            function_t &f = binary.Analysis.Functions[FIdx];

            constantTable[FIdx] = llvm::ConstantInt::get(
                WordType(), ICFG[boost::vertex(f.Entry, ICFG)].Addr);
          }

          constantTable.back() = llvm::Constant::getNullValue(WordType());

          llvm::Constant *Init = llvm::ConstantArray::get(TblTy, constantTable);

          llvm::GlobalVariable *ConstantTableGV = new llvm::GlobalVariable(
              *Module, TblTy, false, llvm::GlobalValue::InternalLinkage, Init,
              (fmt("__jove_foreign_function_table_%u") % BIdx).str());

          llvm::BasicBlock *CaseBB = llvm::BasicBlock::Create(*Context, "", F);
          {
            llvm::IRBuilderTy CaseIRB(CaseBB);

            CaseIRB.SetCurrentDebugLocation(llvm::DILocation::get(
                *Context, 0 /* Line */, 0 /* Column */, DebugInfo.Subprogram));

            CaseIRB.CreateRet(
                CaseIRB.CreateConstInBoundsGEP2_64(ConstantTableGV, 0, 0));
          }

          SI->addCase(llvm::ConstantInt::get(IRB.getInt32Ty(), BIdx - 3),  CaseBB);
        }
      }
    }

    F->setLinkage(llvm::GlobalValue::InternalLinkage);
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

struct TranslateContext {
  function_t &f;
  basic_block_t bb;

  std::array<llvm::AllocaInst *, tcg_num_globals> GlobalAllocaArr;
  std::vector<llvm::AllocaInst *> TempAllocaVec;
  std::vector<llvm::BasicBlock *> LabelVec;
  llvm::AllocaInst *PCAlloca;

  struct {
    llvm::DISubprogram *Subprogram;
  } DebugInformation;

  TranslateContext(function_t &f) : f(f) {
    memset(&GlobalAllocaArr[0], 0, sizeof(llvm::AllocaInst *) * GlobalAllocaArr.size());
  }
};

static llvm::AllocaInst *CreateAllocaForGlobal(llvm::IRBuilderTy &IRB,
                                               unsigned glb,
                                               bool InitializeFromEnv = true) {
  llvm::AllocaInst *res = IRB.CreateAlloca(
      IRB.getIntNTy(bitsOfTCGType(TCG->_ctx.temps[glb].type)), nullptr,
      std::string(TCG->_ctx.temps[glb].name) + "_ptr");

  if (InitializeFromEnv) {
    llvm::LoadInst *LI = IRB.CreateLoad(CPUStateGlobalPointer(glb));
    LI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);

    llvm::StoreInst *SI = IRB.CreateStore(LI, res);
    SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
  }

  return res;
}

static int TranslateBasicBlock(TranslateContext &);

llvm::Constant *CPUStateGlobalPointer(unsigned glb) {
  assert(glb < tcg_num_globals);
  assert(glb != tcg_env_index);

  unsigned bits = bitsOfTCGType(TCG->_ctx.temps[glb].type);
  llvm::Type *GlbTy = llvm::IntegerType::get(*Context, bits);

  struct TCGTemp *base_tmp = TCG->_ctx.temps[glb].mem_base;
  if (unlikely(!base_tmp || temp_idx(base_tmp) != tcg_env_index))
    return nullptr;

  unsigned off = TCG->_ctx.temps[glb].mem_offset;

  llvm::IRBuilderTy IRB(*Context);
  llvm::SmallVector<llvm::Value *, 4> Indices;
  llvm::Value *res = llvm::getNaturalGEPWithOffset(
      IRB, DL, CPUStateGlobal, llvm::APInt(64, off), GlbTy, Indices, "");

  if (res) {
    assert(llvm::isa<llvm::Constant>(res));
    return llvm::ConstantExpr::getPointerCast(llvm::cast<llvm::Constant>(res),
                                              llvm::PointerType::get(GlbTy, 0));
  }

  // fallback
  return llvm::ConstantExpr::getIntToPtr(
      llvm::ConstantExpr::getAdd(
          llvm::ConstantExpr::getPtrToInt(CPUStateGlobal, WordType()),
          llvm::ConstantInt::get(WordType(), off)),
      llvm::PointerType::get(GlbTy, 0));
}

llvm::Value *BuildCPUStatePointer(llvm::IRBuilderTy &IRB, llvm::Value *Env, unsigned glb) {
  assert(glb < tcg_num_globals);
  assert(glb != tcg_env_index);

  unsigned bits = bitsOfTCGType(TCG->_ctx.temps[glb].type);
  llvm::Type *GlbTy = llvm::IntegerType::get(*Context, bits);

  struct TCGTemp *base_tmp = TCG->_ctx.temps[glb].mem_base;
  if (unlikely(!base_tmp || temp_idx(base_tmp) != tcg_env_index))
    return nullptr;

  unsigned off = TCG->_ctx.temps[glb].mem_offset;

  llvm::SmallVector<llvm::Value *, 4> Indices;
  llvm::Value *res = llvm::getNaturalGEPWithOffset(
      IRB, DL, Env, llvm::APInt(64, off), GlbTy, Indices, "");

  if (res)
    return IRB.CreatePointerCast(res, llvm::PointerType::get(GlbTy, 0));

  // fallback
  return IRB.CreateIntToPtr(
      IRB.CreateAdd(IRB.CreatePtrToInt(Env, WordType()),
                    llvm::ConstantInt::get(WordType(), off)),
      llvm::PointerType::get(GlbTy, 0));
}

static int TranslateFunction(function_t &f) {
  TranslateContext TC(f);

  binary_t &Binary = Decompilation.Binaries[BinaryIndex];
  interprocedural_control_flow_graph_t &ICFG = Binary.Analysis.ICFG;
  llvm::Function *F = f.F;
  llvm::DIBuilder &DIB = *DIBuilder;

  if (unlikely(f.BasicBlocks.empty()))
    return 0;

  basic_block_t entry_bb = f.BasicBlocks.front();
  llvm::BasicBlock *EntryB = llvm::BasicBlock::Create(*Context, "", F);

  for (basic_block_t bb : f.BasicBlocks)
    ICFG[bb].B = llvm::BasicBlock::Create(
        *Context, (fmt("%#lx") % ICFG[bb].Addr).str(), F);

  llvm::DISubprogram::DISPFlags SubProgFlags =
      llvm::DISubprogram::SPFlagDefinition |
      llvm::DISubprogram::SPFlagOptimized;

  if (F->hasPrivateLinkage() || F->hasInternalLinkage())
    SubProgFlags |= llvm::DISubprogram::SPFlagLocalToUnit;

  llvm::DISubroutineType *SubProgType =
      DIB.createSubroutineType(DIB.getOrCreateTypeArray(llvm::None));

  TC.DebugInformation.Subprogram = DIB.createFunction(
      /* Scope       */ DebugInformation.CompileUnit,
      /* Name        */ F->getName(),
      /* LinkageName */ F->getName(),
      /* File        */ DebugInformation.File,
      /* LineNo      */ 0,
      /* Ty          */ SubProgType,
      /* ScopeLine   */ 0,
      /* Flags       */ llvm::DINode::FlagZero,
      /* SPFlags     */ SubProgFlags);

  F->setSubprogram(TC.DebugInformation.Subprogram);

  auto &GlobalAllocaArr = TC.GlobalAllocaArr;

  {
    llvm::IRBuilderTy IRB(EntryB);

    IRB.SetCurrentDebugLocation(
        llvm::DILocation::get(*Context, ICFG[entry_bb].Addr, 0 /* Column */,
                              TC.DebugInformation.Subprogram));

    //
    // Create Alloca for program counter
    //
    {
      llvm::AllocaInst *AI;
      if (tcg_program_counter_index >= 0) {
        AI = CreateAllocaForGlobal(IRB, tcg_program_counter_index, false);
        GlobalAllocaArr[tcg_program_counter_index] = AI;
      } else {
        AI = IRB.CreateAlloca(WordType(), 0, "pc_ptr");
      }

      TC.PCAlloca = AI;
    }

    //
    // initialize globals which are passed by value to function
    //
    {
      std::vector<unsigned> glbv;
      ExplodeFunctionArgs(f, glbv);

      llvm::Function::arg_iterator arg_it = F->arg_begin();
      for (unsigned glb : glbv) {
        assert(arg_it != F->arg_end());
        llvm::Argument *Val = &*arg_it++;

        llvm::AllocaInst *Ptr = CreateAllocaForGlobal(IRB, glb, false);
        GlobalAllocaArr[glb] = Ptr;

        llvm::StoreInst *SI = IRB.CreateStore(Val, Ptr);
        SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
      }
    }

    if (opts::DFSan) {
      llvm::AllocaInst *&SPAlloca = GlobalAllocaArr[tcg_stack_pointer_index];

      if (!SPAlloca)
        SPAlloca = CreateAllocaForGlobal(IRB, tcg_stack_pointer_index, true);

      llvm::LoadInst *LI = IRB.CreateLoad(SPAlloca);
      LI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);

      IRB.CreateCall(
          IRB.CreateIntToPtr(
              IRB.CreateLoad(JoveLogFunctionStartClunk),
              JoveLogFunctionStart->getType()),
          {IRB.CreateIntCast(LI, IRB.getInt64Ty(), false)});
    }

    IRB.CreateBr(ICFG[entry_bb].B);
  }

  for (unsigned i = 0; i < f.BasicBlocks.size(); ++i) {
    TC.bb = f.BasicBlocks[i];

    int ret = TranslateBasicBlock(TC);

    if (unlikely(ret))
      return ret;
  }

  DIB.finalizeSubprogram(TC.DebugInformation.Subprogram);

  return 0;
}

int TranslateFunctions(void) {
  llvm::legacy::FunctionPassManager FPM(Module.get());

  llvm::Triple ModuleTriple(Module->getTargetTriple());
  llvm::TargetLibraryInfoImpl TLII(ModuleTriple);
  if (true /* DisableSimplifyLibCalls */)
    TLII.disableAllFunctions();

  FPM.add(new llvm::TargetLibraryInfoWrapperPass(TLII));
  FPM.add(llvm::createTargetTransformInfoWrapperPass(TM->getTargetIRAnalysis()));

  FPM.add(llvm::createScopedNoAliasAAWrapperPass());
  FPM.add(llvm::createBasicAAWrapperPass());

  // Promote allocas to registers.
  FPM.add(llvm::createPromoteMemoryToRegisterPass());
  // Do simple "peephole" optimizations and bit-twiddling optzns.
  FPM.add(llvm::createInstructionCombiningPass());
#if 0
  // Reassociate expressions.
  FPM.add(llvm::createReassociatePass());
  // Eliminate Common SubExpressions.
  FPM.add(llvm::createGVNPass());
#endif
  FPM.add(llvm::createDeadStoreEliminationPass());
  // Simplify the control flow graph (deleting unreachable blocks, etc).
  FPM.add(llvm::createCFGSimplificationPass());

  FPM.doInitialization();

  binary_t &Binary = Decompilation.Binaries[BinaryIndex];
  for (function_t &f : Binary.Analysis.Functions) {
    int ret = TranslateFunction(f);
    if (unlikely(ret))
      return ret;

    if (likely(f.F))
      FPM.run(*f.F);
  }

  llvm::DIBuilder &DIB = *DIBuilder;
  DIB.finalize();

  FPM.doFinalization();

  return 0;
}

static int InlineCalls(void) {
  std::unordered_set<llvm::CallInst *> CallsToInline;

  for (llvm::Function *F : FunctionsToInline) {
    for (llvm::User *U : F->users()) {

      if (!llvm::isa<llvm::CallInst>(U))
        continue;

      llvm::CallInst *Call = llvm::cast<llvm::CallInst>(U);
      if (Call->getCalledFunction() != F)
        continue;

      CallsToInline.insert(Call);
    }
  }

  for (llvm::CallInst *CallInst : CallsToInline) {
    llvm::InlineFunctionInfo IFI;
    llvm::InlineResult InlRes = llvm::InlineFunction(CallInst, IFI);
    if (!InlRes)
      WithColor::error() << llvm::formatv(
          "unable to inline {0} function ({1})\n", *CallInst, InlRes.message);
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
  initializeExpandMemCmpPassPass(Registry);
  initializeScalarizeMaskedMemIntrinPass(Registry);
  initializeCodeGenPreparePass(Registry);
  initializeAtomicExpandPass(Registry);
  initializeRewriteSymbolsLegacyPassPass(Registry);
  initializeWinEHPreparePass(Registry);
  initializeDwarfEHPreparePass(Registry);
  initializeSafeStackLegacyPassPass(Registry);
  initializeSjLjEHPreparePass(Registry);
  initializePreISelIntrinsicLoweringLegacyPassPass(Registry);
  initializeGlobalMergePass(Registry);
  initializeIndirectBrExpandPassPass(Registry);
  initializeInterleavedLoadCombinePass(Registry);
  initializeInterleavedAccessPass(Registry);
  initializeEntryExitInstrumenterPass(Registry);
  initializePostInlineEntryExitInstrumenterPass(Registry);
  initializeUnreachableBlockElimLegacyPassPass(Registry);
  initializeExpandReductionsPass(Registry);
  initializeWasmEHPreparePass(Registry);
  initializeWriteBitcodePassPass(Registry);
  initializeHardwareLoopsPass(Registry);
  initializeTypePromotionPass(Registry);

  return 0;
}

static void ReloadGlobalVariables(void) {
  CPUStateGlobal   = Module->getGlobalVariable("__jove_env",                 true);
  SectsGlobal      = Module->getGlobalVariable((fmt("__jove_sections_%u") % BinaryIndex).str(), true);
  ConstSectsGlobal = Module->getGlobalVariable("__jove_sections_const",      true);
}

int DoOptimize(void) {
  if (llvm::verifyModule(*Module, &llvm::errs())) {
    WithColor::error() << "DoOptimize: [pre] failed to verify module\n";

    WithColor::error() << "Dumping module...\n";
    DumpModule("pre.opt1.fail");

    // llvm::errs() << *Module << '\n';
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
  if (true /* DisableSimplifyLibCalls */)
    TLII.disableAllFunctions();
  MPM.add(new llvm::TargetLibraryInfoWrapperPass(TLII));

  // Add internal analysis passes from the target machine.
  MPM.add(llvm::createTargetTransformInfoWrapperPass(TM->getTargetIRAnalysis()));
  FPM.add(llvm::createTargetTransformInfoWrapperPass(TM->getTargetIRAnalysis()));

  llvm::PassManagerBuilder Builder;
  Builder.OptLevel = OptLevel;
  Builder.SizeLevel = SizeLevel;

  Builder.Inliner =
      llvm::createFunctionInliningPass(OptLevel, SizeLevel, false);

  TM->adjustPassManager(Builder);

  Builder.populateFunctionPassManager(FPM);
  Builder.populateModulePassManager(MPM);

  FPM.doInitialization();
  for (llvm::Function &F : *Module)
    FPM.run(F);
  FPM.doFinalization();

  MPM.run(*Module);

  if (llvm::verifyModule(*Module, &llvm::errs())) {
    WithColor::error() << "DoOptimize: [post] failed to verify module\n";

    DumpModule("post.opt1.fail");
    return 1;
  }

  //
  // if any gv was optimized away, we'd like to make sure our pointer to it
  // becomes null.
  //
  ReloadGlobalVariables();

  return 0;
}

int ConstifyRelocationSectionPointers(void) {
  binary_t &Binary = Decompilation.Binaries[BinaryIndex];

  assert(SectsGlobal && ConstSectsGlobal);

  std::vector<std::pair<llvm::Value *, llvm::Value *>> ToReplace;

  for (llvm::User *U_0 : SectsGlobal->users()) {
    if (!llvm::isa<llvm::ConstantExpr>(U_0))
      continue;

    llvm::ConstantExpr *CE_0 = llvm::cast<llvm::ConstantExpr>(U_0);
    if (CE_0->getOpcode() != llvm::Instruction::PtrToInt)
      continue;

    for (llvm::User *U_1 : CE_0->users()) {
      if (!llvm::isa<llvm::ConstantExpr>(U_1))
        continue;

      llvm::ConstantExpr *CE_1 = llvm::cast<llvm::ConstantExpr>(U_1);
      if (CE_1->getOpcode() != llvm::Instruction::Add)
        continue;

      assert(CE_1->getNumOperands() == 2);
      llvm::Value *Addend = CE_1->getOperand(1);
      if (!llvm::isa<llvm::ConstantInt>(Addend))
        continue;

      if (llvm::cast<llvm::ConstantInt>(Addend)->getValue().isStrictlyPositive()) {
        uintptr_t off =
            llvm::cast<llvm::ConstantInt>(Addend)->getValue().getZExtValue();

        uintptr_t FileAddr = off + Binary.SectsStartAddr;

        bool RelocLoc = ConstantRelocationLocs.find(FileAddr) !=
                        ConstantRelocationLocs.end();

        if (RelocLoc) {
          llvm::IRBuilderTy IRB(*Context);
          llvm::SmallVector<llvm::Value *, 4> Indices;
          llvm::Value *SectionGEP = llvm::getNaturalGEPWithOffset(
              IRB, DL, ConstSectsGlobal, llvm::APInt(64, off), nullptr, Indices, "");

          if (llvm::isa<llvm::Constant>(SectionGEP))
            ToReplace.push_back(
                {(llvm::Value *)CE_1,
                 llvm::ConstantExpr::getPtrToInt(
                     llvm::cast<llvm::Constant>(SectionGEP), WordType())});
        }
      }
    }
  }

  for (auto &TR : ToReplace) {
    llvm::Value *I;
    llvm::Value *V;
    std::tie(I, V) = TR;

    I->replaceAllUsesWith(V);
  }

  return 0;
}

int InternalizeSections(void) {
  if (SectsGlobal)
    SectsGlobal->setLinkage(llvm::GlobalValue::InternalLinkage);
  if (ConstSectsGlobal)
    ConstSectsGlobal->setLinkage(llvm::GlobalValue::InternalLinkage);

  return 0;
}

int ExpandMemoryIntrinsicCalls(void) {
  //
  // lower memory intrinsics (memcpy, memset, memmove)
  //
  for (llvm::Function &F : Module->functions()) {
    if (!F.isDeclaration())
      continue;

    switch (F.getIntrinsicID()) {
    case llvm::Intrinsic::memcpy:
    case llvm::Intrinsic::memmove:
    case llvm::Intrinsic::memset:
      expandMemIntrinsicUses(F);
      break;

    default:
      break;
    }
  }

  return 0;
}

int ReplaceAllRemainingUsesOfConstSections(void) {
  if (!ConstSectsGlobal)
    return 0;

  assert(SectsGlobal);

  if (ConstSectsGlobal->user_begin() != ConstSectsGlobal->user_end())
    ConstSectsGlobal->replaceAllUsesWith(SectsGlobal);

  assert(ConstSectsGlobal->user_begin() == ConstSectsGlobal->user_end());
  ConstSectsGlobal->eraseFromParent();

  return 0;
}

int RenameFunctionLocals(void) {
  if (!CPUStateGlobal)
    return 0;

  for (llvm::User *U : CPUStateGlobal->users()) {
    uint8_t glb = 0xff;

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

    if (glb == 0xff)
      continue;

    const char *nm = TCG->_ctx.temps[glb].name;
    for (llvm::User *UU : U->users()) {
      if (llvm::isa<llvm::LoadInst>(UU))
        UU->setName(nm);
    }
  }

  return 0;
}

int DFSanInstrument(void) {
  assert(opts::DFSan);

#if 0
  if (llvm::verifyModule(*Module, &llvm::errs())) {
    WithColor::error() << "DFSanInstrument: [pre] failed to verify module\n";
    //llvm::errs() << *Module << '\n';
    return 1;
  }
#endif

#if 1
  llvm::legacy::PassManager MPM;
#else
  llvm::legacy::FunctionPassManager FPM(Module.get());
#endif

  // Add an appropriate TargetLibraryInfo pass for the module's triple.
  llvm::Triple ModuleTriple(Module->getTargetTriple());
#if 1
  llvm::TargetLibraryInfoImpl TLII(ModuleTriple);

  // The -disable-simplify-libcalls flag actually disables all builtin optzns.
  if (true /* DisableSimplifyLibCalls */)
    TLII.disableAllFunctions();
  MPM.add(new llvm::TargetLibraryInfoWrapperPass(TLII));

  // Add internal analysis passes from the target machine.
  MPM.add(llvm::createTargetTransformInfoWrapperPass(TM->getTargetIRAnalysis()));

  std::vector<std::string> ABIList = {
      (boost::dll::program_location().parent_path() / "dfsan_abilist.txt")
          .string()};

  MPM.add(llvm::createDataFlowSanitizerPass(ABIList, nullptr, nullptr));

  {
    llvm::StringMap<llvm::cl::Option*> &OptionMap = llvm::cl::getRegisteredOptions();
    {
      auto it = OptionMap.find("dfsan-no-loop-starts");
      if (it == OptionMap.end()) {
        WithColor::error() << "DFSanInstrument: could not find dfsan-no-loop-starts option!\n";
        return 1;
      }

      llvm::cl::Option *O = (*it).second;
      assert(O);
    }
  }

  MPM.run(*Module);
#else
  std::vector<std::string> ABIList;
  FPM.add(llvm::createTargetTransformInfoWrapperPass(TM->getTargetIRAnalysis()));
  FPM.add(llvm::createDataFlowSanitizerPass(ABIList, nullptr, nullptr));

  FPM.doInitialization();
  for (function_t &f : Decompilation.Binaries[BinaryIndex].Analysis.Functions) {
    assert(f.F);

    FPM.run(*f.F);
  }
  FPM.doFinalization();
#endif

#if 0
  if (llvm::verifyModule(*Module, &llvm::errs())) {
    WithColor::error() << "DFSanInstrument: [post] failed to verify module\n";
    //llvm::errs() << *Module << '\n';
    return 1;
  }
#endif

  //
  // XXX
  //
  {
    llvm::GlobalVariable *GV =
        Module->getGlobalVariable("__dfsan_disable_logging", true);
    assert(GV);
    GV->setLinkage(llvm::GlobalValue::ExternalLinkage);
    GV->setInitializer(nullptr);
  }

  {
    llvm::NamedMDNode *TopNode =
        Module->getOrInsertNamedMetadata("DFSanModuleID");
    assert(TopNode);

    llvm::MDNode *SubNode = TopNode->getOperand(0);

    std::string ModuleID =
        llvm::cast<llvm::MDString>(SubNode->getOperand(0))->getString();
    WithColor::note() << llvm::formatv("ModuleID is {0}\n", ModuleID);

    {
      std::ofstream ofs(opts::DFSanOutputModuleID);

      ofs << ModuleID;
    }
  }

  return 0;
}

static int await_process_completion(pid_t pid);

static void InvalidateAllFunctionAnalyses(void) {
  for (binary_t &binary : Decompilation.Binaries)
    for (function_t &f : binary.Analysis.Functions)
      f.InvalidateAnalysis();
}

int await_process_completion(pid_t pid) {
  int wstatus;
  do {
    if (waitpid(pid, &wstatus, WUNTRACED | WCONTINUED) < 0)
      abort();

    if (WIFEXITED(wstatus)) {
      //printf("exited, status=%d\n", WEXITSTATUS(wstatus));
      return WEXITSTATUS(wstatus);
    } else if (WIFSIGNALED(wstatus)) {
      //printf("killed by signal %d\n", WTERMSIG(wstatus));
      return 1;
    } else if (WIFSTOPPED(wstatus)) {
      //printf("stopped by signal %d\n", WSTOPSIG(wstatus));
      return 1;
    } else if (WIFCONTINUED(wstatus)) {
      //printf("continued\n");
    }
  } while (!WIFEXITED(wstatus) && !WIFSIGNALED(wstatus));

  abort();
}

int WriteVersionScript(void) {
  std::ofstream ofs(opts::VersionScript);

  for (const auto &entry : VersionScript.Table) {
    const std::string &VersionNode = entry.first;

    ofs << VersionNode << " {\n";

    if (!entry.second.empty())
      ofs << "global:\n";

    for (const std::string &VersionedSymbol : entry.second)
      ofs << VersionedSymbol << ";\n";

    ofs << "};\n";
  }

  return 0;
}

int WriteModule(void) {
  if (opts::VerifyBitcode) {
    if (llvm::verifyModule(*Module, &llvm::errs())) {
      WithColor::error() << "WriteModule: failed to verify module\n";

      DumpModule("pre.write.module");
      return 1;
    }
  }

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

typedef int (*translate_tcg_op_proc_t)(TCGOp *,
                                       llvm::BasicBlock *,
                                       llvm::IRBuilderTy &,
                                       TranslateContext &);

extern const translate_tcg_op_proc_t TranslateTCGOpTable[180];

static bool seenOpTable[ARRAY_SIZE(tcg_op_defs)];

int TranslateBasicBlock(TranslateContext &TC) {
  auto &GlobalAllocaArr = TC.GlobalAllocaArr;
  auto &TempAllocaVec = TC.TempAllocaVec;
  auto &LabelVec = TC.LabelVec;
  basic_block_t bb = TC.bb;
  function_t &f = TC.f;

  binary_t &Binary = Decompilation.Binaries[BinaryIndex];
  const auto &ICFG = Binary.Analysis.ICFG;
  llvm::IRBuilderTy IRB(ICFG[bb].B);

  //
  // helper functions for GlobalAllocaArr
  //
  auto set = [&](llvm::Value *V, unsigned glb) -> void {
    assert(glb != tcg_env_index);

    if (unlikely(CmdlinePinnedEnvGlbs.test(glb))) {
      llvm::StoreInst *SI = IRB.CreateStore(V, CPUStateGlobalPointer(glb));
      SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
      return;
    }

    llvm::AllocaInst *&Ptr = GlobalAllocaArr.at(glb);
    if (!Ptr) {
      llvm::IRBuilderTy tmpIRB(&f.F->getEntryBlock().front());

      Ptr = CreateAllocaForGlobal(tmpIRB, glb);
    }

    llvm::StoreInst *SI = IRB.CreateStore(V, Ptr);
    SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
  };

  auto get = [&](unsigned glb) -> llvm::Value * {
    switch (glb) {
    case tcg_env_index:
      return llvm::ConstantExpr::getPtrToInt(CPUStateGlobal, WordType());
#if defined(TARGET_X86_64)
    case tcg_fs_base_index:
      return insertThreadPointerInlineAsm(IRB);
#elif defined(TARGET_I386)
    case tcg_gs_base_index:
      return insertThreadPointerInlineAsm(IRB);
#endif
    }

    if (unlikely(CmdlinePinnedEnvGlbs.test(glb))) {
      llvm::LoadInst *LI = IRB.CreateLoad(CPUStateGlobalPointer(glb));
      LI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
      return LI;
    }

    llvm::AllocaInst *&Ptr = GlobalAllocaArr.at(glb);
    if (!Ptr) {
      llvm::IRBuilderTy tmpIRB(&f.F->getEntryBlock().front());

      Ptr = CreateAllocaForGlobal(tmpIRB, glb);
    }

    llvm::LoadInst *LI = IRB.CreateLoad(Ptr);
    LI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
    return LI;
  };

  const uintptr_t Addr = ICFG[bb].Addr;
  const unsigned Size = ICFG[bb].Size;

  if (opts::Trace) {
    binary_index_t BIdx = BinaryIndex;

    boost::property_map<interprocedural_control_flow_graph_t,
                        boost::vertex_index_t>::type bb_idx_map =
        boost::get(boost::vertex_index, ICFG);

    basic_block_index_t BBIdx = bb_idx_map[bb];

    static_assert(sizeof(BIdx) == sizeof(uint32_t), "sizeof(BIdx)");
    static_assert(sizeof(BBIdx) == sizeof(uint32_t), "sizeof(BBIdx)");

    uint64_t comb =
        (static_cast<uint64_t>(BIdx) << 32) | static_cast<uint64_t>(BBIdx);

    llvm::LoadInst *PtrLoad = IRB.CreateLoad(TraceGlobal, true /* Volatile */);
    llvm::Value *PtrInc = IRB.CreateConstGEP1_64(PtrLoad, 1);

    PtrLoad->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);

    {
      llvm::StoreInst *SI =
          IRB.CreateStore(PtrInc, TraceGlobal, true /* Volatile */);

      SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
    }

    {
      llvm::StoreInst *SI =
          IRB.CreateStore(IRB.getInt64(comb), PtrLoad, true /* Volatile */);

      SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
    }
  }

  TCG->set_elf(llvm::cast<ELFO>(Binary.ObjectFile.get())->getELFFile());

  llvm::BasicBlock *ExitBB = nullptr;

  TCGContext *s = &TCG->_ctx;

  unsigned size = 0;
  jove::terminator_info_t T;
  unsigned j = 0;
  do {
    ExitBB = llvm::BasicBlock::Create(
        *Context, (fmt("%#lx_%u_exit") % Addr % j).str(), f.F);
    ++j;

    unsigned len;
    std::tie(len, T) = TCG->translate(Addr + size, Addr + Size);

    TempAllocaVec.resize(s->nb_temps);
    LabelVec.resize(s->nb_labels);

    std::fill(TempAllocaVec.begin(),
              TempAllocaVec.end(),
              nullptr);

    std::fill(LabelVec.begin(),
              LabelVec.end(),
              nullptr);

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

          {
            llvm::IRBuilderTy tmpIRB(&f.F->getEntryBlock().front());

            TempAllocaVec.at(idx) =
              tmpIRB.CreateAlloca(tmpIRB.getIntNTy(bitsOfTCGType(ts->type)), 0,
                                  (fmt("%#lx_%s%u")
                                   % ICFG[bb].Addr
                                   % (ts->temp_local ? "loc" : "tmp")
                                   % (idx - tcg_num_globals)).str());
          }
        }

        for (int i = 0; i < nb_oargs; ++i) {
          TCGTemp *ts = arg_temp(op->args[i]);
          if (ts->temp_global)
            continue;

          unsigned idx = temp_idx(ts);
          if (TempAllocaVec.at(idx))
            continue;

          {
            llvm::IRBuilderTy tmpIRB(&f.F->getEntryBlock().front());

            TempAllocaVec.at(idx) =
              tmpIRB.CreateAlloca(tmpIRB.getIntNTy(bitsOfTCGType(ts->type)), 0,
                              (fmt("%#lx_%s%u")
                               % ICFG[bb].Addr
                               % (ts->temp_local ? "loc" : "tmp")
                               % (idx - tcg_num_globals)).str());
          }
        }
      }
    }

    //
    // create label basic blocks up-front
    //
    for (unsigned i = 0; i < LabelVec.size(); ++i)
      LabelVec[i] = llvm::BasicBlock::Create(
          *Context, (boost::format("%#lx_L%u") % ICFG[bb].Addr % i).str(), f.F);

    if (opts::DumpTCG) {
      if (Addr == std::stoi(opts::ForAddr.c_str(), nullptr, 16))
        TCG->dump_operations();
    }

    TCGOp *op, *op_next;
    QTAILQ_FOREACH_SAFE(op, &s->ops, link, op_next) {
      unsigned opc = op->opc;
      assert(opc < ARRAY_SIZE(TranslateTCGOpTable));

      if (unlikely(!seenOpTable[opc])) {
        WithColor::note() << llvm::formatv("[TCG opcode] {0}\n",
                                           tcg_op_defs[opc].name);

        seenOpTable[opc] = true;
      }

      translate_tcg_op_proc_t translate_tcg_op_proc = TranslateTCGOpTable[opc];
      if (unlikely(!translate_tcg_op_proc)) {
        WithColor::error() << llvm::formatv("[BUG] unhandled TCG opcode {0}\n", opc);
        exit(1);
      }

      int ret = translate_tcg_op_proc(op, ExitBB, IRB, TC);
      if (unlikely(ret)) {
        TCG->dump_operations();
        return ret;
      }
    }

    if (!IRB.GetInsertBlock()->getTerminator()) {
      if (opts::Verbose)
        WithColor::warning() << "TranslateBasicBlock: no terminator in block\n";
      IRB.CreateBr(ExitBB);
    }

    IRB.SetInsertPoint(ExitBB);

    size += len;
  } while (size < Size);

  if (T.Type != ICFG[bb].Term.Type) {
    uintptr_t FuncAddr = ICFG[boost::vertex(f.Entry, ICFG)].Addr;

    WithColor::error() << llvm::formatv(
        "{0}:{1} @ {2:x} (try jove-init'ing over again? this can happen when "
        "tcg.hpp is changed but we haven't gone through the trouble of "
        "re-running jove-add\n"
        "FuncAddr={3:x}\n"
        "T.Type={4}\n"
        "ICFG[bb].Term.Type={5}\n"
        "size={6}\n"
        "Size={7}\n",
        __FILE__, __LINE__,
        Addr, FuncAddr,
        description_of_terminator(T.Type),
        description_of_terminator(ICFG[bb].Term.Type),
        size,
        Size);

    if (T.Type == TERMINATOR::NONE)
      WithColor::error() << llvm::formatv("T._none.NextPC={0:x}\n",
                                          T._none.NextPC);
  }

  assert(T.Type == ICFG[bb].Term.Type);
  //assert(size == ICFG[bb].Size);

  //
  // examine terminator multiple times
  //
  if (T.Type == TERMINATOR::UNREACHABLE) {
    IRB.CreateCall(
        llvm::Intrinsic::getDeclaration(Module.get(), llvm::Intrinsic::trap));
    IRB.CreateUnreachable();
    return 0;
  }

  if (T.Type == TERMINATOR::NONE) {
    auto eit_pair = boost::out_edges(bb, ICFG);
    assert(eit_pair.first != eit_pair.second &&
           std::next(eit_pair.first) == eit_pair.second);
    control_flow_t cf = *eit_pair.first;
    basic_block_t succ = boost::target(cf, ICFG);
    IRB.CreateBr(ICFG[succ].B);
    return 0;
  }

  auto store_stack_pointer = [&](void) -> void {
    auto store_global = [&](unsigned glb) -> void {
      llvm::StoreInst *SI = IRB.CreateStore(get(glb), CPUStateGlobalPointer(glb));
      SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
    };

    store_global(tcg_stack_pointer_index);
  };

  auto reload_stack_pointer = [&](void) -> void {
    auto reload_global = [&](unsigned glb) -> void {
      llvm::LoadInst *LI = IRB.CreateLoad(CPUStateGlobalPointer(glb));
      LI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);

      set(LI, glb);
    };

    reload_global(tcg_stack_pointer_index);
  };

  struct {
    bool IsTailCall;
  } _indirect_jump;

  if (T.Type == TERMINATOR::INDIRECT_JUMP)
    _indirect_jump.IsTailCall = boost::out_degree(bb, ICFG) == 0;

  if (opts::CallStack) {
    switch (T.Type) {
    case TERMINATOR::RETURN:
      IRB.CreateStore(
          IRB.CreateConstGEP1_64(IRB.CreateLoad(CallStackGlobal), -1),
          CallStackGlobal);
      break;

    case TERMINATOR::CALL:
    case TERMINATOR::INDIRECT_CALL: {
      binary_index_t BIdx = BinaryIndex;

      boost::property_map<interprocedural_control_flow_graph_t,
                          boost::vertex_index_t>::type bb_idx_map =
          boost::get(boost::vertex_index, ICFG);

      basic_block_index_t BBIdx = bb_idx_map[bb];

      static_assert(sizeof(BIdx) == sizeof(uint32_t), "sizeof(BIdx)");
      static_assert(sizeof(BBIdx) == sizeof(uint32_t), "sizeof(BBIdx)");

      uint64_t comb =
          (static_cast<uint64_t>(BIdx) << 32) | static_cast<uint64_t>(BBIdx);

      llvm::LoadInst *Ptr = IRB.CreateLoad(CallStackGlobal);
      IRB.CreateStore(IRB.getInt64(comb), Ptr);

      IRB.CreateStore(IRB.CreateConstGEP1_64(Ptr, 1), CallStackGlobal);
      break;
    }

    default:
      break;
    }
  }

#if 1
  llvm::LoadInst *SavedCallStackP = nullptr;
  llvm::LoadInst *SavedCallStackBegin = nullptr;

  auto save_callstack_pointers = [&](void) -> void {
    if (!opts::CallStack)
      return;

    assert(!SavedCallStackP);
    assert(!SavedCallStackBegin);

    SavedCallStackP = IRB.CreateLoad(CallStackGlobal);
    SavedCallStackBegin = IRB.CreateLoad(CallStackBeginGlobal);

    assert(SavedCallStackP);
    assert(SavedCallStackBegin);
  };

  auto restore_callstack_pointers = [&](void) -> void {
    if (!opts::CallStack)
      return;

    assert(SavedCallStackP);
    assert(SavedCallStackBegin);

    IRB.CreateStore(SavedCallStackP, CallStackGlobal);
    IRB.CreateStore(SavedCallStackBegin, CallStackBeginGlobal);

    SavedCallStackP = nullptr;
    SavedCallStackBegin = nullptr;
  };
#endif

  switch (T.Type) {
  case TERMINATOR::CALL: {
    function_index_t FIdx = ICFG[bb].Term._call.Target;

    function_t &callee = Binary.Analysis.Functions.at(FIdx);

    if (opts::DFSan) {
      if (callee.PreHook) {
        assert(callee.hook);
        assert(callee.PreHookClunk);

        llvm::outs() << llvm::formatv("calling pre-hook ({0}, {1})\n",
                                      BinaryIndex,
                                      FIdx);

        const hook_t &hook = *callee.hook;

        std::vector<llvm::Value *> ArgVec;

        ArgVec.resize(hook.Args.size());
        std::transform(hook.Args.begin(),
                       hook.Args.end(),
                       ArgVec.begin(),
                       [](const hook_t::arg_info_t &info) -> llvm::Value * {
                         llvm::Type *Ty = type_of_arg_info(info);
                         return llvm::Constant::getNullValue(Ty);
                       });
        IRB.CreateCall(IRB.CreateIntToPtr(IRB.CreateLoad(callee.PreHookClunk), callee.PreHook->getType()), ArgVec);
      }
    }

    if (callee.IsABI)
      store_stack_pointer();

    std::vector<llvm::Value *> ArgVec;
    {
      std::vector<unsigned> glbv;
      ExplodeFunctionArgs(callee, glbv);

      ArgVec.resize(glbv.size());
      std::transform(glbv.begin(), glbv.end(), ArgVec.begin(),
                     [&](unsigned glb) -> llvm::Value * {
                       return get(glb);
                     });
    }

    struct {
      std::vector<llvm::Value *> SavedArgs;
    } _dfsan_hook;

    if (opts::DFSan) {
      if (callee.PreHook || callee.PostHook) {
        _dfsan_hook.SavedArgs.resize(CallConvArgArray.size());
        std::transform(
            CallConvArgArray.begin(),
            CallConvArgArray.end(),
            _dfsan_hook.SavedArgs.begin(),
            [&](unsigned glb) -> llvm::Value * { return get(glb); });
      }
    }

    if (callee.IsABI) {
      //
      // store globals which are not passed as parameters to env
      //
      tcg_global_set_t glbs(DetermineFunctionArgs(callee) & ~CallConvArgs);
      glbs.reset(tcg_stack_pointer_index);

      std::vector<unsigned> glbv;
      explode_tcg_global_set(glbv, glbs);

      for (unsigned glb : glbv) {
        llvm::StoreInst *SI = IRB.CreateStore(get(glb), CPUStateGlobalPointer(glb));
        SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
      }

      store_stack_pointer();
    }

    llvm::CallInst *Ret = IRB.CreateCall(callee.F, ArgVec);

    if (callee.PreHook || callee.PostHook) {
      llvm::MDNode *Node =
          llvm::MDNode::get(*Context, llvm::MDString::get(*Context, "1"));
      Ret->setMetadata("jove.hook", Node);
    }

    if (callee.IsABI) {
      Ret->setIsNoInline();

#if defined(TARGET_I386)
      //
      // on i386 ABIs have first three registers
      //
      for (unsigned j = 0; j < std::min<unsigned>(3, Ret->getNumArgOperands()); ++j)
        Ret->addParamAttr(j, llvm::Attribute::InReg);
#endif

      reload_stack_pointer();
    }

    if (!DetermineFunctionType(callee)->getReturnType()->isVoidTy()) {
      std::vector<unsigned> glbv;
      ExplodeFunctionRets(callee, glbv);

      if (glbv.size() == 1) {
        assert(DetermineFunctionType(callee)->getReturnType()->isIntegerTy());
        set(Ret, glbv.front());
      } else {
        for (unsigned i = 0; i < glbv.size(); ++i) {
          unsigned glb = glbv[i];

          llvm::Value *Val = IRB.CreateExtractValue(
              Ret, llvm::ArrayRef<unsigned>(i),
              (fmt("_%s_returned_from_%s_")
               % TCG->_ctx.temps[glb].name
               % callee.F->getName().str()).str());

          set(Val, glb);
        }
      }
    }

    if (callee.PostHook) {
      assert(callee.hook);
      assert(callee.PostHookClunk);

      llvm::outs() << llvm::formatv("calling post-hook ({0}, {1})\n",
                                    BinaryIndex,
                                    FIdx);

      const hook_t &hook = *callee.hook;

      //
      // prepare arguments for post hook
      //
      std::vector<llvm::Value *> HookArgVec;
      HookArgVec.resize(hook.Args.size());

      {
        unsigned SPAddend = sizeof(target_ulong);

        for (unsigned j = 0; j < hook.Args.size(); ++j) {
          const hook_t::arg_info_t &info = hook.Args[j];
          assert(is_integral_size(info.Size));

          llvm::Type *DstTy = type_of_arg_info(info);
          assert(DstTy->isIntegerTy() || DstTy->isPointerTy());
          unsigned dstBits =
              DstTy->isIntegerTy()
                  ? llvm::cast<llvm::IntegerType>(DstTy)->getBitWidth()
                  : WordBits();

          llvm::Value *ArgVal = nullptr;
          {
#if defined(TARGET_I386)
            //
            // special-case i386: cdecl means read parameters off stack
            //
            llvm::Value *SP = get(tcg_stack_pointer_index);

            ArgVal = IRB.CreateLoad(IRB.CreateIntToPtr(
                IRB.CreateAdd(SP, IRB.getIntN(WordBits(), SPAddend)),
                llvm::PointerType::get(IRB.getIntNTy(info.Size * 8), 0)));

            SPAddend += info.Size;
#else
            ArgVal = ArgVec.at(j);
#endif
          }

          HookArgVec[j] = [&](void) -> llvm::Value * {
            if (info.isPointer)
              return IRB.CreateIntToPtr(ArgVal, DstTy);

            assert(ArgVal->getType()->isIntegerTy());
            unsigned srcBits =
                llvm::cast<llvm::IntegerType>(ArgVal->getType())
                    ->getBitWidth();

            if (dstBits == srcBits)
              return ArgVal;

            if (dstBits < srcBits)
              return IRB.CreateTrunc(ArgVal, DstTy);

            assert(dstBits > srcBits);
            return IRB.CreateZExt(ArgVal, DstTy);
          }();
        }
      }

      assert(!Ret->getType()->isVoidTy());

      llvm::Value *_Ret = [&](void) -> llvm::Value * {
        llvm::Type *DstTy = type_of_arg_info(hook.Ret);

        llvm::Value* _Ret = Ret;
        if (!Ret->getType()->isIntegerTy()) {
          if (Ret->getType()->isStructTy())
            _Ret = IRB.CreateExtractValue(
                Ret, llvm::ArrayRef<unsigned>(0), "");
        }

        assert(_Ret->getType()->isIntegerTy());
        unsigned srcBits =
            llvm::cast<llvm::IntegerType>(_Ret->getType())
                ->getBitWidth();

        if (hook.Ret.isPointer)
          return IRB.CreateIntToPtr(_Ret, DstTy);

        assert(DstTy->isIntegerTy());
        unsigned dstBits =
            llvm::cast<llvm::IntegerType>(DstTy)->getBitWidth();

        if (dstBits == srcBits)
          return _Ret;

        assert(dstBits < srcBits);

        return IRB.CreateTrunc(_Ret, DstTy);
      }();

      //
      // return value is first argument
      //
      HookArgVec.insert(HookArgVec.begin(), _Ret);

      //
      // make the call
      //
      llvm::CallInst *PostHookRet = IRB.CreateCall(IRB.CreateIntToPtr(IRB.CreateLoad(callee.PostHookClunk), callee.PostHook->getType()), HookArgVec);

      //
      // make the return value from the post-hook be the return value for the call to the hooked function
      //
      set(PostHookRet->getType()->isPointerTy() ? IRB.CreatePtrToInt(PostHookRet, WordType()) : PostHookRet, CallConvRetArray.at(0));
    }

    break;
  }

  case TERMINATOR::INDIRECT_JUMP:
    //
    // if      pc == target_1 ; goto target_1
    // else if pc == target_2 ; goto target_2
    // else if pc == target_3 ; goto target_3
    //       ...
    // else if pc == target_n ; goto target_n
    // else                   ; trap
    //
    if (!_indirect_jump.IsTailCall) { /* otherwise fallthrough */
      llvm::BasicBlock *ElseBlock =
          llvm::BasicBlock::Create(*Context, "else", f.F);

      {
        llvm::Value *SectsGlobalOff = IRB.CreateSub(
            IRB.CreateLoad(TC.PCAlloca),
            llvm::ConstantExpr::getPtrToInt(SectsGlobal, WordType()));

        llvm::SwitchInst *SI = IRB.CreateSwitch(SectsGlobalOff, ElseBlock,
                                                boost::out_degree(bb, ICFG));

        auto it_pair = boost::adjacent_vertices(bb, ICFG);

        for (auto it = it_pair.first; it != it_pair.second; ++it) {
          basic_block_t succ = *it;
          SI->addCase(
              IRB.getIntN(WordBits(), ICFG[succ].Addr - Binary.SectsStartAddr),
              ICFG[succ].B);
        }
      }

      IRB.SetInsertPoint(ElseBlock);

      llvm::Value *PC = IRB.CreateLoad(TC.PCAlloca);

      boost::property_map<interprocedural_control_flow_graph_t,
                          boost::vertex_index_t>::type bb_idx_map =
          boost::get(boost::vertex_index, ICFG);

      llvm::Value *RecoverArgs[] = {IRB.getInt32(bb_idx_map[bb]), PC};
      llvm::Value *FailArgs[] = {
          PC, IRB.CreateGlobalStringPtr("unknown branch target")
      };

      IRB.CreateCall(JoveRecoverBasicBlockFunc, RecoverArgs)->setIsNoInline();
      IRB.CreateCall(JoveRecoverDynTargetFunc, RecoverArgs)->setIsNoInline();
      IRB.CreateCall(JoveFail1Func, FailArgs)->setIsNoInline();
      IRB.CreateUnreachable();
      break;
    }

  case TERMINATOR::INDIRECT_CALL: {
    bool IsCall = T.Type == TERMINATOR::INDIRECT_CALL;
    const auto &DynTargets = ICFG[bb].DynTargets;
    const bool &DynTargetsComplete = ICFG[bb].DynTargetsComplete;

    if (DynTargets.empty()) {
      llvm::Value *PC = IRB.CreateLoad(TC.PCAlloca);

      if (!IsCall && ICFG[bb].Term._indirect_jump.IsLj) {
        IRB.CreateCall(JoveFail1Func, {PC, IRB.CreateGlobalStringPtr("longjmp encountered")})->setIsNoInline();
        IRB.CreateUnreachable();
      } else {
        if (opts::Verbose)
          WithColor::warning() << llvm::formatv(
              "indirect control transfer @ {0:x} has zero dyn targets\n",
              ICFG[bb].Addr);

        boost::property_map<interprocedural_control_flow_graph_t,
                            boost::vertex_index_t>::type bb_idx_map =
            boost::get(boost::vertex_index, ICFG);

        llvm::Value *RecoverArgs[] = {IRB.getInt32(bb_idx_map[bb]), PC};

        IRB.CreateCall(JoveRecoverDynTargetFunc, RecoverArgs)->setIsNoInline();
        if (!IsCall)
          IRB.CreateCall(JoveRecoverBasicBlockFunc, RecoverArgs)->setIsNoInline();
        IRB.CreateCall(JoveRecoverFunctionFunc, RecoverArgs)->setIsNoInline();
        IRB.CreateCall(JoveFail1Func, {PC, IRB.CreateGlobalStringPtr("unknown callee")})->setIsNoInline();
        IRB.CreateUnreachable();
      }

      return 0;
    }

    {
      assert(!DynTargets.empty());

      llvm::Value *PC = IRB.CreateLoad(TC.PCAlloca);

      llvm::BasicBlock *ThruB = llvm::BasicBlock::Create(*Context, "", f.F);

      std::vector<std::pair<binary_index_t, function_index_t>> DynTargetsVec(
          DynTargets.begin(), DynTargets.end());

      std::vector<llvm::BasicBlock *> DynTargetsDoCallBVec;
      DynTargetsDoCallBVec.resize(DynTargetsVec.size());

      std::transform(DynTargetsVec.begin(),
                     DynTargetsVec.end(),
                     DynTargetsDoCallBVec.begin(),
                     [&](dynamic_target_t IdxPair) -> llvm::BasicBlock * {
                       return llvm::BasicBlock::Create(*Context,
                                                       (fmt("call_%s") % dyn_target_desc(IdxPair)).str(), f.F);
                     });

      llvm::BasicBlock *ElseB = nullptr;
      {
        unsigned i = 0;

        llvm::BasicBlock *B = llvm::BasicBlock::Create(
            *Context, (fmt("if %s") % dyn_target_desc(DynTargetsVec[i])).str(),
            f.F);
        IRB.CreateBr(B);

        do {
          IRB.SetInsertPoint(B);

          auto next_i = i + 1;
          if (next_i == DynTargetsVec.size())
            B = llvm::BasicBlock::Create(*Context, "else", f.F);
          else
            B = llvm::BasicBlock::Create(
                *Context,
                (fmt("if %s") % dyn_target_desc(DynTargetsVec[next_i])).str(),
                f.F);

#if 0
          llvm::Value *EQVal = IRB.CreateICmpEQ(
              PC, GetDynTargetAddress<false>(IRB, DynTargetsVec[i], B));
          IRB.CreateCondBr(EQVal, DynTargetsDoCallBVec[i], B);
#else
          llvm::Value *EQV_1 = IRB.CreateICmpEQ(
              PC, GetDynTargetAddress<false>(IRB, DynTargetsVec[i], B));
          llvm::Value *EQV_2 = IRB.CreateICmpEQ(
              PC, GetDynTargetAddress<true>(IRB, DynTargetsVec[i], B));

          IRB.CreateCondBr(IRB.CreateOr(EQV_1, EQV_2), DynTargetsDoCallBVec[i], B);
#endif
        } while (++i != DynTargetsVec.size());

        ElseB = B;
      }

      assert(ElseB);

      {
        IRB.SetInsertPoint(ElseB);

        boost::property_map<interprocedural_control_flow_graph_t,
                            boost::vertex_index_t>::type bb_idx_map =
            boost::get(boost::vertex_index, ICFG);
        llvm::Value *RecoverArgs[] = {IRB.getInt32(bb_idx_map[bb]), PC};
        llvm::Value *FailArgs[] = {PC, IRB.CreateGlobalStringPtr("unknown callee")};

        IRB.CreateCall(JoveRecoverDynTargetFunc, RecoverArgs)->setIsNoInline();
        IRB.CreateCall(JoveRecoverFunctionFunc, RecoverArgs)->setIsNoInline();
        IRB.CreateCall(JoveFail1Func, FailArgs)->setIsNoInline();
        IRB.CreateUnreachable();
      }

      for (unsigned i = 0; i < DynTargetsVec.size(); ++i) {
        llvm::BasicBlock *DoCallB = DynTargetsDoCallBVec[i];
        {
          IRB.SetInsertPoint(DoCallB);

          struct {
            binary_index_t BIdx;
            function_index_t FIdx;
          } ADynTarget;

          std::tie(ADynTarget.BIdx, ADynTarget.FIdx) = DynTargetsVec[i];

          bool foreign = DynTargetNeedsThunkPred(DynTargetsVec[i]);

          function_t &callee = Decompilation.Binaries.at(ADynTarget.BIdx)
                                  .Analysis.Functions.at(ADynTarget.FIdx);

          struct {
            std::vector<llvm::Value *> SavedArgs;
          } _dfsan_hook;

          if (opts::DFSan) {
            if (callee.PreHook || callee.PostHook) {
              function_t &hook_f = Decompilation.Binaries.at(ADynTarget.BIdx)
                                      .Analysis.Functions.at(ADynTarget.FIdx);
              assert(hook_f.hook);
              const hook_t &hook = *hook_f.hook;

#if 0
              llvm::outs() << llvm::formatv("calling post-hook ({0}, {1})\n", (*it).first, (*it).second);
#endif

              _dfsan_hook.SavedArgs.resize(CallConvArgArray.size());
              std::transform(
                  CallConvArgArray.begin(),
                  CallConvArgArray.end(),
                  _dfsan_hook.SavedArgs.begin(),
                  [&](unsigned glb) -> llvm::Value * { return get(glb); });
            }
          }

          if (opts::DFSan) {
            if (callee.PreHook) {
              assert(callee.hook);
              assert(callee.PreHookClunk);

              llvm::outs() << llvm::formatv("calling pre-hook ({0}, {1})\n",
                                            ADynTarget.BIdx, ADynTarget.FIdx);

              const hook_t &hook = *callee.hook;

              //
              // prepare arguments for post hook
              //
              std::vector<llvm::Value *> HookArgVec;
              HookArgVec.resize(hook.Args.size());

              {
                unsigned SPAddend = sizeof(target_ulong);

                for (unsigned j = 0; j < hook.Args.size(); ++j) {
                  const hook_t::arg_info_t &info = hook.Args[j];
                  assert(is_integral_size(info.Size));

                  llvm::Type *DstTy = type_of_arg_info(info);
                  assert(DstTy->isIntegerTy() || DstTy->isPointerTy());
                  unsigned dstBits =
                      DstTy->isIntegerTy()
                          ? llvm::cast<llvm::IntegerType>(DstTy)->getBitWidth()
                          : WordBits();

                  llvm::Value *ArgVal = nullptr;
                  {
#if defined(TARGET_I386)
                    //
                    // special-case i386: cdecl means read parameters off stack
                    //
                    llvm::Value *SP = get(tcg_stack_pointer_index);

                    ArgVal = IRB.CreateLoad(IRB.CreateIntToPtr(
                        IRB.CreateAdd(SP, IRB.getIntN(WordBits(), SPAddend)),
                        llvm::PointerType::get(IRB.getIntNTy(info.Size * 8), 0)));

                    SPAddend += info.Size;
#else
                    ArgVal = _dfsan_hook.SavedArgs.at(j);
#endif
                  }

                  HookArgVec[j] = [&](void) -> llvm::Value * {
                    if (info.isPointer)
                      return IRB.CreateIntToPtr(ArgVal, DstTy);

                    assert(ArgVal->getType()->isIntegerTy());
                    unsigned srcBits =
                        llvm::cast<llvm::IntegerType>(ArgVal->getType())
                            ->getBitWidth();

                    if (dstBits == srcBits)
                      return ArgVal;

                    if (dstBits < srcBits)
                      return IRB.CreateTrunc(ArgVal, DstTy);

                    assert(dstBits > srcBits);
                    return IRB.CreateZExt(ArgVal, DstTy);
                  }();
                }
              }

              //
              // make the call
              //
              IRB.CreateCall(
                  IRB.CreateIntToPtr(IRB.CreateLoad(callee.PreHookClunk),
                                     callee.PreHook->getType()),
                  HookArgVec);
            }
          }

          llvm::CallInst *Ret;
          if (foreign) {
            store_stack_pointer();

            //
            // callstack stuff
            //
            save_callstack_pointers();

            {
              std::vector<llvm::Value *> ArgVec;

              std::vector<unsigned> glbv;
              ExplodeFunctionArgs(callee, glbv);

              ArgVec.resize(glbv.size());
              std::transform(glbv.begin(),
                             glbv.end(),
                             ArgVec.begin(),
                             [&](unsigned glb) -> llvm::Value * {
                               return get(glb);
                             });

              ArgVec.push_back(GetDynTargetAddress<true>(IRB, DynTargetsVec[i]));
              ArgVec.push_back(CPUStateGlobalPointer(tcg_stack_pointer_index));

              llvm::Function *const JoveThunkFuncArray[] = {
#define __THUNK(n, i, data) JoveThunk##i##Func,

#if defined(TARGET_X86_64)
BOOST_PP_REPEAT(7, __THUNK, void)
#elif defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
BOOST_PP_REPEAT(5, __THUNK, void)
#elif defined(TARGET_I386)
BOOST_PP_REPEAT(4, __THUNK, void)
#elif defined(TARGET_AARCH64)
BOOST_PP_REPEAT(9, __THUNK, void)
#else
#error
#endif

#undef __THUNK
              };

              assert(glbv.size() < ARRAY_SIZE(JoveThunkFuncArray));

              llvm::Value *ThunkF = JoveThunkFuncArray[glbv.size()];
#if defined(TARGET_AARCH64)
              {
                llvm::StructType *ResultType;
                {
                  std::vector<llvm::Type *> structRetTypes;
                  structRetTypes.resize(CallConvRetArray.size());

                  std::transform(CallConvRetArray.begin(),
                                 CallConvRetArray.end(),
                                 structRetTypes.begin(),
                                 [&](unsigned glb) -> llvm::Type * {
                                   return IRB.getInt64Ty();
                                 });

                  ResultType = llvm::StructType::get(*Context, structRetTypes);
                }

                assert(llvm::isa<llvm::Function>(ThunkF));
                llvm::FunctionType *ThunkFTy = llvm::cast<llvm::Function>(ThunkF)->getFunctionType();
                llvm::PointerType *CastFTy = llvm::FunctionType::get(ResultType, ThunkFTy->params(), false)->getPointerTo();

                ThunkF = IRB.CreatePointerCast(ThunkF, CastFTy);
              }
#endif

              Ret = IRB.CreateCall(ThunkF, ArgVec);
              Ret->setIsNoInline();
            }

#if defined(TARGET_I386)
            //
            // on i386 ABIs have first three registers
            //
            for (unsigned j = 0; j < std::min<unsigned>(3, Ret->getNumArgOperands()); ++j)
              Ret->addParamAttr(j, llvm::Attribute::InReg);
#endif

            //
            // callstack stuff
            //
            restore_callstack_pointers();
            reload_stack_pointer();

            if (opts::CallStack)
              IRB.CreateStore(
                  IRB.CreateConstGEP1_64(IRB.CreateLoad(CallStackGlobal), -1),
                  CallStackGlobal);
          } else {
            std::vector<llvm::Value *> ArgVec;
            {
              std::vector<unsigned> glbv;
              ExplodeFunctionArgs(callee, glbv);

              ArgVec.resize(glbv.size());
              std::transform(glbv.begin(), glbv.end(), ArgVec.begin(),
                             [&](unsigned glb) -> llvm::Value * {
                               return get(glb);
                             });
            }

            if (callee.IsABI) {
              //
              // store globals which are not passed as parameters to env
              //
              tcg_global_set_t glbs(DetermineFunctionArgs(callee) & ~CallConvArgs);
              glbs.reset(tcg_stack_pointer_index);

              std::vector<unsigned> glbv;
              explode_tcg_global_set(glbv, glbs);

              for (unsigned glb : glbv) {
                llvm::StoreInst *SI = IRB.CreateStore(get(glb), CPUStateGlobalPointer(glb));
                SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
              }

              store_stack_pointer();
            }

            Ret = IRB.CreateCall(
                IRB.CreateIntToPtr(
                    GetDynTargetAddress<true>(IRB, DynTargetsVec[i]),
                    llvm::PointerType::get(DetermineFunctionType(callee), 0)),
                ArgVec);

            if (callee.IsABI) {
#if defined(TARGET_I386)
              //
              // on i386 ABIs have first three registers
              //
              for (unsigned j = 0; j < std::min<unsigned>(3, Ret->getNumArgOperands()); ++j)
                Ret->addParamAttr(j, llvm::Attribute::InReg);
#endif

              reload_stack_pointer();
            }
          }

          if (callee.PreHook || callee.PostHook) {
            llvm::MDNode *Node =
                llvm::MDNode::get(*Context, llvm::MDString::get(*Context, "1"));
            Ret->setMetadata("jove.hook", Node);
          }

          //Ret->setCallingConv(llvm::CallingConv::C);

#if 0
          llvm::MDNode *JoveNode = llvm::MDNode::get(
              *Context, llvm::MDString::get(*Context, std::to_string(1)));
          Ret->setMetadata("jove", JoveNode);
#endif

          if (foreign) {
#if defined(TARGET_X86_64)
            //assert(Ret->getType()->isIntegerTy(128));
            assert(Ret->getType()->isStructTy());
            {
              llvm::Value *X = IRB.CreateExtractValue(Ret, 0, (fmt("_%s_returned") % TCG->_ctx.temps[CallConvRetArray.at(0)].name).str());
              llvm::Value *Y = IRB.CreateExtractValue(Ret, 1, (fmt("_%s_returned") % TCG->_ctx.temps[CallConvRetArray.at(1)].name).str());

              set(X, CallConvRetArray.at(0));
              set(Y, CallConvRetArray.at(1));
            }
#elif defined(TARGET_MIPS64)
            assert(Ret->getType()->isIntegerTy(64));
            set(Ret, CallConvRetArray.front());
#elif defined(TARGET_AARCH64)
            assert(Ret->getType()->isStructTy());

            for (unsigned j = 0; j < CallConvRetArray.size(); ++j) {
              llvm::Value *X = IRB.CreateExtractValue(Ret, j,
                  (fmt("_%s_returned") % TCG->_ctx.temps[CallConvRetArray.at(j)].name).str());
              set(X, CallConvRetArray.at(j));
            }
#elif defined(TARGET_MIPS32) || defined(TARGET_I386)
            assert(Ret->getType()->isIntegerTy(64));
            {
              llvm::Value *X = IRB.CreateTrunc(Ret, IRB.getInt32Ty(),
                  (fmt("_%s_returned") % TCG->_ctx.temps[CallConvRetArray.at(0)].name).str());

              llvm::Value *Y = IRB.CreateTrunc(IRB.CreateLShr(Ret, IRB.getInt64(32)), IRB.getInt32Ty(),
                  (fmt("_%s_returned") % TCG->_ctx.temps[CallConvRetArray.at(1)].name).str());

              set(X, CallConvRetArray.at(0));
              set(Y, CallConvRetArray.at(1));
            }
#else
#error
#endif
          } else {
            if (!DetermineFunctionType(callee)->getReturnType()->isVoidTy()) {
              std::vector<unsigned> glbv;
              ExplodeFunctionRets(callee, glbv);

              assert(glbv.size() > 0);

              if (Ret->getType()->isIntegerTy(WordBits())) {
                assert(glbv.size() == 1);
                set(Ret, glbv.front());
              } else {
                assert(glbv.size() > 1);
                assert(DetermineFunctionType(callee)->getReturnType()->isStructTy());

                for (unsigned i = 0; i < glbv.size(); ++i) {
                  unsigned glb = glbv[i];

                  llvm::Value *Val = IRB.CreateExtractValue(
                      Ret, llvm::ArrayRef<unsigned>(i),
                      (fmt("_%s_returned") % TCG->_ctx.temps[glb].name).str());

                  set(Val, glb);
                }
              }
            }
          }

          if (callee.PostHook) {
            assert(callee.hook);
            assert(callee.PostHookClunk);

            llvm::outs() << llvm::formatv("calling post-hook ({0}, {1})\n",
                                          ADynTarget.BIdx, ADynTarget.FIdx);

            const hook_t &hook = *callee.hook;

            //
            // prepare arguments for post hook
            //
            std::vector<llvm::Value *> HookArgVec;
            HookArgVec.resize(hook.Args.size());

            {
              unsigned SPAddend = sizeof(target_ulong);

              for (unsigned j = 0; j < hook.Args.size(); ++j) {
                const hook_t::arg_info_t &info = hook.Args[j];
                assert(is_integral_size(info.Size));

                llvm::Type *DstTy = type_of_arg_info(info);
                assert(DstTy->isIntegerTy() || DstTy->isPointerTy());
                unsigned dstBits =
                    DstTy->isIntegerTy()
                        ? llvm::cast<llvm::IntegerType>(DstTy)->getBitWidth()
                        : WordBits();

                llvm::Value *ArgVal = nullptr;
                {
#if defined(TARGET_I386)
                  //
                  // special-case i386: cdecl means read parameters off stack
                  //
                  llvm::Value *SP = get(tcg_stack_pointer_index);

                  ArgVal = IRB.CreateLoad(IRB.CreateIntToPtr(
                      IRB.CreateAdd(SP, IRB.getIntN(WordBits(), SPAddend)),
                      llvm::PointerType::get(IRB.getIntNTy(info.Size * 8),
                                             0)));

                  SPAddend += info.Size;
#else
                  ArgVal = _dfsan_hook.SavedArgs.at(j);
#endif
                }

                HookArgVec[j] = [&](void) -> llvm::Value * {
                  if (info.isPointer)
                    return IRB.CreateIntToPtr(ArgVal, DstTy);

                  assert(ArgVal->getType()->isIntegerTy());
                  unsigned srcBits =
                      llvm::cast<llvm::IntegerType>(ArgVal->getType())
                          ->getBitWidth();

                  if (dstBits == srcBits)
                    return ArgVal;

                  if (dstBits < srcBits)
                    return IRB.CreateTrunc(ArgVal, DstTy);

                  assert(dstBits > srcBits);
                  return IRB.CreateZExt(ArgVal, DstTy);
                }();
              }
            }

            llvm::Value *_Ret = nullptr;
            if (Ret->getType()->isVoidTy()) {
              WARN();
              _Ret = llvm::Constant::getNullValue(type_of_arg_info(hook.Ret));
            } else {
              _Ret = [&](void) -> llvm::Value * {
                llvm::Type *DstTy = type_of_arg_info(hook.Ret);

                llvm::Value* _Ret = Ret;
                if (!Ret->getType()->isIntegerTy()) {
                  if (Ret->getType()->isStructTy())
                    _Ret = IRB.CreateExtractValue(
                        Ret, llvm::ArrayRef<unsigned>(0), "");
                }

                assert(_Ret->getType()->isIntegerTy());
                unsigned srcBits =
                    llvm::cast<llvm::IntegerType>(_Ret->getType())
                        ->getBitWidth();

                if (hook.Ret.isPointer)
                  return IRB.CreateIntToPtr(_Ret, DstTy);

                assert(DstTy->isIntegerTy());
                unsigned dstBits =
                    llvm::cast<llvm::IntegerType>(DstTy)->getBitWidth();

                if (dstBits == srcBits)
                  return _Ret;

                assert(dstBits < srcBits);

                return IRB.CreateTrunc(_Ret, DstTy);
              }();
            }

            //
            // return value is first argument
            //
            HookArgVec.insert(HookArgVec.begin(), _Ret);

            //
            // make the call
            //
            IRB.CreateCall(
                IRB.CreateIntToPtr(IRB.CreateLoad(callee.PostHookClunk),
                                   callee.PostHook->getType()),
                HookArgVec);
          }

          IRB.CreateBr(ThruB);
        }
      }

      IRB.SetInsertPoint(ThruB);
    }

    break;
  }

  default:
    break;
  }

  if (T.Type == TERMINATOR::RETURN && opts::CheckEmulatedReturnAddress) {
    assert(JoveCheckReturnAddrFunc);

    llvm::Value *NativeRetAddr =
        IRB.CreateCall(llvm::Intrinsic::getDeclaration(
                           Module.get(), llvm::Intrinsic::returnaddress),
                       IRB.getInt32(0));

#if defined(TARGET_X86_64) || defined(TARGET_I386)
    llvm::Value *Args[] = {IRB.CreateLoad(TC.PCAlloca),
                           IRB.CreatePtrToInt(NativeRetAddr, WordType())};

    IRB.CreateCall(JoveCheckReturnAddrFunc, Args);
#elif defined(TARGET_MIPS32)
    llvm::Value *Args[] = {get(tcg_btarget_index), /* XXX why? */
                           IRB.CreatePtrToInt(NativeRetAddr, WordType())};

    IRB.CreateCall(JoveCheckReturnAddrFunc, Args);
#else
    // TODO
#endif
  }

  switch (T.Type) {
  case TERMINATOR::CONDITIONAL_JUMP: {
    auto eit_pair = boost::out_edges(bb, ICFG);

    assert(boost::out_degree(bb, ICFG) == 2 ||
           boost::out_degree(bb, ICFG) == 1);

    bool is1 = boost::out_degree(bb, ICFG) == 1;

    control_flow_t cf1 = *eit_pair.first;
    control_flow_t cf2 = is1 ? cf1 : *std::next(eit_pair.first);

    basic_block_t succ1 = boost::target(cf1, ICFG);
    basic_block_t succ2 = boost::target(cf2, ICFG);

    llvm::Value *PC = IRB.CreateLoad(TC.PCAlloca);
    llvm::Value *EQV = IRB.CreateICmpEQ(
        PC, IRB.getIntN(WordBits(), ICFG[succ1].Addr));
    IRB.CreateCondBr(EQV, ICFG[succ1].B, ICFG[succ2].B);
    break;
  }

  case TERMINATOR::CALL:
  case TERMINATOR::INDIRECT_CALL: {
    auto eit_pair = boost::out_edges(bb, ICFG);
    if (eit_pair.first == eit_pair.second) { /* otherwise fallthrough */
      boost::property_map<interprocedural_control_flow_graph_t,
                          boost::vertex_index_t>::type bb_idx_map =
          boost::get(boost::vertex_index, ICFG);

      basic_block_index_t BBIdx = bb_idx_map[bb];

      IRB.CreateCall(JoveRecoverReturnedFunc, IRB.getInt32(BBIdx))->setIsNoInline();
      IRB.CreateCall(
          llvm::Intrinsic::getDeclaration(Module.get(), llvm::Intrinsic::trap));
      IRB.CreateUnreachable();
      break;
    }
  }

  case TERMINATOR::UNCONDITIONAL_JUMP: {
    auto eit_pair = boost::out_edges(bb, ICFG);
    assert(eit_pair.first != eit_pair.second &&
           std::next(eit_pair.first) == eit_pair.second);
    control_flow_t cf = *eit_pair.first;
    basic_block_t succ = boost::target(cf, ICFG);
    IRB.CreateBr(ICFG[succ].B);
    break;
  }

  case TERMINATOR::INDIRECT_JUMP:
    if (!_indirect_jump.IsTailCall) /* otherwise fallthrough */
      break;

  case TERMINATOR::RETURN: {
    if (opts::DFSan && false /* opts::Paranoid */)
      IRB.CreateCall(IRB.CreateIntToPtr(
          IRB.CreateLoad(DFSanFiniClunk),
          DFSanFiniFunc->getType())); /* flush the log file */

    if (f.IsABI)
      store_stack_pointer();

    if (DetermineFunctionType(f)->getReturnType()->isVoidTy()) {
      IRB.CreateRetVoid();
      break;
    }

    std::vector<unsigned> glbv;
    ExplodeFunctionRets(f, glbv);

    if (DetermineFunctionType(f)->getReturnType()->isIntegerTy()) {
      assert(glbv.size() == 1);
      IRB.CreateRet(get(glbv.front()));
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
            std::string nm =
                (fmt("_returning_%s_") % TCG->_ctx.temps[glb].name).str();

            return IRB.CreateInsertValue(res,
                                         get(glb),
                                         llvm::ArrayRef<unsigned>(idx++),
                                         nm);
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

llvm::Value *insertThreadPointerInlineAsm(llvm::IRBuilderTy &IRB) {
  llvm::InlineAsm *IA;
  {
    llvm::FunctionType *AsmFTy =
        llvm::FunctionType::get(WordType(), false);

    llvm::StringRef AsmText;
    llvm::StringRef Constraints;

    // TODO replace with thread pointer intrinsic
#if defined(TARGET_X86_64)
    AsmText = "movq \%fs:0x0,$0";
    Constraints = "=r";
#elif defined(TARGET_I386)
    AsmText = "movl \%gs:0x0,$0";
    Constraints = "=r";
#elif defined(TARGET_AARCH64)
    AsmText = "mrs $0, tpidr_el0";
    Constraints = "=r";
#elif defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
    AsmText = "rdhwr $0, $$29";
    Constraints = "=r,~{$1}";
#else
#error
#endif

    IA = llvm::InlineAsm::get(AsmFTy, AsmText, Constraints,
                              false /* hasSideEffects */);
  }

  return IRB.CreateCall(IA);
}

std::string dyn_target_desc(dynamic_target_t IdxPair) {
  struct {
    binary_index_t BIdx;
    function_index_t FIdx;
  } DynTarget;

  std::tie(DynTarget.BIdx, DynTarget.FIdx) = IdxPair;

  binary_t &b = Decompilation.Binaries[DynTarget.BIdx];
  function_t &f = b.Analysis.Functions[DynTarget.FIdx];

  target_ulong Addr =
      b.Analysis.ICFG[boost::vertex(f.Entry, b.Analysis.ICFG)].Addr;

  return (fmt("%s+%#lx") % fs::path(b.Path).filename().string() % Addr).str();
}

static const unsigned bits_of_memop_lookup_table[] = {8, 16, 32, 64};

static unsigned bits_of_memop(MemOp op) {
  return bits_of_memop_lookup_table[op & MO_SIZE];
}

static bool pcrel_flag = false; /* XXX this is ugly, but it works */

template <unsigned opc>
static int TranslateTCGOp(TCGOp *op,
                          llvm::BasicBlock *ExitBB,
                          llvm::IRBuilderTy &IRB,
                          TranslateContext &TC) {
  function_t &f = TC.f;
  basic_block_t bb = TC.bb;
  auto &GlobalAllocaArr = TC.GlobalAllocaArr;
  auto &TempAllocaVec = TC.TempAllocaVec;
  auto &LabelVec = TC.LabelVec;

  binary_t &Binary = Decompilation.Binaries[BinaryIndex];
  const auto &ICFG = Binary.Analysis.ICFG;
  auto &PCAlloca = TC.PCAlloca;
  TCGContext *s = &TCG->_ctx;

  auto set = [&](llvm::Value *V, TCGTemp *ts) -> void {
    unsigned idx = temp_idx(ts);

    if (ts->temp_global) {
      assert(idx != tcg_env_index);

      if (unlikely(CmdlinePinnedEnvGlbs.test(idx))) {
        llvm::StoreInst *SI = IRB.CreateStore(V, CPUStateGlobalPointer(idx));
        SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
        return;
      }

      llvm::AllocaInst *&Ptr = GlobalAllocaArr.at(idx);
      if (!Ptr) {
        llvm::IRBuilderTy tmpIRB(&f.F->getEntryBlock().front());

        Ptr = CreateAllocaForGlobal(tmpIRB, idx);
      }

      llvm::StoreInst *SI = IRB.CreateStore(V, Ptr);
      SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
    } else {
      llvm::AllocaInst *Ptr = TempAllocaVec.at(idx);
      assert(Ptr);

      llvm::StoreInst *SI = IRB.CreateStore(V, Ptr);
      SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
    }
  };

  auto get = [&](TCGTemp *ts) -> llvm::Value * {
    unsigned idx = temp_idx(ts);

    if (ts->temp_global) {
      switch (idx) {
      case tcg_env_index:
        return llvm::ConstantExpr::getPtrToInt(CPUStateGlobal, WordType());
#if defined(TARGET_X86_64)
      case tcg_fs_base_index:
        return insertThreadPointerInlineAsm(IRB);
#elif defined(TARGET_I386)
      case tcg_gs_base_index:
        return insertThreadPointerInlineAsm(IRB);
#endif
      }

      if (unlikely(CmdlinePinnedEnvGlbs.test(idx))) {
        llvm::LoadInst *LI = IRB.CreateLoad(CPUStateGlobalPointer(idx));
        LI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
        return LI;
      }

      llvm::AllocaInst *&Ptr = GlobalAllocaArr.at(idx);
      if (!Ptr) {
        llvm::IRBuilderTy tmpIRB(&f.F->getEntryBlock().front());

        Ptr = CreateAllocaForGlobal(tmpIRB, idx);
      }

      llvm::LoadInst *LI = IRB.CreateLoad(Ptr);
      LI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
      return LI;
    } else {
      llvm::AllocaInst *Ptr = TempAllocaVec.at(idx);
      assert(Ptr);

      llvm::LoadInst *LI = IRB.CreateLoad(Ptr);
      LI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
      return LI;
    }
  };

  auto immediate_constant = [&](unsigned bits, TCGArg A) -> llvm::Value * {
    if (!pcrel_flag)
      return llvm::ConstantInt::get(llvm::Type::getIntNTy(*Context, bits), A);

    pcrel_flag = false; /* reset pcrel flag */
    assert(bits == WordBits());

    return llvm::ConstantExpr::getAdd(
        llvm::ConstantExpr::getPtrToInt(SectsGlobal, WordType()),
        llvm::ConstantExpr::getSub(
            llvm::ConstantInt::get(WordType(), A),
            llvm::ConstantInt::get(WordType(), Binary.SectsStartAddr)));
  };

  if (opc >= ARRAY_SIZE(tcg_op_defs))
    return 1;

  const TCGOpDef &def = tcg_op_defs[opc];

  int nb_oargs = def.nb_oargs;
  int nb_iargs = def.nb_iargs;
  int nb_cargs = def.nb_cargs;

  switch (opc) {
  case INDEX_op_insn_start:
    static uint64_t lstaddr = 0;
    static unsigned NextLine = 0;

    if (op->args[0] == JOVE_PCREL_MAGIC && op->args[1] == JOVE_PCREL_MAGIC) {
      pcrel_flag = true;

      if (opts::PrintPCRel)
        WithColor::note() << "PC-relative expression @ "
                          << (fmt("%#lx") % lstaddr).str() << '\n';
    } else {
      pcrel_flag = false;

      uint64_t Addr = op->args[0];
      assert(Addr < UINT32_MAX);

      lstaddr = Addr;

      unsigned Line = Addr;

      IRB.SetCurrentDebugLocation(llvm::DILocation::get(
          *Context, Line, 0 /* Column */, TC.DebugInformation.Subprogram));
    }
    break;

  case INDEX_op_discard: {
#if 0
    TCGTemp *dst = arg_temp(op->args[0]);
    unsigned idx = temp_idx(dst);

    llvm::Type *Ty = IRB.getIntNTy(bitsOfTCGType(TCG->_ctx.temps[idx].type));
    //set(llvm::UndefValue::get(Ty), dst);
    set(llvm::Constant::getNullValue(Ty), dst);
#endif
    break;
  }

  case INDEX_op_goto_tb:
    break;

  case INDEX_op_set_label: {
    llvm::BasicBlock* lblB = LabelVec.at(arg_label(op->args[0])->id);
    assert(lblB);

    if (!IRB.GetInsertBlock()->getTerminator())
      IRB.CreateBr(lblB);

    IRB.SetInsertPoint(lblB);
    break;
  }

  case INDEX_op_goto_ptr:
  case INDEX_op_exit_tb:
    assert(ExitBB);
    IRB.CreateBr(ExitBB);
    break;

  case INDEX_op_call: {
    nb_oargs = TCGOP_CALLO(op);
    nb_iargs = TCGOP_CALLI(op);
    uintptr_t helper_addr = op->args[nb_oargs + nb_iargs];
    void *helper_ptr = reinterpret_cast<void *>(helper_addr);
    const char *helper_nm = tcg_find_helper(&TCG->_ctx, helper_addr);

    //
    // some helper functions are special-cased
    //
    if (helper_ptr == helper_lookup_tb_ptr)
      break;

    const helper_function_t &hf = LookupHelper(op);
    llvm::FunctionType *FTy = hf.F->getFunctionType();

    //
    // build the vector of arguments to pass
    //
    std::vector<llvm::Value *> ArgVec;
    ArgVec.reserve(nb_iargs);

    int iarg_idx = 0;
    for (llvm::Type *ParamTy : FTy->params()) {
      assert(iarg_idx < nb_iargs);
      TCGTemp *ts = arg_temp(op->args[nb_oargs + iarg_idx]);

      if (temp_idx(ts) == tcg_env_index) {
        assert(hf.EnvArgNo == iarg_idx);

        if (hf.Analysis.Simple && opts::Optimize)
          ArgVec.push_back(IRB.CreateAlloca(CPUStateType));
        else
          ArgVec.push_back(CPUStateGlobal);

        ++iarg_idx;

        if (ts->type == TCG_TYPE_I32 && sizeof(TCGArg) == sizeof(uint64_t)) {
          if (opts::Verbose)
            WithColor::warning() << llvm::formatv("skipping arg at {0}\n", iarg_idx);
          ++iarg_idx;
        }
      } else if (ParamTy->isPointerTy()) {
        if (WordBits() == 32) {
          assert(ts->type == TCG_TYPE_I32);
        } else if (WordBits() == 64) {
          assert(ts->type == TCG_TYPE_I64);
        } else {
          __builtin_trap();
          __builtin_unreachable();
        }

        ArgVec.push_back(IRB.CreateIntToPtr(get(ts), ParamTy));
        ++iarg_idx;

        if (ts->type == TCG_TYPE_I32 && sizeof(TCGArg) == sizeof(uint64_t)) {
          if (opts::Verbose)
            WithColor::warning() << llvm::formatv("skipping arg at {0}\n", iarg_idx);
          ++iarg_idx;
        }
      } else if (ParamTy->isIntegerTy()) {
        if (ParamTy->isIntegerTy(32)) {
          if (ts->type == TCG_TYPE_I32) {
            ArgVec.push_back(get(ts));
            ++iarg_idx;
          } else {
            __builtin_trap();
            __builtin_unreachable();
          }
        } else if (ParamTy->isIntegerTy(64)) {
          if (ts->type == TCG_TYPE_I64) {
            ArgVec.push_back(get(ts));
            ++iarg_idx;
          } else if (ts->type == TCG_TYPE_I32) {
            llvm::Value *lo = get(ts);

            ++iarg_idx;
            assert(iarg_idx < nb_iargs);
            ts = arg_temp(op->args[nb_oargs + iarg_idx]);
            assert(ts->type == TCG_TYPE_I32);
            llvm::Value *hi = get(ts);
            ++iarg_idx;

            llvm::Value *combined =
                IRB.CreateOr(IRB.CreateZExt(lo, IRB.getInt64Ty()),
                             IRB.CreateShl(IRB.CreateZExt(hi, IRB.getInt64Ty()),
                                           llvm::APInt(64, 32)));
            ArgVec.push_back(combined);
          } else {
            __builtin_trap();
            __builtin_unreachable();
          }
        } else {
          __builtin_trap();
          __builtin_unreachable();
        }
      } else {
        __builtin_trap();
        __builtin_unreachable();
      }
    }

    assert(ArgVec.size() == hf.F->arg_size());
    assert(iarg_idx == nb_iargs); /* confirm we consumed all inputs */

    //
    // does the helper function take a CPUState* parameter?
    //
    if (hf.EnvArgNo >= 0) {
      llvm::Value *Env = ArgVec[hf.EnvArgNo];

      //
      // store our globals to the (maybe local) env
      //
      std::vector<unsigned> glbv;
      explode_tcg_global_set(glbv, (hf.Analysis.InGlbs | hf.Analysis.OutGlbs) & ~CmdlinePinnedEnvGlbs);
      for (unsigned glb : glbv) {
        llvm::StoreInst *SI = IRB.CreateStore(get(&s->temps[glb]), BuildCPUStatePointer(IRB, Env, glb));
        SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
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
      explode_tcg_global_set(glbv, hf.Analysis.OutGlbs & ~CmdlinePinnedEnvGlbs);
      for (unsigned glb : glbv) {
        llvm::LoadInst *LI = IRB.CreateLoad(BuildCPUStatePointer(IRB, Env, glb));
        LI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);

        set(LI, &s->temps[glb]);
      }
    }

    //
    // does the helper have an output?
    //
    if (nb_oargs > 0) {
      if (nb_oargs == 1) {
        TCGTemp *dst = arg_temp(op->args[0]);

        set(Ret, dst);
      } else if (nb_oargs == 2) {
        TCGTemp *dst1 = arg_temp(op->args[0]);
        TCGTemp *dst2 = arg_temp(op->args[1]);

        assert(dst1->type == TCG_TYPE_I32);
        assert(dst2->type == TCG_TYPE_I32);

        assert(FTy->getReturnType()->isIntegerTy(64));

        set(IRB.CreateTrunc(Ret, IRB.getInt32Ty()), dst1);
        set(IRB.CreateTrunc(IRB.CreateLShr(Ret, llvm::APInt(64, 32)),
                            IRB.getInt32Ty()),
            dst2);
      } else {
        __builtin_trap();
        __builtin_unreachable();
      }
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
    assert(nb_iargs == 1);
    assert(nb_oargs == 1);

    TCGTemp *dst = arg_temp(op->args[0]);
    TCGTemp *src = arg_temp(op->args[1]);

    if (likely(src->type == dst->type)) {
      set(get(src), dst);
    } else {
      assert(dst->type == TCG_TYPE_I32);
      assert(src->type == TCG_TYPE_I64);

      set(IRB.CreateTrunc(get(src), IRB.getInt32Ty()), dst);
    }
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

#if TCG_TARGET_REG_BITS == 64
    __EXT_OP(INDEX_op_ext8s_i64, 8, 64, S)
    __EXT_OP(INDEX_op_ext8u_i64, 8, 64, Z)
    __EXT_OP(INDEX_op_ext16s_i64, 16, 64, S)
    __EXT_OP(INDEX_op_ext16u_i64, 16, 64, Z)

    __EXT_OP(INDEX_op_ext_i32_i64, 32, 64, S)
    __EXT_OP(INDEX_op_ext32s_i64, 32, 64, S)

    __EXT_OP(INDEX_op_extu_i32_i64, 32, 64, Z)
    __EXT_OP(INDEX_op_ext32u_i64, 32, 64, Z)
    __EXT_OP(INDEX_op_extrl_i64_i32, 32, 64, Z)
#endif

#undef __EXT_OP

#define __OP_QEMU_LD(opc_name, regBits)                                        \
  case opc_name: {                                                             \
    assert(nb_iargs == 1);                                                     \
    assert(nb_oargs == 1 || nb_oargs == 2);                                    \
                                                                               \
    TCGMemOpIdx moidx = op->args[nb_oargs + nb_iargs];                         \
    MemOp mop = get_memop(moidx);                                              \
                                                                               \
    llvm::Value *Addr = get(arg_temp(op->args[nb_oargs]));                     \
    Addr = IRB.CreateZExt(Addr, WordType());                                   \
    Addr = IRB.CreateIntToPtr(                                                 \
        Addr, llvm::PointerType::get(IRB.getIntNTy(bits_of_memop(mop)), 0));   \
                                                                               \
    llvm::LoadInst *Li = IRB.CreateLoad(Addr);                                 \
    Li->setMetadata(llvm::LLVMContext::MD_noalias, AliasScopeMetadata);        \
    llvm::Value *Val = Li;                                                     \
    if (regBits > bits_of_memop(mop))                                          \
      Val = mop & MO_SIGN ? IRB.CreateSExt(Val, IRB.getIntNTy(regBits))        \
                          : IRB.CreateZExt(Val, IRB.getIntNTy(regBits));       \
                                                                               \
    if (nb_oargs == 1) {                                                       \
      set(Val, arg_temp(op->args[0]));                                         \
      break;                                                                   \
    }                                                                          \
                                                                               \
    assert(nb_oargs == 2);                                                     \
    assert(WordBits() == 32);                                                  \
    assert(regBits == 64);                                                     \
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
    assert(nb_oargs == 0);                                                     \
    assert(nb_iargs == 2 || nb_iargs == 3);                                    \
                                                                               \
    TCGMemOpIdx moidx = op->args[nb_oargs + nb_iargs];                         \
    MemOp mop = get_memop(moidx);                                              \
                                                                               \
    llvm::Value *Addr = get(arg_temp(op->args[nb_oargs + nb_iargs - 1]));      \
    Addr = IRB.CreateZExt(Addr, WordType());                                   \
    Addr = IRB.CreateIntToPtr(                                                 \
        Addr, llvm::PointerType::get(IRB.getIntNTy(bits_of_memop(mop)), 0));   \
                                                                               \
    llvm::Value *Val;                                                          \
    if (nb_iargs == 2) {                                                       \
      Val = get(arg_temp(op->args[nb_oargs + 0]));                             \
    } else {                                                                   \
      assert(nb_iargs == 3);                                                   \
      assert(WordBits() == 32);                                                \
      assert(bits == 64);                                                      \
                                                                               \
      llvm::Value *LowVal = get(arg_temp(op->args[nb_oargs + 0]));             \
      llvm::Value *HighVal = get(arg_temp(op->args[nb_oargs + 1]));            \
                                                                               \
      Val = IRB.CreateOr(                                                      \
          IRB.CreateZExt(LowVal, IRB.getInt64Ty()),                            \
          IRB.CreateShl(IRB.CreateZExt(HighVal, IRB.getInt64Ty()),             \
                        IRB.getInt64(32)));                                    \
    }                                                                          \
                                                                               \
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
#if defined(TARGET_AARCH64)
#define __ARCH_LD_OP(off)                                                      \
  {                                                                            \
    if (off == tcg_tpidr_el0_env_offset) {                                     \
      TCGTemp *dst = arg_temp(op->args[0]);                                    \
      assert(dst->type == TCG_TYPE_I64);                                       \
      set(insertThreadPointerInlineAsm(IRB), dst);                             \
      break;                                                                   \
    }                                                                          \
  }
#elif defined(TARGET_MIPS32)
#define __ARCH_LD_OP(off)                                                      \
  {                                                                            \
    if (off == offsetof(CPUMIPSState, active_tc.CP0_UserLocal)) {              \
      TCGTemp *dst = arg_temp(op->args[0]);                                    \
      assert(dst->type == TCG_TYPE_I32);                                       \
      set(insertThreadPointerInlineAsm(IRB), dst);                             \
      break;                                                                   \
    }                                                                          \
                                                                               \
    if (off == offsetof(CPUMIPSState, lladdr)) {                               \
      TCGTemp *dst = arg_temp(op->args[0]);                                    \
      assert(dst->type == TCG_TYPE_I32);                                       \
      set(get(&TCG->_ctx.temps[tcg_lladdr_index]), dst);                       \
      break;                                                                   \
    }                                                                          \
                                                                               \
    if (off == offsetof(CPUMIPSState, llval)) {                                \
      TCGTemp *dst = arg_temp(op->args[0]);                                    \
      assert(dst->type == TCG_TYPE_I32);                                       \
      set(get(&TCG->_ctx.temps[tcg_llval_index]), dst);                        \
      break;                                                                   \
    }                                                                          \
                                                                               \
    { llvm::errs() << llvm::formatv("CURIOSITY: load(env+{0})\n", off); }      \
  }
#else
#define __ARCH_LD_OP(off)                                                      \
  { ; }
#endif

#define __LD_OP(opc_name, memBits, regBits, signE)                             \
  case opc_name: {                                                             \
    unsigned baseidx = temp_idx(arg_temp(op->args[1]));                        \
    assert(baseidx == tcg_env_index);                                          \
                                                                               \
    TCGArg off = op->args[2];                                                  \
                                                                               \
    __ARCH_LD_OP(off)                                                          \
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

#if TCG_TARGET_REG_BITS == 64
    __LD_OP(INDEX_op_ld8u_i64,  8,  64, Z)
    __LD_OP(INDEX_op_ld8s_i64,  8,  64, S)
    __LD_OP(INDEX_op_ld16u_i64, 16, 64, Z)
    __LD_OP(INDEX_op_ld16s_i64, 16, 64, S)
    __LD_OP(INDEX_op_ld32u_i64, 32, 64, Z)
    __LD_OP(INDEX_op_ld32s_i64, 32, 64, S)
    __LD_OP(INDEX_op_ld_i64,    64, 64, Z)
#endif

#undef __LD_OP

#if defined(TARGET_MIPS32)
#define __ARCH_ST_OP(off)                                                      \
  {                                                                            \
    if (off == offsetof(CPUMIPSState, lladdr)) {                               \
      set(Val, &TCG->_ctx.temps[tcg_lladdr_index]);                            \
      break;                                                                   \
    }                                                                          \
                                                                               \
    if (off == offsetof(CPUMIPSState, llval)) {                                \
      set(Val, &TCG->_ctx.temps[tcg_llval_index]);                             \
      break;                                                                   \
    }                                                                          \
                                                                               \
    { llvm::errs() << llvm::formatv("CURIOSITY: store(env+{0})\n", off); }     \
  }
#else
#define __ARCH_ST_OP(off)                                                      \
  { ; }
#endif


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
      assert(memBits == WordBits() && regBits == WordBits());                  \
      IRB.CreateStore(Val, TC.PCAlloca);                                       \
      break;                                                                   \
    }                                                                          \
                                                                               \
    __ARCH_ST_OP(off)                                                          \
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

    __ST_OP(INDEX_op_st8_i32, 8, 32)
    __ST_OP(INDEX_op_st16_i32, 16, 32)
    __ST_OP(INDEX_op_st_i32, 32, 32)

#if TCG_TARGET_REG_BITS == 64
    __ST_OP(INDEX_op_st8_i64, 8, 64)
    __ST_OP(INDEX_op_st16_i64, 16, 64)
    __ST_OP(INDEX_op_st32_i64, 32, 64)
    __ST_OP(INDEX_op_st_i64, 64, 64)
#endif

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

  case INDEX_op_deposit_i32: {
    TCGTemp *dst = arg_temp(op->args[0]);
    TCGTemp *src1 = arg_temp(op->args[1]);
    TCGTemp *src2 = arg_temp(op->args[2]);

    llvm::Value *arg1 = get(src1);
    llvm::Value *arg2 = get(src2);
    arg2 = IRB.CreateTrunc(arg2, IRB.getInt32Ty());

    uint32_t ofs = op->args[3];
    uint32_t len = op->args[4];

    if (0 == ofs && 32 == len) {
      set(arg2, dst);
      break;
    }

    uint32_t mask = (1u << len) - 1;
    llvm::Value *t1, *ret;

    if (ofs + len < 32) {
      t1 = IRB.CreateAnd(arg2, llvm::APInt(32, mask));
      t1 = IRB.CreateShl(t1, llvm::APInt(32, ofs));
    } else {
      t1 = IRB.CreateShl(arg2, llvm::APInt(32, ofs));
    }

    ret = IRB.CreateAnd(arg1, llvm::APInt(32, ~(mask << ofs)));
    ret = IRB.CreateOr(ret, t1);
    set(ret, dst);
    break;
  }

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

  case INDEX_op_mulsh_i64: {
    TCGTemp *dst = arg_temp(op->args[0]);
    TCGTemp *src1 = arg_temp(op->args[1]);
    TCGTemp *src2 = arg_temp(op->args[2]);

    assert(dst->type == TCG_TYPE_I64);
    assert(src1->type == TCG_TYPE_I64);
    assert(src2->type == TCG_TYPE_I64);

    llvm::Value *x =
        IRB.CreateMul(IRB.CreateSExt(get(src1), IRB.getInt128Ty()),
                      IRB.CreateSExt(get(src2), IRB.getInt128Ty()));

    llvm::Value *y = IRB.CreateTrunc(IRB.CreateLShr(x, IRB.getIntN(128, 64)),
                                     IRB.getInt64Ty());

    set(y, dst);
    break;
  }

#define __ADD2_OR_SUB2(opc_name, bits, isAdd)                                  \
  case opc_name: {                                                             \
    assert(nb_oargs == 2);                                                     \
                                                                               \
    TCGTemp *t0_low = arg_temp(op->args[0]);                                   \
    TCGTemp *t0_high = arg_temp(op->args[1]);                                  \
                                                                               \
    TCGTemp *t1_low = arg_temp(op->args[nb_oargs + 0]);                        \
    TCGTemp *t1_high = arg_temp(op->args[nb_oargs + 1]);                       \
                                                                               \
    TCGTemp *t2_low = arg_temp(op->args[nb_oargs + 2]);                        \
    TCGTemp *t2_high = arg_temp(op->args[nb_oargs + 3]);                       \
                                                                               \
    assert(t0_low->type == TCG_TYPE_I##bits);                                  \
    assert(t0_high->type == TCG_TYPE_I##bits);                                 \
                                                                               \
    assert(t1_low->type == TCG_TYPE_I##bits);                                  \
    assert(t1_low->type == TCG_TYPE_I##bits);                                  \
                                                                               \
    assert(t2_low->type == TCG_TYPE_I##bits);                                  \
    assert(t2_high->type == TCG_TYPE_I##bits);                                 \
                                                                               \
    llvm::Value *t1_low_v = get(t1_low);                                       \
    llvm::Value *t1_high_v = get(t1_high);                                     \
                                                                               \
    llvm::Value *t2_low_v = get(t2_low);                                       \
    llvm::Value *t2_high_v = get(t2_high);                                     \
                                                                               \
    llvm::Value *t1 = IRB.CreateOr(                                            \
        IRB.CreateZExt(t1_low_v, IRB.getIntNTy(2 * bits)),                     \
        IRB.CreateShl(IRB.CreateZExt(t1_high_v, IRB.getIntNTy(2 * bits)),      \
                      llvm::APInt(2 * bits, bits)));                           \
                                                                               \
    llvm::Value *t2 = IRB.CreateOr(                                            \
        IRB.CreateZExt(t2_low_v, IRB.getIntNTy(2 * bits)),                     \
        IRB.CreateShl(IRB.CreateZExt(t2_high_v, IRB.getIntNTy(2 * bits)),      \
                      llvm::APInt(2 * bits, bits)));                           \
                                                                               \
    llvm::Value *t0 = (isAdd) ? IRB.CreateAdd(t1, t2) : IRB.CreateSub(t1, t2); \
                                                                               \
    llvm::Value *t0_low_v = IRB.CreateTrunc(t0, IRB.getIntNTy(bits));          \
    llvm::Value *t0_high_v = IRB.CreateTrunc(                                  \
        IRB.CreateLShr(t0, llvm::APInt(2 * bits, bits)), IRB.getIntNTy(bits)); \
                                                                               \
    set(t0_low_v, t0_low);                                                     \
    set(t0_high_v, t0_high);                                                   \
                                                                               \
    break;                                                                     \
  }

    __ADD2_OR_SUB2(INDEX_op_add2_i32, 32, true)
    __ADD2_OR_SUB2(INDEX_op_add2_i64, 64, true)

    __ADD2_OR_SUB2(INDEX_op_sub2_i32, 32, false)
    __ADD2_OR_SUB2(INDEX_op_sub2_i64, 64, false)

#undef __ADD2_OR_SUB2

#define __ORC_OP(opc_name, bits)                                               \
  case opc_name: {                                                             \
    llvm::Value *v1 = get(arg_temp(op->args[1]));                              \
    llvm::Value *v2 = get(arg_temp(op->args[2]));                              \
                                                                               \
    llvm::Value *notv2 =                                                       \
        IRB.CreateXor(bits == 32 ? IRB.getInt32(0xffffffff)                    \
                                 : IRB.getInt64(0xffffffffffffffff),           \
                      v2);                                                     \
                                                                               \
    set(IRB.CreateOr(v1, notv2), arg_temp(op->args[0]));                       \
  } break;

    __ORC_OP(INDEX_op_orc_i32, 32)
    __ORC_OP(INDEX_op_orc_i64, 64)

#undef __ORC_OP

#define __EQV_OP(opc_name, bits)                                               \
  case opc_name: {                                                             \
    llvm::Value *v1 = get(arg_temp(op->args[1]));                              \
    llvm::Value *v2 = get(arg_temp(op->args[2]));                              \
                                                                               \
    llvm::Value *notv2 =                                                       \
        IRB.CreateXor(bits == 32 ? IRB.getInt32(0xffffffff)                    \
                                 : IRB.getInt64(0xffffffffffffffff),           \
                      v2);                                                     \
                                                                               \
    set(IRB.CreateXor(v1, notv2), arg_temp(op->args[0]));                      \
  } break;

    __EQV_OP(INDEX_op_eqv_i32, 32)
    __EQV_OP(INDEX_op_eqv_i64, 64)

#undef __EQV_OP

  case INDEX_op_mb: {
    llvm::StringRef AsmText;
    llvm::StringRef Constraints;

#if defined(TARGET_X86_64)
    AsmText = "mfence";
    Constraints = "~{memory}";
#elif defined(TARGET_I386)
    AsmText = "lock; addl $$0,0(%esp)";
    Constraints = "~{memory},~{cc},~{dirflag},~{fpsr},~{flags}";
#elif defined(TARGET_AARCH64)
    AsmText = "dmb ish";
    Constraints = "~{memory}";
#elif defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
    AsmText = "sync";
    Constraints = "~{memory}";
#else
#error
#endif

    llvm::InlineAsm *IA =
        llvm::InlineAsm::get(llvm::FunctionType::get(VoidType(), false),
                             AsmText, Constraints, true /* hasSideEffects */);
    IRB.CreateCall(IA);
    break;
  }

  default:
    return 1;
  }

  return 0;
}

const translate_tcg_op_proc_t TranslateTCGOpTable[180] = {
    [0 ... 180 - 1] = nullptr,

#define __PROC_CASE(n, i, data) [i] = TranslateTCGOp<i>,

BOOST_PP_REPEAT(180, __PROC_CASE, void)

#undef __PROC_CASE

};

} // namespace jove
