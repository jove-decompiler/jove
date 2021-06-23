#include <boost/icl/interval_set.hpp>
#include <boost/icl/split_interval_map.hpp>
#include <llvm/ADT/StringRef.h>
#include <llvm/ADT/ArrayRef.h>
#include <set>

struct section_properties_t {
  llvm::StringRef name;
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
  llvm::StringRef Name;
  llvm::StringRef Vers;
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
  llvm::GlobalVariable *PreHookGv = nullptr;                                   \
  llvm::Function *PostHook = nullptr;                                          \
  llvm::GlobalVariable *PostHookGv = nullptr;                                  \
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
  void Analyze(void);                                                          \
                                                                               \
  llvm::Function *F = nullptr;

#define JOVE_EXTRA_BIN_PROPERTIES                                              \
  std::unique_ptr<llvm::object::Binary> ObjectFile;                            \
  llvm::GlobalVariable *FunctionsTable = nullptr;                              \
  llvm::Function *SectsF = nullptr;                                            \
  std::unordered_map<tcg_uintptr_t, function_index_t> FuncMap;                 \
  boost::icl::split_interval_map<tcg_uintptr_t, section_properties_set_t> SectMap;

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
#include <llvm/Object/ELFObjectFile.h>
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
#include <llvm/Transforms/Utils/ModuleUtils.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/LowerMemIntrinsics.h>
#include <llvm/Analysis/Passes.h>
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

#ifndef likely
#define likely(x)   __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

static void __warn(const char *file, int line);

#ifndef WARN
#define WARN()                                                                 \
  do {                                                                         \
    __warn(__FILE__, __LINE__);                                                \
  } while (0)
#endif

#ifndef WARN_ON
#define WARN_ON(condition)                                                     \
  ({                                                                           \
    int __ret_warn_on = !!(condition);                                         \
    if (unlikely(__ret_warn_on))                                               \
      WARN();                                                                  \
    unlikely(__ret_warn_on);                                                   \
  })
#endif

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

static cl::opt<std::string> Binary("binary", cl::desc("Binary to decompile"),
                                   cl::Required, cl::value_desc("filename"),
                                   cl::cat(JoveCategory));

static cl::alias BinaryAlias("b", cl::desc("Alias for -binary."),
                             cl::aliasopt(Binary), cl::cat(JoveCategory));

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

static bool CallStack;

static cl::opt<bool>
    CheckEmulatedStackReturnAddress("check-emulated-stack-return-address",
                                    cl::desc("Check for stack overrun"),
                                    cl::cat(JoveCategory));

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
  llvm::StringRef Name;
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

#ifdef TARGET_MIPS32

#define __THUNK(n, i, data)                                                    \
  static llvm::Function *JoveThunk##i##Func;

BOOST_PP_REPEAT(5, __THUNK, void)

#undef __THUNK

#else
static llvm::Function *JoveThunkFunc;
#endif
static llvm::Function *JoveFail1Func;

static llvm::Function *JoveAllocStackFunc;
static llvm::Function *JoveFreeStackFunc;

static llvm::Function *JoveCheckReturnAddrFunc;

static llvm::GlobalVariable *SectsGlobal;
static llvm::GlobalVariable *ConstSectsGlobal;
static target_ulong SectsStartAddr, SectsEndAddr;
static llvm::GlobalVariable *TLSSectsGlobal;

static std::vector<function_index_t> FuncIdxAreABIVec;

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

static std::unordered_map<llvm::GlobalIFunc *,
                          std::pair<binary_index_t, function_index_t>>
    IFuncTargetMap;

static std::unordered_set<target_ulong> ExternGlobalAddrs;

static std::unordered_set<llvm::Function *> FunctionsToInline;

static struct {
  std::unordered_map<std::string, std::unordered_set<std::string>> Table;
} VersionScript;

// set {int}0x08053ebc = 0xf7fa83f0
static std::map<std::pair<target_ulong, unsigned>,
                std::pair<binary_index_t, std::pair<target_ulong, unsigned>>>
    CopyRelocMap;

#define JOVE_PAGE_SIZE 4096
#define JOVE_STACK_SIZE (256 * JOVE_PAGE_SIZE)

//
// Stages
//
static int ProcessCommandLine(void);
static int ParseDecompilation(void);
static int FindBinary(void);
static int CheckBinary(void);
static int InitStateForBinaries(void);
static int CreateModule(void);
static int LocateHooks(void);
static int PrepareToTranslateCode(void);
static int ProcessDynamicTargets(void);
static int ProcessBinaryRelocations(void);
static int ProcessIFuncResolvers(void);
static int ProcessExportedFunctions(void);
static int CreateFunctions(void);
static int CreateFunctionTables(void);
static int ProcessBinaryTLSSymbols(void);
static int ProcessDynamicSymbols(void);
static int CreateTLSModGlobal(void);
static int CreateSectionGlobalVariables(void);
static int ProcessDynamicSymbols2(void);
static int CreateFunctionTable(void);
static int FixupHelperStubs(void);
static int CreateNoAliasMetadata(void);
static int CreateTPOFFCtorHack(void);
static int CreateCopyRelocationHack(void);
static int TranslateFunctions(void);
static int InlineCalls(void);
static int PrepareToOptimize(void);
static int ConstifyRelocationSectionPointers(void);
static int InternalizeStaticFunctions(void);
static int InternalizeSections(void);
static int ExpandMemoryIntrinsicCalls(void);
static int ReplaceAllRemainingUsesOfConstSections(void);
static int RecoverControlFlow(void);
static int DFSanInstrument(void);
static int RenameFunctionLocals(void);
static int WriteDecompilation(void);
static int WriteVersionScript(void);
static int WriteModule(void);

static int DoOptimize(void);
static void DumpModule(const char *);

int llvm(void) {
  return 0
      || ParseDecompilation()
      || FindBinary()
      || CheckBinary()
      || InitStateForBinaries()
      || CreateModule()
      || (opts::DFSan ? LocateHooks() : 0)
      || PrepareToTranslateCode()
      || ProcessCommandLine() /* must do this after TCG is ready */
      || ProcessDynamicTargets()
      || ProcessBinaryRelocations()
      || ProcessIFuncResolvers()
      || ProcessExportedFunctions()
      || CreateFunctions()
      || CreateFunctionTables()
      || ProcessBinaryTLSSymbols()
      || ProcessDynamicSymbols()
      || CreateTLSModGlobal()
      || CreateSectionGlobalVariables()
      || ProcessDynamicSymbols2()
      || CreateFunctionTable()
      || FixupHelperStubs()
      || CreateNoAliasMetadata()
      || CreateTPOFFCtorHack()
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

bool isDFSan(void) {
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

llvm::Type *VoidType(void) {
  return llvm::Type::getVoidTy(*Context);
}

static llvm::Type *VoidFunctionPointer(void) {
  llvm::FunctionType *FTy = llvm::FunctionType::get(VoidType(), false);
  return llvm::PointerType::get(FTy, 0);
}

static std::error_code lockFile(int FD) {
  struct flock Lock;
  memset(&Lock, 0, sizeof(Lock));
  Lock.l_type = F_WRLCK;
  Lock.l_whence = SEEK_SET;
  Lock.l_start = 0;
  Lock.l_len = 0;
  if (::fcntl(FD, F_SETLKW, &Lock) != -1)
    return std::error_code();
  int Error = errno;
  return std::error_code(Error, std::generic_category());
}

static std::error_code unlockFile(int FD) {
  struct flock Lock;
  Lock.l_type = F_UNLCK;
  Lock.l_whence = SEEK_SET;
  Lock.l_start = 0;
  Lock.l_len = 0;
  if (::fcntl(FD, F_SETLK, &Lock) != -1)
    return std::error_code();
  return std::error_code(errno, std::generic_category());
}

int ProcessCommandLine(void) {
  auto tcg_index_of_named_global = [&](const char *nm) -> int {
    for (int i = 0; i < TCG->_ctx.nb_globals; i++) {
      if (strcmp(TCG->_ctx.temps[i].name, nm) == 0)
        return i;
    }

    return -1;
  };

  for (const std::string &PinnedGlobalName : opts::PinnedGlobals) {
    int idx = tcg_index_of_named_global(PinnedGlobalName.c_str());
    if (idx < 0) {
      WithColor::warning() << llvm::formatv(
          "unknown global {0} (--pinned-globals); ignoring\n", idx);
      continue;
    }

    CmdlinePinnedEnvGlbs.set(idx);
  }

  return 0;
}

int ParseDecompilation(void) {
  std::string path = fs::is_directory(opts::jv)
                         ? (opts::jv + "/decompilation.jv")
                         : opts::jv;

  int fd = ::open(path.c_str(), O_RDONLY);
  assert(!(fd < 0));
  lockFile(fd);

  {
    std::ifstream ifs(path);

    boost::archive::text_iarchive ia(ifs);
    ia >> Decompilation;
  }

  unlockFile(fd);
  close(fd);

  return 0;
}

int FindBinary(void) {
  if (opts::Binary.empty())
    return 1;

  if (std::isdigit(opts::Binary[0])) {
    //
    // interpret input as an index of the binary to translate
    //
    int idx = atoi(opts::Binary.c_str());

    if (idx < 0 || idx >= Decompilation.Binaries.size()) {
      WithColor::error() << llvm::formatv("{0}: invalid binary index supplied\n",
                                          __func__);
      return 1;
    }

    BinaryIndex = idx;
    return 0;
  }

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

int CheckBinary(void) {
  if (opts::ForeignLibs) {
    if (!Decompilation.Binaries[BinaryIndex].IsExecutable) {
      WithColor::error() << "--foreign-libs specified but given binary is not "
                            "the executable\n";
      return 1;
    }
  }

  return 0;
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

#if 0
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

#include "elf.hpp"

#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)

static const typename ELFF::Elf_Shdr *
findNotEmptySectionByAddress(const ELFF *Obj, uint64_t Addr) {
  for (const auto &Shdr : unwrapOrError(Obj->sections()))
    if (Shdr.sh_addr == Addr && Shdr.sh_size > 0)
      return &Shdr;
  return nullptr;
}

static const typename ELFF::Elf_Shdr *
findSectionByName(const ELFF &Obj, llvm::StringRef Name) {
  for (const auto &Shdr : unwrapOrError(Obj.sections()))
    if (Name == unwrapOrError(Obj.getSectionName(&Shdr)))
      return &Shdr;
  return nullptr;
}

class MipsGOTParser {
public:
  using Elf_Addr = typename ELFT::Addr;
  using Elf_Shdr = typename ELFT::Shdr;
  using Elf_Sym = typename ELFT::Sym;
  using Elf_Dyn = typename ELFT::Dyn;
  using Elf_Dyn_Range = typename ELFT::DynRange;
  using Elf_Rel = typename ELFT::Rel;
  using Elf_Rela = typename ELFT::Rela;
  using Elf_Relr = typename ELFT::Relr;
  using Elf_Rel_Range = typename ELFT::RelRange;
  using Elf_Rela_Range = typename ELFT::RelaRange;
  using Elf_Relr_Range = typename ELFT::RelrRange;
  using Elf_Phdr = typename ELFT::Phdr;
  using Elf_Half = typename ELFT::Half;
  using Elf_Ehdr = typename ELFT::Ehdr;
  using Elf_Word = typename ELFT::Word;
  using Elf_Hash = typename ELFT::Hash;
  using Elf_GnuHash = typename ELFT::GnuHash;
  using Elf_Note  = typename ELFT::Note;
  using Elf_Sym_Range = typename ELFT::SymRange;
  using Elf_Versym = typename ELFT::Versym;
  using Elf_Verneed = typename ELFT::Verneed;
  using Elf_Vernaux = typename ELFT::Vernaux;
  using Elf_Verdef = typename ELFT::Verdef;
  using Elf_Verdaux = typename ELFT::Verdaux;
  using Elf_CGProfile = typename ELFT::CGProfile;
  using uintX_t = typename ELFT::uint;

  using Entry = typename ELFF::Elf_Addr;
  using Entries = llvm::ArrayRef<Entry>;

  const bool IsStatic;
  const ELFF * const Obj;

  MipsGOTParser(const ELFF *Obj,
                Elf_Dyn_Range DynTable, Elf_Sym_Range DynSyms)
      : IsStatic(DynTable.empty()), Obj(Obj), GotSec(nullptr), LocalNum(0),
        GlobalNum(0), PltSec(nullptr), PltRelSec(nullptr), PltSymTable(nullptr) {
    // See "Global Offset Table" in Chapter 5 in the following document
    // for detailed GOT description.
    // ftp://www.linux-mips.org/pub/linux/mips/doc/ABI/mipsabi.pdf

    // Find static GOT secton.
    if (IsStatic) {
      GotSec = findSectionByName(*Obj, ".got");
      if (!GotSec)
        return;

      llvm::ArrayRef<uint8_t> Content =
          unwrapOrError(Obj->getSectionContents(GotSec));
      GotEntries = Entries(reinterpret_cast<const Entry *>(Content.data()),
                           Content.size() / sizeof(Entry));
      LocalNum = GotEntries.size();
      return;
    }

    // Lookup dynamic table tags which define GOT/PLT layouts.
    llvm::Optional<uint64_t> DtPltGot;
    llvm::Optional<uint64_t> DtLocalGotNum;
    llvm::Optional<uint64_t> DtGotSym;
    llvm::Optional<uint64_t> DtMipsPltGot;
    llvm::Optional<uint64_t> DtJmpRel;
    for (const auto &Entry : DynTable) {
      switch (Entry.getTag()) {
      case llvm::ELF::DT_PLTGOT:
        DtPltGot = Entry.getVal();
        break;
      case llvm::ELF::DT_MIPS_LOCAL_GOTNO:
        DtLocalGotNum = Entry.getVal();
        break;
      case llvm::ELF::DT_MIPS_GOTSYM:
        DtGotSym = Entry.getVal();
        break;
      case llvm::ELF::DT_MIPS_PLTGOT:
        DtMipsPltGot = Entry.getVal();
        break;
      case llvm::ELF::DT_JMPREL:
        DtJmpRel = Entry.getVal();
        break;
      }
    }

    // Find dynamic GOT section.
    if (DtPltGot || DtLocalGotNum || DtGotSym) {
      if (!DtPltGot) {
        WithColor::warning() << "Cannot find PLTGOT dynamic table tag.\n";
        abort();
      }
      if (!DtLocalGotNum) {
        WithColor::warning() << "Cannot find MIPS_LOCAL_GOTNO dynamic table tag.\n";
        abort();
      }
      if (!DtGotSym) {
        WithColor::warning() << "Cannot find MIPS_GOTSYM dynamic table tag.\n";
        abort();
      }

      size_t DynSymTotal = DynSyms.size();
      if (*DtGotSym > DynSymTotal) {
        WithColor::error() << llvm::formatv(
            "MIPS_GOTSYM ({0}) exceeds a number of dynamic symbols ({1})\n",
            *DtGotSym, DynSymTotal);
      }

      GotSec = findNotEmptySectionByAddress(Obj, *DtPltGot);
      if (!GotSec) {
        WithColor::error() << llvm::formatv("There is no not empty GOT section at {0}\n",
                                            llvm::Twine::utohexstr(*DtPltGot));
      } else {
        llvm::ArrayRef<uint8_t> Content =
            unwrapOrError(Obj->getSectionContents(GotSec));
        GotEntries = Entries(reinterpret_cast<const Entry *>(Content.data()),
                             Content.size() / sizeof(Entry));

        LocalNum = *DtLocalGotNum;
        GlobalNum = DynSymTotal - *DtGotSym;
        GotDynSyms = DynSyms.drop_front(*DtGotSym);
      }
    }

    // Find PLT section.
    if (DtMipsPltGot || DtJmpRel) {
      if (!DtMipsPltGot) {
        WithColor::warning() << "Cannot find PLTGOT dynamic table tag.\n";
      } else {
        if (!DtJmpRel) {
          WithColor::warning() << "Cannot find JMPREL dynamic table tag.\n";
        } else {
          PltSec = findNotEmptySectionByAddress(Obj, *DtMipsPltGot);
          if (!PltSec) {
            WithColor::warning() << llvm::formatv("There is no not empty PLTGOT section at {0}\n",
                                                  llvm::Twine::utohexstr(*DtMipsPltGot));
          } else {
            PltRelSec = findNotEmptySectionByAddress(Obj, *DtJmpRel);
            if (!PltRelSec) {
              WithColor::error() << llvm::formatv("There is no not empty RELPLT section at {0}\n",
                                                  llvm::Twine::utohexstr(*DtPltGot));
            } else {
              llvm::ArrayRef<uint8_t> PltContent =
                  unwrapOrError(Obj->getSectionContents(PltSec));
              PltEntries = Entries(reinterpret_cast<const Entry *>(PltContent.data()),
                                   PltContent.size() / sizeof(Entry));

              PltSymTable =
                  unwrapOrError(Obj->getSection(PltRelSec->sh_link));
              PltStrTable =
                  unwrapOrError(Obj->getStringTableForSymtab(*PltSymTable));
            }
          }
        }
      }
    }
  }

  bool hasGot() const { return !GotEntries.empty(); }
  bool hasPlt() const { return !PltEntries.empty(); }

  uint64_t getGp() const {
    return GotSec->sh_addr + 0x7ff0;
  }

  const Entry *getGotLazyResolver() const {
    return LocalNum > 0 ? &GotEntries[0] : nullptr;
  }
  const Entry *getGotModulePointer() const {
    if (LocalNum < 2)
      return nullptr;
    const Entry &E = GotEntries[1];
    if ((E >> (sizeof(Entry) * 8 - 1)) == 0)
      return nullptr;
    return &E;
  }
  const Entry *getPltLazyResolver() const {
    return PltEntries.empty() ? nullptr : &PltEntries[0];
  }
  const Entry *getPltModulePointer() const {
    return PltEntries.size() < 2 ? nullptr : &PltEntries[1];
  }

  Entries getLocalEntries() const {
    if (LocalNum == 0)
      return Entries();

    size_t Skip = getGotModulePointer() ? 2 : 1;
    if (LocalNum - Skip <= 0)
      return Entries();
    return GotEntries.slice(Skip, LocalNum - Skip);
  }

  Entries getGlobalEntries() const {
    if (GlobalNum == 0)
      return Entries();
    return GotEntries.slice(LocalNum, GlobalNum);
  }
  Entries getOtherEntries() const {
    size_t OtherNum = GotEntries.size() - LocalNum - GlobalNum;
    if (OtherNum == 0)
      return Entries();
    return GotEntries.slice(LocalNum + GlobalNum, OtherNum);
  }
  Entries getPltEntries() const {
    if (PltEntries.size() <= 2)
      return Entries();
    return PltEntries.slice(2, PltEntries.size() - 2);
  }

  uint64_t getGotAddress(const Entry * E) const {
    int64_t Offset = std::distance(GotEntries.data(), E) * sizeof(Entry);
    return GotSec->sh_addr + Offset;
  }

  int64_t getGotOffset(const Entry * E) const {
    int64_t Offset = std::distance(GotEntries.data(), E) * sizeof(Entry);
    return Offset - 0x7ff0;
  }
  const Elf_Sym *getGotSym(const Entry *E) const {
    int64_t Offset = std::distance(GotEntries.data(), E);
    return &GotDynSyms[Offset - LocalNum];
  }

  uint64_t getPltAddress(const Entry * E) const {
    int64_t Offset = std::distance(PltEntries.data(), E) * sizeof(Entry);
    return PltSec->sh_addr + Offset;
  }
  const Elf_Sym *getPltSym(const Entry *E) const {
    int64_t Offset = std::distance(getPltEntries().data(), E);
    if (PltRelSec->sh_type == llvm::ELF::SHT_REL) {
      Elf_Rel_Range Rels = unwrapOrError(Obj->rels(PltRelSec));
      return unwrapOrError(Obj->getRelocationSymbol(&Rels[Offset], PltSymTable));
    } else {
      Elf_Rela_Range Rels = unwrapOrError(Obj->relas(PltRelSec));
      return unwrapOrError(Obj->getRelocationSymbol(&Rels[Offset], PltSymTable));
    }
  }

  llvm::StringRef getPltStrTable() const { return PltStrTable; }

private:
  const Elf_Shdr *GotSec;
  size_t LocalNum;
  size_t GlobalNum;

  const Elf_Shdr *PltSec;
  const Elf_Shdr *PltRelSec;
  const Elf_Shdr *PltSymTable;

  Elf_Sym_Range GotDynSyms;
  llvm::StringRef PltStrTable;

  Entries GotEntries;
  Entries PltEntries;
};

#endif

// TODO this whole function needs to be obliterated
int InitStateForBinaries(void) {
  for (binary_index_t BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx) {
    auto &binary = Decompilation.Binaries[BIdx];
    auto &ICFG = binary.Analysis.ICFG;
    auto &FuncMap = binary.FuncMap;
    auto &SectMap = binary.SectMap;

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
      WithColor::error() << "failed to create binary from " << binary.Path
                         << '\n';

      boost::icl::interval<target_ulong>::type intervl =
          boost::icl::interval<target_ulong>::right_open(0, binary.Data.size());

      assert(SectMap.find(intervl) == SectMap.end());

      section_properties_t sectprop;
      sectprop.name = ".text";
      sectprop.contents = llvm::ArrayRef<uint8_t>((uint8_t *)&binary.Data[0], binary.Data.size());
      sectprop.w = false;
      sectprop.x = true;
      sectprop.initArray = false;
      sectprop.finiArray = false;
      SectMap.add({intervl, {sectprop}});
    } else {
      std::unique_ptr<obj::Binary> &BinRef = BinOrErr.get();

      binary.ObjectFile = std::move(BinRef);

      assert(llvm::isa<ELFO>(binary.ObjectFile.get()));
      ELFO &O = *llvm::cast<ELFO>(binary.ObjectFile.get());

      TheTriple = O.makeTriple();
      Features = O.getFeatures();

      const ELFF &E = *O.getELFFile();

      //
      // build section map
      //
      llvm::Expected<Elf_Shdr_Range> sections = E.sections();
      if (!sections) {
        WithColor::error() << "error: could not get ELF sections for binary "
                           << binary.Path << '\n';
        return 1;
      }

      if (opts::Verbose)
        llvm::outs() << binary.Path << '\n';

      for (const Elf_Shdr &Sec : *sections) {
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
    }

    if (BIdx == BinaryIndex) {
      llvm::outs() << "Address Space:\n";
      for (const auto &pair : SectMap) {
        const section_properties_t &sect = *pair.second.begin();

        llvm::outs() <<
          (boost::format("%-20s [%x, %x)")
           % sect.name.str()
           % pair.first.lower()
           % pair.first.upper()).str()
          << '\n';
      }

      //
      // compute SectsStartAddr, SectsEndAddr
      //
      {
        target_ulong minAddr = std::numeric_limits<target_ulong>::max(), maxAddr = 0;
        for (const auto &pair : SectMap) {
          minAddr = std::min(minAddr, pair.first.lower());
          maxAddr = std::max(maxAddr, pair.first.upper());
        }

        SectsStartAddr = minAddr;
        SectsEndAddr = maxAddr;

        WithColor::note() << llvm::formatv("SectsStartAddr is {0:x}\n",
                                           SectsStartAddr);
      }
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

#ifdef TARGET_MIPS32

#define __THUNK(n, i, data)                                                    \
  JoveThunk##i##Func = Module->getFunction("_jove_thunk" #i);                  \
  assert(JoveThunk##i##Func);                                                  \
  assert(!JoveThunk##i##Func->empty());                                        \
  JoveThunk##i##Func->setLinkage(llvm::GlobalValue::InternalLinkage);

  BOOST_PP_REPEAT(5, __THUNK, void)

#undef __THUNK

#else
  JoveThunkFunc = Module->getFunction("_jove_thunk");
  assert(JoveThunkFunc);
  assert(!JoveThunkFunc->empty());
  JoveThunkFunc->setLinkage(llvm::GlobalValue::InternalLinkage);
#endif

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
  //assert(JoveRecoverFunctionFunc && !JoveRecoverFunctionFunc->empty());

  JoveAllocStackFunc = Module->getFunction("_jove_alloc_stack");
  assert(JoveAllocStackFunc);

  JoveFreeStackFunc = Module->getFunction("_jove_free_stack");
  assert(JoveFreeStackFunc);

  JoveCheckReturnAddrFunc = Module->getFunction("_jove_check_return_address");
  JoveCheckReturnAddrFunc->setLinkage(llvm::GlobalValue::InternalLinkage);
  assert(JoveCheckReturnAddrFunc);

  return 0;
}

typedef std::unordered_set<
    std::pair<binary_index_t, function_index_t>,
    boost::hash<std::pair<binary_index_t, function_index_t>>>
    hooks_t;

static hooks_t dfsanPreHooks, dfsanPostHooks;

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
};

#define PRE 1
#define POST 2

static const hook_t HookArray[] = {
#define ___HOOK1(hook_kind, rett, sym, t1)                                     \
  {                                                                            \
      .Sym = #sym,                                                             \
      .Args = {{.Size = std::is_pointer<t1>::value ? sizeof(target_ulong)      \
                                                   : sizeof(t1),               \
                .isPointer = std::is_pointer<t1>::value}},                     \
      .Ret = {.Size = sizeof(rett),                                            \
              .isPointer = std::is_pointer<rett>::value},                      \
      .Pre = !!(hook_kind & PRE),                                              \
      .Post = !!(hook_kind & POST),                                            \
  },
#define ___HOOK2(hook_kind, rett, sym, t1, t2)                                 \
  {                                                                            \
      .Sym = #sym,                                                             \
      .Args = {{.Size = std::is_pointer<t1>::value ? sizeof(target_ulong)      \
                                                   : sizeof(t1),               \
                .isPointer = std::is_pointer<t1>::value},                      \
               {.Size = std::is_pointer<t1>::value ? sizeof(target_ulong)      \
                                                   : sizeof(t2),               \
                .isPointer = std::is_pointer<t2>::value}},                     \
      .Ret = {.Size = sizeof(rett),                                            \
              .isPointer = std::is_pointer<rett>::value},                      \
      .Pre = !!(hook_kind & PRE),                                              \
      .Post = !!(hook_kind & POST),                                            \
  },
#define ___HOOK3(hook_kind, rett, sym, t1, t2, t3)                             \
  {                                                                            \
      .Sym = #sym,                                                             \
      .Args = {{.Size = std::is_pointer<t1>::value ? sizeof(target_ulong)      \
                                                   : sizeof(t1),               \
                .isPointer = std::is_pointer<t1>::value},                      \
               {.Size = std::is_pointer<t1>::value ? sizeof(target_ulong)      \
                                                   : sizeof(t2),               \
                .isPointer = std::is_pointer<t2>::value},                      \
               {.Size = std::is_pointer<t1>::value ? sizeof(target_ulong)      \
                                                   : sizeof(t3),               \
                .isPointer = std::is_pointer<t3>::value}},                     \
      .Ret = {.Size = sizeof(rett),                                            \
              .isPointer = std::is_pointer<rett>::value},                      \
      .Pre = !!(hook_kind & PRE),                                              \
      .Post = !!(hook_kind & POST),                                            \
  },
#include "dfsan_hooks.inc.h"
};

static llvm::Type *type_of_arg_info(const hook_t::arg_info_t &info) {
  if (info.isPointer)
    return llvm::PointerType::get(llvm::Type::getInt8Ty(*Context), 0);

  return llvm::Type::getIntNTy(*Context, info.Size * 8);
}

template <bool IsPreOrPost>
static std::pair<llvm::GlobalVariable *, llvm::Function *> declareHook(const hook_t &h) {
  const char *namePrefix = IsPreOrPost ? "__dfs_pre_hook_"
                                       : "__dfs_post_hook_";
  const char *gvNamePrefix = IsPreOrPost ? "__dfs_pre_hook_gv_"
                                         : "__dfs_post_hook_gv_";


  std::string name(namePrefix);
  name.append(h.Sym);

  std::string gvName(gvNamePrefix);
  gvName.append(h.Sym);

  // first check if it already exists
  if (llvm::Function *F = Module->getFunction(name)) {
    assert(F->empty());

    llvm::GlobalVariable *GV = Module->getGlobalVariable(gvName, true);
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
      llvm::FunctionType::get(VoidType(), argTypes, false);

  llvm::Function *F = llvm::Function::Create(
      FTy, llvm::GlobalValue::ExternalLinkage, name, Module.get());

  llvm::GlobalVariable *GV = new llvm::GlobalVariable(
        *Module,
        WordType(),
        false,
        llvm::GlobalValue::InternalLinkage,
        llvm::ConstantExpr::getPtrToInt(F, WordType()),
        gvName);

  return std::make_pair(GV, F);
}

static std::pair<llvm::GlobalVariable *, llvm::Function *> declarePreHook(const hook_t &h) {
  return declareHook<true>(h);
}

static std::pair<llvm::GlobalVariable *, llvm::Function *> declarePostHook(const hook_t &h) {
  return declareHook<false>(h);
}

//
// the duty of this function is to map symbol names to (BIdx, FIdx) pairs
//
int LocateHooks(void) {
  assert(opts::DFSan);

  for (unsigned i = 0; i < ARRAY_SIZE(HookArray); ++i) {
    const hook_t &h = HookArray[i];

    for (const auto &binary : Decompilation.Binaries) {
      auto &SymDynTargets = binary.Analysis.SymDynTargets;

      auto it = SymDynTargets.find(h.Sym);
      if (it == SymDynTargets.end())
        continue;

      for (std::pair<binary_index_t, function_index_t> IdxPair : (*it).second) {
        function_t &f = Decompilation.Binaries.at(IdxPair.first)
                            .Analysis.Functions.at(IdxPair.second);

        if (h.Pre && dfsanPreHooks.insert(IdxPair).second) {
          f.hook = &h;
          std::tie(f.PreHookGv, f.PreHook) = declarePreHook(h);

          llvm::outs() << llvm::formatv("pre-hook {0} @ ({1}, {2})\n",
                                        h.Sym,
                                        IdxPair.first,
                                        IdxPair.second);
        }

        if (h.Post && dfsanPostHooks.insert(IdxPair).second) {
          f.hook = &h;
          std::tie(f.PostHookGv, f.PostHook) = declarePostHook(h);

          llvm::outs() << llvm::formatv("post-hook {0} @ ({1}, {2})\n",
                                        h.Sym,
                                        IdxPair.first,
                                        IdxPair.second);
        }
      }
    }
  }

#if 0
  for (binary_index_t BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx) {
    auto &binary = Decompilation.Binaries[BIdx];
  }

  for (const auto &binary : Decompilation.Binaries) {
    auto &SymDynTargets = binary.Analysis.SymDynTargets;
    auto it = SymDynTargets.find(

    auto _it = SymDynTargets.find(SymName);
    if (_it != SymDynTargets.end()) {
      IdxPair = *(*_it).second.begin();
      break;
    }
  }
#endif

  return 0;
}

int ProcessBinaryTLSSymbols(void) {
  binary_index_t BIdx = BinaryIndex;
  auto &binary = Decompilation.Binaries[BIdx];

  assert(binary.ObjectFile);
  assert(llvm::isa<ELFO>(binary.ObjectFile.get()));
  ELFO &O = *llvm::cast<ELFO>(binary.ObjectFile.get());
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
  DynRegionInfo DynamicTable(O.getFileName());
  loadDynamicTable(&E, &O, DynamicTable);

  assert(DynamicTable.Addr);

  DynRegionInfo DynSymRegion(O.getFileName());
  llvm::StringRef DynamicStringTable;

  for (const Elf_Shdr &Sec : unwrapOrError(E.sections())) {
    if (Sec.sh_type == llvm::ELF::SHT_DYNSYM) {
      DynSymRegion = createDRIFrom(&Sec, &O);

      if (llvm::Expected<llvm::StringRef> ExpectedStringTable = E.getStringTableForSymtab(Sec)) {
        DynamicStringTable = *ExpectedStringTable;
      } else {
        std::string Buf;
        {
          llvm::raw_string_ostream OS(Buf);
          llvm::logAllUnhandledErrors(ExpectedStringTable.takeError(), OS, "");
        }

        WithColor::warning() << llvm::formatv(
            "couldn't get string table from SHT_DYNSYM: {0}\n", Buf);
      }

      break;
    }
  }

  //
  // parse dynamic table
  //
  {
    auto dynamic_table = [&DynamicTable](void) -> Elf_Dyn_Range {
      return DynamicTable.getAsArrayRef<Elf_Dyn>();
    };

    const char *StringTableBegin = nullptr;
    uint64_t StringTableSize = 0;
    for (const Elf_Dyn &Dyn : dynamic_table()) {
      if (unlikely(Dyn.d_tag == llvm::ELF::DT_NULL))
        break; /* marks end of dynamic table. */

      switch (Dyn.d_tag) {
      case llvm::ELF::DT_STRTAB:
        if (llvm::Expected<const uint8_t *> ExpectedPtr = E.toMappedAddr(Dyn.getPtr()))
          StringTableBegin = reinterpret_cast<const char *>(*ExpectedPtr);
        break;
      case llvm::ELF::DT_STRSZ:
        if (uint64_t sz = Dyn.getVal())
          StringTableSize = sz;
        break;
      case llvm::ELF::DT_SYMTAB:
        if (llvm::Expected<const uint8_t *> ExpectedPtr = E.toMappedAddr(Dyn.getPtr())) {
          const uint8_t *Ptr = *ExpectedPtr;

          if (DynSymRegion.EntSize && Ptr != DynSymRegion.Addr)
            WithColor::warning()
                << "SHT_DYNSYM section header and DT_SYMTAB disagree about "
                   "the location of the dynamic symbol table\n";

          DynSymRegion.Addr = Ptr;
          DynSymRegion.EntSize = sizeof(Elf_Sym);
        }
        break;

      default:
        break;
      }
    };

    if (StringTableBegin && StringTableSize && StringTableSize > DynamicStringTable.size())
      DynamicStringTable = llvm::StringRef(StringTableBegin, StringTableSize);
  }

  auto dynamic_symbols = [&DynSymRegion](void) -> Elf_Sym_Range {
    return DynSymRegion.getAsArrayRef<Elf_Sym>();
  };

  for (const Elf_Sym &Sym : dynamic_symbols()) {
    if (Sym.getType() != llvm::ELF::STT_TLS)
      continue;

    if (Sym.isUndefined())
      continue;

    llvm::StringRef SymName = unwrapOrError(Sym.getName(DynamicStringTable));

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

class VersionMapEntry : public llvm::PointerIntPair<const void *, 1> {
public:
  // If the integer is 0, this is an Elf_Verdef*.
  // If the integer is 1, this is an Elf_Vernaux*.
  VersionMapEntry() : PointerIntPair<const void *, 1>(nullptr, 0) {}
  VersionMapEntry(const Elf_Verdef *verdef)
      : PointerIntPair<const void *, 1>(verdef, 0) {}
  VersionMapEntry(const Elf_Vernaux *vernaux)
      : PointerIntPair<const void *, 1>(vernaux, 1) {}

  bool isNull() const { return getPointer() == nullptr; }
  bool isVerdef() const { return !isNull() && getInt() == 0; }
  bool isVernaux() const { return !isNull() && getInt() == 1; }
  const Elf_Verdef *getVerdef() const {
    return isVerdef() ? (const Elf_Verdef *)getPointer() : nullptr;
  }
  const Elf_Vernaux *getVernaux() const {
    return isVernaux() ? (const Elf_Vernaux *)getPointer() : nullptr;
  }
};

int ProcessExportedFunctions(void) {
  for (binary_index_t BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx) {
    auto &binary = Decompilation.Binaries[BIdx];
    auto &FuncMap = binary.FuncMap;

    if (!binary.ObjectFile)
      continue;

    assert(llvm::isa<ELFO>(binary.ObjectFile.get()));
    ELFO &O = *llvm::cast<ELFO>(binary.ObjectFile.get());
    const ELFF &E = *O.getELFFile();

    DynRegionInfo DynamicTable(O.getFileName());
    loadDynamicTable(&E, &O, DynamicTable);

    assert(DynamicTable.Addr);

    DynRegionInfo DynSymRegion(O.getFileName());
    llvm::StringRef DynSymtabName;
    llvm::StringRef DynamicStringTable;

    for (const Elf_Shdr &Sec : unwrapOrError(E.sections())) {
      switch (Sec.sh_type) {
      case llvm::ELF::SHT_DYNSYM:
        DynSymRegion = createDRIFrom(&Sec, &O);
        DynSymtabName = unwrapOrError(E.getSectionName(&Sec));
        DynamicStringTable = unwrapOrError(E.getStringTableForSymtab(Sec));
        break;
      }
    }

    //
    // parse dynamic table
    //
    auto dynamic_table = [&DynamicTable](void) -> Elf_Dyn_Range {
      return DynamicTable.getAsArrayRef<Elf_Dyn>();
    };

    {
      const char *StringTableBegin = nullptr;
      uint64_t StringTableSize = 0;

      for (const Elf_Dyn &Dyn : dynamic_table()) {
        if (unlikely(Dyn.d_tag == llvm::ELF::DT_NULL))
          break; /* marks end of dynamic table. */

        switch (Dyn.d_tag) {
        case llvm::ELF::DT_STRTAB:
          if (llvm::Expected<const uint8_t *> ExpectedPtr =
                  E.toMappedAddr(Dyn.getPtr()))
            StringTableBegin = reinterpret_cast<const char *>(*ExpectedPtr);
          break;
        case llvm::ELF::DT_STRSZ:
          if (uint64_t sz = Dyn.getVal())
            StringTableSize = sz;
          break;
        case llvm::ELF::DT_SYMTAB:
          if (llvm::Expected<const uint8_t *> ExpectedPtr = E.toMappedAddr(Dyn.getPtr())) {
            const uint8_t *Ptr = *ExpectedPtr;

            if (DynSymRegion.EntSize && Ptr != DynSymRegion.Addr)
              WithColor::warning()
                  << "SHT_DYNSYM section header and DT_SYMTAB disagree about "
                     "the location of the dynamic symbol table\n";

            DynSymRegion.Addr = Ptr;
            DynSymRegion.EntSize = sizeof(Elf_Sym);
          }
          break;

        default:
          break;
        }
      }

      if (StringTableBegin && StringTableSize && StringTableSize > DynamicStringTable.size())
        DynamicStringTable = llvm::StringRef(StringTableBegin, StringTableSize);
    }

    auto dynamic_symbols = [&DynSymRegion](void) -> Elf_Sym_Range {
      return DynSymRegion.getAsArrayRef<Elf_Sym>();
    };

    const Elf_Shdr *SymbolVersionSection = nullptr;     // .gnu.version
    const Elf_Shdr *SymbolVersionNeedSection = nullptr; // .gnu.version_r
    const Elf_Shdr *SymbolVersionDefSection = nullptr;  // .gnu.version_d

    for (const Elf_Shdr &Sec : unwrapOrError(E.sections())) {
      switch (Sec.sh_type) {
      case llvm::ELF::SHT_GNU_versym:
        if (!SymbolVersionSection)
          SymbolVersionSection = &Sec;
        break;

      case llvm::ELF::SHT_GNU_verdef:
        if (!SymbolVersionDefSection)
          SymbolVersionDefSection = &Sec;
        break;

      case llvm::ELF::SHT_GNU_verneed:
        if (!SymbolVersionNeedSection)
          SymbolVersionNeedSection = &Sec;
        break;
      }
    }

    llvm::SmallVector<VersionMapEntry, 16> VersionMap;

    auto LoadVersionDefs = [&](const Elf_Shdr *Sec) -> void {
      unsigned VerdefSize = Sec->sh_size;    // Size of section in bytes
      unsigned VerdefEntries = Sec->sh_info; // Number of Verdef entries
      const uint8_t *VerdefStart =
          reinterpret_cast<const uint8_t *>(E.base() + Sec->sh_offset);
      const uint8_t *VerdefEnd = VerdefStart + VerdefSize;
      // The first Verdef entry is at the start of the section.
      const uint8_t *VerdefBuf = VerdefStart;
      for (unsigned VerdefIndex = 0; VerdefIndex < VerdefEntries;
           ++VerdefIndex) {
        if (VerdefBuf + sizeof(Elf_Verdef) > VerdefEnd) {
#if 0
      report_fatal_error("Section ended unexpectedly while scanning "
                         "version definitions.");
#else
          abort();
#endif
        }

        const Elf_Verdef *Verdef =
            reinterpret_cast<const Elf_Verdef *>(VerdefBuf);
        if (Verdef->vd_version != llvm::ELF::VER_DEF_CURRENT) {
#if 0
      report_fatal_error("Unexpected verdef version");
#else
          abort();
#endif
        }

        size_t Index = Verdef->vd_ndx & llvm::ELF::VERSYM_VERSION;
        if (Index >= VersionMap.size())
          VersionMap.resize(Index + 1);
        VersionMap[Index] = VersionMapEntry(Verdef);
        VerdefBuf += Verdef->vd_next;
      }
    };

    auto LoadVersionNeeds = [&](const Elf_Shdr *Sec) -> void {
      unsigned VerneedSize = Sec->sh_size;    // Size of section in bytes
      unsigned VerneedEntries = Sec->sh_info; // Number of Verneed entries
      const uint8_t *VerneedStart =
          reinterpret_cast<const uint8_t *>(E.base() + Sec->sh_offset);
      const uint8_t *VerneedEnd = VerneedStart + VerneedSize;
      // The first Verneed entry is at the start of the section.
      const uint8_t *VerneedBuf = VerneedStart;
      for (unsigned VerneedIndex = 0; VerneedIndex < VerneedEntries;
           ++VerneedIndex) {
        if (VerneedBuf + sizeof(Elf_Verneed) > VerneedEnd) {
#if 0
        report_fatal_error("Section ended unexpectedly while scanning "
                           "version needed records.");
#else
          abort();
#endif
        }
        const Elf_Verneed *Verneed =
            reinterpret_cast<const Elf_Verneed *>(VerneedBuf);
        if (Verneed->vn_version != llvm::ELF::VER_NEED_CURRENT) {
#if 0
        report_fatal_error("Unexpected verneed version");
#else
          abort();
#endif
        }
        // Iterate through the Vernaux entries
        const uint8_t *VernauxBuf = VerneedBuf + Verneed->vn_aux;
        for (unsigned VernauxIndex = 0; VernauxIndex < Verneed->vn_cnt;
             ++VernauxIndex) {
          if (VernauxBuf + sizeof(Elf_Vernaux) > VerneedEnd) {
#if 0
          report_fatal_error(
              "Section ended unexpected while scanning auxiliary "
              "version needed records.");
#else
            abort();
#endif
          }
          const Elf_Vernaux *Vernaux =
              reinterpret_cast<const Elf_Vernaux *>(VernauxBuf);
          size_t Index = Vernaux->vna_other & llvm::ELF::VERSYM_VERSION;
          if (Index >= VersionMap.size())
            VersionMap.resize(Index + 1);
          VersionMap[Index] = VersionMapEntry(Vernaux);
          VernauxBuf += Vernaux->vna_next;
        }
        VerneedBuf += Verneed->vn_next;
      }
    };

    for (const Elf_Sym &Sym : dynamic_symbols()) {
      if (Sym.isUndefined() || Sym.getType() != llvm::ELF::STT_FUNC)
        continue;

      llvm::Expected<llvm::StringRef> ExpectedSymName = Sym.getName(DynamicStringTable);
      if (!ExpectedSymName) {
        if (unlikely(opts::Verbose)) {
          std::string Buf;
          {
            llvm::raw_string_ostream OS(Buf);
            llvm::logAllUnhandledErrors(ExpectedSymName.takeError(), OS, "");
          }

          WithColor::warning()
              << llvm::formatv("could not get symbol name ({0})\n", Buf);
        }

        continue;
      }

      llvm::StringRef SymName = *ExpectedSymName;

      function_index_t FuncIdx;
      {
        auto it = FuncMap.find(Sym.st_value);
        if (it == FuncMap.end()) {
          WithColor::warning() << llvm::formatv(
              "no function for {0} exists at 0x{1:x}\n", SymName, Sym.st_value);
          continue;
        }

        FuncIdx = (*it).second;
      }

      function_t &f = binary.Analysis.Functions[FuncIdx];
      f.IsABI = true;

      f.Syms.resize(f.Syms.size() + 1);
      symbol_t &res = f.Syms.back();

      res.Name = SymName;

      //
      // symbol versioning
      //
      if (!SymbolVersionSection) {
        res.Visibility.IsDefault = false;
      } else {
        // Determine the position in the symbol table of this entry.
        size_t EntryIndex = (reinterpret_cast<uintptr_t>(&Sym) -
                             reinterpret_cast<uintptr_t>(DynSymRegion.Addr)) /
                            sizeof(Elf_Sym);

        // Get the corresponding version index entry.
        const Elf_Versym *Versym = unwrapOrError(
            E.getEntry<Elf_Versym>(SymbolVersionSection, EntryIndex));

        auto getSymbolVersionByIndex = [&](llvm::StringRef StrTab,
                                           uint32_t SymbolVersionIndex,
                                           bool &IsDefault) -> llvm::StringRef {
          size_t VersionIndex = SymbolVersionIndex & llvm::ELF::VERSYM_VERSION;

          // Special markers for unversioned symbols.
          if (VersionIndex == llvm::ELF::VER_NDX_LOCAL ||
              VersionIndex == llvm::ELF::VER_NDX_GLOBAL) {
            IsDefault = false;
            return "";
          }

          auto LoadVersionMap = [&](void) -> void {
            // If there is no dynamic symtab or version table, there is nothing to
            // do.
            if (!DynSymRegion.Addr || !SymbolVersionSection)
              return;

            // Has the VersionMap already been loaded?
            if (!VersionMap.empty())
              return;

            // The first two version indexes are reserved.
            // Index 0 is LOCAL, index 1 is GLOBAL.
            VersionMap.push_back(VersionMapEntry());
            VersionMap.push_back(VersionMapEntry());

            if (SymbolVersionDefSection)
              LoadVersionDefs(SymbolVersionDefSection);

            if (SymbolVersionNeedSection)
              LoadVersionNeeds(SymbolVersionNeedSection);
          };

          // Lookup this symbol in the version table.
          LoadVersionMap();
          if (VersionIndex >= VersionMap.size() ||
              VersionMap[VersionIndex].isNull()) {
            WithColor::error() << "Invalid version entry\n";
            exit(1);
          }

          const VersionMapEntry &Entry = VersionMap[VersionIndex];

          // Get the version name string.
          size_t NameOffset;
          if (Entry.isVerdef()) {
            // The first Verdaux entry holds the name.
            NameOffset = Entry.getVerdef()->getAux()->vda_name;
            IsDefault = !(SymbolVersionIndex & llvm::ELF::VERSYM_HIDDEN);
          } else {
            NameOffset = Entry.getVernaux()->vna_name;
            IsDefault = false;
          }

          if (NameOffset >= StrTab.size()) {
            WithColor::error() << "Invalid string offset\n";
            return "";
          }

          return StrTab.data() + NameOffset;
        };

        res.Vers = getSymbolVersionByIndex(DynamicStringTable, Versym->vs_index,
                                           res.Visibility.IsDefault);
      }

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

      res.Addr = Sym.isUndefined() ? 0 : Sym.st_value;
      res.Type = elf_symbol_type_mapping[Sym.getType()];
      res.Size = Sym.st_size;
      res.Bind = elf_symbol_binding_mapping[Sym.getBinding()];
    }
  }

  return 0;
}

static llvm::Constant *CPUStateGlobalPointer(unsigned glb);

int ProcessDynamicSymbols(void) {
  std::set<std::pair<uintptr_t, unsigned>> gdefs;

  for (binary_index_t BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx) {
    auto &binary = Decompilation.Binaries[BIdx];
    auto &FuncMap = binary.FuncMap;

    if (!binary.ObjectFile)
      continue;

    assert(llvm::isa<ELFO>(binary.ObjectFile.get()));
    ELFO &O = *llvm::cast<ELFO>(binary.ObjectFile.get());
    const ELFF &E = *O.getELFFile();

    DynRegionInfo DynamicTable(O.getFileName());
    loadDynamicTable(&E, &O, DynamicTable);

    assert(DynamicTable.Addr);

    DynRegionInfo DynSymRegion(O.getFileName());
    llvm::StringRef DynSymtabName;
    llvm::StringRef DynamicStringTable;

    for (const Elf_Shdr &Sec : unwrapOrError(E.sections())) {
      switch (Sec.sh_type) {
      case llvm::ELF::SHT_DYNSYM:
        DynSymRegion = createDRIFrom(&Sec, &O);
        DynSymtabName = unwrapOrError(E.getSectionName(&Sec));
        DynamicStringTable = unwrapOrError(E.getStringTableForSymtab(Sec));
        break;
      }
    }

    //
    // parse dynamic table
    //
    {
      auto dynamic_table = [&DynamicTable](void) -> Elf_Dyn_Range {
        return DynamicTable.getAsArrayRef<Elf_Dyn>();
      };

      const char *StringTableBegin = nullptr;
      uint64_t StringTableSize = 0;
      for (const Elf_Dyn &Dyn : dynamic_table()) {
        if (unlikely(Dyn.d_tag == llvm::ELF::DT_NULL))
          break; /* marks end of dynamic table. */

        switch (Dyn.d_tag) {
        case llvm::ELF::DT_STRTAB:
          if (llvm::Expected<const uint8_t *> ExpectedPtr = E.toMappedAddr(Dyn.getPtr()))
            StringTableBegin = reinterpret_cast<const char *>(*ExpectedPtr);
          break;
        case llvm::ELF::DT_STRSZ:
          if (uint64_t sz = Dyn.getVal())
            StringTableSize = sz;
          break;
        case llvm::ELF::DT_SYMTAB:
          if (llvm::Expected<const uint8_t *> ExpectedPtr = E.toMappedAddr(Dyn.getPtr())) {
            const uint8_t *Ptr = *ExpectedPtr;

            if (DynSymRegion.EntSize && Ptr != DynSymRegion.Addr)
              WithColor::warning()
                  << "SHT_DYNSYM section header and DT_SYMTAB disagree about "
                     "the location of the dynamic symbol table\n";

            DynSymRegion.Addr = Ptr;
            DynSymRegion.EntSize = sizeof(Elf_Sym);
          }
          break;
        }
      };

      if (StringTableBegin && StringTableSize && StringTableSize > DynamicStringTable.size())
        DynamicStringTable = llvm::StringRef(StringTableBegin, StringTableSize);
    }

    auto dynamic_symbols = [&DynSymRegion](void) -> Elf_Sym_Range {
      return DynSymRegion.getAsArrayRef<Elf_Sym>();
    };

    const Elf_Shdr *SymbolVersionSection = nullptr;     // .gnu.version
    const Elf_Shdr *SymbolVersionNeedSection = nullptr; // .gnu.version_r
    const Elf_Shdr *SymbolVersionDefSection = nullptr;  // .gnu.version_d

    for (const Elf_Shdr &Sec : unwrapOrError(E.sections())) {
      switch (Sec.sh_type) {
      case llvm::ELF::SHT_GNU_versym:
        if (!SymbolVersionSection)
          SymbolVersionSection = &Sec;
        break;

      case llvm::ELF::SHT_GNU_verdef:
        if (!SymbolVersionDefSection)
          SymbolVersionDefSection = &Sec;
        break;

      case llvm::ELF::SHT_GNU_verneed:
        if (!SymbolVersionNeedSection)
          SymbolVersionNeedSection = &Sec;
        break;
      }
    }

    llvm::SmallVector<VersionMapEntry, 16> VersionMap;

    auto LoadVersionDefs = [&](const Elf_Shdr *Sec) -> void {
      unsigned VerdefSize = Sec->sh_size;    // Size of section in bytes
      unsigned VerdefEntries = Sec->sh_info; // Number of Verdef entries
      const uint8_t *VerdefStart =
          reinterpret_cast<const uint8_t *>(E.base() + Sec->sh_offset);
      const uint8_t *VerdefEnd = VerdefStart + VerdefSize;
      // The first Verdef entry is at the start of the section.
      const uint8_t *VerdefBuf = VerdefStart;
      for (unsigned VerdefIndex = 0; VerdefIndex < VerdefEntries;
           ++VerdefIndex) {
        if (VerdefBuf + sizeof(Elf_Verdef) > VerdefEnd) {
#if 0
      report_fatal_error("Section ended unexpectedly while scanning "
                         "version definitions.");
#else
          abort();
#endif
        }

        const Elf_Verdef *Verdef =
            reinterpret_cast<const Elf_Verdef *>(VerdefBuf);
        if (Verdef->vd_version != llvm::ELF::VER_DEF_CURRENT) {
#if 0
      report_fatal_error("Unexpected verdef version");
#else
          abort();
#endif
        }

        size_t Index = Verdef->vd_ndx & llvm::ELF::VERSYM_VERSION;
        if (Index >= VersionMap.size())
          VersionMap.resize(Index + 1);
        VersionMap[Index] = VersionMapEntry(Verdef);
        VerdefBuf += Verdef->vd_next;
      }
    };

    auto LoadVersionNeeds = [&](const Elf_Shdr *Sec) -> void {
      unsigned VerneedSize = Sec->sh_size;    // Size of section in bytes
      unsigned VerneedEntries = Sec->sh_info; // Number of Verneed entries
      const uint8_t *VerneedStart =
          reinterpret_cast<const uint8_t *>(E.base() + Sec->sh_offset);
      const uint8_t *VerneedEnd = VerneedStart + VerneedSize;
      // The first Verneed entry is at the start of the section.
      const uint8_t *VerneedBuf = VerneedStart;
      for (unsigned VerneedIndex = 0; VerneedIndex < VerneedEntries;
           ++VerneedIndex) {
        if (VerneedBuf + sizeof(Elf_Verneed) > VerneedEnd) {
#if 0
        report_fatal_error("Section ended unexpectedly while scanning "
                           "version needed records.");
#else
          abort();
#endif
        }
        const Elf_Verneed *Verneed =
            reinterpret_cast<const Elf_Verneed *>(VerneedBuf);
        if (Verneed->vn_version != llvm::ELF::VER_NEED_CURRENT) {
#if 0
        report_fatal_error("Unexpected verneed version");
#else
          abort();
#endif
        }
        // Iterate through the Vernaux entries
        const uint8_t *VernauxBuf = VerneedBuf + Verneed->vn_aux;
        for (unsigned VernauxIndex = 0; VernauxIndex < Verneed->vn_cnt;
             ++VernauxIndex) {
          if (VernauxBuf + sizeof(Elf_Vernaux) > VerneedEnd) {
#if 0
          report_fatal_error(
              "Section ended unexpected while scanning auxiliary "
              "version needed records.");
#else
            abort();
#endif
          }
          const Elf_Vernaux *Vernaux =
              reinterpret_cast<const Elf_Vernaux *>(VernauxBuf);
          size_t Index = Vernaux->vna_other & llvm::ELF::VERSYM_VERSION;
          if (Index >= VersionMap.size())
            VersionMap.resize(Index + 1);
          VersionMap[Index] = VersionMapEntry(Vernaux);
          VernauxBuf += Vernaux->vna_next;
        }
        VerneedBuf += Verneed->vn_next;
      }
    };


    for (const Elf_Sym &Sym : dynamic_symbols()) {
      if (Sym.isUndefined()) /* defined */
        continue;

      llvm::Expected<llvm::StringRef> ExpectedSymName = Sym.getName(DynamicStringTable);
      if (!ExpectedSymName) {
        std::string Buf;
        {
          llvm::raw_string_ostream OS(Buf);
          llvm::logAllUnhandledErrors(ExpectedSymName.takeError(), OS, "");
        }

        WithColor::warning() << llvm::formatv("could not get symbol name ({0})\n", Buf);
        continue;
      }

      llvm::StringRef SymName = *ExpectedSymName;

      //////////////////////////////////////////////////////
      //////////////////////////////////////////////////////
      //////////////////////////////////////////////////////

      symbol_t sym;

      sym.Name = SymName;

      //
      // symbol versioning
      //
      if (!SymbolVersionSection) {
        sym.Visibility.IsDefault = false;
      } else {
        // Determine the position in the symbol table of this entry.
        size_t EntryIndex = (reinterpret_cast<uintptr_t>(&Sym) -
                             reinterpret_cast<uintptr_t>(DynSymRegion.Addr)) /
                            sizeof(Elf_Sym);

        // Get the corresponding version index entry.
        const Elf_Versym *Versym = unwrapOrError(
            E.getEntry<Elf_Versym>(SymbolVersionSection, EntryIndex));

        auto getSymbolVersionByIndex = [&](llvm::StringRef StrTab,
                                           uint32_t SymbolVersionIndex,
                                           bool &IsDefault) -> llvm::StringRef {
          size_t VersionIndex = SymbolVersionIndex & llvm::ELF::VERSYM_VERSION;

          // Special markers for unversioned symbols.
          if (VersionIndex == llvm::ELF::VER_NDX_LOCAL ||
              VersionIndex == llvm::ELF::VER_NDX_GLOBAL) {
            IsDefault = false;
            return "";
          }

          auto LoadVersionMap = [&](void) -> void {
            // If there is no dynamic symtab or version table, there is nothing to
            // do.
            if (!DynSymRegion.Addr || !SymbolVersionSection)
              return;

            // Has the VersionMap already been loaded?
            if (!VersionMap.empty())
              return;

            // The first two version indexes are reserved.
            // Index 0 is LOCAL, index 1 is GLOBAL.
            VersionMap.push_back(VersionMapEntry());
            VersionMap.push_back(VersionMapEntry());

            if (SymbolVersionDefSection)
              LoadVersionDefs(SymbolVersionDefSection);

            if (SymbolVersionNeedSection)
              LoadVersionNeeds(SymbolVersionNeedSection);
          };

          // Lookup this symbol in the version table.
          LoadVersionMap();
          if (VersionIndex >= VersionMap.size() ||
              VersionMap[VersionIndex].isNull()) {
            WithColor::error() << "Invalid version entry\n";
            exit(1);
          }

          const VersionMapEntry &Entry = VersionMap[VersionIndex];

          // Get the version name string.
          size_t NameOffset;
          if (Entry.isVerdef()) {
            // The first Verdaux entry holds the name.
            NameOffset = Entry.getVerdef()->getAux()->vda_name;
            IsDefault = !(SymbolVersionIndex & llvm::ELF::VERSYM_HIDDEN);
          } else {
            NameOffset = Entry.getVernaux()->vna_name;
            IsDefault = false;
          }

          if (NameOffset >= StrTab.size()) {
            WithColor::error() << "Invalid string offset\n";
            return "";
          }

          return StrTab.data() + NameOffset;
        };

        sym.Vers = getSymbolVersionByIndex(DynamicStringTable, Versym->vs_index,
                                           sym.Visibility.IsDefault);
      }

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

      sym.Addr = Sym.isUndefined() ? 0 : Sym.st_value;
      sym.Type = elf_symbol_type_mapping[Sym.getType()];
      sym.Size = Sym.st_size;
      sym.Bind = elf_symbol_binding_mapping[Sym.getBinding()];

      //////////////////////////////////////////////////////
      //////////////////////////////////////////////////////
      //////////////////////////////////////////////////////

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
                << llvm::formatv("no function for {0} exists at 0x{1:x}\n",
                                 SymName, Sym.st_value);
            continue;
          }

          FuncIdx = (*it).second;
        }

        Decompilation.Binaries[BIdx].Analysis.Functions[FuncIdx].Syms.push_back(
            sym);

        ExportedFunctions[SymName].insert({BIdx, FuncIdx});
      } else if (Sym.getType() == llvm::ELF::STT_GNU_IFUNC) {
        std::pair<binary_index_t, function_index_t> IdxPair(
            invalid_binary_index, invalid_function_index);

        {
          auto &IFuncDynTargets = binary.Analysis.IFuncDynTargets;
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

        if (IdxPair.first == invalid_binary_index ||
            IdxPair.second == invalid_function_index) {
          if (BIdx == BinaryIndex)
            WithColor::warning() << llvm::formatv(
                "failed to process {0} ifunc symbol\n", SymName);
          continue;
        }

        ExportedFunctions[SymName].insert(IdxPair);

        if (BIdx == BinaryIndex) {
          auto it = FuncMap.find(Sym.st_value);
          assert(it != FuncMap.end());

          function_t &f = binary.Analysis.Functions.at((*it).second);

          f.Syms.push_back(sym);

          if (f._resolver.IFunc) {
#if 0
            llvm::GlobalAlias::create(SymName, f._resolver.IFunc);
#else
            llvm::FunctionType *FTy = DetermineFunctionType(IdxPair);

            llvm::GlobalIFunc *IFunc = llvm::GlobalIFunc::create(
                FTy, 0, llvm::GlobalValue::ExternalLinkage, SymName,
                f._resolver.IFunc->getResolver(), Module.get());
            IFuncTargetMap.insert({IFunc, IdxPair});

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
            llvm::FunctionType *FTy = DetermineFunctionType(IdxPair);

            // TODO refactor this
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

              if (IdxPair.first == BinaryIndex) {
                llvm::Constant *Res = llvm::ConstantExpr::getPtrToInt(
                    Decompilation.Binaries[BinaryIndex]
                        .Analysis.Functions.at(IdxPair.second)
                        .F,
                    WordType());

                IRB.CreateRet(IRB.CreateIntToPtr(
                    Res, CallsF->getFunctionType()->getReturnType()));
              } else if (DynTargetNeedsThunkPred(IdxPair)) {
                IRB.CreateCall(JoveInstallForeignFunctionTables)
                    ->setIsNoInline();
                IRB.CreateCall(
                       Module->getFunction("_jove_install_function_table"))
                    ->setIsNoInline();

                llvm::Value *Res = GetDynTargetAddress<true>(IRB, IdxPair);

                IRB.CreateRet(IRB.CreateIntToPtr(
                    Res, CallsF->getFunctionType()->getReturnType()));
              } else if (!Decompilation.Binaries.at(IdxPair.first).IsDynamicallyLoaded) {
                llvm::Value *Res = GetDynTargetAddress<true>(IRB, IdxPair);

                IRB.CreateRet(IRB.CreateIntToPtr(
                    Res, CallsF->getFunctionType()->getReturnType()));
              } else {
                IRB.CreateCall(JoveInstallForeignFunctionTables)
                    ->setIsNoInline();
                IRB.CreateCall(
                       Module->getFunction("_jove_install_function_table"))
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

                  llvm::Value *AlignedNewSP = IRB.CreateAnd(
                      IRB.CreatePtrToInt(NewSP, WordType()),
                      IRB.getIntN(sizeof(target_ulong) * 8,
                                  sizeof(target_ulong) == sizeof(uint32_t)
                                      ? 0xfffffff0
                                      : 0xfffffffffffffff0));

                  IRB.CreateStore(AlignedNewSP, SPPtr);
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

#if 0
            // we can't have calls to PLT entries in resolver functions
            ResolverF->setLinkage(llvm::GlobalValue::InternalLinkage);

            llvm::InlineFunctionInfo IFI;
            llvm::InlineResult InlRes = llvm::InlineFunction(Call, IFI);
            if (!InlRes)
              WithColor::error() << llvm::formatv(
                  "unable to inline IFunc resolver function ({0})\n",
                  InlRes.message);
#else
#endif

            f._resolver.IFunc = llvm::GlobalIFunc::create(
                FTy, 0, llvm::GlobalValue::ExternalLinkage, SymName, CallsF,
                Module.get());

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

            IFuncTargetMap.insert({f._resolver.IFunc, IdxPair});
          }
        }
      }
    }
  }

  return 0;
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
  binary_t &binary = Decompilation.Binaries[BinaryIndex];

  assert(llvm::isa<ELFO>(binary.ObjectFile.get()));
  ELFO &O = *llvm::cast<ELFO>(binary.ObjectFile.get());

  TheTriple = O.makeTriple();
  Features = O.getFeatures();

  const ELFF &E = *O.getELFFile();

  DynRegionInfo DynamicTable(O.getFileName());
  loadDynamicTable(&E, &O, DynamicTable);

  assert(DynamicTable.Addr);

  DynRegionInfo DynSymRegion(O.getFileName());
  llvm::StringRef DynSymtabName;
  llvm::StringRef DynamicStringTable;

  const Elf_Shdr *SymbolVersionSection = nullptr;     // .gnu.version
  const Elf_Shdr *SymbolVersionNeedSection = nullptr; // .gnu.version_r
  const Elf_Shdr *SymbolVersionDefSection = nullptr;  // .gnu.version_d

  for (const Elf_Shdr &Sec : unwrapOrError(E.sections())) {
    switch (Sec.sh_type) {
    case llvm::ELF::SHT_DYNSYM:
      DynSymRegion = createDRIFrom(&Sec, &O);
      DynSymtabName = unwrapOrError(E.getSectionName(&Sec));
      DynamicStringTable = unwrapOrError(E.getStringTableForSymtab(Sec));
      break;

    case llvm::ELF::SHT_GNU_versym:
      if (!SymbolVersionSection)
        SymbolVersionSection = &Sec;
      break;

    case llvm::ELF::SHT_GNU_verdef:
      if (!SymbolVersionDefSection)
        SymbolVersionDefSection = &Sec;
      break;

    case llvm::ELF::SHT_GNU_verneed:
      if (!SymbolVersionNeedSection)
        SymbolVersionNeedSection = &Sec;
      break;
    }
  }

  //
  // parse dynamic table
  //
  auto dynamic_table = [&DynamicTable](void) -> Elf_Dyn_Range {
    return DynamicTable.getAsArrayRef<Elf_Dyn>();
  };

  {
    const char *StringTableBegin = nullptr;
    uint64_t StringTableSize = 0;

    for (const Elf_Dyn &Dyn : dynamic_table()) {
      if (unlikely(Dyn.d_tag == llvm::ELF::DT_NULL))
        break; /* marks end of dynamic table. */

      switch (Dyn.d_tag) {
        case llvm::ELF::DT_STRTAB:
          if (llvm::Expected<const uint8_t *> ExpectedPtr = E.toMappedAddr(Dyn.getPtr()))
            StringTableBegin = reinterpret_cast<const char *>(*ExpectedPtr);
          break;
        case llvm::ELF::DT_STRSZ:
          if (uint64_t sz = Dyn.getVal())
            StringTableSize = sz;
          break;
        case llvm::ELF::DT_SYMTAB:
          if (llvm::Expected<const uint8_t *> ExpectedPtr = E.toMappedAddr(Dyn.getPtr())) {
            const uint8_t *Ptr = *ExpectedPtr;

            if (DynSymRegion.EntSize && Ptr != DynSymRegion.Addr)
              WithColor::warning()
                  << "SHT_DYNSYM section header and DT_SYMTAB disagree about "
                     "the location of the dynamic symbol table\n";

            DynSymRegion.Addr = Ptr;
            DynSymRegion.EntSize = sizeof(Elf_Sym);
          }
          break;
        default:
          break;
      }

      if (StringTableBegin && StringTableSize && StringTableSize > DynamicStringTable.size())
        DynamicStringTable = llvm::StringRef(StringTableBegin, StringTableSize);
    }
  }

  llvm::SmallVector<VersionMapEntry, 16> VersionMap;

  auto LoadVersionDefs = [&](const Elf_Shdr *Sec) -> void {
    unsigned VerdefSize = Sec->sh_size;    // Size of section in bytes
    unsigned VerdefEntries = Sec->sh_info; // Number of Verdef entries
    const uint8_t *VerdefStart =
        reinterpret_cast<const uint8_t *>(E.base() + Sec->sh_offset);
    const uint8_t *VerdefEnd = VerdefStart + VerdefSize;
    // The first Verdef entry is at the start of the section.
    const uint8_t *VerdefBuf = VerdefStart;
    for (unsigned VerdefIndex = 0; VerdefIndex < VerdefEntries; ++VerdefIndex) {
      if (VerdefBuf + sizeof(Elf_Verdef) > VerdefEnd) {
#if 0
      report_fatal_error("Section ended unexpectedly while scanning "
                         "version definitions.");
#else
        abort();
#endif
      }

      const Elf_Verdef *Verdef =
          reinterpret_cast<const Elf_Verdef *>(VerdefBuf);
      if (Verdef->vd_version != llvm::ELF::VER_DEF_CURRENT) {
#if 0
      report_fatal_error("Unexpected verdef version");
#else
        abort();
#endif
      }

      size_t Index = Verdef->vd_ndx & llvm::ELF::VERSYM_VERSION;
      if (Index >= VersionMap.size())
        VersionMap.resize(Index + 1);
      VersionMap[Index] = VersionMapEntry(Verdef);
      VerdefBuf += Verdef->vd_next;
    }
  };

  auto LoadVersionNeeds = [&](const Elf_Shdr *Sec) -> void {
    unsigned VerneedSize = Sec->sh_size;    // Size of section in bytes
    unsigned VerneedEntries = Sec->sh_info; // Number of Verneed entries
    const uint8_t *VerneedStart =
        reinterpret_cast<const uint8_t *>(E.base() + Sec->sh_offset);
    const uint8_t *VerneedEnd = VerneedStart + VerneedSize;
    // The first Verneed entry is at the start of the section.
    const uint8_t *VerneedBuf = VerneedStart;
    for (unsigned VerneedIndex = 0; VerneedIndex < VerneedEntries;
         ++VerneedIndex) {
      if (VerneedBuf + sizeof(Elf_Verneed) > VerneedEnd) {
#if 0
        report_fatal_error("Section ended unexpectedly while scanning "
                           "version needed records.");
#else
        abort();
#endif
      }
      const Elf_Verneed *Verneed =
          reinterpret_cast<const Elf_Verneed *>(VerneedBuf);
      if (Verneed->vn_version != llvm::ELF::VER_NEED_CURRENT) {
#if 0
        report_fatal_error("Unexpected verneed version");
#else
        abort();
#endif
      }
      // Iterate through the Vernaux entries
      const uint8_t *VernauxBuf = VerneedBuf + Verneed->vn_aux;
      for (unsigned VernauxIndex = 0; VernauxIndex < Verneed->vn_cnt;
           ++VernauxIndex) {
        if (VernauxBuf + sizeof(Elf_Vernaux) > VerneedEnd) {
#if 0
          report_fatal_error(
              "Section ended unexpected while scanning auxiliary "
              "version needed records.");
#else
          abort();
#endif
        }
        const Elf_Vernaux *Vernaux =
            reinterpret_cast<const Elf_Vernaux *>(VernauxBuf);
        size_t Index = Vernaux->vna_other & llvm::ELF::VERSYM_VERSION;
        if (Index >= VersionMap.size())
          VersionMap.resize(Index + 1);
        VersionMap[Index] = VersionMapEntry(Vernaux);
        VernauxBuf += Vernaux->vna_next;
      }
      VerneedBuf += Verneed->vn_next;
    }
  };

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

    //
    // symbol versioning
    //
    if (!SymbolVersionSection) {
      res.Visibility.IsDefault = false;
    } else {
      // Determine the position in the symbol table of this entry.
      size_t EntryIndex = (reinterpret_cast<uintptr_t>(&Sym) -
                           reinterpret_cast<uintptr_t>(DynSymRegion.Addr)) /
                          sizeof(Elf_Sym);

      // Get the corresponding version index entry.
      const Elf_Versym *Versym = unwrapOrError(
          E.getEntry<Elf_Versym>(SymbolVersionSection, EntryIndex));

      auto getSymbolVersionByIndex = [&](llvm::StringRef StrTab,
                                         uint32_t SymbolVersionIndex,
                                         bool &IsDefault) -> llvm::StringRef {
        size_t VersionIndex = SymbolVersionIndex & llvm::ELF::VERSYM_VERSION;

        // Special markers for unversioned symbols.
        if (VersionIndex == llvm::ELF::VER_NDX_LOCAL ||
            VersionIndex == llvm::ELF::VER_NDX_GLOBAL) {
          IsDefault = false;
          return "";
        }

        auto LoadVersionMap = [&](void) -> void {
          // If there is no dynamic symtab or version table, there is nothing to
          // do.
          if (!DynSymRegion.Addr || !SymbolVersionSection)
            return;

          // Has the VersionMap already been loaded?
          if (!VersionMap.empty())
            return;

          // The first two version indexes are reserved.
          // Index 0 is LOCAL, index 1 is GLOBAL.
          VersionMap.push_back(VersionMapEntry());
          VersionMap.push_back(VersionMapEntry());

          if (SymbolVersionDefSection)
            LoadVersionDefs(SymbolVersionDefSection);

          if (SymbolVersionNeedSection)
            LoadVersionNeeds(SymbolVersionNeedSection);
        };

        // Lookup this symbol in the version table.
        LoadVersionMap();
        if (VersionIndex >= VersionMap.size() ||
            VersionMap[VersionIndex].isNull()) {
          WithColor::error() << "Invalid version entry\n";
          exit(1);
        }

        const VersionMapEntry &Entry = VersionMap[VersionIndex];

        // Get the version name string.
        size_t NameOffset;
        if (Entry.isVerdef()) {
          // The first Verdaux entry holds the name.
          NameOffset = Entry.getVerdef()->getAux()->vda_name;
          IsDefault = !(SymbolVersionIndex & llvm::ELF::VERSYM_HIDDEN);
        } else {
          NameOffset = Entry.getVernaux()->vna_name;
          IsDefault = false;
        }

        if (NameOffset >= StrTab.size()) {
          WithColor::error() << "Invalid string offset\n";
          return "";
        }

        return StrTab.data() + NameOffset;
      };

      res.Vers = getSymbolVersionByIndex(DynamicStringTable, Versym->vs_index,
                                         res.Visibility.IsDefault);
    }

#if 0
    llvm::errs() << llvm::formatv("Name={0} Vers={1} IsDefault={2}\n", res.Name,
                                  res.Vers, res.Visibility.IsDefault);
#endif

    res.Addr = Sym.isUndefined() ? 0 : Sym.st_value;
    res.Type = elf_symbol_type_mapping[Sym.getType()];
    res.Size = Sym.st_size;
    res.Bind = elf_symbol_binding_mapping[Sym.getBinding()];

#if 1
    if (res.Type == symbol_t::TYPE::NONE &&
        res.Bind == symbol_t::BINDING::WEAK && !res.Addr) {
      WithColor::warning() << llvm::formatv("making {0} into function symbol\n",
                                            res.Name);
      res.Type = symbol_t::TYPE::FUNCTION;
    }
#endif

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


    if (E.isMips64EL()) {
      unsigned Type = R.getType(E.isMips64EL());

      // The Mips N64 ABI allows up to three operations to be specified per
      // relocation record. Unfortunately there's no easy way to test for the
      // presence of N64 ELFs as they have no special flag that identifies them
      // as being N64. We can safely assume at the moment that all Mips
      // ELFCLASS64 ELFs are N64. New Mips64 ABIs should provide enough
      // information to disambiguate between old vs new ABIs.
      uint8_t Type1 = (Type >> 0) & 0xFF;
      uint8_t Type2 = (Type >> 8) & 0xFF;
      uint8_t Type3 = (Type >> 16) & 0xFF;

      relocation_t::TYPE RelType1 = relocation_type_of_elf_rel_type(Type1);
      relocation_t::TYPE RelType2 = relocation_type_of_elf_rel_type(Type2);
      relocation_t::TYPE RelType3 = relocation_type_of_elf_rel_type(Type3);

      bool Rel1None = RelType1 == relocation_t::TYPE::NONE;
      bool Rel2None = RelType2 == relocation_t::TYPE::NONE;
      bool Rel3None = RelType3 == relocation_t::TYPE::NONE;

      res.Type = relocation_t::TYPE::NONE;
      if (!Rel1None)
        res.Type = RelType1;
      else if (!Rel2None)
        res.Type = RelType2;
      else if (!Rel3None)
        res.Type = RelType3;
    } else {
      res.Type = relocation_type_of_elf_rel_type(R.getType(E.isMips64EL()));
    }

    res.Addr = R.r_offset;
    res.Addend = 0;

    E.getRelocationTypeName(R.getType(E.isMips64EL()), res.RelocationTypeName);

    if (res.Type != relocation_t::TYPE::NONE)
      RelocationTable.push_back(res);
    else
      WithColor::warning() << llvm::formatv("unrecognized relocation: {0}\n",
                                            res.RelocationTypeName);
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

    if (E.isMips64EL()) {
      unsigned Type = R.getType(E.isMips64EL());

      // The Mips N64 ABI allows up to three operations to be specified per
      // relocation record. Unfortunately there's no easy way to test for the
      // presence of N64 ELFs as they have no special flag that identifies them
      // as being N64. We can safely assume at the moment that all Mips
      // ELFCLASS64 ELFs are N64. New Mips64 ABIs should provide enough
      // information to disambiguate between old vs new ABIs.
      uint8_t Type1 = (Type >> 0) & 0xFF;
      uint8_t Type2 = (Type >> 8) & 0xFF;
      uint8_t Type3 = (Type >> 16) & 0xFF;

      relocation_t::TYPE RelType1 = relocation_type_of_elf_rela_type(Type1);
      relocation_t::TYPE RelType2 = relocation_type_of_elf_rela_type(Type2);
      relocation_t::TYPE RelType3 = relocation_type_of_elf_rela_type(Type3);

      bool Rel1None = RelType1 == relocation_t::TYPE::NONE;
      bool Rel2None = RelType2 == relocation_t::TYPE::NONE;
      bool Rel3None = RelType3 == relocation_t::TYPE::NONE;

      res.Type = relocation_t::TYPE::NONE;
      if (!Rel1None)
        res.Type = RelType1;
      else if (!Rel2None)
        res.Type = RelType2;
      else if (!Rel3None)
        res.Type = RelType3;
    } else {
      res.Type = relocation_type_of_elf_rela_type(R.getType(E.isMips64EL()));
    }

    res.Addr = R.r_offset;
    res.Addend = R.r_addend;

    E.getRelocationTypeName(R.getType(E.isMips64EL()), res.RelocationTypeName);

    if (res.Type != relocation_t::TYPE::NONE)
      RelocationTable.push_back(res);
    else
      WithColor::warning() << llvm::formatv("unrecognized relocation: {0}\n",
                                            res.RelocationTypeName);
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

#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
  //
  // on MIPS there is an arch-specific representation of the GOT.
  //
  auto dynamic_symbols = [&DynSymRegion](void) -> Elf_Sym_Range {
    return DynSymRegion.getAsArrayRef<Elf_Sym>();
  };

  MipsGOTParser Parser(&E,
                       dynamic_table(),
                       dynamic_symbols());

  for (const MipsGOTParser::Entry &Ent : Parser.getLocalEntries()) {
    const target_ulong Addr = Parser.getGotAddress(&Ent);

    llvm::outs() << llvm::formatv("LocalEntry: {0:x}\n", Addr);

    relocation_t res;
    res.Type = relocation_t::TYPE::RELATIVE;
    res.Addr = Addr;
    res.Addend = 0;
    res.SymbolIndex = std::numeric_limits<unsigned>::max();
    res.T = nullptr;
    res.C = nullptr;
    res.RelocationTypeName = "LocalGOTEntry";

    RelocationTable.push_back(res);
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


    llvm::Expected<llvm::StringRef> ExpectedSymName = Sym->getName(DynamicStringTable);
    if (!ExpectedSymName) {
      std::string Buf;
      {
        llvm::raw_string_ostream OS(Buf);
        llvm::logAllUnhandledErrors(ExpectedSymName.takeError(), OS, "");
      }

      WithColor::note() << llvm::formatv("MipsGOTParser: could not get sym name: {0}\n",
                                         Buf);
      continue;
    }

    llvm::StringRef SymName = *ExpectedSymName;

    llvm::outs() << llvm::formatv("GlobalEntry: {0} {1}\n", Ent,
                                  SymName);

    relocation_t res;
    res.Type = relocation_t::TYPE::ADDRESSOF;
    res.Addr = Addr;
    res.Addend = 0;
    res.SymbolIndex = SymbolTable.size();
    {
      symbol_t sym;

      sym.Name = SymName;
      sym.Addr = is_undefined ? 0 : Sym->st_value;
      sym.Visibility.IsDefault = false;

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

      sym.Type = elf_symbol_type_mapping[Sym->getType()];
      sym.Size = Sym->st_size;

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

      sym.Bind = elf_symbol_binding_mapping[Sym->getBinding()];

      SymbolTable.push_back(sym);
    }

    res.T = nullptr;
    res.C = nullptr;
    res.RelocationTypeName = "GlobalGOTEntry";

    RelocationTable.push_back(res);
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
         % sym.Name.str()
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
  auto &SectMap = Decompilation.Binaries[BinaryIndex].SectMap;
  auto &FuncMap = Decompilation.Binaries[BinaryIndex].FuncMap;
  const unsigned NumSections = SectMap.iterative_size();

  //
  // create sections table and address -> section index map
  //
  std::vector<section_t> SectTable;
  SectTable.resize(NumSections);

  boost::icl::interval_map<target_ulong, unsigned> SectIdxMap;

  {
    target_ulong minAddr = std::numeric_limits<target_ulong>::max(), maxAddr = 0;
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
          boost::icl::interval<target_ulong>::right_open(0, Sect.Size));
      Sect.initArray = prop.initArray;
      Sect.finiArray = prop.finiArray;

      ++i;
    }
  }

  auto &binary = Decompilation.Binaries[BinaryIndex];

  for (const relocation_t &R : RelocationTable) {
    if (R.Type != relocation_t::TYPE::IRELATIVE)
      continue;

    target_ulong ifunc_resolver_addr = R.Addend;
    if (!ifunc_resolver_addr) {
      // TODO refactor
      auto it = SectIdxMap.find(R.Addr);
      assert(it != SectIdxMap.end());

      section_t &Sect = SectTable[(*it).second];
      unsigned Off = R.Addr - Sect.Addr;

      assert(!Sect.Contents.empty());
      ifunc_resolver_addr = *reinterpret_cast<const target_ulong *>(&Sect.Contents[Off]);
    }
    assert(ifunc_resolver_addr);

    auto it = FuncMap.find(ifunc_resolver_addr);
    assert(it != FuncMap.end());

    function_t &resolver = binary.Analysis.Functions[(*it).second];
    resolver.IsABI = true;

    // TODO we know function type is i64 (*)(void)
  }

  assert(llvm::isa<ELFO>(binary.ObjectFile.get()));
  ELFO &O = *llvm::cast<ELFO>(binary.ObjectFile.get());
  const ELFF &E = *O.getELFFile();

  DynRegionInfo DynamicTable(O.getFileName());
  loadDynamicTable(&E, &O, DynamicTable);

  assert(DynamicTable.Addr);

  DynRegionInfo DynSymRegion(O.getFileName());
  llvm::StringRef DynSymtabName;
  llvm::StringRef DynamicStringTable;

  for (const Elf_Shdr &Sec : unwrapOrError(E.sections())) {
    switch (Sec.sh_type) {
    case llvm::ELF::SHT_DYNSYM:
      DynSymRegion = createDRIFrom(&Sec, &O);
      DynSymtabName = unwrapOrError(E.getSectionName(&Sec));
      DynamicStringTable = unwrapOrError(E.getStringTableForSymtab(Sec));
      break;
    }
  }

  //
  // parse dynamic table
  //
  auto dynamic_table = [&DynamicTable](void) -> Elf_Dyn_Range {
    return DynamicTable.getAsArrayRef<Elf_Dyn>();
  };

  {
    const char *StringTableBegin = nullptr;
    uint64_t StringTableSize = 0;
    for (const Elf_Dyn &Dyn : dynamic_table()) {
      if (unlikely(Dyn.d_tag == llvm::ELF::DT_NULL))
        break; /* marks end of dynamic table. */

      switch (Dyn.d_tag) {
      case llvm::ELF::DT_STRTAB:
        if (llvm::Expected<const uint8_t *> ExpectedPtr = E.toMappedAddr(Dyn.getPtr()))
          StringTableBegin = reinterpret_cast<const char *>(*ExpectedPtr);
        break;
      case llvm::ELF::DT_STRSZ:
        if (uint64_t sz = Dyn.getVal())
          StringTableSize = sz;
        break;
      case llvm::ELF::DT_SYMTAB:
        if (llvm::Expected<const uint8_t *> ExpectedPtr = E.toMappedAddr(Dyn.getPtr())) {
          const uint8_t *Ptr = *ExpectedPtr;

          if (DynSymRegion.EntSize && Ptr != DynSymRegion.Addr)
            WithColor::warning()
                << "SHT_DYNSYM section header and DT_SYMTAB disagree about "
                   "the location of the dynamic symbol table\n";

          DynSymRegion.Addr = Ptr;
          DynSymRegion.EntSize = sizeof(Elf_Sym);
        }
        break;
      }
    };

    if (StringTableBegin && StringTableSize && StringTableSize > DynamicStringTable.size())
      DynamicStringTable = llvm::StringRef(StringTableBegin, StringTableSize);
  }

  auto dynamic_symbols = [&DynSymRegion](void) -> Elf_Sym_Range {
    return DynSymRegion.getAsArrayRef<Elf_Sym>();
  };

  for (const Elf_Sym &Sym : dynamic_symbols()) {
    if (Sym.isUndefined()) /* defined */
      continue;
    if (Sym.getType() != llvm::ELF::STT_GNU_IFUNC)
      continue;

    auto it = FuncMap.find(Sym.st_value);
    if (it == FuncMap.end()) {
      WithColor::error() << llvm::formatv("Sym.st_value=0x{0:x}\n",
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
    f.IsABI = true;
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

    if (!f.IsABI && !f.Syms.empty()) {
      WithColor::error() << llvm::formatv(
          "!f.IsABI && !f.Syms.empty() where f.Syms[0] is {0} {1}\n",
          f.Syms.front().Name, f.Syms.front().Vers);
      return 1;
    }

    if (!is_basic_block_index_valid(f.Entry))
      continue;

    std::string jove_name = (fmt("%c%lx") % (f.IsABI ? 'J' : 'j') %
                             ICFG[boost::vertex(f.Entry, ICFG)].Addr)
                                .str();

    f.F = llvm::Function::Create(DetermineFunctionType(f),
                                 llvm::GlobalValue::ExternalLinkage, jove_name,
                                 Module.get());
#if defined(TARGET_I386)
    if (f.IsABI) {
      for (unsigned i = 0; i < f.F->arg_size(); ++i) {
        f.F->addParamAttr(i, llvm::Attribute::InReg);
      }
    }
#endif

    //f.F->addFnAttr(llvm::Attribute::UWTable);

    target_ulong Addr = ICFG[boost::vertex(f.Entry, ICFG)].Addr;
    unsigned off = Addr - SectsStartAddr;

    for (const symbol_t &sym : f.Syms) {
      if (sym.Vers.empty()) {
#if 0
        llvm::GlobalAlias::create(sym.Name, f.F);
#else
        Module->appendModuleInlineAsm(
            (fmt(".globl %s\n"
                 ".type  %s,@function\n"
                 ".set   %s, __jove_sections_%u + %u")
             % sym.Name.str()
             % sym.Name.str()
             % sym.Name.str() % BinaryIndex % off).str());
#endif
      } else {
         // make sure version node is defined
        VersionScript.Table[sym.Vers.str()];

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

    if (!is_basic_block_index_valid(f.Entry)) {
      constantTable[2 * i + 0] = llvm::Constant::getNullValue(WordType());
      constantTable[2 * i + 1] = llvm::Constant::getNullValue(WordType());
      continue;
    }

    target_ulong Addr = ICFG[boost::vertex(f.Entry, ICFG)].Addr;

    llvm::Constant *C1 = SectionPointer(Addr);
    llvm::Constant *C2 = f.IsABI
                             ? llvm::ConstantExpr::getPtrToInt(f.F, WordType())
                             : llvm::Constant::getNullValue(WordType());

    constantTable[2 * i + 0] = C1;
    constantTable[2 * i + 1] = C2;
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
  assert(SectsStartAddr);
  assert(SectsEndAddr);

  int64_t off =
      static_cast<int64_t>(Addr) -
      static_cast<int64_t>(SectsStartAddr);

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
  auto &SectMap = Decompilation.Binaries[BinaryIndex].SectMap;
  auto &FuncMap = Decompilation.Binaries[BinaryIndex].FuncMap;
  const unsigned NumSections = SectMap.iterative_size();

  //
  // create sections table and address -> section index map
  //
  std::vector<section_t> SectTable;
  SectTable.resize(NumSections);

  boost::icl::interval_map<target_ulong, unsigned> SectIdxMap;

  {
    target_ulong minAddr = std::numeric_limits<target_ulong>::max(), maxAddr = 0;
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
          boost::icl::interval<target_ulong>::right_open(0, Sect.Size));
      Sect.initArray = prop.initArray;
      Sect.finiArray = prop.finiArray;

      ++i;
    }

    SectsStartAddr = minAddr;
    SectsEndAddr = maxAddr;
  }

#if defined(TARGET_MIPS32) || defined(TARGET_MIPS64)

  //
  // on mips, we cannot rely on the SectionsGlobal to be not placed in
  // non executable memory (see READ_IMPLIES_EXEC)
  //
  struct PatchContents {
    boost::icl::interval_map<target_ulong, unsigned> &SectIdxMap;
    std::vector<section_t> &SectTable;

    std::vector<uint32_t> FunctionOrigInsnTable;

    PatchContents(boost::icl::interval_map<target_ulong, unsigned> &SectIdxMap,
                  std::vector<section_t> &SectTable)
      : SectIdxMap(SectIdxMap),
        SectTable(SectTable) {
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
      auto it = SectIdxMap.find(Addr);
      assert(it != SectIdxMap.end());

      section_t &Sect = SectTable[(*it).second];
      unsigned Off = Addr - Sect.Addr;

      return const_cast<unsigned char *>(&Sect.Contents[Off]);
    }
  } __PatchContents(SectIdxMap, SectTable);
#endif

  auto type_at_address = [&](target_ulong Addr, llvm::Type *T) -> void {
    auto it = SectIdxMap.find(Addr);
    assert(it != SectIdxMap.end());

    section_t &Sect = SectTable[(*it).second];
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
          "copy relocation @ 0x{0:x} specifies symbol {1} with size 0\n",
          R.Addr, S.Name);
      abort();
    }

    WithColor::error() << llvm::formatv(
        "copy relocation @ 0x{0:x} specifies symbol {1} with size {2}\n"
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

    section_t &Sect = SectTable[(*it).second];
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
      if (it == RelocDynTargets.end() || (*it).second.empty()) {
        WithColor::error() << llvm::formatv(
            "{0}:{1} have you run jove-dyn? (symbol: {2})\n", __FILE__,
            __LINE__, S.Name);

        FTy = llvm::FunctionType::get(VoidType(), false);
      } else {
        auto &DynTargets = (*it).second;

        for (std::pair<binary_index_t, function_index_t> pair : DynTargets) {
          if (pair.first == BinaryIndex)
            continue;

          FTy = DetermineFunctionType(pair);
          break;
        }

        if (!FTy)
          FTy = DetermineFunctionType(*DynTargets.begin());
      }
    }

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

    //auto it = FuncMap.find(S.Addr);
    //assert(it != FuncMap.end());

#if 0
    return Decompilation.Binaries[BinaryIndex]
        .Analysis.Functions[(*it).second]
        .F;
#else
    return SectionPointer(S.Addr);
#endif
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

  auto constant_of_addressof_defined_data_relocation =
      [&](const relocation_t &R, const symbol_t &S) -> llvm::Constant * {
    assert(!S.IsUndefined());

    if (llvm::GlobalValue *GV = Module->getNamedValue(S.Name))
      return llvm::ConstantExpr::getPtrToInt(GV, WordType());

    AddrToSymbolMap[S.Addr].insert(S.Name);
    AddrToSizeMap[S.Addr] = S.Size;

    return nullptr;
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
      auto it = SectIdxMap.find(R.Addr);
      assert(it != SectIdxMap.end());

      section_t &Sect = SectTable[(*it).second];
      unsigned Off = R.Addr - Sect.Addr;

      assert(!Sect.Contents.empty());
      Addr = *reinterpret_cast<const target_ulong *>(&Sect.Contents[Off]);
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
        WithColor::error() << llvm::formatv("{0}:{1} have you run jove-dyn?\n",
                                            __FILE__, __LINE__);
        abort();
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

      return llvm::ConstantExpr::getPtrToInt(GV, WordType());
    }

#if defined(TARGET_I386) || defined(TARGET_MIPS32)
    unsigned tpoff;
    {
      auto it = SectIdxMap.find(R.Addr);
      assert(it != SectIdxMap.end());

      section_t &Sect = SectTable[(*it).second];
      unsigned Off = R.Addr - Sect.Addr;

      assert(!Sect.Contents.empty());
      tpoff = *reinterpret_cast<const target_ulong *>(&Sect.Contents[Off]);
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

    return llvm::ConstantExpr::getPtrToInt(GV, WordType());
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
    section_t &Sect = SectTable[(*it).second];
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
             % sym.Name.str()
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
             % sym.Name.str()
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

    DynRegionInfo DynamicTable(O.getFileName());
    loadDynamicTable(&E, &O, DynamicTable);

    assert(DynamicTable.Addr);

    //
    // parse dynamic table
    //
    auto dynamic_table = [&DynamicTable](void) -> Elf_Dyn_Range {
      return DynamicTable.getAsArrayRef<Elf_Dyn>();
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

    if (initFunctionAddr) {
      llvm::appendToGlobalCtors(
          *Module,
          (llvm::Function *)llvm::ConstantExpr::getIntToPtr(
              SectionPointer(initFunctionAddr), VoidFunctionPointer()),
          0);
    }
  }

  // XXX clean this up
  std::unordered_map<llvm::Function *, function_index_t> LLVMFnToJoveFnMap;

  {
    for (function_index_t fidx = 0;
         fidx < Decompilation.Binaries[BinaryIndex].Analysis.Functions.size();
         ++fidx) {
      function_t &f =
          Decompilation.Binaries[BinaryIndex].Analysis.Functions.at(fidx);
      LLVMFnToJoveFnMap.insert({f.F, fidx});
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
    auto &binary = Decompilation.Binaries[BIdx];
    auto &FuncMap = binary.FuncMap;

    if (!binary.ObjectFile)
      continue;

    assert(llvm::isa<ELFO>(binary.ObjectFile.get()));
    ELFO &O = *llvm::cast<ELFO>(binary.ObjectFile.get());
    const ELFF &E = *O.getELFFile();

    DynRegionInfo DynamicTable(O.getFileName());
    loadDynamicTable(&E, &O, DynamicTable);

    assert(DynamicTable.Addr);

    DynRegionInfo DynSymRegion(O.getFileName());
    llvm::StringRef DynSymtabName;
    llvm::StringRef DynamicStringTable;

    for (const Elf_Shdr &Sec : unwrapOrError(E.sections())) {
      switch (Sec.sh_type) {
      case llvm::ELF::SHT_DYNSYM:
        DynSymRegion = createDRIFrom(&Sec, &O);
        DynSymtabName = unwrapOrError(E.getSectionName(&Sec));
        DynamicStringTable = unwrapOrError(E.getStringTableForSymtab(Sec));
        break;
      }
    }

    //
    // parse dynamic table
    //
    {
      auto dynamic_table = [&DynamicTable](void) -> Elf_Dyn_Range {
        return DynamicTable.getAsArrayRef<Elf_Dyn>();
      };

      const char *StringTableBegin = nullptr;
      uint64_t StringTableSize = 0;
      for (const Elf_Dyn &Dyn : dynamic_table()) {
        if (unlikely(Dyn.d_tag == llvm::ELF::DT_NULL))
          break; /* marks end of dynamic table. */

        switch (Dyn.d_tag) {
        case llvm::ELF::DT_STRTAB:
          if (llvm::Expected<const uint8_t *> ExpectedPtr = E.toMappedAddr(Dyn.getPtr()))
            StringTableBegin = reinterpret_cast<const char *>(*ExpectedPtr);
          break;
        case llvm::ELF::DT_STRSZ:
          if (uint64_t sz = Dyn.getVal())
            StringTableSize = sz;
          break;
        case llvm::ELF::DT_SYMTAB:
          if (llvm::Expected<const uint8_t *> ExpectedPtr = E.toMappedAddr(Dyn.getPtr())) {
            const uint8_t *Ptr = *ExpectedPtr;

            if (DynSymRegion.EntSize && Ptr != DynSymRegion.Addr)
              WithColor::warning()
                  << "SHT_DYNSYM section header and DT_SYMTAB disagree about "
                     "the location of the dynamic symbol table\n";

            DynSymRegion.Addr = Ptr;
            DynSymRegion.EntSize = sizeof(Elf_Sym);
          }
          break;
        }
      }

      if (StringTableBegin && StringTableSize &&
          StringTableSize > DynamicStringTable.size())
        DynamicStringTable = llvm::StringRef(StringTableBegin, StringTableSize);
    }

    auto dynamic_symbols = [&DynSymRegion](void) -> Elf_Sym_Range {
      return DynSymRegion.getAsArrayRef<Elf_Sym>();
    };

    const Elf_Shdr *SymbolVersionSection = nullptr;     // .gnu.version
    const Elf_Shdr *SymbolVersionNeedSection = nullptr; // .gnu.version_r
    const Elf_Shdr *SymbolVersionDefSection = nullptr;  // .gnu.version_d

    for (const Elf_Shdr &Sec : unwrapOrError(E.sections())) {
      switch (Sec.sh_type) {
      case llvm::ELF::SHT_GNU_versym:
        if (!SymbolVersionSection)
          SymbolVersionSection = &Sec;
        break;

      case llvm::ELF::SHT_GNU_verdef:
        if (!SymbolVersionDefSection)
          SymbolVersionDefSection = &Sec;
        break;

      case llvm::ELF::SHT_GNU_verneed:
        if (!SymbolVersionNeedSection)
          SymbolVersionNeedSection = &Sec;
        break;
      }
    }

    llvm::SmallVector<VersionMapEntry, 16> VersionMap;

    auto LoadVersionDefs = [&](const Elf_Shdr *Sec) -> void {
      unsigned VerdefSize = Sec->sh_size;    // Size of section in bytes
      unsigned VerdefEntries = Sec->sh_info; // Number of Verdef entries
      const uint8_t *VerdefStart =
          reinterpret_cast<const uint8_t *>(E.base() + Sec->sh_offset);
      const uint8_t *VerdefEnd = VerdefStart + VerdefSize;
      // The first Verdef entry is at the start of the section.
      const uint8_t *VerdefBuf = VerdefStart;
      for (unsigned VerdefIndex = 0; VerdefIndex < VerdefEntries;
           ++VerdefIndex) {
        if (VerdefBuf + sizeof(Elf_Verdef) > VerdefEnd) {
#if 0
      report_fatal_error("Section ended unexpectedly while scanning "
                         "version definitions.");
#else
          abort();
#endif
        }

        const Elf_Verdef *Verdef =
            reinterpret_cast<const Elf_Verdef *>(VerdefBuf);
        if (Verdef->vd_version != llvm::ELF::VER_DEF_CURRENT) {
#if 0
      report_fatal_error("Unexpected verdef version");
#else
          abort();
#endif
        }

        size_t Index = Verdef->vd_ndx & llvm::ELF::VERSYM_VERSION;
        if (Index >= VersionMap.size())
          VersionMap.resize(Index + 1);
        VersionMap[Index] = VersionMapEntry(Verdef);
        VerdefBuf += Verdef->vd_next;
      }
    };

    auto LoadVersionNeeds = [&](const Elf_Shdr *Sec) -> void {
      unsigned VerneedSize = Sec->sh_size;    // Size of section in bytes
      unsigned VerneedEntries = Sec->sh_info; // Number of Verneed entries
      const uint8_t *VerneedStart =
          reinterpret_cast<const uint8_t *>(E.base() + Sec->sh_offset);
      const uint8_t *VerneedEnd = VerneedStart + VerneedSize;
      // The first Verneed entry is at the start of the section.
      const uint8_t *VerneedBuf = VerneedStart;
      for (unsigned VerneedIndex = 0; VerneedIndex < VerneedEntries;
           ++VerneedIndex) {
        if (VerneedBuf + sizeof(Elf_Verneed) > VerneedEnd) {
#if 0
        report_fatal_error("Section ended unexpectedly while scanning "
                           "version needed records.");
#else
          abort();
#endif
        }
        const Elf_Verneed *Verneed =
            reinterpret_cast<const Elf_Verneed *>(VerneedBuf);
        if (Verneed->vn_version != llvm::ELF::VER_NEED_CURRENT) {
#if 0
        report_fatal_error("Unexpected verneed version");
#else
          abort();
#endif
        }
        // Iterate through the Vernaux entries
        const uint8_t *VernauxBuf = VerneedBuf + Verneed->vn_aux;
        for (unsigned VernauxIndex = 0; VernauxIndex < Verneed->vn_cnt;
             ++VernauxIndex) {
          if (VernauxBuf + sizeof(Elf_Vernaux) > VerneedEnd) {
#if 0
          report_fatal_error(
              "Section ended unexpected while scanning auxiliary "
              "version needed records.");
#else
            abort();
#endif
          }
          const Elf_Vernaux *Vernaux =
              reinterpret_cast<const Elf_Vernaux *>(VernauxBuf);
          size_t Index = Vernaux->vna_other & llvm::ELF::VERSYM_VERSION;
          if (Index >= VersionMap.size())
            VersionMap.resize(Index + 1);
          VersionMap[Index] = VersionMapEntry(Vernaux);
          VernauxBuf += Vernaux->vna_next;
        }
        VerneedBuf += Verneed->vn_next;
      }
    };


    for (const Elf_Sym &Sym : dynamic_symbols()) {
      if (Sym.isUndefined()) /* defined */
        continue;

      llvm::Expected<llvm::StringRef> ExpectedSymName = Sym.getName(DynamicStringTable);

      if (WARN_ON(!ExpectedSymName)) {
        std::string Buf;
        {
          llvm::raw_string_ostream OS(Buf);
          llvm::logAllUnhandledErrors(ExpectedSymName.takeError(), OS, "");
        }

        WithColor::warning() << llvm::formatv("could not get symbol name ({0})\n", Buf);
        continue;
      }

      llvm::StringRef SymName = *ExpectedSymName;

      //////////////////////////////////////////////////////
      //////////////////////////////////////////////////////
      //////////////////////////////////////////////////////

      symbol_t sym;

      sym.Name = SymName;

      //
      // symbol versioning
      //
      if (!SymbolVersionSection) {
        sym.Visibility.IsDefault = false;
      } else {
        // Determine the position in the symbol table of this entry.
        size_t EntryIndex = (reinterpret_cast<uintptr_t>(&Sym) -
                             reinterpret_cast<uintptr_t>(DynSymRegion.Addr)) /
                            sizeof(Elf_Sym);

        // Get the corresponding version index entry.
        const Elf_Versym *Versym = unwrapOrError(
            E.getEntry<Elf_Versym>(SymbolVersionSection, EntryIndex));

        auto getSymbolVersionByIndex = [&](llvm::StringRef StrTab,
                                           uint32_t SymbolVersionIndex,
                                           bool &IsDefault) -> llvm::StringRef {
          size_t VersionIndex = SymbolVersionIndex & llvm::ELF::VERSYM_VERSION;

          // Special markers for unversioned symbols.
          if (VersionIndex == llvm::ELF::VER_NDX_LOCAL ||
              VersionIndex == llvm::ELF::VER_NDX_GLOBAL) {
            IsDefault = false;
            return "";
          }

          auto LoadVersionMap = [&](void) -> void {
            // If there is no dynamic symtab or version table, there is nothing to
            // do.
            if (!DynSymRegion.Addr || !SymbolVersionSection)
              return;

            // Has the VersionMap already been loaded?
            if (!VersionMap.empty())
              return;

            // The first two version indexes are reserved.
            // Index 0 is LOCAL, index 1 is GLOBAL.
            VersionMap.push_back(VersionMapEntry());
            VersionMap.push_back(VersionMapEntry());

            if (SymbolVersionDefSection)
              LoadVersionDefs(SymbolVersionDefSection);

            if (SymbolVersionNeedSection)
              LoadVersionNeeds(SymbolVersionNeedSection);
          };

          // Lookup this symbol in the version table.
          LoadVersionMap();
          if (VersionIndex >= VersionMap.size() ||
              VersionMap[VersionIndex].isNull()) {
            WithColor::error() << "Invalid version entry\n";
            exit(1);
          }

          const VersionMapEntry &Entry = VersionMap[VersionIndex];

          // Get the version name string.
          size_t NameOffset;
          if (Entry.isVerdef()) {
            // The first Verdaux entry holds the name.
            NameOffset = Entry.getVerdef()->getAux()->vda_name;
            IsDefault = !(SymbolVersionIndex & llvm::ELF::VERSYM_HIDDEN);
          } else {
            NameOffset = Entry.getVernaux()->vna_name;
            IsDefault = false;
          }

          if (NameOffset >= StrTab.size()) {
            WithColor::error() << "Invalid string offset\n";
            return "";
          }

          return StrTab.data() + NameOffset;
        };

        sym.Vers = getSymbolVersionByIndex(DynamicStringTable, Versym->vs_index,
                                           sym.Visibility.IsDefault);
      }

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

      sym.Addr = Sym.isUndefined() ? 0 : Sym.st_value;
      sym.Type = elf_symbol_type_mapping[Sym.getType()];
      sym.Size = Sym.st_size;
      sym.Bind = elf_symbol_binding_mapping[Sym.getBinding()];

      //////////////////////////////////////////////////////
      //////////////////////////////////////////////////////
      //////////////////////////////////////////////////////

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
              unsigned off = Sym.st_value - SectsStartAddr;

              if (sym.Vers.empty()) {
                Module->appendModuleInlineAsm(
                    (fmt(".globl %s\n"
                         ".type  %s,@object\n"
                         ".size  %s, %u\n"
                         ".set   %s, __jove_sections_%u + %u")
                     % sym.Name.str()
                     % sym.Name.str()
                     % sym.Name.str() % Sym.st_size
                     % sym.Name.str() % BinaryIndex % off).str());
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
                     % sym.Name.str()
                     % (sym.Visibility.IsDefault ? "@@" : "@")
                     % sym.Vers.str()).str());

                // make sure version node is defined
                VersionScript.Table[sym.Vers.str()];
              }
            } else {
              if (Module->getNamedValue(sym.Name)) {
                if (!sym.Vers.empty())
                  VersionScript.Table[sym.Vers.str()].insert(sym.Name.str());

                continue;
              }

              llvm::GlobalVariable *GV =
                  Module->getGlobalVariable(*(*it).second.begin(), true);
              assert(GV);

              llvm::GlobalAlias::create(sym.Name, GV);
              if (!sym.Vers.empty())
                VersionScript.Table[sym.Vers.str()].insert(sym.Name.str());
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
  auto &Binary = Decompilation.Binaries[BinaryIndex];
  assert(Binary.IsExecutable);

  for (binary_index_t BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx) {
    if (BIdx == BinaryIndex)
      continue;

    auto &binary = Decompilation.Binaries[BIdx];
    if (binary.IsVDSO)
      continue;
    if (binary.IsDynamicLinker)
      continue;
    if (!binary.ObjectFile)
      continue;

    assert(llvm::isa<ELFO>(binary.ObjectFile.get()));
    ELFO &O = *llvm::cast<ELFO>(binary.ObjectFile.get());
    const ELFF &E = *O.getELFFile();

    DynRegionInfo DynamicTable(O.getFileName());
    loadDynamicTable(&E, &O, DynamicTable);

    assert(DynamicTable.Addr);

    DynRegionInfo DynSymRegion(O.getFileName());
    llvm::StringRef DynSymtabName;
    llvm::StringRef DynamicStringTable;

    {
      for (const Elf_Shdr &Sec : unwrapOrError(E.sections())) {
        switch (Sec.sh_type) {
        case llvm::ELF::SHT_DYNSYM:
          DynSymRegion = createDRIFrom(&Sec, &O);
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

      const char *StringTableBegin = nullptr;
      uint64_t StringTableSize = 0;
      for (const Elf_Dyn &Dyn : dynamic_table()) {
        if (unlikely(Dyn.d_tag == llvm::ELF::DT_NULL))
          break; /* marks end of dynamic table. */

        switch (Dyn.d_tag) {
        case llvm::ELF::DT_STRTAB:
          if (llvm::Expected<const uint8_t *> ExpectedPtr = E.toMappedAddr(Dyn.getPtr()))
            StringTableBegin = reinterpret_cast<const char *>(*ExpectedPtr);
          break;
        case llvm::ELF::DT_STRSZ:
          if (uint64_t sz = Dyn.getVal())
            StringTableSize = sz;
          break;
        case llvm::ELF::DT_SYMTAB:
          if (llvm::Expected<const uint8_t *> ExpectedPtr = E.toMappedAddr(Dyn.getPtr())) {
            const uint8_t *Ptr = *ExpectedPtr;

            if (DynSymRegion.EntSize && Ptr != DynSymRegion.Addr)
              WithColor::warning()
                  << "SHT_DYNSYM section header and DT_SYMTAB disagree about "
                     "the location of the dynamic symbol table\n";

            DynSymRegion.Addr = Ptr;
            DynSymRegion.EntSize = sizeof(Elf_Sym);
          }
          break;
        }
      }

      if (StringTableBegin && StringTableSize && StringTableSize > DynamicStringTable.size())
        DynamicStringTable = llvm::StringRef(StringTableBegin, StringTableSize);
    }

    auto dynamic_symbols = [&DynSymRegion](void) -> Elf_Sym_Range {
      return DynSymRegion.getAsArrayRef<Elf_Sym>();
    };

    const Elf_Shdr *SymbolVersionSection = nullptr;     // .gnu.version
    const Elf_Shdr *SymbolVersionNeedSection = nullptr; // .gnu.version_r
    const Elf_Shdr *SymbolVersionDefSection = nullptr;  // .gnu.version_d

    for (const Elf_Shdr &Sec : unwrapOrError(E.sections())) {
      switch (Sec.sh_type) {
      case llvm::ELF::SHT_GNU_versym:
        if (!SymbolVersionSection)
          SymbolVersionSection = &Sec;
        break;

      case llvm::ELF::SHT_GNU_verdef:
        if (!SymbolVersionDefSection)
          SymbolVersionDefSection = &Sec;
        break;

      case llvm::ELF::SHT_GNU_verneed:
        if (!SymbolVersionNeedSection)
          SymbolVersionNeedSection = &Sec;
        break;
      }
    }

    llvm::SmallVector<VersionMapEntry, 16> VersionMap;

    auto LoadVersionDefs = [&](const Elf_Shdr *Sec) -> void {
      unsigned VerdefSize = Sec->sh_size;    // Size of section in bytes
      unsigned VerdefEntries = Sec->sh_info; // Number of Verdef entries
      const uint8_t *VerdefStart =
          reinterpret_cast<const uint8_t *>(E.base() + Sec->sh_offset);
      const uint8_t *VerdefEnd = VerdefStart + VerdefSize;
      // The first Verdef entry is at the start of the section.
      const uint8_t *VerdefBuf = VerdefStart;
      for (unsigned VerdefIndex = 0; VerdefIndex < VerdefEntries;
           ++VerdefIndex) {
        if (VerdefBuf + sizeof(Elf_Verdef) > VerdefEnd) {
#if 0
      report_fatal_error("Section ended unexpectedly while scanning "
                         "version definitions.");
#else
          abort();
#endif
        }

        const Elf_Verdef *Verdef =
            reinterpret_cast<const Elf_Verdef *>(VerdefBuf);
        if (Verdef->vd_version != llvm::ELF::VER_DEF_CURRENT) {
#if 0
      report_fatal_error("Unexpected verdef version");
#else
          abort();
#endif
        }

        size_t Index = Verdef->vd_ndx & llvm::ELF::VERSYM_VERSION;
        if (Index >= VersionMap.size())
          VersionMap.resize(Index + 1);
        VersionMap[Index] = VersionMapEntry(Verdef);
        VerdefBuf += Verdef->vd_next;
      }
    };

    auto LoadVersionNeeds = [&](const Elf_Shdr *Sec) -> void {
      unsigned VerneedSize = Sec->sh_size;    // Size of section in bytes
      unsigned VerneedEntries = Sec->sh_info; // Number of Verneed entries
      const uint8_t *VerneedStart =
          reinterpret_cast<const uint8_t *>(E.base() + Sec->sh_offset);
      const uint8_t *VerneedEnd = VerneedStart + VerneedSize;
      // The first Verneed entry is at the start of the section.
      const uint8_t *VerneedBuf = VerneedStart;
      for (unsigned VerneedIndex = 0; VerneedIndex < VerneedEntries;
           ++VerneedIndex) {
        if (VerneedBuf + sizeof(Elf_Verneed) > VerneedEnd) {
#if 0
        report_fatal_error("Section ended unexpectedly while scanning "
                           "version needed records.");
#else
          abort();
#endif
        }
        const Elf_Verneed *Verneed =
            reinterpret_cast<const Elf_Verneed *>(VerneedBuf);
        if (Verneed->vn_version != llvm::ELF::VER_NEED_CURRENT) {
#if 0
        report_fatal_error("Unexpected verneed version");
#else
          abort();
#endif
        }
        // Iterate through the Vernaux entries
        const uint8_t *VernauxBuf = VerneedBuf + Verneed->vn_aux;
        for (unsigned VernauxIndex = 0; VernauxIndex < Verneed->vn_cnt;
             ++VernauxIndex) {
          if (VernauxBuf + sizeof(Elf_Vernaux) > VerneedEnd) {
#if 0
          report_fatal_error(
              "Section ended unexpected while scanning auxiliary "
              "version needed records.");
#else
            abort();
#endif
          }
          const Elf_Vernaux *Vernaux =
              reinterpret_cast<const Elf_Vernaux *>(VernauxBuf);
          size_t Index = Vernaux->vna_other & llvm::ELF::VERSYM_VERSION;
          if (Index >= VersionMap.size())
            VersionMap.resize(Index + 1);
          VersionMap[Index] = VersionMapEntry(Vernaux);
          VernauxBuf += Vernaux->vna_next;
        }
        VerneedBuf += Verneed->vn_next;
      }
    };

    for (const Elf_Sym &Sym : dynamic_symbols()) {
      if (Sym.isUndefined())
        continue;

      if (Sym.getType() != llvm::ELF::STT_OBJECT)
        continue;

      llvm::StringRef SymName = unwrapOrError(Sym.getName(DynamicStringTable));

      //////////////////////////////////////////////////////
      //////////////////////////////////////////////////////
      //////////////////////////////////////////////////////

      symbol_t sym;

      sym.Name = SymName;

      //
      // symbol versioning
      //
      if (!SymbolVersionSection) {
        sym.Visibility.IsDefault = false;
      } else {
        // Determine the position in the symbol table of this entry.
        size_t EntryIndex = (reinterpret_cast<uintptr_t>(&Sym) -
                             reinterpret_cast<uintptr_t>(DynSymRegion.Addr)) /
                            sizeof(Elf_Sym);

        // Get the corresponding version index entry.
        const Elf_Versym *Versym = unwrapOrError(
            E.getEntry<Elf_Versym>(SymbolVersionSection, EntryIndex));

        auto getSymbolVersionByIndex = [&](llvm::StringRef StrTab,
                                           uint32_t SymbolVersionIndex,
                                           bool &IsDefault) -> llvm::StringRef {
          size_t VersionIndex = SymbolVersionIndex & llvm::ELF::VERSYM_VERSION;

          // Special markers for unversioned symbols.
          if (VersionIndex == llvm::ELF::VER_NDX_LOCAL ||
              VersionIndex == llvm::ELF::VER_NDX_GLOBAL) {
            IsDefault = false;
            return "";
          }

          auto LoadVersionMap = [&](void) -> void {
            // If there is no dynamic symtab or version table, there is nothing to
            // do.
            if (!DynSymRegion.Addr || !SymbolVersionSection)
              return;

            // Has the VersionMap already been loaded?
            if (!VersionMap.empty())
              return;

            // The first two version indexes are reserved.
            // Index 0 is LOCAL, index 1 is GLOBAL.
            VersionMap.push_back(VersionMapEntry());
            VersionMap.push_back(VersionMapEntry());

            if (SymbolVersionDefSection)
              LoadVersionDefs(SymbolVersionDefSection);

            if (SymbolVersionNeedSection)
              LoadVersionNeeds(SymbolVersionNeedSection);
          };

          // Lookup this symbol in the version table.
          LoadVersionMap();
          if (VersionIndex >= VersionMap.size() ||
              VersionMap[VersionIndex].isNull()) {
            WithColor::error() << "Invalid version entry\n";
            exit(1);
          }

          const VersionMapEntry &Entry = VersionMap[VersionIndex];

          // Get the version name string.
          size_t NameOffset;
          if (Entry.isVerdef()) {
            // The first Verdaux entry holds the name.
            NameOffset = Entry.getVerdef()->getAux()->vda_name;
            IsDefault = !(SymbolVersionIndex & llvm::ELF::VERSYM_HIDDEN);
          } else {
            NameOffset = Entry.getVernaux()->vna_name;
            IsDefault = false;
          }

          if (NameOffset >= StrTab.size()) {
            WithColor::error() << "Invalid string offset\n";
            return "";
          }

          return StrTab.data() + NameOffset;
        };

        sym.Vers = getSymbolVersionByIndex(DynamicStringTable, Versym->vs_index,
                                           sym.Visibility.IsDefault);
      }

      //////////////////////////////////////////////////////
      //////////////////////////////////////////////////////
      //////////////////////////////////////////////////////

      if ((sym.Name == S.Name &&
           sym.Vers == S.Vers)) {
        //
        // we have a match.
        //
        uintptr_t _SectsStartAddr = std::numeric_limits<uintptr_t>::max();

        for (const Elf_Shdr &Sec : unwrapOrError(E.sections())) {
          if (!(Sec.sh_flags & llvm::ELF::SHF_ALLOC))
            continue;

          llvm::Expected<llvm::StringRef> name = E.getSectionName(&Sec);

          if (!name)
            continue;

          if ((Sec.sh_flags & llvm::ELF::SHF_TLS) && *name == std::string(".tbss"))
            continue;

          if (!Sec.sh_size)
            continue;

          _SectsStartAddr = std::min<uintptr_t>(_SectsStartAddr, Sec.sh_addr);
        }

        assert(Sym.st_value > _SectsStartAddr);

        return {BIdx, {Sym.st_value, Sym.st_value - _SectsStartAddr}};
      }
    }
  }

  WithColor::warning() << llvm::formatv(
      "failed to decipher copy relocation {0} {1}\n", S.Name, S.Vers);

  return {invalid_binary_index, {0, 0}};
}

static llvm::Value *insertThreadPointerInlineAsm(llvm::IRBuilderTy &);

int CreateTPOFFCtorHack(void) {
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
      uintptr_t off = pair.first - SectsStartAddr;

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

      IRB.CreateRet(llvm::ConstantInt::get(WordType(), SectsStartAddr));
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
      target_ulong SectsGlobalSize = SectsEndAddr - SectsStartAddr;

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
    std::fill(GlobalAllocaArr.begin(),
              GlobalAllocaArr.end(),
              nullptr);
  }
};

static llvm::AllocaInst *CreateAllocaForGlobal(llvm::IRBuilderTy &IRB,
                                               unsigned glb,
                                               bool InitializeFromEnv = true) {
  llvm::AllocaInst *res = IRB.CreateAlloca(
      IRB.getIntNTy(bitsOfTCGType(TCG->_ctx.temps[glb].type)), nullptr,
      std::string(TCG->_ctx.temps[glb].name) + "_ptr");

  if (InitializeFromEnv) {
    llvm::Constant *GlbPtr = CPUStateGlobalPointer(glb);
    assert(GlbPtr);

    llvm::LoadInst *LI = IRB.CreateLoad(GlbPtr);
    LI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);

    llvm::StoreInst *SI = IRB.CreateStore(LI, res);
    SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
  }

  return res;
}

static int TranslateBasicBlock(TranslateContext &);

llvm::Constant *CPUStateGlobalPointer(unsigned glb) {
  assert(glb < tcg_num_globals);

  if (glb == tcg_env_index)
    return CPUStateGlobal;

  unsigned bits = bitsOfTCGType(TCG->_ctx.temps[glb].type);
  llvm::Type *GlbTy = llvm::IntegerType::get(*Context, bits);

  struct TCGTemp *base_tmp = TCG->_ctx.temps[glb].mem_base;
  if (!base_tmp || temp_idx(base_tmp) != tcg_env_index) {
#if 1
    // we don't know how to locate it.
    return nullptr;
#else
    static int i = 0;

    return llvm::ConstantExpr::getPointerCast(
        new llvm::GlobalVariable(*Module, WordType(), false,
                                 llvm::GlobalValue::ExternalLinkage, nullptr,
                                 (fmt("CPUStateGlobalPointer_fail_%s_%i")
                                  % TCG->_ctx.temps[glb].name
                                  % i++).str()),
        llvm::PointerType::get(GlbTy, 0));
#endif
  }

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

  //
  // fallback
  //
#if 0
  WithColor::error() << llvm::formatv(
      "failed to get CPUState global pointer for {0}\n",
      TCG->_ctx.temps[glb].name);
#endif

  return llvm::ConstantExpr::getIntToPtr(
      llvm::ConstantExpr::getAdd(
          llvm::ConstantExpr::getPtrToInt(CPUStateGlobal, WordType()),
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

  //
  // initialize the globals which are used as function arguments
  //
  {
    llvm::IRBuilderTy IRB(EntryB);

    IRB.SetCurrentDebugLocation(
        llvm::DILocation::get(*Context, ICFG[entry_bb].Addr, 0 /* Column */,
                              TC.DebugInformation.Subprogram));

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

        uintptr_t FileAddr = off + SectsStartAddr;

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

int RecoverControlFlow(void) {
  {
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = SIG_IGN;

    sigaction(SIGINT, &sa, nullptr);
  }

  JoveRecoverDynTargetFunc = Module->getFunction("_jove_recover_dyn_target");
  if (!JoveRecoverDynTargetFunc)
    return 0;

  // sanity check.
  assert(JoveRecoverDynTargetFunc->arg_size() == 2);

  std::unordered_map<llvm::Function *,
                     std::pair<binary_index_t, function_index_t>>
      LLVMFnToJoveFnMap;

  {
    binary_t &b = Decompilation.Binaries[BinaryIndex];
    for (function_t &f : b.Analysis.Functions)
      LLVMFnToJoveFnMap.insert({f.F, {f.BIdx, f.FIdx}});
  }

  bool Changed = false;

  for (llvm::User *U : JoveRecoverDynTargetFunc->users()) {
    assert(llvm::isa<llvm::CallInst>(U));
    llvm::CallInst *Call = llvm::cast<llvm::CallInst>(U);

    llvm::Value *CalleeV = Call->getOperand(1);
    if (!llvm::isa<llvm::ConstantExpr>(CalleeV))
      continue;

    llvm::ConstantExpr *CalleeCE = llvm::cast<llvm::ConstantExpr>(CalleeV);
    if (CalleeCE->getOpcode() != llvm::Instruction::PtrToInt)
      continue;

    if (!llvm::isa<llvm::GlobalIFunc>(CalleeCE->getOperand(0)) &&
        !llvm::isa<llvm::Function>(CalleeCE->getOperand(0)))
      continue;

    assert(llvm::isa<llvm::ConstantInt>(Call->getOperand(0)));

    struct {
      binary_index_t BIdx;
      basic_block_index_t BBIdx;
    } Caller;

    Caller.BIdx  = BinaryIndex;
    Caller.BBIdx = llvm::cast<llvm::ConstantInt>(Call->getOperand(0))->getZExtValue();

#if 0
    llvm::outs() << llvm::formatv("_jove_recover_dyn_target({0}, {1}, {2})\n",
                                  Caller.BIdx, Caller.BBIdx, *IFunc);
#endif

    struct {
      binary_index_t BIdx;
      function_index_t FIdx;
    } Callee;

    if (llvm::isa<llvm::GlobalIFunc>(CalleeCE->getOperand(0))) {
      llvm::GlobalIFunc *IFunc =
          llvm::cast<llvm::GlobalIFunc>(CalleeCE->getOperand(0));

      auto it = IFuncTargetMap.find(IFunc);
      if (it == IFuncTargetMap.end()) {
        WithColor::warning() << llvm::formatv("no IdxPair for {0}\n", *IFunc);
        continue;
      }

      std::tie(Callee.BIdx, Callee.FIdx) = (*it).second;
    } else {
      assert(llvm::isa<llvm::Function>(CalleeCE->getOperand(0)));

      llvm::Function *Func =
          llvm::cast<llvm::Function>(CalleeCE->getOperand(0));

      if (!Func->empty()) {
        auto it = LLVMFnToJoveFnMap.find(Func);
        if (it == LLVMFnToJoveFnMap.end()) {
          WithColor::warning()
              << llvm::formatv("unknown defined function \"{0}\" passed to "
                               "_jove_recover_dyn_target\n",
                               Func->getName());
          continue;
        }

        std::tie(Callee.BIdx, Callee.FIdx) = (*it).second;
      } else {
        binary_t &binary = Decompilation.Binaries[BinaryIndex];
        auto &SymDynTargets = binary.Analysis.SymDynTargets;
        auto it = SymDynTargets.find(Func->getName());
        if (it == SymDynTargets.end()) {
          WithColor::warning()
              << llvm::formatv("no SymDynTarget for declared function \"{0}\" "
                               "passed to _jove_recover_dyn_target\n",
                               Func->getName());
          continue;
        }

        std::tie(Callee.BIdx, Callee.FIdx) = *(*it).second.begin();
      }
    }

    // XXX code duplication. this is in jove-recover

    // Check that Callee is valid
    (void)Decompilation.Binaries.at(Callee.BIdx)
             .Analysis.Functions.at(Callee.FIdx);

    auto &ICFG = Decompilation.Binaries.at(Caller.BIdx).Analysis.ICFG;

    basic_block_properties_t &bbprop = ICFG[boost::vertex(Caller.BBIdx, ICFG)];

    // TODO assert that out_degree(bb) = 0

    bool isNewTarget =
        bbprop.DynTargets.insert({Callee.BIdx, Callee.FIdx}).second;

    Changed = Changed || isNewTarget;

    // TODO only invalidate those functions which contains ...
    if (isNewTarget)
      InvalidateAllFunctionAnalyses();

    // XXX hehe. only change DynTargetsComplete if it's an IFunc.
    if (llvm::isa<llvm::GlobalIFunc>(CalleeCE->getOperand(0))) {
      bool &DynTargetsComplete = bbprop.DynTargetsComplete;

      bool DynTargetsComplete_Changed = !DynTargetsComplete;

      DynTargetsComplete = true;

      Changed = Changed || DynTargetsComplete_Changed;

      if (DynTargetsComplete_Changed)
        ; //InvalidateAllFunctionAnalyses();
    }
  }

  return 0;
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

int WriteDecompilation(void) {
  {
    std::string path = fs::is_directory(opts::jv)
                           ? (opts::jv + "/decompilation.jv")
                           : opts::jv;

    int fd = ::open(path.c_str(), O_RDONLY);
    assert(!(fd < 0));

    lockFile(fd);

    {
      std::ofstream ofs(path);

      boost::archive::text_oarchive oa(ofs);
      oa << Decompilation;
    }

    unlockFile(fd);
    close(fd);
  }

  //
  // git commit
  //
  std::string msg("[jove-llvm]");
  for (char **argp = cmdline.argv; *argp ; ++argp) {
    msg.push_back(' ');
    msg.append(*argp);
  }

  // TODO check that there are no uncommitted changes

  if (fs::is_directory(opts::jv)) {
    pid_t pid = fork();
    if (!pid) { /* child */
      chdir(opts::jv.c_str());

      const char *argv[] = {"/usr/bin/git", "commit",    ".",
                            "-m",           msg.c_str(), nullptr};

      execve(argv[0], const_cast<char **>(argv), ::environ);
      abort();
    }

    await_process_completion(pid);
  }

  return 0;
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

extern const translate_tcg_op_proc_t TranslateTCGOpTable[250];

static std::string
dyn_target_desc(const std::pair<binary_index_t, function_index_t> &IdxPair);

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
      llvm::Constant *GlbPtr = CPUStateGlobalPointer(glb);
      assert(GlbPtr);

      llvm::StoreInst *SI = IRB.CreateStore(V, GlbPtr);
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
      llvm::Constant *GlbPtr = CPUStateGlobalPointer(glb);
      assert(GlbPtr);

      llvm::LoadInst *LI = IRB.CreateLoad(GlbPtr);
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
          IRB.CreateStore(IRB.getInt64(comb), PtrLoad, true /* Volatile */);

      SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
    }

    {
      llvm::StoreInst *SI =
          IRB.CreateStore(PtrInc, TraceGlobal, true /* Volatile */);

      SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
    }
  }

  {
    auto sectit = Binary.SectMap.find(Addr);
    assert(sectit != Binary.SectMap.end());

    const section_properties_t &sectprop = *(*sectit).second.begin();
    assert(sectprop.x);
    TCG->set_section((*sectit).first.lower(), sectprop.contents.data());
  }

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

    if (opts::DFSan) {
      auto it = dfsanPreHooks.find({BinaryIndex, FIdx});
      if (it != dfsanPreHooks.end()) {
        llvm::outs() << llvm::formatv("calling pre-hook ({0}, {1})\n",
                                      (*it).first,
                                      (*it).second);

        function_t &hook_f = Decompilation.Binaries.at((*it).first)
                               .Analysis.Functions.at((*it).second);
        assert(hook_f.hook);
        const hook_t &hook = *hook_f.hook;

        std::vector<llvm::Value *> ArgVec;

        ArgVec.resize(hook.Args.size());
        std::transform(hook.Args.begin(),
                       hook.Args.end(),
                       ArgVec.begin(),
                       [](const hook_t::arg_info_t &info) -> llvm::Value * {
                         llvm::Type *Ty = type_of_arg_info(info);
                         return llvm::Constant::getNullValue(Ty);
                       });
        IRB.CreateCall(IRB.CreateIntToPtr(IRB.CreateLoad(hook_f.PreHookGv), hook_f.PreHook->getType()), ArgVec);
      }
    }

    function_t &callee = Binary.Analysis.Functions.at(FIdx);

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
      auto it = dfsanPostHooks.find({BinaryIndex, FIdx});
      if (it != dfsanPostHooks.end()) {
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
        llvm::Constant *GlbPtr = CPUStateGlobalPointer(glb);
        assert(GlbPtr);

        llvm::StoreInst *SI = IRB.CreateStore(get(glb), GlbPtr);
        SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
      }

      store_stack_pointer();
    }

    llvm::CallInst *Ret = IRB.CreateCall(callee.F, ArgVec);

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

    if (opts::DFSan) {
      auto it = dfsanPostHooks.find({BinaryIndex, FIdx});
      if (it != dfsanPostHooks.end()) {
        llvm::outs() << llvm::formatv("calling post-hook ({0}, {1})\n",
                                      (*it).first, (*it).second);

        function_t &hook_f = Decompilation.Binaries.at((*it).first)
                                 .Analysis.Functions.at((*it).second);
        assert(hook_f.hook);
        const hook_t &hook = *hook_f.hook;

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
        IRB.CreateCall(IRB.CreateIntToPtr(IRB.CreateLoad(hook_f.PostHookGv), hook_f.PostHook->getType()), HookArgVec);
      }
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
      auto adj_it_pair = boost::adjacent_vertices(bb, ICFG);
      unsigned N = std::distance(adj_it_pair.first, adj_it_pair.second);
      assert(N > 0);

      // TODO fix style here
      std::vector<basic_block_t> succ_bb_vec;
      succ_bb_vec.resize(N);
      std::transform(adj_it_pair.first, adj_it_pair.second, succ_bb_vec.begin(),
                     [](basic_block_t bb) -> basic_block_t { return bb; });

      std::vector<llvm::BasicBlock *> IfSuccBlockVec;
      IfSuccBlockVec.resize(N);
      for (unsigned i = 0; i < N; ++i) {
        basic_block_t succ = succ_bb_vec[i];

        IfSuccBlockVec[i] = llvm::BasicBlock::Create(
            *Context, (fmt("if %#lx") % ICFG[succ].Addr).str(), f.F);
      }

      llvm::BasicBlock *ElseBlock =
          llvm::BasicBlock::Create(*Context, "else", f.F);

      IRB.CreateBr(IfSuccBlockVec.front());

      for (unsigned i = 0; i < N; ++i) {
        basic_block_t succ = succ_bb_vec[i];

        IRB.SetInsertPoint(IfSuccBlockVec[i]);
        llvm::Value *PC = IRB.CreateLoad(TC.PCAlloca);
        llvm::Value *EQV =
            IRB.CreateICmpEQ(PC, SectionPointer(ICFG[succ].Addr));
        IRB.CreateCondBr(EQV, ICFG[succ].B,
                         i + 1 < N ? IfSuccBlockVec[i + 1] : ElseBlock);
      }

      IRB.SetInsertPoint(ElseBlock);

      boost::property_map<interprocedural_control_flow_graph_t,
                          boost::vertex_index_t>::type bb_idx_map =
          boost::get(boost::vertex_index, ICFG);

      llvm::Value *RecoverArgs[] = {IRB.getInt32(bb_idx_map[bb]),
                                    IRB.CreateLoad(TC.PCAlloca)};

      IRB.CreateCall(JoveRecoverBasicBlockFunc, RecoverArgs);
      IRB.CreateCall(
          llvm::Intrinsic::getDeclaration(Module.get(), llvm::Intrinsic::trap));
      IRB.CreateUnreachable();
      break;
    }

  case TERMINATOR::INDIRECT_CALL: {
    bool IsCall = T.Type == TERMINATOR::INDIRECT_CALL;
    const auto &DynTargets = ICFG[bb].DynTargets;
    const bool &DynTargetsComplete = ICFG[bb].DynTargetsComplete;

    if (DynTargets.empty()) {
      if (opts::Verbose)
        WithColor::warning() << llvm::formatv(
            "indirect control transfer @ 0x{0:x} has zero dyn targets\n",
            ICFG[bb].Addr);

      boost::property_map<interprocedural_control_flow_graph_t,
                          boost::vertex_index_t>::type bb_idx_map =
          boost::get(boost::vertex_index, ICFG);

      llvm::Value *RecoverArgs[] = {IRB.getInt32(bb_idx_map[bb]),
                                    IRB.CreateLoad(TC.PCAlloca)};

      IRB.CreateCall(JoveRecoverDynTargetFunc, RecoverArgs);

      //
      // if this is an indirect jump, then it's possible this is a goto
      //
      if (T.Type == TERMINATOR::INDIRECT_JUMP)
        IRB.CreateCall(JoveRecoverBasicBlockFunc, RecoverArgs);

      if (T.Type == TERMINATOR::INDIRECT_CALL &&
          JoveRecoverFunctionFunc)
        IRB.CreateCall(JoveRecoverFunctionFunc, RecoverArgs);

      if (JoveFail1Func) {
        llvm::Value *FailArgs[] = {IRB.CreateLoad(TC.PCAlloca)};
        IRB.CreateCall(JoveFail1Func, FailArgs);
      } else {
        IRB.CreateCall(llvm::Intrinsic::getDeclaration(Module.get(),
                                                       llvm::Intrinsic::trap));
      }

      IRB.CreateUnreachable();
      return 0;
    }

    {
      assert(!DynTargets.empty());

      llvm::BasicBlock *ThruB = llvm::BasicBlock::Create(*Context, "", f.F);

      std::vector<std::pair<binary_index_t, function_index_t>> DynTargetsVec(
          DynTargets.begin(), DynTargets.end());

      std::vector<llvm::BasicBlock *> DynTargetsDoCallBVec;
      DynTargetsDoCallBVec.resize(DynTargetsVec.size());

      std::transform(DynTargetsVec.begin(), DynTargetsVec.end(),
                     DynTargetsDoCallBVec.begin(),
                     [&](std::pair<binary_index_t, function_index_t> IdxPair)
                         -> llvm::BasicBlock * {
                       return llvm::BasicBlock::Create(
                           *Context,
                           (fmt("call %s") % dyn_target_desc(IdxPair)).str(),
                           f.F);
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

          llvm::Value *PC = IRB.CreateLoad(TC.PCAlloca);

          auto next_i = i + 1;
          if (next_i == DynTargetsVec.size())
            B = llvm::BasicBlock::Create(*Context, "else", f.F);
          else
            B = llvm::BasicBlock::Create(
                *Context,
                (fmt("if %s") % dyn_target_desc(DynTargetsVec[next_i])).str(),
                f.F);

          llvm::Value *EQV_1 = IRB.CreateICmpEQ(
              PC, GetDynTargetAddress<false>(IRB, DynTargetsVec[i], B));
          llvm::Value *EQV_2 = IRB.CreateICmpEQ(
              PC, GetDynTargetAddress<true>(IRB, DynTargetsVec[i], B));

          IRB.CreateCondBr(IRB.CreateOr(EQV_1, EQV_2), DynTargetsDoCallBVec[i], B);
        } while (++i != DynTargetsVec.size());

        ElseB = B;
      }

      assert(ElseB);

      {
        IRB.SetInsertPoint(ElseB);

        boost::property_map<interprocedural_control_flow_graph_t,
                            boost::vertex_index_t>::type bb_idx_map =
            boost::get(boost::vertex_index, ICFG);
        llvm::Value *RecoverArgs[] = {IRB.getInt32(bb_idx_map[bb]),
                                      IRB.CreateLoad(TC.PCAlloca)};

        IRB.CreateCall(JoveRecoverDynTargetFunc, RecoverArgs);

        if (JoveRecoverFunctionFunc)
          IRB.CreateCall(JoveRecoverFunctionFunc, RecoverArgs);

        if (JoveFail1Func) {
          llvm::Value *FailArgs[] = {IRB.CreateLoad(TC.PCAlloca)};
          IRB.CreateCall(JoveFail1Func, FailArgs);
        } else {
          IRB.CreateCall(llvm::Intrinsic::getDeclaration(
              Module.get(), llvm::Intrinsic::trap));
        }
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
            auto it = dfsanPostHooks.find(DynTargetsVec[i]);
            if (it != dfsanPostHooks.end()) {
              function_t &hook_f = Decompilation.Binaries.at((*it).first)
                                       .Analysis.Functions.at((*it).second);
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

          llvm::CallInst *Ret;
          if (foreign) {
            store_stack_pointer();

            //
            // callstack stuff
            //
            save_callstack_pointers();

#ifdef TARGET_MIPS32
            {
              std::vector<llvm::Value *> ArgVec;

              std::vector<unsigned> glbv;
              ExplodeFunctionArgs(callee, glbv);

              glbv.resize(std::min<unsigned>(glbv.size(), 4));

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
                JoveThunk0Func,
                JoveThunk1Func,
                JoveThunk2Func,
                JoveThunk3Func,
                JoveThunk4Func,
              };

              Ret = IRB.CreateCall(JoveThunkFuncArray[glbv.size()], ArgVec);
            }
#else
            {
              unsigned NumWords = CallConvArgArray.size();

              llvm::AllocaInst *ArgArrAlloca =
                  IRB.CreateAlloca(llvm::ArrayType::get(WordType(), NumWords));

              for (unsigned i = 0; i < CallConvArgArray.size(); ++i) {
                unsigned glb = CallConvArgArray[i];

                llvm::Value *Val = get(glb);
                llvm::Value *Ptr = IRB.CreateConstInBoundsGEP2_64(ArgArrAlloca, 0, i);

                IRB.CreateStore(Val, Ptr);
              }

              llvm::Value *CallArgs[] = {
                  GetDynTargetAddress<true>(IRB, DynTargetsVec[i]),
                  IRB.CreateConstInBoundsGEP2_64(ArgArrAlloca, 0, 0),
                  CPUStateGlobalPointer(tcg_stack_pointer_index)};

              Ret = IRB.CreateCall(JoveThunkFunc, CallArgs);
            }
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
                llvm::Constant *GlbPtr = CPUStateGlobalPointer(glb);
                assert(GlbPtr);

                llvm::StoreInst *SI = IRB.CreateStore(get(glb), GlbPtr);
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

          Ret->setCallingConv(llvm::CallingConv::C);

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
            /* TODO */
            assert(Ret->getType()->isStructTy());
            assert(false && "TODO");
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

          if (opts::DFSan) {
            auto it = dfsanPostHooks.find(DynTargetsVec[i]);
            if (it != dfsanPostHooks.end()) {
              llvm::outs() << llvm::formatv("calling post-hook ({0}, {1})\n",
                                            (*it).first, (*it).second);

              function_t &hook_f = Decompilation.Binaries.at((*it).first)
                                       .Analysis.Functions.at((*it).second);
              assert(hook_f.hook);
              const hook_t &hook = *hook_f.hook;

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
              IRB.CreateCall(IRB.CreateIntToPtr(IRB.CreateLoad(hook_f.PostHookGv), hook_f.PostHook->getType()), HookArgVec);
            }
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

  if (T.Type == TERMINATOR::RETURN && opts::CheckEmulatedStackReturnAddress) {
#if defined(TARGET_X86_64) || defined(TARGET_I386)
    llvm::Value *Args[] = {
        IRB.CreateLoad(TC.PCAlloca),
        IRB.CreatePtrToInt(
            IRB.CreateCall(llvm::Intrinsic::getDeclaration(
                               Module.get(), llvm::Intrinsic::returnaddress),
                           IRB.getInt32(0)),
            WordType())};

    IRB.CreateCall(JoveCheckReturnAddrFunc, Args);
#endif
  }

  switch (T.Type) {
  case TERMINATOR::CONDITIONAL_JUMP: {
    auto eit_pair = boost::out_edges(bb, ICFG);

#if 0
    if (boost::out_degree(bb, ICFG) != 2) {
      WithColor::error() << llvm::formatv(
          "conditional jump @ {0:x} goes to {1} places\n", ICFG[bb].Addr,
          boost::out_degree(bb, ICFG));

      for (auto eit = eit_pair.first; eit != eit_pair.second; ++eit) {
        control_flow_t cf = *eit;
        basic_block_t succ = boost::target(cf, ICFG);

        WithColor::note() << llvm::formatv("  -> {0:x} \n", ICFG[succ].Addr);
      }
    }
#endif

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

      IRB.CreateCall(JoveRecoverReturnedFunc, IRB.getInt32(BBIdx));
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
            return IRB.CreateInsertValue(res,
                                         get(glb),
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

std::string
dyn_target_desc(const std::pair<binary_index_t, function_index_t> &IdxPair) {
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

static bool seenOpTable[ARRAY_SIZE(tcg_op_defs)];

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

  if (!(opc < ARRAY_SIZE(tcg_op_defs)))
    return 1;

  binary_t &Binary = Decompilation.Binaries[BinaryIndex];
  const auto &ICFG = Binary.Analysis.ICFG;
  auto &PCAlloca = TC.PCAlloca;
  TCGContext *s = &TCG->_ctx;

  auto set = [&](llvm::Value *V, TCGTemp *ts) -> void {
    unsigned idx = temp_idx(ts);

    if (ts->temp_global) {
      assert(idx != tcg_env_index);

      if (unlikely(CmdlinePinnedEnvGlbs.test(idx))) {
        llvm::Constant *GlbPtr = CPUStateGlobalPointer(idx);
        assert(GlbPtr);

        llvm::StoreInst *SI = IRB.CreateStore(V, GlbPtr);
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
        llvm::Constant *GlbPtr = CPUStateGlobalPointer(idx);
        assert(GlbPtr);

        llvm::LoadInst *LI = IRB.CreateLoad(GlbPtr);
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
            llvm::ConstantInt::get(WordType(), SectsStartAddr)));
  };

#if 0
  const TCGOpcode opc = op->opc;
#else
  assert(op->opc == opc);
#endif

  const TCGOpDef &def = tcg_op_defs[opc];

  int nb_oargs = def.nb_oargs;
  int nb_iargs = def.nb_iargs;
  int nb_cargs = def.nb_cargs;

#if 0
  if (likely(opc < ARRAY_SIZE(seenOpTable))) {
    bool seen = seenOpTable[opc];
    if (!seen) {
      WithColor::note() << llvm::formatv("[opcode] {0}\n", def.name);

      seenOpTable[opc] = true;
    }
  }
#endif

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
    if (opts::Verbose) {
      auto StringOfTCGTemp = [](TCGTemp *ts) -> std::string {
        return std::to_string(bitsOfTCGType(ts->type));
      };

      std::string arguments_str;
#if 0
      for (int i = 0; i < nb_oargs) {
        TCGTemp *ts = arg_temp(op->args[i]);

        arguments_str.append(" ");
        arguments_str.append(StringOfTCGTemp(ts));
      }
#endif

      for (int i = 0; i < nb_iargs; ++i) {
        TCGTemp *ts = arg_temp(op->args[nb_oargs + i]);

        if (i != 0)
          arguments_str.append(" ");

        arguments_str.append(StringOfTCGTemp(ts));
      }

      llvm::errs() << llvm::formatv("{0} helper_{1}({2}) nb_oargs={3} nb_iargs={4}\n", *hf.F->getType(), helper_nm, arguments_str, nb_oargs, nb_iargs);
    }

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

#if 0
            WithColor::note()
                << llvm::formatv("{0}:{1} lo={2} hi={3} [{4}]\n",
                                 __FILE__,
                                 __LINE__,
                                 *lo, *hi, helper_nm);
#endif

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
      explode_tcg_global_set(glbv, hf.Analysis.InGlbs | hf.Analysis.OutGlbs);
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
    if (off < sizeof(tcg_global_by_offset_lookup_table)) {                     \
      uint8_t idx = tcg_global_by_offset_lookup_table[off];                    \
      if (idx != 0xff) {                                                       \
        llvm::errs() << "[tonpetty] __ARCH_LD_OP: "                            \
                     << TCG->_ctx.temps[idx].name << '\n';                     \
      }                                                                        \
    }                                                                          \
    if (off == offsetof(CPUMIPSState, active_tc.CP0_UserLocal)) {              \
      TCGTemp *dst = arg_temp(op->args[0]);                                    \
      assert(dst->type == TCG_TYPE_I32);                                       \
      set(insertThreadPointerInlineAsm(IRB), dst);                             \
      break;                                                                   \
    }                                                                          \
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
    if (off < sizeof(tcg_global_by_offset_lookup_table)) {                     \
      uint8_t idx = tcg_global_by_offset_lookup_table[off];                    \
      if (idx != 0xff) {                                                       \
        llvm::errs() << "[tonpetty] __ARCH_ST_OP: "                            \
                     << TCG->_ctx.temps[idx].name << '\n';                     \
      }                                                                        \
    }                                                                          \
                                                                               \
    if (off == offsetof(CPUMIPSState, lladdr)) {                               \
      set(Val, &TCG->_ctx.temps[tcg_lladdr_index]);                            \
      break;                                                                   \
    }                                                                          \
                                                                               \
    if (off == offsetof(CPUMIPSState, llval)) {                                \
      set(Val, &TCG->_ctx.temps[tcg_llval_index]);                             \
      break;                                                                   \
    }                                                                          \
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
#if 0
    WithColor::error() << "unhandled TCG instruction (" << def.name << ")\n";
    TCG->dump_operations();
    llvm::errs() << *f.F << '\n';
#endif
    return 1;
  }

  return 0;
}

const translate_tcg_op_proc_t TranslateTCGOpTable[250] = {
    [0 ... 250 - 1] = nullptr,

#define __PROC_CASE(n, i, data) [i] = TranslateTCGOp<i>,

BOOST_PP_REPEAT(178, __PROC_CASE, void)

#undef __PROC_CASE

};

}

void __warn(const char *file, int line) {
  WithColor::warning() << llvm::formatv("{0}:{1}\n", file, line);
}
