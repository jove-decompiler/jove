#include <llvm/ADT/StringRef.h>

//
// forward decls
//
namespace llvm {
class Function;
class BasicBlock;
class AllocaInst;
class Type;
class LoadInst;
class DISubprogram;
class GlobalIFunc;
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
  llvm::LoadInst *TPBaseVal;                                                   \
  const hook_t *hook;                                                          \
  llvm::Function *PreHook;                                                     \
  llvm::Function *PostHook;                                                    \
                                                                               \
  struct {                                                                     \
    llvm::GlobalIFunc *IFunc;                                                  \
  } _resolver;                                                                 \
                                                                               \
  struct {                                                                     \
    llvm::DISubprogram *Subprogram;                                            \
  } DebugInformation;                                                          \
                                                                               \
  bool IsNamed;                                                                \
                                                                               \
  bool Analyzed;                                                               \
                                                                               \
  std::vector<symbol_t> Syms;                                                  \
                                                                               \
  function_t()                                                                 \
      : hook(nullptr), PreHook(nullptr), PostHook(nullptr),                    \
        _resolver({.IFunc = nullptr}), IsNamed(false), Analyzed(false) {}      \
                                                                               \
  void Analyze(void);                                                          \
                                                                               \
  llvm::Function *F;

#define JOVE_EXTRA_BIN_PROPERTIES                                              \
  std::unique_ptr<llvm::object::Binary> ObjectFile;

#include "tcgcommon.hpp"

#include <tuple>
#include <memory>
#include <sstream>
#include <fstream>
#include <unordered_set>
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
#include <boost/serialization/bitset.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/container_hash/extensions.hpp>

#define GET_INSTRINFO_ENUM
#include "LLVMGenInstrInfo.hpp"

#define GET_REGINFO_ENUM
#include "LLVMGenRegisterInfo.hpp"

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

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

static cl::opt<bool> NoInline("noinline",
                              cl::desc("Prevents inlining internal functions"),
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

static cl::opt<bool> NoOpt1("no-opt1", cl::desc("Don't optimize bitcode (1)"),
                            cl::cat(JoveCategory));

static cl::opt<bool>
    NoFixupPcrel("no-fixup-pcrel",
                 cl::desc("Don't fixup pc-relative references"),
                 cl::cat(JoveCategory));

#if defined(LLVM_ENABLE_STATS) && LLVM_ENABLE_STATS
static cl::opt<bool>
    OptStats("opt-stats",
             cl::desc("Print statistics during bitcode optimization"),
             cl::cat(JoveCategory));
#endif

static cl::opt<bool> NoOpt2("no-opt2", cl::desc("Don't optimize bitcode (2)"),
                            cl::cat(JoveCategory));

static cl::opt<bool> Graphviz("graphviz",
                              cl::desc("Dump graphviz of flow graphs"),
                              cl::cat(JoveCategory));

static cl::opt<bool> DumpPreOpt1("dump-pre-opt1",
                                 cl::desc("Dump bitcode before Optimize1()"),
                                 cl::cat(JoveCategory));

static cl::opt<bool> DumpPostOpt1("dump-post-opt1",
                                  cl::desc("Dump bitcode after Optimize1()"),
                                  cl::cat(JoveCategory));

static cl::opt<bool> DumpPreOpt2("dump-pre-opt2",
                                 cl::desc("Dump bitcode before Optimize2()"),
                                 cl::cat(JoveCategory));

static cl::opt<bool>
    DumpAfterFSBaseFixup("dump-after-fsbase-fixup",
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

struct binary_state_t {
  std::unordered_map<uintptr_t, function_index_t> FuncMap;
  std::unordered_map<uintptr_t, basic_block_index_t> BBMap;
  boost::icl::split_interval_map<uintptr_t, section_properties_set_t> SectMap;
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

  uintptr_t Addr;
  unsigned SymbolIndex;
  uintptr_t Addend;

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
static std::unordered_set<uintptr_t> ConstantRelocationLocs;

static llvm::GlobalVariable *CPUStateGlobal;
static llvm::Type *CPUStateType;

static llvm::GlobalVariable *TraceGlobal;
static llvm::GlobalVariable *CallStackGlobal;
static llvm::GlobalVariable *CallStackBeginGlobal;

static llvm::GlobalVariable *JoveFunctionTablesGlobal;
static llvm::GlobalVariable *JoveForeignFunctionTablesGlobal;
static llvm::Function *JoveRecoverDynTargetFunc;
static llvm::Function *JoveRecoverBasicBlockFunc;

static llvm::Function *JoveInstallForeignFunctionTables;

static llvm::Function *JoveThunkFunc;
static llvm::Function *JoveFail1Func;

static llvm::Function *JoveAllocStackFunc;
static llvm::Function *JoveFreeStackFunc;

static llvm::Function *JoveCheckReturnAddrFunc;

static llvm::GlobalVariable *SectsGlobal;
static llvm::GlobalVariable *ConstSectsGlobal;
static uintptr_t SectsStartAddr, SectsEndAddr;

static std::vector<function_index_t> FuncIdxAreABIVec;

static llvm::GlobalVariable *PCRelGlobal;
static llvm::GlobalVariable *TLSModGlobal;

static llvm::GlobalVariable *TPBaseGlobal;

static llvm::MDNode *AliasScopeMetadata;

static std::unique_ptr<llvm::DIBuilder> DIBuilder;

static bool ABIChanged = false;

static struct {
  struct {
    // in memory, the .tbss section is allocated directly following the .tdata
    // section, with the aligment obeyed
    unsigned Size;
  } Data;

  uintptr_t Beg, End;
} ThreadLocalStorage;

static struct {
  llvm::DIFile *File;
  llvm::DICompileUnit *CompileUnit;
} DebugInformation;

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

static std::unordered_map<uintptr_t, std::set<llvm::StringRef>>
    TLSValueToSymbolMap;
static std::unordered_map<uintptr_t, unsigned>
    TLSValueToSizeMap;

static boost::icl::split_interval_set<uintptr_t> AddressSpaceObjects;

static std::unordered_map<uintptr_t, std::set<llvm::StringRef>>
    AddrToSymbolMap;
static std::unordered_map<uintptr_t, unsigned>
    AddrToSizeMap;
static std::unordered_set<uintptr_t>
    TLSObjects; // XXX

static std::unordered_map<llvm::Function *, llvm::Function *> CtorStubMap;

static std::unordered_map<llvm::GlobalIFunc *,
                          std::pair<binary_index_t, function_index_t>>
    IFuncTargetMap;

static std::unordered_set<uintptr_t> ExternGlobalAddrs;

static std::vector<llvm::CallInst *> CallsToInline;

static struct {
  std::unordered_map<std::string, std::unordered_set<std::string>> Table;
} VersionScript;

#if defined(__x86_64__) || defined(__aarch64__) || defined(__mips64)
constexpr target_ulong Cookie = 0xbd47c92caa6cbcb4;
#elif defined(__i386__) || defined(__mips__)
constexpr target_ulong Cookie = 0xd27b9f5a;
#else
#error
#endif

#define JOVE_PAGE_SIZE 4096
#define JOVE_STACK_SIZE (256 * JOVE_PAGE_SIZE)

//
// Stages
//
static int ParseDecompilation(void);
static int FindBinary(void);
static int InitStateForBinaries(void);
static int CreateModule(void);
static int LocateHooks(void);
static int PrepareToTranslateCode(void);
static int ProcessDynamicTargets(void);
static int ProcessBinaryRelocations(void);
static int ProcessIFuncResolvers(void);
static int ProcessExportedFunctions(void);
static int CreateFunctions(void);
static int ProcessBinaryTLSSymbols(void);
static int ProcessDynamicSymbols(void);
static int CreateTLSModGlobal(void);
static int CreateSectionGlobalVariables(void);
static int CreateFunctionTable(void);
static int CreatePCRelGlobal(void);
static int CreateTPBaseGlobal(void);
static int FixupHelperStubs(void);
static int CreateNoAliasMetadata(void);
static int TranslateFunctions(void);
static int InlineCalls(void);
static int PrepareToOptimize(void);
static int Optimize1(void);
static int FixupPCRelativeAddrs(void);
static int FixupTPBaseAddrs(void);
static int InternalizeStaticFunctions(void);
static int InternalizeSections(void);
static int Optimize2(void);
static int ReplaceAllRemainingUsesOfConstSections(void);
static int RecoverControlFlow(void);
static int DFSanInstrument(void);
static int RenameFunctionLocals(void);
static int WriteDecompilation(void);
static int WriteVersionScript(void);
static int WriteModule(void);

static void DumpModule(const char *);

int llvm(void) {
  return ParseDecompilation()
      || FindBinary()
      || InitStateForBinaries()
      || CreateModule()
      || (opts::DFSan ? LocateHooks() : 0)
      || PrepareToTranslateCode()
      || ProcessDynamicTargets()
      || ProcessBinaryRelocations()
      || ProcessIFuncResolvers()
      || ProcessExportedFunctions()
      || CreateFunctions()
      || ProcessBinaryTLSSymbols()
      || ProcessDynamicSymbols()
      || CreateTLSModGlobal()
      || CreateSectionGlobalVariables()
      || CreateFunctionTable()
      || CreatePCRelGlobal()
      || CreateTPBaseGlobal()
      || FixupHelperStubs()
      || CreateNoAliasMetadata()
      || TranslateFunctions()
      || InlineCalls()
      || PrepareToOptimize()
      || (opts::DumpPreOpt1 ? (DumpModule("pre.opt1"), 1) : 0)
      || Optimize1()
      || (opts::DumpPostOpt1 ? (DumpModule("post.opt1"), 1) : 0)
      || (opts::NoFixupPcrel ? 0 : FixupPCRelativeAddrs())
      || FixupTPBaseAddrs()
      || InternalizeStaticFunctions()
      || InternalizeSections()
      || (opts::DumpPreOpt2 ? (DumpModule("pre.opt2"), 1) : 0)
      || Optimize2()
      || ReplaceAllRemainingUsesOfConstSections()
      || RecoverControlFlow()
      || (opts::DFSan ? DFSanInstrument() : 0)
      || RenameFunctionLocals()

      || WriteDecompilation()

      || (!opts::VersionScript.empty() ? WriteVersionScript() : 0)
      || WriteModule();
}

static void DumpModule(const char *suffix) {
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
}

void _qemu_log(const char *cstr) {
  llvm::errs() << cstr;
}

static bool is_integral_size(unsigned n) {
  return n == 1 || n == 2 || n == 4 || n == 8;
}

static llvm::Type *WordType(void) {
  return llvm::Type::getIntNTy(*Context, sizeof(uintptr_t) * 8);
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

static bool
DynTargetNeedsThunkPred(std::pair<binary_index_t, function_index_t> DynTarget) {
  binary_index_t BIdx = DynTarget.first;

  const binary_t &binary = Decompilation.Binaries[BIdx];
  return binary.IsDynamicLinker || binary.IsVDSO;
}

static llvm::Constant *SectionPointer(uintptr_t Addr);

static llvm::Value *
GetDynTargetAddress(llvm::IRBuilderTy &IRB,
                    std::pair<binary_index_t, function_index_t> IdxPair) {
  struct {
    binary_index_t BIdx;
    function_index_t FIdx;
  } DynTarget;

  std::tie(DynTarget.BIdx, DynTarget.FIdx) = IdxPair;

  if (DynTarget.BIdx == BinaryIndex) {
    binary_t &binary = Decompilation.Binaries[BinaryIndex];
    auto &ICFG = binary.Analysis.ICFG;
    const function_t &f = binary.Analysis.Functions[DynTarget.FIdx];
    return llvm::ConstantExpr::getPtrToInt(
        SectionPointer(ICFG[boost::vertex(f.Entry, ICFG)].Addr), WordType());
  }

  bool needsThunk = DynTargetNeedsThunkPred(IdxPair);

  llvm::Value *FnsTbl = IRB.CreateLoad(IRB.CreateConstInBoundsGEP2_64(
      needsThunk ? JoveForeignFunctionTablesGlobal
                 : JoveFunctionTablesGlobal,
      0, DynTarget.BIdx));

  return IRB.CreateLoad(IRB.CreateConstGEP1_64(
      FnsTbl, needsThunk ? DynTarget.FIdx : 2 * DynTarget.FIdx + 0));
}

static llvm::Value *GetDynTargetCallableAddress(
    llvm::IRBuilderTy &IRB,
    std::pair<binary_index_t, function_index_t> IdxPair) {
  struct {
    binary_index_t BIdx;
    function_index_t FIdx;
  } DynTarget;

  std::tie(DynTarget.BIdx, DynTarget.FIdx) = IdxPair;

  if (DynTarget.BIdx == BinaryIndex) {
    binary_t &binary = Decompilation.Binaries[BinaryIndex];
    auto &ICFG = binary.Analysis.ICFG;
    const function_t &f = binary.Analysis.Functions[DynTarget.FIdx];
    return llvm::ConstantExpr::getPtrToInt(f.F, WordType());
  }

  bool needsThunk = DynTargetNeedsThunkPred(IdxPair);

  llvm::Value *FnsTbl = IRB.CreateLoad(IRB.CreateConstInBoundsGEP2_64(
      needsThunk ? JoveForeignFunctionTablesGlobal
                 : JoveFunctionTablesGlobal,
      0, DynTarget.BIdx));

  return IRB.CreateLoad(IRB.CreateConstGEP1_64(
      FnsTbl, needsThunk ? DynTarget.FIdx : 2 * DynTarget.FIdx + 1));
}

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

#if defined(__x86_64__) || defined(__aarch64__) || defined(__mips64)
typedef typename llvm::object::ELF64LEObjectFile ELFO;
typedef typename llvm::object::ELF64LEFile ELFT;
#elif defined(__i386__) || defined(__mips__)
typedef typename llvm::object::ELF32LEObjectFile ELFO;
typedef typename llvm::object::ELF32LEFile ELFT;
#else
#error
#endif

typedef typename ELFT::Elf_Dyn Elf_Dyn;
typedef typename ELFT::Elf_Dyn_Range Elf_Dyn_Range;
typedef typename ELFT::Elf_Phdr Elf_Phdr;
typedef typename ELFT::Elf_Phdr_Range Elf_Phdr_Range;
typedef typename ELFT::Elf_Rel Elf_Rel;
typedef typename ELFT::Elf_Rela Elf_Rela;
typedef typename ELFT::Elf_Shdr Elf_Shdr;
typedef typename ELFT::Elf_Shdr_Range Elf_Shdr_Range;
typedef typename ELFT::Elf_Sym Elf_Sym;
typedef typename ELFT::Elf_Sym_Range Elf_Sym_Range;
typedef typename ELFT::Elf_Word Elf_Word;
typedef typename ELFT::Elf_Versym Elf_Versym;
typedef typename ELFT::Elf_Verdef Elf_Verdef;
typedef typename ELFT::Elf_Vernaux Elf_Vernaux;
typedef typename ELFT::Elf_Verneed Elf_Verneed;

// TODO this whole function needs to be obliterated
int InitStateForBinaries(void) {
  BinStateVec.resize(Decompilation.Binaries.size());

  for (binary_index_t BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx) {
    auto &binary = Decompilation.Binaries[BIdx];
    auto &ICFG = binary.Analysis.ICFG;
    auto &st = BinStateVec[BIdx];

    //
    // FuncMap
    //
    for (function_index_t FIdx = 0; FIdx < binary.Analysis.Functions.size();
         ++FIdx) {
      function_t &f = binary.Analysis.Functions[FIdx];
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
                     return ICFG[bb].Term.Type == TERMINATOR::RETURN ||
                            IsDefinitelyTailCall(ICFG, bb);
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
    llvm::StringRef Buffer(reinterpret_cast<const char *>(&binary.Data[0]),
                           binary.Data.size());
    llvm::StringRef Identifier(binary.Path);
    llvm::MemoryBufferRef MemBuffRef(Buffer, Identifier);

    llvm::Expected<std::unique_ptr<obj::Binary>> BinOrErr =
        obj::createBinary(MemBuffRef);
    if (!BinOrErr) {
      WithColor::error() << "failed to create binary from " << binary.Path
                         << '\n';
      return 1;
    }

    std::unique_ptr<obj::Binary> &BinRef = BinOrErr.get();

    binary.ObjectFile = std::move(BinRef);

    assert(llvm::isa<ELFO>(binary.ObjectFile.get()));
    ELFO &O = *llvm::cast<ELFO>(binary.ObjectFile.get());

    TheTriple = O.makeTriple();
    Features = O.getFeatures();

    const ELFT &E = *O.getELFFile();

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

      if ((Sec.sh_flags & llvm::ELF::SHF_TLS) && *name == std::string(".tbss"))
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

      boost::icl::interval<uintptr_t>::type intervl =
          boost::icl::interval<uintptr_t>::right_open(
              Sec.sh_addr, Sec.sh_addr + Sec.sh_size);

      {
        auto it = st.SectMap.find(intervl);
        if (it != st.SectMap.end()) {
          WithColor::error() << "the following sections intersect: "
                             << (*(*it).second.begin()).name << " and "
                             << sectprop.name << '\n';
          return 1;
        }
      }

      st.SectMap.add({intervl, {sectprop}});
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

      //
      // compute SectsStartAddr, SectsEndAddr
      //
      {
        uintptr_t minAddr = std::numeric_limits<uintptr_t>::max(), maxAddr = 0;
        for (const auto &pair : st.SectMap) {
          minAddr = std::min(minAddr, pair.first.lower());
          maxAddr = std::max(maxAddr, pair.first.upper());
        }

        SectsStartAddr = minAddr;
        SectsEndAddr = maxAddr;
      }
    }
  }

  return 0;
}

int CreateModule(void) {
  Context.reset(new llvm::LLVMContext);

  const char *bootstrap_mod_name =
#if 0
      Decompilation.Binaries[BinaryIndex].IsExecutable ? "jove_start" : "jove";
#else
      "jove";
#endif

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

  JoveThunkFunc = Module->getFunction("_jove_thunk");
  assert(JoveThunkFunc);
  assert(!JoveThunkFunc->empty());
  JoveThunkFunc->setLinkage(llvm::GlobalValue::InternalLinkage);

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
    .Sym = #sym,                                                               \
    .Args = {{.Size = sizeof(t1), .isPointer = std::is_pointer<t1>::value}},   \
    .Ret = {                                                                   \
      .Size = sizeof(rett),                                                    \
      .isPointer = std::is_pointer<rett>::value                                \
    },                                                                         \
    .Pre = !!(hook_kind & PRE),                                                \
    .Post = !!(hook_kind & POST),                                              \
  },
#define ___HOOK2(hook_kind, rett, sym, t1, t2)                                 \
  {                                                                            \
    .Sym = #sym,                                                               \
    .Args = {{.Size = sizeof(t1), .isPointer = std::is_pointer<t1>::value},    \
             {.Size = sizeof(t2), .isPointer = std::is_pointer<t2>::value}},   \
    .Ret = {                                                                   \
      .Size = sizeof(rett),                                                    \
      .isPointer = std::is_pointer<rett>::value                                \
    },                                                                         \
    .Pre = !!(hook_kind & PRE),                                                \
    .Post = !!(hook_kind & POST),                                              \
  },
#define ___HOOK3(hook_kind, rett, sym, t1, t2, t3)                             \
  {                                                                            \
    .Sym = #sym,                                                               \
    .Args = {{.Size = sizeof(t1), .isPointer = std::is_pointer<t1>::value},    \
             {.Size = sizeof(t2), .isPointer = std::is_pointer<t2>::value},    \
             {.Size = sizeof(t3), .isPointer = std::is_pointer<t3>::value}},   \
    .Ret = {                                                                   \
      .Size = sizeof(rett),                                                    \
      .isPointer = std::is_pointer<rett>::value                                \
    },                                                                         \
    .Pre = !!(hook_kind & PRE),                                                \
    .Post = !!(hook_kind & POST),                                              \
  },
#include "dfsan_hooks.inc.h"
};

static llvm::Type *type_of_arg_info(const hook_t::arg_info_t &info) {
  if (info.isPointer)
    return llvm::PointerType::get(llvm::Type::getInt8Ty(*Context), 0);

  return llvm::Type::getIntNTy(*Context, info.Size * 8);
}

static llvm::Type *VoidType(void);

template <bool IsPreOrPost>
static llvm::Function *declareHook(const hook_t &h) {
  const char *namePrefix = IsPreOrPost ? "__dfs_pre_hook_"
                                       : "__dfs_post_hook_";

  std::string name(namePrefix);
  name.append(h.Sym);

  // first check if it already exists
  if (llvm::Function *F = Module->getFunction(name)) {
    assert(F->empty());
    return F; // it does
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

  return llvm::Function::Create(FTy, llvm::GlobalValue::ExternalLinkage, name,
                                Module.get());
}

static llvm::Function *declarePreHook(const hook_t &h) {
  return declareHook<true>(h);
}

static llvm::Function *declarePostHook(const hook_t &h) {
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
          f.PreHook = declarePreHook(h);

          llvm::outs() << llvm::formatv("pre-hook {0} @ ({1}, {2})\n",
                                        h.Sym,
                                        IdxPair.first,
                                        IdxPair.second);
        }

        if (h.Post && dfsanPostHooks.insert(IdxPair).second) {
          f.hook = &h;
          f.PostHook = declarePostHook(h);

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

int ProcessBinaryTLSSymbols(void) {
  binary_index_t BIdx = BinaryIndex;
  auto &binary = Decompilation.Binaries[BIdx];

  assert(llvm::isa<ELFO>(binary.ObjectFile.get()));
  ELFO &O = *llvm::cast<ELFO>(binary.ObjectFile.get());
  const ELFT &E = *O.getELFFile();

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

  if (!tlsPhdr)
    return 0;

  ThreadLocalStorage.Beg = tlsPhdr->p_vaddr;
  ThreadLocalStorage.End = tlsPhdr->p_vaddr + tlsPhdr->p_memsz;
  ThreadLocalStorage.Data.Size = tlsPhdr->p_filesz;

  if (opts::Verbose)
    llvm::outs() << llvm::formatv("TLS: [0x{0:x}, 0x{1:x})\n",
                                  ThreadLocalStorage.Beg,
                                  ThreadLocalStorage.End);

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

  if (!SymTab)
    return 0;

  llvm::StringRef StrTable = unwrapOrError(E.getStringTableForSymtab(*SymTab));

  for (const Elf_Sym &Sym : unwrapOrError(E.symbols(SymTab))) {
    if (Sym.getType() != llvm::ELF::STT_TLS)
      continue;

    llvm::StringRef SymName = unwrapOrError(Sym.getName(StrTable));

    if (Sym.st_value >= tlsPhdr->p_memsz) {
      WithColor::error() << llvm::formatv("bad TLS offset {0} for symbol {1}",
                                          Sym.st_value, SymName)
                         << '\n';
      continue;
    }

    uintptr_t Addr = ThreadLocalStorage.Beg + Sym.st_value;
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
    auto &st = BinStateVec[BIdx];

    assert(llvm::isa<ELFO>(binary.ObjectFile.get()));
    ELFO &O = *llvm::cast<ELFO>(binary.ObjectFile.get());
    const ELFT &E = *O.getELFFile();

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
        if (Phdr.p_type == llvm::ELF::PT_DYNAMIC)
          DynamicTable = createDRIFrom(&Phdr, sizeof(Elf_Dyn));

        if (Phdr.p_type == llvm::ELF::PT_LOAD && Phdr.p_filesz != 0)
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
    auto dynamic_table = [&DynamicTable](void) -> Elf_Dyn_Range {
      return DynamicTable.getAsArrayRef<Elf_Dyn>();
    };

    auto toMappedAddr = [&E, &LoadSegments](uint64_t VAddr) -> const uint8_t * {
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

    {
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
        case llvm::ELF::DT_SYMTAB:
          DynSymRegion.Addr = toMappedAddr(Dyn.getPtr());
          DynSymRegion.EntSize = sizeof(Elf_Sym);
          break;
        }
      }

      if (StringTableBegin)
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

      llvm::StringRef SymName = unwrapOrError(Sym.getName(DynamicStringTable));

      function_index_t FuncIdx;
      {
        auto it = st.FuncMap.find(Sym.st_value);
        if (it == st.FuncMap.end()) {
          WithColor::warning() << llvm::formatv(
              "no function for {0} exists at 0x{1:x}\n", SymName, Sym.st_value);
          continue;
        }

        FuncIdx = (*it).second;
      }

      function_t &f = binary.Analysis.Functions[FuncIdx];
      assert(!f.Analyzed);
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
    auto &st = BinStateVec[BIdx];

    assert(llvm::isa<ELFO>(binary.ObjectFile.get()));
    ELFO &O = *llvm::cast<ELFO>(binary.ObjectFile.get());
    const ELFT &E = *O.getELFFile();

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
        if (Phdr.p_type == llvm::ELF::PT_DYNAMIC)
          DynamicTable = createDRIFrom(&Phdr, sizeof(Elf_Dyn));

        if (Phdr.p_type == llvm::ELF::PT_LOAD && Phdr.p_filesz != 0)
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
#if 0
            AddrToSymbolMap[Sym.st_value].insert(SymName);

            {
              auto it = AddrToSizeMap.find(Sym.st_value);
              if (it == AddrToSizeMap.end()) {
                AddrToSizeMap.insert({Sym.st_value, Sym.st_size});
              } else {
                if ((*it).second != Sym.st_size) {
                  // TODO symbol versions
                  if (opts::Verbose)
                    WithColor::warning()
                        << llvm::formatv("binary symbol {0} is defined with "
                                         "multiple distinct sizes: {1}, {2}\n",
                                         SymName, Sym.st_size, (*it).second);

                  (*it).second = std::max<unsigned>((*it).second, Sym.st_size);
                }
              }
            }

            boost::icl::interval<uintptr_t>::type intervl =
                boost::icl::interval<uintptr_t>::right_open(
                    Sym.st_value, Sym.st_value + Sym.st_size);

            auto it = AddressSpaceObjects.find(intervl);
            if (it != AddressSpaceObjects.end()) {
              if (boost::icl::contains(intervl, *it)) {
                intervl = boost::icl::hull(*it, intervl);
                AddressSpaceObjects.erase(it);
              }
            }

            AddressSpaceObjects.insert({intervl});
#elif 0
            unsigned off = Sym.st_value - SectsStartAddr;

            Module->appendModuleInlineAsm(
                (fmt(".globl %s\n"
                     ".type  %s,@object\n"
                     ".size  %s, %u\n" 
                     ".set   %s, __jove_sections + %u")
                 % sym.Name.str()
                 % sym.Name.str()
                 % sym.Name.str() % Sym.st_size
                 % sym.Name.str() % off).str());

            if (!sym.Vers.empty())
              VersionScript.Table[sym.Vers.str()].insert(sym.Name.str());

#elif 1
            unsigned off = Sym.st_value - SectsStartAddr;

            if (sym.Vers.empty()) {
              Module->appendModuleInlineAsm(
                  (fmt(".globl %s\n"
                       ".type  %s,@object\n"
                       ".size  %s, %u\n" 
                       ".set   %s, __jove_sections + %u")
                   % sym.Name.str()
                   % sym.Name.str()
                   % sym.Name.str() % Sym.st_size
                   % sym.Name.str() % off).str());
            } else {
              if (gdefs.find({Sym.st_value, Sym.st_size}) == gdefs.end()) {
                Module->appendModuleInlineAsm(
                    (fmt(".hidden g%lx_%u\n"
                         ".globl  g%lx_%u\n"
                         ".type   g%lx_%u,@object\n"
                         ".size   g%lx_%u, %u\n" 
                         ".set    g%lx_%u, __jove_sections + %u")
                     % Sym.st_value % Sym.st_size
                     % Sym.st_value % Sym.st_size
                     % Sym.st_value % Sym.st_size
                     % Sym.st_value % Sym.st_size % Sym.st_size
                     % Sym.st_value % Sym.st_size % off).str());

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
#endif
          }
        }
      } else if (Sym.getType() == llvm::ELF::STT_FUNC) {
        function_index_t FuncIdx;
        {
          auto it = st.FuncMap.find(Sym.st_value);
          if (it == st.FuncMap.end()) {
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
          auto it = st.FuncMap.find(Sym.st_value);
          assert(it != st.FuncMap.end());

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
                llvm::GlobalValue::InternalLinkage,
                std::string(f.F->getName()) + "_ifunc", Module.get());

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

              if (DynTargetNeedsThunkPred(IdxPair)) {
                IRB.CreateCall(JoveInstallForeignFunctionTables)
                    ->setIsNoInline();

                llvm::Value *Res = GetDynTargetAddress(IRB, IdxPair);

                IRB.CreateRet(IRB.CreateIntToPtr(
                    Res, CallsF->getFunctionType()->getReturnType()));
              } else if (IdxPair.first == BinaryIndex) {
                llvm::Value *Res = Decompilation.Binaries[BinaryIndex]
                                       .Analysis.Functions.at(IdxPair.second)
                                       .F;

                IRB.CreateRet(IRB.CreateIntToPtr(
                    Res, CallsF->getFunctionType()->getReturnType()));
              } else {
                llvm::Value *SPPtr =
                    CPUStateGlobalPointer(tcg_stack_pointer_index);

                llvm::Value *SavedSP = IRB.CreateLoad(SPPtr);
                SavedSP->setName("saved_sp");

                {
                  constexpr unsigned StackAllocaSize = 0x10000;

                  llvm::AllocaInst *StackAlloca = IRB.CreateAlloca(
                      llvm::ArrayType::get(IRB.getInt8Ty(), StackAllocaSize));

                  llvm::Value *NewSP = IRB.CreateConstInBoundsGEP2_64(
                      StackAlloca, 0, StackAllocaSize - 4096);

                  IRB.CreateStore(IRB.CreatePtrToInt(NewSP, WordType()), SPPtr);
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
                CallsToInline.push_back(Call);

                IRB.CreateStore(SavedSP, SPPtr);

                if (opts::Trace)
                  IRB.CreateStore(SavedTraceP, TraceGlobal);

                if (f.F->getFunctionType()->getReturnType()->isVoidTy()) {
                  WithColor::warning() << llvm::formatv(
                      "ifunc resolver {0} returns void\n", *f.F);

                  IRB.CreateRet(llvm::Constant::getNullValue(
                      CallsF->getFunctionType()->getReturnType()));
                } else {
                  IRB.CreateRet(IRB.CreateIntToPtr(
                      Call, CallsF->getFunctionType()->getReturnType()));
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
  //
  // Note that every function which is seen to be the target of an indirect
  // branch must conform to the system ABI calling convention
  //
  for (binary_index_t BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx) {
    auto &binary = Decompilation.Binaries[BIdx];
    auto &ICFG = binary.Analysis.ICFG;

    for (basic_block_index_t BBIdx = 0; BBIdx < boost::num_vertices(ICFG);
         ++BBIdx) {
      basic_block_t bb = boost::vertex(BBIdx, ICFG);

      for (const auto &dyn_targ : ICFG[bb].DynTargets) {
        function_t &callee = Decompilation.Binaries[dyn_targ.first]
                                 .Analysis.Functions[dyn_targ.second];

        assert(!callee.Analyzed);
        callee.IsABI = true;
      }
    }
  }

  //
  // for the binary under consideration, we'll build a set of dynamic
  // targets that can be used for the purposes of dynamic symbol resolution
  //
  {
    auto &binary = Decompilation.Binaries[BinaryIndex];
    auto &ICFG = binary.Analysis.ICFG;

    auto it_pair = boost::vertices(ICFG);
    for (auto it = it_pair.first; it != it_pair.second; ++it) {
      auto &DynTargets = ICFG[*it].DynTargets;

      BinaryDynamicTargets.insert(DynTargets.begin(), DynTargets.end());
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

        assert(!f.Analyzed);
        f.IsABI = true;
      }
    }
  }

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

        assert(!f.Analyzed);
        f.IsABI = true;
      }
    }
  }

  return 0;
}

int ProcessBinaryRelocations(void) {
  binary_t &binary = Decompilation.Binaries[BinaryIndex];

  assert(llvm::isa<ELFO>(binary.ObjectFile.get()));
  ELFO &O = *llvm::cast<ELFO>(binary.ObjectFile.get());

  TheTriple = O.makeTriple();
  Features = O.getFeatures();

  const ELFT &E = *O.getELFFile();

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
      if (Phdr.p_type == llvm::ELF::PT_DYNAMIC)
        DynamicTable = createDRIFrom(&Phdr, sizeof(Elf_Dyn));

      if (Phdr.p_type == llvm::ELF::PT_LOAD && Phdr.p_filesz != 0)
        LoadSegments.push_back(&Phdr);
    }
  }

  assert(DynamicTable.Addr);

  DynRegionInfo DynSymRegion;
  llvm::StringRef DynSymtabName;
  llvm::StringRef DynamicStringTable;

  const Elf_Shdr *SymbolVersionSection = nullptr;     // .gnu.version
  const Elf_Shdr *SymbolVersionNeedSection = nullptr; // .gnu.version_r
  const Elf_Shdr *SymbolVersionDefSection = nullptr;  // .gnu.version_d

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
  }

  //
  // parse dynamic table
  //
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

  for (const Elf_Dyn &Dyn : dynamic_table()) {
    switch (Dyn.d_tag) {
    case llvm::ELF::DT_SYMTAB:
      DynSymRegion.Addr = toMappedAddr(Dyn.getPtr());
      DynSymRegion.EntSize = sizeof(Elf_Sym);
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
    case relocation_t::TYPE::TPOFF:
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
  auto &binary = Decompilation.Binaries[BinaryIndex];
  auto &st = BinStateVec[BinaryIndex];
  auto &FuncMap = st.FuncMap;

  for (const relocation_t &R : RelocationTable) {
    if (R.Type != relocation_t::TYPE::IRELATIVE)
      continue;

    auto it = FuncMap.find(R.Addend);
    assert(it != FuncMap.end());

    function_t &resolver = binary.Analysis.Functions[(*it).second];
    assert(!resolver.Analyzed);
    resolver.IsABI = true;

    // TODO we know function type is i64 (*)(void)
  }

  assert(llvm::isa<ELFO>(binary.ObjectFile.get()));
  ELFO &O = *llvm::cast<ELFO>(binary.ObjectFile.get());
  const ELFT &E = *O.getELFFile();

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
  auto dynamic_table = [&DynamicTable](void) -> Elf_Dyn_Range {
    return DynamicTable.getAsArrayRef<Elf_Dyn>();
  };

  {
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
    if (Sym.isUndefined()) /* defined */
      continue;
    if (Sym.getType() != llvm::ELF::STT_GNU_IFUNC)
      continue;

    auto it = FuncMap.find(Sym.st_value);
    assert(it != FuncMap.end());

    function_t &resolver = binary.Analysis.Functions.at((*it).second);
    assert(!resolver.Analyzed);
    resolver.IsABI = true;
  }

  //
  // DT_INIT
  //
  uintptr_t initFunctionAddr = 0;

  for (const Elf_Dyn &Dyn : dynamic_table()) {
    switch (Dyn.d_tag) {
    case llvm::ELF::DT_INIT:
      initFunctionAddr = Dyn.getVal();
      break;
    }
  };

  if (initFunctionAddr) {
    auto it = FuncMap.find(initFunctionAddr);
    assert(it != FuncMap.end());

    function_t &f =
        Decompilation.Binaries[BinaryIndex].Analysis.Functions[(*it).second];
    assert(!f.Analyzed);
    f.IsABI = true;
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

static bool AnalyzeHelper(helper_function_t &hf);

static void explode_tcg_global_set(std::vector<unsigned> &out,
                                   tcg_global_set_t glbs) {
  if (glbs.none())
    return;

  out.reserve(glbs.count());

  constexpr bool FitsInUnsignedLongLong =
      tcg_num_globals <= sizeof(unsigned long long) * 8;

  if (FitsInUnsignedLongLong) { /* use ffsll */
    unsigned long long x = glbs.to_ullong();

    int idx = 0;
    do {
      int pos = ffsll(x);
      x >>= pos;
      idx += pos;
      out.push_back(idx - 1);
    } while (x);
  } else {
    for (size_t glb = glbs._Find_first(); glb < glbs.size();
         glb = glbs._Find_next(glb))
      out.push_back(glb);
  }
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

struct flow_vertex_properties_t {
  const basic_block_properties_t *bbprop;

  tcg_global_set_t IN, OUT;
};

static tcg_global_set_t identity_flow(tcg_global_set_t x) {
  return x;
}

static tcg_global_set_t mask_CallConvRets_flow(tcg_global_set_t x) {
  tcg_global_set_t mask(CallConvRets);
  mask.set(tcg_stack_pointer_index);

  return x & mask;
}

static tcg_global_set_t mask_CallConvArgs_flow(tcg_global_set_t x) {
  tcg_global_set_t mask(CallConvArgs);
  mask.set(tcg_stack_pointer_index);

  return x & mask;
}

struct flow_edge_properties_t {
  struct {
    tcg_global_set_t (*flow)(tcg_global_set_t);
  } live;

  struct {
    tcg_global_set_t (*flow)(tcg_global_set_t);
  } reach;

  flow_edge_properties_t () {
    live.flow = identity_flow;
    reach.flow = identity_flow;
  }
};

typedef boost::adjacency_list<boost::setS,              /* OutEdgeList */
                              boost::vecS,              /* VertexList */
                              boost::bidirectionalS,    /* Directed */
                              flow_vertex_properties_t, /* VertexProperties */
                              flow_edge_properties_t    /* EdgeProperties */>
    flow_graph_t;

typedef flow_graph_t::vertex_descriptor flow_vertex_t;
typedef flow_graph_t::edge_descriptor flow_edge_t;

struct vertex_copier {
  const interprocedural_control_flow_graph_t &ICFG;
  flow_graph_t &G;

  vertex_copier(const interprocedural_control_flow_graph_t &ICFG,
                flow_graph_t &G)
      : ICFG(ICFG), G(G) {}

  void operator()(basic_block_t bb, flow_vertex_t V) const {
    G[V].bbprop = &ICFG[bb];
  }
};

struct edge_copier {
  void operator()(control_flow_t, flow_edge_t) const {}
};

struct function_flow_vertex_pair_t {
  function_t *f;
  flow_vertex_t entryV;
};

static bool fn_flow_vert_pair_comp(const function_flow_vertex_pair_t &lhs,
                                   const function_flow_vertex_pair_t &rhs) {
  return lhs.f < rhs.f;
}

static basic_block_properties_t empty_bb_prop;

static flow_vertex_t copy_function_cfg(
    bool &NeedsUpdate, flow_graph_t &G, function_t &f,
    std::vector<flow_vertex_t> &exitVertices,
    std::unordered_map<function_t *,
                       std::pair<flow_vertex_t, std::vector<flow_vertex_t>>>
        &memoize) {
  //
  // make sure basic blocks have been analyzed
  //
  auto &Binary = Decompilation.Binaries[f.BIdx];
  auto &ICFG = Binary.Analysis.ICFG;
  for (basic_block_t bb : f.BasicBlocks) {
    NeedsUpdate = NeedsUpdate || ICFG[bb].Analysis.Stale;

    ICFG[bb].Analyze(f.BIdx);
  }

  //
  // check for back edge
  //
  {
    auto it = memoize.find(&f);
    if (it != memoize.end()) {
      exitVertices = (*it).second.second;
      return (*it).second.first;
    }
  }

  assert(!f.BasicBlocks.empty());

  //
  // copy the function's CFG into the flow graph, maintaining a mapping from the
  // CFG's basic blocks to the flow graph vertices
  //
  std::map<basic_block_t, flow_vertex_t> Orig2CopyMap;
  {
    vertex_copier vc(ICFG, G);
    edge_copier ec;

    boost::copy_component(
        ICFG, f.BasicBlocks.front(), G,
        boost::orig_to_copy(
            boost::associative_property_map<
                std::map<basic_block_t, flow_vertex_t>>(Orig2CopyMap))
            .vertex_copy(vc)
            .edge_copy(ec));
  }

  flow_vertex_t res;
  {
    auto it = Orig2CopyMap.find(f.BasicBlocks.front());
    assert(it != Orig2CopyMap.end());
    res = (*it).second;
  }

  exitVertices.resize(f.ExitBasicBlocks.size());
  std::transform(f.ExitBasicBlocks.begin(),
                 f.ExitBasicBlocks.end(),
                 exitVertices.begin(),
                 [&](basic_block_t bb) -> flow_vertex_t {
                   auto it = Orig2CopyMap.find(bb);
                   assert(it != Orig2CopyMap.end());
                   return (*it).second;
                 });

  memoize.insert({&f, {res, exitVertices}});

  //
  // this recursive function's duty is also to inline calls to functions and
  // indirect jumps
  //
  for (basic_block_t bb : f.BasicBlocks) {
    function_t *callee_ptr = nullptr;

    switch (ICFG[bb].Term.Type) {
    case TERMINATOR::INDIRECT_CALL: {
      auto &DynTargets = ICFG[bb].DynTargets;
      if (DynTargets.empty())
        continue;
      auto &DynTarget = *DynTargets.begin();

      callee_ptr = &Decompilation.Binaries[DynTarget.first]
                        .Analysis.Functions[DynTarget.second];
      /* fallthrough */
    }

    case TERMINATOR::CALL: {
      function_t &callee =
          callee_ptr ? *callee_ptr
                     : Binary.Analysis.Functions[ICFG[bb].Term._call.Target];

      std::vector<flow_vertex_t> calleeExitVertices;
      flow_vertex_t calleeEntryV = copy_function_cfg(
          NeedsUpdate, G, callee, calleeExitVertices, memoize);

      auto eit_pair = boost::out_edges(bb, ICFG);
      if (eit_pair.first == eit_pair.second)
        break;

      assert(eit_pair.first != eit_pair.second &&
             std::next(eit_pair.first) == eit_pair.second);

      flow_vertex_t succV = Orig2CopyMap[boost::target(*eit_pair.first, ICFG)];

      boost::remove_edge(Orig2CopyMap[bb], succV, G);

      {
        flow_edge_t E = boost::add_edge(Orig2CopyMap[bb], calleeEntryV, G).first;
        if (callee.IsABI)
          G[E].live.flow = mask_CallConvArgs_flow;
      }

      for (flow_vertex_t exitV : calleeExitVertices) {
        flow_edge_t E = boost::add_edge(exitV, succV, G).first;
        if (callee.IsABI)
          G[E].reach.flow = mask_CallConvRets_flow;
      }

      break;
    }

    case TERMINATOR::INDIRECT_JUMP: {
      auto it = std::find(exitVertices.begin(),
                          exitVertices.end(),
                          Orig2CopyMap[bb]);
      if (it == exitVertices.end())
        continue;

      const auto &DynTargets = ICFG[bb].DynTargets;
      if (DynTargets.empty())
        continue;
      auto &DynTarget = *DynTargets.begin();

      auto eit_pair = boost::out_edges(bb, ICFG);
      assert(eit_pair.first == eit_pair.second);

      function_t &callee = Decompilation.Binaries[DynTarget.first]
                               .Analysis.Functions[DynTarget.second];

      std::vector<flow_vertex_t> calleeExitVertices;
      flow_vertex_t calleeEntryV = copy_function_cfg(
          NeedsUpdate, G, callee, calleeExitVertices, memoize);
      flow_vertex_t newExitV = boost::add_vertex(G);
      G[newExitV].bbprop = &empty_bb_prop;

      {
        flow_edge_t E =
            boost::add_edge(Orig2CopyMap[bb], calleeEntryV, G).first;
        assert(callee.IsABI);
        G[E].live.flow = mask_CallConvArgs_flow;
      }

      for (flow_vertex_t V : calleeExitVertices) {
        flow_edge_t E = boost::add_edge(V, newExitV, G).first;
        G[E].reach.flow = mask_CallConvRets_flow;
      }

      exitVertices.erase(it);
      exitVertices.push_back(newExitV);
      break;
    }

    default:
      continue;
    }
  }

  return res;
}

void function_t::Analyze(void) {
  if (!this->Analysis.Stale)
    return;
  this->Analysis.Stale = false;

  {
    flow_graph_t G;

    std::unordered_map<function_t *,
                       std::pair<flow_vertex_t, std::vector<flow_vertex_t>>>
        _unused;

    bool NeedsUpdate = false;
    std::vector<flow_vertex_t> exitVertices;
    flow_vertex_t entryV =
        copy_function_cfg(NeedsUpdate, G, *this, exitVertices, _unused);

    //
    // build vector of vertices in DFS order
    //
    std::vector<flow_vertex_t> Vertices;
    Vertices.reserve(boost::num_vertices(G));

    {
      dfs_visitor<flow_graph_t> vis(Vertices);

      std::map<flow_vertex_t, boost::default_color_type> colorMap;
#if 0
    boost::depth_first_visit(
        G, entryV, vis,
        boost::associative_property_map<
            std::map<flow_vertex_t, boost::default_color_type>>(colorMap));
#else
      boost::depth_first_search(
          G, vis,
          boost::associative_property_map<
              std::map<flow_vertex_t, boost::default_color_type>>(colorMap));
#endif
    }

    bool change;

    //
    // liveness analysis
    //
    for (flow_vertex_t V : Vertices) {
      G[V].IN.reset();
      G[V].OUT.reset();
    }

    do {
      change = false;

      for (flow_vertex_t V : boost::adaptors::reverse(Vertices)) {
        const tcg_global_set_t _IN = G[V].IN;

        auto eit_pair = boost::out_edges(V, G);
        G[V].OUT = std::accumulate(
            eit_pair.first, eit_pair.second, tcg_global_set_t(),
            [&](tcg_global_set_t res, control_flow_t E) {
              return res | G[boost::target(E, G)].IN;
            });

        tcg_global_set_t use = G[V].bbprop->Analysis.live.use;
        tcg_global_set_t def = G[V].bbprop->Analysis.live.def;

        G[V].IN = use | (G[V].OUT & ~def);

        change = change || _IN != G[V].IN;
      }
    } while (change);

    this->Analysis.args = G[entryV].IN;
    this->Analysis.args.reset(tcg_env_index);
#if defined(__x86_64__)
    this->Analysis.args.reset(tcg_fs_base_index);
#elif defined(__i386__)
    this->Analysis.args.reset(tcg_gs_base_index);
#endif
    if (tcg_program_counter_index >= 0)
      this->Analysis.args.reset(tcg_program_counter_index);

    //
    // reaching definitions
    //
    for (flow_vertex_t V : Vertices) {
      G[V].IN.reset();
      G[V].OUT.reset();
    }

    do {
      change = false;

      for (flow_vertex_t V : Vertices) {
        const tcg_global_set_t _OUT = G[V].OUT;

        auto eit_pair = boost::in_edges(V, G);
        G[V].IN = std::accumulate(
            eit_pair.first, eit_pair.second, tcg_global_set_t(),
            [&](tcg_global_set_t glbs, flow_edge_t E) {
              return glbs | G[E].reach.flow(G[boost::source(E, G)].OUT);
            });
        G[V].OUT = G[V].bbprop->Analysis.reach.def | G[V].IN;

        change = change || _OUT != G[V].OUT;
      }
    } while (change);

    if (exitVertices.empty()) {
      this->Analysis.rets.reset();
    } else {
      this->Analysis.rets =
          std::accumulate(std::next(exitVertices.begin()), exitVertices.end(),
                          G[exitVertices.front()].OUT,
                          [&](tcg_global_set_t res, flow_vertex_t V) {
                            return res & G[V].OUT;
                          });

      this->Analysis.rets.reset(tcg_env_index);
#if defined(__x86_64__)
      this->Analysis.rets.reset(tcg_fs_base_index);
#elif defined(__i386__)
      this->Analysis.rets.reset(tcg_gs_base_index);
#endif
      if (tcg_program_counter_index >= 0)
        this->Analysis.rets.reset(tcg_program_counter_index);
    }
  }

  if (this->IsABI) {
    this->Analysis.rets &= CallConvRets;

#if 0
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
#elif 0
    // XXX TODO
    assert(!CallConvRetArray.empty());
    if (this->Analysis.rets[CallConvRetArray.front()]) {
      this->Analysis.rets.reset();
      this->Analysis.rets.set(CallConvRetArray.front());
    } else {
      this->Analysis.rets.reset();
    }
#endif
  }

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
  }
}

const helper_function_t &LookupHelper(TCGOp *op);

static tcg_global_set_t DetermineFunctionArgs(function_t &);
static tcg_global_set_t DetermineFunctionRets(function_t &);

void basic_block_properties_t::Analyze(binary_index_t BIdx) {
  if (!this->Analysis.Stale)
    return;

  this->Analysis.Stale = false;

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
    do_tcg_optimization = true; /* XXX */

    unsigned len;
    std::tie(len, T) = TCG->translate(Addr + size, Addr + Size);

    do_tcg_optimization = false; /* XXX */

    TCGArg constprop[tcg_max_temps];
    constprop[tcg_syscall_number_index] = std::numeric_limits<TCGArg>::max();

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

        void *helper_ptr =
            reinterpret_cast<void *>(op->args[nb_oargs + nb_iargs]);
#if defined(__x86_64__)
        if (helper_ptr == helper_syscall) {
#elif defined(__i386__)
        if (helper_ptr && false /* TODO */) {
#elif defined(__aarch64__)
        if (helper_ptr == helper_exception_with_syndrome &&
	    constprop[temp_idx(arg_temp(op->args[nb_oargs + 1]))] == EXCP_SWI) {
#elif defined(__mips64)
        if (helper_ptr && false /* TODO */) {
#elif defined(__mips__)
        if (helper_ptr && false /* TODO */) {
#else
#error
#endif
          const auto &N = constprop[tcg_syscall_number_index];
          if (N < syscalls::NR_END) {
            iglbs.reset();
            oglbs.reset();

            unsigned M = syscalls::nparams_tbl[N];
            assert(M < 7);
            switch (M) {
              case 6:
                if (tcg_syscall_arg6_index >= 0)
                  iglbs.set(tcg_syscall_arg6_index);
                /* fallthrough */
              case 5:
                if (tcg_syscall_arg5_index >= 0)
                  iglbs.set(tcg_syscall_arg5_index);
                /* fallthrough */
              case 4:
                if (tcg_syscall_arg4_index >= 0)
                  iglbs.set(tcg_syscall_arg4_index);
                /* fallthrough */
              case 3:
                if (tcg_syscall_arg3_index >= 0)
                  iglbs.set(tcg_syscall_arg3_index);
                /* fallthrough */
              case 2:
                if (tcg_syscall_arg2_index >= 0)
                  iglbs.set(tcg_syscall_arg2_index);
                /* fallthrough */
              case 1:
                if (tcg_syscall_arg1_index >= 0)
                  iglbs.set(tcg_syscall_arg1_index);
                /* fallthrough */
              case 0:
                break;

              default:
                __builtin_trap();
                __builtin_unreachable();
            }

            oglbs.set(tcg_syscall_return_index);
            iglbs.set(tcg_syscall_number_index);
          }
        }
      } else {
        const TCGOpDef &opdef = tcg_op_defs[opc];

        nb_iargs = opdef.nb_iargs;
        nb_oargs = opdef.nb_oargs;
      }

      if (opc == INDEX_op_movi_i64 ||
          opc == INDEX_op_movi_i32) {
        TCGTemp *ts = arg_temp(op->args[0]);
        unsigned glb_idx = temp_idx(ts);

        constprop[glb_idx] = op->args[1];
      }

      if (opc == INDEX_op_mov_i64 ||
          opc == INDEX_op_mov_i32) {
        TCGTemp *dst = arg_temp(op->args[0]);
        TCGTemp *src = arg_temp(op->args[1]);

        unsigned dst_idx = temp_idx(dst);
        unsigned src_idx = temp_idx(src);

        constprop[dst_idx] = constprop[src_idx];
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

  switch (this->Term.Type) {
  case TERMINATOR::INDIRECT_JUMP:
  case TERMINATOR::INDIRECT_CALL: {
    tcg_global_set_t iglbs, oglbs;
    iglbs.set(tcg_stack_pointer_index);
    oglbs.set(tcg_stack_pointer_index);

    this->Analysis.live.use |= (iglbs & ~this->Analysis.live.def);
    this->Analysis.live.def |= (oglbs & ~this->Analysis.live.use);

    this->Analysis.reach.def |= oglbs;
    break;
  }

  default:
    break;
  }

  if (opts::PrintDefAndUse) {
    llvm::outs() << (fmt("%#lx") % Addr).str() << '\n';

    uint64_t InstLen;
    for (uintptr_t A = Addr; A < Addr + Size; A += InstLen) {
      std::ptrdiff_t Offset = A - (*sectit).first.lower();

      llvm::MCInst Inst;
      bool Disassembled = DisAsm->getInstruction(
          Inst, InstLen, sectprop.contents.slice(Offset), A, llvm::nulls());
      if (!Disassembled) {
        WithColor::error() << "failed to disassemble "
                           << (fmt("%#lx") % Addr).str() << '\n';
        break;
      }

      IP->printInst(&Inst, A, "", *STI, llvm::outs());
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

static bool shouldExpandOperationWithSize(llvm::Value *Size) {
#if 0
  ConstantInt *CI = dyn_cast<ConstantInt>(Size);
  return !CI || (CI->getZExtValue() > MaxStaticSize);
#else
  return true;
#endif
}

// from AMDGPULowerIntrinsics.cpp
static bool expandMemIntrinsicUses(llvm::Function &F) {
  llvm::Intrinsic::ID ID = F.getIntrinsicID();
  bool Changed = false;

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
        expandMemCpyAsLoop(Memcpy, TTI);
        Changed = true;
        Memcpy->eraseFromParent();
      }

      break;
    }
    case llvm::Intrinsic::memmove: {
      auto *Memmove = llvm::cast<llvm::MemMoveInst>(Inst);
      if (shouldExpandOperationWithSize(Memmove->getLength())) {
        llvm::expandMemMoveAsLoop(Memmove);
        Changed = true;
        Memmove->eraseFromParent();
      }

      break;
    }
    case llvm::Intrinsic::memset: {
      auto *Memset = llvm::cast<llvm::MemSetInst>(Inst);
      if (shouldExpandOperationWithSize(Memset->getLength())) {
        llvm::expandMemSetAsLoop(Memset);
        Changed = true;
        Memset->eraseFromParent();
      }

      break;
    }
    default:
      break;
    }
  }

  return Changed;
}

const helper_function_t &LookupHelper(TCGOp *op) {
  int nb_oargs = TCGOP_CALLO(op);
  int nb_iargs = TCGOP_CALLI(op);
  int nb_cargs;

  {
    const TCGOpcode opc = op->opc;
    const TCGOpDef &def = tcg_op_defs[opc];

    nb_cargs = def.nb_cargs;
  }

  uintptr_t addr = op->args[nb_oargs + nb_iargs];

  auto it = HelperFuncMap.find(addr);
  if (it == HelperFuncMap.end()) {
    TCGContext *s = &TCG->_ctx;
    const char *helper_nm = tcg_find_helper(s, addr);
    assert(helper_nm);

    assert(!Module->getFunction(std::string("helper_") + helper_nm) &&
           "helper function already exists");

    std::string suffix = opts::DFSan ? ".dfsan.bc" : ".bc";

    std::string helperModulePath =
        (boost::dll::program_location().parent_path() /
         (std::string(helper_nm) + suffix))
            .string();

    llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> BufferOr =
        llvm::MemoryBuffer::getFile(helperModulePath);
    if (!BufferOr) {
      WithColor::error() << "could not open bitcode for helper_" << helper_nm
                         << " (" << BufferOr.getError().message() << ")\n";
      exit(1);
    }

    llvm::Expected<std::unique_ptr<llvm::Module>> helperModuleOr =
        llvm::parseBitcodeFile(BufferOr.get()->getMemBufferRef(), *Context);
    if (!helperModuleOr) {
      llvm::logAllUnhandledErrors(helperModuleOr.takeError(), llvm::errs(),
                                  "could not parse helper bitcode: ");
      exit(1);
    }

    std::unique_ptr<llvm::Module> &helperModule = helperModuleOr.get();

    //
    // process helper bitcode
    //
    {
      llvm::Module &helperM = *helperModule;

      //
      // internalize all functions except the desired helper
      //
      for (llvm::Function &F : helperM.functions()) {
        if (F.isIntrinsic())
          continue;

        // is declaration?
        if (F.empty())
          continue;

        // is helper function?
        if (F.getName() == std::string("helper_") + helper_nm) {
          assert(F.getLinkage() == llvm::GlobalValue::ExternalLinkage);
          continue;
        }

#if 1
        F.setLinkage(llvm::GlobalValue::InternalLinkage);
#else
        F.setLinkage(llvm::GlobalValue::LinkOnceODRLinkage);
        F.setVisibility(llvm::GlobalValue::HiddenVisibility);
#endif
      }

      //
      // internalize global variables
      //
      for (llvm::GlobalVariable &GV : helperM.globals()) {
        if (!GV.hasInitializer())
          continue;

#if 1
        GV.setLinkage(llvm::GlobalValue::InternalLinkage);
#else
        GV.setLinkage(llvm::GlobalValue::LinkOnceODRLinkage);
#endif
      }

      //
      // lower memory intrinsics (memcpy, memset, memmove)
      //
      for (llvm::Function &F : helperM.functions()) {
        if (!F.isDeclaration())
          continue;

        switch (F.getIntrinsicID()) {
        case llvm::Intrinsic::memcpy:
        case llvm::Intrinsic::memmove:
        case llvm::Intrinsic::memset:
          if (!expandMemIntrinsicUses(F))
            WithColor::warning() << "couldn't expand llvm.mem intrinsic\n";
          break;

        default:
          break;
        }
      }
    }

    llvm::Linker::linkModules(*Module, std::move(helperModule));

    llvm::Function *helperF =
        Module->getFunction(std::string("helper_") + helper_nm);

    if (!helperF) {
      WithColor::error() << llvm::formatv("cannot find helper function {0}\n",
                                          helper_nm);
      abort();
    }

#if 0
    if (helperF->arg_size() != nb_iargs) {
      WithColor::error() << llvm::formatv(
          "helper {0} takes {1} args but nb_iargs={2}\n", helper_nm,
          helperF->arg_size(), nb_iargs);
      exit(1);
    }
#else
    assert(nb_iargs >= helperF->arg_size());
#endif

    assert(helperF->getLinkage() == llvm::GlobalValue::ExternalLinkage);
    helperF->setVisibility(llvm::GlobalValue::HiddenVisibility);

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

    helper_function_t &hf = HelperFuncMap[addr];
    hf.F = helperF;
    hf.EnvArgNo = EnvArgNo;
    hf.Analysis.Simple = AnalyzeHelper(hf); /* may modify hf.Analysis.InGlbs */

#if defined(__x86_64__)
    if (reinterpret_cast<void *>(addr) ==
        reinterpret_cast<void *>(helper_syscall))
#elif defined(__aarch64__)
    if (reinterpret_cast<void *>(addr) ==
        reinterpret_cast<void *>(helper_exception_with_syndrome))
#else
    if (false)
#endif
    {
      hf.Analysis.Simple = true; /* XXX */
    }

    WithColor::note() << llvm::formatv(
        "[helper] {0} {1}\n", hf.Analysis.Simple ? "-" : "+", helper_nm);

    return hf;
  } else {
    return (*it).second;
  }
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

static llvm::Type *PointerToWordType(void) {
  return llvm::PointerType::get(WordType(), 0);
}

static llvm::Type *PPointerType(void) {
  return llvm::PointerType::get(PointerToWordType(), 0);
}

static unsigned WordBits(void) {
  return sizeof(uintptr_t) * 8;
}

llvm::Type *VoidType(void) {
  return llvm::Type::getVoidTy(*Context);
}

static llvm::Type *VoidFunctionPointer(void) {
  llvm::FunctionType *FTy = llvm::FunctionType::get(VoidType(), false);
  return llvm::PointerType::get(FTy, 0);
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

    std::string jove_name = (fmt("%c%lx") % (f.IsABI ? 'J' : 'j') %
                             ICFG[boost::vertex(f.Entry, ICFG)].Addr)
                                .str();

    f.F = llvm::Function::Create(DetermineFunctionType(f),
                                 llvm::GlobalValue::ExternalLinkage, jove_name,
                                 Module.get());
    //f.F->addFnAttr(llvm::Attribute::UWTable);

    for (const symbol_t &sym : f.Syms) {
      if (sym.Vers.empty()) {
        llvm::GlobalAlias::create(sym.Name, f.F);
      } else {
         // make sure version node is defined
        VersionScript.Table[sym.Vers.str()];

        Module->appendModuleInlineAsm(
            (llvm::Twine(".symver ") + jove_name + "," + sym.Name +
             (sym.Visibility.IsDefault ? "@@" : "@") + sym.Vers)
                .str());
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

int CreateFunctionTable(void) {
  binary_t &binary = Decompilation.Binaries[BinaryIndex];
  auto &ICFG = binary.Analysis.ICFG;

  std::vector<llvm::Constant *> constantTable;
  constantTable.resize(2 * binary.Analysis.Functions.size());

  for (unsigned i = 0; i < binary.Analysis.Functions.size(); ++i) {
    const function_t &f = binary.Analysis.Functions[i];
    uintptr_t Addr = ICFG[boost::vertex(f.Entry, ICFG)].Addr;

    llvm::Constant *C1 = llvm::ConstantExpr::getPtrToInt(SectionPointer(Addr), WordType());
    llvm::Constant *C2 = llvm::ConstantExpr::getPtrToInt(f.F, WordType());

    constantTable[2 * i + 0] = C1;
    constantTable[2 * i + 1] = C2;
  }

  constantTable.push_back(llvm::Constant::getNullValue(WordType()));

  llvm::ArrayType *T = llvm::ArrayType::get(WordType(), constantTable.size());
  llvm::Constant *Init = llvm::ConstantArray::get(T, constantTable);
  llvm::GlobalVariable *ConstantTableGV = new llvm::GlobalVariable(
      *Module, T, true, llvm::GlobalValue::InternalLinkage, Init,
      "__jove_function_table");

#if 0
  {
    llvm::Function *StoresFnTblPtrF =
        Module->getFunction("_jove_install_function_table");
    assert(StoresFnTblPtrF && StoresFnTblPtrF->empty());

    llvm::BasicBlock *EntryB =
        llvm::BasicBlock::Create(*Context, "", StoresFnTblPtrF);

    {
      llvm::IRBuilderTy IRB(EntryB);

      IRB.CreateStore(IRB.CreateConstInBoundsGEP2_64(FuncTableGV, 0, 0),
                      IRB.CreateConstInBoundsGEP2_64(JoveFunctionTablesGlobal,
                                                     0, BinaryIndex));

      IRB.CreateRetVoid();
    }

    StoresFnTblPtrF->setLinkage(llvm::GlobalValue::InternalLinkage);

    llvm::appendToGlobalCtors(*Module, StoresFnTblPtrF, 0);
  }
#else
  llvm::Function *GetFunctionTableF =
      Module->getFunction("_jove_get_function_table");
  assert(GetFunctionTableF && GetFunctionTableF->empty());

  llvm::BasicBlock *BB =
      llvm::BasicBlock::Create(*Context, "", GetFunctionTableF);

  {
    llvm::IRBuilderTy IRB(BB);

    IRB.CreateRet(IRB.CreateConstInBoundsGEP2_64(ConstantTableGV, 0, 0));
  }

  GetFunctionTableF->setLinkage(llvm::GlobalValue::InternalLinkage);
#endif

  return 0;
}

#if 0
int RenameFunctions(void) {
  for (const auto &pair : ExportedFunctions) {
    assert(!pair.second.empty());

    for (const auto &IdxPair : pair.second) {
      binary_index_t BinIdx;
      function_index_t FuncIdx;
      std::tie(BinIdx, FuncIdx) = IdxPair;

      if (BinIdx != BinaryIndex)
        continue;

      function_t &f =
          Decompilation.Binaries[BinIdx].Analysis.Functions[FuncIdx];

      if (!f.IsNamed) {
        f.IsNamed = true;

        std::string oldName = f.F->getName();
        f.F->setName(pair.first);

        llvm::GlobalAlias::create(oldName, f.F);
      } else {
        llvm::GlobalAlias::create(pair.first, f.F);
      }
    }
  }

  return 0;
}
#endif

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

struct section_t {
  llvm::StringRef Name;
  llvm::ArrayRef<uint8_t> Contents;
  uintptr_t Addr;
  unsigned Size;

  bool initArray;
  bool finiArray;

  struct {
    boost::icl::split_interval_set<uintptr_t> Intervals;
    std::map<unsigned, llvm::Constant *> Constants;
    std::map<unsigned, llvm::Type *> Types;
  } Stuff;

  llvm::StructType *T;
};

llvm::Constant *SectionPointer(uintptr_t Addr) {
  if (!(Addr >= SectsStartAddr && Addr <= SectsEndAddr))
    return nullptr;

  unsigned off = Addr - SectsStartAddr;

  llvm::GlobalVariable *SectsGV =
      ConstantRelocationLocs.find(Addr) != ConstantRelocationLocs.end()
          ? ConstSectsGlobal
          : SectsGlobal;

  assert(SectsGV);

  // special case the end
  if (Addr == SectsEndAddr)
    return llvm::ConstantExpr::getIntToPtr(
        llvm::ConstantExpr::getAdd(
            llvm::ConstantExpr::getPtrToInt(SectsGV, WordType()),
            llvm::ConstantInt::get(WordType(), off)),
        llvm::PointerType::get(llvm::Type::getInt8Ty(*Context), 0));

  {
    llvm::IRBuilderTy IRB(*Context);
    llvm::SmallVector<llvm::Value *, 4> Indices;
    llvm::Value *res = llvm::getNaturalGEPWithOffset(
        IRB, DL, SectsGV, llvm::APInt(64, off), nullptr, Indices, "");

    if (res && llvm::isa<llvm::Constant>(res))
      return llvm::cast<llvm::Constant>(res);
  }

  return llvm::ConstantExpr::getIntToPtr(
      llvm::ConstantExpr::getAdd(
          llvm::ConstantExpr::getPtrToInt(SectsGV, WordType()),
          llvm::ConstantInt::get(WordType(), off)),
      llvm::PointerType::get(llvm::Type::getInt8Ty(*Context), 0));
}

int CreateTLSModGlobal(void) {
  TLSModGlobal = new llvm::GlobalVariable(
      *Module, WordType(), true, llvm::GlobalValue::InternalLinkage,
      llvm::ConstantInt::get(WordType(), 0x12345678), "__jove_tpmod");
  return 0;
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
      Sect.initArray = prop.initArray;
      Sect.finiArray = prop.finiArray;

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
        FTy = DetermineFunctionType(*(*it).second.begin());
      }
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

    return llvm::PointerType::get(llvm::Type::getInt8Ty(*Context), 0);
  };

  auto type_of_relative_relocation =
      [&](const relocation_t &R) -> llvm::Type * {
    uintptr_t Addr;
    if (R.Addend) {
      Addr = R.Addend;
    } else {
      auto it = SectIdxMap.find(R.Addr);
      assert(it != SectIdxMap.end());

      section_t &Sect = SectTable[(*it).second];
      unsigned Off = R.Addr - Sect.Addr;

      assert(!Sect.Contents.empty());
      Addr = *reinterpret_cast<const uintptr_t *>(&Sect.Contents[Off]);
    }

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

    {
      auto &RelocDynTargets =
          Decompilation.Binaries[BinaryIndex].Analysis.RelocDynTargets;

      auto it = RelocDynTargets.find(R.Addr);
      if (it == RelocDynTargets.end() || (*it).second.empty()) {
        WithColor::error() << llvm::formatv("{0}:{1} have you run jove-dyn?\n",
                                            __FILE__, __LINE__);
        exit(1);
      }

      FTy = DetermineFunctionType(*(*it).second.begin());
    }

    return llvm::PointerType::get(FTy, 0);
  };

  auto type_of_tpoff_relocation = [&](const relocation_t &R) -> llvm::Type * {
    if (R.SymbolIndex < SymbolTable.size()) {
      const symbol_t &S = SymbolTable[R.SymbolIndex];

      assert(S.IsUndefined());
      assert(!S.Size);

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

      return llvm::PointerType::get(T, 0);
    }

    auto it = TLSValueToSymbolMap.find(R.Addend);
    if (it == TLSValueToSymbolMap.end()) {
      WithColor::error() << "no sym found for tpoff relocation\n";
      return nullptr;
    }

    llvm::StringRef SymName = *(*it).second.begin();
    llvm::GlobalVariable *GV = Module->getGlobalVariable(SymName, true);
    if (!GV)
      return nullptr;

    return GV->getType();
  };

  auto type_of_tpmod_relocation = [&](const relocation_t &R) -> llvm::Type * {
    return TLSModGlobal->getType();
  };

  auto type_of_copy_relocation = [&](const relocation_t &R,
                                     const symbol_t &S) -> llvm::Type * {
    assert(R.Addr == S.Addr);

    if (!S.Size) {
      WithColor::error() << llvm::formatv(
          "copy relocation @ 0x{0:x} specifies symbol {1} with size 0\n",
          R.Addr, S.Name);
      abort();
    }

    WithColor::error() << llvm::formatv(
        "copy relocation @ 0x{0:x} specifies symbol {1} with size {2}\n"
        "was prog compiled as a position-independant executable?\n",
        R.Addr, S.Name, S.Size);
    abort();

#if 0
    unsigned off = R.Addr - SectsStartAddr;

    Module->appendModuleInlineAsm(
        (fmt(".reloc __jove_sections+%u, R_X86_64_COPY, %s")
         % off
         % S.Name.str()).str());
#elif 1
    Module->appendModuleInlineAsm(
        (fmt(".reloc __jove_sections, R_X86_64_COPY, %s") % S.Name.str()).str());
#elif 0
    unsigned off = R.Addr - SectsStartAddr;

    Module->appendModuleInlineAsm(
        (fmt("lbl%u:\n.8byte 0\n.reloc lbl%u, R_X86_64_COPY, %s")
         % off
         % off
         % S.Name.str()).str());
#endif

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

    default:
      WithColor::error() << llvm::formatv(
          "type_of_relocation: unhandled relocation type {0}\n",
          string_of_reloc_type(R.Type));
      abort();
    }
  };

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

    if (llvm::Function *F = Module->getFunction(S.Name))
      return F;

    llvm::FunctionType *FTy;
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
        FTy = DetermineFunctionType(*(*it).second.begin());
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

    //return Module->getNamedValue(S.Name);

    return llvm::ConstantExpr::getBitCast(
        SectionPointer(S.Addr),
        llvm::PointerType::get(llvm::Type::getInt8Ty(*Context), 0));
  };

  auto constant_of_relative_relocation =
      [&](const relocation_t &R) -> llvm::Constant * {
    uintptr_t Addr;
    if (R.Addend) {
      Addr = R.Addend;
    } else {
      auto it = SectIdxMap.find(R.Addr);
      assert(it != SectIdxMap.end());

      section_t &Sect = SectTable[(*it).second];
      unsigned Off = R.Addr - Sect.Addr;

      assert(!Sect.Contents.empty());
      Addr = *reinterpret_cast<const uintptr_t *>(&Sect.Contents[Off]);
    }

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
        exit(1);
      }

      IdxPair = *(*it).second.begin();
    }

    auto it = FuncMap.find(R.Addend);
    assert(it != FuncMap.end());

    function_t &f =
        Decompilation.Binaries[BinaryIndex].Analysis.Functions[(*it).second];

    assert(f._resolver.IFunc);
    return f._resolver.IFunc;
  };

  auto constant_of_tpoff_relocation =
      [&](const relocation_t &R) -> llvm::Constant * {
    if (R.SymbolIndex < SymbolTable.size()) {
      const symbol_t &S = SymbolTable[R.SymbolIndex];

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

      return GV;
    }

    auto it = TLSValueToSymbolMap.find(R.Addend);
    if (it == TLSValueToSymbolMap.end()) {
      WithColor::error() << "no sym found for tpoff relocation\n";
      return nullptr;
    }

    llvm::StringRef SymName = *(*it).second.begin();
    llvm::GlobalVariable *GV = Module->getGlobalVariable(SymName, true);
    if (!GV)
      return nullptr;

    return GV;
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

#if 1
      default:
        WithColor::warning() << llvm::formatv(
            "addressof {0} has unknown symbol type; treating as data\n",
            S.Name);
#endif

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
                                           nullptr, "__jove_sections");
    SectsGlobal->setAlignment(llvm::MaybeAlign(4096));

    ConstSectsGlobal = new llvm::GlobalVariable(
        *Module, SectsGlobalTy, false, llvm::GlobalValue::ExternalLinkage,
        nullptr, "__jove_sections_const");
    ConstSectsGlobal->setAlignment(llvm::MaybeAlign(4096));

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

  auto create_global_variable = [&](uintptr_t Addr, unsigned Size,
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
      if (Size == sizeof(uintptr_t)) {
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

    for (const auto &_intvl : Sect.Stuff.Intervals) {
      uintptr_t lower = _intvl.lower();
      uintptr_t upper = _intvl.upper();

      if (upper <= Off)
        continue;

      if (lower >= Off + Size)
        break;

      if (lower < Off)
        lower = Off;
      if (upper > Off + Size)
        upper = Off + Size;

      ptrdiff_t len = upper - lower;

      auto typeit = Sect.Stuff.Types.find(lower);
      auto constit = Sect.Stuff.Constants.find(lower);

      llvm::Type *T;
      llvm::Constant *C;

      if (typeit == Sect.Stuff.Types.end() ||
          constit == Sect.Stuff.Constants.end()) {
        T = llvm::ArrayType::get(llvm::IntegerType::get(*Context, 8), len);
        if (Sect.Contents.size() >= len) {
          C = llvm::ConstantDataArray::get(
              *Context, llvm::ArrayRef<uint8_t>(Sect.Contents.begin() + lower,
                                                Sect.Contents.begin() + upper));
        } else {
          C = llvm::Constant::getNullValue(T);
        }
      } else {
        assert(constit != Sect.Stuff.Constants.end());

        T = (*typeit).second;
        C = (*constit).second;
      }

      if (!T || !C)
        return nullptr;

      GVFieldTys.push_back(T);
      GVFieldInits.push_back(C);
    }

    llvm::StructType *ST = llvm::StructType::create(
        *Context, GVFieldTys, "struct." + SymName.str(), true /* isPacked */);

    return new llvm::GlobalVariable(
        *Module, ST, false, llvm::GlobalValue::ExternalLinkage,
        llvm::ConstantStruct::get(ST, GVFieldInits), SymName, nullptr, tlsMode);
  };

  auto clear_section_stuff = [&](void) -> void {
    for (section_t &Sect : SectTable) {
      Sect.Stuff.Constants.clear();
      Sect.Stuff.Types.clear();
      Sect.Stuff.Intervals.clear();
      Sect.Stuff.Intervals.insert(
          boost::icl::interval<uintptr_t>::right_open(0, Sect.Size));
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

      if (Module->getNamedValue(SymName))
        continue;

      uintptr_t Addr = pair.first;

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
  } while (!done);

  //
  // Binary DT_INIT
  //
  // XXX this should go somewhere else
  {
    auto &binary = Decompilation.Binaries[BinaryIndex];
    auto &st = BinStateVec[BinaryIndex];
    auto &FuncMap = st.FuncMap;

    assert(llvm::isa<ELFO>(binary.ObjectFile.get()));
    ELFO &O = *llvm::cast<ELFO>(binary.ObjectFile.get());
    const ELFT &E = *O.getELFFile();

    auto checkDRI = [&E](DynRegionInfo DRI) -> DynRegionInfo {
      if (DRI.Addr < E.base() ||
          (const uint8_t *)DRI.Addr + DRI.Size > E.base() + E.getBufSize())
        abort();
      return DRI;
    };

    DynRegionInfo DynamicTable;
    {
      auto createDRIFrom = [&E, &checkDRI](const Elf_Phdr *P,
                                           uint64_t EntSize) -> DynRegionInfo {
        return checkDRI({E.base() + P->p_offset, P->p_filesz, EntSize});
      };

      for (const Elf_Phdr &Phdr : unwrapOrError(E.program_headers())) {
        if (Phdr.p_type != llvm::ELF::PT_DYNAMIC)
          continue;

        DynamicTable = createDRIFrom(&Phdr, sizeof(Elf_Dyn));
        break;
      }
    }

    assert(DynamicTable.Addr);

    //
    // parse dynamic table
    //
    auto dynamic_table = [&DynamicTable](void) -> Elf_Dyn_Range {
      return DynamicTable.getAsArrayRef<Elf_Dyn>();
    };

    uintptr_t initFunctionAddr = 0;

    for (const Elf_Dyn &Dyn : dynamic_table()) {
      switch (Dyn.d_tag) {
      case llvm::ELF::DT_INIT:
        initFunctionAddr = Dyn.getVal();
        break;
      }
    };

    if (initFunctionAddr) {
      auto it = FuncMap.find(initFunctionAddr);
      if (it == FuncMap.end()) {
        WithColor::error() << llvm::formatv(
            "DT_INIT: unknown function @ {0:x}\n", initFunctionAddr);
      } else {
        function_t &f = Decompilation.Binaries[BinaryIndex]
                            .Analysis.Functions[(*it).second];
        assert(f.IsABI);

        llvm::Function *F = f.F;
        auto it = CtorStubMap.find(F);
        if (it == CtorStubMap.end()) {
          llvm::FunctionType *FTy = F->getFunctionType();

          // TODO refactor this
          llvm::Function *CallsF = llvm::Function::Create(
              FTy, llvm::GlobalValue::ExternalLinkage,
              std::string(F->getName()) + "_ctor", Module.get());

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

          llvm::CallInst *Call;
          {
            llvm::IRBuilderTy IRB(EntryB);
            IRB.SetCurrentDebugLocation(llvm::DILocation::get(
                *Context, /* Line */ 0, /* Column */ 0, DebugInfo.Subprogram));

            IRB.CreateCall(JoveInstallForeignFunctionTables)->setIsNoInline();

            {
              llvm::Function *StoresFnTblPtrF =
                  Module->getFunction("_jove_install_function_table");
              assert(StoresFnTblPtrF && !StoresFnTblPtrF->empty());
              IRB.CreateCall(StoresFnTblPtrF);
            }

            llvm::Value *SPPtr = CPUStateGlobalPointer(tcg_stack_pointer_index);

            llvm::Value *SavedSP = IRB.CreateLoad(SPPtr);
            SavedSP->setName("saved_sp");

#if 0
            {
              constexpr unsigned StackAllocaSize = 0x10000;

              llvm::AllocaInst *StackAlloca = IRB.CreateAlloca(
                  llvm::ArrayType::get(IRB.getInt8Ty(), StackAllocaSize));

              llvm::Value *NewSP = IRB.CreateConstInBoundsGEP2_64(
                  StackAlloca, 0, StackAllocaSize - 4096);

              IRB.CreateStore(IRB.CreatePtrToInt(NewSP, WordType()), SPPtr);
            }
#else
            llvm::Value *TemporaryStack = IRB.CreateCall(JoveAllocStackFunc);

            {
              llvm::Value *NewSP = IRB.CreateAdd(
                  TemporaryStack,
                  llvm::ConstantInt::get(WordType(), JOVE_STACK_SIZE -
                                                         JOVE_PAGE_SIZE - 16));

              IRB.CreateStore(llvm::ConstantInt::get(WordType(), Cookie),
                              IRB.CreateIntToPtr(NewSP, llvm::PointerType::get(
                                                            WordType(), 0)));

              IRB.CreateStore(NewSP, SPPtr);
            }
#endif

            llvm::Value *SavedTraceP = nullptr;
            if (opts::Trace) {
              SavedTraceP = IRB.CreateLoad(TraceGlobal);
              SavedTraceP->setName("saved_tracep");

              {
                constexpr unsigned TraceAllocaSize = 4096;

                llvm::AllocaInst *TraceAlloca = IRB.CreateAlloca(
                    llvm::ArrayType::get(IRB.getInt64Ty(), TraceAllocaSize));

                llvm::Value *NewTraceP =
                    IRB.CreateConstInBoundsGEP2_64(TraceAlloca, 0, 0);

                IRB.CreateStore(NewTraceP, TraceGlobal);
              }
            }

            llvm::Value *SavedCallStackP = nullptr;
            if (opts::CallStack) {
              SavedCallStackP = IRB.CreateLoad(CallStackGlobal);
              SavedCallStackP->setName("saved_callstack");

              {
                constexpr unsigned CallStackAllocaSize = 4096 * 16;

                llvm::AllocaInst *TraceAlloca = IRB.CreateAlloca(
                    llvm::ArrayType::get(IRB.getInt64Ty(), CallStackAllocaSize));

                llvm::Value *NewCallStackP =
                    IRB.CreateConstInBoundsGEP2_64(TraceAlloca, 0, 0);

                IRB.CreateStore(NewCallStackP, CallStackGlobal);
              }
            }

            unsigned N = FTy->getNumParams();

            std::vector<llvm::Value *> ArgVec;
            ArgVec.resize(N);

            for (unsigned i = 0; i < N; ++i)
              ArgVec[i] = &CallsF->arg_begin()[i];

            Call = IRB.CreateCall(F, ArgVec);
            Call->setIsNoInline();

            IRB.CreateStore(SavedSP, SPPtr);

#if 1
            {
              std::vector<llvm::Value *> _ArgVec = {TemporaryStack};
              IRB.CreateCall(JoveFreeStackFunc, _ArgVec);
            }
#endif

            if (opts::Trace)
              IRB.CreateStore(SavedTraceP, TraceGlobal);

            if (opts::CallStack)
              IRB.CreateStore(SavedCallStackP, CallStackGlobal);

            if (FTy->getReturnType()->isVoidTy())
              IRB.CreateRetVoid();
            else
              IRB.CreateRet(Call);
          }

          DIB.finalizeSubprogram(DebugInfo.Subprogram);

          //CallsToInline.push_back(Call);

          it = CtorStubMap.insert({F, CallsF}).first;
        }

        llvm::Function *CallsF = (*it).second;

        // casting to a llvm::Function* is a complete hack here. hoping the
        // following gets merged:
        // https://reviews.llvm.org/D64962
        llvm::appendToGlobalCtors(
            *Module,
            (llvm::Function *)llvm::ConstantExpr::getBitCast(
                CallsF, VoidFunctionPointer()),
            0);
      }
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
      assert(llvm::isa<llvm::Function>(C));

      llvm::Function *F = llvm::cast<llvm::Function>(C);

      {
        function_t &f = Decompilation.Binaries[BinaryIndex]
                            .Analysis.Functions[LLVMFnToJoveFnMap[F]];
        if (!f.IsABI) {
          WithColor::note() << llvm::formatv("!IsABI for {0}\n", F->getName());
          f.IsABI = true;

          ABIChanged = true;
        }
      }

      auto it = CtorStubMap.find(F);
      if (it == CtorStubMap.end()) {
        llvm::FunctionType *FTy = F->getFunctionType();

        // TODO refactor this
        llvm::Function *CallsF = llvm::Function::Create(
            FTy, llvm::GlobalValue::ExternalLinkage,
            std::string(F->getName()) + "_ctor", Module.get());

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

        llvm::CallInst *Call;
        {
          llvm::IRBuilderTy IRB(EntryB);
          IRB.SetCurrentDebugLocation(llvm::DILocation::get(
              *Context, /* Line */ 0, /* Column */ 0, DebugInfo.Subprogram));

          IRB.CreateCall(JoveInstallForeignFunctionTables)->setIsNoInline();

          {
            llvm::Function *StoresFnTblPtrF =
                Module->getFunction("_jove_install_function_table");
            assert(StoresFnTblPtrF && !StoresFnTblPtrF->empty());
            IRB.CreateCall(StoresFnTblPtrF);
          }

          llvm::Value *SPPtr = CPUStateGlobalPointer(tcg_stack_pointer_index);

          llvm::Value *SavedSP = IRB.CreateLoad(SPPtr);
          SavedSP->setName("saved_sp");

#if 0
          {
            constexpr unsigned StackAllocaSize = 0x10000;

            llvm::AllocaInst *StackAlloca = IRB.CreateAlloca(
                llvm::ArrayType::get(IRB.getInt8Ty(), StackAllocaSize));

            llvm::Value *NewSP = IRB.CreateConstInBoundsGEP2_64(
                StackAlloca, 0, StackAllocaSize - 4096);

            IRB.CreateStore(IRB.CreatePtrToInt(NewSP, WordType()), SPPtr);
          }
#else
          llvm::Value *TemporaryStack = IRB.CreateCall(JoveAllocStackFunc);

          {
            llvm::Value *NewSP = IRB.CreateAdd(
                TemporaryStack,
                llvm::ConstantInt::get(WordType(),
                                       JOVE_STACK_SIZE - JOVE_PAGE_SIZE - 16));

            IRB.CreateStore(llvm::ConstantInt::get(WordType(), Cookie),
                            IRB.CreateIntToPtr(
                                NewSP, llvm::PointerType::get(WordType(), 0)));

            IRB.CreateStore(NewSP, SPPtr);
          }
#endif

          llvm::Value *SavedTraceP = nullptr;
          if (opts::Trace) {
            SavedTraceP = IRB.CreateLoad(TraceGlobal);
            SavedTraceP->setName("saved_tracep");

            {
              constexpr unsigned TraceAllocaSize = 4096;

              llvm::AllocaInst *TraceAlloca = IRB.CreateAlloca(
                  llvm::ArrayType::get(IRB.getInt64Ty(), TraceAllocaSize));

              llvm::Value *NewTraceP =
                  IRB.CreateConstInBoundsGEP2_64(TraceAlloca, 0, 0);

              IRB.CreateStore(NewTraceP, TraceGlobal);
            }
          }

          llvm::Value *SavedCallStackP = nullptr;
          if (opts::CallStack) {
            SavedCallStackP = IRB.CreateLoad(CallStackGlobal);
            SavedCallStackP->setName("saved_callstack");

            {
              constexpr unsigned CallStackAllocaSize = 4096 * 16;

              llvm::AllocaInst *TraceAlloca = IRB.CreateAlloca(
                  llvm::ArrayType::get(IRB.getInt64Ty(), CallStackAllocaSize));

              llvm::Value *NewCallStackP =
                  IRB.CreateConstInBoundsGEP2_64(TraceAlloca, 0, 0);

              IRB.CreateStore(NewCallStackP, CallStackGlobal);
            }
          }

          unsigned N = FTy->getNumParams();

          std::vector<llvm::Value *> ArgVec;
          ArgVec.resize(N);

          for (unsigned i = 0; i < N; ++i)
            ArgVec[i] = &CallsF->arg_begin()[i];

          Call = IRB.CreateCall(F, ArgVec);
          Call->setIsNoInline();

          IRB.CreateStore(SavedSP, SPPtr);

#if 1
          {
            std::vector<llvm::Value *> _ArgVec = {TemporaryStack};
            IRB.CreateCall(JoveFreeStackFunc, _ArgVec);
          }
#endif

          if (opts::Trace)
            IRB.CreateStore(SavedTraceP, TraceGlobal);

          if (opts::CallStack)
            IRB.CreateStore(SavedCallStackP, CallStackGlobal);

          if (FTy->getReturnType()->isVoidTy())
            IRB.CreateRetVoid();
          else
            IRB.CreateRet(Call);
        }

        DIB.finalizeSubprogram(DebugInfo.Subprogram);

        //CallsToInline.push_back(Call);

        it = CtorStubMap.insert({F, CallsF}).first;
      }

      llvm::Function *CallsF = (*it).second;

      // casting to a llvm::Function* is a complete hack here. hoping the
      // following gets merged:
      // https://reviews.llvm.org/D64962
      if (Sect.initArray)
        llvm::appendToGlobalCtors(
            *Module,
            (llvm::Function *)llvm::ConstantExpr::getBitCast(
                CallsF, VoidFunctionPointer()),
            0);
      else
        llvm::appendToGlobalDtors(
            *Module,
            (llvm::Function *)llvm::ConstantExpr::getBitCast(
                CallsF, VoidFunctionPointer()),
            0);
    }
  }

  SectsGlobal->setVisibility(llvm::GlobalValue::HiddenVisibility);

  if (ABIChanged) {
    WriteDecompilation();

    execve(cmdline.argv[0], cmdline.argv, ::environ);
    abort();
  }

  return 0;
}

int CreatePCRelGlobal(void) {
  PCRelGlobal = new llvm::GlobalVariable(*Module, WordType(), false,
                                         llvm::GlobalValue::ExternalLinkage,
                                         nullptr, "__jove_pcrel");
  return 0;
}

int CreateTPBaseGlobal(void) {
  TPBaseGlobal = new llvm::GlobalVariable(
      *Module, WordType(), false, llvm::GlobalValue::ExternalLinkage, nullptr,
      "__jove_thread_pointer_base");
  return 0;
}

int FixupHelperStubs(void) {
  binary_t &Binary = Decompilation.Binaries[BinaryIndex];

  {
    llvm::Function *F = Module->getFunction("_jove_sections_start_file_addr");
    assert(F && F->empty());

    llvm::BasicBlock *BB = llvm::BasicBlock::Create(*Context, "", F);
    {
      llvm::IRBuilderTy IRB(BB);

      IRB.CreateRet(llvm::ConstantInt::get(WordType(), SectsStartAddr));
    }

    F->setLinkage(llvm::GlobalValue::InternalLinkage);
  }

  {
    llvm::Function *F = Module->getFunction("_jove_sections_global_beg_addr");
    assert(F && F->empty());

    llvm::BasicBlock *BB = llvm::BasicBlock::Create(*Context, "", F);
    {
      llvm::IRBuilderTy IRB(BB);

      IRB.CreateRet(llvm::ConstantExpr::getPtrToInt(SectsGlobal, WordType()));
    }

    F->setLinkage(llvm::GlobalValue::InternalLinkage);
  }

  {
    llvm::Function *F = Module->getFunction("_jove_sections_global_end_addr");
    assert(F && F->empty());

    llvm::BasicBlock *BB = llvm::BasicBlock::Create(*Context, "", F);
    {
      llvm::IRBuilderTy IRB(BB);

      // TODO call DL.getAllocSize and verify the numbers are the same
      uintptr_t SectsGlobalSize = SectsEndAddr - SectsStartAddr;

      IRB.CreateRet(llvm::ConstantExpr::getAdd(
          llvm::ConstantExpr::getPtrToInt(SectsGlobal, WordType()),
          llvm::ConstantInt::get(WordType(), SectsGlobalSize)));
    }

    F->setLinkage(llvm::GlobalValue::InternalLinkage);
  }

  {
    llvm::Function *F = Module->getFunction("_jove_binary_index");
    assert(F && F->empty());

    llvm::BasicBlock *BB = llvm::BasicBlock::Create(*Context, "", F);
    {
      llvm::IRBuilderTy IRB(BB);

      IRB.CreateRet(IRB.getInt32(BinaryIndex));
    }

    F->setLinkage(llvm::GlobalValue::InternalLinkage);
  }

  {
    llvm::Function *TraceEnabledF = Module->getFunction("_jove_trace_enabled");
    assert(TraceEnabledF && TraceEnabledF->empty());

    llvm::BasicBlock *BB =
        llvm::BasicBlock::Create(*Context, "", TraceEnabledF);
    {
      llvm::IRBuilderTy IRB(BB);

      IRB.CreateRet(IRB.getInt1(opts::Trace));
    }

    TraceEnabledF->setLinkage(llvm::GlobalValue::InternalLinkage);
  }

  {
    llvm::Function *F = Module->getFunction("_jove_dfsan_enabled");
    assert(F && F->empty());

    llvm::BasicBlock *BB =
        llvm::BasicBlock::Create(*Context, "", F);
    {
      llvm::IRBuilderTy IRB(BB);

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

    llvm::BasicBlock *BB =
        llvm::BasicBlock::Create(*Context, "", GetDynlFunctionTableF);

    {
      llvm::IRBuilderTy IRB(BB);

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

    llvm::BasicBlock *BB =
        llvm::BasicBlock::Create(*Context, "", GetVDSOFunctionTableF);

    {
      llvm::IRBuilderTy IRB(BB);

      IRB.CreateRet(IRB.CreateConstInBoundsGEP2_64(ConstantTableGV, 0, 0));
    }

    GetVDSOFunctionTableF->setLinkage(llvm::GlobalValue::InternalLinkage);
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

llvm::Constant *CPUStateGlobalPointer(unsigned glb) {
  if (glb == tcg_env_index)
    return CPUStateGlobal;

  assert(glb < tcg_num_globals);
  assert(temp_idx(TCG->_ctx.temps[glb].mem_base) == tcg_env_index);

  unsigned off = TCG->_ctx.temps[glb].mem_offset;

  unsigned bits = bitsOfTCGType(TCG->_ctx.temps[glb].type);
  llvm::Type *GlbTy = llvm::IntegerType::get(*Context, bits);

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

static int TranslateFunction(binary_t &Binary, function_t &f) {
  interprocedural_control_flow_graph_t &ICFG = Binary.Analysis.ICFG;
  llvm::Function *F = f.F;
  llvm::DIBuilder &DIB = *DIBuilder;

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

  llvm::DISubprogram::DISPFlags SubProgFlags =
      llvm::DISubprogram::SPFlagDefinition |
      llvm::DISubprogram::SPFlagOptimized;

  if (F->hasPrivateLinkage() || F->hasInternalLinkage())
    SubProgFlags |= llvm::DISubprogram::SPFlagLocalToUnit;

  llvm::DISubroutineType *SubProgType =
      DIB.createSubroutineType(DIB.getOrCreateTypeArray(llvm::None));

  f.DebugInformation.Subprogram = DIB.createFunction(
      /* Scope       */ DebugInformation.CompileUnit,
      /* Name        */ F->getName(),
      /* LinkageName */ F->getName(),
      /* File        */ DebugInformation.File,
      /* LineNo      */ 0,
      /* Ty          */ SubProgType,
      /* ScopeLine   */ 0,
      /* Flags       */ llvm::DINode::FlagZero,
      /* SPFlags     */ SubProgFlags);

  F->setSubprogram(f.DebugInformation.Subprogram);

  //
  // create the AllocaInst's for each global referenced at the start of the
  // entry basic block of the function
  //
  {
    llvm::IRBuilderTy IRB(ICFG[entry_bb].B);

    for (unsigned glb = 0; glb < f.GlobalAllocaVec.size(); ++glb) {
      f.GlobalAllocaVec[glb] = IRB.CreateAlloca(
          IRB.getIntNTy(bitsOfTCGType(TCG->_ctx.temps[glb].type)), 0,
          std::string(TCG->_ctx.temps[glb].name) + "_ptr");
    }

    f.PCAlloca = tcg_program_counter_index < 0
                     ? IRB.CreateAlloca(WordType(), 0, "pc_ptr")
                     : f.GlobalAllocaVec[tcg_program_counter_index];

    f.PCRelVal = IRB.CreateLoad(PCRelGlobal, "pcrel");
    f.TPBaseVal = IRB.CreateLoad(TPBaseGlobal, "tpbase");

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
        llvm::Value *Val = IRB.CreateLoad(CPUStateGlobalPointer(glb));
        llvm::Value *Ptr = f.GlobalAllocaVec[glb];
        IRB.CreateStore(Val, Ptr);
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

  DIB.finalizeSubprogram(f.DebugInformation.Subprogram);

  return 0;
}

int TranslateFunctions(void) {
  binary_t &Binary = Decompilation.Binaries[BinaryIndex];
  for (function_t &f : Binary.Analysis.Functions) {
    if (int ret = TranslateFunction(Binary, f))
      return ret;
  }

  llvm::DIBuilder &DIB = *DIBuilder;
  DIB.finalize();

  return 0;
}

static int InlineCalls(void) {
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
  PCRelGlobal      = Module->getGlobalVariable("__jove_pcrel",               true);
  TPBaseGlobal     = Module->getGlobalVariable("__jove_thread_pointer_base", true);
  CPUStateGlobal   = Module->getGlobalVariable("__jove_env",                 true);
  SectsGlobal      = Module->getGlobalVariable("__jove_sections",            true);
  ConstSectsGlobal = Module->getGlobalVariable("__jove_sections_const",      true);
}

static int DoOptimize(void) {
  if (llvm::verifyModule(*Module, &llvm::errs())) {
    WithColor::error() << "DoOptimize: [pre] failed to verify module\n";
    //llvm::errs() << *Module << '\n';
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
    //llvm::errs() << *Module << '\n';
    return 1;
  }

  //
  // if any gv was optimized away, we'd like to make sure our pointer to it
  // becomes null.
  //
  ReloadGlobalVariables();

  return 0;
}

int Optimize1(void) {
  if (opts::NoOpt1)
    return 0;

  if (int ret = DoOptimize())
    return ret;

  if (opts::DumpPostOpt1) {
#if 0
    std::error_code EC;
    llvm::ToolOutputFile Out(opts::Output, EC, llvm::sys::fs::F_None);
    if (EC) {
      WithColor::error() << EC.message() << '\n';
      return 1;
    }

    llvm::WriteBitcodeToFile(*Module, Out.os());

    // Declare success.
    Out.keep();
#else
    std::string s;
    {

      llvm::raw_string_ostream os(s);
      os << *Module << '\n';
    }

    {
      std::ofstream ofs(opts::Output);
      ofs << s;
    }
#endif
    exit(0);
  }

  return 0;
}

static llvm::Constant *
ConstantForAddress(uintptr_t Addr) {
  if (!(Addr >= SectsStartAddr && Addr <= SectsEndAddr))
    return nullptr;

  binary_state_t &st = BinStateVec[BinaryIndex];
  binary_t &Binary = Decompilation.Binaries[BinaryIndex];

  llvm::Constant *res;

  auto it = st.FuncMap.find(Addr);
  if (it != st.FuncMap.end()) {
    function_t &f = Binary.Analysis.Functions[(*it).second];
    res = f.F;

    if (!f.IsABI) {
      WithColor::note() << llvm::formatv("!IsABI for function @ {0:x}\n", Addr);

      FuncIdxAreABIVec.push_back((*it).second);
      ABIChanged = true;
    }
  } else {
    res = SectionPointer(Addr);
    assert(res);
  }

  assert(res->getType()->isPointerTy());
  return llvm::ConstantExpr::getPtrToInt(res, WordType());
}

int FixupPCRelativeAddrs(void) {
  // TODO REMOVE THE FOLLOWING COMMENTED OUT CODE
#if 0
  if (!PCRelGlobal)
    return 0;

#define WARN(val)                                                              \
  do {                                                                         \
    WithColor::warning() << llvm::formatv("{0}:{1}: {2}\n", __FILE__,          \
                                          __LINE__, val);                      \
  } while (false)

  auto handle_load_of_pcrel = [&](llvm::LoadInst *L) -> void {
    for (llvm::User *U : L->users()) {
      assert(llvm::isa<llvm::Instruction>(U));
      llvm::Instruction *Inst = llvm::cast<llvm::Instruction>(U);

      switch (Inst->getOpcode()) {
      case llvm::Instruction::Sub:
      case llvm::Instruction::Add: {
        llvm::Value *LHS = Inst->getOperand(0);
        llvm::Value *RHS = Inst->getOperand(1);

        assert(LHS == L || RHS == L);

        llvm::Value *Other = LHS == L ? RHS : LHS;
        unsigned OtherOperandIdx = LHS == L ? 1 : 0;

        if (llvm::isa<llvm::ConstantInt>(Other)) {
          llvm::ConstantInt *CI = llvm::cast<llvm::ConstantInt>(Other);

          Inst->setOperand(OtherOperandIdx, ConstantForAddress(CI->getValue()));
          continue;
        }

        if (llvm::isa<llvm::SelectInst>(Other)) {
          llvm::SelectInst *SI = llvm::cast<llvm::SelectInst>(Other);
          if (llvm::isa<llvm::ConstantInt>(SI->getTrueValue()) &&
              llvm::isa<llvm::ConstantInt>(SI->getFalseValue())) {
            SI->setTrueValue(ConstantForAddress(
                llvm::cast<llvm::ConstantInt>(SI->getTrueValue())->getValue()));
            SI->setFalseValue(ConstantForAddress(
                llvm::cast<llvm::ConstantInt>(SI->getFalseValue())
                    ->getValue()));
            continue;
          }
        }

        if (llvm::isa<llvm::PHINode>(Other)) {
          llvm::PHINode *PI = llvm::cast<llvm::PHINode>(Other);

          for (unsigned i = 0; i < PI->getNumIncomingValues(); ++i) {
            llvm::Value *incomingValue = PI->getIncomingValue(i);

            if (llvm::isa<llvm::ConstantInt>(incomingValue)) {
              llvm::ConstantInt *CI =
                  llvm::cast<llvm::ConstantInt>(incomingValue);
              PI->setIncomingValue(i, ConstantForAddress(CI->getValue()));
              continue;
            }

            if (llvm::isa<llvm::SelectInst>(incomingValue)) {
              llvm::SelectInst *SI =
                  llvm::cast<llvm::SelectInst>(incomingValue);
              if (llvm::isa<llvm::ConstantInt>(SI->getTrueValue()) &&
                  llvm::isa<llvm::ConstantInt>(SI->getFalseValue())) {
                SI->setTrueValue(ConstantForAddress(
                    llvm::cast<llvm::ConstantInt>(SI->getTrueValue())
                        ->getValue()));
                SI->setFalseValue(ConstantForAddress(
                    llvm::cast<llvm::ConstantInt>(SI->getFalseValue())
                        ->getValue()));
                continue;
              }
            }

            WithColor::error() << llvm::formatv(
                "handle_load_of_pcrel: unknown PHI operand {0} in function {1}\n",
                *PI->getIncomingValue(i),
                Inst->getParent()->getParent()->getName());
          }

          continue;
        }

        //
        //
        //
        assert(llvm::isa<llvm::Instruction>(Other));
        llvm::Instruction *OtherInst = llvm::cast<llvm::Instruction>(Other);
        switch (OtherInst->getOpcode()) {
        case llvm::Instruction::Sub:
        case llvm::Instruction::Add: {
          llvm::Value *_LHS = OtherInst->getOperand(0);
          llvm::Value *_RHS = OtherInst->getOperand(1);

          if (llvm::isa<llvm::ConstantInt>(_LHS) ||
              llvm::isa<llvm::ConstantInt>(_RHS)) {
            assert(!(llvm::isa<llvm::ConstantInt>(_LHS) &&
                     llvm::isa<llvm::ConstantInt>(_RHS)));

            unsigned _OtherOperandIdx =
                llvm::isa<llvm::ConstantInt>(_LHS) ? 0 : 1;

            llvm::ConstantInt *CI = _OtherOperandIdx == 0
                                        ? llvm::cast<llvm::ConstantInt>(_LHS)
                                        : llvm::cast<llvm::ConstantInt>(_RHS);

            OtherInst->setOperand(_OtherOperandIdx,
                                  ConstantForAddress(CI->getValue()));
            continue;
          }

          WithColor::error() << llvm::formatv(
              "handle_load_of_pcrel: unknown _LHS={0} _RHS={1} in function {2}\n",
              *_LHS, *_RHS,
              Inst->getParent()->getParent()->getName());
          break;
        }

        case llvm::Instruction::Select: {
          llvm::SelectInst *SI = llvm::cast<llvm::SelectInst>(OtherInst);

          {
            llvm::Value *T = SI->getTrueValue();

            if (llvm::isa<llvm::ConstantInt>(T)) {
              SI->setTrueValue(ConstantForAddress(llvm::cast<llvm::ConstantInt>(T)->getValue()));
            } else if (llvm::isa<llvm::SelectInst>(T)) {
              llvm::SelectInst *_SI = llvm::cast<llvm::SelectInst>(T);

              {
                llvm::Value *_T = _SI->getTrueValue();
                if (llvm::isa<llvm::ConstantInt>(_T))
                  _SI->setTrueValue(ConstantForAddress(llvm::cast<llvm::ConstantInt>(_T)->getValue()));
                else
                  WARN(*_T);
              }

              {
                llvm::Value *_F = _SI->getFalseValue();
                if (llvm::isa<llvm::ConstantInt>(_F))
                  _SI->setFalseValue(ConstantForAddress(llvm::cast<llvm::ConstantInt>(_F)->getValue()));
                else
                  WARN(*_F);
              }
            } else {
              WARN(*T);
            }
          }

          {
            llvm::Value *F = SI->getFalseValue();

            if (llvm::isa<llvm::ConstantInt>(F)) {
              SI->setFalseValue(ConstantForAddress(llvm::cast<llvm::ConstantInt>(F)->getValue()));
            } else if (llvm::isa<llvm::SelectInst>(F)) {
              llvm::SelectInst *_SI = llvm::cast<llvm::SelectInst>(F);

              {
                llvm::Value *_T = _SI->getTrueValue();
                if (llvm::isa<llvm::ConstantInt>(_T))
                  _SI->setTrueValue(ConstantForAddress(llvm::cast<llvm::ConstantInt>(_T)->getValue()));
                else
                  WARN(*_T);
              }

              {
                llvm::Value *_F = _SI->getFalseValue();
                if (llvm::isa<llvm::ConstantInt>(_F))
                  _SI->setFalseValue(ConstantForAddress(llvm::cast<llvm::ConstantInt>(_F)->getValue()));
                else
                  WARN(*_F);
              }
            } else {
              WARN(*F);
            }
          }

          break;
        }

        default:
          WithColor::error() << llvm::formatv(
              "handle_load_of_pcrel: unknown OtherInst {0} in function {1}\n",
              *OtherInst,
              Inst->getParent()->getParent()->getName());
          break;
        }

        break;
      }

      default:
        WithColor::error() << llvm::formatv(
            "handle_load_of_pcrel: unknown Inst user {0} in function {1}\n",
            *Inst,
            Inst->getParent()->getParent()->getName());
        break;
      }
    }
  };

  for (llvm::User *U : PCRelGlobal->users()) {
    assert(llvm::isa<llvm::LoadInst>(U));

    handle_load_of_pcrel(llvm::cast<llvm::LoadInst>(U));
  }

  PCRelGlobal->setInitializer(llvm::Constant::getNullValue(WordType()));
  PCRelGlobal->setConstant(true);
  PCRelGlobal->setLinkage(llvm::GlobalValue::InternalLinkage);
#endif

  return 0;
}

int FixupTPBaseAddrs(void) {
  if (opts::NoFixupFSBase)
    return 0;

  if (!TPBaseGlobal)
    return 0;

  std::vector<std::pair<llvm::Value *, llvm::Value *>> ToReplace;

  llvm::InlineAsm *IA;
  {
    std::vector<llvm::Type *> AsmArgTypes;
    std::vector<llvm::Value *> AsmArgs;

    llvm::FunctionType *AsmFTy =
        llvm::FunctionType::get(WordType(), AsmArgTypes, false);

    // TODO replace with thread pointer intrinsic
#if defined(__x86_64__)
    llvm::StringRef AsmText("movq \%fs:0x0,$0");
#elif defined(__i386__)
    llvm::StringRef AsmText("mov \%gs:0x0,$0");
#elif defined(__aarch64__)
    llvm::StringRef AsmText("mrs $0, tpidr_el0");
#elif defined(__mips64) || defined(__mips__)
    llvm::StringRef AsmText("thiswontassemble");
#else
#error
#endif

    llvm::StringRef Constraints("=r");

    IA = llvm::InlineAsm::get(AsmFTy, AsmText, Constraints,
                              false /* hasSideEffects */);
  }

  llvm::GlobalVariable *ZeroGV =
      new llvm::GlobalVariable(*Module, WordType(), true,
                               llvm::GlobalValue::InternalLinkage,
                               llvm::Constant::getNullValue(WordType()),
                               "ZeroGV");
  llvm::GlobalVariable *ZeroPGV =
      new llvm::GlobalVariable(*Module, PointerToWordType(), true,
                               llvm::GlobalValue::InternalLinkage, ZeroGV,
                               "ZeroPGV");
  llvm::GlobalVariable *ZeroPPGV =
      new llvm::GlobalVariable(*Module, PPointerType(), true,
                               llvm::GlobalValue::InternalLinkage, ZeroPGV,
                               "ZeroPPGV");

  auto handle_load_of_fsbase = [&](llvm::LoadInst *L) -> void {
    for (llvm::User *U : L->users()) {
      assert(llvm::isa<llvm::Instruction>(U));
      llvm::Instruction *Inst = llvm::cast<llvm::Instruction>(U);

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

        llvm::IRBuilderTy IRB(Inst);
        ToReplace.push_back({Inst, IRB.CreateAdd(IRB.CreateCall(IA), CI)});
        break;
      }

      case llvm::Instruction::IntToPtr:
        // an inttoptr(fs_base) implies something of the sort
        //
        // mov r15,QWORD PTR fs:0x0
        //
        // which is a load of tcbhead_t::tcb
        assert(U->getType() == ZeroGV->getType());
        ToReplace.push_back({Inst, ZeroGV});
        break;

      default:
        WithColor::warning() << llvm::formatv(
            "FixupTPBaseAddrs: handle_load_of_fsbase: unknown user {0}\n", *U);
        break;
      }
    }
  };

  for (llvm::User *U : TPBaseGlobal->users()) {
    if (!llvm::isa<llvm::Instruction>(U)) {
      for (llvm::User *_U : U->users()) {
        assert(llvm::isa<llvm::Instruction>(_U));
        llvm::Instruction *_Inst = llvm::cast<llvm::Instruction>(_U);

        if (_Inst->getType() == ZeroGV->getType()) {
          WithColor::note() << llvm::formatv(
              "FixupTPBaseAddrs: _Inst: {0} in {1} (replacing with ZeroGV)\n",
              *_Inst,
              _Inst->getParent()->getParent()->getName());

          ToReplace.push_back({_Inst, ZeroGV});
          continue;
        }
        if (_Inst->getType() == ZeroPGV->getType()) {
          WithColor::note() << llvm::formatv(
              "FixupTPBaseAddrs: _Inst: {0} in {1} (replacing with ZeroPGV)\n",
              *_Inst,
              _Inst->getParent()->getParent()->getName());

          ToReplace.push_back({_Inst, ZeroPGV});
          continue;
        }
        if (_Inst->getType() == ZeroPPGV->getType()) {
          WithColor::note() << llvm::formatv(
              "FixupTPBaseAddrs: _Inst: {0} in {1} (replacing with ZeroPPGV)\n",
              *_Inst,
              _Inst->getParent()->getParent()->getName());

          ToReplace.push_back({_Inst, ZeroPPGV});
          continue;
        }

        llvm::Function *_Func = _Inst->getParent()->getParent();
        WithColor::error() << llvm::formatv("FixupTPBaseAddrs: unknown user!\n"
                                            "U: {0}\n"
                                            "_Inst: {1}\n"
                                            "_Func: {2}\n",
                                            *U, *_Inst, *_Func);
        return 1;
      }

      continue;
    }

    assert(llvm::isa<llvm::Instruction>(U));
    llvm::Instruction *Inst = llvm::cast<llvm::Instruction>(U);

    if (!llvm::isa<llvm::LoadInst>(U)) {
      WithColor::error() << llvm::formatv(
          "FixupTPBaseAddrs: unknown user {0} in {1}\n", *U,
          Inst->getParent()->getParent()->getName());
      continue;
    }

    handle_load_of_fsbase(llvm::cast<llvm::LoadInst>(U));
  }

  assert(TPBaseGlobal->getType() == ZeroGV->getType());
  ToReplace.push_back({TPBaseGlobal, ZeroGV});

  for (auto &TR : ToReplace) {
    llvm::Value *I;
    llvm::Value *V;
    std::tie(I, V) = TR;

    I->replaceAllUsesWith(V);
  }

  if (opts::DumpAfterFSBaseFixup) {
    std::string s;
    {

      llvm::raw_string_ostream os(s);
      os << *Module << '\n';
    }

    {
      std::ofstream ofs(opts::Output);
      ofs << s;
    }

    exit(0);
  }

  return 0;
}

int InternalizeStaticFunctions(void) {
  return 0;

  binary_t &b = Decompilation.Binaries[BinaryIndex];

  for (function_t &f : b.Analysis.Functions) {
    if (f.IsABI)
      continue;

    if (!f.F->empty())
      f.F->setLinkage(llvm::GlobalValue::InternalLinkage);
  }

  JoveThunkFunc = Module->getFunction("_jove_thunk");
  if (JoveThunkFunc) {
    JoveThunkFunc->setLinkage(llvm::GlobalValue::InternalLinkage);
    JoveThunkFunc->setCallingConv(llvm::CallingConv::C);
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

int DFSanInstrument(void) {
  assert(opts::DFSan);

  if (llvm::verifyModule(*Module, &llvm::errs())) {
    WithColor::error() << "DFSanInstrument: [pre] failed to verify module\n";
    //llvm::errs() << *Module << '\n';
    return 1;
  }

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

  if (llvm::verifyModule(*Module, &llvm::errs())) {
    WithColor::error() << "DFSanInstrument: [post] failed to verify module\n";
    //llvm::errs() << *Module << '\n';
    return 1;
  }

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

    bool isNewTarget =
        bbprop.DynTargets.insert({Callee.BIdx, Callee.FIdx}).second;

    Changed = Changed || isNewTarget;

    // TODO only invalidate those functions which contains ...
    if (isNewTarget)
      InvalidateAllFunctionAnalyses();

    {
      bool &DynTargetsComplete = bbprop.DynTargetsComplete;

      bool DynTargetsComplete_Changed = !DynTargetsComplete;

      DynTargetsComplete = true;

      Changed = Changed || DynTargetsComplete_Changed;

      if (DynTargetsComplete_Changed)
        ; //InvalidateAllFunctionAnalyses();
    }
  }

  if (!Changed && !ABIChanged)
    return 0;

  binary_t &Binary = Decompilation.Binaries[BinaryIndex];
  for (function_index_t fidx : FuncIdxAreABIVec)
    Binary.Analysis.Functions.at(fidx).IsABI = true;

  WriteDecompilation();

  execve(cmdline.argv[0], cmdline.argv, ::environ);
  abort();
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
    std::ofstream ofs(fs::is_directory(opts::jv)
                          ? (opts::jv + "/decompilation.jv")
                          : opts::jv);

    boost::archive::binary_oarchive oa(ofs);
    oa << Decompilation;
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
  if (llvm::verifyModule(*Module, &llvm::errs())) {
    WithColor::error() << "WriteModule: failed to verify module\n";
    //llvm::errs() << *Module << '\n';
    return 1;
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

static int TranslateTCGOp(TCGOp *op, TCGOp *op_next,
                          binary_t &, function_t &, basic_block_t,
                          std::vector<llvm::AllocaInst *> &,
                          std::vector<llvm::BasicBlock *> &,
                          llvm::BasicBlock *,
                          llvm::IRBuilderTy &);

static std::string
dyn_target_desc(const std::pair<binary_index_t, function_index_t> &IdxPair);

int TranslateBasicBlock(binary_t &Binary,
                        function_t &f,
                        basic_block_t bb,
                        llvm::IRBuilderTy &IRB) {
  const auto &ICFG = Binary.Analysis.ICFG;

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

    llvm::Value *Ptr = IRB.CreateLoad(TraceGlobal, true /* Volatile */);
    llvm::Value *PtrInc = IRB.CreateConstGEP1_64(Ptr, 1);

    IRB.CreateStore(IRB.getInt64(comb), Ptr,         true /* Volatile */);
    IRB.CreateStore(PtrInc,             TraceGlobal, true /* Volatile */);
  }

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
    std::tie(len, T) = TCG->translate(Addr + size, Addr + Size);

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

    if (opts::DumpTCG) {
      if (Addr == std::stoi(opts::ForAddr.c_str(), nullptr, 16))
        TCG->dump_operations();
    }

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

  assert(T.Type == ICFG[bb].Term.Type);
  //assert(size == ICFG[bb].Size);

  if (!IRB.GetInsertBlock()->getTerminator()) {
    if (opts::Verbose)
      WithColor::warning() << "TranslateBasicBlock: no terminator in block\n";
    assert(ExitBB);
    IRB.CreateBr(ExitBB);
  }

  IRB.SetInsertPoint(ExitBB);

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

  auto store_stack_pointers = [&](void) -> void {
    auto store = [&](unsigned glb) -> void {
      llvm::LoadInst *LI = IRB.CreateLoad(f.GlobalAllocaVec[glb]);
      LI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);

      llvm::StoreInst *SI = IRB.CreateStore(LI, CPUStateGlobalPointer(glb));
      SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
    };

    store(tcg_stack_pointer_index);
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
    if (!_indirect_jump.IsTailCall) /* otherwise fallthrough */
      break;

  case TERMINATOR::INDIRECT_CALL:
    store_stack_pointers();
    break;

  default:
    break;
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
        IRB.CreateCall(hook_f.PreHook, ArgVec);
      }
    }

    function_t &callee = Binary.Analysis.Functions.at(FIdx);

    std::vector<llvm::Value *> ArgVec;
    {
      std::vector<unsigned> glbv;
      ExplodeFunctionArgs(callee, glbv);

      ArgVec.resize(glbv.size());
      std::transform(glbv.begin(), glbv.end(), ArgVec.begin(),
                     [&](unsigned glb) -> llvm::Value * {
                       return IRB.CreateLoad(f.GlobalAllocaVec[glb]);
                     });
    }

    llvm::CallInst *Ret = IRB.CreateCall(callee.F, ArgVec);

    if (opts::NoInline || callee.IsABI)
      Ret->setIsNoInline();

#if 0
    if (!opts::NoInline &&
        callee.BasicBlocks.size() == 1 &&
        ICFG[callee.BasicBlocks.front()].IsSingleInstruction())
      ; /* allow this call to be inlined */
    else
#endif

    if (!DetermineFunctionType(callee)->getReturnType()->isVoidTy()) {
      std::vector<unsigned> glbv;
      ExplodeFunctionRets(callee, glbv);

      if (glbv.size() == 1) {
        assert(DetermineFunctionType(callee)->getReturnType()->isIntegerTy());
        IRB.CreateStore(Ret, f.GlobalAllocaVec[glbv.front()]);
      } else {
        for (unsigned i = 0; i < glbv.size(); ++i) {
          unsigned glb = glbv[i];

          llvm::Value *Val = IRB.CreateExtractValue(
              Ret, llvm::ArrayRef<unsigned>(i),
              (fmt("_%s_returned_from_%s_")
               % TCG->_ctx.temps[glb].name
               % callee.F->getName().str()).str());

          IRB.CreateStore(Val, f.GlobalAllocaVec[glb]);
        }
      }
    }

    if (opts::DFSan) {
      auto it = dfsanPostHooks.find({BinaryIndex, FIdx});
      if (it != dfsanPostHooks.end()) {
        llvm::outs() << llvm::formatv("calling post-hook ({0}, {1})\n",
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

        ArgVec.insert(ArgVec.begin(),
                      llvm::Constant::getNullValue(type_of_arg_info(hook.Ret)));

        IRB.CreateCall(hook_f.PostHook, ArgVec);
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
        llvm::Value *PC = IRB.CreateLoad(f.PCAlloca);
        llvm::Value *EQV = IRB.CreateICmpEQ(
            PC, llvm::ConstantExpr::getPtrToInt(SectionPointer(ICFG[succ].Addr),
                                                WordType()));
        IRB.CreateCondBr(EQV, ICFG[succ].B,
                         i + 1 < N ? IfSuccBlockVec[i + 1] : ElseBlock);
      }

      IRB.SetInsertPoint(ElseBlock);

      boost::property_map<interprocedural_control_flow_graph_t,
                          boost::vertex_index_t>::type bb_idx_map =
          boost::get(boost::vertex_index, ICFG);

      llvm::Value *RecoverArgs[] = {IRB.getInt32(bb_idx_map[bb]),
                                    IRB.CreateLoad(f.PCAlloca)};

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
                                    IRB.CreateLoad(f.PCAlloca)};

      IRB.CreateCall(JoveRecoverDynTargetFunc, RecoverArgs);

      //
      // if this is an indirect jump, then it's possible this is a goto
      //
      if (T.Type == TERMINATOR::INDIRECT_JUMP) {
        assert(boost::out_degree(bb, ICFG) == 0);

        llvm::Value *RecoverArgs[] = {IRB.getInt32(bb_idx_map[bb]),
                                      IRB.CreateLoad(f.PCAlloca)};

        IRB.CreateCall(JoveRecoverBasicBlockFunc, RecoverArgs);
      }

      if (JoveFail1Func) {
        llvm::Value *FailArgs[] = {IRB.CreateLoad(f.PCAlloca)};
        IRB.CreateCall(JoveFail1Func, FailArgs);
      } else {
        IRB.CreateCall(llvm::Intrinsic::getDeclaration(Module.get(),
                                                       llvm::Intrinsic::trap));
      }

      IRB.CreateUnreachable();
      return 0;
    }

    if (DynTargetsComplete) {
      if (DynTargets.size() > 1)
        WithColor::warning() << llvm::formatv(
            "DynTargetsComplete but more than one dyn target ({0:x})\n",
            ICFG[bb].Term.Addr);

      bool foreign = DynTargetNeedsThunkPred(*DynTargets.begin());

      struct {
        binary_index_t BIdx;
        function_index_t FIdx;
      } ADynTarget;

      std::tie(ADynTarget.BIdx, ADynTarget.FIdx) = *DynTargets.begin();

      function_t &callee = Decompilation.Binaries.at(ADynTarget.BIdx)
                               .Analysis.Functions.at(ADynTarget.FIdx);

      std::vector<llvm::Value *> ArgVec;
      {
        std::vector<unsigned> glbv;
        ExplodeFunctionArgs(callee, glbv);

        ArgVec.resize(glbv.size());
        std::transform(glbv.begin(), glbv.end(), ArgVec.begin(),
                       [&](unsigned glb) -> llvm::Value * {
                         return IRB.CreateLoad(f.GlobalAllocaVec[glb]);
                       });
      }

      llvm::CallInst *Ret;
      if (DynTargetNeedsThunkPred(*DynTargets.begin()) &&
          ArgVec.size() >= CallConvArgArray.size()) {
        llvm::AllocaInst *ArgArrAlloca = IRB.CreateAlloca(
            llvm::ArrayType::get(WordType(), CallConvArgArray.size()));

        for (unsigned i = 0; i < ArgVec.size(); ++i) {
          llvm::Value *Val = ArgVec[i];
          llvm::Value *Ptr = IRB.CreateConstInBoundsGEP2_64(ArgArrAlloca, 0, i);

          IRB.CreateStore(Val, Ptr);
        }

        llvm::Value *CallArgs[] = {
            IRB.CreateLoad(f.PCAlloca),
            IRB.CreateConstInBoundsGEP2_64(ArgArrAlloca, 0, 0),
            CPUStateGlobalPointer(tcg_stack_pointer_index)};

        save_callstack_pointers();
        Ret = IRB.CreateCall(JoveThunkFunc, CallArgs);
        restore_callstack_pointers();
      } else {
        if (foreign)
          save_callstack_pointers();

        Ret = IRB.CreateCall(
            IRB.CreateIntToPtr(
                IRB.CreateLoad(f.PCAlloca),
                llvm::PointerType::get(DetermineFunctionType(callee), 0)),
            ArgVec);

        if (foreign)
          restore_callstack_pointers();

#if defined(__x86_64__)
        if (foreign) // SP += 8 to "pop" the emulated return address
          IRB.CreateStore(
              IRB.CreateAdd(
                  IRB.CreateLoad(f.GlobalAllocaVec[tcg_stack_pointer_index]),
                  llvm::ConstantInt::get(WordType(), sizeof(uintptr_t))),
              CPUStateGlobalPointer(tcg_stack_pointer_index));
#endif
      }

      if (opts::CallStack && foreign)
        IRB.CreateStore(
            IRB.CreateConstGEP1_64(IRB.CreateLoad(CallStackGlobal), -1),
            CallStackGlobal);

      Ret->setCallingConv(llvm::CallingConv::C);

      if (!DetermineFunctionType(callee)->getReturnType()->isVoidTy()) {
        std::vector<unsigned> glbv;
        ExplodeFunctionRets(callee, glbv);

        if (glbv.size() == 1) {
          IRB.CreateStore(Ret, f.GlobalAllocaVec[glbv.front()]);
        } else {
          for (unsigned i = 0; i < glbv.size(); ++i) {
            unsigned glb = glbv[i];

            llvm::Value *Val = IRB.CreateExtractValue(
                Ret, llvm::ArrayRef<unsigned>(i),
                (fmt("_%s_returned") % TCG->_ctx.temps[glb].name).str());

            IRB.CreateStore(Val, f.GlobalAllocaVec[glb]);
          }
        }
      }

      if (opts::DFSan) {
        auto it = dfsanPostHooks.find(*DynTargets.begin());
        if (it != dfsanPostHooks.end()) {
          llvm::outs() << llvm::formatv("calling post-hook ({0}, {1})\n",
                                        (*it).first, (*it).second);

          function_t &hook_f = Decompilation.Binaries.at((*it).first)
                                   .Analysis.Functions.at((*it).second);
          assert(hook_f.hook);
          const hook_t &hook = *hook_f.hook;

          assert(hook.Args.size() <= CallConvArgArray.size()); /* TODO stack arguments */

          std::vector<llvm::Value *> _ArgVec;
          _ArgVec.resize(hook.Args.size());

          {
            unsigned j = 0;
            std::transform(
                hook.Args.begin(),
                hook.Args.end(),
                _ArgVec.begin(),
                [&ArgVec, &IRB, &j](const hook_t::arg_info_t &info) -> llvm::Value * {
                  llvm::Value *ArgVal = ArgVec.at(j++);

                  llvm::Type *DstTy = type_of_arg_info(info);
                  if (info.isPointer)
                    return IRB.CreateIntToPtr(ArgVal, DstTy);

                  assert(DstTy->isIntegerTy());
                  unsigned dstBits =
                      llvm::cast<llvm::IntegerType>(DstTy)->getBitWidth();

                  if (dstBits == WordBits())
                    return ArgVal;

                  assert(dstBits < WordBits());

                  return IRB.CreateTrunc(ArgVal, DstTy);
                });
          }

          assert(Ret->getType() != VoidType());

          llvm::Value *_Ret =
              [Ret, &IRB](const hook_t::arg_info_t &info) -> llvm::Value * {
            llvm::Type *DstTy = type_of_arg_info(info);
            if (info.isPointer)
              return IRB.CreateIntToPtr(Ret, DstTy);

            assert(DstTy->isIntegerTy());
            unsigned dstBits =
                llvm::cast<llvm::IntegerType>(DstTy)->getBitWidth();

            if (dstBits == WordBits())
              return Ret;

            assert(dstBits < WordBits());

            return IRB.CreateTrunc(Ret, DstTy);
          }(hook.Ret);

          _ArgVec.insert(_ArgVec.begin(), _Ret);

          IRB.CreateCall(hook_f.PostHook, _ArgVec);
        }
      }
    } else {
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

          llvm::Value *PC = IRB.CreateLoad(f.PCAlloca);
          llvm::Value *EQV_1 =
              IRB.CreateICmpEQ(PC,
                               GetDynTargetAddress(IRB, DynTargetsVec[i]));
          llvm::Value *EQV_2 =
              IRB.CreateICmpEQ(PC,
                               GetDynTargetCallableAddress(IRB, DynTargetsVec[i]));

          auto next_i = i + 1;
          if (next_i == DynTargetsVec.size())
            B = llvm::BasicBlock::Create(*Context, "else", f.F);
          else
            B = llvm::BasicBlock::Create(
                *Context,
                (fmt("if %s") % dyn_target_desc(DynTargetsVec[next_i])).str(),
                f.F);

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
                                      IRB.CreateLoad(f.PCAlloca)};

        IRB.CreateCall(JoveRecoverDynTargetFunc, RecoverArgs);
        if (JoveFail1Func) {
          llvm::Value *FailArgs[] = {IRB.CreateLoad(f.PCAlloca)};
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

          std::vector<llvm::Value *> ArgVec;
          {
            std::vector<unsigned> glbv;
            ExplodeFunctionArgs(callee, glbv);

            ArgVec.resize(glbv.size());
            std::transform(glbv.begin(), glbv.end(), ArgVec.begin(),
                           [&](unsigned glb) -> llvm::Value * {
                             llvm::Value *Ptr = f.GlobalAllocaVec[glb];
                             assert(Ptr);
                             return IRB.CreateLoad(Ptr);
                           });
          }

          llvm::CallInst *Ret;
          if (DynTargetNeedsThunkPred(DynTargetsVec[i]) &&
              ArgVec.size() >= CallConvArgArray.size()) {
            llvm::AllocaInst *ArgArrAlloca = IRB.CreateAlloca(
                llvm::ArrayType::get(WordType(), CallConvArgArray.size()));

            for (unsigned i = 0; i < ArgVec.size(); ++i) {
              llvm::Value *Val = ArgVec[i];
              llvm::Value *Ptr = IRB.CreateConstInBoundsGEP2_64(ArgArrAlloca, 0, i);

              IRB.CreateStore(Val, Ptr);
            }

            llvm::Value *CallArgs[] = {
                GetDynTargetCallableAddress(IRB, DynTargetsVec[i]),
                IRB.CreateConstInBoundsGEP2_64(ArgArrAlloca, 0, 0),
                CPUStateGlobalPointer(tcg_stack_pointer_index)};

            save_callstack_pointers();
            Ret = IRB.CreateCall(JoveThunkFunc, CallArgs);
            restore_callstack_pointers();
          } else {
            if (foreign)
              save_callstack_pointers();

            Ret = IRB.CreateCall(
                IRB.CreateIntToPtr(
                    GetDynTargetCallableAddress(IRB, DynTargetsVec[i]),
                    llvm::PointerType::get(DetermineFunctionType(callee), 0)),
                ArgVec);

            if (foreign)
              restore_callstack_pointers();

#if defined(__x86_64__)
            if (foreign) // SP += 8 to "pop" the emulated return address
              IRB.CreateStore(
                  IRB.CreateAdd(
                      IRB.CreateLoad(f.GlobalAllocaVec[tcg_stack_pointer_index]),
                      llvm::ConstantInt::get(WordType(), sizeof(uintptr_t))),
                  CPUStateGlobalPointer(tcg_stack_pointer_index));
#endif
          }

          if (opts::CallStack && foreign)
            IRB.CreateStore(
                IRB.CreateConstGEP1_64(IRB.CreateLoad(CallStackGlobal), -1),
                CallStackGlobal);

          Ret->setCallingConv(llvm::CallingConv::C);

          if (!DetermineFunctionType(callee)->getReturnType()->isVoidTy()) {
            std::vector<unsigned> glbv;
            ExplodeFunctionRets(callee, glbv);

            assert(glbv.size() == 1);
            IRB.CreateStore(Ret, f.GlobalAllocaVec[glbv.front()]);
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

              assert(hook.Args.size() <= CallConvArgArray.size()); /* TODO stack arguments */

              std::vector<llvm::Value *> _ArgVec;
              _ArgVec.resize(hook.Args.size());

              {
                unsigned j = 0;
                std::transform(
                    hook.Args.begin(),
                    hook.Args.end(),
                    _ArgVec.begin(),
                    [&ArgVec, &IRB, &j](const hook_t::arg_info_t &info) -> llvm::Value * {
                      llvm::Value *ArgVal = ArgVec.at(j++);

                      llvm::Type *DstTy = type_of_arg_info(info);
                      if (info.isPointer)
                        return IRB.CreateIntToPtr(ArgVal, DstTy);

                      assert(DstTy->isIntegerTy());
                      unsigned dstBits =
                          llvm::cast<llvm::IntegerType>(DstTy)->getBitWidth();

                      if (dstBits == WordBits())
                        return ArgVal;

                      assert(dstBits < WordBits());

                      return IRB.CreateTrunc(ArgVal, DstTy);
                    });
              }

              assert(Ret->getType() != VoidType());

              llvm::Value *_Ret =
                  [Ret, &IRB](const hook_t::arg_info_t &info) -> llvm::Value * {
                llvm::Type *DstTy = type_of_arg_info(info);
                if (info.isPointer)
                  return IRB.CreateIntToPtr(Ret, DstTy);

                assert(DstTy->isIntegerTy());
                unsigned dstBits =
                    llvm::cast<llvm::IntegerType>(DstTy)->getBitWidth();

                if (dstBits == WordBits())
                  return Ret;

                assert(dstBits < WordBits());

                return IRB.CreateTrunc(Ret, DstTy);
              }(hook.Ret);

              _ArgVec.insert(_ArgVec.begin(), _Ret);

              IRB.CreateCall(hook_f.PostHook, _ArgVec);
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

  auto reload_stack_pointers = [&](void) -> void {
    auto reload = [&](unsigned glb) -> void {
      llvm::LoadInst *LI = IRB.CreateLoad(CPUStateGlobalPointer(glb));
      LI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);

      llvm::StoreInst *SI = IRB.CreateStore(LI, f.GlobalAllocaVec[glb]);
      SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
    };

    reload(tcg_stack_pointer_index);
  };

  switch (T.Type) {
  case TERMINATOR::CALL: {
    function_t &callee = Binary.Analysis.Functions[ICFG[bb].Term._call.Target];
    if (callee.IsABI)
      reload_stack_pointers();
    break;
  }

  case TERMINATOR::INDIRECT_JUMP:
    if (!_indirect_jump.IsTailCall) /* otherwise fallthrough */
      break;

  case TERMINATOR::INDIRECT_CALL:
    reload_stack_pointers();
    break;

  default:
    break;
  }

  if (T.Type == TERMINATOR::RETURN && opts::CheckEmulatedStackReturnAddress) {
#if defined(__x86_64__)
    llvm::Value *Args[] = {
        IRB.CreateLoad(f.PCAlloca),
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

    llvm::Value *PC = IRB.CreateLoad(f.PCAlloca);
    llvm::Value *EQV = IRB.CreateICmpEQ(
        PC, IRB.getIntN(sizeof(uintptr_t) * 8, ICFG[succ1].Addr));
    IRB.CreateCondBr(EQV, ICFG[succ1].B, ICFG[succ2].B);
    break;
  }

  case TERMINATOR::CALL:
  case TERMINATOR::INDIRECT_CALL: {
    auto eit_pair = boost::out_edges(bb, ICFG);
    if (eit_pair.first == eit_pair.second) { /* otherwise fallthrough */
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

std::string
dyn_target_desc(const std::pair<binary_index_t, function_index_t> &IdxPair) {
  struct {
    binary_index_t BIdx;
    function_index_t FIdx;
  } DynTarget;

  std::tie(DynTarget.BIdx, DynTarget.FIdx) = IdxPair;

  binary_t &b = Decompilation.Binaries[DynTarget.BIdx];
  function_t &f = b.Analysis.Functions[DynTarget.FIdx];

  uintptr_t Addr =
      b.Analysis.ICFG[boost::vertex(f.Entry, b.Analysis.ICFG)].Addr;

  return (fmt("%s+%#lx") % fs::path(b.Path).filename().string() % Addr).str();
}

bool AnalyzeHelper(helper_function_t &hf) {
  if (hf.EnvArgNo < 0)
    return true; /* doesn't take CPUState* parameter */

  bool res = true;

  llvm::Function::arg_iterator arg_it = hf.F->arg_begin();
  std::advance(arg_it, hf.EnvArgNo);
  llvm::Argument &A = *arg_it;

  for (llvm::User *EnvU : A.users()) {
    if (llvm::isa<llvm::GetElementPtrInst>(EnvU)) {
      llvm::GetElementPtrInst *EnvGEP =
          llvm::cast<llvm::GetElementPtrInst>(EnvU);

      if (!llvm::cast<llvm::GEPOperator>(EnvGEP)->hasAllConstantIndices()) {
        res = false;
        continue;
      }

      llvm::APInt Off(DL.getIndexSizeInBits(EnvGEP->getPointerAddressSpace()), 0);
      llvm::cast<llvm::GEPOperator>(EnvGEP)->accumulateConstantOffset(DL, Off);
      unsigned off = Off.getZExtValue();

      if (!(off < sizeof(tcg_global_by_offset_lookup_table)) ||
          tcg_global_by_offset_lookup_table[off] < 0) {

        if (opts::Verbose)
          WithColor::warning() << llvm::formatv("{0}: off={1} EnvGEP={2}\n",
                                                __func__, off, *EnvGEP);

        res = false;
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
          assert(llvm::isa<llvm::Instruction>(GEPU));
          if (!llvm::Instruction::isCast(
                  llvm::cast<llvm::Instruction>(GEPU)->getOpcode())) {
            WithColor::warning() << llvm::formatv(
                "{0}: unknown global GEP user {1}\n", __func__, *GEPU);
          }

          res = false;
        }
      }
    } else {
      WithColor::warning() << llvm::formatv(
          "{0}: unknown env user {1}\n", __func__, *EnvU);

      res = false;
    }
  }

  return res;
}

static const unsigned bits_of_memop_lookup_table[] = {8, 16, 32, 64};

static unsigned bits_of_memop(MemOp op) {
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

    if (ts->temp_global) {
      assert(idx != tcg_env_index);
#if defined(__x86_64__)
      assert(idx != tcg_fs_base_index);
#elif defined(__i386__)
      assert(idx != tcg_gs_base_index);
#endif
    }

    llvm::AllocaInst *Ptr =
        ts->temp_global ? GlobalAllocaVec.at(idx) : TempAllocaVec.at(idx);
    assert(Ptr);

    llvm::StoreInst *SI = IRB.CreateStore(V, Ptr);
    SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
  };

  auto get = [&](TCGTemp *ts) -> llvm::Value * {
    unsigned idx = temp_idx(ts);

    if (ts->temp_global) {
      switch (idx) {
      case tcg_env_index:
        return llvm::ConstantExpr::getPtrToInt(CPUStateGlobal, WordType());

#if defined(__x86_64__)
      case tcg_fs_base_index:
        return f.TPBaseVal;
#elif defined(__i386__)
      case tcg_gs_base_index:
        return f.TPBaseVal;
#endif
      }
    }

    llvm::AllocaInst *Ptr =
        ts->temp_global ? GlobalAllocaVec.at(idx) : TempAllocaVec.at(idx);
    assert(Ptr);

    llvm::LoadInst *LI = IRB.CreateLoad(Ptr);
    LI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
    return LI;
  };

  static bool pcrel_flag = false;

  auto immediate_constant = [&](unsigned bits, TCGArg A) -> llvm::Value * {
    if (!pcrel_flag)
      return llvm::ConstantInt::get(llvm::Type::getIntNTy(*Context, bits), A);

    pcrel_flag = false; /* reset pcrel flag */
    assert(bits == WordBits());

    //
    // on x86_64, PC-relative accesses are easy to handle. But on other
    // architectures, the program counter register cannot be directly
    // referenced, and so it is not as simple.
    //
    // on aarch64, adrp retrives address of 4KB page at a PC-relative offset.
    //
    // on i386, a call instruction is often followed immediately by a pop
    // instruction which retrives the PC-relative address.
    //
#ifdef __x86_64__ /* we can get away with this on x86_64 */
    llvm::Value *res = ConstantForAddress(A);
    assert(res);
    return res;
#else
    return llvm::ConstantExpr::getAdd(
        llvm::ConstantExpr::getPtrToInt(SectsGlobal, WordType()),
        llvm::ConstantExpr::getSub(
            llvm::ConstantInt::get(WordType(), A),
            llvm::ConstantInt::get(WordType(), SectsStartAddr)));
#endif
  };

  const TCGOpcode opc = op->opc;
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
          *Context, Line, 0 /* Column */, f.DebugInformation.Subprogram));
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
    if (ExitBB)
      IRB.CreateBr(ExitBB);
    break;

  case INDEX_op_call: {
    nb_oargs = TCGOP_CALLO(op);
    nb_iargs = TCGOP_CALLI(op);
    uintptr_t helper_addr = op->args[nb_oargs + nb_iargs];
    void *helper_ptr = reinterpret_cast<void *>(helper_addr);
    //const char *helper_nm = tcg_find_helper(&TCG->_ctx, helper_addr);

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

        if (hf.Analysis.Simple)
	  ArgVec.push_back(IRB.CreateAlloca(CPUStateType));
	else
	  ArgVec.push_back(CPUStateGlobal);

        ++iarg_idx;
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
      // store our globals to the local env
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
    MemOp mop = get_memop(moidx);                                              \
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
#if defined(__aarch64__)
#define __ARCH_LD_OP(off)                                                      \
  {                                                                            \
    if (off == tcg_tpidr_el0_env_offset) {                                     \
      TCGTemp *dst = arg_temp(op->args[0]);                                    \
      assert(dst->type == TCG_TYPE_I64);                                       \
      set(f.TPBaseVal, dst);                                                   \
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

#define __ADD2(opc_name, bits)                                                 \
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
    llvm::Value *t0 = IRB.CreateAdd(t1, t2);                                   \
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

    __ADD2(INDEX_op_add2_i32, 32)
    __ADD2(INDEX_op_add2_i64, 64)

#undef __ADD2

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

#if 0
  case INDEX_op_add2_i32: {
    assert(nb_oargs == 2);

    TCGTemp *t0_low = arg_temp(op->args[0]);
    TCGTemp *t0_high = arg_temp(op->args[1]);

    TCGTemp *t1_low = arg_temp(op->args[nb_oargs + 0]);
    TCGTemp *t1_high = arg_temp(op->args[nb_oargs + 1]);

    TCGTemp *t2_low = arg_temp(op->args[nb_oargs + 2]);
    TCGTemp *t2_high = arg_temp(op->args[nb_oargs + 3]);

    assert(t0_low->type == TCG_TYPE_I32);
    assert(t0_high->type == TCG_TYPE_I32);

    assert(t1_low->type == TCG_TYPE_I32);
    assert(t1_low->type == TCG_TYPE_I32);

    assert(t2_low->type == TCG_TYPE_I32);
    assert(t2_high->type == TCG_TYPE_I32);

    llvm::Value *t1_low_v = get(t1_low);
    llvm::Value *t1_high_v = get(t1_high);

    llvm::Value *t2_low_v = get(t2_low);
    llvm::Value *t2_high_v = get(t2_high);

    llvm::Value *t1 =
        IRB.CreateOr(IRB.CreateZExt(t1_low_v, IRB.getInt64Ty()),
                     IRB.CreateShl(IRB.CreateZExt(t1_high_v, IRB.getInt64Ty()),
                                   llvm::APInt(64, 32)));

    llvm::Value *t2 =
        IRB.CreateOr(IRB.CreateZExt(t1_low_v, IRB.getInt64Ty()),
                     IRB.CreateShl(IRB.CreateZExt(t1_high_v, IRB.getInt64Ty()),
                                   llvm::APInt(64, 32)));

    llvm::Value *t0 = IRB.CreateAdd(t1, t2);

    llvm::Value *t0_low_v = IRB.CreateTrunc(t0, IRB.getInt32Ty());
    llvm::Value *t0_high_v = IRB.CreateTrunc(
        IRB.CreateLShr(t0, llvm::APInt(64, 32)), IRB.getInt32Ty());

    set(t0_low_v, t0_low);
    set(t0_high_v, t0_high);
    break;
  }
#endif

  case INDEX_op_mb: {
    // TODO relaxed version
    // see smp_mb() in tcg/tci.c

    std::vector<llvm::Type *> AsmArgTypes;
    std::vector<llvm::Value *> AsmArgs;

    llvm::FunctionType *AsmFTy =
        llvm::FunctionType::get(VoidType(), AsmArgTypes, false);

#if defined(__x86_64__)
    llvm::StringRef AsmText("mfence");
    llvm::StringRef Constraints("~{memory}");
#elif defined(__i386__)
    llvm::StringRef AsmText("lock; addl $$0,0(%esp)");
    llvm::StringRef Constraints("~{memory},~{cc},~{dirflag},~{fpsr},~{flags}");
#elif defined(__aarch64__)
    llvm::StringRef AsmText("dmb ish");
    llvm::StringRef Constraints("~{memory}");
#elif defined(__mips64) || defined(__mips__)
    llvm::StringRef AsmText("thiswontassemble"); /* TODO XXX */
    llvm::StringRef Constraints("~{memory}");
#else
#error
#endif

    llvm::InlineAsm *IA = llvm::InlineAsm::get(AsmFTy, AsmText, Constraints,
                                               true /* hasSideEffects */);
    IRB.CreateCall(IA);
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
