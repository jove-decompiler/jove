#include "qemu_tcg.h"
#include "../qemu/include/jove.h"

#include "tcg.h"
#include "tool.h"
#include "B.h"
#include "disas.h"

#include <boost/algorithm/string/replace.hpp>
#include <boost/container_hash/extensions.hpp>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include <boost/graph/copy.hpp>
#include <boost/graph/depth_first_search.hpp>
#include <boost/graph/filtered_graph.hpp>
#include <boost/graph/graphviz.hpp>
#include <boost/preprocessor/arithmetic/inc.hpp>
#include <boost/preprocessor/punctuation/comma_if.hpp>
#include <boost/preprocessor/repetition/repeat.hpp>
#include <boost/range/adaptor/reversed.hpp>
#include <boost/icl/split_interval_map.hpp>

#include <llvm/Analysis/Passes.h>
#include <llvm/Analysis/TargetTransformInfo.h>
#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DIBuilder.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/GlobalAlias.h>
#include <llvm/IR/GlobalIFunc.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/MDBuilder.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PatternMatch.h>
#include <llvm/IR/Verifier.h>
#include <llvm/InitializePasses.h>
#include <llvm/InitializePasses.h>
#include <llvm/LinkAllIR.h>
#include <llvm/LinkAllPasses.h>
#include <llvm/Linker/Linker.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/StandardInstrumentations.h>
#include <llvm/Support/DataTypes.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/Host.h>
#include <llvm/Support/ScopedPrinter.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/ToolOutputFile.h>
#include <llvm/Support/WithColor.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/Transforms/Instrumentation/DataFlowSanitizer.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/Debugify.h>
#include <llvm/Transforms/Utils/LowerMemIntrinsics.h>
#include <llvm/Transforms/Utils/ModuleUtils.h>

#include <cctype>
#include <random>
#include <set>
#include <unordered_set>

#include "jove_macros.h"
#include "jove_constants.h"

extern "C" {
void __attribute__((noinline))
     __attribute__((visibility("default")))
TCGLLVMUserBreakPoint(void) {
  puts(__func__);
}
}

#define GET_INSTRINFO_ENUM
#include "LLVMGenInstrInfo.hpp"

#define GET_REGINFO_ENUM
#include "LLVMGenRegisterInfo.hpp"

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

//#include "analyze.hpp"

namespace llvm {

using IRBuilderTy = IRBuilder<ConstantFolder, IRBuilderDefaultInserter>;

}

namespace jove {

struct hook_t;

namespace {

struct basic_block_state_t {
  tcg_global_set_t IN, OUT;

  llvm::BasicBlock *B = nullptr;
};

struct function_state_t {
  basic_block_vec_t bbvec;
  basic_block_vec_t exit_bbvec;

  const hook_t *hook = nullptr;
  llvm::Function *PreHook = nullptr;
  llvm::GlobalVariable *PreHookClunk = nullptr;
  llvm::Function *PostHook = nullptr;
  llvm::GlobalVariable *PostHookClunk = nullptr;

  struct {
    llvm::GlobalIFunc *IFunc = nullptr;
  } _resolver;

  struct {
    llvm::AllocaInst *SavedCPUState = nullptr;
  } _signal_handler;

  bool IsNamed = false;

  bool IsLeaf;
  bool IsSj, IsLj;

  llvm::Function *F = nullptr;
  llvm::Function *adapterF = nullptr;
};

struct binary_state_t {
  std::unique_ptr<llvm::object::Binary> Bin;
  struct {
    elf::DynRegionInfo DynamicTable;
    llvm::StringRef DynamicStringTable;
    const Elf_Shdr *SymbolVersionSection;
    std::vector<elf::VersionMapEntry> VersionMap;
    std::optional<elf::DynRegionInfo> OptionalDynSymRegion;

    elf::DynRegionInfo DynRelRegion;
    elf::DynRegionInfo DynRelaRegion;
    elf::DynRegionInfo DynRelrRegion;
    elf::DynRegionInfo DynPLTRelRegion;
  } _elf;
  llvm::GlobalVariable *FunctionsTable = nullptr;
  llvm::GlobalVariable *FunctionsTableClunk = nullptr;
  llvm::Function *SectsF = nullptr;
  uint64_t SectsStartAddr = 0;
  uint64_t SectsEndAddr = 0;
};

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

struct TranslateContext;

struct LLVMTool : public StatefulJVTool<ToolKind::CopyOnWrite,
                                                 binary_state_t,
                                                 function_state_t,
                                                 basic_block_state_t> {
  struct Cmdline {
    cl::opt<std::string> Binary;
    cl::alias BinaryAlias;
    cl::opt<std::string> BinaryIndex;
    cl::opt<std::string> Output;
    cl::alias OutputAlias;
    cl::opt<std::string> VersionScript;
    cl::opt<std::string> LinkerScript;
    cl::opt<bool> Trace;
    cl::opt<bool> NoFixupFSBase;
    cl::opt<bool> PrintPCRel;
    cl::opt<bool> PrintDefAndUse;
    cl::opt<bool> PrintLiveness;
    cl::opt<bool> DebugSjlj;
    cl::opt<bool> DumpTCG;
    cl::opt<std::string> ForAddr;
    cl::opt<bool> Optimize;
    cl::opt<bool> VerifyBitcode;
    cl::opt<bool> Graphviz;
    cl::opt<bool> DumpPreOpt1;
    cl::opt<bool> DumpPostOpt1;
    cl::opt<bool> DumpPreFSBaseFixup;
    cl::opt<bool> DumpPostFSBaseFixup;
    cl::opt<bool> DFSan;
    cl::opt<std::string> DFSanOutputModuleID;
    bool CallStack, CheckEmulatedReturnAddress;
    cl::opt<bool> ForeignLibs;
    cl::alias ForeignLibsAlias;
    cl::list<std::string> PinnedGlobals;
    cl::opt<bool> ABICalls;
    cl::opt<bool> InlineHelpers;
    cl::opt<bool> ForCBE;
    cl::opt<bool> MT;
    cl::opt<bool> BreakBeforeUnreachables;
    cl::opt<bool> LayOutSections;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Binary("binary", cl::desc("Binary to translate"),
                 cl::value_desc("path"), cl::cat(JoveCategory)),

          BinaryAlias("b", cl::desc("Alias for -binary."), cl::aliasopt(Binary),
                      cl::cat(JoveCategory)),

          BinaryIndex("binary-index", cl::desc("Index of binary to translate"),
                      cl::cat(JoveCategory)),

          Output("output", cl::desc("Output bitcode"), cl::Required,
                 cl::value_desc("filename"), cl::cat(JoveCategory)),

          OutputAlias("o", cl::desc("Alias for -output."), cl::aliasopt(Output),
                      cl::cat(JoveCategory)),

          VersionScript("version-script",
                        cl::desc("Output version script file for use with ld"),
                        cl::value_desc("filename"),
                        cl::cat(JoveCategory)),

          LinkerScript("linker-script",
                       cl::desc("Output linker script file for use with ld"),
                       cl::value_desc("filename"), cl::cat(JoveCategory)),

          Trace(
              "trace",
              cl::desc("Instrument code to output basic block execution trace"),
              cl::cat(JoveCategory)),

          NoFixupFSBase("no-fixup-fsbase",
                        cl::desc("Don't fixup FS-relative references"),
                        cl::cat(JoveCategory)),

          PrintPCRel("pcrel", cl::desc("Print pc-relative references"),
                     cl::cat(JoveCategory)),

          PrintDefAndUse(
              "print-def-and-use",
              cl::desc("Print use_B and def_B for every basic block B"),
              cl::cat(JoveCategory)),

          PrintLiveness("print-liveness",
                        cl::desc("Print liveness for every function"),
                        cl::cat(JoveCategory)),

          DebugSjlj(
              "debug-sjlj",
              cl::desc(
                  "Before setjmp/longjmp, dump information about the call"),
              cl::cat(JoveCategory)),

          DumpTCG("dump-tcg",
                  cl::desc("Dump TCG operations when translating basic blocks"),
                  cl::cat(JoveCategory)),
          ForAddr("for-addr", cl::desc("Do stuff for the given address"),
                  cl::cat(JoveCategory)),

          Optimize("optimize", cl::desc("Optimize bitcode"),
                   cl::cat(JoveCategory)),

          VerifyBitcode("verify-bitcode",
                        cl::desc("run llvm::verifyModule on the bitcode"),
                        cl::cat(JoveCategory)),

          Graphviz("graphviz", cl::desc("Dump graphviz of flow graphs"),
                   cl::cat(JoveCategory)),

          DumpPreOpt1("dump-pre-opt",
                      cl::desc("Dump bitcode before DoOptimize()"),
                      cl::cat(JoveCategory)),

          DumpPostOpt1("dump-post-opt",
                       cl::desc("Dump bitcode after DoOptimize()"),
                       cl::cat(JoveCategory)),

          DumpPreFSBaseFixup("dump-pre-fsbase-fixup",
                             cl::desc("Dump bitcode after fsbase fixup"),
                             cl::cat(JoveCategory)),

          DumpPostFSBaseFixup("dump-post-fsbase-fixup",
                              cl::desc("Dump bitcode after fsbase fixup"),
                              cl::cat(JoveCategory)),

          DFSan("dfsan", cl::desc("Instrument code with DataFlowSanitizer"),
                cl::cat(JoveCategory)),

          DFSanOutputModuleID(
              "dfsan-output-module-id",
              cl::desc("Write to file containing module ID (which is "
                       "found from DFSanModuleID metadata"),
              cl::value_desc("filename"), cl::cat(JoveCategory)),

          ForeignLibs("foreign-libs",
                      cl::desc("only recompile the executable itself; "
                               "treat all other binaries as \"foreign\""),
                      cl::cat(JoveCategory), cl::init(true)),

          ForeignLibsAlias("x", cl::desc("Exe only. Alias for --foreign-libs."),
                           cl::aliasopt(ForeignLibs), cl::cat(JoveCategory)),

          PinnedGlobals(
              "pinned-globals", cl::CommaSeparated,
              cl::value_desc("glb_1,glb_2,...,glb_n"),
              cl::desc(
                  "force specified TCG globals to always go through CPUState"),
              cl::cat(JoveCategory)),

          ABICalls("abi-calls",
                   cl::desc("Call ABIs indirectly through _jove_call"),
                   cl::cat(JoveCategory), cl::init(true)),

          InlineHelpers("inline-helpers",
                        cl::desc("Try to inline all helper function calls"),
                        cl::cat(JoveCategory)),

          ForCBE("for-cbe", cl::desc("Generate LLVM for C backend"),
                 cl::cat(JoveCategory)),

          MT("mt", cl::desc("Thread model (multi)"), cl::cat(JoveCategory),
             cl::init(true)),

          BreakBeforeUnreachables("break-before-unreachables",
                                  cl::desc("Debugging purposes only"),
                                  cl::cat(JoveCategory)),

          LayOutSections(
              "lay-out-sections",
              cl::desc("mode where each section becomes a "
                       "distinct global variable. we check in "
                       "_jove_check_sections_laid_out() at runtime to make "
                       "sure that those aforementioned global variables exist "
                       "side-by-side in memory in the way we expect them to"),
              cl::cat(JoveCategory)) {}

  } opts;

  binary_index_t BinaryIndex = invalid_binary_index;
  bool IsCOFF = false;

  uint64_t ForAddr = 0;

  std::unique_ptr<tiny_code_generator_t> TCG;
  std::unique_ptr<llvm::LLVMContext> Context;
  std::unique_ptr<llvm::Module> Module;

  llvm::DataLayout DL;

  std::string SectsGlobalName, ConstSectsGlobalName;

  llvm::GlobalVariable *SectsGlobal = nullptr;
  llvm::GlobalVariable *ConstSectsGlobal = nullptr;

  std::unordered_map<std::string, std::set<dynamic_target_t>> ExportedFunctions;

  disas_t disas;

  std::unordered_set<uint64_t> ConstantRelocationLocs;
  uint64_t libcEarlyInitAddr = 0;

  llvm::GlobalVariable *CPUStateGlobal = nullptr;
  llvm::Type *CPUStateType = nullptr;

  llvm::GlobalVariable *TraceGlobal = nullptr;
  llvm::GlobalVariable *CallStackGlobal = nullptr;
  llvm::GlobalVariable *CallStackBeginGlobal = nullptr;

  llvm::GlobalVariable *JoveFunctionTablesGlobal = nullptr;
  llvm::GlobalVariable *JoveForeignFunctionTablesGlobal = nullptr;
  llvm::Function *JoveRecoverDynTargetFunc = nullptr;
  llvm::Function *JoveRecoverBasicBlockFunc = nullptr;
  llvm::Function *JoveRecoverReturnedFunc = nullptr;
  llvm::Function *JoveRecoverABIFunc = nullptr;
  llvm::Function *JoveRecoverFunctionFunc = nullptr;

  llvm::Function *JoveInstallForeignFunctionTables = nullptr;

#define __THUNK(n, i, data) llvm::Function *JoveThunk##i##Func;

  BOOST_PP_REPEAT(BOOST_PP_INC(TARGET_NUM_REG_ARGS), __THUNK, void)

#undef __THUNK

  llvm::Function *JoveFail1Func = nullptr;
  llvm::Function *JoveLog1Func = nullptr;
  llvm::Function *JoveLog2Func = nullptr;

  llvm::Function *JoveAllocStackFunc = nullptr;
  llvm::Function *JoveFreeStackFunc = nullptr;
  llvm::Function *JoveNoDCEFunc = nullptr;
  llvm::Function *JoveCallFunc = nullptr;

  //
  // DFSan
  //
  llvm::Function *JoveCheckReturnAddrFunc = nullptr;
  llvm::Function *JoveLogFunctionStart = nullptr;
  llvm::GlobalVariable *JoveLogFunctionStartClunk = nullptr;
  llvm::Function *DFSanFiniFunc = nullptr;
  llvm::GlobalVariable *DFSanFiniClunk = nullptr;

  llvm::GlobalVariable *TLSSectsGlobal = nullptr;

  llvm::GlobalVariable *TLSModGlobal = nullptr;

  llvm::MDNode *AliasScopeMetadata = nullptr;

  std::unique_ptr<llvm::DIBuilder> DIBuilder;

  std::map<uint64_t, llvm::Constant *> TPOFFHack;

  struct {
    llvm::ArrayType *T = nullptr;
    llvm::GlobalVariable *GV = nullptr;
  } TLSDescHack;

  struct {
    struct {
      // in memory, the .tbss section is allocated directly following the .tdata
      // section, with the aligment obeyed
      unsigned Size;
    } Data;

    uint64_t Beg, End;

    bool Present;
  } ThreadLocalStorage;

  struct {
    llvm::DIFile *File;
    llvm::DICompileUnit *CompileUnit;
  } DebugInformation;

  struct {
    llvm::GlobalVariable *HeadGV = nullptr;
    std::vector<std::pair<llvm::GlobalVariable *, unsigned>> GVVec;
  } LaidOut;

  std::unordered_map<std::string, unsigned> GlobalSymbolDefinedSizeMap;

  std::unordered_map<uint64_t, std::set<llvm::StringRef>>
      TLSValueToSymbolMap;
  std::unordered_map<uint64_t, unsigned> TLSValueToSizeMap;

  boost::icl::split_interval_set<uint64_t> AddressSpaceObjects;

  std::unordered_map<uint64_t, std::set<std::string>> AddrToSymbolMap;
  std::unordered_map<uint64_t, unsigned> AddrToSizeMap;
  std::unordered_set<uint64_t> TLSObjects; // XXX

  std::unordered_set<std::string> CopyRelSyms;

  std::unordered_map<llvm::Function *, llvm::Function *> CtorStubMap;

  std::unordered_set<llvm::Function *> FunctionsToInline;

  struct {
    std::unordered_map<std::string, std::unordered_set<std::string>> Table;
  } VersionScript;

  // set {int}0x08053ebc = 0xf7fa83f0
  std::map<std::pair<uint64_t, unsigned>,
           std::pair<binary_index_t, std::pair<uint64_t, unsigned>>>
      CopyRelocMap;

  std::vector<uint64_t> possible_tramps_vec;

  std::unordered_map<std::string, std::set<unsigned>> ordinal_imports;

  llvm::Constant *__jove_fail_UnknownBranchTarget;
  llvm::Constant *__jove_fail_UnknownCallee;

  bool pcrel_flag = false; /* XXX this is ugly, but it works */
  uint64_t lstaddr = 0;

public:
  LLVMTool() : opts(JoveCategory), DL("") {}

  int Run(void) override;

  int TranslateFunction(function_t &f);
  int TranslateBasicBlock(TranslateContext *);
  int TranslateTCGOp(TCGOp *,
                     llvm::BasicBlock *ExitBB,
                     llvm::IRBuilderTy &,
                     TranslateContext &);

  int InitStateForBinaries(void);
  int CreateModule(void);
  int PrepareToTranslateCode(void);
  int ProcessCOPYRelocations(void);
  int CreateFunctions(void);
  int CreateFunctionTables(void);
  int ProcessBinaryTLSSymbols(void);
  int LocateHooks(void);
  int CreateTLSModGlobal(void);
  int CreateSectionGlobalVariables(void);
  int CreatePossibleTramps(void);
  int CreateFunctionTable(void);
  int FixupHelperStubs(void);
  int CreateNoAliasMetadata(void);
  int ProcessManualRelocations(void);
  int CreateCopyRelocationHack(void);
  int TranslateFunctions(void);
  int PrepareToOptimize(void);
  int ConstifyRelocationSectionPointers(void);
  int InternalizeSections(void);
  int PrepareForCBE(void);
  int ExpandMemoryIntrinsicCalls(void);
  int ReplaceAllRemainingUsesOfConstSections(void);
  int DFSanInstrument(void);
  int RenameFunctionLocals(void);
  int WriteVersionScript(void);
  int WriteLinkerScript(void);
  int InlineHelpers(void);
  int BreakBeforeUnreachables(void);
  int ForceCallConv(void);
  int WriteModule(void);

  void DumpModule(const char *);

  void ReloadGlobalVariables(void);
  int DoOptimize(void);

  llvm::Type *VoidType(void);
  llvm::IntegerType *WordType(void);
  llvm::Type *PointerToWordType(void);
  llvm::Type *PPointerType(void);
  llvm::Type *VoidFunctionPointer(void);
  llvm::Constant *BigWord(void);

  llvm::Constant *CPUStateGlobalPointer(llvm::IRBuilderTy &, unsigned glb);

  llvm::Value *BuildCPUStatePointer(llvm::IRBuilderTy &,
                                    llvm::Value *Env,
                                    unsigned glb);

  std::string SectionsTopName(void) {
    if (LaidOut.HeadGV)
      return LaidOut.HeadGV->getName().str();

    return SectsGlobalName;
  }

  llvm::GlobalVariable *SectionsTop(void) {
    if (LaidOut.HeadGV)
      return LaidOut.HeadGV;

    assert(SectsGlobal);
    return SectsGlobal;
  }

  llvm::Constant *SectionPointer(uint64_t Addr) {
    auto &Binary = jv.Binaries.at(BinaryIndex);

    int64_t off =
        static_cast<int64_t>(Addr) -
        static_cast<int64_t>(state.for_binary(Binary).SectsStartAddr);

    return llvm::ConstantExpr::getAdd(
        llvm::ConstantExpr::getPtrToInt(SectionsTop(), WordType()),
        llvm::ConstantInt::getSigned(WordType(), off));
  }

  bool DynTargetNeedsThunkPred(dynamic_target_t DynTarget) {
    binary_index_t BIdx = DynTarget.first;
    const binary_t &binary = jv.Binaries.at(BIdx);

    if (opts.ForeignLibs)
      return !binary.IsExecutable;

    return binary.IsDynamicLinker || binary.IsVDSO;
  }

  template <bool Callable>
  llvm::Value *
  GetDynTargetAddress(llvm::IRBuilderTy &IRB,
                      std::pair<binary_index_t, function_index_t> IdxPair,
                      llvm::BasicBlock *FailBlock = nullptr) {
    struct {
      binary_index_t BIdx;
      function_index_t FIdx;
    } DynTarget;

    std::tie(DynTarget.BIdx, DynTarget.FIdx) = IdxPair;

    binary_t &binary = jv.Binaries.at(DynTarget.BIdx);

    if (DynTarget.BIdx == BinaryIndex) {
      const function_t &f = binary.Analysis.Functions.at(DynTarget.FIdx);
      if (Callable) {
        assert(state.for_function(f).F);
        return llvm::ConstantExpr::getPtrToInt(state.for_function(f).F, WordType());
      } else {
        auto &ICFG = binary.Analysis.ICFG;
        return SectionPointer(ICFG[basic_block_of_index(f.Entry, ICFG)].Addr);
      }
    }

    if (DynTargetNeedsThunkPred(IdxPair)) {
      llvm::Value *FnsTbl = IRB.CreateLoad(
          IRB.getPtrTy(),
          IRB.CreateConstInBoundsGEP2_64(
              JoveForeignFunctionTablesGlobal->getValueType(),
              JoveForeignFunctionTablesGlobal, 0, DynTarget.BIdx));
      return IRB.CreateLoad(WordType(),
                            IRB.CreateConstGEP1_64(WordType()->getPointerTo(),
                                                   FnsTbl, DynTarget.FIdx));
    }

    if (!binary.IsDynamicallyLoaded) {
      llvm::Value *FnsTbl = IRB.CreateLoad(
          IRB.getPtrTy(),
          state.for_binary(jv.Binaries.at(DynTarget.BIdx)).FunctionsTableClunk);
      assert(FnsTbl);

      return IRB.CreateLoad(WordType(),
          IRB.CreateConstGEP2_64(state.for_binary(jv.Binaries.at(DynTarget.BIdx)).FunctionsTable->getValueType(),
                                 FnsTbl, 0, 3 * DynTarget.FIdx + (Callable ? 1 : 0)));
    }

    //
    // check if the functions table pointer is NULL. this can happen if a DSO
    // hasn't been loaded yet
    //
    llvm::Value *FnsTbl = IRB.CreateLoad(
        IRB.getPtrTy(),
        IRB.CreateConstInBoundsGEP1_64(
            IRB.getPtrTy()->getPointerTo(),
            IRB.CreateLoad(IRB.getPtrTy(), JoveFunctionTablesGlobal),
            DynTarget.BIdx));
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
        WordType(),
        IRB.CreateConstGEP1_64(IRB.getPtrTy(), FnsTbl,
                               3 * DynTarget.FIdx + (Callable ? 1 : 0)));
  }

  llvm::AllocaInst *CreateAllocaForGlobal(TranslateContext &,
                                          llvm::IRBuilderTy &,
                                          unsigned glb,
                                          bool InitializeFromEnv = true);

  void ReferenceInNoDCEFunc(llvm::Value *V) {
    assert(JoveNoDCEFunc);
    assert(!JoveNoDCEFunc->empty());
    assert(!JoveNoDCEFunc->empty());
    assert(!JoveNoDCEFunc->getEntryBlock().empty());

    static unsigned Idx = 40; /* XXX */

    assert(JoveNoDCEFunc->arg_size() == 1);
    llvm::Value *OutArg = JoveNoDCEFunc->getArg(0);

    {
      llvm::IRBuilderTy IRB(&JoveNoDCEFunc->getEntryBlock().front());

      llvm::Value *Ptr = IRB.CreateConstInBoundsGEP1_32(
          IRB.getPtrTy()->getPointerTo(), OutArg, Idx++);

      IRB.CreateStore(V, Ptr);
    }
  }

  void fillInFunctionBody(llvm::Function *F,
                          std::function<void(llvm::IRBuilderTy &)> funcBuilder,
                          bool internalize = true);

  llvm::Type *type_of_arg_info(const hook_t::arg_info_t &info) {
    if (info.isPointer)
      return llvm::PointerType::get(llvm::Type::getInt8Ty(*Context), 0);

    return llvm::Type::getIntNTy(*Context, info.Size * 8);
  }

  std::pair<llvm::GlobalVariable *, llvm::Function *>
  declareHook(const hook_t &h, bool IsPreOrPost);

  std::pair<llvm::GlobalVariable *, llvm::Function *>
  declarePreHook(const hook_t &h) {
    return declareHook(h, true);
  }

  std::pair<llvm::GlobalVariable *, llvm::Function *>
  declarePostHook(const hook_t &h) {
    return declareHook(h, false);
  }

  llvm::GlobalIFunc *buildGlobalIFunc(function_t &f,
                                      dynamic_target_t,
                                      llvm::StringRef SymName);

  bool shouldExpandOperationWithSize(llvm::Value *Size);
  void expandMemIntrinsicUses(llvm::Function &);

  tcg_global_set_t DetermineFunctionArgs(function_t &);
  tcg_global_set_t DetermineFunctionRets(function_t &);

  void ExplodeFunctionArgs(function_t &f, std::vector<unsigned> &glbv);
  void ExplodeFunctionRets(function_t &f, std::vector<unsigned> &glbv);

  llvm::FunctionType *FunctionTypeOfArgsAndRets(tcg_global_set_t args,
                                                tcg_global_set_t rets);

  llvm::FunctionType *DetermineFunctionType(function_t &f) {
    tcg_global_set_t args = DetermineFunctionArgs(f);
    tcg_global_set_t rets = DetermineFunctionRets(f);

    if (f.IsABI) {
      args &= CallConvArgs;
      rets &= CallConvRets;
    }

    return FunctionTypeOfArgsAndRets(args, rets);
  }

  llvm::FunctionType *DetermineFunctionType(dynamic_target_t X) {
    return DetermineFunctionType(function_of_target(X, jv));
  }

  llvm::FunctionType *DetermineFunctionType(binary_index_t BIdx,
                                            function_index_t FIdx) {
    dynamic_target_t X(BIdx, FIdx);
    return DetermineFunctionType(X);
  }

  llvm::Type *elf_type_of_expression_for_relocation(const elf::Relocation &);

  llvm::Constant *elf_expression_for_relocation(const elf::Relocation &,
                                                const elf::RelSymbol &);

  llvm::ArrayType *TLSDescType(void);
  llvm::GlobalVariable *TLSDescGV(void);

  bool elf_is_manual_relocation(const elf::Relocation &);
  bool elf_is_constant_relocation(const elf::Relocation &);

  void elf_compute_manual_relocation(llvm::IRBuilderTy &,
                                     const elf::Relocation &,
                                     const elf::RelSymbol &);

  void elf_compute_tpoff_relocation(llvm::IRBuilderTy &,
                                    const elf::RelSymbol &,
                                    unsigned Offset);

  void elf_compute_irelative_relocation(llvm::IRBuilderTy &,
                                        uint64_t resolverAddr);

  llvm::Type *coff_type_of_expression_for_relocation(uint8_t RelocType);
  llvm::Constant *coff_expression_for_relocation(uint8_t RelocType, uint64_t Offset);

  bool coff_is_constant_relocation(uint8_t RelocType);

  llvm::Constant *SymbolAddress(const elf::RelSymbol &);
  llvm::Constant *ImportFunction(llvm::StringRef Name);
  llvm::Constant *ImportFunctionByOrdinal(llvm::StringRef DLL, uint32_t Ordinal);
  llvm::Constant *ImportedFunctionAddress(llvm::StringRef DLL, uint32_t Ordinal,
                                          llvm::StringRef Name, uint64_t Addr);

  uint64_t ExtractWordAtAddress(uint64_t Addr);

  std::pair<binary_index_t, std::pair<uint64_t, unsigned>>
  decipher_copy_relocation(const elf::RelSymbol &S);

  llvm::Value *insertThreadPointerInlineAsm(llvm::IRBuilderTy &);

  std::string dyn_target_desc(dynamic_target_t IdxPair);

  const char *name_of_global_for_offset(unsigned off) {
    if (!(off < sizeof(tcg_global_by_offset_lookup_table)) ||
        tcg_global_by_offset_lookup_table[off] == 0xff) {
      return nullptr;
    }

    unsigned glb =
        static_cast<unsigned>(tcg_global_by_offset_lookup_table[off]);

    TCGTemp *ts = &jv_get_tcg_context()->temps[glb];
    assert(ts->kind == TEMP_GLOBAL);
    return ts->name;
  }

  llvm::Function *bswap_i(unsigned bits) {
    assert(bits > 8);

    llvm::Type *Tys[] = {llvm::Type::getIntNTy(*Context, bits)};

    llvm::Function *bswap =
        llvm::Intrinsic::getDeclaration(Module.get(), llvm::Intrinsic::bswap,
                                        llvm::ArrayRef<llvm::Type *>(Tys, 1));
    return bswap;
  }

  unsigned bitsOfTCGType(TCGType ty) {
    if (unlikely(ty > 2))
      die("bitsOfTCGType: unhandled");

    static_assert(TCG_TYPE_I32 == 0);
    static_assert(TCG_TYPE_I64 == 1);
    static_assert(TCG_TYPE_I128 == 2);

    return 1u << (static_cast<unsigned>(ty) + 5);
  }

  unsigned BitsOfMemOp(MemOp op) {
    static_assert(MO_8 == 0);
    static_assert(MO_16 == 1);
    static_assert(MO_32 == 2);
    static_assert(MO_64 == 3);
    static_assert(MO_128 == 4);
    static_assert(MO_256 == 5);
    static_assert(MO_512 == 6);
    static_assert(MO_1024 == 7);
    static_assert(MO_SIZE == 0x07);

    return 1u << ((static_cast<unsigned>(op) & MO_SIZE) + 3);
  }

  llvm::IntegerType *TypeOfTCGGlobal(unsigned glb) {
    TCGContext *s = jv_get_tcg_context();

    return TypeOfTCGType(s->temps[glb].type);
  }

  llvm::IntegerType *TypeOfTCGType(TCGType ty) {
    return llvm::Type::getIntNTy(*Context, bitsOfTCGType(ty));
  }
};

JOVE_REGISTER_TOOL("llvm", LLVMTool);

typedef boost::format fmt;

struct section_properties_t {
  std::string name;
  llvm::ArrayRef<uint8_t> contents;

  bool w, x;

  struct {
    bool initArray = false;
    bool finiArray = false;
  } _elf;

  bool operator==(const section_properties_t &sect) const {
    return name == sect.name;
  }

  bool operator<(const section_properties_t &sect) const {
    return name < sect.name;
  }
};
typedef std::set<section_properties_t> section_properties_set_t;

struct helper_function_t {
  llvm::Function *F;
  int EnvArgNo;

  struct {
    bool Simple;
    tcg_global_set_t InGlbs, OutGlbs;
  } Analysis;
};

const helper_function_t &LookupHelper(llvm::Module &M, tiny_code_generator_t &TCG, TCGOp *op, bool DFSan, bool ForCBE, Tool &tool);

static std::unordered_map<uintptr_t, helper_function_t> HelperFuncMap;
static std::mutex helper_mtx;

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

struct flow_vertex_properties_t {
  const basic_block_properties_t *bbprop;

  tcg_global_set_t IN, OUT;
};

struct flow_edge_properties_t {
  struct {
    tcg_global_set_t mask = ~tcg_global_set_t();
  } reach;
};

typedef boost::adjacency_list<boost::setS,              /* OutEdgeList */
                              boost::vecS,              /* VertexList */
                              boost::bidirectionalS,    /* Directed */
                              flow_vertex_properties_t, /* VertexProperties */
                              flow_edge_properties_t    /* EdgeProperties */>
    flow_graph_t;

typedef flow_graph_t::vertex_descriptor flow_vertex_t;
typedef flow_graph_t::edge_descriptor flow_edge_t;

typedef std::vector<flow_vertex_t> flow_vertex_vec_t;

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

typedef std::pair<flow_vertex_t, bool> exit_vertex_pair_t;

static basic_block_properties_t dummy_bbprop;

void AnalyzeBasicBlock(tiny_code_generator_t &TCG,
                       llvm::Module &M,
                       binary_t &binary,
                       llvm::object::Binary &B,
                       basic_block_t bb,
                       bool DFSan = false,
                       bool ForCBE = false,
                       Tool *tool = nullptr);

static flow_vertex_t copy_function_cfg(jv_t &jv,
                                       tiny_code_generator_t &TCG,
                                       llvm::Module &M,
                                       flow_graph_t &G,
                                       function_t &f,
                                       std::function<llvm::object::Binary &(binary_t &)> GetBinary,
                                       std::function<std::pair<basic_block_vec_t &, basic_block_vec_t &>(function_t &)> GetBlocks,
                                       bool DFSan,
                                       bool ForCBE,
                                       std::vector<exit_vertex_pair_t> &exitVertices,
                                       std::unordered_map<function_t *, std::pair<flow_vertex_t, std::vector<exit_vertex_pair_t>>> &memoize,
                                       Tool &tool) {
  binary_index_t BIdx = binary_index_of_function(f, jv); /* XXX */
  auto &b = jv.Binaries.at(BIdx);
  auto &ICFG = b.Analysis.ICFG;

  auto BlocksPair = GetBlocks(f);

  basic_block_vec_t &bbvec = BlocksPair.first;
  basic_block_vec_t &exit_bbvec = BlocksPair.second;

  //
  // make sure basic blocks have been analyzed
  //
  for (basic_block_t bb : bbvec)
    AnalyzeBasicBlock(TCG, M, b, GetBinary(b), bb, DFSan, ForCBE, &tool);

  if (!IsLeafFunction(f, b, bbvec)) {
    //
    // have we already copied this function's CFG?
    //
    auto it = memoize.find(&f);
    if (it != memoize.end()) {
      exitVertices = (*it).second.second;
      return (*it).second.first;
    }
  }

  assert(!bbvec.empty());

  //
  // copy the function's CFG into the flow graph, maintaining a mapping from the
  // CFG's basic blocks to the flow graph vertices
  //
  std::map<basic_block_t, flow_vertex_t> Orig2CopyMap;
  {
    vertex_copier vc(ICFG, G);
    edge_copier ec;

    boost::copy_component(
        ICFG, bbvec.front(), G,
        boost::orig_to_copy(
            boost::associative_property_map<
                std::map<basic_block_t, flow_vertex_t>>(Orig2CopyMap))
            .vertex_copy(vc)
            .edge_copy(ec));
  }

  flow_vertex_t res = Orig2CopyMap.at(bbvec.front());

  exitVertices.resize(exit_bbvec.size());
  std::transform(exit_bbvec.begin(),
                 exit_bbvec.end(),
                 exitVertices.begin(),
                 [&](basic_block_t bb) -> exit_vertex_pair_t {
                   return exit_vertex_pair_t(Orig2CopyMap.at(bb), false);
                 });

  memoize.insert({&f, {res, exitVertices}});

  //
  // this recursive function's duty is also to inline calls to functions and
  // indirect jumps
  //
  for (basic_block_t bb : bbvec) {
    switch (ICFG[bb].Term.Type) {
    case TERMINATOR::INDIRECT_CALL: {
      if (!ICFG[bb].hasDynTarget())
        continue;

      auto eit_pair = boost::out_edges(bb, ICFG);

      for (dynamic_target_t DynTarget : ICFG[bb].dyn_targets()) {
        function_t &callee = function_of_target(DynTarget, jv);

        std::vector<exit_vertex_pair_t> calleeExitVertices;
        flow_vertex_t calleeEntryV =
            copy_function_cfg(jv, TCG, M, G, callee, GetBinary, GetBlocks,
                              DFSan, ForCBE, calleeExitVertices, memoize, tool);
        boost::add_edge(Orig2CopyMap.at(bb), calleeEntryV, G);

        if (eit_pair.first != eit_pair.second) {
          flow_vertex_t succV = Orig2CopyMap.at(boost::target(*eit_pair.first, ICFG));

          for (const auto &calleeExitVertPair : calleeExitVertices) {
            flow_vertex_t exitV;
            bool IsABI;

            std::tie(exitV, IsABI) = calleeExitVertPair;

            flow_edge_t E = boost::add_edge(exitV, succV, G).first;

            if (callee.IsABI || IsABI)
              G[E].reach.mask = CallConvRets;
          }
        }
      }

      if (eit_pair.first != eit_pair.second) {
        assert(std::next(eit_pair.first) == eit_pair.second);

        flow_vertex_t succV = Orig2CopyMap.at(boost::target(*eit_pair.first, ICFG));

        boost::remove_edge(Orig2CopyMap.at(bb), succV, G);
      }
      break;
    }

    case TERMINATOR::CALL: {
      function_t &callee = b.Analysis.Functions.at(ICFG[bb].Term._call.Target);

      std::vector<exit_vertex_pair_t> calleeExitVertices;
      flow_vertex_t calleeEntryV =
          copy_function_cfg(jv, TCG, M, G, callee, GetBinary, GetBlocks, DFSan, ForCBE, calleeExitVertices, memoize, tool);

      boost::add_edge(Orig2CopyMap.at(bb), calleeEntryV, G);

      auto eit_pair = boost::out_edges(bb, ICFG);
      if (eit_pair.first == eit_pair.second)
        break;

      assert(eit_pair.first != eit_pair.second &&
             std::next(eit_pair.first) == eit_pair.second);

      flow_vertex_t succV = Orig2CopyMap.at(boost::target(*eit_pair.first, ICFG));

      boost::remove_edge(Orig2CopyMap.at(bb), succV, G);

      for (const auto &calleeExitVertPair : calleeExitVertices) {
        flow_vertex_t exitV;
        bool IsABI;

        std::tie(exitV, IsABI) = calleeExitVertPair;

        flow_edge_t E = boost::add_edge(exitV, succV, G).first;
        if (callee.IsABI || IsABI)
          G[E].reach.mask = CallConvRets;
      }

      break;
    }

    case TERMINATOR::INDIRECT_JUMP: {
      {
        flow_vertex_t flowVert = Orig2CopyMap.at(bb);
        auto it = std::find_if(exitVertices.begin(),
                               exitVertices.end(),
                               [&](exit_vertex_pair_t pair) -> bool {
                                 return pair.first == flowVert;
                               });
        if (it == exitVertices.end())
          continue;
        exitVertices.erase(it);
      }

      assert(ICFG[bb].hasDynTarget());

      for (dynamic_target_t DynTarget : ICFG[bb].dyn_targets()) {
        function_t &callee = function_of_target(DynTarget, jv);

        std::vector<exit_vertex_pair_t> calleeExitVertices;
        flow_vertex_t calleeEntryV =
            copy_function_cfg(jv, TCG, M, G, callee, GetBinary, GetBlocks, DFSan, ForCBE, calleeExitVertices, memoize, tool);
        boost::add_edge(Orig2CopyMap.at(bb), calleeEntryV, G);

        for (const auto &calleeExitVertPair : calleeExitVertices) {
          flow_vertex_t V;
          bool IsABI;
          std::tie(V, IsABI) = calleeExitVertPair;

          exitVertices.emplace_back(V, callee.IsABI);
        }
      }
      break;
    }

    default:
      continue;
    }
  }

  //
  // does f return even if we don't know how?
  //
  if (f.Returns && exitVertices.empty()) {
    flow_vertex_t dummyV = boost::add_vertex(G);

    dummy_bbprop.Analysis.reach.def = CallConvRets;
    G[dummyV].bbprop = &dummy_bbprop;

    exitVertices.emplace_back(dummyV, true);
  }

  return res;
}

static bool AnalyzeHelper(helper_function_t &hf, Tool &tool) {
  if (hf.EnvArgNo < 0)
    return true; /* doesn't take CPUState* parameter */

  bool res = true;

  auto NotSimple = [&](llvm::Value *V = nullptr) -> void {
    res = false;

    if (!V)
      return;

    if (tool.IsVeryVerbose())
      llvm::errs() << llvm::formatv("[AnalyzeHelper] unknown use of env: {0}\n", *V);
  };

  auto EnvMemAccess = [&](unsigned off, bool store) -> void {
    tcg_global_set_t &bits = store ? hf.Analysis.OutGlbs :
                                     hf.Analysis.InGlbs;

    if (off >= sizeof(tcg_global_by_offset_lookup_table) ||
        tcg_global_by_offset_lookup_table[off] == 0xff) {
      NotSimple();
      return;
    }

    bits.set(tcg_global_by_offset_lookup_table[off]);
  };

  llvm::Function::arg_iterator arg_it = hf.F->arg_begin();
  std::advance(arg_it, hf.EnvArgNo);
  llvm::Argument &A = *arg_it;

  for (llvm::User *EnvU : A.users()) {
    if (auto *EnvGEP = llvm::dyn_cast<llvm::GetElementPtrInst>(EnvU)) {
      if (!llvm::cast<llvm::GEPOperator>(EnvGEP)->hasAllConstantIndices()) {
        NotSimple(EnvGEP);
        continue;
      }

      //
      // get byte offset of GEP
      //
      assert(hf.F);
      llvm::DataLayout DL = hf.F->getParent()->getDataLayout();
      llvm::APInt Off(DL.getIndexSizeInBits(EnvGEP->getPointerAddressSpace()), 0);
      llvm::cast<llvm::GEPOperator>(EnvGEP)->accumulateConstantOffset(DL, Off);

      for (llvm::User *GEPU : EnvGEP->users()) {
        if (auto *LI = llvm::dyn_cast<llvm::LoadInst>(GEPU)) {
          assert(LI->getPointerOperand() == EnvGEP);

          EnvMemAccess(Off.getZExtValue(), false);
        } else if (auto *SI = llvm::dyn_cast<llvm::StoreInst>(GEPU)) {
          assert(SI->getPointerOperand() == EnvGEP);

          EnvMemAccess(Off.getZExtValue(), true);
        } else {
          NotSimple(GEPU);
        }
      }
    } else if (auto *LI = llvm::dyn_cast<llvm::LoadInst>(EnvU)) {
      assert(LI->getPointerOperand() == &A);

      EnvMemAccess(0, false);
    } else if (auto *SI = llvm::dyn_cast<llvm::StoreInst>(EnvU)) {
      assert(SI->getPointerOperand() == &A);

      EnvMemAccess(0, true);
    } else {
      NotSimple(EnvU);
    }
  }

  return res;
}

const helper_function_t &LookupHelper(llvm::Module &M, tiny_code_generator_t &TCG, TCGOp *op, bool DFSan, bool ForCBE, Tool &tool) {
  std::lock_guard<std::mutex> lck(helper_mtx);

  int nb_oargs = TCGOP_CALLO(op);
  int nb_iargs = TCGOP_CALLI(op);

  TCGArg helper_addr = op->args[nb_oargs + nb_iargs];

  {
    auto it = HelperFuncMap.find(helper_addr);
    if (it != HelperFuncMap.end())
      return (*it).second;
  }

  const char *helper_nm = jv_tcg_find_helper(op);
  assert(helper_nm);
  const std::string helper_fn_nm = std::string("helper_") + helper_nm;

  if (llvm::Function *F = M.getFunction(helper_fn_nm)) {
    static unsigned j = 0;
    F->setName(helper_fn_nm + "_" + std::to_string(j++));
  }

  assert(!M.getFunction(helper_fn_nm));

  std::string suffix = DFSan ? ".dfsan.bc" : ".bc";

  llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> BufferOr =
      llvm::MemoryBuffer::getFile(tool.locator().helper_bitcode(helper_nm));
  if (!BufferOr) {
    WithColor::error() << "could not open bitcode for helper_" << helper_nm
                       << " at " << tool.locator().helper_bitcode(helper_nm) << " (" << BufferOr.getError().message() << ")\n";
    exit(1);
  }

  llvm::Expected<std::unique_ptr<llvm::Module>> helperModuleOr =
      llvm::parseBitcodeFile(BufferOr.get()->getMemBufferRef(), M.getContext());
  if (!helperModuleOr) {
    llvm::logAllUnhandledErrors(helperModuleOr.takeError(), llvm::errs(),
                                "could not parse helper bitcode: ");
    exit(1);
  }

  std::unique_ptr<llvm::Module> &helperModule = helperModuleOr.get();

  //
  // process global variables
  //
  std::for_each(helperModule->global_begin(),
                helperModule->global_end(),
                [&](llvm::GlobalVariable &GV) {
                  if (!GV.hasInitializer())
                    return;

                  GV.setLinkage(llvm::GlobalValue::InternalLinkage);
                });

  //
  // process functions
  //
  std::for_each(
      helperModule->begin(),
      helperModule->end(), [&](llvm::Function &F) {
        if (F.isIntrinsic())
          return;

        if (F.empty())
          return;

        if (F.getName() == helper_fn_nm) {
          assert(F.getLinkage() == llvm::GlobalValue::ExternalLinkage);
          return;
        }

        if (ForCBE)
          F.deleteBody();
        else
          F.setLinkage(llvm::GlobalValue::InternalLinkage);
      });

  llvm::Linker::linkModules(M, std::move(helperModule));

  helper_function_t &hf = HelperFuncMap[helper_addr];
  hf.F = M.getFunction(helper_fn_nm);
  if (unlikely(!hf.F)) {
    WithColor::error() << llvm::formatv("cannot find helper function {0}\n",
                                        helper_nm);
    exit(1);
  }

  if (!ForCBE)
    hf.F->setVisibility(llvm::GlobalValue::HiddenVisibility);

  assert(nb_iargs >= hf.F->arg_size());

  //
  // analyze helper
  //
  int EnvArgNo = -1;
  {
    TCGArg *const inputs_beg = &op->args[nb_oargs + 0];
    TCGArg *const inputs_end = &op->args[nb_oargs + nb_iargs];
    TCGArg *it = std::find_if(inputs_beg, inputs_end, [](TCGArg arg) -> bool {
      char buf[256];
      return strcmp(jv_tcg_get_arg_str(buf, sizeof(buf), arg), "env") == 0;
    });

    if (it != inputs_end)
      EnvArgNo = std::distance(inputs_beg, it);
  }

  hf.EnvArgNo = EnvArgNo;
  hf.Analysis.Simple = AnalyzeHelper(hf, tool);

  //
  // is this a system call?
  //
  const char *const syscall_helper_nm =
#if defined(TARGET_X86_64)
      "syscall"
#elif defined(TARGET_I386)
      "raise_interrupt"
#elif defined(TARGET_AARCH64)
      "exception_with_syndrome"
#elif defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
      "raise_exception_err"
#else
#error
#endif
      ;

  if (strcmp(helper_nm, syscall_helper_nm) == 0)
    hf.Analysis.Simple = true; /* force */

  {
    std::string InGlbsStr;

    {
      std::vector<unsigned> iglbv;
      explode_tcg_global_set(iglbv, hf.Analysis.InGlbs);

      //InGlbsStr.push_back('{');
      for (auto it = iglbv.begin(); it != iglbv.end(); ++it) {
        unsigned glb = *it;

        InGlbsStr.append(jv_get_global_name(glb));
        if (std::next(it) != iglbv.end())
          InGlbsStr.append(", ");
      }
      //InGlbsStr.push_back('}');
    }

    std::string OutGlbsStr;

    {
      std::vector<unsigned> oglbv;
      explode_tcg_global_set(oglbv, hf.Analysis.OutGlbs);

      //OutGlbsStr.push_back('{');
      for (auto it = oglbv.begin(); it != oglbv.end(); ++it) {
        unsigned glb = *it;

        OutGlbsStr.append(jv_get_global_name(glb));
        if (std::next(it) != oglbv.end())
          OutGlbsStr.append(", ");
      }
      //OutGlbsStr.push_back('}');
    }

    const char *IsSimpleStr = hf.Analysis.Simple ? "-" : "+";

    if (InGlbsStr.empty() && OutGlbsStr.empty()) {
      WithColor::note() << llvm::formatv("helper_{0} ({1})\n", helper_nm, IsSimpleStr);
    } else {
      WithColor::note() << llvm::formatv("helper_{0} : {1} -> {2} ({3})\n",
                                         helper_nm,
                                         InGlbsStr,
                                         OutGlbsStr,
                                         IsSimpleStr);
    }
  }

  return hf;
}

void AnalyzeBasicBlock(tiny_code_generator_t &TCG,
                       llvm::Module &M,
                       binary_t &binary,
                       llvm::object::Binary &B,
                       basic_block_t bb,
                       bool DFSan,
                       bool ForCBE,
                       Tool *tool) {
  auto &ICFG = binary.Analysis.ICFG;
  auto &bbprop = ICFG[bb];

  if (!bbprop.Analysis.Stale)
    return;

  bbprop.Analysis.Stale = false;

  const uint64_t Addr = bbprop.Addr;
  const unsigned Size = bbprop.Size;

  TCG.set_binary(B);

  bbprop.Analysis.live.use.reset();
  bbprop.Analysis.live.def.reset();
  bbprop.Analysis.reach.def.reset();

  unsigned size = 0;
  jove::terminator_info_t T;
  do {
    unsigned len;
    std::tie(len, T) = TCG.translate(Addr + size, Addr + Size);

    TCGContext *s = jv_get_tcg_context();

    TCGOp *op;
    QTAILQ_FOREACH(op, &s->ops, link) {
      TCGOpcode opc = op->opc;

      tcg_global_set_t iglbs, oglbs;

      int nb_oargs, nb_iargs;
      if (opc == INDEX_op_call) {
        nb_oargs = TCGOP_CALLO(op);
        nb_iargs = TCGOP_CALLI(op);

        const helper_function_t &hf = LookupHelper(M, TCG, op, DFSan, ForCBE, *tool);

        iglbs = hf.Analysis.InGlbs;
        oglbs = hf.Analysis.OutGlbs;
      } else {
        nb_iargs = jv_tcgopc_nb_iargs_in_def(opc);
        nb_oargs = jv_tcgopc_nb_oargs_in_def(opc);
      }

      for (int i = 0; i < nb_iargs; ++i) {
        TCGTemp *ts = arg_temp(op->args[nb_oargs + i]);
        if (ts->kind != TEMP_GLOBAL)
          continue;

        unsigned glb_idx = temp_idx(ts);
        if (glb_idx == tcg_env_index)
          continue;

        iglbs.set(glb_idx);
      }

      for (int i = 0; i < nb_oargs; ++i) {
        TCGTemp *ts = arg_temp(op->args[i]);
        if (ts->kind != TEMP_GLOBAL)
          continue;

        unsigned glb_idx = temp_idx(ts);
        if (glb_idx == tcg_env_index)
          continue;

        oglbs.set(glb_idx);
      }

      bbprop.Analysis.live.use |= (iglbs & ~bbprop.Analysis.live.def);
      bbprop.Analysis.live.def |= (oglbs & ~bbprop.Analysis.live.use);

      bbprop.Analysis.reach.def |= oglbs;
    }

    size += len;
  } while (size < Size);

#if 0
  if (false /* opts::PrintDefAndUse */) {
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
      explode_tcg_global_set(glbv, bbprop.Analysis.live.def);
      for (unsigned glb : glbv)
        llvm::outs() << ' ' << s->temps[glb].name;
    }
    llvm::outs() << '\n';

    llvm::outs() << "live.use:";
    {
      std::vector<unsigned> glbv;
      explode_tcg_global_set(glbv, bbprop.Analysis.live.use);
      for (unsigned glb : glbv)
        llvm::outs() << ' ' << s->temps[glb].name;
    }
    llvm::outs() << '\n';

    llvm::outs() << "reach.def:";
    {
      std::vector<unsigned> glbv;
      explode_tcg_global_set(glbv, bbprop.Analysis.reach.def);
      for (unsigned glb : glbv)
        llvm::outs() << ' ' << s->temps[glb].name;
    }
    llvm::outs() << '\n';
  }
#endif
}

void AnalyzeFunction(jv_t &jv,
                     tiny_code_generator_t &TCG,
                     llvm::Module &M,
                     function_t &f,
                     std::function<llvm::object::Binary &(binary_t &)> GetBinary,
                     std::function<std::pair<basic_block_vec_t &, basic_block_vec_t &>(function_t &)> GetBlocks,
                     bool DFSan,
                     bool ForCBE,
                     Tool *tool) {
  if (!f.Analysis.Stale)
    return;
  f.Analysis.Stale = false;

  {
    flow_graph_t G;

    std::unordered_map<function_t *,
                       std::pair<flow_vertex_t, std::vector<exit_vertex_pair_t>>>
        memoize;

    std::vector<exit_vertex_pair_t> exitVertices;
    flow_vertex_t entryV = copy_function_cfg(jv, TCG, M, G, f, GetBinary, GetBlocks, DFSan, ForCBE, exitVertices, memoize, *tool);

    //
    // build vector of vertices in DFS order
    //
    flow_vertex_vec_t Vertices;
    Vertices.reserve(boost::num_vertices(G));

    {
      struct flowvert_dfs_visitor : public boost::default_dfs_visitor {
        flow_vertex_vec_t &out;

        flowvert_dfs_visitor(flow_vertex_vec_t &out) : out(out) {}

        void discover_vertex(flow_vertex_t v, const flow_graph_t &) const {
          out.push_back(v);
        }
      };

      flowvert_dfs_visitor vis(Vertices);

      std::map<flow_vertex_t, boost::default_color_type> colorMap;
      boost::depth_first_search(
          G, vis,
          boost::associative_property_map<
              std::map<flow_vertex_t, boost::default_color_type>>(colorMap));
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
            eit_pair.first,
            eit_pair.second,
            tcg_global_set_t(),
            [&](tcg_global_set_t res, flow_edge_t E) -> tcg_global_set_t {
              return res | G[boost::target(E, G)].IN;
            });

        tcg_global_set_t use = G[V].bbprop->Analysis.live.use;
        tcg_global_set_t def = G[V].bbprop->Analysis.live.def;

        G[V].IN = use | (G[V].OUT & ~def);

        change = change || _IN != G[V].IN;
      }
    } while (likely(change));

    f.Analysis.args = G[entryV].IN & ~(NotArgs | PinnedEnvGlbs);

    //
    // all non-ABI functions will be passed the stack pointer.
    //
    if (!f.IsABI)
      f.Analysis.args.set(tcg_stack_pointer_index);

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
            eit_pair.first,
            eit_pair.second,
            tcg_global_set_t(),
            [&](tcg_global_set_t res, flow_edge_t E) -> tcg_global_set_t {
              return res | (G[boost::source(E, G)].OUT & G[E].reach.mask);
            });
        G[V].OUT = G[V].bbprop->Analysis.reach.def | G[V].IN;

        change = change || _OUT != G[V].OUT;
      }
    } while (likely(change));

    if (f.Returns)
      assert(!exitVertices.empty());

    if (exitVertices.empty()) {
      f.Analysis.rets.reset();
    } else {
      f.Analysis.rets =
          std::accumulate(
              exitVertices.begin(),
              exitVertices.end(),
              ~tcg_global_set_t(),
              [&](tcg_global_set_t res, exit_vertex_pair_t Pair) -> tcg_global_set_t {
                flow_vertex_t V;
                bool IsABI;

                std::tie(V, IsABI) = Pair;

                res &= G[V].OUT;

                if (IsABI)
                  res &= CallConvRets;

                return res;
              }) &
          ~(NotRets | PinnedEnvGlbs);

      //
      // all non-ABI functions with an exit block will return the stack pointer.
      //
      if (!f.IsABI)
        f.Analysis.rets.set(tcg_stack_pointer_index);
    }
  }

#if 0
  if (f.IsABI) {
    //
    // for ABI's, if we need a return register whose index > 0, then we will
    // infer that all the preceeding return registers are live as well
    //
    std::vector<unsigned> glbv;
    explode_tcg_global_set(glbv, f.Analysis.rets);
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
        f.Analysis.rets.set(CallConvRetArray[i]);
    }
#elif 0
    // XXX TODO
    assert(!CallConvRetArray.empty());
    if (f.Analysis.rets[CallConvRetArray.front()]) {
      f.Analysis.rets.reset();
      f.Analysis.rets.set(CallConvRetArray.front());
    } else {
      f.Analysis.rets.reset();
    }
  }
#endif

  //
  // for ABI's, if we need a register parameter whose index > 0, then we will
  // infer that all the preceeding paramter registers are live as well
  //
  if (f.IsABI) {
    std::vector<unsigned> glbv;
    explode_tcg_global_set(glbv, f.Analysis.args);

    auto rit = std::accumulate(
        glbv.begin(), glbv.end(), CallConvArgArray.crend(),
        [](CallConvArgArrayTy::const_reverse_iterator res, unsigned glb) {
          return std::min(res, std::find(CallConvArgArray.crbegin(),
                                         CallConvArgArray.crend(), glb));
        });

    if (rit != CallConvArgArray.crend()) {
      unsigned idx = std::distance(CallConvArgArray.cbegin(), rit.base()) - 1;
      for (unsigned i = 0; i <= idx; ++i)
        f.Analysis.args.set(CallConvArgArray[i]);
    }
  }
}

//
// Types
//

struct section_t {
  std::string Name;
  llvm::ArrayRef<uint8_t> Contents;
  uint64_t Addr;
  unsigned Size;

  struct {
    bool initArray = false;
    bool finiArray = false;
  } _elf;

  struct {
    boost::icl::split_interval_set<uint64_t> Intervals;
    std::map<unsigned, llvm::Constant *> Constants;
    std::map<unsigned, llvm::Type *> Types;
  } Stuff;

  llvm::StructType *T = nullptr;
  llvm::Constant *C = nullptr;
};

#if 0
static int tcg_global_index_of_name(const char *nm) {
  for (int i = 0; i < jv_get_tcg_context()->nb_globals; i++) {
    if (strcmp(jv_get_tcg_context()->temps[i].name, nm) == 0)
      return i;
  }

  return -1;
}
#endif

static bool is_integral_size(unsigned n) {
  return n == 1 || n == 2 || n == 4 || n == 8;
}

static constexpr unsigned WordBytes(void) {
  return sizeof(target_ulong);
}

static constexpr unsigned WordBits(void) {
  return WordBytes() * 8;
}

llvm::Type *LLVMTool::VoidType(void) {
  return llvm::Type::getVoidTy(*Context);
}

llvm::IntegerType *LLVMTool::WordType(void) {
  return llvm::Type::getIntNTy(*Context, WordBits());
}

llvm::Type *LLVMTool::PointerToWordType(void) {
  return llvm::PointerType::get(WordType(), 0);
}

llvm::Type *LLVMTool::PPointerType(void) {
  return llvm::PointerType::get(PointerToWordType(), 0);
}

llvm::Type *LLVMTool::VoidFunctionPointer(void) {
  llvm::FunctionType *FTy = llvm::FunctionType::get(VoidType(), false);
  return llvm::PointerType::get(FTy, 0);
}

llvm::Constant *LLVMTool::BigWord(void) {
  //
  // we want a constant integer sufficiently large to cause a SIGSEGV if
  // dereferenced or otherwise used as a pointer value.
  //
  return llvm::Constant::getAllOnesValue(WordType());
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
  llvm::WithColor::error() << Buf << '\n';
  abort();
}

#include "relocs_common.hpp"

static bool is_builtin_sym(const std::string &);

int LLVMTool::Run(void) {
  //jove::cmdline.argv = argv;
  opts.CallStack = opts.DFSan;
  opts.CheckEmulatedReturnAddress = opts.DFSan;

  //
  // binary index (cmdline)
  //
  if (!opts.Binary.empty()) {
    for (binary_index_t BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx) {
      binary_t &b = jv.Binaries.at(BIdx);

      if (fs::path(b.path_str()).filename().string() == opts.Binary) {
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
  if (!opts.BinaryIndex.empty()) {
    int idx = atoi(opts.BinaryIndex.c_str());

    if (idx < 0 || idx >= jv.Binaries.size()) {
      WithColor::error() << "invalid binary index supplied\n";
      return 1;
    }

    BinaryIndex = idx;
  }
  if (!is_binary_index_valid(BinaryIndex)) {
    WithColor::error() << "must specify binary\n";
    return 1;
  }

  SectsGlobalName =
      (fmt("__jove_sections_%u") % static_cast<unsigned>(BinaryIndex)).str();
  ConstSectsGlobalName =
      (fmt("__jove_sections_const_%u") % static_cast<unsigned>(BinaryIndex)).str();

  if (opts.DumpTCG) {
    if (opts.ForAddr.empty()) {
      WithColor::error() << "if --dump-tcg is passed, --for-addr must also be passed\n";
      return 1;
    } else {
      ForAddr = std::stoi(opts.ForAddr.c_str(), nullptr, 16);
    }
  }

  if (opts.ForeignLibs) {
    if (!jv.Binaries.at(BinaryIndex).IsExecutable) {
      WithColor::error() << "--foreign-libs specified but given binary is not "
                            "the executable\n";
      return 1;
    }
  }

  int rc;
  if ((rc = InitStateForBinaries()) ||
      (rc = CreateModule()) ||
      (rc = PrepareToTranslateCode()))
    return rc;

#if 0
  //
  // pinned globals (cmdline)
  //
  for (const std::string &PinnedGlobalName : opts.PinnedGlobals) {
    int idx = tcg_global_index_of_name(PinnedGlobalName.c_str());
    if (idx < 0) {
      WithColor::warning() << llvm::formatv(
          "unknown global {0} (--pinned-globals); ignoring\n", idx);
      continue;
    }

    CmdlinePinnedEnvGlbs.set(idx);
  }
#endif

  identify_ABIs(jv);

  if (unlikely(opts.DFSan)) {
    //
    // examine function symbols in every binary (ExportedFunctions)
    //
    for_each_binary_if(
        jv,
        [&](binary_t &b) -> bool {
          return state.for_binary(b).Bin.get() != nullptr &&
                 state.for_binary(b)._elf.OptionalDynSymRegion;
        },
        [&](binary_t &b) {
          binary_index_t BIdx = index_of_binary(b, jv);

          auto DynSyms = state.for_binary(b)._elf.OptionalDynSymRegion->template getAsArrayRef<Elf_Sym>();

          for_each_if(
              DynSyms.begin(),
              DynSyms.end(),
              [&](const Elf_Sym &Sym) -> bool {
                return !(Sym.isUndefined() ||
                         Sym.st_shndx == llvm::ELF::SHN_UNDEF) &&
                       Sym.getType() == llvm::ELF::STT_FUNC;
              },
              [&](const Elf_Sym &Sym) {
                llvm::Expected<llvm::StringRef> ExpectedSymName =
                    Sym.getName(state.for_binary(b)._elf.DynamicStringTable);

                if (!ExpectedSymName)
                  return;

                function_index_t FIdx = index_of_function_at_address(b, Sym.st_value);
                assert(is_function_index_valid(FIdx));

                llvm::StringRef SymName = *ExpectedSymName;

                ExportedFunctions.at(SymName.str()).insert({BIdx, FIdx});
              });
        });
  }

  //
  // examine data symbols in every binary (GlobalSymbolDefinedSizeMap)
  //
  for_each_binary_if(
      jv,
      [&](binary_t &b) -> bool {
        return state.for_binary(b).Bin.get() != nullptr &&
               state.for_binary(b)._elf.OptionalDynSymRegion;
      },
      [&](binary_t &b) {
        auto DynSyms = state.for_binary(b)._elf.OptionalDynSymRegion->template getAsArrayRef<Elf_Sym>();

        for_each_if(
            DynSyms.begin(),
            DynSyms.end(),
            [&](const Elf_Sym &Sym) -> bool {
              return !(Sym.isUndefined() ||
                       Sym.st_shndx == llvm::ELF::SHN_UNDEF) &&
                     (Sym.getType() == llvm::ELF::STT_OBJECT ||
                      Sym.getType() == llvm::ELF::STT_TLS) &&
                     Sym.st_size > 0;
            },
            [&](const Elf_Sym &Sym) {
              llvm::Expected<llvm::StringRef> ExpectedSymName =
                  Sym.getName(state.for_binary(b)._elf.DynamicStringTable);

              if (!ExpectedSymName)
                return;

              llvm::StringRef SymName = *ExpectedSymName;

              auto it = GlobalSymbolDefinedSizeMap.find(SymName.str());
              if (it == GlobalSymbolDefinedSizeMap.end()) {
                GlobalSymbolDefinedSizeMap.emplace(SymName, Sym.st_size);
              } else {
                if ((*it).second != Sym.st_size) {
                  if (IsVerbose())
                    WithColor::warning()
                        << llvm::formatv("global symbol {0} is defined with "
                                         "multiple distinct sizes: {1}, {2}\n",
                                         SymName, Sym.st_size, (*it).second);
                  (*it).second = std::max<unsigned>((*it).second, Sym.st_size);
                }
              }
            });
      });

  binary_t &Binary = jv.Binaries.at(BinaryIndex);
  assert(state.for_binary(Binary).Bin.get());

  llvm::ArrayRef<Elf_Sym> BinaryDynSyms = {};

  B::_elf(*state.for_binary(Binary).Bin, [&](ELFO &O) {

  const ELFF &Elf = O.getELFFile();

  if (state.for_binary(Binary)._elf.OptionalDynSymRegion)
    BinaryDynSyms = state.for_binary(Binary)._elf.OptionalDynSymRegion->template getAsArrayRef<Elf_Sym>();

  //
  // process binary function symbols
  //
  for_each_if(
      BinaryDynSyms.begin(),
      BinaryDynSyms.end(),
      [&](const Elf_Sym &Sym) -> bool {
        return !(Sym.isUndefined() ||
                 Sym.st_shndx == llvm::ELF::SHN_UNDEF) &&
               Sym.getType() == llvm::ELF::STT_FUNC;
      },
      [&](const Elf_Sym &Sym) {
        llvm::Expected<llvm::StringRef> ExpectedSymName =
            Sym.getName(state.for_binary(Binary)._elf.DynamicStringTable);

        if (!ExpectedSymName)
          return;

        llvm::StringRef SymName = *ExpectedSymName;
        llvm::StringRef SymVers;
        bool VisibilityIsDefault;

        if (state.for_binary(Binary)._elf.SymbolVersionSection) {
          unsigned SymNo = (reinterpret_cast<uintptr_t>(&Sym) -
                            reinterpret_cast<uintptr_t>(
                                state.for_binary(Binary)._elf.OptionalDynSymRegion->Addr)) /
                           sizeof(Elf_Sym);

          const Elf_Versym *Versym =
              unwrapOrError(Elf.template getEntry<Elf_Versym>(
                  *state.for_binary(Binary)._elf.SymbolVersionSection, SymNo));

          SymVers = getSymbolVersionByIndex(state.for_binary(Binary)._elf.VersionMap,
                                            state.for_binary(Binary)._elf.DynamicStringTable,
                                            Versym->vs_index,
                                            VisibilityIsDefault);
        }

        //
        // avoid redefining symbols in libclang_rt.builtins-<arch>.a
        //
        if (is_builtin_sym(SymName.str()))
          return;

        const uint64_t Addr = Sym.st_value;

        //
        // XXX hack for glibc
        //
        if (unlikely(SymName == "__libc_early_init" &&
                     SymVers == "GLIBC_PRIVATE")) {
          Module->appendModuleInlineAsm(
              ".symver "
              "_jove__libc_early_init,__libc_early_init@@GLIBC_PRIVATE");
          VersionScript.Table["GLIBC_PRIVATE"];

          libcEarlyInitAddr = Addr; /* we are libc */
          return;
        }

        // jove-add should have explored this
        assert(exists_function_at_address(Binary, Addr));

        const unsigned SectsOff = Addr - state.for_binary(Binary).SectsStartAddr;

        if (SymVers.empty()) {
          Module->appendModuleInlineAsm(
              (fmt(".globl %s\n"
                   ".type  %s,@function\n"
                   ".set   %s, %s + %u")
               % SymName.str()
               % SymName.str()
               % SymName.str() % SectionsTopName() % SectsOff).str());
        } else {
           // make sure version node is defined
          VersionScript.Table[SymVers.str()];

          std::string dummy_name = (fmt("_dummy_%lx_%d") % Addr % rand()).str();

          Module->appendModuleInlineAsm(
              (fmt(".globl %s\n"
//                 ".hidden %s\n"
                   ".type  %s,@function\n"
                   ".set   %s, %s + %u")
               % dummy_name
//             % dummy_name
               % dummy_name
               % dummy_name % SectionsTopName() % SectsOff).str());

          Module->appendModuleInlineAsm(
              (llvm::Twine(".symver ") + dummy_name + "," + SymName +
               (VisibilityIsDefault ? "@@" : "@") + SymVers)
                  .str());
        }
      });

  //
  // process binary TLS symbols
  //
  for_each_if(
      BinaryDynSyms.begin(),
      BinaryDynSyms.end(),
      [&](const Elf_Sym &Sym) -> bool {
        return !(Sym.isUndefined() ||
                 Sym.st_shndx == llvm::ELF::SHN_UNDEF) &&
               Sym.getType() == llvm::ELF::STT_TLS;
      },
      [&](const Elf_Sym &Sym) {
        llvm::Expected<llvm::StringRef> ExpectedSymName =
            Sym.getName(state.for_binary(Binary)._elf.DynamicStringTable);

        if (!ExpectedSymName)
          return;

        llvm::StringRef SymName = *ExpectedSymName;

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
      });

  });

  if ((rc = ProcessCOPYRelocations()) ||
      (rc = CreateFunctions()) ||
      (rc = CreateFunctionTables()) ||
      (rc = ProcessBinaryTLSSymbols()) ||
      (rc = (opts.DFSan ? LocateHooks() : 0)) ||
      (rc = CreateTLSModGlobal()) ||
      (rc = CreateSectionGlobalVariables()) ||
      (rc = CreatePossibleTramps()))
    return rc;

  B::_elf(*state.for_binary(Binary).Bin, [&](ELFO &O) {

  const ELFF &Elf = O.getELFFile();

  //
  // process binary IFunc symbols
  //
  for_each_if(
      BinaryDynSyms.begin(),
      BinaryDynSyms.end(),
      [&](const Elf_Sym &Sym) -> bool {
        return !(Sym.isUndefined() ||
                 Sym.st_shndx == llvm::ELF::SHN_UNDEF) &&
               Sym.getType() == llvm::ELF::STT_GNU_IFUNC;
      },
      [&](const Elf_Sym &Sym) {
        llvm::Expected<llvm::StringRef> ExpectedSymName =
            Sym.getName(state.for_binary(Binary)._elf.DynamicStringTable);

        if (!ExpectedSymName)
          return;

        llvm::StringRef SymName = *ExpectedSymName;
        llvm::StringRef SymVers;
        bool VisibilityIsDefault;

        if (state.for_binary(Binary)._elf.SymbolVersionSection) {
          unsigned SymNo = (reinterpret_cast<uintptr_t>(&Sym) -
                            reinterpret_cast<uintptr_t>(
                                state.for_binary(Binary)._elf.OptionalDynSymRegion->Addr)) /
                           sizeof(Elf_Sym);

          const Elf_Versym *Versym =
              unwrapOrError(Elf.template getEntry<Elf_Versym>(
                  *state.for_binary(Binary)._elf.SymbolVersionSection, SymNo));

          SymVers = getSymbolVersionByIndex(state.for_binary(Binary)._elf.VersionMap,
                                            state.for_binary(Binary)._elf.DynamicStringTable,
                                            Versym->vs_index,
                                            VisibilityIsDefault);
        }

        function_t &f = function_at_address(Binary, Sym.st_value);

        if (state.for_function(f)._resolver.IFunc) { /* aliased? */
          llvm::FunctionType *FTy = llvm::FunctionType::get(VoidType(), false);

          llvm::GlobalIFunc *IFunc = llvm::GlobalIFunc::create(
              FTy, 0, llvm::GlobalValue::ExternalLinkage, SymName,
              state.for_function(f)._resolver.IFunc->getResolver(), Module.get());
        } else {
          state.for_function(f)._resolver.IFunc = buildGlobalIFunc(f, invalid_dynamic_target, SymName);
        }

        if (!SymVers.empty())
          VersionScript.Table[SymVers.str()].insert(SymName.str());
      });

  //
  // process binary data symbols (this is intentionally done after
  // AddrToSymbolMap is populated by CreateSectionGlobalVariables)
  //
  {
    std::set<std::pair<uint64_t, unsigned>> gdefs;

    for_each_if(
        BinaryDynSyms.begin(),
        BinaryDynSyms.end(),
        [&](const Elf_Sym &Sym) -> bool {
          return !(Sym.isUndefined() ||
                   Sym.st_shndx == llvm::ELF::SHN_UNDEF) &&
                 Sym.getType() == llvm::ELF::STT_OBJECT &&
                 Sym.st_size > 0;
        },
        [&](const Elf_Sym &Sym) {
          llvm::Expected<llvm::StringRef> ExpectedSymName =
              Sym.getName(state.for_binary(Binary)._elf.DynamicStringTable);

          if (!ExpectedSymName)
            return;

          llvm::StringRef SymName = *ExpectedSymName;
          llvm::StringRef SymVers;
          bool VisibilityIsDefault;

          if (state.for_binary(Binary)._elf.SymbolVersionSection) {
            unsigned SymNo = (reinterpret_cast<uintptr_t>(&Sym) -
                              reinterpret_cast<uintptr_t>(
                                  state.for_binary(Binary)._elf.OptionalDynSymRegion->Addr)) /
                             sizeof(Elf_Sym);

            const Elf_Versym *Versym =
                unwrapOrError(Elf.template getEntry<Elf_Versym>(
                    *state.for_binary(Binary)._elf.SymbolVersionSection, SymNo));

            SymVers = getSymbolVersionByIndex(state.for_binary(Binary)._elf.VersionMap,
                                              state.for_binary(Binary)._elf.DynamicStringTable,
                                              Versym->vs_index,
                                              VisibilityIsDefault);
          }

          const uint64_t Addr = Sym.st_value;
          const unsigned Size = Sym.st_size;

          const unsigned SectsOff = Addr - state.for_binary(Binary).SectsStartAddr;

          auto it = AddrToSymbolMap.find(Addr);
          if (it == AddrToSymbolMap.end()) {
            if (SymVers.empty()) {
              Module->appendModuleInlineAsm(
                  (fmt(".globl %s\n"
                       ".type  %s,@object\n"
                       ".size  %s, %u\n"
                       ".set   %s, %s + %u")
                   % SymName.str()
                   % SymName.str()
                   % SymName.str() % Size
                   % SymName.str() % SectionsTopName() % SectsOff).str());
            } else {
              if (gdefs.find({Addr, Size}) == gdefs.end()) {
                Module->appendModuleInlineAsm(
                    (fmt(//".hidden g%lx_%u\n"
                         ".globl  g%lx_%u\n"
                         ".type   g%lx_%u,@object\n"
                         ".size   g%lx_%u, %u\n"
                         ".set    g%lx_%u, %s + %u")
//                   % Addr % Size
                     % Addr % Size
                     % Addr % Size
                     % Addr % Size % Size
                     % Addr % Size % SectionsTopName() % SectsOff).str());

                gdefs.insert({Addr, Size});
              }

              Module->appendModuleInlineAsm(
                  (fmt(".symver g%lx_%u, %s%s%s")
                   % Addr % Size
                   % SymName.str()
                   % (VisibilityIsDefault ? "@@" : "@")
                   % SymVers.str()).str());

              // make sure version node is defined
              VersionScript.Table[SymVers.str()];
            }
          } else {
            if (Module->getNamedValue(SymName)) {
              if (!SymVers.empty())
                VersionScript.Table[SymVers.str()].insert(SymName.str());

              return;
            }

            llvm::GlobalVariable *GV =
                Module->getGlobalVariable(*(*it).second.begin(), true);
            assert(GV);

            llvm::GlobalAlias::create(SymName, GV);
            if (!SymVers.empty())
              VersionScript.Table[SymVers.str()].insert(SymName.str());
          }
        });
  }
  });

  return CreateFunctionTable()
      || FixupHelperStubs()
      || CreateNoAliasMetadata()
      || ProcessManualRelocations()
      || CreateCopyRelocationHack()
      || TranslateFunctions()
      || InternalizeSections()
      || InlineHelpers()
      || (opts.ForCBE ? PrepareForCBE() : 0)
      || (opts.DumpPreOpt1 ? (RenameFunctionLocals(), DumpModule("pre.opt"), 1) : 0)
      || ((opts.Optimize || opts.ForCBE) ? DoOptimize() : 0)
      || (opts.DumpPostOpt1 ? (RenameFunctionLocals(), DumpModule("post.opt"), 1) : 0)
      || ForceCallConv()
      || ExpandMemoryIntrinsicCalls()
      || ReplaceAllRemainingUsesOfConstSections()
      || (opts.DFSan ? DFSanInstrument() : 0)
      || RenameFunctionLocals()
      || (!opts.VersionScript.empty() ? WriteVersionScript() : 0)
      || (!opts.LinkerScript.empty() ? WriteLinkerScript() : 0)
      || (opts.BreakBeforeUnreachables ? BreakBeforeUnreachables() : 0)
      || WriteModule();
}

void LLVMTool::DumpModule(const char *suffix) {
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
        fs::path(opts.Output).replace_extension(std::string(suffix) + ".ll");

    WithColor::note() << llvm::formatv("dumping module to {0} ({1})\n",
                                       dumpOutputPath.c_str(), suffix);

    std::ofstream ofs(dumpOutputPath.c_str());
    ofs << s;
  }

  {
    fs::path dumpOutputPath =
        fs::path(opts.Output).replace_extension(std::string(suffix) + ".bc");

    WithColor::note() << llvm::formatv("dumping module to {0} ({1})\n",
                                       dumpOutputPath.c_str(), suffix);

    std::error_code EC;
    llvm::ToolOutputFile Out(dumpOutputPath.c_str(), EC, llvm::sys::fs::OF_None);
    if (EC) {
      WithColor::error() << EC.message() << '\n';
      return;
    }

    llvm::WriteBitcodeToFile(*Module, Out.os());

    // Declare success.
    Out.keep();
  }
}

int LLVMTool::InitStateForBinaries(void) {
  for_each_binary(std::execution::par_unseq, jv, [&](binary_t &binary) {
    binary_state_t &x = state.for_binary(binary);

    auto &ICFG = binary.Analysis.ICFG;

    for_each_function_in_binary(std::execution::par_unseq, binary,
                                [&](function_t &f) {
      if (!is_basic_block_index_valid(f.Entry))
        return;

      function_state_t &y = state.for_function(f);

      basic_blocks_of_function(f, binary, y.bbvec);
      exit_basic_blocks_of_function(f, binary, y.bbvec, y.exit_bbvec);

      y.IsLeaf = IsLeafFunction(f, binary, y.bbvec);

      y.IsSj = IsFunctionSetjmp(f, binary, y.bbvec);
      y.IsLj = IsFunctionLongjmp(f, binary, y.bbvec);

      if (y.IsSj)
        llvm::outs() << llvm::formatv("setjmp found at {0:x} in {1}\n",
                                      ICFG[basic_block_of_index(f.Entry, ICFG)].Addr,
                                      fs::path(binary.path_str()).filename().string());

      if (y.IsLj)
        llvm::outs() << llvm::formatv("longjmp found at {0:x} in {1}\n",
                                      ICFG[basic_block_of_index(f.Entry, ICFG)].Addr,
                                      fs::path(binary.path_str()).filename().string());
    });

    ignore_exception([&]() {
      x.Bin = B::Create(binary.data());

      auto &SectsStartAddr = x.SectsStartAddr;
      auto &SectsEndAddr   = x.SectsEndAddr;
      std::tie(SectsStartAddr, SectsEndAddr) = B::bounds_of_binary(*x.Bin);

      WithColor::note() << llvm::formatv("SectsStartAddr for {0} is {1:x}\n",
                                         binary.Name.c_str(),
                                         SectsStartAddr);

      B::_elf(*x.Bin, [&](ELFO &O) {

      elf::loadDynamicTable(O, x._elf.DynamicTable);

      if (x._elf.DynamicTable.Addr) {
        x._elf.OptionalDynSymRegion =
            loadDynamicSymbols(O,
                               x._elf.DynamicTable,
                               x._elf.DynamicStringTable,
                               x._elf.SymbolVersionSection,
                               x._elf.VersionMap);

        if (index_of_binary(binary, jv) == BinaryIndex)
          loadDynamicRelocations(O,
                                 x._elf.DynamicTable,
                                 x._elf.DynRelRegion,
                                 x._elf.DynRelaRegion,
                                 x._elf.DynRelrRegion,
                                 x._elf.DynPLTRelRegion);
      }
      });
    });
  });

  auto &Binary = jv.Binaries.at(BinaryIndex);
  IsCOFF = B::_X(*state.for_binary(Binary).Bin,
      [&](ELFO &O) -> bool { return false; },
      [&](COFFO &O) -> bool { return true; });

  return 0;
}

//
// this function takes a pointer to an llvm::Function which is merely a
// declaration, and turns it into a defined function with a single BB, and
// supplies an IRBuilder for the purpose of building the rest of the
// function's body
//
void LLVMTool::fillInFunctionBody(llvm::Function *F,
                                  std::function<void(llvm::IRBuilderTy &)> funcBuilder,
                                  bool internalize) {
  assert(F && "function is NULL!");
  assert(F->empty() && "function is already defined!");

  //
  // if we don't create debug information, llvm::verifyModule() will fail
  //
  llvm::DIBuilder &DIB = *DIBuilder;
  llvm::DISubprogram::DISPFlags SubProgFlags =
      llvm::DISubprogram::SPFlagDefinition |
      llvm::DISubprogram::SPFlagOptimized;

  if (internalize)
    SubProgFlags |= llvm::DISubprogram::SPFlagLocalToUnit;

  llvm::DISubroutineType *SubProgType =
      DIB.createSubroutineType(DIB.getOrCreateTypeArray(std::nullopt));

  llvm::DISubprogram *DbgSubprogram = DIB.createFunction(
      /* Scope       */ DebugInformation.CompileUnit,
      /* Name        */ F->getName(),
      /* LinkageName */ F->getName(),
      /* File        */ DebugInformation.File,
      /* LineNo      */ 0,
      /* Ty          */ SubProgType,
      /* ScopeLine   */ 0,
      /* Flags       */ llvm::DINode::FlagZero,
      /* SPFlags     */ SubProgFlags);

  F->setSubprogram(DbgSubprogram);

  llvm::BasicBlock *BB = llvm::BasicBlock::Create(*Context, "", F);
  {
    llvm::IRBuilderTy IRB(BB);

    IRB.SetCurrentDebugLocation(llvm::DILocation::get(
        *Context, 0 /* Line */, 0 /* Column */, DbgSubprogram));

    funcBuilder(IRB);

    assert(IRB.GetInsertBlock()->getTerminator() &&
           "did not define function!");
  }

  if (internalize) {
    F->setLinkage(llvm::GlobalValue::InternalLinkage);
  } else {
    if (F->getLinkage() != llvm::GlobalValue::ExternalLinkage) {
      WithColor::warning() << llvm::formatv("function {0} is not external!\n",
                                            F->getName());
      F->setLinkage(llvm::GlobalValue::ExternalLinkage);
    }
    F->setVisibility(llvm::GlobalValue::HiddenVisibility);
  }

  DIB.finalizeSubprogram(DbgSubprogram);
}

int LLVMTool::CreateModule(void) {
  Context.reset(new llvm::LLVMContext);

  const char *bootstrap_mod_name = opts.DFSan ? "jove.dfsan" : "jove";

  llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> BufferOr =
      llvm::MemoryBuffer::getFile(locator().starter_bitcode(opts.MT));
  if (!BufferOr) {
    WithColor::error() << "failed to open bitcode "
                       << locator().starter_bitcode(opts.MT) << ": "
                       << BufferOr.getError().message() << '\n';
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

  Module->setSemanticInterposition(false);

#if 0
  //
  // nonlazybind (FIXME?)
  //
  for (llvm::Function &F : *Module) {
    if (F.empty())
      F.addFnAttr(llvm::Attribute::NonLazyBind);
  }
#endif

  //
  // removing dso_local (FIXME?)
  //
  for (llvm::GlobalObject &GO : Module->global_objects()) {
    if (GO.isDeclaration() && GO.isDSOLocal())
      GO.setDSOLocal(false);
  }

  DL = Module->getDataLayout();

  {
    CPUStateGlobal = Module->getGlobalVariable("__jove_env", true);
    assert(CPUStateGlobal);

    CPUStateType = CPUStateGlobal->getValueType();
  }

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

BOOST_PP_REPEAT(BOOST_PP_INC(TARGET_NUM_REG_ARGS), __THUNK, void)

#undef __THUNK

  JoveFail1Func = Module->getFunction("_jove_fail1");
  assert(JoveFail1Func && !JoveFail1Func->empty());
  JoveFail1Func->setLinkage(llvm::GlobalValue::InternalLinkage);

  JoveLog1Func = Module->getFunction("_jove_log1");
  assert(JoveLog1Func && !JoveLog1Func->empty());
  JoveLog1Func->setLinkage(llvm::GlobalValue::InternalLinkage);

  JoveLog2Func = Module->getFunction("_jove_log2");
  assert(JoveLog2Func && !JoveLog2Func->empty());
  JoveLog2Func->setLinkage(llvm::GlobalValue::InternalLinkage);

  JoveFunctionTablesGlobal =
      Module->getGlobalVariable("__jove_function_tables", true);
  assert(JoveFunctionTablesGlobal);

  JoveForeignFunctionTablesGlobal =
      Module->getGlobalVariable("__jove_foreign_function_tables", true);
  assert(JoveForeignFunctionTablesGlobal);
  JoveForeignFunctionTablesGlobal->setInitializer(llvm::Constant::getNullValue(
      JoveForeignFunctionTablesGlobal->getValueType()));
  if (opts.ForCBE)
    JoveForeignFunctionTablesGlobal->setVisibility(
        llvm::GlobalValue::HiddenVisibility);
  else
    JoveForeignFunctionTablesGlobal->setLinkage(
        llvm::GlobalValue::InternalLinkage);

  JoveRecoverDynTargetFunc = Module->getFunction("_jove_recover_dyn_target");
  assert(JoveRecoverDynTargetFunc && !JoveRecoverDynTargetFunc->empty());

  JoveRecoverBasicBlockFunc = Module->getFunction("_jove_recover_basic_block");
  assert(JoveRecoverBasicBlockFunc && !JoveRecoverBasicBlockFunc->empty());

  JoveRecoverReturnedFunc = Module->getFunction("_jove_recover_returned");
  assert(JoveRecoverReturnedFunc && !JoveRecoverReturnedFunc->empty());

  JoveRecoverABIFunc = Module->getFunction("_jove_recover_ABI");
  assert(JoveRecoverABIFunc && !JoveRecoverABIFunc->empty());

  JoveRecoverFunctionFunc = Module->getFunction("_jove_recover_function");
  assert(JoveRecoverFunctionFunc && !JoveRecoverFunctionFunc->empty());

  JoveAllocStackFunc = Module->getFunction("_jove_alloc_stack");
  assert(JoveAllocStackFunc);

  JoveFreeStackFunc = Module->getFunction("_jove_free_stack");
  assert(JoveFreeStackFunc);

  JoveCallFunc = Module->getFunction("_jove_call");
  assert(JoveCallFunc);

  JoveCheckReturnAddrFunc = Module->getFunction("_jove_check_return_address");
  if (opts.CheckEmulatedReturnAddress) {
    assert(JoveCheckReturnAddrFunc);
    JoveCheckReturnAddrFunc->setLinkage(llvm::GlobalValue::InternalLinkage);
  }

  if (opts.DFSan) {
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

  JoveNoDCEFunc = Module->getFunction("__nodce");
  assert(JoveNoDCEFunc);

  if (opts.ForCBE) {
    std::for_each(Module->begin(),
                  Module->end(), [&](llvm::Function &F) {
      if (F.isIntrinsic())
        return;

      if (F.empty())
        return;

      if (&F == JoveNoDCEFunc)
        return;

      F.setVisibility(llvm::GlobalValue::DefaultVisibility);
      F.deleteBody();
    });
  }

  return 0;
}

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

std::pair<llvm::GlobalVariable *, llvm::Function *>
LLVMTool::declareHook(const hook_t &h, bool IsPreOrPost) {
  const char *namePrefix =
    IsPreOrPost ? "__dfs_pre_hook_" : "__dfs_post_hook_";
  const char *clunkNamePrefix =
    IsPreOrPost ? "__dfs_pre_hook_clunk_" : "__dfs_post_hook_clunk_";

  std::string name(namePrefix);
  name.append(h.Sym);

  std::string clunkName(clunkNamePrefix);
  clunkName.append(h.Sym);

  // first check if it already exists
  if (auto *F = Module->getFunction(name)) {
    assert(F->empty());

    llvm::GlobalVariable *GV = Module->getGlobalVariable(clunkName, true);
    assert(GV);

    return std::make_pair(GV, F);
  }

  std::vector<llvm::Type *> argTypes;
  argTypes.resize(h.Args.size());
  std::transform(h.Args.begin(),
                 h.Args.end(), argTypes.begin(),
                 [&](const hook_t::arg_info_t &info) -> llvm::Type * {
                   return type_of_arg_info(info);
                 });

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

//
// the duty of this function is to map symbol names to (BIdx, FIdx) pairs
//
int LLVMTool::LocateHooks(void) {
  assert(opts.DFSan);

  const bool ForeignLibs = opts.ForeignLibs;

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
      function_t &f = function_of_target(IdxPair, jv);

      if (state.for_function(f).hook) {
        WithColor::warning() << llvm::formatv("hook already installed for {0}\n", h.Sym);
        continue;
      }

      llvm::outs() << llvm::formatv("[hook] {0} @ {1}\n",
                                    h.Sym,
                                    dyn_target_desc(IdxPair));

      state.for_function(f).hook = &h;

      if (h.Pre)
        std::tie(state.for_function(f).PreHookClunk,
                 state.for_function(f).PreHook) = declarePreHook(h);

      if (h.Post)
        std::tie(state.for_function(f).PostHookClunk,
                 state.for_function(f).PostHook) = declarePostHook(h);
    }
  }

  return 0;
}

int LLVMTool::ProcessBinaryTLSSymbols(void) {
  binary_t &b = jv.Binaries.at(BinaryIndex);

  B::_elf(*state.for_binary(b).Bin, [&](ELFO &O) {

  const ELFF &Elf = O.getELFFile();

  //
  // To set up the memory for the thread-local storage the dynamic linker gets
  // the information about each module's thread-local storage requirements from
  // the PT TLS program header entry
  //
  const Elf_Phdr *tlsPhdr = nullptr;
  for (const Elf_Phdr &Phdr : unwrapOrError(Elf.program_headers())) {
    if (Phdr.p_type == llvm::ELF::PT_TLS) {
      tlsPhdr = &Phdr;
      break;
    }
  }

  if (!tlsPhdr) {
    ThreadLocalStorage.Present = false;

    WithColor::note() << llvm::formatv("{0}: No thread local storage\n",
                                       __func__);
    return;
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

    for (const Elf_Shdr &Sect : unwrapOrError(Elf.sections())) {
      if (Sect.sh_type == llvm::ELF::SHT_SYMTAB) {
        assert(!SymTab);
        SymTab = &Sect;
      } else if (Sect.sh_type == llvm::ELF::SHT_SYMTAB_SHNDX) {
        ShndxTable = unwrapOrError(Elf.getSHNDXTable(Sect));
      }
    }

    if (SymTab) {
      llvm::StringRef StrTable = unwrapOrError(Elf.getStringTableForSymtab(*SymTab));

      for (const Elf_Sym &Sym : unwrapOrError(Elf.symbols(SymTab))) {
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

        uint64_t Addr = ThreadLocalStorage.Beg + Sym.st_value;
        AddrToSymbolMap[Addr].insert(SymName.str());
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
  auto OptionalDynSymRegion = state.for_binary(b)._elf.OptionalDynSymRegion;
  if (!OptionalDynSymRegion)
    return; /* no dynamic symbols */

  const elf::DynRegionInfo &DynSymRegion = *OptionalDynSymRegion;

  auto dynamic_symbols = [&](void) -> Elf_Sym_Range {
    return DynSymRegion.getAsArrayRef<Elf_Sym>();
  };

  for (const Elf_Sym &Sym : dynamic_symbols()) {
    if (Sym.getType() != llvm::ELF::STT_TLS)
      continue;

    if (Sym.isUndefined())
      continue;

    llvm::StringRef SymName = unwrapOrError(Sym.getName(state.for_binary(b)._elf.DynamicStringTable));

    WithColor::note() << llvm::formatv("{0}: {1} [{2}]\n", __func__, SymName,
                                       __LINE__);

    if (Sym.st_value >= tlsPhdr->p_memsz) {
      WithColor::error() << llvm::formatv("bad TLS offset {0} for symbol {1}",
                                          Sym.st_value, SymName)
                         << '\n';
      continue;
    }

    uint64_t Addr = ThreadLocalStorage.Beg + Sym.st_value;
    AddrToSymbolMap[Addr].insert(SymName.str());
    AddrToSizeMap[Addr] = Sym.st_size;

    TLSObjects.insert(Addr);

    TLSValueToSizeMap[Sym.st_value] = Sym.st_size;
    TLSValueToSymbolMap[Sym.st_value].insert(SymName);
  }

  // The names of the sections, as is in theory the case for all sections in ELF
  // files, are not important. Instead the linker will treat all sections of
  // type SHT PROGBITS with the SHF TLS flags set as .tdata sections, and all
  // sections of type SHT NOBITS with SHF TLS set as .tbss sections.
  });

  return 0;
}

static llvm::FunctionType *DetermineFunctionType(function_t &);
static llvm::FunctionType *DetermineFunctionType(binary_index_t, function_index_t);
static llvm::FunctionType *DetermineFunctionType(dynamic_target_t);

llvm::GlobalIFunc *LLVMTool::buildGlobalIFunc(function_t &f,
                                              dynamic_target_t IdxPair,
                                              llvm::StringRef SymName) {
  assert(SectsGlobal);

  llvm::FunctionType *FTy = is_dynamic_target_valid(IdxPair)
                                ? DetermineFunctionType(IdxPair)
                                : llvm::FunctionType::get(VoidType(), false);

  llvm::Function *F = llvm::Function::Create(
      llvm::FunctionType::get(llvm::PointerType::get(FTy, 0), false),
      llvm::GlobalValue::ExternalLinkage,
      std::string(state.for_function(f).F->getName()) + "_ifunc", Module.get());

  fillInFunctionBody(F, [&](auto &IRB) -> void {
    if (is_dynamic_target_valid(IdxPair) && IdxPair.first == BinaryIndex) {
      function_t &f = function_of_target(IdxPair, jv);

      auto &Binary = jv.Binaries.at(BinaryIndex);
      auto &ICFG = Binary.Analysis.ICFG;

      uint64_t Addr = ICFG[basic_block_of_index(f.Entry, ICFG)].Addr;

      IRB.CreateRet(IRB.CreateIntToPtr(
          SectionPointer(Addr), F->getFunctionType()->getReturnType()));
    } else if (is_dynamic_target_valid(IdxPair) &&
               DynTargetNeedsThunkPred(IdxPair)) {
      IRB.CreateCall(JoveInstallForeignFunctionTables)->setIsNoInline();

      llvm::Value *Res = GetDynTargetAddress<false>(IRB, IdxPair);

      IRB.CreateRet(
          IRB.CreateIntToPtr(Res, F->getFunctionType()->getReturnType()));
    } else if (is_dynamic_target_valid(IdxPair) &&
               !jv.Binaries.at(IdxPair.first).IsDynamicallyLoaded) {
      llvm::Value *Res = GetDynTargetAddress<false>(IRB, IdxPair);

      IRB.CreateRet(
          IRB.CreateIntToPtr(Res, F->getFunctionType()->getReturnType()));
    } else {
      IRB.CreateCall(JoveInstallForeignFunctionTables)->setIsNoInline();

      llvm::Value *SPPtr =
          BuildCPUStatePointer(IRB, CPUStateGlobal, tcg_stack_pointer_index);

      llvm::Value *SavedSP = IRB.CreateLoad(WordType(), SPPtr);
      SavedSP->setName("saved_sp");

      llvm::Value *TemporaryStack = nullptr;
      {
        TemporaryStack = IRB.CreateCall(JoveAllocStackFunc);
        llvm::Value *NewSP = IRB.CreateAdd(
            TemporaryStack, llvm::ConstantInt::get(
                                WordType(), JOVE_STACK_SIZE - JOVE_PAGE_SIZE));

        llvm::Value *AlignedNewSP =
            IRB.CreateAnd(IRB.CreatePtrToInt(NewSP, WordType()),
                          IRB.getIntN(WordBytes() * 8, ~15UL));

        llvm::Value *SPVal = AlignedNewSP;

#if defined(TARGET_X86_64) || defined(TARGET_I386)
        SPVal = IRB.CreateSub(
            SPVal, IRB.getIntN(WordBytes() * 8, WordBytes()));
#endif

        IRB.CreateStore(SPVal, SPPtr);
      }

      llvm::Value *SavedTraceP = nullptr;
      if (opts.Trace) {
        SavedTraceP = IRB.CreateLoad(IRB.getPtrTy(), TraceGlobal);
        SavedTraceP->setName("saved_tracep");

        {
          constexpr unsigned TraceAllocaSize = 4096;

          llvm::AllocaInst *TraceAlloca = IRB.CreateAlloca(
              llvm::ArrayType::get(IRB.getInt64Ty(), TraceAllocaSize));

          llvm::Value *NewTraceP = IRB.CreateConstInBoundsGEP2_64(
              TraceAlloca->getType(), TraceAlloca, 0, 0);

          IRB.CreateStore(NewTraceP, TraceGlobal);
        }
      }

      std::vector<llvm::Value *> ArgVec;
      ArgVec.resize(state.for_function(f).F->getFunctionType()->getNumParams());

      for (unsigned i = 0; i < ArgVec.size(); ++i)
        ArgVec[i] = llvm::UndefValue::get(state.for_function(f).F->getFunctionType()->getParamType(i));

      llvm::CallInst *Call = IRB.CreateCall(state.for_function(f).F, ArgVec);

      IRB.CreateStore(SavedSP, SPPtr);

      IRB.CreateCall(JoveFreeStackFunc, {TemporaryStack});

      if (opts.Trace)
        IRB.CreateStore(SavedTraceP, TraceGlobal);

      if (state.for_function(f).F->getFunctionType()->getReturnType()->isVoidTy()) {
        WithColor::warning()
            << llvm::formatv("ifunc resolver {0} returns void\n", *state.for_function(f).F);

        IRB.CreateRet(llvm::Constant::getNullValue(
            F->getFunctionType()->getReturnType()));
      } else {
        if (state.for_function(f).F->getFunctionType()->getReturnType()->isIntegerTy()) {
          IRB.CreateRet(IRB.CreateIntToPtr(
              Call, F->getFunctionType()->getReturnType()));
        } else {
          assert(state.for_function(f).F->getFunctionType()->getReturnType()->isStructTy());

          llvm::Value *Val =
              IRB.CreateExtractValue(Call, llvm::ArrayRef<unsigned>(0), "");

          IRB.CreateRet(IRB.CreateIntToPtr(
              Val, F->getFunctionType()->getReturnType()));
        }
      }
    }
  }, true);

  llvm::GlobalIFunc *res = llvm::GlobalIFunc::create(
      FTy, 0, llvm::GlobalValue::ExternalLinkage, SymName, F,
      Module.get());

  return res;
}

int LLVMTool::ProcessCOPYRelocations(void) {
  binary_t &Binary = jv.Binaries.at(BinaryIndex);

  B::_elf(*state.for_binary(Binary).Bin, [&](ELFO &O) {

  const ELFF &Elf = O.getELFFile();

  auto OptionalDynSymRegion = state.for_binary(Binary)._elf.OptionalDynSymRegion;

  if (!OptionalDynSymRegion)
    return; /* no dynamic symbols */

  const elf::DynRegionInfo &DynSymRegion = *OptionalDynSymRegion;

  auto dynamic_symbols = [&](void) -> Elf_Sym_Range {
    return DynSymRegion.getAsArrayRef<Elf_Sym>();
  };

  for_each_dynamic_relocation_if(Elf,
      state.for_binary(Binary)._elf.DynRelRegion,
      state.for_binary(Binary)._elf.DynRelaRegion,
      state.for_binary(Binary)._elf.DynRelrRegion,
      state.for_binary(Binary)._elf.DynPLTRelRegion,
      elf_is_copy_relocation,
      [&](const elf::Relocation &R) {
        elf::RelSymbol RelSym = elf::getSymbolForReloc(O, dynamic_symbols(),
                                                       state.for_binary(Binary)._elf.DynamicStringTable, R);

        assert(RelSym.Sym);

        //
        // determine symbol version (if present)
        //
        if (state.for_binary(Binary)._elf.SymbolVersionSection) {
          // Determine the position in the symbol table of this entry.
          size_t EntryIndex =
              (reinterpret_cast<uintptr_t>(RelSym.Sym) -
               reinterpret_cast<uintptr_t>(state.for_binary(Binary)._elf.OptionalDynSymRegion->Addr)) /
              sizeof(Elf_Sym);

          // Get the corresponding version index entry.
          llvm::Expected<const Elf_Versym *> ExpectedVersym =
              Elf.getEntry<Elf_Versym>(*state.for_binary(Binary)._elf.SymbolVersionSection, EntryIndex);

          if (ExpectedVersym) {
            RelSym.Vers = getSymbolVersionByIndex(state.for_binary(Binary)._elf.VersionMap,
                                                  state.for_binary(Binary)._elf.DynamicStringTable,
                                                  (*ExpectedVersym)->vs_index,
                                                  RelSym.IsVersionDefault);
          }
        }

        llvm::errs() << llvm::formatv("COPY relocation: {0} {1}\n", RelSym.Name, RelSym.Vers);

        //
        // _jove_do_emulate_copy_relocations is not actually called when the
        // dynamic linker processes COPY relocations (in an ideal world it
        // would). instead it is called some time later, after shared library
        // constructors have run. the constructor function in glibc that gives
        // us trouble is _init_first. here's what it does:
        //
        //  ...
        //  /* Save the command-line arguments.  */
        //  __environ = envp;
        //  ...
        //
        //  in normal circumstances this happens after the dynamic linker has
        //  processed COPY relocations but under jove, this happens *before*
        //  COPY relocations are processed. consequently, a COPY relocation
        //  for __environ would cause the assignment of __environ here to be
        //  overwritten by _jove_do_emulate_copy_relocations. XXX
        //
        if (RelSym.Name == "__environ") {
          WithColor::note() << "ignoring __environ COPY relocation\n";
          return;
        }

        CopyRelSyms.insert(RelSym.Name);

        if (!RelSym.Sym->st_size) {
          WithColor::error() << llvm::formatv(
              "copy relocation @ {0:x} specifies symbol {1} with size 0\n",
              R.Offset, RelSym.Name);
          abort();
        }

        WithColor::note() << llvm::formatv(
            "copy relocation @ {0:x} specifies symbol {1} with size {2}\n",
            R.Offset, RelSym.Name, RelSym.Sym->st_size);

        if (CopyRelocMap.find(std::pair<uint64_t, unsigned>(RelSym.Sym->st_value, RelSym.Sym->st_size)) !=
            CopyRelocMap.end())
          return;

        //
        // the dreaded copy relocation. we have to figure out who really defines
        // the given symbol, and then insert an entry into a map we will read later
        // to generate code that copies bytes from said symbol located in shared
        // library to said symbol in executable
        //
        struct {
          binary_index_t BIdx;
          std::pair<uint64_t, unsigned> OffsetPair;
        } CopyFrom;

        //
        // find out who to copy from
        //
        std::tie(CopyFrom.BIdx, CopyFrom.OffsetPair) = decipher_copy_relocation(RelSym);

        if (is_binary_index_valid(CopyFrom.BIdx))
          CopyRelocMap.emplace(std::pair<uint64_t, unsigned>(RelSym.Sym->st_value, RelSym.Sym->st_size),
                               std::pair<binary_index_t, std::pair<uint64_t, unsigned>>(
                                   CopyFrom.BIdx, CopyFrom.OffsetPair));

      });
  });

  return 0;
}

int LLVMTool::PrepareToTranslateCode(void) {
  TCG.reset(new tiny_code_generator_t);

  binary_t &Binary = jv.Binaries.at(BinaryIndex);

  DIBuilder.reset(new llvm::DIBuilder(*Module));

  llvm::DIBuilder &DIB = *DIBuilder;

  DebugInformation.File =
      DIB.createFile(fs::path(Binary.path_str()).filename().string() + ".fake",
                     fs::path(Binary.path_str()).parent_path().string());

  DebugInformation.CompileUnit = DIB.createCompileUnit(
      /* Lang        */ llvm::dwarf::DW_LANG_C,
      /* File        */ DebugInformation.File,
      /* Producer    */ "jove",
      /* isOptimized */ true,
      /* Flags       */ "",
      /* RunTimeVer  */ 0);

#define CONST_STRING(var, s)                                                   \
  do {                                                                         \
    llvm::Constant *StrConstant =                                              \
        llvm::ConstantDataArray::getString(*Context, s);                       \
                                                                               \
    auto *GV = new llvm::GlobalVariable(*Module, StrConstant->getType(), true, \
                                        llvm::GlobalValue::PrivateLinkage,     \
                                        StrConstant, #var, nullptr,            \
                                        llvm::GlobalVariable::NotThreadLocal); \
    GV->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::Global);                \
    GV->setAlignment(llvm::Align(1));                                          \
    llvm::Constant *Zero =                                                     \
        llvm::ConstantInt::get(llvm::Type::getInt32Ty(*Context), 0);           \
    llvm::Constant *Indices[] = {Zero, Zero};                                  \
                                                                               \
    var = llvm::ConstantExpr::getInBoundsGetElementPtr(GV->getValueType(), GV, \
                                                       Indices);               \
  } while (0)

  CONST_STRING(__jove_fail_UnknownBranchTarget, "unknown branch target");
  CONST_STRING(__jove_fail_UnknownCallee, "unknown callee");

  return 0;
}

tcg_global_set_t LLVMTool::DetermineFunctionArgs(function_t &f) {
  AnalyzeFunction(
      jv, *TCG, *Module, f,
      [&](binary_t &b) -> llvm::object::Binary & {
        return *state.for_binary(b).Bin;
      },
      [&](function_t &f) -> std::pair<basic_block_vec_t &, basic_block_vec_t &> {
        function_state_t &x = state.for_function(f);
        return std::pair<basic_block_vec_t &, basic_block_vec_t &>(x.bbvec, x.exit_bbvec);
      },
      opts.DFSan, opts.ForCBE, this);

  return f.Analysis.args;
}

tcg_global_set_t LLVMTool::DetermineFunctionRets(function_t &f) {
  AnalyzeFunction(
      jv, *TCG, *Module, f,
      [&](binary_t &b) -> llvm::object::Binary & {
        return *state.for_binary(b).Bin;
      },
      [&](function_t &f) -> std::pair<basic_block_vec_t &, basic_block_vec_t &> {
        function_state_t &x = state.for_function(f);
        return std::pair<basic_block_vec_t &, basic_block_vec_t &>(x.bbvec, x.exit_bbvec);
      },
      opts.DFSan, opts.ForCBE, this);

  return f.Analysis.rets;
}

static void sort_tcg_global_args(std::vector<unsigned> &glbv) {
  //
  // the order we want to impose is
  // CallConvArgs [sorted as CallConvArgs] ... !(CallConvArgs) [sorted by index]
  //
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

static void sort_tcg_global_rets(std::vector<unsigned> &glbv) {
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

void LLVMTool::ExplodeFunctionArgs(function_t &f, std::vector<unsigned> &glbv) {
  tcg_global_set_t args = DetermineFunctionArgs(f);

  if (f.IsABI)
    args &= CallConvArgs;

  explode_tcg_global_set(glbv, args);
  sort_tcg_global_args(glbv);
}

void LLVMTool::ExplodeFunctionRets(function_t &f, std::vector<unsigned> &glbv) {
  tcg_global_set_t rets = DetermineFunctionRets(f);

  if (f.IsABI)
    rets &= CallConvRets;

  explode_tcg_global_set(glbv, rets);
  sort_tcg_global_rets(glbv);
}

llvm::FunctionType *LLVMTool::FunctionTypeOfArgsAndRets(tcg_global_set_t args,
                                                        tcg_global_set_t rets) {
  std::vector<llvm::Type *> argTypes;
  {
    std::vector<unsigned> glbv;
    explode_tcg_global_set(glbv, args);
    sort_tcg_global_args(glbv);

    argTypes.resize(glbv.size());
    std::transform(glbv.begin(),
                   glbv.end(),
                   argTypes.begin(),
                   [&](unsigned glb) -> llvm::Type * {
                     return llvm::Type::getIntNTy(
                         *Context, bitsOfTCGType(jv_get_tcg_context()->temps[glb].type));
                   });
  }

  llvm::Type *retTy = nullptr;
  {
    std::vector<unsigned> glbv;
    explode_tcg_global_set(glbv, rets);
    sort_tcg_global_rets(glbv);

    if (glbv.empty()) {
      retTy = VoidType();
    } else if (glbv.size() == 1) {
      retTy = llvm::Type::getIntNTy(
          *Context, bitsOfTCGType(jv_get_tcg_context()->temps[glbv.front()].type));
    } else {
      std::vector<llvm::Type *> retTypes;
      retTypes.resize(glbv.size());
      std::transform(glbv.begin(), glbv.end(), retTypes.begin(),
                     [&](unsigned glb) -> llvm::Type * {
                       return llvm::Type::getIntNTy(
                           *Context, bitsOfTCGType(jv_get_tcg_context()->temps[glb].type));
                     });

      retTy = llvm::StructType::get(*Context, retTypes);
    }
  }

  return llvm::FunctionType::get(retTy, argTypes, false);
}

static const char *builtin_syms_arr[] = {
#include "builtin_syms.hpp"
};

struct ConstCharStarComparator {
  bool operator()(const char *s1, const char *s2) const {
    return strcmp(s1, s2) < 0;
  }
};

bool is_builtin_sym(const std::string &sym) {
  return std::binary_search(std::cbegin(builtin_syms_arr),
                            std::cend(builtin_syms_arr),
                            sym.c_str(),
                            ConstCharStarComparator());
}

int LLVMTool::CreateFunctions(void) {
  binary_t &Binary = jv.Binaries.at(BinaryIndex);
  const auto &ICFG = Binary.Analysis.ICFG;

  for_each_function_in_binary(Binary, [&](function_t &f) {
    if (unlikely(!is_basic_block_index_valid(f.Entry)))
      return;

    const uint64_t Addr = ICFG[basic_block_of_index(f.Entry, ICFG)].Addr;

    std::string jove_name = (fmt("%c%lx") % (f.IsABI ? 'J' : 'j') % Addr).str();

    state.for_function(f).F =
        llvm::Function::Create(DetermineFunctionType(f),
                               f.IsABI ? llvm::GlobalValue::ExternalLinkage
                                       : llvm::GlobalValue::InternalLinkage,
                               jove_name, Module.get());
    state.for_function(f).F->addFnAttr(llvm::Attribute::NonLazyBind);

    if (f.IsABI)
      state.for_function(f).F->setVisibility(llvm::GlobalValue::HiddenVisibility);

#if defined(TARGET_I386)
    //
    // XXX i386 quirk
    //
    if (f.IsABI) {
      for (unsigned i = 0; i < state.for_function(f).F->arg_size(); ++i) {
        assert(i < 3);

        state.for_function(f).F->addParamAttr(i, llvm::Attribute::InReg);
      }
    }
#endif

    //
    // assign names to the arguments, the registers they represent
    //
    {
      std::vector<unsigned> glbv;
      ExplodeFunctionArgs(f, glbv);

      unsigned i = 0;
      for (llvm::Argument &A : state.for_function(f).F->args()) {
        std::string name = opts.ForCBE ? "_" : "";
        name.append(jv_get_tcg_context()->temps[glbv.at(i)].name);
        A.setName(name);
        ++i;
      }
    }
  });

  for_each_function_in_binary(Binary, [&](function_t &f) {
    if (unlikely(!is_basic_block_index_valid(f.Entry)))
      return;

    const uint64_t Addr = ICFG[basic_block_of_index(f.Entry, ICFG)].Addr;

    if (!f.IsABI) {
      //
      // create "ABI adapter"
      //
      state.for_function(f).adapterF = llvm::Function::Create(
          FunctionTypeOfArgsAndRets(CallConvArgs, CallConvRets),
          llvm::GlobalValue::ExternalLinkage,
          (fmt("Jj%lx") % Addr).str(), Module.get());

      state.for_function(f).adapterF->addFnAttr(llvm::Attribute::NonLazyBind);

      //
      // assign names to the arguments, the registers they represent
      //
      unsigned i = 0;
      for (llvm::Argument &A : state.for_function(f).adapterF->args()) {
        std::string name = opts.ForCBE ? "_" : "";
        name.append(jv_get_tcg_context()->temps[CallConvArgArray.at(i)].name);
        A.setName(name);
        ++i;
      }
    }
  });

  return 0;
}

int LLVMTool::CreateFunctionTables(void) {
  for (binary_index_t BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx) {
    binary_t &binary = jv.Binaries.at(BIdx);
    if (binary.IsDynamicLinker)
      continue;
    if (binary.IsVDSO)
      continue;
    if (binary.IsDynamicallyLoaded)
      continue;
    if (opts.ForeignLibs && !binary.IsExecutable)
      continue;

    state.for_binary(binary).SectsF = llvm::Function::Create(
        llvm::FunctionType::get(WordType(), false),
        llvm::GlobalValue::ExternalLinkage,
        (fmt("__jove_b%u_sects") % BIdx).str(), Module.get());

    if (BIdx == BinaryIndex)
      continue;

    state.for_binary(binary).FunctionsTable = new llvm::GlobalVariable(
        *Module,
        llvm::ArrayType::get(WordType(),
                             3 * binary.Analysis.Functions.size() + 1),
        false, llvm::GlobalValue::ExternalLinkage, nullptr,
        (fmt("__jove_b%u") % BIdx).str());

    state.for_binary(binary).FunctionsTableClunk = new llvm::GlobalVariable(
        *Module,
        llvm::PointerType::get(*Context, 0),
        false, llvm::GlobalValue::InternalLinkage,
        state.for_binary(binary).FunctionsTable,
        (fmt("__jove_b%u_clunk") % BIdx).str());

    ReferenceInNoDCEFunc(state.for_binary(binary).FunctionsTableClunk);
  }

  return 0;
}

int LLVMTool::CreateFunctionTable(void) {
  binary_t &Binary = jv.Binaries.at(BinaryIndex);
  auto &ICFG = Binary.Analysis.ICFG;

  if (llvm::Function *F = state.for_binary(Binary).SectsF) {
    fillInFunctionBody(F, [&](auto &IRB) {
      IRB.CreateRet(llvm::ConstantExpr::getPtrToInt(SectionsTop(), WordType()));
    }, false /* internalize */);

    F->setVisibility(llvm::GlobalValue::DefaultVisibility);
  }

  std::vector<llvm::Constant *> constantTable;
  constantTable.resize(3 * Binary.Analysis.Functions.size());

  for (unsigned i = 0; i < Binary.Analysis.Functions.size(); ++i) {
    const function_t &f = Binary.Analysis.Functions.at(i);

    llvm::Constant *&C1 = constantTable[3 * i + 0];
    llvm::Constant *&C2 = constantTable[3 * i + 1];
    llvm::Constant *&C3 = constantTable[3 * i + 2];

    if (unlikely(!is_basic_block_index_valid(f.Entry))) {
      C1 = llvm::Constant::getNullValue(WordType());
      C2 = llvm::Constant::getNullValue(WordType());
      C3 = llvm::Constant::getNullValue(WordType());
      continue;
    }

    if (!f.IsABI)
      assert(state.for_function(f).adapterF);

    C1 = SectionPointer(ICFG[basic_block_of_index(f.Entry, ICFG)].Addr);
    C2 = llvm::ConstantExpr::getPtrToInt(state.for_function(f).F, WordType());
    C3 = state.for_function(f).adapterF
             ? llvm::ConstantExpr::getPtrToInt(state.for_function(f).adapterF, WordType())
             : llvm::ConstantExpr::getPtrToInt(state.for_function(f).F, WordType());
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

  fillInFunctionBody(
      Module->getFunction("_jove_get_function_table"),
      [&](auto &IRB) {
        IRB.CreateRet(IRB.CreateConstInBoundsGEP2_64(
            ConstantTableInternalGV->getValueType(),
            ConstantTableInternalGV, 0, 0));
      },
      !opts.ForCBE);

  fillInFunctionBody(
      Module->getFunction("_jove_function_count"), [&](auto &IRB) {
        IRB.CreateRet(IRB.getInt32(Binary.Analysis.Functions.size()));
      }, !opts.ForCBE);

  fillInFunctionBody(
      Module->getFunction("_jove_foreign_functions_count"), [&](auto &IRB) {
#if 0
        unsigned N_1 =
            std::accumulate(std::next(jv.Binaries.begin(), 1),
                            std::next(jv.Binaries.begin(), 3), 0u,
                            [&](unsigned res, const binary_t &b) -> unsigned {
                              return res + b.Analysis.Functions.size();
                            });

        unsigned N_2 =
            std::accumulate(std::next(jv.Binaries.begin(), 3),
                            jv.Binaries.end(), 0u,
                            [&](unsigned res, const binary_t &b) -> unsigned {
                              return res + b.Analysis.Functions.size();
                            });

        unsigned M = N_1 + (opts.ForeignLibs ? N_2 : 0);

        IRB.CreateRet(IRB.getInt32(M));
#else
        unsigned N =
            std::accumulate(jv.Binaries.begin(),
                            jv.Binaries.end(), 0u,
                            [&](unsigned res, const binary_t &b) -> unsigned {
                              return res + b.Analysis.Functions.size();
                            });
        IRB.CreateRet(IRB.getInt32(N));
#endif
      }, !opts.ForCBE);

  return 0;
}

} // namespace jove

namespace llvm {

static Value *getNaturalGEPWithOffset(IRBuilderTy &,
                                      const DataLayout &,
                                      std::pair<Value *, Type *> Ptr,
                                      APInt Offset,
                                      Type *TargetTy,
                                      SmallVectorImpl<Value *> &Indices,
                                      const Twine &NamePrefix);
} // namespace llvm

namespace jove {

int LLVMTool::CreateTLSModGlobal(void) {
  TLSModGlobal = new llvm::GlobalVariable(
      *Module, WordType(), true, llvm::GlobalValue::InternalLinkage,
      llvm::ConstantInt::get(WordType(), 0x12345678), "__jove_tpmod");
  return 0;
}

llvm::ArrayType *LLVMTool::TLSDescType(void) {
  llvm::ArrayType *&T = TLSDescHack.T;

  if (!T)
    T = llvm::ArrayType::get(WordType(), 2);

  return TLSDescHack.T;
}

llvm::GlobalVariable *LLVMTool::TLSDescGV(void) {
  assert(IsX86Target); /* FIXME? */

  llvm::GlobalVariable *&GV = TLSDescHack.GV;

  if (!GV) {
    llvm::ArrayType *T = TLSDescType();

    std::vector<llvm::Constant *> constantTable(
        2, llvm::Constant::getAllOnesValue(WordType()));
    llvm::Constant *Init = llvm::ConstantArray::get(T, constantTable);

    GV = new llvm::GlobalVariable(*Module, T, false,
                                  llvm::GlobalValue::ExternalLinkage,
                                  Init, "__jove_td");
    GV->setVisibility(llvm::GlobalValue::HiddenVisibility);

    //Module->appendModuleInlineAsm(".reloc __jove_td, R_X86_64_TLSDESC");
  }

  return GV;
}

llvm::Constant *LLVMTool::SymbolAddress(const elf::RelSymbol &RelSym) {
  assert(RelSym.Sym);

  bool IsDefined = !RelSym.Sym->isUndefined() &&
                   RelSym.Sym->st_shndx != llvm::ELF::SHN_UNDEF;

  bool IsCode = RelSym.Sym->getType() == llvm::ELF::STT_FUNC;

  bool IsTLS = RelSym.Sym->getType() == llvm::ELF::STT_TLS;

  if (IsDefined) {
    if (IsCode) {
      //
      // the following breaks symbol interposition
      //
      return SectionPointer(RelSym.Sym->st_value);
    } else {
      assert(RelSym.Sym->st_size > 0);

      if (IsTLS) {
        llvm::GlobalValue *GV = Module->getNamedValue(RelSym.Name);

        assert(GV);
        assert(GV->getThreadLocalMode() != llvm::GlobalValue::NotThreadLocal);

        return llvm::ConstantExpr::getPtrToInt(GV, WordType());
      }

#if !defined(TARGET_MIPS64) && !defined(TARGET_MIPS32)
      if (CopyRelSyms.find(RelSym.Name) == CopyRelSyms.end()) {
        //
        // working symbol interposition
        //
        if (llvm::GlobalValue *GV = Module->getNamedValue(RelSym.Name)) {
          //assert(GV->hasInitializer());
          return llvm::ConstantExpr::getPtrToInt(GV, WordType());
        }

        AddrToSymbolMap[RelSym.Sym->st_value].insert(RelSym.Name);
        AddrToSizeMap[RelSym.Sym->st_value] = RelSym.Sym->st_size;

        return nullptr;
      }
#endif

      //
      // the following breaks symbol interposition
      //
      return SectionPointer(RelSym.Sym->st_value);
    }
  } else {
    if (IsCode) {
      if (auto *F = Module->getFunction(RelSym.Name)) {
        assert(F->empty());
        return llvm::ConstantExpr::getPtrToInt(F, WordType());
      }

      //
      // we have to declare it.
      //
      llvm::FunctionType *FTy = llvm::FunctionType::get(VoidType(), false); /* TODO */

      llvm::Function *F =
          llvm::Function::Create(FTy,
                                 RelSym.Sym->getBinding() == llvm::ELF::STB_WEAK
                                     ? llvm::GlobalValue::ExternalWeakLinkage
                                     : llvm::GlobalValue::ExternalLinkage,
                                 RelSym.Name, Module.get());
      F->addFnAttr(llvm::Attribute::NonLazyBind);

      if (!RelSym.Vers.empty()) {
        Module->appendModuleInlineAsm(
            (llvm::Twine(".symver ") + RelSym.Name + "," + RelSym.Name +
             (RelSym.IsVersionDefault ? "@@" : "@") + RelSym.Vers)
                .str());

        VersionScript.Table[RelSym.Vers];
      }

      return llvm::ConstantExpr::getPtrToInt(F, WordType());
    } else {
      if (llvm::GlobalVariable *GV = Module->getGlobalVariable(RelSym.Name, false)) {
        assert(!GV->hasInitializer());
        return llvm::ConstantExpr::getPtrToInt(GV, WordType());
      }

      //
      // we have to declare it.
      //
      unsigned Size;

      auto it = GlobalSymbolDefinedSizeMap.find(RelSym.Name);
      if (it == GlobalSymbolDefinedSizeMap.end()) {
        WithColor::warning() << llvm::formatv(
            "{0}: unknown size for {1}\n",
            __func__, RelSym.Name);

        Size = WordBytes();
      } else {
        Size = (*it).second;
      }

      llvm::Type *GTy =
          is_integral_size(Size)
              ? static_cast<llvm::Type *>(llvm::Type::getIntNTy(*Context, Size * 8))
              : static_cast<llvm::Type *>(llvm::ArrayType::get(llvm::Type::getInt8Ty(*Context), Size));

      auto *GV =
          new llvm::GlobalVariable(*Module, GTy, false,
                                   RelSym.Sym->getBinding() == llvm::ELF::STB_WEAK
                                       ? llvm::GlobalValue::ExternalWeakLinkage
                                       : llvm::GlobalValue::ExternalLinkage,
                                   nullptr, RelSym.Name, nullptr,
                                   IsTLS ? llvm::GlobalValue::GeneralDynamicTLSModel :
                                           llvm::GlobalValue::NotThreadLocal);
      GV->setAlignment(llvm::Align(2 * WordBytes()));

      if (!RelSym.Vers.empty()) {
        Module->appendModuleInlineAsm(
            (llvm::Twine(".symver ") + RelSym.Name + "," + RelSym.Name +
             (RelSym.IsVersionDefault ? "@@" : "@") + RelSym.Vers)
                .str());
        //VersionScript.Table[RelSym.Vers];
      }

      return llvm::ConstantExpr::getPtrToInt(GV, WordType());
    }
  }
}

llvm::Constant *LLVMTool::ImportFunction(llvm::StringRef Name) {
  llvm::FunctionType *FTy =
      llvm::FunctionType::get(VoidType(), false); /* FIXME? */
  llvm::Function *F = llvm::Function::Create(
      FTy, llvm::GlobalValue::ExternalLinkage, Name, Module.get());
  F->setDLLStorageClass(llvm::GlobalValue::DLLImportStorageClass);
  F->addFnAttr(llvm::Attribute::NonLazyBind);

  return F;
}

llvm::Constant *LLVMTool::ImportFunctionByOrdinal(llvm::StringRef DLL,
                                                  uint32_t Ordinal) {
  std::string nm(coff::unique_symbol_for_ordinal_in_dll(DLL, Ordinal));

  llvm::errs() << "creating " << nm << '\n';

  llvm::FunctionType *FTy =
      llvm::FunctionType::get(VoidType(), false); /* FIXME? */
  llvm::Function *F = llvm::Function::Create(
      FTy, llvm::GlobalValue::ExternalLinkage, nm, Module.get());
  F->setDLLStorageClass(llvm::GlobalValue::DLLImportStorageClass);
  F->addFnAttr(llvm::Attribute::NonLazyBind);

  bool success = ordinal_imports[DLL.str()].insert(Ordinal).second;
  assert(success);

  return F;
}

llvm::Constant *LLVMTool::ImportedFunctionAddress(llvm::StringRef DLL,
                                                  uint32_t Ordinal,
                                                  llvm::StringRef Name,
                                                  uint64_t Addr) {
  const bool ByOrdinal = Name.empty();

  std::string nm = ByOrdinal
                       ? coff::unique_symbol_for_ordinal_in_dll(DLL, Ordinal)
                       : Name.str();

  if (auto *F = Module->getFunction(nm)) {
    assert(F->empty());
    return llvm::ConstantExpr::getPtrToInt(F, WordType());
  }

  //
  // this is new to us
  //
  possible_tramps_vec.push_back(Addr);
  if (ByOrdinal) {
    return llvm::ConstantExpr::getPtrToInt(ImportFunctionByOrdinal(DLL, Ordinal), WordType());
  } else {
    return llvm::ConstantExpr::getPtrToInt(ImportFunction(Name), WordType());
  }
}

void LLVMTool::elf_compute_irelative_relocation(llvm::IRBuilderTy &IRB,
                                            uint64_t resolverAddr) {
  llvm::Value *TemporaryStack = IRB.CreateCall(JoveAllocStackFunc);

  llvm::Value *SPPtr =
      BuildCPUStatePointer(IRB, CPUStateGlobal, tcg_stack_pointer_index);
  {
    llvm::Value *NewSP = IRB.CreateAdd(
        TemporaryStack,
        llvm::ConstantInt::get(WordType(), JOVE_STACK_SIZE - JOVE_PAGE_SIZE));

    NewSP = IRB.CreateAnd(NewSP, IRB.getIntN(WordBits(), ~15UL));

#if defined(TARGET_X86_64) || defined(TARGET_I386)
    //
    // account for stack pointer on stack
    //
    NewSP = IRB.CreateSub(NewSP, IRB.getIntN(WordBits(), WordBytes()));
#endif

    IRB.CreateStore(NewSP, SPPtr);
  }

  binary_t &Binary = jv.Binaries.at(BinaryIndex);

  function_t &resolver_f = function_at_address(Binary, resolverAddr);
  assert(resolver_f.IsABI && "resolver function should be ABI!");

  llvm::Function *resolverF = state.for_function(resolver_f).F;

  std::vector<llvm::Value *> ArgVec(
      resolverF->getFunctionType()->getNumParams(),
      llvm::Constant::getNullValue(WordType()));

  llvm::CallInst *Call = IRB.CreateCall(resolverF, ArgVec);

  llvm::Value *Res = nullptr;

  if (resolverF->getFunctionType()->getReturnType()->isIntegerTy()) {
    Res = Call;
  } else {
    assert(resolverF->getFunctionType()->getReturnType()->isStructTy());

    Res = IRB.CreateExtractValue(Call, llvm::ArrayRef<unsigned>(0), "");
  }

  IRB.CreateCall(JoveFreeStackFunc, {TemporaryStack});

  IRB.CreateRet(Res);
}

void LLVMTool::elf_compute_tpoff_relocation(llvm::IRBuilderTy &IRB,
                                        const elf::RelSymbol &RelSym,
                                        unsigned Offset) {
  llvm::Value *TLSAddr = nullptr;
  if (RelSym.Sym) {
    TLSAddr = SymbolAddress(RelSym);
    assert(TLSAddr);
  } else {
    auto it = TLSValueToSymbolMap.find(Offset);
    if (it == TLSValueToSymbolMap.end()) {
      TLSAddr = llvm::ConstantExpr::getAdd(
          llvm::ConstantExpr::getPtrToInt(TLSSectsGlobal, WordType()),
          llvm::ConstantInt::get(WordType(), Offset));
    } else {
      llvm::GlobalVariable *GV = nullptr;
      for (auto sym_it = (*it).second.begin(); sym_it != (*it).second.end(); ++sym_it) {
        GV = Module->getGlobalVariable(*sym_it);
        if (GV)
          break;
      }

      assert(GV);
      assert(GV->isThreadLocal());
      TLSAddr = llvm::ConstantExpr::getPtrToInt(GV, WordType());
    }
  }

#if 0 // good intention behind this, but the offset here can be < 0!
  llvm::BasicBlock *Fail =
      llvm::BasicBlock::Create(*Context, "fail", IRB.GetInsertBlock()->getParent());
  llvm::BasicBlock *Good =
      llvm::BasicBlock::Create(*Context, "succ", IRB.GetInsertBlock()->getParent());

  llvm::Value *TP = insertThreadPointerInlineAsm(IRB);

  IRB.CreateCondBr(IRB.CreateICmpUGE(TLSAddr, TP), Good, Fail);

  {
    IRB.SetInsertPoint(Fail);

    IRB.CreateCall(llvm::Intrinsic::getDeclaration(
        Module.get(), llvm::Intrinsic::trap)); /* FIXME */
    IRB.CreateUnreachable();
  }

  {
    IRB.SetInsertPoint(Good);

    IRB.CreateRet(IRB.CreateSub(TLSAddr, TP));
  }
#else
  llvm::Value *TP = insertThreadPointerInlineAsm(IRB);
  IRB.CreateRet(IRB.CreateSub(TLSAddr, TP));
#endif
}

uint64_t LLVMTool::ExtractWordAtAddress(uint64_t Addr) {
  auto &Binary = jv.Binaries.at(BinaryIndex);

  auto &Bin = state.for_binary(Binary).Bin;

  const void *Ptr = B::toMappedAddr(*Bin, Addr);
  return B::extractAddress(*Bin, Ptr);
}

struct unhandled_relocation_exception {};

#include "relocs_llvm.hpp"

int LLVMTool::CreateSectionGlobalVariables(void) {
  binary_t &Binary = jv.Binaries.at(BinaryIndex);
  auto &Bin = state.for_binary(Binary).Bin;

  struct PatchContents {
    LLVMTool &tool;
    binary_index_t BinaryIndex;
    std::vector<uint32_t> FunctionOrigInsnTable;

    PatchContents(LLVMTool &tool, binary_index_t BinaryIndex)
        : tool(tool), BinaryIndex(BinaryIndex) {
      auto &Binary = tool.jv.Binaries.at(BinaryIndex);
      auto &ICFG = Binary.Analysis.ICFG;

      FunctionOrigInsnTable.resize(Binary.Analysis.Functions.size());

      for (function_index_t FIdx = 0; FIdx <  Binary.Analysis.Functions.size(); ++FIdx) {
        function_t &f = Binary.Analysis.Functions.at(FIdx);
        if (!is_basic_block_index_valid(f.Entry))
          continue;

        uint64_t Addr = ICFG[basic_block_of_index(f.Entry, ICFG)].Addr;

        uint32_t &insn = *((uint32_t *)binary_data_ptr_of_addr(Addr));

        FunctionOrigInsnTable[FIdx] = insn;
      }

      for (function_index_t FIdx = 0; FIdx <  Binary.Analysis.Functions.size(); ++FIdx) {
        function_t &f = Binary.Analysis.Functions.at(FIdx);
        if (!is_basic_block_index_valid(f.Entry))
          continue;

        if (!f.IsABI)
          continue;

        if (tool.state.for_function(f).IsLj ||
            tool.state.for_function(f).IsSj)
          continue;

        uint64_t Addr = ICFG[basic_block_of_index(f.Entry, ICFG)].Addr;

#if defined(TARGET_MIPS32) || defined(TARGET_MIPS64)
        uint8_t *insnp = ((uint8_t *)binary_data_ptr_of_addr(Addr));

        //
        // lw at,0(zero) ; <- guaranteed to SIGSEGV
        //
#ifdef TARGET_WORDS_BIGENDIAN
        insnp[0] = 0x8c;
        insnp[1] = 0x01;
        insnp[2] = 0x00;
        insnp[3] = 0x00;
#else
        insnp[0] = 0x00;
        insnp[1] = 0x00;
        insnp[2] = 0x01;
        insnp[3] = 0x8c;
#endif
#elif defined(TARGET_X86_64) || defined(TARGET_I386)
        uint8_t *insnp = ((uint8_t *)binary_data_ptr_of_addr(Addr));

        insnp[0] = 0x0f; /* ud2 ; <- guaranteed to SIGILL */
        insnp[1] = 0x0b;
#elif defined(TARGET_AARCH64)
        uint32_t &insn = *((uint32_t *)binary_data_ptr_of_addr(Addr));

        insn = 0x00000000; /* udf     #0 ; <- guaranteed to SIGILL */
#else
#error
#endif
      }
    }
    ~PatchContents() {
      auto &Binary = tool.jv.Binaries.at(BinaryIndex);
      auto &ICFG = Binary.Analysis.ICFG;

      //
      // restore original insns
      //
      for (function_index_t FIdx = 0; FIdx <  Binary.Analysis.Functions.size(); ++FIdx) {
        function_t &f = Binary.Analysis.Functions.at(FIdx);
        if (!is_basic_block_index_valid(f.Entry))
          continue;

        if (!f.IsABI)
          continue;

        if (tool.state.for_function(f).IsLj ||
            tool.state.for_function(f).IsSj)
          continue;

        uint64_t Addr = ICFG[basic_block_of_index(f.Entry, ICFG)].Addr;

        uint32_t &insn = *((uint32_t *)binary_data_ptr_of_addr(Addr));

        insn = FunctionOrigInsnTable[FIdx];
      }
    }

    void *binary_data_ptr_of_addr(uint64_t Addr) {
      auto &Binary = tool.jv.Binaries.at(BinaryIndex);
      auto &Bin = tool.state.for_binary(Binary).Bin;

      const void *Ptr = B::toMappedAddr(*Bin, Addr);

      //
      // the data resides in a std::string; it is writeable memory
      //
      return const_cast<void *>(Ptr);
    }
  } __PatchContents(*this, BinaryIndex);

  unsigned NumSections = 0;
  boost::icl::split_interval_map<uint64_t, section_properties_set_t> SectMap;
  std::vector<section_t> SectTable;
  boost::icl::interval_map<uint64_t, unsigned> SectIdxMap;

  std::vector<std::vector<uint8_t>> SegContents;

  const uint64_t SectsStartAddr = state.for_binary(Binary).SectsStartAddr;
  const uint64_t SectsEndAddr = state.for_binary(Binary).SectsEndAddr;

  struct {
    int rsrcSectIdx = -1;
  } _coff;

  B::_elf(*Bin, [&](ELFO &O) {

  const ELFF &Elf = O.getELFFile();

  llvm::Expected<Elf_Shdr_Range> ExpectedSections = Elf.sections();
  if (ExpectedSections && !(*ExpectedSections).empty()) {
    //
    // build section map
    //
    for (const Elf_Shdr &Sec : *ExpectedSections) {
      if (!(Sec.sh_flags & llvm::ELF::SHF_ALLOC))
        continue;

      llvm::Expected<llvm::StringRef> name = Elf.getSectionName(Sec);

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
            Elf.getSectionContents(Sec);
        assert(contents);
        sectprop.contents = *contents;
      }

      sectprop.w = !!(Sec.sh_flags & llvm::ELF::SHF_WRITE);
      sectprop.x = !!(Sec.sh_flags & llvm::ELF::SHF_EXECINSTR);

      sectprop._elf.initArray = Sec.sh_type == llvm::ELF::SHT_INIT_ARRAY;
      sectprop._elf.finiArray = Sec.sh_type == llvm::ELF::SHT_FINI_ARRAY;

      boost::icl::interval<uint64_t>::type intervl =
          boost::icl::interval<uint64_t>::right_open(
              Sec.sh_addr, Sec.sh_addr + Sec.sh_size);

      {
        auto it = SectMap.find(intervl);
        if (it != SectMap.end()) {
          WithColor::error() << "the following sections intersect: "
                             << (*(*it).second.begin()).name << " and "
                             << sectprop.name << '\n';
          exit(1);
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
          boost::icl::interval<uint64_t>::right_open(0, Sect.Size));
      Sect._elf.initArray = prop._elf.initArray;
      Sect._elf.finiArray = prop._elf.finiArray;

      ++i;
    }
  } else {
    llvm::SmallVector<const Elf_Phdr *, 4> LoadSegments;

    auto ProgramHeadersOrError = Elf.program_headers();
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

      std::vector<uint8_t> &vec = SegContents.at(i);
      vec.resize(LoadSegments[i]->p_memsz);
      memset(&vec[0], 0, vec.size());
      memcpy(&vec[0], Elf.base() + LoadSegments[i]->p_offset, LoadSegments[i]->p_filesz);

      boost::icl::interval<uint64_t>::type intervl =
          boost::icl::interval<uint64_t>::right_open(
              LoadSegments[i]->p_vaddr,
              LoadSegments[i]->p_vaddr + LoadSegments[i]->p_memsz);

      SectIdxMap.add({intervl, 1+i});

      {
        section_properties_t sectprop;

        sectprop.name = (fmt(".seg.%u") % i).str();
        sectprop.contents = vec;
        sectprop.w = true;
        sectprop.x = false;
        sectprop._elf.initArray = false;
        sectprop._elf.finiArray = false;

        SectMap.add({intervl, {sectprop}});
      }

      {
        section_t &s = SectTable[i];

        s.Addr = LoadSegments[i]->p_vaddr;
        s.Size = LoadSegments[i]->p_memsz;
        s.Name = (fmt(".seg.%u") % i).str();
        s.Contents = vec;
        s.Stuff.Intervals.insert(
            boost::icl::interval<uint64_t>::right_open(0, s.Size));
        s._elf.initArray = false;
        s._elf.finiArray = false;
        s.T = nullptr;
      }
    }
  }

  });

  B::_coff(*Bin, [&](COFFO &O) {
    NumSections = O.getNumberOfSections();
    SectTable.resize(NumSections);
    SegContents.resize(NumSections);

    unsigned i = 0;
    auto sect_itr = O.sections();
    for (auto it = sect_itr.begin(); it != sect_itr.end(); ++it, ++i) {
      const obj::SectionRef &S = *it;

      const llvm::object::coff_section *pSect = O.getCOFFSection(S);
      assert(pSect);
      const llvm::object::coff_section &Sect = *pSect;

      section_properties_t sectprop;
      sectprop.name = Sect.Name;

      if (Sect.PointerToRawData) {
        llvm::ArrayRef<uint8_t> contents;
        if (llvm::errorToBool(O.getSectionContents(&Sect, contents))) {
          WithColor::warning() << "failed to get contents of section "
                             << Sect.Name << '\n';
        } else {
          assert(contents.size() <= Sect.SizeOfRawData);

          if (IsVerbose())
            llvm::errs() << llvm::formatv(
                "section {0} is {1} bytes (have {2}) (should have {3})\n",
                Sect.Name,
                Sect.VirtualSize,
                contents.size(),
                Sect.SizeOfRawData);

          std::vector<uint8_t> &vec = SegContents.at(i);

          vec.resize(Sect.VirtualSize);
          memset(&vec[0], 0, vec.size());
          memcpy(&vec[0], contents.data(), std::min(vec.size(), contents.size()));

          sectprop.contents = vec;
        }
      }

      sectprop.x = Sect.Characteristics & llvm::COFF::IMAGE_SCN_MEM_EXECUTE;
      sectprop.w = Sect.Characteristics & llvm::COFF::IMAGE_SCN_MEM_WRITE;

      boost::icl::interval<uint64_t>::type intervl =
          boost::icl::interval<uint64_t>::right_open(
              coff::va_of_rva(O, Sect.VirtualAddress),
              coff::va_of_rva(O, Sect.VirtualAddress) + Sect.VirtualSize);

      {
        auto _it = SectMap.find(intervl);
        if (_it != SectMap.end()) {
          WithColor::error() << "the following sections intersect: "
                             << (*(*_it).second.begin()).name << " and "
                             << Sect.Name << '\n';
          exit(1);
        }
      }

      SectMap.add({intervl, {sectprop}});
    }

    assert(SectMap.iterative_size() == NumSections);

    i = 0;
    for (const auto &pair : SectMap) {
      section_t &Sect = SectTable.at(i);

      SectIdxMap.add({pair.first, 1+i});

      const section_properties_t &prop = *pair.second.begin();
      Sect.Addr = pair.first.lower();
      Sect.Size = pair.first.upper() - pair.first.lower();
      Sect.Name = prop.name;
      Sect.Contents = prop.contents;
      Sect.Stuff.Intervals.insert(
          boost::icl::interval<uint64_t>::right_open(0, Sect.Size));
      Sect._elf.initArray = prop._elf.initArray;
      Sect._elf.finiArray = prop._elf.finiArray;

      if (Sect.Name == ".rsrc") {
        if (_coff.rsrcSectIdx >= 0)
          die("multiple .rsrc sections in PE file?");

        _coff.rsrcSectIdx = i;
      }

      ++i;
    }
  });

  auto type_at_address = [&](uint64_t Addr, llvm::Type *T) -> void {
    auto it = SectIdxMap.find(Addr);
    assert(it != SectIdxMap.end());

    section_t &Sect = SectTable[-1+(*it).second];
    unsigned Off = Addr - Sect.Addr;

    Sect.Stuff.Intervals.insert(boost::icl::interval<uint64_t>::right_open(
        Off, Off + DL.getTypeAllocSize(T)));
    Sect.Stuff.Types[Off] = T;
  };

  auto constant_at_address = [&](uint64_t Addr, llvm::Constant *C) -> void {
    auto it = SectIdxMap.find(Addr);
    assert(it != SectIdxMap.end());

    section_t &Sect = SectTable[-1+(*it).second];
    unsigned Off = Addr - Sect.Addr;

#if 0
    Sect.Stuff.Intervals.insert(boost::icl::interval<uintptr_t>::right_open(
        Off, Off + sizeof(uintptr_t)));
#endif

    if (Sect.Stuff.Types.find(Off) == Sect.Stuff.Types.end())
      WithColor::warning() << llvm::formatv("%s:%d\n", __FILE__, __LINE__);

    Sect.Stuff.Constants[Off] = C;
  };

  llvm::StructType *SectsGlobalTy;

  auto declare_sections = [&](void) -> void {
    //
    // create global variable for sections
    //
    std::vector<llvm::Type *> SectsGlobalFieldTys;
    for (unsigned i = 0; i < NumSections; ++i) {
      section_t &Sect = SectTable[i];
#if 0
      llvm::errs() << llvm::formatv("Section: {0}\n", Sect.Name);
#endif

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

#if 0
        llvm::errs() << llvm::formatv("  [{0:x}, {1:x}) <T: {2}>\n",
                                      intvl.lower(),
                                      intvl.upper(), *T);
#endif

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

    SectsGlobal = new llvm::GlobalVariable(*Module,
        SectsGlobalTy, false, llvm::GlobalValue::ExternalLinkage, nullptr,
        SectsGlobalName);

    ConstSectsGlobal = new llvm::GlobalVariable(
        *Module, SectsGlobalTy, false, llvm::GlobalValue::ExternalLinkage,
        nullptr, ConstSectsGlobalName);

    if (!jv.Binaries.at(BinaryIndex).IsPIC) {
      assert(jv.Binaries.at(BinaryIndex).IsExecutable);

      SectsGlobal->setAlignment(llvm::Align(1));
      ConstSectsGlobal->setAlignment(llvm::Align(1));
    } else {
      SectsGlobal->setAlignment(llvm::Align(2 * WordBytes()));
      ConstSectsGlobal->setAlignment(llvm::Align(2 * WordBytes()));
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

      if (IsVerbose())
        llvm::errs() << llvm::formatv("Section: {0} ({1} bytes)\n", Sect.Name,
                                      Sect.Contents.size());

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
#if 0
        if (IsVerbose())
          llvm::errs() << llvm::formatv("  [{0:x}, {1:x})\n",
                                        intvl.lower(),
                                        intvl.upper());
#endif
        //
        // FIXME the following is code duplication, don't you think?
        //
        llvm::Type *T;
        {
          auto it = Sect.Stuff.Types.find(intvl.lower());

          if (it == Sect.Stuff.Types.end() || !(*it).second)
            T = llvm::ArrayType::get(llvm::IntegerType::get(*Context, 8),
                                     intvl.upper() - intvl.lower());
          else
            T = (*it).second;
        }

        auto it = Sect.Stuff.Constants.find(intvl.lower());

        llvm::Constant *C = nullptr;
        if (it == Sect.Stuff.Constants.end()) {
          ptrdiff_t len = intvl.upper() - intvl.lower();
          assert(len > 0);

          if (Sect.Contents.size() >= len) {
            assert(Sect.Contents.size() - intvl.lower() >= len);

            C = llvm::ConstantDataArray::get(
                *Context,
                llvm::ArrayRef<uint8_t>(Sect.Contents.begin() + intvl.lower(),
                                        Sect.Contents.begin() + intvl.upper()));
          } else {
            C = llvm::Constant::getNullValue(
                llvm::ArrayType::get(llvm::Type::getInt8Ty(*Context), len));
          }
        } else {
          C = (*it).second ?: llvm::Constant::getNullValue(T);
        }
        assert(C);

#if 0
        if (IsVerbose())
          llvm::errs() << llvm::formatv("  [{0:x}, {1:x}) <C: {2}>\n",
                                        intvl.lower(),
                                        intvl.upper(), *C);
#endif

        SectFieldInits.push_back(C);
      }

      // XXX the following assumes .rsrc is just pure bytes, and it assumes the
      // section can basically just be anywhere relative to the other sections
      // XXX wasteful, consider --lay-out-sections
      if (!opts.LayOutSections && IsCOFF && Sect.Name == ".rsrc" &&
          !Module->getGlobalVariable("__jove_rsrc", true)) {
        llvm::GlobalVariable *rsrcSectGV = new llvm::GlobalVariable(
            *Module, SectTable[i].T, false, llvm::GlobalValue::InternalLinkage,
            llvm::ConstantStruct::get(SectTable[i].T, SectFieldInits),
            "__jove_rsrc");
        rsrcSectGV->setSection(".rsrc");
      }

      SectTable[i].C = llvm::ConstantStruct::get(SectTable[i].T, SectFieldInits);

      SectsGlobalFieldInits.push_back(SectTable[i].C);
    }

    SectsGlobal->setInitializer(
        llvm::ConstantStruct::get(SectsGlobalTy, SectsGlobalFieldInits));
    ConstSectsGlobal->setInitializer(
        llvm::ConstantStruct::get(SectsGlobalTy, SectsGlobalFieldInits));

    ConstSectsGlobal->setConstant(true);
  };

  auto create_global_variable = [&](const uint64_t Addr,
                                    const unsigned Size,
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
    const unsigned Off = Addr - Sect.Addr;

    if (is_integral_size(Size)) {
      if (Size == WordBytes()) {
        auto T_it = Sect.Stuff.Types.find(Off);
        auto C_it = Sect.Stuff.Constants.find(Off);

        if (T_it != Sect.Stuff.Types.end()) {
          assert(C_it != Sect.Stuff.Constants.end());

          llvm::Constant *Initializer = (*C_it).second;

          if (!Initializer)
            return nullptr;

          return new llvm::GlobalVariable(
              *Module, Initializer->getType(), false,
              llvm::GlobalValue::ExternalLinkage, Initializer, SymName, nullptr,
              tlsMode);
        }
      }

      bool HasRel = false;
      for (unsigned byte = 0; byte < Size; ++byte)
        HasRel |= (Sect.Stuff.Types.find(Off + byte) != Sect.Stuff.Types.end());

      if (!HasRel) {
        llvm::IntegerType *IntTy = llvm::Type::getIntNTy(*Context, Size * 8);

        llvm::Constant *Initializer;
        if (Sect.Contents.empty()) {
          Initializer = llvm::Constant::getNullValue(IntTy);
        } else {
          assert(Sect.Contents.size() >= Size);
          assert(Off + (Size - 1) < Sect.Contents.size());

          llvm::APInt X(Size * 8, 0u, false);

          {
            const uint8_t *const bytes = Sect.Contents.begin() + Off;

            /* FIXME this algorithm sucks. can't we do better than this? */

#define __APINT_BYTE(n, byte, data)                                            \
  do {                                                                         \
    std::bitset<8> bits(static_cast<unsigned long>(bytes[byte]));              \
    for (unsigned i = 0; i < 8; ++i)                                           \
      if (bits.test(i))                                                        \
        X.setBit((byte * 8) + i);                                              \
  } while (0);

#define __APINT_FROM_BYTES(n) BOOST_PP_REPEAT(n, __APINT_BYTE, void)

            switch (Size) {
            case 1: __APINT_FROM_BYTES(1); break;
            case 2: __APINT_FROM_BYTES(2); break;
            case 4: __APINT_FROM_BYTES(4); break;
            case 8: __APINT_FROM_BYTES(8); break;

            default:
              abort();
            }

#undef __APINT_FROM_BYTES
#undef __APINT_BYTE
          }

          Initializer = llvm::ConstantInt::get(IntTy, X);
        }

        return new llvm::GlobalVariable(*Module, Initializer->getType(), false,
                                        llvm::GlobalValue::ExternalLinkage,
                                        Initializer, SymName, nullptr, tlsMode);
      }
    }

    std::vector<llvm::Type *> GVFieldTys;
    std::vector<llvm::Constant *> GVFieldInits;

    int Left = Size;

    for (const auto &_intvl : Sect.Stuff.Intervals) {
      uint64_t lower = _intvl.lower();
      uint64_t upper = _intvl.upper();

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
        assert(typeit != Sect.Stuff.Types.end());
        assert(constit != Sect.Stuff.Constants.end());

        T = (*typeit).second;
        C = (*constit).second;

        assert(T->isIntegerTy(WordBits()) || T->isPointerTy());
        Left -= WordBytes();
      }

      // C might be NULL if the global variable needs to be initialized with the
      // address of itself
      if (!T) {
        if (IsVerbose())
          llvm::errs() << llvm::formatv(
              "!create_global_variable for {0} @ {1:x}\n", SymName,
              Sect.Addr + lower);
        return nullptr;
      }

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

      llvm::Type *Ty = GV->getValueType();
      assert(Ty->isStructTy());

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
          boost::icl::interval<uint64_t>::right_open(0, Sect.Size));
    }
  };

  B::_elf(*Bin, [&](ELFO &O) {

  const ELFF &Elf = O.getELFFile();

  //
  // print relocations
  //
  for_each_dynamic_relocation(Elf,
      state.for_binary(Binary)._elf.DynRelRegion,
      state.for_binary(Binary)._elf.DynRelaRegion,
      state.for_binary(Binary)._elf.DynRelrRegion,
      state.for_binary(Binary)._elf.DynPLTRelRegion,
      [&](const elf::Relocation &R) {
        //
        // determine symbol (if present)
        //
        elf::RelSymbol RelSym(nullptr, "");
        if (state.for_binary(Binary)._elf.OptionalDynSymRegion) {
          const elf::DynRegionInfo &DynSymRegion = *state.for_binary(Binary)._elf.OptionalDynSymRegion;

          RelSym = elf::getSymbolForReloc(O, DynSymRegion.getAsArrayRef<Elf_Sym>(),
                                          state.for_binary(Binary)._elf.DynamicStringTable, R);

          //
          // determine symbol version (if present)
          //
          if (RelSym.Sym && state.for_binary(Binary)._elf.SymbolVersionSection) {
            // Determine the position in the symbol table of this entry.
            size_t EntryIndex =
                (reinterpret_cast<uintptr_t>(RelSym.Sym) -
                 reinterpret_cast<uintptr_t>(DynSymRegion.Addr)) / sizeof(Elf_Sym);

            // Get the corresponding version index entry.
            llvm::Expected<const Elf_Versym *> ExpectedVersym =
                Elf.getEntry<Elf_Versym>(
                    *state.for_binary(Binary)._elf.SymbolVersionSection,
                    EntryIndex);

            if (ExpectedVersym) {
              RelSym.Vers = getSymbolVersionByIndex(
                  state.for_binary(Binary)._elf.VersionMap,
                  state.for_binary(Binary)._elf.DynamicStringTable,
                  (*ExpectedVersym)->vs_index, RelSym.IsVersionDefault);
            }
          }
        }

        llvm::outs() <<
          (fmt("%-18s @ %-8x") % Elf.getRelocationTypeName(R.Type).str()
                               % R.Offset).str();

        if (R.Addend)
          llvm::outs() << (fmt(" +%-8u") % *R.Addend).str();

        if (const Elf_Sym *Sym = RelSym.Sym) {
          llvm::outs() <<
            (fmt(" %-30s %-15s [%s] @ %x {%d}")
             % RelSym.Name
             % RelSym.Vers
             % llvm::object::ElfSymbolTypes[Sym->getType()].AltName.str()
             % Sym->st_value
             % Sym->st_size).str();
        }
        llvm::outs() << '\n';
      });

#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
  //
  // print arch-specific relocations
  //
  if (state.for_binary(Binary)._elf.OptionalDynSymRegion) {
    const elf::DynRegionInfo &DynSymRegion = *state.for_binary(Binary)._elf.OptionalDynSymRegion;

    auto dynamic_table = [&](void) -> Elf_Dyn_Range {
      return state.for_binary(Binary)._elf.DynamicTable.getAsArrayRef<Elf_Dyn>();
    };
    auto dynamic_symbols = [&](void) -> Elf_Sym_Range {
      return DynSymRegion.getAsArrayRef<Elf_Sym>();
    };

    elf::MipsGOTParser Parser(Elf, Binary.path_str());
    if (llvm::Error Err = Parser.findGOT(dynamic_table(),
                                         dynamic_symbols())) {
      WithColor::warning() << llvm::formatv("Failed to find GOT: {0}\n", Err);
      return;
    }

    for (const elf::MipsGOTParser::Entry &Ent : Parser.getLocalEntries()) {
      const uint64_t Addr = Parser.getGotAddress(&Ent);

      llvm::outs() << (fmt("%-18s @ %-8x\n") % "R_MIPS_32" % Addr).str();
    }

    for (const elf::MipsGOTParser::Entry &Ent : Parser.getGlobalEntries()) {
      const uint64_t Offset = Parser.getGotAddress(&Ent);

      const Elf_Sym *Sym = Parser.getGotSym(&Ent);
      assert(Sym);

      auto ExpectedSymName = Sym->getName(state.for_binary(Binary)._elf.DynamicStringTable);
      if (!ExpectedSymName) {
        WithColor::error() << llvm::formatv(
            "Failed to get symbol name for gotrel @ {0:x}: {1}\n", Offset,
            llvm::toString(ExpectedSymName.takeError()));
        continue;
      }

      llvm::StringRef SymName = *ExpectedSymName;
      llvm::StringRef SymVers = "";
      bool IsVersionDefault;

      //
      // determine symbol version (if present)
      //
      if (state.for_binary(Binary)._elf.SymbolVersionSection) {
        // Determine the position in the symbol table of this entry.
        size_t EntryIndex =
            (reinterpret_cast<uintptr_t>(Sym) -
             reinterpret_cast<uintptr_t>(DynSymRegion.Addr)) / sizeof(Elf_Sym);

        // Get the corresponding version index entry.
        llvm::Expected<const Elf_Versym *> ExpectedVersym =
            Elf.getEntry<Elf_Versym>(
                *state.for_binary(Binary)._elf.SymbolVersionSection,
                EntryIndex);

        if (ExpectedVersym)
          SymVers = getSymbolVersionByIndex(state.for_binary(Binary)._elf.VersionMap,
                                            state.for_binary(Binary)._elf.DynamicStringTable,
                                            (*ExpectedVersym)->vs_index,
                                            IsVersionDefault);
      }

      const char *RelocationTypeName = nullptr;
      if (Sym->st_shndx == llvm::ELF::SHN_UNDEF) {
        if (Sym->getType() == llvm::ELF::STT_FUNC && Sym->st_value)
          RelocationTypeName = "R_MIPS_JUMP_SLOT";
        else
          RelocationTypeName = "R_MIPS_32";
      } else if (Sym->st_shndx == llvm::ELF::SHN_COMMON) {
        RelocationTypeName = "R_MIPS_32";
      } else if (Sym->getType() == llvm::ELF::STT_FUNC &&
                 ExtractWordAtAddress(Offset) != Sym->st_value) {
        RelocationTypeName = "R_MIPS_JUMP_SLOT";
      } else if (Sym->getType() == llvm::ELF::STT_SECTION) {
        if (Sym->st_other == 0)
          RelocationTypeName = "R_MIPS_32";
        else
          RelocationTypeName = "?";
      } else {
        RelocationTypeName = "R_MIPS_32";
      }
      assert(RelocationTypeName);

      llvm::outs() <<
        (fmt("%-18s @ %-8x %-30s %-15s [%s] @ %x {%d}\n")
         % RelocationTypeName
         % Offset
         % SymName.str()
         % SymVers.str()
         % llvm::object::ElfSymbolTypes[Sym->getType()].AltName.str()
         % Sym->st_value
         % Sym->st_size).str();
    }
  }
#endif

  });

  B::_coff(*Bin, [&](COFFO &O) {

  auto printImportedSymbols =
      [&](llvm::StringRef DLL, uint32_t RVA,
          llvm::iterator_range<llvm::object::imported_symbol_iterator> Range,
          bool IAT) -> void {
    unsigned i = 0;
    for (auto it = Range.begin(); it != Range.end(); ++it, ++i) {
      const llvm::object::ImportedSymbolRef &I = *it;

      llvm::StringRef SymName;
      if (llvm::errorToBool(I.getSymbolName(SymName)))
        ;
      uint16_t Ordinal = UINT16_MAX;
      if (llvm::errorToBool(I.getOrdinal(Ordinal)))
        ;

      llvm::outs() <<
        (fmt("[%s] %-15s (%u) @ %x <%s>\n")
         % (IAT ? "IAT" : "ILT")
         % SymName.str()
         % Ordinal
         % (coff::va_of_rva(O, RVA + i*WordBytes()))
         % DLL.str()).str();
    }
  };

  // Regular imports
  for (const llvm::object::ImportDirectoryEntryRef &I : O.import_directories()) {
    llvm::StringRef DLL;
    if (llvm::errorToBool(I.getName(DLL)))
      continue;

    uint32_t ILTAddr;
    uint32_t IATAddr;

    // The import lookup table can be missing with certain older linkers
    if (!llvm::errorToBool(I.getImportLookupTableRVA(ILTAddr)) && ILTAddr)
      printImportedSymbols(DLL, ILTAddr, I.lookup_table_symbols(), false);

    if (!llvm::errorToBool(I.getImportAddressTableRVA(IATAddr)) && IATAddr)
      printImportedSymbols(DLL, IATAddr, I.imported_symbols(), true);
  }

  });

  ConstSectsGlobal = nullptr;
  SectsGlobal = nullptr;

  // iterative algorithm to create the sections
  bool done;
  do {
    done = true;

    clear_section_stuff();


    B::_elf(*Bin, [&](ELFO &O) {

    const ELFF &Elf = O.getELFFile();

    for_each_dynamic_relocation(Elf,
        state.for_binary(Binary)._elf.DynRelRegion,
        state.for_binary(Binary)._elf.DynRelaRegion,
        state.for_binary(Binary)._elf.DynRelrRegion,
        state.for_binary(Binary)._elf.DynPLTRelRegion,
        [&](const elf::Relocation &R) {
          llvm::Type *R_T = nullptr;

          try {
            R_T = elf_type_of_expression_for_relocation(R);
          } catch (const unhandled_relocation_exception &) {
            WithColor::error() << llvm::formatv(
                "elf_type_of_expression_for_relocation: unhandled relocation {0} ({1:x})\n",
                Elf.getRelocationTypeName(R.Type), R.Type);
            abort();
          }

          assert(R_T);

          if (R_T->isVoidTy())
            return;

          type_at_address(R.Offset, R_T);

          if (elf_is_constant_relocation(R))
            ConstantRelocationLocs.insert(R.Offset);
        });

#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
    //
    // arch-specific relocations
    //
    if (state.for_binary(Binary)._elf.OptionalDynSymRegion) {
      const elf::DynRegionInfo &DynSymRegion = *state.for_binary(Binary)._elf.OptionalDynSymRegion;

      auto dynamic_table = [&](void) -> Elf_Dyn_Range {
        return state.for_binary(Binary)._elf.DynamicTable.getAsArrayRef<Elf_Dyn>();
      };
      auto dynamic_symbols = [&](void) -> Elf_Sym_Range {
        return DynSymRegion.getAsArrayRef<Elf_Sym>();
      };

      elf::MipsGOTParser Parser(Elf, Binary.path_str());
      if (llvm::Error Err = Parser.findGOT(dynamic_table(),
                                           dynamic_symbols())) {
        WithColor::warning() << llvm::formatv("Failed to find GOT: {0}\n", Err);
        return;
      }

      for (const elf::MipsGOTParser::Entry &Ent : Parser.getLocalEntries())
        type_at_address(Parser.getGotAddress(&Ent), WordType());

      for (const elf::MipsGOTParser::Entry &Ent : Parser.getGlobalEntries())
        type_at_address(Parser.getGotAddress(&Ent), WordType());

      for (const elf::MipsGOTParser::Entry &Ent : Parser.getLocalEntries())
        ConstantRelocationLocs.insert(Parser.getGotAddress(&Ent));

      for (const elf::MipsGOTParser::Entry &Ent : Parser.getGlobalEntries())
        ConstantRelocationLocs.insert(Parser.getGotAddress(&Ent));
    }
#endif

    });

    B::_coff(*Bin, [&](COFFO &O) {
      coff::for_each_base_relocation(
          O, [&](uint8_t RelocType, uint64_t RVA) {
            uint64_t Offset = coff::va_of_rva(O, RVA);

            llvm::Type *R_T = nullptr;

            try {
              R_T = coff_type_of_expression_for_relocation(RelocType);
            } catch (const unhandled_relocation_exception &) {
              WithColor::error() << llvm::formatv(
                  "coff_type_of_expression_for_relocation: unhandled relocation {0:x}\n",
                  RelocType);
              abort();
            }

            assert(R_T);

            if (R_T->isVoidTy())
              return;

            type_at_address(Offset, R_T);

            if (coff_is_constant_relocation(RelocType))
              ConstantRelocationLocs.insert(Offset);
          });

      coff::for_each_imported_function(
          O, [&](llvm::StringRef DLL,
                 uint32_t Ordinal,
                 llvm::StringRef Name,
                 uint64_t RVA) {
            type_at_address(coff::va_of_rva(O, RVA), WordType());
          });
    });

    declare_sections();

    B::_elf(*Bin, [&](ELFO &O) {

    const ELFF &Elf = O.getELFFile();

    for_each_dynamic_relocation(Elf,
        state.for_binary(Binary)._elf.DynRelRegion,
        state.for_binary(Binary)._elf.DynRelaRegion,
        state.for_binary(Binary)._elf.DynRelrRegion,
        state.for_binary(Binary)._elf.DynPLTRelRegion,
        [&](const elf::Relocation &R) {
          llvm::Type *R_T = elf_type_of_expression_for_relocation(R);
          assert(R_T);

          if (R_T->isVoidTy())
            return;

          //
          // determine symbol (if present)
          //
          elf::RelSymbol RelSym(nullptr, "");
          if (state.for_binary(Binary)._elf.OptionalDynSymRegion) {
            const elf::DynRegionInfo &DynSymRegion = *state.for_binary(Binary)._elf.OptionalDynSymRegion;

            auto dynamic_symbols = [&](void) -> Elf_Sym_Range {
              return DynSymRegion.getAsArrayRef<Elf_Sym>();
            };

            RelSym = elf::getSymbolForReloc(O, dynamic_symbols(),
                                            state.for_binary(Binary)._elf.DynamicStringTable, R);

            //
            // determine symbol version (if present)
            //
            if (RelSym.Sym && state.for_binary(Binary)._elf.SymbolVersionSection) {
              // Determine the position in the symbol table of this entry.
              size_t EntryIndex =
                  (reinterpret_cast<uintptr_t>(RelSym.Sym) -
                   reinterpret_cast<uintptr_t>(DynSymRegion.Addr)) /
                  sizeof(Elf_Sym);

              // Get the corresponding version index entry.
              llvm::Expected<const Elf_Versym *> ExpectedVersym =
                  Elf.getEntry<Elf_Versym>(
                      *state.for_binary(Binary)._elf.SymbolVersionSection,
                      EntryIndex);

              if (ExpectedVersym)
                RelSym.Vers = getSymbolVersionByIndex(state.for_binary(Binary)._elf.VersionMap,
                                                      state.for_binary(Binary)._elf.DynamicStringTable,
                                                      (*ExpectedVersym)->vs_index,
                                                      RelSym.IsVersionDefault);
            }
          }

          llvm::Constant *R_C = nullptr;
          try {
            R_C = elf_expression_for_relocation(R, RelSym);
          } catch (const unhandled_relocation_exception &) {
            WithColor::error() << llvm::formatv(
                "elf_expression_for_relocation: unhandled relocation {0}\n",
                Elf.getRelocationTypeName(R.Type));
            abort();
          }

          if (!R_C)
            done = false;

          constant_at_address(R.Offset, R_C); /* n.b. R_C may be NULL */
        });

#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
    //
    // arch-specific relocations
    //
    if (state.for_binary(Binary)._elf.OptionalDynSymRegion) {
      const elf::DynRegionInfo &DynSymRegion = *state.for_binary(Binary)._elf.OptionalDynSymRegion;

      auto dynamic_table = [&](void) -> Elf_Dyn_Range {
        return state.for_binary(Binary)._elf.DynamicTable.getAsArrayRef<Elf_Dyn>();
      };
      auto dynamic_symbols = [&](void) -> Elf_Sym_Range {
        return DynSymRegion.getAsArrayRef<Elf_Sym>();
      };

      elf::MipsGOTParser Parser(Elf, Binary.path_str());
      if (llvm::Error Err = Parser.findGOT(dynamic_table(),
                                           dynamic_symbols())) {
        WithColor::warning() << llvm::formatv("Failed to find GOT: {0}\n", Err);
        return;
      }

      for (const elf::MipsGOTParser::Entry &Ent : Parser.getLocalEntries()) {
        const uint64_t Offset = Parser.getGotAddress(&Ent);

        llvm::Constant *R_C = SectionPointer(ExtractWordAtAddress(Offset));
        assert(R_C);

        constant_at_address(Offset, R_C);
      }

      for (const elf::MipsGOTParser::Entry &Ent : Parser.getGlobalEntries()) {
        const uint64_t Offset = Parser.getGotAddress(&Ent);

        const Elf_Sym *Sym = Parser.getGotSym(&Ent);
        assert(Sym);

        auto ExpectedSymName = Sym->getName(state.for_binary(Binary)._elf.DynamicStringTable);
        if (!ExpectedSymName) {
          WithColor::error() << llvm::formatv(
              "failed to get symbol name for gotrel @ {0:x}: {1}\n", Offset,
              llvm::toString(ExpectedSymName.takeError()));
          continue;
        }

        llvm::StringRef SymName = *ExpectedSymName;
        llvm::StringRef SymVers = "";
        bool IsVersionDefault = false;

        //
        // determine symbol version (if present)
        //
        if (state.for_binary(Binary)._elf.SymbolVersionSection) {
          // Determine the position in the symbol table of this entry.
          size_t EntryIndex =
              (reinterpret_cast<uintptr_t>(Sym) -
               reinterpret_cast<uintptr_t>(DynSymRegion.Addr)) / sizeof(Elf_Sym);

          // Get the corresponding version index entry.
          llvm::Expected<const Elf_Versym *> ExpectedVersym =
              Elf.getEntry<Elf_Versym>(
                  *state.for_binary(Binary)._elf.SymbolVersionSection,
                  EntryIndex);

          if (ExpectedVersym)
            SymVers = getSymbolVersionByIndex(state.for_binary(Binary)._elf.VersionMap,
                                              state.for_binary(Binary)._elf.DynamicStringTable,
                                              (*ExpectedVersym)->vs_index,
                                              IsVersionDefault);
        }

        elf::RelSymbol RelSym(Sym, "");
        RelSym.Name = SymName.str();
        RelSym.Vers = SymVers.str();
        RelSym.IsVersionDefault = IsVersionDefault;

        llvm::Constant *R_C = SymbolAddress(RelSym);

        constant_at_address(Offset, R_C); /* n.b. R_C may be NULL */
      }
    }
#endif

    });

    B::_coff(*Bin, [&](COFFO &O) {
      coff::for_each_base_relocation(
          O, [&](uint8_t RelocType, uint64_t RVA) {
            uint64_t Offset = coff::va_of_rva(O, RVA);

            llvm::Constant *R_C = nullptr;
            try {
              R_C = coff_expression_for_relocation(RelocType, Offset);
            } catch (const unhandled_relocation_exception &) {
              WithColor::error() << llvm::formatv(
                  "coff_expression_for_relocation: unhandled relocation {0:x}\n",
                  RelocType);
              abort();
            }

            if (!R_C)
              done = false;

            constant_at_address(Offset, R_C); /* n.b. R_C may be NULL */
          });

      coff::for_each_imported_function(
          O, [&](llvm::StringRef DLL,
                 uint32_t Ordinal,
                 llvm::StringRef Name,
                 uint64_t RVA) {
            uint64_t Offset = coff::va_of_rva(O, RVA);

            llvm::Constant *R_C =
                ImportedFunctionAddress(DLL, Ordinal, Name, Offset);

            if (!R_C)
              done = false;

            constant_at_address(Offset, R_C);
          });
    });

    define_sections();

    //
    // global variables
    //
    for (const auto &pair : AddrToSymbolMap) {
      const std::set<std::string> &Syms = pair.second;

      assert(!Syms.empty());
      const std::string &SymName = *Syms.begin();

      llvm::errs() << llvm::formatv("iterating AddrToSymbolMap ({0})\n", SymName);

      if (llvm::GlobalVariable *GV = Module->getGlobalVariable(SymName, true)) {
        if (GV->hasInitializer())
          continue;
      }

      uint64_t Addr = pair.first;

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
      if (GV)
	GV->setAlignment(llvm::Align(2 * WordBytes()));

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

  if (TLSSectsGlobal) {
    TLSSectsGlobal->setAlignment(llvm::Align(2 * WordBytes()));
    TLSSectsGlobal->setLinkage(llvm::GlobalValue::InternalLinkage);
  }

  if (opts.LayOutSections) {
    std::string CurrSectName = IsCOFF ? ".jove_pr" : ".jove";

    unsigned j = 0;
    for (unsigned i = 0; i < NumSections; ++i) {
      section_t &Sect = SectTable[i];

      //
      // check if there's space between the start of this section and the
      // previous
      //
      if (i > 0) {
        section_t &PrevSect = SectTable[i - 1];
        ptrdiff_t space = Sect.Addr - (PrevSect.Addr + PrevSect.Size);
        if (space > 0) { // zero padding between sections
          auto *T = llvm::ArrayType::get(llvm::Type::getInt8Ty(*Context), space);
          auto *C = llvm::Constant::getNullValue(
                  llvm::ArrayType::get(llvm::Type::getInt8Ty(*Context), space));

          auto *GV = new llvm::GlobalVariable(
              *Module, T, false, llvm::GlobalValue::InternalLinkage, C,
              "__jove_space_" + std::to_string(j));
          ++j;

          GV->setAlignment(llvm::Align(1));
          GV->setSection(CurrSectName); /* no .bss */

          LaidOut.GVVec.emplace_back(GV, space);
        }
      }

      if (IsVerbose())
        llvm::errs() << llvm::formatv("Laying out section {0}\n", Sect.Name);

      if (IsCOFF && _coff.rsrcSectIdx >= 0) {
        if (i < _coff.rsrcSectIdx)
          CurrSectName = ".jove_pr";
        else if (i > _coff.rsrcSectIdx)
          CurrSectName = ".jove_po";
        else
          CurrSectName = ".rsrc";
      }

      auto *T = SectTable[i].T;
      auto *C = SectTable[i].C;

      assert(T);
      assert(C);

      std::string suffix = Sect.Name;
      std::replace_if(
          suffix.begin(), suffix.end(),
          [](char c) { return !std::isalnum(static_cast<unsigned char>(c)); }, '_');

      auto *GV = new llvm::GlobalVariable(*Module, T, false,
                                          llvm::GlobalValue::InternalLinkage,
                                          C, "__jove_section_" + suffix);
      ++j;

      if (!LaidOut.HeadGV) {
        GV->setAlignment(llvm::Align(WordBytes()));
        LaidOut.HeadGV = GV;
      } else {
        GV->setAlignment(llvm::Align(1));
      }

      GV->setSection(CurrSectName);

      LaidOut.GVVec.emplace_back(GV, Sect.Size);
    }

    SectsGlobal->replaceAllUsesWith(llvm::ConstantExpr::getPointerCast(
        LaidOut.HeadGV, SectsGlobal->getType()));

    ConstSectsGlobal->replaceAllUsesWith(llvm::ConstantExpr::getPointerCast(
        LaidOut.HeadGV, ConstSectsGlobal->getType()));

    assert(SectsGlobal->use_empty());
    assert(ConstSectsGlobal->use_empty());

    SectsGlobal->eraseFromParent();
    ConstSectsGlobal->eraseFromParent();

    SectsGlobal = nullptr;
    ConstSectsGlobal = nullptr;
  }

  //
  // Binary DT_INIT
  //
  // XXX this should go somewhere else
  {
    auto &binary = jv.Binaries.at(BinaryIndex);

    //
    // parse dynamic table
    //
    uint64_t initFunctionAddr = 0;

    if (state.for_binary(binary)._elf.DynamicTable.Addr) {
      auto dynamic_table = [&](void) -> Elf_Dyn_Range {
        return state.for_binary(binary)._elf.DynamicTable.getAsArrayRef<Elf_Dyn>();
      };

      for (const Elf_Dyn &Dyn : dynamic_table()) {
        if (unlikely(Dyn.d_tag == llvm::ELF::DT_NULL))
          break; /* marks end of dynamic table. */

        switch (Dyn.d_tag) {
        case llvm::ELF::DT_INIT:
          initFunctionAddr = Dyn.getVal();
          break;
        }
      };
    }

    if (auto *F = Module->getFunction("_jove_get_init_fn"))
      fillInFunctionBody(F,
          [&](auto &IRB) {
            llvm::Value *Ret = nullptr;
            if (initFunctionAddr) {
              function_t &initfn_f = function_at_address(Binary, initFunctionAddr);

              Ret = llvm::ConstantExpr::getPtrToInt(state.for_function(initfn_f).F, WordType());
            } else {
              Ret = llvm::Constant::getNullValue(WordType());
            }
            IRB.CreateRet(Ret);
          },
          false);

    if (auto *F = Module->getFunction("_jove_get_init_fn_sect_ptr"))
      fillInFunctionBody(F,
          [&](auto &IRB) {
            IRB.CreateRet(initFunctionAddr
                              ? SectionPointer(initFunctionAddr)
                              : llvm::Constant::getNullValue(WordType()));
          },
          false);
  }

  if (auto *F = Module->getFunction("_jove_get_libc_early_init_fn")) {
    fillInFunctionBody(F,
        [&](auto &IRB) {
          llvm::Value *Ret = nullptr;
          if (libcEarlyInitAddr) {
            function_t &f = function_at_address(Binary, libcEarlyInitAddr);

            Ret = llvm::ConstantExpr::getPtrToInt(state.for_function(f).F, WordType());
          } else {
            Ret = llvm::Constant::getNullValue(WordType());
          }
          IRB.CreateRet(Ret);
        },
        false);
  }

  if (auto *F = Module->getFunction("_jove_get_libc_early_init_fn_sect_ptr")) {
    fillInFunctionBody(F,
        [&](auto &IRB) {
          IRB.CreateRet(libcEarlyInitAddr
                            ? SectionPointer(libcEarlyInitAddr)
                            : llvm::Constant::getNullValue(WordType()));
        },
        false);
  }

  //
  // Global Ctors/Dtors
  //
  // XXX this should go somewhere else
  for (section_t &Sect : SectTable) {
    if (!Sect._elf.initArray && !Sect._elf.finiArray)
      continue;

    assert(!(Sect._elf.initArray && Sect._elf.finiArray));

    for (const auto &pair : Sect.Stuff.Constants) {
      llvm::Constant *C = pair.second;
      llvm::Function *F = nullptr;

      llvm::ConstantInt *matched_Addend = nullptr;
      if (llvm::PatternMatch::match(
              C, llvm::PatternMatch::m_Add(
                     llvm::PatternMatch::m_PtrToInt(
                         llvm::PatternMatch::m_Specific(SectionsTop())),
                     llvm::PatternMatch::m_ConstantInt(matched_Addend)))) {
        assert(matched_Addend);
        uintptr_t off = matched_Addend->getValue().getZExtValue();
        uintptr_t FileAddr = off + SectsStartAddr;

        binary_t &Binary = jv.Binaries.at(BinaryIndex);
        function_t &f = function_at_address(Binary, FileAddr);

        if (!f.IsABI) {
          WithColor::error() << llvm::formatv(
              "!IsABI for {0}; did you run jove-bootstrap -s?\n",
              state.for_function(f).F->getName());
          abort();
        }

        // FIXME casting to a llvm::Function* is a complete hack here. it's only
        // ever used as a llvm::Constant* in llvm/lib/Transforms/Utils/ModuleUtils.cpp
        if (Sect._elf.initArray)
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

  if (SectsGlobal &&
      jv.Binaries.at(BinaryIndex).IsExecutable &&
      !jv.Binaries.at(BinaryIndex).IsPIC)
    SectsGlobal->setSection(".jove"); /* we will refer to this later with ld,
                                       * placing the section at the executable's
                                       * original base address in memory */

  return 0;
}

int LLVMTool::CreatePossibleTramps(void) {
  if (IsVerbose())
    llvm::errs() << llvm::formatv("# of possible tramps: {0}\n",
                                  possible_tramps_vec.size());

  fillInFunctionBody(
      Module->getFunction("_jove_possible_tramps"),
      [&](auto &IRB) {
        if (possible_tramps_vec.empty()) {
          IRB.CreateRet(llvm::Constant::getNullValue(WordType()));
          return;
        }

        std::vector<llvm::Constant *> constantTable;
        constantTable.reserve(possible_tramps_vec.size());
        for (uint64_t poss : possible_tramps_vec)
          constantTable.push_back(SectionPointer(poss));

        auto *T = llvm::ArrayType::get(WordType(), constantTable.size());
        auto *C = llvm::ConstantArray::get(T, constantTable);

        auto *GV = new llvm::GlobalVariable(
            *Module, T, true, llvm::GlobalValue::InternalLinkage, C,
            (fmt("__jove_poss_tramps%u") % BinaryIndex).str());

        IRB.CreateRet(
            IRB.CreateConstInBoundsGEP2_64(GV->getValueType(), GV, 0, 0));
      },
      !opts.ForCBE);

  fillInFunctionBody(
      Module->getFunction("_jove_possible_tramps_count"),
      [&](auto &IRB) {
        IRB.CreateRet(IRB.getInt32(possible_tramps_vec.size()));
      },
      !opts.ForCBE);

  return 0;
}

std::pair<binary_index_t, std::pair<uint64_t, unsigned>>
LLVMTool::decipher_copy_relocation(const elf::RelSymbol &S) {
  assert(jv.Binaries.at(BinaryIndex).IsExecutable);

  for (binary_index_t BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx) {
    if (BIdx == BinaryIndex)
      continue;

    auto &b = jv.Binaries.at(BIdx);
    if (b.IsVDSO)
      continue;
    if (b.IsDynamicLinker)
      continue;

    if (!state.for_binary(b).Bin)
      continue;

    assert(llvm::isa<ELFO>(state.for_binary(b).Bin.get()));
    const ELFF &Elf =
        llvm::cast<ELFO>(state.for_binary(b).Bin.get())->getELFFile();

    if (!state.for_binary(b)._elf.OptionalDynSymRegion)
      continue; /* no dynamic symbols */

    auto DynSyms = state.for_binary(b)._elf.OptionalDynSymRegion->getAsArrayRef<Elf_Sym>();

    for (unsigned SymNo = 0; SymNo < DynSyms.size(); ++SymNo) {
      const Elf_Sym &Sym = DynSyms[SymNo];

      if (Sym.isUndefined())
        continue;

      if (Sym.getType() != llvm::ELF::STT_OBJECT)
        continue;

      llvm::Expected<llvm::StringRef> ExpectedSymName =
          Sym.getName(state.for_binary(b)._elf.DynamicStringTable);
      if (!ExpectedSymName)
        continue;

      llvm::StringRef SymName = *ExpectedSymName;
      llvm::StringRef SymVers;
      bool VisibilityIsDefault;

      //
      // symbol versioning
      //
      if (state.for_binary(b)._elf.SymbolVersionSection) {
        const Elf_Versym *Versym = unwrapOrError(Elf.getEntry<Elf_Versym>(
            *state.for_binary(b)._elf.SymbolVersionSection, SymNo));

        SymVers = getSymbolVersionByIndex(state.for_binary(b)._elf.VersionMap,
                                          state.for_binary(b)._elf.DynamicStringTable,
                                          Versym->vs_index,
                                          VisibilityIsDefault);
      }

      if ((SymName == S.Name &&
           SymVers == S.Vers)) {
        //
        // we have a match.
        //
        assert(Sym.st_value > state.for_binary(b).SectsStartAddr);

        return {BIdx, {Sym.st_value, Sym.st_value - state.for_binary(b).SectsStartAddr}};
      }
    }
  }

  WithColor::warning() << llvm::formatv(
      "failed to decipher copy relocation {0} {1}\n", S.Name, S.Vers);

  return {invalid_binary_index, {0, 0}};
}

int LLVMTool::ProcessManualRelocations(void) {
  binary_t &Binary = jv.Binaries.at(BinaryIndex);

  std::map<uint64_t, llvm::Function *> ManualRelocs;

  B::_elf(*state.for_binary(Binary).Bin, [&](ELFO &O) {
  const ELFF &Elf = O.getELFFile();

  auto OptionalDynSymRegion = state.for_binary(Binary)._elf.OptionalDynSymRegion;

  if (!OptionalDynSymRegion)
    return; /* no dynamic symbols */

  const elf::DynRegionInfo &DynSymRegion = *OptionalDynSymRegion;

  auto dynamic_symbols = [&](void) -> Elf_Sym_Range {
    return DynSymRegion.getAsArrayRef<Elf_Sym>();
  };

  for_each_dynamic_relocation_if(Elf,
      state.for_binary(Binary)._elf.DynRelRegion,
      state.for_binary(Binary)._elf.DynRelaRegion,
      state.for_binary(Binary)._elf.DynRelrRegion,
      state.for_binary(Binary)._elf.DynPLTRelRegion,
      [&](const elf::Relocation &R) -> bool { return elf_is_manual_relocation(R); },
      [&](const elf::Relocation &R) {
        llvm::Type *R_T = elf_type_of_expression_for_relocation(R);

        elf::RelSymbol RelSym = elf::getSymbolForReloc(O, dynamic_symbols(),
                                                       state.for_binary(Binary)._elf.DynamicStringTable, R);

        llvm::Function *F = llvm::Function::Create(
            llvm::FunctionType::get(R_T, false),
            llvm::GlobalValue::InternalLinkage,
            std::string("_jove_compute_relocation_") + (fmt("%lx") % R.Offset).str(),
            Module.get());

        fillInFunctionBody(F, [&](auto &IRB) {
          try {
            elf_compute_manual_relocation(IRB, R, RelSym);
          } catch (const unhandled_relocation_exception &) {
            WithColor::error()
                << llvm::formatv("{0}: unhandled relocation {1}", __func__,
                                 Elf.getRelocationTypeName(R.Type));
            abort();
          }
        }, true);

        ManualRelocs.emplace(R.Offset, F);
      });
  });

  fillInFunctionBody(
      Module->getFunction("_jove_do_manual_relocations"),
      [&](auto &IRB) {
        std::for_each(
            ManualRelocs.begin(),
            ManualRelocs.end(), [&](const auto &pair) {
              llvm::Value *Computation = IRB.CreateCall(pair.second);

              uintptr_t off = pair.first - state.for_binary(Binary).SectsStartAddr;

              llvm::Value *Ptr = nullptr;
              if (!opts.LayOutSections) {
                llvm::SmallVector<llvm::Value *, 4> Indices;
                Ptr = llvm::getNaturalGEPWithOffset(
                    IRB, DL,
                    std::make_pair(SectsGlobal, SectsGlobal->getValueType()),
                    llvm::APInt(64, off), Computation->getType(), Indices, "");
              }

              if (!Ptr)
                Ptr = IRB.CreateIntToPtr(
                    IRB.CreateAdd(
                        IRB.CreatePtrToInt(SectionsTop(), WordType()),
                        IRB.getIntN(WordBits(), off)),
                    llvm::PointerType::get(Computation->getType(), 0));

              IRB.CreateStore(Computation, Ptr, true /* Volatile */);
            });

        IRB.CreateRetVoid();
      }, !opts.ForCBE);

  return 0;
}

int LLVMTool::CreateCopyRelocationHack(void) {
  fillInFunctionBody(
      Module->getFunction("_jove_do_emulate_copy_relocations"),
      [&](auto &IRB) -> void {
        binary_t &Binary = jv.Binaries.at(BinaryIndex);

        if (!Binary.IsExecutable) {
          assert(CopyRelocMap.empty());
        }

        for (const auto &pair : CopyRelocMap) {
          binary_index_t BIdxFrom = pair.second.first;
          auto &BinaryFrom = jv.Binaries.at(BIdxFrom);

          WARN_ON(pair.second.first < 3);

          if (state.for_binary(BinaryFrom).SectsF) {
            IRB.CreateMemCpyInline(
                IRB.CreateIntToPtr(SectionPointer(pair.first.first),
                                   IRB.getInt8PtrTy()),
                llvm::MaybeAlign(),
                IRB.CreateIntToPtr(
                    IRB.CreateAdd(
                        IRB.CreateCall(state.for_binary(BinaryFrom).SectsF),
                        IRB.getIntN(WordBits(), pair.second.second.second)),
                    IRB.getInt8PtrTy()),
                llvm::MaybeAlign(),
		IRB.getInt32(pair.first.second), true /* Volatile */);
          } else {
            assert(opts.ForeignLibs);

            auto &ICFG = BinaryFrom.Analysis.ICFG;

            assert(!BinaryFrom.Analysis.Functions.empty());

            //
            // get the load address
            //
            llvm::Value *FnsTbl = IRB.CreateLoad(
                IRB.getPtrTy(),
                IRB.CreateConstInBoundsGEP2_64(
                    JoveForeignFunctionTablesGlobal->getValueType(),
                    JoveForeignFunctionTablesGlobal, 0, BIdxFrom));

            llvm::Value *FirstEntry = IRB.CreateLoad(WordType(), FnsTbl);

            llvm::Value *LoadBias = IRB.CreateSub(
                FirstEntry,
                IRB.getIntN(
                    WordBits(),
                    ICFG[basic_block_of_index(BinaryFrom.Analysis.Functions.at(0).Entry,
                                       ICFG)]
                        .Addr));

            llvm::errs() << llvm::formatv("FnsTbl: {0} Type: {1}\n", *FnsTbl,
                                          *FnsTbl->getType());

            IRB.CreateMemCpyInline(
                IRB.CreateIntToPtr(SectionPointer(pair.first.first),
                                   IRB.getInt8PtrTy()),
                llvm::MaybeAlign(),
                IRB.CreateIntToPtr(
                    IRB.CreateAdd(
                        LoadBias,
                        IRB.getIntN(WordBits(), pair.second.second.first)),
                    IRB.getInt8PtrTy()),
                llvm::MaybeAlign(),
		IRB.getInt32(pair.first.second), true /* Volatile */);
          }

          if (IsVerbose())
            WithColor::note() << llvm::formatv(
                "COPY RELOC HACK {0} {1} {2} {3}\n", pair.first.first,
                pair.first.second, pair.second.second.first,
                pair.second.second.second);
        }

        IRB.CreateRetVoid();
      }, !opts.ForCBE);

  return 0;
}

int LLVMTool::FixupHelperStubs(void) {
  binary_t &Binary = jv.Binaries.at(BinaryIndex);

  fillInFunctionBody(
      Module->getFunction("_jove_sections_start_file_addr"),
      [&](auto &IRB) {
        IRB.CreateRet(llvm::ConstantInt::get(WordType(), state.for_binary(Binary).SectsStartAddr));
      }, !opts.ForCBE);

  fillInFunctionBody(
      Module->getFunction("_jove_sections_global_beg_addr"),
      [&](auto &IRB) {
        IRB.CreateRet(llvm::ConstantExpr::getPtrToInt(SectionsTop(), WordType()));
      }, !opts.ForCBE);

  fillInFunctionBody(
      Module->getFunction("_jove_sections_global_end_addr"),
      [&](auto &IRB) {
        // TODO call DL.getAllocSize and verify the numbers are the same
        uint64_t SectsGlobalSize = state.for_binary(Binary).SectsEndAddr - state.for_binary(Binary).SectsStartAddr;

        IRB.CreateRet(llvm::ConstantExpr::getAdd(
            llvm::ConstantExpr::getPtrToInt(SectionsTop(), WordType()),
            llvm::ConstantInt::get(WordType(), SectsGlobalSize)));
      }, !opts.ForCBE);

  fillInFunctionBody(
      Module->getFunction("_jove_binary_index"),
      [&](auto &IRB) {
        IRB.CreateRet(IRB.getInt32(BinaryIndex));
      }, !opts.ForCBE);

  fillInFunctionBody(
      Module->getFunction("_jove_dynl_path"),
      [&](auto &IRB) {
        std::string dynl_path;
        for (binary_t &binary : jv.Binaries) {
          if (binary.IsDynamicLinker) {
            dynl_path = binary.path_str();
            break;
          }
        }
        assert(!dynl_path.empty());

        IRB.CreateRet(IRB.CreateGlobalStringPtr(dynl_path));
      }, !opts.ForCBE);

  fillInFunctionBody(
      Module->getFunction("_jove_trace_enabled"),
      [&](auto &IRB) {
        IRB.CreateRet(IRB.getInt1(opts.Trace));
      }, !opts.ForCBE);

  fillInFunctionBody(
      Module->getFunction("_jove_dfsan_enabled"),
      [&](auto &IRB) {
        IRB.CreateRet(IRB.getInt1(opts.DFSan));
      }, !opts.ForCBE);

  if (Binary.IsExecutable)
    assert(is_function_index_valid(Binary.Analysis.EntryFunction));

  fillInFunctionBody(
      Module->getFunction("_jove_call_entry"),
      [&](auto &IRB) -> void {
        if (is_function_index_valid(Binary.Analysis.EntryFunction)) {
          function_t &f = Binary.Analysis.Functions.at(Binary.Analysis.EntryFunction);

          std::vector<llvm::Value *> ArgVec;
          {
            std::vector<unsigned> glbv;
            ExplodeFunctionArgs(f, glbv);

            ArgVec.resize(glbv.size());
            std::transform(
                glbv.begin(),
                glbv.end(), ArgVec.begin(),
                [&](unsigned glb) -> llvm::Value * {
                  return IRB.CreateLoad(
                      TypeOfTCGGlobal(glb),
                      BuildCPUStatePointer(IRB, CPUStateGlobal, glb));
                });
          }

          IRB.CreateCall(state.for_function(f).F, ArgVec)->setIsNoInline();
        }

        IRB.CreateCall(
            llvm::Intrinsic::getDeclaration(Module.get(), llvm::Intrinsic::trap));
        IRB.CreateUnreachable();
      }, !opts.ForCBE);

  fillInFunctionBody(
      Module->getFunction("_jove_get_dynl_function_table"),
      [&](auto &IRB) -> void {
        binary_t &dynl_binary = get_dynl(jv);
        assert(dynl_binary.IsDynamicLinker);
        auto &ICFG = dynl_binary.Analysis.ICFG;

        std::vector<llvm::Constant *> constantTable;
        constantTable.resize(dynl_binary.Analysis.Functions.size());

        std::transform(
            dynl_binary.Analysis.Functions.begin(),
            dynl_binary.Analysis.Functions.end(), constantTable.begin(),
            [&](const function_t &f) -> llvm::Constant * {
              uintptr_t Addr = ICFG[basic_block_of_index(f.Entry, ICFG)].Addr;
              return llvm::ConstantInt::get(WordType(), Addr);
            });

        constantTable.push_back(llvm::Constant::getNullValue(WordType()));

        llvm::ArrayType *T =
            llvm::ArrayType::get(WordType(), constantTable.size());

        llvm::Constant *Init = llvm::ConstantArray::get(T, constantTable);
        llvm::GlobalVariable *ConstantTableGV = new llvm::GlobalVariable(
            *Module, T, false, llvm::GlobalValue::InternalLinkage, Init,
            "__jove_dynl_function_table");

        IRB.CreateRet(IRB.CreateConstInBoundsGEP2_64(
            ConstantTableGV->getValueType(), ConstantTableGV, 0, 0));
      }, !opts.ForCBE);

  fillInFunctionBody(
      Module->getFunction("_jove_get_vdso_function_table"),
      [&](auto &IRB) -> void {
        binary_t &vdso_binary = get_vdso(jv);
        assert(vdso_binary.IsVDSO);
        auto &ICFG = vdso_binary.Analysis.ICFG;

        std::vector<llvm::Constant *> constantTable;
        constantTable.resize(vdso_binary.Analysis.Functions.size());

        std::transform(vdso_binary.Analysis.Functions.begin(),
                       vdso_binary.Analysis.Functions.end(), constantTable.begin(),
                       [&](const function_t &f) -> llvm::Constant * {
                         uintptr_t Addr = ICFG[basic_block_of_index(f.Entry, ICFG)].Addr;
                         return llvm::ConstantInt::get(WordType(), Addr);
                       });

        constantTable.push_back(llvm::Constant::getNullValue(WordType()));

        llvm::ArrayType *T = llvm::ArrayType::get(WordType(), constantTable.size());

        llvm::Constant *Init = llvm::ConstantArray::get(T, constantTable);
        llvm::GlobalVariable *ConstantTableGV = new llvm::GlobalVariable(
            *Module, T, false, llvm::GlobalValue::InternalLinkage, Init,
            "__jove_vdso_function_table");
        IRB.CreateRet(IRB.CreateConstInBoundsGEP2_64(
            ConstantTableGV->getValueType(), ConstantTableGV, 0, 0));
      }, !opts.ForCBE);

  fillInFunctionBody(
      Module->getFunction("_jove_foreign_lib_count"),
      [&](auto &IRB) {
        uint32_t res =
            opts.ForeignLibs ? (jv.Binaries.size()
                                 - 1 /* rtld */
                                 - 1 /* vdso */
                                 - 1 /* exe  */) : 0;

        IRB.CreateRet(IRB.getInt32(res));
      }, !opts.ForCBE);

  fillInFunctionBody(
      Module->getFunction("_jove_foreign_lib_path"),
      [&](auto &IRB) {
        llvm::Function *F = IRB.GetInsertBlock()->getParent();

        llvm::BasicBlock *DefaultBB = llvm::BasicBlock::Create(*Context, "", F);
        {
          llvm::IRBuilderTy defaultIRB(DefaultBB);

          defaultIRB.SetCurrentDebugLocation(llvm::DILocation::get(
              *Context, 7 /* Line */, 7 /* Column */, F->getSubprogram()));

          defaultIRB.CreateRet(llvm::Constant::getNullValue(
              F->getFunctionType()->getReturnType()));
        }

        {
          assert(F->arg_begin() != F->arg_end());
          llvm::SwitchInst *SI = IRB.CreateSwitch(F->arg_begin(), DefaultBB,
                                                  jv.Binaries.size() - 3);
          if (opts.ForeignLibs) {
            for (binary_index_t BIdx = 3; BIdx < jv.Binaries.size(); ++BIdx) {
              llvm::BasicBlock *CaseBB = llvm::BasicBlock::Create(*Context, "", F);
              {
                llvm::IRBuilderTy CaseIRB(CaseBB);

                CaseIRB.SetCurrentDebugLocation(llvm::DILocation::get(
                    *Context, 0 /* Line */, 0 /* Column */, F->getSubprogram()));

                CaseIRB.CreateRet(
                    CaseIRB.CreateGlobalStringPtr(jv.Binaries.at(BIdx).path_str()));
              }

              SI->addCase(llvm::ConstantInt::get(IRB.getInt32Ty(), BIdx - 3),  CaseBB);
            }
          }
        }
      }, !opts.ForCBE);


  fillInFunctionBody(
      Module->getFunction("_jove_foreign_lib_function_table"),
      [&](auto &IRB) {
        llvm::Function *F = IRB.GetInsertBlock()->getParent();

        llvm::BasicBlock *DefaultBB = llvm::BasicBlock::Create(*Context, "", F);
        {
          llvm::IRBuilderTy defaultIRB(DefaultBB);

          defaultIRB.SetCurrentDebugLocation(llvm::DILocation::get(
              *Context, 7 /* Line */, 7 /* Column */, F->getSubprogram()));

          defaultIRB.CreateRet(llvm::Constant::getNullValue(
              F->getFunctionType()->getReturnType()));
        }

        {
          assert(F->arg_begin() != F->arg_end());
          llvm::SwitchInst *SI = IRB.CreateSwitch(F->arg_begin(), DefaultBB,
                                                  jv.Binaries.size() - 3);
          if (opts.ForeignLibs) {
            for (binary_index_t BIdx = 3; BIdx < jv.Binaries.size(); ++BIdx) {
              binary_t &binary = jv.Binaries.at(BIdx);
              auto &ICFG = binary.Analysis.ICFG;

              auto &Bin = state.for_binary(binary).Bin;

              llvm::ArrayType *TblTy =
                llvm::ArrayType::get(WordType(),
                                     binary.Analysis.Functions.size() + 1);

              std::vector<llvm::Constant *> constantTable;
              constantTable.resize(binary.Analysis.Functions.size() + 1);

              for (function_index_t FIdx = 0; FIdx < binary.Analysis.Functions.size(); ++FIdx) {
                function_t &f = binary.Analysis.Functions.at(FIdx);

                constantTable[FIdx] = llvm::ConstantInt::get(WordType(),
                  B::offset_of_va(*Bin, ICFG[basic_block_of_index(f.Entry, ICFG)].Addr));
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
                    *Context, 0 /* Line */, 0 /* Column */, F->getSubprogram()));

                CaseIRB.CreateRet(CaseIRB.CreateConstInBoundsGEP2_64(
                    ConstantTableGV->getValueType(), ConstantTableGV, 0, 0));
              }

              SI->addCase(llvm::ConstantInt::get(IRB.getInt32Ty(), BIdx - 3),  CaseBB);
            }
          }
        }
      }, !opts.ForCBE);

  fillInFunctionBody(
      Module->getFunction("_jove_laid_out_sections"),
      [&](auto &IRB) -> void {
        binary_t &dynl_binary = get_dynl(jv);
        assert(dynl_binary.IsDynamicLinker);
        auto &ICFG = dynl_binary.Analysis.ICFG;

        llvm::ArrayType *ElemTy = llvm::ArrayType::get(WordType(), 2);

        std::vector<llvm::Constant *> constantTable;
        constantTable.resize(LaidOut.GVVec.size());

        std::transform(
            LaidOut.GVVec.begin(),
            LaidOut.GVVec.end(), constantTable.begin(),
            [&](const auto &pair) -> llvm::Constant * {
              llvm::GlobalVariable *GV;
              unsigned ExpectedSize;

              std::tie(GV, ExpectedSize) = pair;

              std::array<llvm::Constant *, 2> _constantTable = {
                  {llvm::ConstantExpr::getPtrToInt(GV, WordType()),
                   IRB.getIntN(WordBits(), ExpectedSize)}};

              return llvm::ConstantArray::get(ElemTy, _constantTable);
            });

        llvm::ArrayType *T = llvm::ArrayType::get(ElemTy, constantTable.size());

        llvm::GlobalVariable *ConstantTableGV = new llvm::GlobalVariable(
            *Module, T, false, llvm::GlobalValue::InternalLinkage,
            llvm::ConstantArray::get(T, constantTable),
            "__jove_laid_out_sections");

        IRB.CreateRet(ConstantTableGV);
      }, !opts.ForCBE);

  fillInFunctionBody(
      Module->getFunction("_jove_laid_out_sections_count"),
      [&](auto &IRB) {
        IRB.CreateRet(IRB.getInt32(LaidOut.GVVec.size()));
      }, !opts.ForCBE);

  return 0;
}

int LLVMTool::CreateNoAliasMetadata(void) {
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
  LLVMTool &tool;
  function_t &f;
  basic_block_t bb;

  std::array<llvm::AllocaInst *, tcg_num_globals> GlobalAllocaArr;
  std::vector<llvm::AllocaInst *> TempAllocaVec;
  std::vector<llvm::BasicBlock *> LabelVec;
  llvm::AllocaInst *PCAlloca;

  struct {
    llvm::DISubprogram *Subprogram;
  } DebugInformation;

  TranslateContext(LLVMTool &tool, function_t &f) : tool(tool), f(f) {
    memset(&GlobalAllocaArr[0], 0, sizeof(llvm::AllocaInst *) * GlobalAllocaArr.size());
  }
};

llvm::AllocaInst *
LLVMTool::CreateAllocaForGlobal(TranslateContext &TC,
                                llvm::IRBuilderTy &IRB,
                                unsigned glb,
                                bool InitializeFromEnv) {
  llvm::AllocaInst *res =
      IRB.CreateAlloca(TypeOfTCGGlobal(glb), nullptr,
                       std::string(jv_get_tcg_context()->temps[glb].name));

  if (InitializeFromEnv) {
    llvm::MDNode *Metadata = AliasScopeMetadata;

    llvm::LoadInst *LI = IRB.CreateLoad(
        TypeOfTCGGlobal(glb), BuildCPUStatePointer(IRB, CPUStateGlobal, glb));
    LI->setMetadata(llvm::LLVMContext::MD_alias_scope, Metadata);

    llvm::StoreInst *SI = IRB.CreateStore(LI, res);
    SI->setMetadata(llvm::LLVMContext::MD_alias_scope, Metadata);
  }

  return res;
}

llvm::Constant *LLVMTool::CPUStateGlobalPointer(llvm::IRBuilderTy &IRB,
                                                unsigned glb) {
  assert(glb < tcg_num_globals);
  assert(glb != tcg_env_index);

  llvm::IntegerType *GlbTy = TypeOfTCGGlobal(glb);

  struct TCGTemp *base_tmp = jv_get_tcg_context()->temps[glb].mem_base;
  if (unlikely(!base_tmp || temp_idx(base_tmp) != tcg_env_index))
    return nullptr;

  unsigned Off = jv_get_tcg_context()->temps[glb].mem_offset;

  llvm::SmallVector<llvm::Value *, 4> Indices;
  llvm::Value *res = llvm::getNaturalGEPWithOffset(
      IRB, DL, std::make_pair(CPUStateGlobal, CPUStateType),
      llvm::APInt(64, Off), GlbTy, Indices, "");

  if (res) {
    assert(llvm::isa<llvm::Constant>(res));
    return llvm::cast<llvm::Constant>(res);
  }

  return llvm::ConstantExpr::getIntToPtr(
      llvm::ConstantExpr::getAdd(
          llvm::ConstantExpr::getPtrToInt(CPUStateGlobal, WordType()),
          llvm::ConstantInt::get(WordType(), Off)),
      GlbTy->getPointerTo());
}

llvm::Value *LLVMTool::BuildCPUStatePointer(llvm::IRBuilderTy &IRB,
                                            llvm::Value *Env,
                                            unsigned glb) {
  assert(glb < tcg_num_globals);
  assert(glb != tcg_env_index);

  llvm::IntegerType *GlbTy = TypeOfTCGGlobal(glb);

  struct TCGTemp *base_tmp = jv_get_tcg_context()->temps[glb].mem_base;
  if (unlikely(!base_tmp || temp_idx(base_tmp) != tcg_env_index))
    return nullptr;

  unsigned Off = jv_get_tcg_context()->temps[glb].mem_offset;

  llvm::SmallVector<llvm::Value *, 4> Indices;
  if (llvm::Value *res = llvm::getNaturalGEPWithOffset(
          IRB, DL, std::make_pair(Env, CPUStateType), llvm::APInt(64, Off),
          GlbTy, Indices, ""))
    return res;

  // fallback
  return IRB.CreateIntToPtr(IRB.CreateAdd(IRB.CreatePtrToInt(Env, WordType()),
                                          IRB.getIntN(WordBits(), Off)),
                            GlbTy->getPointerTo());
}

int LLVMTool::TranslateFunction(function_t &f) {
  TranslateContext TC(*this, f);

  binary_t &Binary = jv.Binaries.at(BinaryIndex);
  const function_index_t FIdx = index_of_function_in_binary(f, Binary);
  interprocedural_control_flow_graph_t &ICFG = Binary.Analysis.ICFG;
  llvm::Function *F = state.for_function(f).F;
  llvm::DIBuilder &DIB = *DIBuilder;

  if (unlikely(state.for_function(f).bbvec.empty()))
    return 0;

  basic_block_t entry_bb = state.for_function(f).bbvec.front();

  llvm::BasicBlock *EntryB = llvm::BasicBlock::Create(*Context, "", F);
  for (basic_block_t bb : state.for_function(f).bbvec)
    state.for_basic_block(Binary, bb).B = llvm::BasicBlock::Create(
        *Context, (fmt("l%lx") % ICFG[bb].Addr).str(), F);

  llvm::DISubprogram::DISPFlags SubProgFlags =
      llvm::DISubprogram::SPFlagDefinition |
      llvm::DISubprogram::SPFlagOptimized;

  if (F->hasPrivateLinkage() || F->hasInternalLinkage())
    SubProgFlags |= llvm::DISubprogram::SPFlagLocalToUnit;

  llvm::DISubroutineType *SubProgType =
      DIB.createSubroutineType(DIB.getOrCreateTypeArray(std::nullopt));

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
        AI = CreateAllocaForGlobal(TC, IRB, tcg_program_counter_index, false);
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

        llvm::AllocaInst *AI = GlobalAllocaArr[glb] =
            CreateAllocaForGlobal(TC, IRB, glb, false);

        llvm::StoreInst *SI = IRB.CreateStore(Val, AI);
        SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
      }
    }

#if defined(TARGET_MIPS32) || defined(TARGET_MIPS64)
    if (opts.ForCBE && f.IsABI) {
      unsigned glb = tcg_t9_index;

      llvm::AllocaInst *AI = GlobalAllocaArr[glb] =
          CreateAllocaForGlobal(TC, IRB, glb, false);

      llvm::StoreInst *SI = IRB.CreateStore(SectionPointer(ICFG[entry_bb].Addr), AI);
      SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
    }
#endif

    if (opts.DFSan) {
      llvm::AllocaInst *&SPAlloca = GlobalAllocaArr[tcg_stack_pointer_index];

      if (!SPAlloca)
        SPAlloca = CreateAllocaForGlobal(TC, IRB, tcg_stack_pointer_index, true);

      llvm::LoadInst *LI = IRB.CreateLoad(WordType(), SPAlloca);
      LI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);

      IRB.CreateCall(JoveLogFunctionStart->getFunctionType(),
                     IRB.CreateIntToPtr(
                         IRB.CreateLoad(WordType(), JoveLogFunctionStartClunk),
                         JoveLogFunctionStart->getType()),
                     {IRB.CreateIntCast(LI, IRB.getInt64Ty(), false)});
    }

    IRB.CreateBr(state.for_basic_block(Binary, entry_bb).B);
  }

  for (basic_block_t bb : state.for_function(f).bbvec) {
    TC.bb = bb;

    int ret = TranslateBasicBlock(&TC);

    if (unlikely(ret))
      return ret;
  }

  DIB.finalizeSubprogram(TC.DebugInformation.Subprogram);

  if (!f.IsABI) {
    //
    // build "ABI adapter"
    //
    F = state.for_function(f).adapterF;

    assert(F);
    llvm::FunctionType *FTy = F->getFunctionType();

    llvm::DISubprogram *Subprogram = DIB.createFunction(
        /* Scope       */ DebugInformation.CompileUnit,
        /* Name        */ F->getName(),
        /* LinkageName */ F->getName(),
        /* File        */ DebugInformation.File,
        /* LineNo      */ 0,
        /* Ty          */ SubProgType,
        /* ScopeLine   */ 0,
        /* Flags       */ llvm::DINode::FlagZero,
        /* SPFlags     */ SubProgFlags);

    F->setSubprogram(Subprogram);

    {
      llvm::IRBuilderTy IRB(llvm::BasicBlock::Create(*Context, "", F));

      IRB.SetCurrentDebugLocation(llvm::DILocation::get(
          *Context, ICFG[entry_bb].Addr, 0 /* Column */, Subprogram));

      IRB.CreateCall(JoveRecoverABIFunc, {IRB.getInt32(FIdx)})->setIsNoInline();

      std::vector<llvm::Value *> argsToPass;
      {
        std::vector<unsigned> glbv;
        ExplodeFunctionArgs(f, glbv);

        argsToPass.resize(glbv.size());

        std::transform(glbv.begin(),
                       glbv.end(),
                       argsToPass.begin(),
                       [&](unsigned glb) -> llvm::Value * {
                         if (CallConvArgs.test(glb)) {
                           unsigned Idx = std::distance(
                               CallConvArgArray.begin(),
                               std::find(CallConvArgArray.begin(),
                                         CallConvArgArray.end(), glb));
                           return F->getArg(Idx);
                         } else {
                           llvm::LoadInst *LI = IRB.CreateLoad(
                               TypeOfTCGGlobal(glb),
                               BuildCPUStatePointer(IRB, CPUStateGlobal, glb));
                           LI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
                           return LI;
                         }
                       });
      }

      llvm::CallInst *Ret = IRB.CreateCall(state.for_function(f).F, argsToPass);
      Ret->setIsNoInline();

      {
        std::vector<unsigned> glbv;
        ExplodeFunctionRets(f, glbv);

        if (Ret->getType()->isVoidTy()) {
          assert(glbv.empty());

          IRB.CreateCall(
              llvm::Intrinsic::getDeclaration(Module.get(), llvm::Intrinsic::trap));
          IRB.CreateUnreachable();
        } else {
          std::vector<llvm::Value *> RetValues(
              CallConvRetArray.size(),
              llvm::UndefValue::get(TypeOfTCGGlobal(CallConvRetArray.at(0))));

          if (Ret->getType()->isIntegerTy(WordBits())) {
            assert(glbv.size() == 1);

            unsigned glb = glbv.front();
            assert(glb == tcg_stack_pointer_index);

            llvm::StoreInst *SI = IRB.CreateStore(Ret, BuildCPUStatePointer(IRB, CPUStateGlobal, glb));
            SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
          } else {
            assert(glbv.size() > 1);
            assert(Ret->getType()->isStructTy());

            for (unsigned i = 0; i < glbv.size(); ++i) {
              unsigned glb = glbv[i];

              if (glb == tcg_stack_pointer_index) {
                llvm::Value *ReturnedSP = IRB.CreateExtractValue(
                    Ret, llvm::ArrayRef<unsigned>(i),
                    jv_get_tcg_context()->temps[glb].name + std::string("_"));

                llvm::StoreInst *SI = IRB.CreateStore(
                    ReturnedSP, BuildCPUStatePointer(IRB, CPUStateGlobal, glb));
                SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
              } else if (CallConvRets.test(glb)) {
                 unsigned Idx = std::distance(
                     CallConvRetArray.begin(),
                     std::find(CallConvRetArray.begin(),
                               CallConvRetArray.end(), glb));

                 RetValues.at(Idx) = IRB.CreateExtractValue(
                     Ret, llvm::ArrayRef<unsigned>(i),
                     jv_get_tcg_context()->temps[glb].name + std::string("_"));
              } else {
                ;
              }
            }
          }

          assert(FTy->getReturnType()->isStructTy());
          {
            unsigned j = 0;

            llvm::Value *init = llvm::UndefValue::get(FTy->getReturnType());
            llvm::Value *res = std::accumulate(
                RetValues.begin(),
                RetValues.end(), init,
                [&](llvm::Value *res, llvm::Value *Val) -> llvm::Value * {
                  std::string nm = std::string("_ret_") + jv_get_tcg_context()->temps[CallConvRetArray.at(j)].name + std::string("_");

                  return IRB.CreateInsertValue(res,
                                               Val,
                                               llvm::ArrayRef<unsigned>(j++),
                                               nm);
                });

            IRB.CreateRet(res);
          }
        }
      }
    }

    DIB.finalizeSubprogram(Subprogram);

    F->setVisibility(llvm::GlobalValue::HiddenVisibility);
  }

  return 0;
}

int LLVMTool::TranslateFunctions(void) {
  llvm::legacy::FunctionPassManager FPM(Module.get());

  FPM.add(llvm::createScopedNoAliasAAWrapperPass());
  FPM.add(llvm::createBasicAAWrapperPass());
  FPM.add(llvm::createPromoteMemoryToRegisterPass());
  if (!opts.DumpPreOpt1) {
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
  }

  FPM.doInitialization();

  binary_t &Binary = jv.Binaries.at(BinaryIndex);
  for (function_t &f : Binary.Analysis.Functions) {
    int ret = TranslateFunction(f);
    if (unlikely(ret))
      return ret;

    if (likely(state.for_function(f).F))
      FPM.run(*state.for_function(f).F);
  }

  llvm::DIBuilder &DIB = *DIBuilder;
  DIB.finalize();

  FPM.doFinalization();

  return 0;
}

int LLVMTool::PrepareToOptimize(void) {
  // Initialize passes
  llvm::PassRegistry &Registry = *llvm::PassRegistry::getPassRegistry();
  initializeCore(Registry);
  initializeScalarOpts(Registry);
  initializeVectorization(Registry);
  initializeIPO(Registry);
  initializeAnalysis(Registry);
  initializeTransformUtils(Registry);
  initializeInstCombine(Registry);
  initializeTarget(Registry);
  // For codegen passes, only passes that do IR to IR transformation are
  // supported.
  initializeExpandLargeDivRemLegacyPassPass(Registry);
  initializeExpandLargeFpConvertLegacyPassPass(Registry);
  initializeExpandMemCmpPassPass(Registry);
  initializeScalarizeMaskedMemIntrinLegacyPassPass(Registry);
  initializeSelectOptimizePass(Registry);
  initializeCodeGenPreparePass(Registry);
  initializeAtomicExpandPass(Registry);
  initializeRewriteSymbolsLegacyPassPass(Registry);
  initializeWinEHPreparePass(Registry);
  initializeDwarfEHPrepareLegacyPassPass(Registry);
  initializeSafeStackLegacyPassPass(Registry);
  initializeSjLjEHPreparePass(Registry);
  initializePreISelIntrinsicLoweringLegacyPassPass(Registry);
  initializeGlobalMergePass(Registry);
  initializeIndirectBrExpandPassPass(Registry);
  initializeInterleavedLoadCombinePass(Registry);
  initializeInterleavedAccessPass(Registry);
  initializeUnreachableBlockElimLegacyPassPass(Registry);
  initializeExpandReductionsPass(Registry);
  initializeExpandVectorPredicationPass(Registry);
  initializeWasmEHPreparePass(Registry);
  initializeWriteBitcodePassPass(Registry);
  initializeHardwareLoopsPass(Registry);
  initializeReplaceWithVeclibLegacyPass(Registry);
  initializeJMCInstrumenterPass(Registry);

  return 0;
}

void LLVMTool::ReloadGlobalVariables(void) {
  SectsGlobal      = Module->getGlobalVariable(SectsGlobalName, true);
  ConstSectsGlobal = Module->getGlobalVariable(ConstSectsGlobalName, true);
}

int LLVMTool::DoOptimize(void) {
  PrepareToOptimize();

  const bool DoVerify = true;

  // Immediately run the verifier to catch any problems before starting up the
  // pass pipelines.  Otherwise we can crash on broken code during
  // doInitialization().
  if (DoVerify && llvm::verifyModule(*Module, &llvm::errs())) {
    WithColor::error() << "DoOptimize: [pre] failed to verify module\n";
    DumpModule("pre.opt.fail");
    return 1;
  }

  std::string VerifyDIPreserveExport("");
  std::optional<llvm::PGOOptions> P;

  llvm::Triple ModuleTriple(Module->getTargetTriple());
  llvm::TargetLibraryInfoImpl TLII(ModuleTriple);
  if (true /* DisableSimplifyLibCalls */)
    TLII.disableAllFunctions();

  llvm::LoopAnalysisManager LAM;
  llvm::FunctionAnalysisManager FAM;
  llvm::CGSCCAnalysisManager CGAM;
  llvm::ModuleAnalysisManager MAM;

  llvm::PassInstrumentationCallbacks PIC;

#if 0
  llvm::PrintPassOptions PrintPassOpts;

  PrintPassOpts.Verbose = IsVerbose();
  PrintPassOpts.SkipAnalyses = true; // quiet

  llvm::StandardInstrumentations SI(*Context,
                                    false /* DebugLogging */,
                                    false /* VerifyEachPass */,
                                    PrintPassOpts);
  SI.registerCallbacks(PIC, &FAM);
#endif

#if 0
  llvm::DebugifyEachInstrumentation Debugify;
  DebugifyStatsMap DIStatsMap;
  DebugInfoPerPass DebugInfoBeforePass;
  if (false /* DebugifyEach */) {
    Debugify.setDIStatsMap(DIStatsMap);
    Debugify.setDebugifyMode(DebugifyMode::SyntheticDebugInfo);
    Debugify.registerCallbacks(PIC);
  } else if (false /* VerifyEachDebugInfoPreserve */) {
    Debugify.setDebugInfoBeforePass(DebugInfoBeforePass);
    Debugify.setDebugifyMode(DebugifyMode::OriginalDebugInfo);
    Debugify.setOrigDIVerifyBugsReportFilePath(VerifyDIPreserveExport);
    Debugify.registerCallbacks(PIC);
  }
#endif

  llvm::PipelineTuningOptions PTO;
  PTO.LoopUnrolling = false;

  llvm::PassBuilder PB(disas.TM.get(), PTO, P, &PIC);

  const std::string AAPipeline("default");

  // Specially handle the alias analysis manager so that we can register
  // a custom pipeline of AA passes with it.
  llvm::AAManager AA;
  if (auto Err = PB.parseAAPipeline(AA, AAPipeline)) {
    WithColor::error() << llvm::toString(std::move(Err)) << "\n";
    return 1;
  }

  // Register the AA manager first so that our version is the one used.
  FAM.registerPass([&] { return std::move(AA); });
  // Register our TargetLibraryInfoImpl.
  FAM.registerPass([&] { return llvm::TargetLibraryAnalysis(TLII); });

  // Register all the basic analyses with the managers.
  PB.registerModuleAnalyses(MAM);
  PB.registerCGSCCAnalyses(CGAM);
  PB.registerFunctionAnalyses(FAM);
  PB.registerLoopAnalyses(LAM);
  PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);

  llvm::ModulePassManager MPM;

#if 0
  const bool EnableDebugify = false;
  const bool VerifyDIPreserve = false;

  if (EnableDebugify)
    MPM.addPass(NewPMDebugifyPass());
  if (VerifyDIPreserve)
    MPM.addPass(NewPMDebugifyPass(DebugifyMode::OriginalDebugInfo, "",
                                  &DebugInfoBeforePass));
#endif

  const llvm::StringRef PassPipeline = "default<O3>";
  if (auto Err = PB.parsePassPipeline(MPM, PassPipeline)) {
    WithColor::error() << llvm::toString(std::move(Err)) << "\n";
    return false;
  }

  //MPM.addPass(llvm::VerifierPass());

#if 0
  if (EnableDebugify)
    MPM.addPass(NewPMCheckDebugifyPass(false, "", &DIStatsMap));
  if (VerifyDIPreserve)
    MPM.addPass(NewPMCheckDebugifyPass(
        false, "", nullptr, DebugifyMode::OriginalDebugInfo,
        &DebugInfoBeforePass, VerifyDIPreserveExport));
#endif

  // Print a textual, '-passes=' compatible, representation of pipeline if
  // requested.
  if (false /* IsVeryVerbose() */) {
    std::string Pipeline;
    llvm::raw_string_ostream SOS(Pipeline);
    MPM.printPipeline(SOS, [&PIC](llvm::StringRef ClassName) {
      auto PassName = PIC.getPassNameForClassName(ClassName);
      return PassName.empty() ? ClassName : PassName;
    });
    llvm::outs() << Pipeline;
    llvm::outs() << "\n";

    const bool DisablePipelineVerification = false;
    if (!DisablePipelineVerification) {
      // Check that we can parse the returned pipeline string as an actual
      // pipeline.
      llvm::ModulePassManager TempPM;
      if (auto Err = PB.parsePassPipeline(TempPM, Pipeline)) {
        WithColor::error() << "Could not parse dumped pass pipeline: "
                           << llvm::toString(std::move(Err)) << "\n";
        return false;
      }
    }

    return true;
  }

  // Now that we have all of the passes ready, run them.
  MPM.run(*Module, MAM);

  if (DoVerify && llvm::verifyModule(*Module, &llvm::errs())) {
    WithColor::error() << "DoOptimize: [post] failed to verify module\n";

    WithColor::error() << "Dumping module...\n";
    DumpModule("post.opt.fail");

    // llvm::errs() << *Module << '\n';
    return 1;
  }

  //
  // if any gv was optimized away, we'd like to make sure our pointer to it
  // becomes null.
  //
  ReloadGlobalVariables();

  return 0;
}

int LLVMTool::ConstifyRelocationSectionPointers(void) {
  return 0;

  if (opts.LayOutSections)
    return 0;

  binary_t &Binary = jv.Binaries.at(BinaryIndex);

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
        uint64_t off =
            llvm::cast<llvm::ConstantInt>(Addend)->getValue().getZExtValue();

        uintptr_t FileAddr = off + state.for_binary(Binary).SectsStartAddr;

        bool RelocLoc = ConstantRelocationLocs.find(FileAddr) !=
                        ConstantRelocationLocs.end();

        if (RelocLoc) {
          llvm::IRBuilderTy IRB(*Context);
          llvm::SmallVector<llvm::Value *, 4> Indices;
          llvm::Value *SectionGEP = llvm::getNaturalGEPWithOffset(
              IRB, DL,
              std::make_pair(ConstSectsGlobal,
                             ConstSectsGlobal->getValueType()),
              llvm::APInt(64, off), nullptr, Indices, "");

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

int LLVMTool::InternalizeSections(void) {
  if (SectsGlobal)
    SectsGlobal->setLinkage(llvm::GlobalValue::InternalLinkage);
  if (ConstSectsGlobal)
    ConstSectsGlobal->setLinkage(llvm::GlobalValue::InternalLinkage);

  return 0;
}

int LLVMTool::PrepareForCBE(void) {
  assert(opts.ForCBE);

  //
  // delete function bodies for TCG helpers
  //
  for (auto &pair : HelperFuncMap) {
    helper_function_t &hf = pair.second;

    hf.F->setVisibility(llvm::GlobalValue::DefaultVisibility);
    hf.F->deleteBody();
  }

  JoveNoDCEFunc->setVisibility(llvm::GlobalValue::DefaultVisibility);
  JoveNoDCEFunc->deleteBody();

  return ConstifyRelocationSectionPointers();
}

bool LLVMTool::shouldExpandOperationWithSize(llvm::Value *Size) {
  if (opts.ForCBE)
    return true;
  if (opts.DFSan) /* erase all notions of contiguous memory */
    return true;

  constexpr unsigned MaxStaticSize = 32;

  llvm::ConstantInt *CI = llvm::dyn_cast<llvm::ConstantInt>(Size);
  return !CI || (CI->getZExtValue() > MaxStaticSize);
}

int LLVMTool::ExpandMemoryIntrinsicCalls(void) {
  //
  // lower memory intrinsics (memcpy, memset, memmove)
  //
  llvm::TargetTransformInfo TTI(DL);

  auto DoExpandMemcpy = [&](llvm::Instruction *Inst) -> void {
    llvm::expandMemCpyAsLoop(llvm::cast<llvm::MemCpyInst>(Inst), TTI);
  };

  auto DoExpandMemmove = [&](llvm::Instruction *Inst) -> void {
    llvm::expandMemMoveAsLoop(llvm::cast<llvm::MemMoveInst>(Inst));
  };

  auto DoExpandMemset = [&](llvm::Instruction *Inst) -> void {
    llvm::expandMemSetAsLoop(llvm::cast<llvm::MemSetInst>(Inst));
  };

  for (llvm::Function &F : Module->functions()) {
    if (!F.isDeclaration())
      continue;

    std::function<void(llvm::Instruction *)> ExpandFunc;

    switch (F.getIntrinsicID()) {
    case llvm::Intrinsic::memcpy:
    case llvm::Intrinsic::memcpy_inline:
      ExpandFunc = DoExpandMemcpy;
      break;
    case llvm::Intrinsic::memmove:
      ExpandFunc = DoExpandMemmove;
      break;
    case llvm::Intrinsic::memset:
    case llvm::Intrinsic::memset_inline:
      ExpandFunc = DoExpandMemset;
      break;

    default:
      continue;
    }

    for (llvm::User *U : llvm::make_early_inc_range(F.users())) {
      assert(llvm::isa<llvm::Instruction>(U));
      llvm::Instruction *Inst = llvm::cast<llvm::Instruction>(U);

      auto *MemTrans = llvm::dyn_cast<llvm::MemTransferInst>(Inst);
      if (MemTrans && !shouldExpandOperationWithSize(MemTrans->getLength()))
        continue;

      ExpandFunc(Inst);
      Inst->eraseFromParent();
    }
  }

  return 0;
}

int LLVMTool::ReplaceAllRemainingUsesOfConstSections(void) {
  if (!ConstSectsGlobal)
    return 0;

  assert(SectsGlobal);

  if (ConstSectsGlobal->user_begin() != ConstSectsGlobal->user_end())
    ConstSectsGlobal->replaceAllUsesWith(SectsGlobal);

  assert(ConstSectsGlobal->user_begin() == ConstSectsGlobal->user_end());
  ConstSectsGlobal->eraseFromParent();

  return 0;
}

int LLVMTool::RenameFunctionLocals(void) {
  if (opts.ForCBE) {
    for (llvm::Function &Func : *Module) {
      for (llvm::BasicBlock &Block : Func) {
        for (llvm::Instruction &Inst : Block) {
          const llvm::StringRef &Name = Inst.getName();
          if (std::all_of(Name.begin(),
                          Name.end(),
                          [](char ch) -> bool { return ::isalnum(ch) || ch == '_'; }))
            continue;

          std::string NewName;
          for (auto it = Name.begin(); it != Name.end(); ++it) {
            unsigned char ch = *it;

            if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                  (ch >= '0' && ch <= '9') || ch == '_')) {
              if (ch == '.') {
                NewName += '_';
              } else {
                NewName = "";
                break;
              }
            } else {
              NewName += ch;
            }
          }

          Inst.setName(NewName);
        }
      }
    }
  }

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

    const char *nm = jv_get_tcg_context()->temps[glb].name;
    for (llvm::User *UU : U->users()) {
      if (llvm::isa<llvm::LoadInst>(UU))
        UU->setName(nm + std::string("_"));
    }
  }

  return 0;
}

int LLVMTool::DFSanInstrument(void) {
  assert(opts.DFSan);

#if 0
  if (llvm::verifyModule(*Module, &llvm::errs())) {
    WithColor::error() << "DFSanInstrument: [pre] failed to verify module\n";
    //llvm::errs() << *Module << '\n';
    return 1;
  }
#endif

  llvm::ModulePassManager MPM;

  // Add an appropriate TargetLibraryInfo pass for the module's triple.
  llvm::Triple ModuleTriple(Module->getTargetTriple());
  llvm::TargetLibraryInfoImpl TLII(ModuleTriple);

  // The -disable-simplify-libcalls flag actually disables all builtin optzns.
  if (true /* DisableSimplifyLibCalls */)
    TLII.disableAllFunctions();

#if 0
  MPM.addPass(new llvm::TargetLibraryInfoWrapperPass(TLII));

  // Add internal analysis passes from the target machine.
  MPM.addPass(llvm::createTargetTransformInfoWrapperPass(disas.TM->getTargetIRAnalysis()));
#endif

  std::vector<std::string> ABIList = {locator().dfsan_abilist()};

  MPM.addPass(llvm::DataFlowSanitizerPass(ABIList));

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

  llvm::ModuleAnalysisManager MAM;
  llvm::CGSCCAnalysisManager CGAM;
  llvm::FunctionAnalysisManager FAM;
  llvm::LoopAnalysisManager LAM;

  llvm::PipelineTuningOptions PTO;
  llvm::PassInstrumentationCallbacks PIC;
  std::optional<llvm::PGOOptions> P;
  llvm::PassBuilder PB(disas.TM.get(), PTO, P, &PIC);

  // Register all the basic analyses with the managers.
  PB.registerModuleAnalyses(MAM);
  PB.registerCGSCCAnalyses(CGAM);
  PB.registerFunctionAnalyses(FAM);
  PB.registerLoopAnalyses(LAM);
  PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);

  MPM.run(*Module, MAM);

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
        llvm::cast<llvm::MDString>(SubNode->getOperand(0))->getString().str();
    WithColor::note() << llvm::formatv("ModuleID is {0}\n", ModuleID);

    {
      std::ofstream ofs(opts.DFSanOutputModuleID);

      ofs << ModuleID;
    }
  }

  return 0;
}

int LLVMTool::WriteVersionScript(void) {
  assert(!opts.VersionScript.empty());

  std::ofstream ofs(opts.VersionScript);

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

int LLVMTool::WriteLinkerScript(void) {
  assert(!opts.LinkerScript.empty());

  binary_t &Binary = jv.Binaries.at(BinaryIndex);
  assert(Binary.IsExecutable);

  binary_state_t &x = state.for_binary(Binary);

  std::ofstream ofs(opts.LinkerScript);

  if (IsCOFF) {
    if (!opts.LayOutSections)
      return 0;

#if 0
    //out << "NAME " << DLL.str() << '\n';
    ofs << "SECTIONS\n";
    ofs << ".jove.pre READ WRITE";
    ofs << ".rsrc READ WRITE";
    ofs << ".jove.post READ WRITE";
#elif 1
    /* currently, the linker script being nonempty tells jove-recompile that
     * the sections are laid out. */

    ofs << ".jove.pr\n";
    ofs << ".rsrc\n";
    ofs << ".jove.po\n";
#endif
  } else {
    return 0; /* TODO? */

    ofs <<
      (fmt(
      "SECTIONS"                               "\n"
      "{"                                      "\n"
      "  .text : { *(.text) }"                 "\n"
      "  .data : { *(.data) }"                 "\n"
      "  .bss  : { *(.bss) }"                  "\n"
      ""                                       "\n"
      "}")).str();
    ;
  }

  return 0;
}

int LLVMTool::BreakBeforeUnreachables(void) {
  assert(opts.BreakBeforeUnreachables);

  //
  // Why would we go to the trouble of doing this? Because LLVM optimizers
  // can get "carried away" from just a touch of undefined behavior. This is a
  // countermeasure that is intended to prevent impossible-to-debug situations.
  //
  llvm::Module &M = *Module;

  for (llvm::Function &F : M)
    for (llvm::BasicBlock &BB : F)
      for (llvm::Instruction &I : llvm::make_early_inc_range(BB))
        if (llvm::isa<llvm::UnreachableInst>(I)) {
          llvm::IRBuilderTy IRB(&I);

          IRB.CreateCall(llvm::Intrinsic::getDeclaration(Module.get(), llvm::Intrinsic::trap));
        }

  return 0;
}

int LLVMTool::InlineHelpers(void) {
  if (!opts.Optimize && !opts.InlineHelpers)
    return 0;

  for (const auto &pair : HelperFuncMap) {
    const helper_function_t &hf = pair.second;
    if (hf.EnvArgNo < 0 || !hf.Analysis.Simple)
      continue;

    llvm::Function *F = pair.second.F;

    for (llvm::User *HelperFU : llvm::make_early_inc_range(F->users())) {
      if (!llvm::isa<llvm::CallInst>(HelperFU))
        continue;

      llvm::InlineFunctionInfo IFI;
      llvm::InlineFunction(*llvm::cast<llvm::CallInst>(HelperFU), IFI);
    }
  }

  return 0;
}

int LLVMTool::ForceCallConv(void) {
  if (!IsCOFF)
    return 0;

  auto force_callconv = [&](llvm::Function *F) -> void {
    F->setCallingConv(llvm::CallingConv::X86_64_SysV);

    for (llvm::User *FU : llvm::make_early_inc_range(F->users())) {
      if (!llvm::isa<llvm::CallInst>(FU))
        continue;

      llvm::CallInst *CI = llvm::cast<llvm::CallInst>(FU);
      if (CI->getCalledFunction() != F)
        continue;

      CI->setCallingConv(llvm::CallingConv::X86_64_SysV);
    }
  };

  //
  // force callconv for ABI functions and _jove_thunk_*
  //
#define __THUNK(n, i, data)                                                    \
  JoveThunk##i##Func = Module->getFunction("_jove_thunk" #i);                  \
  if (JoveThunk##i##Func) {                                                    \
    assert(!JoveThunk##i##Func->empty());                                      \
    force_callconv(JoveThunk##i##Func);                                        \
  }

  BOOST_PP_REPEAT(BOOST_PP_INC(TARGET_NUM_REG_ARGS), __THUNK, void)

#undef __THUNK

  binary_t &Binary = jv.Binaries.at(BinaryIndex);
  for (function_t &f : Binary.Analysis.Functions) {
    if (!f.IsABI)
      continue;

    if (llvm::Function *F = state.for_function(f).F)
      force_callconv(F);
  }

  return 0;
}

int LLVMTool::WriteModule(void) {
  if (opts.VerifyBitcode) {
    if (llvm::verifyModule(*Module, &llvm::errs())) {
      WithColor::error() << "WriteModule: failed to verify module\n";

      DumpModule("pre.write.module");
      return 1;
    }
  }

  std::error_code EC;
  llvm::ToolOutputFile Out(opts.Output, EC, llvm::sys::fs::OF_None);
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
static Value *buildGEP(IRBuilderTy &IRB, std::pair<Value *, Type *> BasePtr,
                       SmallVectorImpl<Value *> &Indices,
                       const Twine &NamePrefix) {
  if (Indices.empty())
    return BasePtr.first;

  // A single zero index is a no-op, so check for this and avoid building a GEP
  // in that case.
  if (Indices.size() == 1 && cast<ConstantInt>(Indices.back())->isZero())
    return BasePtr.first;

  Type *ElementTy = BasePtr.first->getType()->isOpaquePointerTy()
                        ? BasePtr.second
                        : BasePtr.first->getType()->getNonOpaquePointerElementType();

  // buildGEP() is only called for non-opaque pointers.
  if (isa<Constant>(BasePtr.first))
    return llvm::ConstantExpr::getInBoundsGetElementPtr(
        ElementTy, cast<Constant>(BasePtr.first), Indices);
  else
    return IRB.CreateInBoundsGEP(ElementTy, BasePtr.first, Indices,
                                 NamePrefix + "sroa_idx");
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
                                    std::pair<Value *, Type *> BasePtr,
                                    Type *Ty, Type *TargetTy,
                                    SmallVectorImpl<Value *> &Indices,
                                    const Twine &NamePrefix) {
  if (Ty == TargetTy)
    return buildGEP(IRB, BasePtr, Indices, NamePrefix);

  // Offset size to use for the indices.
  unsigned OffsetSize = DL.getIndexTypeSizeInBits(BasePtr.first->getType());

  // See if we can descend into a struct and locate a field with the correct
  // type.
  unsigned NumLayers = 0;
  Type *ElementTy = Ty;
  do {
    if (ElementTy->isPointerTy())
      break;

    if (ArrayType *ArrayTy = dyn_cast<ArrayType>(ElementTy)) {
      ElementTy = ArrayTy->getElementType();
      Indices.push_back(IRB.getIntN(OffsetSize, 0));
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
                                      std::pair<Value *, Type *> Ptr,
                                      APInt Offset, Type *TargetTy,
                                      SmallVectorImpl<Value *> &Indices,
                                      const Twine &NamePrefix) {
  assert(isa<PointerType>(Ptr.first->getType()));
  PointerType *Ty = cast<PointerType>(Ptr.first->getType());

  // Don't consider any GEPs through an i8* as natural unless the TargetTy is
  // an i8.
  if (Ty == IRB.getInt8PtrTy(Ty->getAddressSpace()) && TargetTy->isIntegerTy(8))
    return nullptr;

  Type *ElementTy = Ty->isOpaquePointerTy()
                        ? Ptr.second
                        : Ty->getNonOpaquePointerElementType();
  if (!ElementTy || !ElementTy->isSized())
    return nullptr; // We can't GEP through an unsized element.

  SmallVector<APInt> IntIndices = DL.getGEPIndicesForOffset(ElementTy, Offset);
  if (Offset != 0)
    return nullptr;

  for (const APInt &Index : IntIndices)
    Indices.push_back(IRB.getInt(Index));
  return getNaturalGEPWithType(IRB, DL, Ptr, ElementTy, TargetTy, Indices,
                               NamePrefix);
}

} // namespace llvm

namespace jove {

typedef int (*translate_tcg_op_proc_t)(TCGOp *,
                                       llvm::BasicBlock *,
                                       llvm::IRBuilderTy &,
                                       TranslateContext &);

#if 0
static bool seenOpTable[ARRAY_SIZE(tcg_op_defs)];
#endif

int LLVMTool::TranslateBasicBlock(TranslateContext *ptrTC) {
  TranslateContext &TC = *ptrTC;
  auto &GlobalAllocaArr = TC.GlobalAllocaArr;
  auto &TempAllocaVec = TC.TempAllocaVec;
  auto &LabelVec = TC.LabelVec;
  basic_block_t bb = TC.bb;
  function_t &f = TC.f;

  binary_t &Binary = jv.Binaries.at(BinaryIndex);
  const auto &ICFG = Binary.Analysis.ICFG;

  const uint64_t Addr = ICFG[bb].Addr;
  const unsigned Size = ICFG[bb].Size;

  llvm::IRBuilderTy IRB(state.for_basic_block(Binary, bb).B);

  IRB.SetCurrentDebugLocation(llvm::DILocation::get(
      *Context, Addr, 0 /* Column */, TC.DebugInformation.Subprogram));

  //
  // helper functions for GlobalAllocaArr
  //
  auto set = [&](llvm::Value *V, unsigned glb) -> void {
    assert(glb != tcg_env_index);

    if (unlikely(PinnedEnvGlbs.test(glb))) {
      llvm::StoreInst *SI =
          IRB.CreateStore(V, BuildCPUStatePointer(IRB, CPUStateGlobal, glb));
      SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
      return;
    }

    llvm::AllocaInst *&Ptr = GlobalAllocaArr.at(glb);
    if (!Ptr) {
      llvm::IRBuilderTy tmpIRB(&state.for_function(f).F->getEntryBlock().front());

      Ptr = CreateAllocaForGlobal(TC, tmpIRB, glb);
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

    if (unlikely(PinnedEnvGlbs.test(glb))) {
      llvm::LoadInst *LI = IRB.CreateLoad(
          TypeOfTCGGlobal(glb), BuildCPUStatePointer(IRB, CPUStateGlobal, glb));
      LI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
      return LI;
    }

    llvm::AllocaInst *&Ptr = GlobalAllocaArr.at(glb);
    if (!Ptr) {
      llvm::IRBuilderTy tmpIRB(&state.for_function(f).F->getEntryBlock().front());

      Ptr = CreateAllocaForGlobal(TC, tmpIRB, glb);
    }

    llvm::LoadInst *LI = IRB.CreateLoad(TypeOfTCGGlobal(glb), Ptr);
    LI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
    return LI;
  };

  if (opts.Trace) {
    binary_index_t BIdx = BinaryIndex;
    basic_block_index_t BBIdx = index_of_basic_block(ICFG, bb);

    static_assert(sizeof(BIdx) == sizeof(uint32_t), "sizeof(BIdx)");
    static_assert(sizeof(BBIdx) == sizeof(uint32_t), "sizeof(BBIdx)");

    uint64_t comb =
        (static_cast<uint64_t>(BIdx) << 32) | static_cast<uint64_t>(BBIdx);

    llvm::LoadInst *PtrLoad = IRB.CreateLoad(IRB.getPtrTy(), TraceGlobal, true /* Volatile */);
    llvm::Value *PtrInc = IRB.CreateConstGEP1_64(IRB.getInt64Ty(), PtrLoad, 1);

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

  TCG->set_binary(*state.for_binary(Binary).Bin);

  llvm::BasicBlock *ExitBB = nullptr;

  unsigned size = 0;
  jove::terminator_info_t T;
  unsigned j = 0;
  do {
    ExitBB = llvm::BasicBlock::Create(
        *Context, (fmt("l%lx_%u_exit") % Addr % j).str(), state.for_function(f).F);
    ++j;

    bool ForAddrMatch = opts.DumpTCG && Addr == ForAddr;

    if (unlikely(ForAddrMatch))
      TCGLLVMUserBreakPoint();

    unsigned len;
    std::tie(len, T) = TCG->translate(Addr + size, Addr + Size);

    if (unlikely(ForAddrMatch))
      TCG->dump_operations();

    TCGContext *s = jv_get_tcg_context();

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
      TCGOp *op;
      QTAILQ_FOREACH(op, &s->ops, link) {
        TCGOpcode opc = op->opc;

        int nb_oargs, nb_iargs;
        if (opc == INDEX_op_call) {
          nb_oargs = TCGOP_CALLO(op);
          nb_iargs = TCGOP_CALLI(op);
        } else {
          nb_iargs = jv_tcgopc_nb_iargs_in_def(opc);
          nb_oargs = jv_tcgopc_nb_oargs_in_def(opc);
        }

        for (int i = 0; i < nb_iargs; ++i) {
          TCGTemp *ts = arg_temp(op->args[nb_oargs + i]);
          if (ts->kind == TEMP_GLOBAL)
            continue;

          unsigned idx = temp_idx(ts);
          if (idx == tcg_env_index)
            continue;

#if 0
          if (!(idx >= tcg_num_globals)) {
            char buf[256];
            HumanOut() << "WTF? "
                       << idx << " "
                       << jv_tcg_get_arg_str(buf, sizeof(buf),
                                             op->args[nb_oargs + i])
                       << '\n';
          }
#endif
          assert(idx >= tcg_num_globals);

          if (TempAllocaVec.at(idx))
            continue;

          {
            llvm::IRBuilderTy tmpIRB(&state.for_function(f).F->getEntryBlock().front());

            TempAllocaVec.at(idx) =
              tmpIRB.CreateAlloca(tmpIRB.getIntNTy(bitsOfTCGType(ts->type)), 0,
                                  (fmt("%#lx_%s%u")
                                   % ICFG[bb].Addr
                                   % "tmp"
                                   % (idx - tcg_num_globals)).str());
          }
        }

        for (int i = 0; i < nb_oargs; ++i) {
          TCGTemp *ts = arg_temp(op->args[i]);
          if (ts->kind == TEMP_GLOBAL)
            continue;

          unsigned idx = temp_idx(ts);
          if (idx == tcg_env_index)
            continue;

#if 0
          if (!(idx >= tcg_num_globals)) {
            char buf[256];
            HumanOut() << "WTF? "
                       << idx << " "
                       << jv_tcg_get_arg_str(buf, sizeof(buf), op->args[i])
                       << '\n';
          }
#endif
          assert(idx >= tcg_num_globals);

          if (TempAllocaVec.at(idx))
            continue;

          {
            llvm::IRBuilderTy tmpIRB(&state.for_function(f).F->getEntryBlock().front());

            TempAllocaVec.at(idx) =
              tmpIRB.CreateAlloca(tmpIRB.getIntNTy(bitsOfTCGType(ts->type)), 0,
                              (fmt("%#lx_%s%u")
                               % ICFG[bb].Addr
                               % "tmp"
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
          *Context, (boost::format("l%lx_%u") % ICFG[bb].Addr % i).str(), state.for_function(f).F);

    TCGOp *op;
    QTAILQ_FOREACH(op, &s->ops, link) {
#if 0
      unsigned opc = op->opc;

      if (unlikely(!seenOpTable[opc])) {
        WithColor::note() << llvm::formatv("[TCG opcode] {0}\n",
                                           tcg_op_defs[opc].name);

        seenOpTable[opc] = true;
      }
#endif

      int ret = TranslateTCGOp(op, ExitBB, IRB, TC);
      if (unlikely(ret)) {
        WithColor::warning() << "!TranslateTCGOp\n";
        TCG->dump_operations();
        return ret;
      }
    }

    if (!IRB.GetInsertBlock()->getTerminator()) {
#if 0
      if (IsVerbose())
        WithColor::warning() << "TranslateBasicBlock: no terminator in block\n";
#endif
      IRB.CreateBr(ExitBB);
    }

    IRB.SetInsertPoint(ExitBB);

    size += len;
  } while (size < Size);

  if (T.Type != ICFG[bb].Term.Type) {
    uintptr_t FuncAddr = ICFG[basic_block_of_index(f.Entry, ICFG)].Addr;

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
    IRB.CreateBr(state.for_basic_block(Binary, succ).B);
    return 0;
  }

  auto store_global_to_global_cpu_state = [&](unsigned glb) -> void {
    llvm::StoreInst *SI = IRB.CreateStore(
        get(glb), BuildCPUStatePointer(IRB, CPUStateGlobal, glb));
    SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
  };

  auto store_stack_pointer = [&](void) -> void {
    store_global_to_global_cpu_state(tcg_stack_pointer_index);
  };

  auto reload_global_from_global_cpu_state = [&](unsigned glb) -> void {
    llvm::LoadInst *LI = IRB.CreateLoad(
        TypeOfTCGGlobal(glb), BuildCPUStatePointer(IRB, CPUStateGlobal, glb));
    LI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);

    set(LI, glb);
  };

  auto reload_stack_pointer = [&](void) -> void {
    reload_global_from_global_cpu_state(tcg_stack_pointer_index);
  };

  struct {
    bool IsTailCall;
  } _indirect_jump;

  if (T.Type == TERMINATOR::INDIRECT_JUMP)
    _indirect_jump.IsTailCall = boost::out_degree(bb, ICFG) == 0;

  if (opts.CallStack) {
    switch (T.Type) {
    case TERMINATOR::RETURN:
      IRB.CreateStore(IRB.CreateConstGEP1_64(
                          IRB.getPtrTy(),
                          IRB.CreateLoad(IRB.getPtrTy(), CallStackGlobal), -1),
                      CallStackGlobal);
      break;

    case TERMINATOR::CALL:
    case TERMINATOR::INDIRECT_CALL: {
      binary_index_t BIdx = BinaryIndex;
      basic_block_index_t BBIdx = index_of_basic_block(ICFG, bb);

      static_assert(sizeof(BIdx) == sizeof(uint32_t), "sizeof(BIdx)");
      static_assert(sizeof(BBIdx) == sizeof(uint32_t), "sizeof(BBIdx)");

      uint64_t comb =
          (static_cast<uint64_t>(BIdx) << 32) | static_cast<uint64_t>(BBIdx);

      llvm::LoadInst *Ptr = IRB.CreateLoad(IRB.getPtrTy(), CallStackGlobal);
      IRB.CreateStore(IRB.getInt64(comb), Ptr);

      IRB.CreateStore(IRB.CreateConstGEP1_64(IRB.getPtrTy(), Ptr, 1), CallStackGlobal);
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
    if (!opts.CallStack)
      return;

    assert(!SavedCallStackP);
    assert(!SavedCallStackBegin);

    SavedCallStackP = IRB.CreateLoad(IRB.getPtrTy(), CallStackGlobal);
    SavedCallStackBegin = IRB.CreateLoad(IRB.getPtrTy(), CallStackBeginGlobal);

    assert(SavedCallStackP);
    assert(SavedCallStackBegin);
  };

  auto restore_callstack_pointers = [&](void) -> void {
    if (!opts.CallStack)
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

    //
    // setjmp/longjmp
    //
    const bool Lj = state.for_function(callee).IsLj;
    const bool Sj = state.for_function(callee).IsSj;
    const bool SjLj = Lj || Sj;
    if (unlikely(SjLj)) {
      assert(Lj ^ Sj);
      llvm::outs() << llvm::formatv("calling {0} {1:x} from {2:x} (call)\n",
                                    Lj ? "longjmp" : "setjmp",
                                    ICFG[basic_block_of_index(callee.Entry, ICFG)].Addr,
                                    ICFG[bb].Term.Addr);

#if defined(TARGET_I386)
      std::vector<llvm::Type *> argTypes(2, WordType());

      llvm::Value *CastedPtr = IRB.CreateIntToPtr(
          SectionPointer(ICFG[basic_block_of_index(callee.Entry, ICFG)].Addr),
          llvm::FunctionType::get(WordType(), argTypes, false)->getPointerTo());

      std::vector<llvm::Value *> ArgVec;

      {
        llvm::Value *SP = get(tcg_stack_pointer_index);

        ArgVec.push_back(IRB.CreateLoad(WordType(), IRB.CreateIntToPtr(
            IRB.CreateAdd(SP, IRB.getIntN(WordBits(), 1 * WordBytes())),
            WordType()->getPointerTo())));

        ArgVec.push_back(IRB.CreateLoad(WordType(), IRB.CreateIntToPtr(
            IRB.CreateAdd(SP, IRB.getIntN(WordBits(), 2 * WordBytes())),
            WordType()->getPointerTo())));

#if 0
        {
          std::string message =
              (fmt("doing %s (call) to %s @ %s+0x%x\n")
               % (Lj ? "longjmp" : "setjmp")
               % dyn_target_desc({BinaryIndex, FIdx})
               % fs::path(Binary.path_str()).filename().string()
               % ICFG[bb].Term.Addr).str();

          IRB.CreateCall(JoveLog2Func,
                         {IRB.CreateGlobalStringPtr(message.c_str()),
                          ArgVec.at(0),
                          ArgVec.at(1)});
        }
#endif
      }

      assert(ArgVec.size() == argTypes.size());
#else
      std::vector<llvm::Type *> argTypes(CallConvArgArray.size(), WordType());

      llvm::Value *CastedPtr = IRB.CreateIntToPtr(
          SectionPointer(ICFG[basic_block_of_index(callee.Entry, ICFG)].Addr),
          llvm::FunctionType::get(WordType(), argTypes, false)->getPointerTo());

      std::vector<llvm::Value *> ArgVec;
      ArgVec.resize(CallConvArgArray.size());

      std::transform(CallConvArgArray.begin(),
                     CallConvArgArray.end(),
                     ArgVec.begin(),
                     [&](unsigned glb) -> llvm::Value * {
                       return get(glb);
                     });
#endif

      if (opts.DebugSjlj) {
        std::string message =
            (fmt("doing %s (call) to %s @ %s+0x%x\n")
             % (Lj ? "longjmp" : "setjmp")
             % dyn_target_desc({BinaryIndex, FIdx})
             % fs::path(Binary.path_str()).filename().string()
             % ICFG[bb].Term.Addr).str();
        IRB.CreateCall(JoveLog1Func, {IRB.CreateGlobalStringPtr(message.c_str()), ArgVec.at(0)});
      }

      llvm::CallInst *Ret = IRB.CreateCall(
          llvm::FunctionType::get(WordType(), argTypes, false),
          CastedPtr, ArgVec);

      if (Sj) {
        set(Ret, CallConvRetArray.at(0));

#if defined(TARGET_X86_64) || defined(TARGET_I386)
        //
        // simulate return address being popped
        //
        set(IRB.CreateAdd(
                get(tcg_stack_pointer_index),
                llvm::ConstantInt::get(WordType(), WordBytes())),
            tcg_stack_pointer_index);
#endif
        break;
      } else {
        assert(Lj);
        IRB.CreateCall(
            llvm::Intrinsic::getDeclaration(Module.get(), llvm::Intrinsic::trap));
        IRB.CreateUnreachable();

        return 0;
      }
    }

    assert(!SjLj);

    if (opts.DFSan) {
      if (state.for_function(callee).PreHook) {
        assert(state.for_function(callee).hook);
        assert(state.for_function(callee).PreHookClunk);

        llvm::outs() << llvm::formatv("calling pre-hook ({0}, {1})\n",
                                      BinaryIndex,
                                      FIdx);

        const hook_t &hook = *state.for_function(callee).hook;

        std::vector<llvm::Value *> ArgVec;

        ArgVec.resize(hook.Args.size());
        std::transform(hook.Args.begin(),
                       hook.Args.end(),
                       ArgVec.begin(),
                       [&](const hook_t::arg_info_t &info) -> llvm::Value * {
                         llvm::Type *Ty = type_of_arg_info(info);
                         return llvm::Constant::getNullValue(Ty);
                       });
        IRB.CreateCall(
            state.for_function(callee).PreHook->getFunctionType(),
            IRB.CreateIntToPtr(
                IRB.CreateLoad(WordType(),
                               state.for_function(callee).PreHookClunk),
                state.for_function(callee).PreHook->getType()),
            ArgVec);
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

    if (opts.DFSan) {
      if (state.for_function(callee).PreHook ||
          state.for_function(callee).PostHook) {
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
        llvm::StoreInst *SI = IRB.CreateStore(
            get(glb), BuildCPUStatePointer(IRB, CPUStateGlobal, glb));
        SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
      }

      store_stack_pointer();
    }

    llvm::CallInst *Ret = IRB.CreateCall(state.for_function(callee).F, ArgVec);

    if (state.for_function(callee).PreHook ||
        state.for_function(callee).PostHook) {
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
      for (unsigned j = 0; j < std::min<unsigned>(3, Ret->getNumOperands() - 1); ++j)
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
              jv_get_tcg_context()->temps[glb].name + std::string("_"));

          set(Val, glb);
        }
      }
    }

    if (state.for_function(callee).PostHook) {
      assert(state.for_function(callee).hook);
      assert(state.for_function(callee).PostHookClunk);

      llvm::outs() << llvm::formatv("calling post-hook ({0}, {1})\n",
                                    BinaryIndex,
                                    FIdx);

      const hook_t &hook = *state.for_function(callee).hook;

      //
      // prepare arguments for post hook
      //
      std::vector<llvm::Value *> HookArgVec;
      HookArgVec.resize(hook.Args.size());

      {
        unsigned SPAddend = WordBytes();

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

            ArgVal = IRB.CreateLoad(
                IRB.getIntNTy(info.Size * 8),
                IRB.CreateIntToPtr(
                    IRB.CreateAdd(SP, IRB.getIntN(WordBits(), SPAddend)),
                    IRB.getIntNTy(info.Size * 8)->getPointerTo()));

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
      llvm::CallInst *PostHookRet = IRB.CreateCall(
          state.for_function(callee).PostHook->getFunctionType(),
          IRB.CreateIntToPtr(IRB.CreateLoad(WordType(), state.for_function(callee).PostHookClunk),
                             state.for_function(callee).PostHook->getType()),
          HookArgVec);

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
          llvm::BasicBlock::Create(*Context, (fmt("l%lx_recover") % Addr).str(),
                                   state.for_function(f).F);

      llvm::Value *PC = IRB.CreateLoad(WordType(), TC.PCAlloca);

      llvm::Value *SectsGlobalOff = IRB.CreateSub(
          PC, llvm::ConstantExpr::getPtrToInt(SectionsTop(), WordType()));

      auto it_pair = boost::adjacent_vertices(bb, ICFG);

      {
        llvm::SwitchInst *SI = IRB.CreateSwitch(SectsGlobalOff, ElseBlock,
                                                boost::out_degree(bb, ICFG));

        for (auto it = it_pair.first; it != it_pair.second; ++it) {
          basic_block_t succ = *it;
          SI->addCase(
              IRB.getIntN(WordBits(), ICFG[succ].Addr - state.for_binary(Binary).SectsStartAddr),
              state.for_basic_block(Binary, succ).B);
        }
      }

      IRB.SetInsertPoint(ElseBlock);

      llvm::Value *RecoverArgs[] = {IRB.getInt32(index_of_basic_block(ICFG, bb)), PC};
      llvm::Value *FailArgs[] = {PC, __jove_fail_UnknownBranchTarget};

      IRB.CreateCall(JoveRecoverBasicBlockFunc, RecoverArgs)->setIsNoInline();
      IRB.CreateCall(JoveRecoverDynTargetFunc, RecoverArgs)->setIsNoInline();
      IRB.CreateCall(JoveFail1Func, FailArgs)->setIsNoInline();
      IRB.CreateUnreachable();
      break;
    }

  case TERMINATOR::INDIRECT_CALL: {
    bool IsCall = T.Type == TERMINATOR::INDIRECT_CALL;
    const bool &DynTargetsComplete = ICFG[bb].DynTargetsComplete;

    llvm::Value *PC = IRB.CreateLoad(WordType(), TC.PCAlloca);
    if (!IsCall && ICFG[bb].Term._indirect_jump.IsLj) {
      llvm::outs() << llvm::formatv("longjmp at {0:x}\n", ICFG[bb].Addr);

      std::string message =
          (fmt("encountered longjmp @ %s+0x%x") %
           fs::path(Binary.path_str()).filename().string() % ICFG[bb].Term.Addr)
              .str();
      IRB.CreateCall(JoveFail1Func, {PC, IRB.CreateGlobalStringPtr(message.c_str())})->setIsNoInline();
      IRB.CreateUnreachable();
      return 0;
    }

    if (!ICFG[bb].hasDynTarget()) {
#if 0
      if (IsVerbose())
        WithColor::warning() << llvm::formatv(
            "indirect control transfer @ {0:x} has zero dyn targets\n",
            ICFG[bb].Addr);
#endif

      llvm::Value *RecoverArgs[] = {IRB.getInt32(index_of_basic_block(ICFG, bb)), PC};

      IRB.CreateCall(JoveRecoverDynTargetFunc, RecoverArgs)->setIsNoInline();
      if (!IsCall)
        IRB.CreateCall(JoveRecoverBasicBlockFunc, RecoverArgs)->setIsNoInline();
      IRB.CreateCall(JoveRecoverFunctionFunc, RecoverArgs)->setIsNoInline();
      IRB.CreateCall(JoveFail1Func, {PC, __jove_fail_UnknownCallee})->setIsNoInline();
      IRB.CreateUnreachable();

      return 0;
    }

    //
    // setjmp/longjmp
    //
    const bool Lj = std::any_of(ICFG[bb].dyn_targets_begin(),
                                ICFG[bb].dyn_targets_end(),
                                [&](dynamic_target_t X) -> bool {
                                  return state.for_function(function_of_target(X, jv)).IsLj;
                                });
    const bool Sj = std::any_of(ICFG[bb].dyn_targets_begin(),
                                ICFG[bb].dyn_targets_end(),
                                [&](dynamic_target_t X) -> bool {
                                  return state.for_function(function_of_target(X, jv)).IsSj;
                                });

    const bool SjLj = Lj || Sj;
    if (unlikely(SjLj)) {
      assert(Lj ^ Sj);

      dynamic_target_t X = *ICFG[bb].dyn_targets_begin();

      function_t &callee = function_of_target(X, jv);

      llvm::outs() << llvm::formatv("calling {0} from {1:x} ({2})\n",
                                    Lj ? "longjmp" : "setjmp",
                                    ICFG[bb].Term.Addr,
                                    IsCall ? "indcall" : "indjmp");

#if defined(TARGET_I386)
      std::vector<llvm::Type *> argTypes(2, WordType());

      llvm::Value *CastedPtr = IRB.CreateIntToPtr(
          GetDynTargetAddress<false>(IRB, X),
          llvm::FunctionType::get(WordType(), argTypes, false)->getPointerTo());

      std::vector<llvm::Value *> ArgVec;

      {
        llvm::Value *SP = get(tcg_stack_pointer_index);

        ArgVec.push_back(IRB.CreateLoad(WordType(), IRB.CreateIntToPtr(
            IRB.CreateAdd(SP, IRB.getIntN(WordBits(), 1 * sizeof(uint32_t))),
            WordType()->getPointerTo())));

        ArgVec.push_back(IRB.CreateLoad(WordType(), IRB.CreateIntToPtr(
            IRB.CreateAdd(SP, IRB.getIntN(WordBits(), 2 * sizeof(uint32_t))),
            WordType()->getPointerTo())));

#if 0
        {
          std::string message =
              (fmt("doing %s (%s) to %s @ %s+0x%x\n")
               % (Lj ? "longjmp" : "setjmp")
               % (IsCall ? "indcall" : "indjmp")
               % dyn_target_desc(X)
               % fs::path(Binary.path_str()).filename().string()
               % ICFG[bb].Term.Addr).str();

          IRB.CreateCall(JoveLog2Func,
                         {IRB.CreateGlobalStringPtr(message.c_str()),
                          ArgVec.at(0),
                          ArgVec.at(1)});
        }
#endif
      }

      assert(ArgVec.size() == argTypes.size());
#else
      std::vector<llvm::Type *> argTypes(CallConvArgArray.size(), WordType());

      llvm::Value *CastedPtr = IRB.CreateIntToPtr(
          GetDynTargetAddress<false>(IRB, X),
          llvm::FunctionType::get(WordType(), argTypes, false)->getPointerTo());

      std::vector<llvm::Value *> ArgVec;
      ArgVec.resize(CallConvArgArray.size());

      std::transform(CallConvArgArray.begin(),
                     CallConvArgArray.end(),
                     ArgVec.begin(),
                     [&](unsigned glb) -> llvm::Value * {
                       return get(glb);
                     });
#endif

      if (opts.DebugSjlj) {
        std::string message =
            (fmt("doing %s (%s) to %s @ %s+0x%x\n")
             % (Lj ? "longjmp" : "setjmp")
             % (IsCall ? "indcall" : "indjmp")
             % dyn_target_desc(X)
             % fs::path(Binary.path_str()).filename().string()
             % ICFG[bb].Term.Addr).str();
        IRB.CreateCall(JoveLog1Func, {IRB.CreateGlobalStringPtr(message.c_str()), ArgVec.at(0)});
      }

      llvm::CallInst *Ret = IRB.CreateCall(
          llvm::FunctionType::get(WordType(), argTypes, false),
          CastedPtr, ArgVec);

      if (Sj) {
        set(Ret, CallConvRetArray.at(0));

#if defined(TARGET_X86_64) || defined(TARGET_I386)
        //
        // simulate return address being popped
        //
        set(IRB.CreateAdd(
                get(tcg_stack_pointer_index),
                llvm::ConstantInt::get(WordType(), WordBytes())),
            tcg_stack_pointer_index);
#endif
        break;
      } else {
        assert(Lj);

        IRB.CreateCall(
            llvm::Intrinsic::getDeclaration(Module.get(), llvm::Intrinsic::trap));
        IRB.CreateUnreachable();

        return 0;
      }
    }

    assert(!SjLj);

    bool IsABICall = std::all_of(ICFG[bb].dyn_targets_begin(),
                                 ICFG[bb].dyn_targets_end(),
                                 [&](dynamic_target_t X) -> bool {
                                   return function_of_target(X, jv).IsABI;
                                 });
    if (opts.ABICalls && IsABICall)
    {
      llvm::Value *PC = IRB.CreateLoad(WordType(), TC.PCAlloca);

      std::vector<llvm::Type *> argTypes(CallConvArgArray.size()+1, WordType());

      std::vector<llvm::Value *> ArgVec;
      ArgVec.resize(CallConvArgArray.size());

      std::transform(CallConvArgArray.begin(),
                     CallConvArgArray.end(),
                     ArgVec.begin(),
                     [&](unsigned glb) -> llvm::Value * {
                       return get(glb);
                     });

      ArgVec.push_back(PC);
      ArgVec.push_back(IRB.getInt32(index_of_basic_block(ICFG, bb)));

      store_stack_pointer();
      save_callstack_pointers();

#if defined(TARGET_MIPS32) || defined(TARGET_MIPS64)
      store_global_to_global_cpu_state(tcg_t9_index);
      store_global_to_global_cpu_state(tcg_ra_index);
#endif

      llvm::CallInst *Ret = IRB.CreateCall(JoveCallFunc, ArgVec);
      Ret->setIsNoInline();

      restore_callstack_pointers();
      reload_stack_pointer();

#if defined(TARGET_I386)
      for (unsigned j = 0; j < std::min<unsigned>(3, Ret->getNumOperands() - 1); ++j)
        Ret->addParamAttr(j, llvm::Attribute::InReg);
#endif

#if defined(TARGET_X86_64)
      //assert(Ret->getType()->isIntegerTy(128));
      assert(Ret->getType()->isStructTy());
      {
        llvm::Value *X = IRB.CreateExtractValue(Ret, 0, jv_get_tcg_context()->temps[CallConvRetArray.at(0)].name + std::string("_"));
        llvm::Value *Y = IRB.CreateExtractValue(Ret, 1, jv_get_tcg_context()->temps[CallConvRetArray.at(1)].name + std::string("_"));

        set(X, CallConvRetArray.at(0));
        set(Y, CallConvRetArray.at(1));
      }
#elif defined(TARGET_MIPS64)
      assert(Ret->getType()->isIntegerTy(64));
      set(Ret, CallConvRetArray.front());
#elif defined(TARGET_AARCH64)
      assert(Ret->getType()->isIntegerTy(128));
      {
        llvm::Value *X =
            IRB.CreateTrunc(Ret, IRB.getInt64Ty(),
                            jv_get_tcg_context()->temps[CallConvRetArray.at(0)].name + std::string("_"));

        llvm::Value *Y = IRB.CreateTrunc(
            IRB.CreateLShr(Ret, IRB.getIntN(128, 64)), IRB.getInt64Ty(),
            jv_get_tcg_context()->temps[CallConvRetArray.at(1)].name + std::string("_"));

        set(X, CallConvRetArray.at(0));
        set(Y, CallConvRetArray.at(1));
      }
#elif defined(TARGET_MIPS32) || defined(TARGET_I386)
      assert(Ret->getType()->isIntegerTy(64));
      {
        llvm::Value *X =
            IRB.CreateTrunc(Ret, IRB.getInt32Ty(),
                            jv_get_tcg_context()->temps[CallConvRetArray.at(0)].name + std::string("_"));

        llvm::Value *Y = IRB.CreateTrunc(
            IRB.CreateLShr(Ret, IRB.getInt64(32)), IRB.getInt32Ty(),
            jv_get_tcg_context()->temps[CallConvRetArray.at(1)].name + std::string("_"));

#ifdef TARGET_WORDS_BIGENDIAN
        set(X, CallConvRetArray.at(1));
        set(Y, CallConvRetArray.at(0));
#else
        set(X, CallConvRetArray.at(0));
        set(Y, CallConvRetArray.at(1));
#endif
      }
#else
#error
#endif
    }
    else
    {
      assert(ICFG[bb].hasDynTarget());

      llvm::Value *PC = IRB.CreateLoad(WordType(), TC.PCAlloca);

      llvm::BasicBlock *ThruB = llvm::BasicBlock::Create(*Context, "", state.for_function(f).F);

      std::vector<std::pair<binary_index_t, function_index_t>> DynTargetsVec(
          ICFG[bb].dyn_targets_begin(),
          ICFG[bb].dyn_targets_end());

      std::vector<llvm::BasicBlock *> DynTargetsDoCallBVec;
      DynTargetsDoCallBVec.resize(DynTargetsVec.size());

      std::transform(DynTargetsVec.begin(),
                     DynTargetsVec.end(),
                     DynTargetsDoCallBVec.begin(),
                     [&](dynamic_target_t IdxPair) -> llvm::BasicBlock * {
                       return llvm::BasicBlock::Create(*Context,
                                                       (fmt("call_%s") % dyn_target_desc(IdxPair)).str(), state.for_function(f).F);
                     });

      llvm::BasicBlock *ElseB = nullptr;
      {
        unsigned i = 0;

        llvm::BasicBlock *B = llvm::BasicBlock::Create(
            *Context, (fmt("if_%s") % dyn_target_desc(DynTargetsVec[i])).str(),
            state.for_function(f).F);
        IRB.CreateBr(B);

        do {
          IRB.SetInsertPoint(B);

          auto next_i = i + 1;
          if (next_i == DynTargetsVec.size())
            B = llvm::BasicBlock::Create(*Context, "", state.for_function(f).F);
          else
            B = llvm::BasicBlock::Create(
                *Context,
                (fmt("if_%s") % dyn_target_desc(DynTargetsVec[next_i])).str(),
                state.for_function(f).F);

          llvm::Value *EQVal = IRB.CreateICmpEQ(
              PC, GetDynTargetAddress<false>(IRB, DynTargetsVec[i], B));
          IRB.CreateCondBr(EQVal, DynTargetsDoCallBVec[i], B);
        } while (++i != DynTargetsVec.size());

        ElseB = B;
      }

      assert(ElseB);

      {
        IRB.SetInsertPoint(ElseB);

        llvm::Value *RecoverArgs[] = {IRB.getInt32(index_of_basic_block(ICFG, bb)), PC};
        llvm::Value *FailArgs[] = {PC, __jove_fail_UnknownCallee};

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

          function_t &callee = function_of_target(DynTargetsVec[i], jv);

          const bool Lj = state.for_function(callee).IsLj;
          const bool Sj = state.for_function(callee).IsSj;
          const bool SjLj = Lj || Sj;

          if (unlikely(SjLj)) {
            assert(Lj ^ Sj);
            llvm::outs() << llvm::formatv("calling {0} from {1:x} (indjmp/indcall)\n",
                                          Lj ? "longjmp" : "setjmp",
                                          ICFG[bb].Addr);
          }

          struct {
            std::vector<llvm::Value *> SavedArgs;
          } _dfsan_hook;

          if (opts.DFSan) {
            if (state.for_function(callee).PreHook ||
                state.for_function(callee).PostHook) {
              assert(state.for_function(callee).hook);
              const hook_t &hook = *state.for_function(callee).hook;

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

          if (opts.DFSan) {
            if (state.for_function(callee).PreHook) {
              assert(state.for_function(callee).hook);
              assert(state.for_function(callee).PreHookClunk);

              llvm::outs() << llvm::formatv("calling pre-hook ({0}, {1})\n",
                                            ADynTarget.BIdx, ADynTarget.FIdx);

              const hook_t &hook = *state.for_function(callee).hook;

              //
              // prepare arguments for post hook
              //
              std::vector<llvm::Value *> HookArgVec;
              HookArgVec.resize(hook.Args.size());

              {
                unsigned SPAddend = sizeof(uint64_t);

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

                    ArgVal = IRB.CreateLoad(
                        IRB.getIntNTy(info.Size * 8),
                        IRB.CreateIntToPtr(
                            IRB.CreateAdd(SP, IRB.getIntN(WordBits(), SPAddend)),
                            IRB.getIntNTy(info.Size * 8)->getPointerTo()));

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
                  state.for_function(callee).PreHook->getFunctionType(),
                  IRB.CreateIntToPtr(IRB.CreateLoad(WordType(), state.for_function(callee).PreHookClunk),
                                     state.for_function(callee).PreHook->getType()),
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
              ArgVec.push_back(BuildCPUStatePointer(IRB, CPUStateGlobal, tcg_stack_pointer_index));

              llvm::Function *const JoveThunkFuncArray[] = {
#define __THUNK(n, i, data) JoveThunk##i##Func,

BOOST_PP_REPEAT(BOOST_PP_INC(TARGET_NUM_REG_ARGS), __THUNK, void)

#undef __THUNK
              };

              assert(glbv.size() < ARRAY_SIZE(JoveThunkFuncArray));

              llvm::Function *ThunkF = JoveThunkFuncArray[glbv.size()];
              llvm::FunctionType *ThunkFTy = ThunkF->getFunctionType();
              llvm::Value *ThunkFVal = ThunkF;

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

                ThunkFTy = llvm::FunctionType::get(ResultType, ThunkFTy->params(), false);
                llvm::PointerType *CastFTy = ThunkFTy->getPointerTo();
                ThunkFVal = IRB.CreatePointerCast(ThunkF, CastFTy);
              }
#endif

              Ret = IRB.CreateCall(ThunkFTy, ThunkFVal, ArgVec);
              Ret->setIsNoInline();
            }

#if defined(TARGET_I386)
            for (unsigned j = 0; j < std::min<unsigned>(3, Ret->getNumOperands() - 1); ++j)
              Ret->addParamAttr(j, llvm::Attribute::InReg);
#endif

            //
            // callstack stuff
            //
            restore_callstack_pointers();
            reload_stack_pointer();

            if (opts.CallStack)
              IRB.CreateStore(
                  IRB.CreateConstGEP1_64(IRB.getPtrTy(),
                                         IRB.CreateLoad(IRB.getPtrTy(), CallStackGlobal), -1),
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
                llvm::StoreInst *SI = IRB.CreateStore(get(glb), BuildCPUStatePointer(IRB, CPUStateGlobal, glb));
                SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
              }

              store_stack_pointer();
            }

            Ret = IRB.CreateCall(
                DetermineFunctionType(callee),
                IRB.CreateIntToPtr(
                    GetDynTargetAddress<true>(IRB, DynTargetsVec[i]),
                    llvm::PointerType::get(DetermineFunctionType(callee), 0)),
                ArgVec);

            if (callee.IsABI) {
#if defined(TARGET_I386)
              //
              // on i386 ABIs have first three registers
              //
              for (unsigned j = 0; j < std::min<unsigned>(3, Ret->getNumOperands() - 1); ++j)
                Ret->addParamAttr(j, llvm::Attribute::InReg);
#endif

              reload_stack_pointer();
            }
          }

          if (state.for_function(callee).PreHook ||
              state.for_function(callee).PostHook) {
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
              llvm::Value *X = IRB.CreateExtractValue(
                  Ret, 0, jv_get_tcg_context()->temps[CallConvRetArray.at(0)].name + std::string("_"));
              llvm::Value *Y = IRB.CreateExtractValue(
                  Ret, 1, jv_get_tcg_context()->temps[CallConvRetArray.at(1)].name + std::string("_"));

              set(X, CallConvRetArray.at(0));
              set(Y, CallConvRetArray.at(1));
            }
#elif defined(TARGET_MIPS64)
            assert(Ret->getType()->isIntegerTy(64));
            set(Ret, CallConvRetArray.front());
#elif defined(TARGET_AARCH64)
            assert(Ret->getType()->isStructTy());

            for (unsigned j = 0; j < CallConvRetArray.size(); ++j) {
              llvm::Value *X = IRB.CreateExtractValue(
                  Ret, j, jv_get_tcg_context()->temps[CallConvRetArray.at(j)].name + std::string("_"));
              set(X, CallConvRetArray.at(j));
            }
#elif defined(TARGET_MIPS32) || defined(TARGET_I386)
            assert(Ret->getType()->isIntegerTy(64));
            {
              llvm::Value *X = IRB.CreateTrunc(
                  Ret, IRB.getInt32Ty(),
                  jv_get_tcg_context()->temps[CallConvRetArray.at(0)].name + std::string("_"));

              llvm::Value *Y = IRB.CreateTrunc(
                  IRB.CreateLShr(Ret, IRB.getInt64(32)), IRB.getInt32Ty(),
                  jv_get_tcg_context()->temps[CallConvRetArray.at(1)].name + std::string("_"));

#ifdef TARGET_WORDS_BIGENDIAN
              set(X, CallConvRetArray.at(1));
              set(Y, CallConvRetArray.at(0));
#else
              set(X, CallConvRetArray.at(0));
              set(Y, CallConvRetArray.at(1));
#endif
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

                  llvm::Value *Val =
                      IRB.CreateExtractValue(Ret, llvm::ArrayRef<unsigned>(i),
                                             jv_get_tcg_context()->temps[glb].name + std::string("_"));

                  set(Val, glb);
                }
              }
            }
          }

          if (state.for_function(callee).PostHook) {
            assert(state.for_function(callee).hook);
            assert(state.for_function(callee).PostHookClunk);

            llvm::outs() << llvm::formatv("calling post-hook ({0}, {1})\n",
                                          ADynTarget.BIdx, ADynTarget.FIdx);

            const hook_t &hook = *state.for_function(callee).hook;

            //
            // prepare arguments for post hook
            //
            std::vector<llvm::Value *> HookArgVec;
            HookArgVec.resize(hook.Args.size());

            {
              unsigned SPAddend = sizeof(uint64_t);

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

                  ArgVal = IRB.CreateLoad(
                      IRB.getIntNTy(info.Size * 8),
                      IRB.CreateIntToPtr(
                          IRB.CreateAdd(SP, IRB.getIntN(WordBits(), SPAddend)),
                          IRB.getIntNTy(info.Size * 8)->getPointerTo()));

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
                state.for_function(callee).PostHook->getFunctionType(),
                IRB.CreateIntToPtr(
                    IRB.CreateLoad(WordType(),
                                   state.for_function(callee).PostHookClunk),
                    state.for_function(callee).PostHook->getType()),
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

  if (T.Type == TERMINATOR::RETURN && opts.CheckEmulatedReturnAddress) {
    assert(JoveCheckReturnAddrFunc);

    llvm::Value *NativeRetAddr =
        IRB.CreateCall(llvm::Intrinsic::getDeclaration(
                           Module.get(), llvm::Intrinsic::returnaddress),
                       IRB.getInt32(0));

#if defined(TARGET_X86_64) || defined(TARGET_I386)
    llvm::Value *Args[] = {IRB.CreateLoad(WordType(), TC.PCAlloca),
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

    llvm::Value *PC = IRB.CreateLoad(WordType(), TC.PCAlloca);
    llvm::Value *EQV = IRB.CreateICmpEQ(
        PC, IRB.getIntN(WordBits(), ICFG[succ1].Addr));
    IRB.CreateCondBr(EQV,
                     state.for_basic_block(Binary, succ1).B,
                     state.for_basic_block(Binary, succ2).B);
    break;
  }

  case TERMINATOR::CALL:
  case TERMINATOR::INDIRECT_CALL: {
    auto eit_pair = boost::out_edges(bb, ICFG);
    if (eit_pair.first == eit_pair.second) { /* otherwise fallthrough */
      IRB.CreateCall(JoveRecoverReturnedFunc, IRB.getInt32(index_of_basic_block(ICFG, bb)))->setIsNoInline();
      IRB.CreateCall(llvm::Intrinsic::getDeclaration(Module.get(), llvm::Intrinsic::trap));
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
    IRB.CreateBr(state.for_basic_block(Binary, succ).B);
    break;
  }

  case TERMINATOR::INDIRECT_JUMP:
    if (!_indirect_jump.IsTailCall) /* otherwise fallthrough */
      break;

  case TERMINATOR::RETURN: {
    if (opts.DFSan && false /* opts.Paranoid */)
      IRB.CreateCall(
          DFSanFiniFunc->getFunctionType(),
          IRB.CreateIntToPtr(IRB.CreateLoad(IRB.getPtrTy(), DFSanFiniClunk),
                             DFSanFiniFunc->getType()));

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
            std::string nm = std::string("_ret_") + jv_get_tcg_context()->temps[glb].name + std::string("_");

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

llvm::Value *LLVMTool::insertThreadPointerInlineAsm(llvm::IRBuilderTy &IRB) {
  const bool UseTPIntrinsic = /* IsELF || */ opts.ForCBE;
  if (UseTPIntrinsic) {
    llvm::Function *TPIntrinsic = llvm::Intrinsic::getDeclaration(
        Module.get(), llvm::Intrinsic::thread_pointer);
    assert(TPIntrinsic);
    return IRB.CreatePtrToInt(IRB.CreateCall(TPIntrinsic), WordType());
  }

  llvm::InlineAsm *IA;
  {
    llvm::FunctionType *AsmFTy =
        llvm::FunctionType::get(WordType(), false);

    llvm::StringRef AsmText;
    llvm::StringRef Constraints;

#if defined(TARGET_X86_64)
    if (IsCOFF)
      AsmText = "movq \%gs:0x30,$0";
    else
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

std::string LLVMTool::dyn_target_desc(dynamic_target_t IdxPair) {
  struct {
    binary_index_t BIdx;
    function_index_t FIdx;
  } DynTarget;

  std::tie(DynTarget.BIdx, DynTarget.FIdx) = IdxPair;

  binary_t &b = jv.Binaries.at(DynTarget.BIdx);
  function_t &f = b.Analysis.Functions.at(DynTarget.FIdx);

  uint64_t Addr =
      b.Analysis.ICFG[basic_block_of_index(f.Entry, b.Analysis.ICFG)].Addr;

  return (fmt("%s+%#lx") % fs::path(b.path_str()).filename().string() % Addr).str();
}

int LLVMTool::TranslateTCGOp(TCGOp *op,
                             llvm::BasicBlock *ExitBB,
                             llvm::IRBuilderTy &IRB,
                             TranslateContext &TC) {
  function_t &f = TC.f;
  basic_block_t bb = TC.bb;
  auto &GlobalAllocaArr = TC.GlobalAllocaArr;
  auto &TempAllocaVec = TC.TempAllocaVec;
  auto &LabelVec = TC.LabelVec;

  binary_t &Binary = TC.tool.jv.Binaries.at(TC.tool.BinaryIndex);
  const auto &ICFG = Binary.Analysis.ICFG;
  auto &PCAlloca = TC.PCAlloca;
  TCGContext *s = jv_get_tcg_context();

  auto set = [&](llvm::Value *V, TCGTemp *ts) -> void {
    assert(ts->kind != TEMP_CONST);

    unsigned idx = temp_idx(ts);
    assert(idx != tcg_env_index);

    if (V->getType()->isPointerTy())
      V = IRB.CreatePtrToInt(V, WordType());

    V = IRB.CreateIntCast(V, IRB.getIntNTy(bitsOfTCGType(ts->type)), false);

    if (ts->kind == TEMP_GLOBAL) {
      if (unlikely(PinnedEnvGlbs.test(idx))) {
        llvm::StoreInst *SI =
            IRB.CreateStore(V, BuildCPUStatePointer(IRB, CPUStateGlobal, idx));
        SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
        return;
      }

      llvm::AllocaInst *&Ptr = GlobalAllocaArr.at(idx);
      if (!Ptr) {
        llvm::IRBuilderTy tmpIRB(&state.for_function(f).F->getEntryBlock().front());

        Ptr = CreateAllocaForGlobal(TC, tmpIRB, idx);
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

  auto immediate_constant = [&](unsigned bits, TCGArg A) -> llvm::Value * {
    if (!pcrel_flag)
      return llvm::ConstantInt::get(llvm::Type::getIntNTy(*Context, bits), A);

    pcrel_flag = false; /* reset pcrel flag */
    assert(bits == WordBits());

    return llvm::ConstantExpr::getAdd(
        llvm::ConstantExpr::getPtrToInt(SectionsTop(), WordType()),
        llvm::ConstantExpr::getSub(
            llvm::ConstantInt::get(WordType(), A),
            llvm::ConstantInt::get(WordType(), state.for_binary(Binary).SectsStartAddr)));
  };

  auto get = [&](TCGTemp *ts) -> llvm::Value * {
    if (ts->kind == TEMP_CONST)
      return immediate_constant(bitsOfTCGType(ts->type), ts->val);

    unsigned idx = temp_idx(ts);
    switch (idx) {
    case tcg_env_index:
      return IRB.CreatePtrToInt(CPUStateGlobal, WordType());
#if defined(TARGET_X86_64)
    case tcg_fs_base_index:
#endif
#if defined(TARGET_X86_64) || defined(TARGET_I386)
    case tcg_gs_base_index:
#endif
      return insertThreadPointerInlineAsm(IRB);
    }

    if (ts->kind == TEMP_GLOBAL) {
      if (unlikely(PinnedEnvGlbs.test(idx))) {
        llvm::LoadInst *LI =
            IRB.CreateLoad(TypeOfTCGType(ts->type),
                           BuildCPUStatePointer(IRB, CPUStateGlobal, idx));
        LI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
        return LI;
      }

      llvm::AllocaInst *&Ptr = GlobalAllocaArr.at(idx);
      if (!Ptr) {
        llvm::IRBuilderTy tmpIRB(&state.for_function(f).F->getEntryBlock().front());

        Ptr = CreateAllocaForGlobal(TC, tmpIRB, idx);
      }

      llvm::LoadInst *LI = IRB.CreateLoad(TypeOfTCGType(ts->type), Ptr);
      LI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
      return LI;
    } else {
      llvm::AllocaInst *Ptr = TempAllocaVec.at(idx);
      assert(Ptr);

      llvm::LoadInst *LI = IRB.CreateLoad(TypeOfTCGType(ts->type), Ptr);
      LI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
      return LI;
    }
  };

  TCGOpcode opc = op->opc;

#if 0
  if (opc >= ARRAY_SIZE(tcg_op_defs))
    return 1;

  const TCGOpDef &def = tcg_op_defs[opc];
#endif

  int nb_oargs = jv_tcgopc_nb_oargs_in_def(opc);
  int nb_iargs = jv_tcgopc_nb_iargs_in_def(opc);
  int nb_cargs = jv_tcgopc_nb_cargs_in_def(opc);

#if 0
  if (IsVerbose())
    HumanOut() << llvm::formatv("{0} {1}:{2}:{3}\n",
                                jv_tcgopc_name_in_def(opc),
                                nb_oargs, nb_iargs, nb_cargs);
#endif

  auto output_arg = [&](int i) -> TCGTemp * {
    assert(i < nb_oargs);
    return arg_temp(op->args[i]);
  };
  auto input_arg = [&](int i) -> TCGTemp * {
    assert(i < nb_iargs);
    return arg_temp(op->args[nb_oargs + i]);
  };
  auto const_arg = [&](int i) -> TCGArg {
    assert(i < nb_cargs);
    return op->args[nb_oargs + nb_iargs + i];
  };

  /* Set two 32 bit registers from a 64 bit value. */
  auto write_reg64 = [&](TCGTemp *high, TCGTemp *low, llvm::Value *value) -> void {
    assert(TCG_TARGET_REG_BITS == 32);
    assert(value->getType()->isIntegerTy(64));

    set(IRB.CreateTrunc(value, IRB.getInt32Ty()), low);
    set(IRB.CreateTrunc(IRB.CreateLShr(value, IRB.getInt64(32)),
                        IRB.getInt32Ty()), high);
  };

  /* Create a 64 bit value from two 32 bit values. */
  auto uint64 = [&](llvm::Value *high, llvm::Value *low) -> llvm::Value * {
    assert(high->getType()->isIntegerTy(32));
    assert(low->getType()->isIntegerTy(32));

    return IRB.CreateAdd(
        IRB.CreateShl(IRB.CreateZExt(high, IRB.getInt64Ty()), IRB.getInt64(32)),
        IRB.CreateZExt(low, IRB.getInt64Ty()));
  };

  auto do_qemu_ld = [&](llvm::Value *Addr, MemOpIdx oi) -> llvm::Value * {
    MemOp mop = get_memop(oi);

    Addr = IRB.CreateZExt(Addr, WordType());

    Addr = IRB.CreateIntToPtr(                                             
        Addr, llvm::PointerType::get(IRB.getIntNTy(BitsOfMemOp(mop)), 0));

    llvm::LoadInst *LI = IRB.CreateLoad(IRB.getIntNTy(BitsOfMemOp(mop)), Addr);
    LI->setMetadata(llvm::LLVMContext::MD_noalias, AliasScopeMetadata);

    llvm::Value *Res = LI;

#ifndef TARGET_WORDS_BIGENDIAN /* XXX */
    if (mop & MO_BSWAP)
      Res = IRB.CreateCall(bswap_i(BitsOfMemOp(mop)), Res);
#endif

    Res = IRB.CreateIntCast(Res, IRB.getInt64Ty(), !!(mop & MO_SIGN));
    return Res;
  };

  auto do_qemu_st = [&](llvm::Value *Addr, llvm::Value *Val, MemOpIdx oi) -> void {
    assert(Val->getType()->isIntegerTy(64));

    MemOp mop = get_memop(oi);
    assert(!(mop & MO_SIGN));

    Val = IRB.CreateTrunc(Val, IRB.getIntNTy(BitsOfMemOp(mop)));

#ifndef TARGET_WORDS_BIGENDIAN /* XXX */
    if (mop & MO_BSWAP)
      Val = IRB.CreateCall(bswap_i(BitsOfMemOp(mop)), Val);
#endif

    Addr = IRB.CreateZExt(Addr, WordType());
    Addr = IRB.CreateIntToPtr(
        Addr, llvm::PointerType::get(IRB.getIntNTy(BitsOfMemOp(mop)), 0));

    llvm::StoreInst *St = IRB.CreateStore(Val, Addr);
    St->setMetadata(llvm::LLVMContext::MD_noalias, AliasScopeMetadata);
  };

  auto do_ld_or_store = [&](bool IsLoad, unsigned bits, bool Signed) -> void {
    TCGArg off = const_arg(0);
    TCGTemp *ptr_tmp = input_arg(IsLoad ? 0 : 1);

    if (temp_idx(ptr_tmp) == tcg_env_index) {
      if (IsLoad) {
        TCGTemp *dst = output_arg(0);

        switch (off) {
#if defined(TARGET_MIPS32) || defined(TARGET_MIPS64)
        case offsetof(CPUMIPSState, active_tc.CP0_UserLocal):
          set(insertThreadPointerInlineAsm(IRB), dst);
          return;
        case offsetof(CPUMIPSState, lladdr):
          set(get(&s->temps[tcg_lladdr_index]), dst);
          return;
        case offsetof(CPUMIPSState, llval):
          set(get(&s->temps[tcg_llval_index]), dst);
          return;
        case offsetof(CPUMIPSState, error_code):
          break;
#elif defined(TARGET_X86_64)
        case offsetof(CPUX86State, df):
          break;
#elif defined(TARGET_AARCH64)
        case offsetof(CPUARMState, vfp.zregs[0])...offsetof(CPUARMState, vfp.zregs[32]) - 1:
          break;
        case offsetof(CPUARMState, cp15.tpidr_el[0]):
          set(insertThreadPointerInlineAsm(IRB), dst);
          return;
#endif

        default:
          if (IsVerbose())
            curiosity("load(env+" + std::to_string(off) + ") @ " +
                      taddr2str(lstaddr, false));
          break;
        }
      } else {
        switch (off) {
#if defined(TARGET_MIPS32) || defined(TARGET_MIPS64)
        case offsetof(CPUMIPSState, lladdr):
          set(get(input_arg(0)), &s->temps[tcg_lladdr_index]);
          return;
        case offsetof(CPUMIPSState, llval):
          set(get(input_arg(0)), &s->temps[tcg_llval_index]);
          return;
        case offsetof(CPUMIPSState, error_code):
          break;
#elif defined(TARGET_X86_64)
        case offsetof(CPUX86State, df):
          break;
#elif defined(TARGET_AARCH64)
        case offsetof(CPUARMState, vfp.zregs[0])...offsetof(CPUARMState, vfp.zregs[32]) - 1:
          break;
        case offsetof(CPUARMState, btype):
          break;
#endif

        default:
          if (IsVerbose())
            curiosity("store(env+" + std::to_string(off) + ") @ " +
                      taddr2str(lstaddr, false));
          break;
        }
      }
    }

    llvm::Value *ptr = get(ptr_tmp);

    ptr = IRB.CreateZExt(ptr, WordType());
    ptr = IRB.CreateAdd(ptr, IRB.getIntN(WordBits(), off));

    ptr = IRB.CreateIntToPtr(
        ptr, llvm::PointerType::get(IRB.getIntNTy(bits), 0));

    if (IsLoad) {
      llvm::LoadInst *LI = IRB.CreateLoad(IRB.getIntNTy(bits), ptr);

      llvm::Value *Casted = IRB.CreateIntCast(
          LI,
          IRB.getIntNTy(bitsOfTCGType(s->temps[temp_idx(output_arg(0))].type)),
          Signed);

      set(Casted, output_arg(0));
    } else {
      llvm::Value *Casted =
          IRB.CreateIntCast(get(input_arg(0)), IRB.getIntNTy(bits), Signed);
      IRB.CreateStore(Casted, ptr);
    }
  };

  auto do_extract = [&](unsigned bits, bool Signed) -> void {
    assert(bits == 32 || bits == 64);

    TCGArg start = const_arg(0);
    TCGArg length = const_arg(1);

    assert(start >= 0 && length > 0 && length <= bits - start);

    if (Signed) {
      set(IRB.CreateAShr(
              IRB.CreateShl(get(input_arg(0)),
                            IRB.getIntN(bits, bits - length - start)),
              IRB.getIntN(bits, bits - length)),
          output_arg(0));
    } else {
      set(IRB.CreateAnd(
              IRB.CreateLShr(get(input_arg(0)), IRB.getIntN(bits, start)),
              IRB.getIntN(bits, ~0ULL >> (bits - length))),
          output_arg(0));
    }
  };

  llvm::Value *taddr = nullptr;
  llvm::Value *tmp64 = nullptr;


#if TCG_TARGET_REG_BITS == 64
#define CASE_32_64(x)                                                          \
  case INDEX_op_##x##_i64:                                                     \
  case INDEX_op_##x##_i32:
#define CASE_64(x)                                                             \
  case INDEX_op_##x##_i64:
#else
#define CASE_32_64(x)                                                          \
  case INDEX_op_##x##_i32:
# define CASE_64(x)
#endif

  switch (opc) {
  case INDEX_op_insn_start:
    if (const_arg(0) == JOVE_PCREL_MAGIC) {
      pcrel_flag = true;

      if (opts.PrintPCRel)
        WithColor::note() << "PC-relative expression @ "
                          << (fmt("%#lx") % lstaddr).str() << '\n';
    } else {
      pcrel_flag = false;

      uint64_t Addr = op->args[0];

#if 0
      if (IsVerbose())
        HumanOut() << llvm::formatv("insn @ {0:x}\n", Addr);
#endif

      lstaddr = Addr;

      unsigned Line = Addr;

      /* FIXME line and column numbers are 32 bits each; on 64-bit encode VA
       * as one half line, one half column */
      IRB.SetCurrentDebugLocation(llvm::DILocation::get(
          *Context, Line, 0 /* Column */, TC.DebugInformation.Subprogram));
    }
    break;

  case INDEX_op_discard: {
    // FIXME
#if 0
    TCGTemp *dst = arg_temp(op->args[0]);
    unsigned idx = temp_idx(dst);

    llvm::Type *Ty = IRB.getIntNTy(bitsOfTCGType(s->temps[idx].type));
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
    const char *helper_nm = jv_tcg_find_helper(op);

    //
    // some helper functions are special-cased
    //
    if (strcmp(helper_nm, "lookup_tb_ptr") == 0) /* FIXME */
      break;

    const helper_function_t &hf = LookupHelper(*Module, *TCG, op, opts.DFSan, opts.ForCBE, *this);
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

        if (hf.Analysis.Simple && opts.Optimize && opts.InlineHelpers)
          ArgVec.push_back(IRB.CreatePointerCast(IRB.CreateAlloca(CPUStateType), ParamTy));
        else
          ArgVec.push_back(IRB.CreatePointerCast(CPUStateGlobal, ParamTy));

        ++iarg_idx;

        if (ts->type == TCG_TYPE_I32 && sizeof(TCGArg) == sizeof(uint64_t)) {
          if (IsVerbose())
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
          if (IsVerbose())
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
      explode_tcg_global_set(glbv, (hf.Analysis.InGlbs | hf.Analysis.OutGlbs) & ~PinnedEnvGlbs);
      for (unsigned glb : glbv) {
        llvm::StoreInst *SI = IRB.CreateStore(get(&s->temps[glb]), BuildCPUStatePointer(IRB, Env, glb));
        SI->setMetadata(llvm::LLVMContext::MD_alias_scope, AliasScopeMetadata);
      }
    }

#if 0
    llvm::errs() << "calling " << hf.F->getName() << " with ";
    for (llvm::Value *Arg : ArgVec)
      llvm::errs() << *Arg << ' ';
    llvm::errs() << '\n';
#endif

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
      explode_tcg_global_set(glbv, hf.Analysis.OutGlbs & ~PinnedEnvGlbs);
      for (unsigned glb : glbv) {
        llvm::LoadInst *LI = IRB.CreateLoad(
            TypeOfTCGGlobal(glb), BuildCPUStatePointer(IRB, Env, glb));
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

#if 1
  case INDEX_op_mov_i64:
  case INDEX_op_mov_i32:
    set(get(input_arg(0)), output_arg(0));
    break;
#else

  case INDEX_op_mov_i32: {
    assert(nb_iargs == 1);
    assert(nb_oargs == 1);

    TCGTemp *dst = arg_temp(op->args[0]);
    TCGTemp *src = arg_temp(op->args[1]);

    if (likely(src->type == dst->type)) {
      set(get(src), dst);
    } else {
      //WithColor::warning() << llvm::formatv("[INDEX_op_mov_i32] {0} (i32)={1} (i64)\n", dst->name ?: "_", src->name ?: "_");
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
#endif

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

  case INDEX_op_qemu_ld_a32_i32:
    taddr = IRB.CreateIntCast(get(input_arg(0)), IRB.getInt32Ty(), false);
    goto do_ld_i32;
  case INDEX_op_qemu_ld_a64_i32:
    if (TCG_TARGET_REG_BITS == 64)
      taddr = get(input_arg(0));
    else
      taddr = uint64(get(input_arg(1)), get(input_arg(0)));

  do_ld_i32:
    set(do_qemu_ld(taddr, const_arg(0)), output_arg(0));
    break;

  case INDEX_op_qemu_ld_a32_i64:
    taddr = IRB.CreateIntCast(get(input_arg(0)), IRB.getInt32Ty(), false);
    goto do_ld_i64;
  case INDEX_op_qemu_ld_a64_i64:
    if (TCG_TARGET_REG_BITS == 64)
      taddr = get(input_arg(0));
    else
      taddr = uint64(get(input_arg(1)), get(input_arg(0)));

  do_ld_i64:
    tmp64 = do_qemu_ld(taddr, const_arg(0));
    if (TCG_TARGET_REG_BITS == 32)
      write_reg64(output_arg(1), output_arg(0), tmp64);
    else
      set(tmp64, output_arg(0));
    break;

  case INDEX_op_qemu_st_a32_i32:
    taddr = IRB.CreateIntCast(get(input_arg(1)), IRB.getInt32Ty(), false);
    goto do_st_i32;
  case INDEX_op_qemu_st_a64_i32:
    if (TCG_TARGET_REG_BITS == 64)
      taddr = get(input_arg(1));
    else
      taddr = uint64(get(input_arg(2)), get(input_arg(1)));

  do_st_i32:
    do_qemu_st(taddr,
               IRB.CreateIntCast(IRB.CreateIntCast(get(input_arg(0)),
                                                   IRB.getInt32Ty(), false),
                                 IRB.getInt64Ty(), false),
               const_arg(0));
    break;

  case INDEX_op_qemu_st_a32_i64:
    if (TCG_TARGET_REG_BITS == 64) {
      tmp64 = get(input_arg(0));
      taddr = IRB.CreateIntCast(get(input_arg(1)), IRB.getInt32Ty(), false);
    } else {
      tmp64 = uint64(get(input_arg(1)), get(input_arg(0)));
      taddr = get(input_arg(2));
    }
    goto do_st_i64;
  case INDEX_op_qemu_st_a64_i64:
    if (TCG_TARGET_REG_BITS == 64) {
      tmp64 = get(input_arg(0));
      taddr = get(input_arg(1));
    } else {
      tmp64 = uint64(get(input_arg(1)), get(input_arg(0)));
      taddr = uint64(get(input_arg(3)), get(input_arg(2)));
    }

  do_st_i64:
    do_qemu_st(taddr, tmp64, const_arg(0));
    break;

#define __ARITH_OP(opc_name, LLVMOp, bits)                                     \
  case opc_name:                                                               \
    set(IRB.Create##LLVMOp(get(input_arg(0)), get(input_arg(1))),              \
        output_arg(0));                                                        \
    break;

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
      set(get(&s->temps[tcg_lladdr_index]), dst);                              \
      break;                                                                   \
    }                                                                          \
                                                                               \
    if (off == offsetof(CPUMIPSState, llval)) {                                \
      TCGTemp *dst = arg_temp(op->args[0]);                                    \
      assert(dst->type == TCG_TYPE_I32);                                       \
      set(get(&s->temps[tcg_llval_index]), dst);                               \
      break;                                                                   \
    }                                                                          \
                                                                               \
    { curiosity("load(env+" + std::to_string(off) + ")"); }                    \
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
              IRB.CreatePtrToInt(CPUStateGlobal, WordType()),                  \
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

#if 0
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
#endif

#undef __LD_OP

#if defined(TARGET_MIPS32)
#define __ARCH_ST_OP(off)                                                      \
  {                                                                            \
    if (off == offsetof(CPUMIPSState, lladdr)) {                               \
      set(Val, &s->temps[tcg_lladdr_index]);                                   \
      break;                                                                   \
    }                                                                          \
                                                                               \
    if (off == offsetof(CPUMIPSState, llval)) {                                \
      set(Val, &s->temps[tcg_llval_index]);                                    \
      break;                                                                   \
    }                                                                          \
                                                                               \
    { curiosity("store(env+" + std::to_string(off) + ")"); }                   \
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
              IRB.CreatePtrToInt(CPUStateGlobal, WordType()),                  \
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

#if 0
    __ST_OP(INDEX_op_st8_i32, 8, 32)
    __ST_OP(INDEX_op_st16_i32, 16, 32)
    __ST_OP(INDEX_op_st_i32, 32, 32)

#if TCG_TARGET_REG_BITS == 64
    __ST_OP(INDEX_op_st8_i64, 8, 64)
    __ST_OP(INDEX_op_st16_i64, 16, 64)
    __ST_OP(INDEX_op_st32_i64, 32, 64)
    __ST_OP(INDEX_op_st_i64, 64, 64)
#endif
#endif

#undef __ST_OP

        /* Load/store operations (32 bit). */
        CASE_32_64(ld8u)
            do_ld_or_store(true, 8, false);
            break;
        CASE_32_64(ld8s)
            do_ld_or_store(true, 8, true);
            break;
        CASE_32_64(ld16u)
            do_ld_or_store(true, 16, false);
            break;
        CASE_32_64(ld16s)
            do_ld_or_store(true, 16, true);
            break;
        case INDEX_op_ld_i32:
        CASE_64(ld32u)
            do_ld_or_store(true, 32, false);
            break;
        CASE_32_64(st8)
            do_ld_or_store(false, 8, false);
            break;
        CASE_32_64(st16)
            do_ld_or_store(false, 16, false);
            break;
        case INDEX_op_st_i32:
        CASE_64(st32)
            do_ld_or_store(false, 32, false);
            break;

#if TCG_TARGET_REG_BITS == 64
         /* Load/store operations (64 bit). */
        case INDEX_op_ld32s_i64:
            do_ld_or_store(true, 32, true);
            break;
        case INDEX_op_ld_i64:
            do_ld_or_store(true, 64, false);
            break;
        case INDEX_op_st_i64:
            do_ld_or_store(false, 64, false);
            break;
#endif


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
        *Context, (boost::format("l%lx_fallthru") % ICFG[bb].Addr).str(),      \
        state.for_function(f).F);                                              \
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
      die("unrecognized TCG_COND");                                            \
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
      die("unrecognized TCG_COND");                                            \
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
    TCGTemp *dst = output_arg(0);
    TCGTemp *src1 = input_arg(0);
    TCGTemp *src2 = input_arg(1);

    llvm::Value *arg1 = get(src1);
    llvm::Value *arg2 = get(src2);
    arg2 = IRB.CreateTrunc(arg2, IRB.getInt64Ty());

    TCGArg ofs = const_arg(0);
    TCGArg len = const_arg(1);

    if (0 == ofs && 64 == len) {
      set(arg2, dst);
      break;
    }

    uint64_t mask = (UINT64_C(1) << len) - 1;
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

  case INDEX_op_extract_i32:
    do_extract(32, false);
    break;
  case INDEX_op_sextract_i32:
    do_extract(32, true);
    break;
  case INDEX_op_extract_i64:
    do_extract(64, false);
    break;
  case INDEX_op_sextract_i64:
    do_extract(64, true);
    break;

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

  CASE_32_64(nor)
    set(IRB.CreateNot(IRB.CreateOr(get(input_arg(0)),
                                   get(input_arg(1)))),
        output_arg(0));
    break;

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
    die(std::string("unhandled TCGOpcode: ") + jv_tcgopc_name_in_def(opc));
  }

  return 0;
}

void _qemu_log(const char *cstr) { llvm::errs() << cstr; }

}
