#pragma once
#include "jove/jove.h"

#ifndef JOVE_NO_BACKEND
#include "analyze.h"
#include "B.h"
#include "tcg.h"
#include "disas.h"
#include "locator.h"

#include <boost/icl/split_interval_map.hpp>

#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DIBuilder.h>

#include <memory>

namespace jove {

struct llvm_options_t {
  std::string Output;
  std::string Binary;
  std::string BinaryIndex;

  bool ForeignLibs = true;
  bool CheckEmulatedStackReturnAddress = false;
  bool DumpTCG = false;
  bool DFSan = false;
  bool InlineHelpers = false;
  bool ForCBE = false;
  bool DumpPreOpt1 = false;
  bool DumpPostOpt1 = false;
  bool Optimize = false;
  bool BreakBeforeUnreachables = false;
  bool Debugify = false;
  bool RuntimeMT = true;
  bool Trace = false;
  bool PlaceSectionBreakpoints = false;
  bool LayOutSections = false;
  bool CallStack = false;
  bool VerifyBitcode = false;
  bool DebugSjlj = false;
  bool ABICalls = true;
  bool PrintPCRel = false;
  bool SoftfpuBitcode = false;

  std::string ForAddr;
  std::string VersionScript;
  std::string LinkerScript; /* FIXME entirely unused */
  std::string DFSanOutputModuleID;

  tcg_global_set_t PinnedEnvGlbs = InitPinnedEnvGlbs;

  unsigned VerbosityLevel = 0;

  bool IsVerbose(void) const { return VerbosityLevel >= 1; };
  bool IsVeryVerbose(void) const { return VerbosityLevel >= 2; };

  std::string temp_dir;
};

struct TranslateContext;

using IRBuilderTy =
    llvm::IRBuilder<llvm::ConstantFolder, llvm::IRBuilderDefaultInserter>;

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

struct section_t {
  std::string Name;
  llvm::ArrayRef<uint8_t> Contents;
  uint64_t Addr;
  unsigned Size;

  bool w = true;

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

// returns whether the block was actually analyzed
bool AnalyzeBasicBlock(tiny_code_generator_t &,
                       helpers_context_t &,
                       llvm::Module &,
                       llvm::object::Binary &,
                       bbprop_t &,
                       const analyzer_options_t &);

template <bool MT, bool MinSize>
class llvm_t {
  using jv_t = jv_base_t<MT, MinSize>;
  using binary_t = binary_base_t<MT, MinSize>;
  using icfg_t = ip_icfg_base_t<MT>;
  using bb_t = typename ip_icfg_base_t<MT>::vertex_descriptor;

  const jv_t &jv;

  const llvm_options_t &opts;
  const analyzer_options_t &analyzer_options;

  locator_t &locator_;

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
    struct {
      boost::unordered::unordered_flat_map<std::string_view, uint32_t> Name2RVA;
    } _coff;
    llvm::GlobalVariable *FunctionsTable = nullptr;
    llvm::GlobalVariable *FunctionsTableClunk = nullptr;
    llvm::Function *SectsF = nullptr;
    uint64_t SectsStartAddr = 0;
    uint64_t SectsEndAddr = 0;

    binary_state_t(const binary_t &b) {
      Bin = B::Create(b.data());

      std::tie(SectsStartAddr, SectsEndAddr) = B::bounds_of_binary(*Bin);

      B::_elf(*Bin, [&](ELFO &O) {
        elf::loadDynamicTable(O, _elf.DynamicTable);

        if (_elf.DynamicTable.Addr) {
          _elf.OptionalDynSymRegion =
              loadDynamicSymbols(O,
                                 _elf.DynamicTable,
                                 _elf.DynamicStringTable,
                                 _elf.SymbolVersionSection,
                                 _elf.VersionMap);
        }
      });

      B::_coff(*Bin, [&](COFFO &O) {
        coff::for_each_exported_function(
            O, [&](uint32_t Ordinal, llvm::StringRef Name, uint64_t RVA) {
              _coff.Name2RVA.emplace(Name, RVA);
            });
      });
    }
  };

  struct basic_block_state_t {
    tcg_global_set_t IN, OUT;

    llvm::BasicBlock *B = nullptr;

    basic_block_state_t(const auto &b, auto bb_t) {}
  };

  struct function_state_t {
    using bb_t = typename ip_icfg_base_t<AreWeMT>::vertex_descriptor;
    using bb_vec_t = std::vector<bb_t>;

    bb_vec_t bbvec;
    bb_vec_t exit_bbvec;

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

    function_state_t(const auto &f, const auto &b) {
      if (!is_basic_block_index_valid(f.Entry))
        return;

      basic_blocks_of_function(f, b, bbvec);
      exit_basic_blocks_of_function(f, b, bbvec, exit_bbvec);

      IsLeaf = IsLeafFunction(f, b, bbvec, exit_bbvec);

      IsSj = IsFunctionSetjmp(f, b, bbvec);
      IsLj = IsFunctionLongjmp(f, b, bbvec);
    }
  };

  jv_state_t<binary_state_t, function_state_t, basic_block_state_t, AreWeMT,
             true, false, true, true, MT, MinSize>
      state;

  template <typename Key, typename Value>
  using unordered_map = boost::unordered::unordered_flat_map<Key, Value>;

  template <typename T>
  using unordered_set = boost::unordered::unordered_flat_set<T>;

  using section_properties_set_t = std::set<section_properties_t>;

  binary_index_t BinaryIndex = invalid_binary_index;

  tcg_global_set_t PinnedEnvGlbs = InitPinnedEnvGlbs;

  bool IsCOFF = false;

  uint64_t ForAddr = 0;

  llvm::LLVMContext &Context;
  std::unique_ptr<llvm::Module> Module; /* initialized from starter bitcode */
  helpers_context_t helpers;

  tiny_code_generator_t &TCG;

  llvm::DataLayout DL;

  std::string SectsGlobalName, ConstSectsGlobalName;

  llvm::GlobalVariable *SectsGlobal = nullptr;
  llvm::GlobalVariable *ConstSectsGlobal = nullptr;

  unordered_map<std::string, std::set<dynamic_target_t>> ExportedFunctions;

  struct {
    unordered_map<std::string, binary_index_t> DLL2Binary;
  } _coff;

  std::vector<unordered_set<std::string_view>> bin_paths_vec;
  llvm::GlobalVariable *binNamesTable;

  disas_t disas;

  unordered_set<uint64_t> ConstantRelocationLocs;
  uint64_t libcEarlyInitAddr = 0;

  llvm::GlobalVariable *EnvGlobal = nullptr;
  llvm::Function *GetEnvFunc = nullptr;
  llvm::Value *CachedEnv = nullptr;
  llvm::Type *CPUStateType = nullptr;

  llvm::GlobalVariable *TraceGlobal = nullptr;
  llvm::Function *GetTraceFunc = nullptr;
  llvm::Value *CachedTrace = nullptr;

  llvm::GlobalVariable *CallStackGlobal = nullptr;
  llvm::Function *GetCallStackFunc = nullptr;
  llvm::Value *CachedCallStack = nullptr;
  llvm::GlobalVariable *CallStackBeginGlobal = nullptr;
  llvm::Function *GetCallStackBeginFunc = nullptr;

  llvm::GlobalVariable *JoveFunctionTablesGlobal = nullptr;
  llvm::GlobalVariable *JoveForeignFunctionTablesGlobal = nullptr;
  llvm::GlobalVariable *JoveForeignFunctionTablesBiasGlobal = nullptr;
  llvm::Function *JoveRecoverDynTargetFunc = nullptr;
  llvm::Function *JoveRecoverBasicBlockFunc = nullptr;
  llvm::Function *JoveRecoverReturnedFunc = nullptr;
  llvm::Function *JoveRecoverABIFunc = nullptr;
  llvm::Function *JoveRecoverFunctionFunc = nullptr;
  llvm::Function *JoveRecoverForeignFunctionFunc = nullptr;
  llvm::Function *JoveRecoverForeignBinaryFunc = nullptr;
  llvm::Function *JoveRecoverAnonymousForeignFunction = nullptr;
  llvm::Function *JoveRecoverAnonymousForeignBinary = nullptr;

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

  llvm::Function *JoveMakeSectionsExeFunc = nullptr;
  llvm::Function *JoveMakeSectionsNotExeFunc = nullptr;

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

  llvm::Function *AssertNonZeroU32 = nullptr;
  llvm::Function *AssertNonZeroU64 = nullptr;

  struct {
    llvm::ArrayType *T = nullptr;
    llvm::GlobalVariable *GV = nullptr;
  } TLSDescHack;

  struct {
    struct {
      // in memory, the .tbss section is allocated directly following the .tdata
      // section, with the aligment obeyed
      unsigned Size = ~0u;
    } Data;

    uint64_t Beg, End;

    bool Present = false;
  } ThreadLocalStorage;

  struct {
    llvm::DIFile *File = nullptr;
    llvm::DICompileUnit *CompileUnit = nullptr;
  } DebugInformation;

  static constexpr const char *DIVersionKey = "Debug Info Version";

  unsigned NumSections = 0;
  boost::icl::split_interval_map<uint64_t, section_properties_set_t> SectMap;
  std::vector<section_t> SectTable;
  boost::icl::interval_map<uint64_t, unsigned> SectIdxMap;

  std::vector<std::vector<uint8_t>> SegContents;

  struct {
    llvm::GlobalVariable *HeadGV = nullptr;
    std::vector<std::pair<llvm::GlobalVariable *, unsigned>> GVVec;
  } LaidOut;

  unordered_map<std::string, unsigned> GlobalSymbolDefinedSizeMap;

  unordered_map<uint64_t, std::set<llvm::StringRef>> TLSValueToSymbolMap;
  unordered_map<uint64_t, unsigned> TLSValueToSizeMap;

  boost::icl::split_interval_set<uint64_t> AddressSpaceObjects;

  unordered_map<uint64_t, std::set<std::string>> AddrToSymbolMap;
  unordered_map<uint64_t, unsigned> AddrToSizeMap;
  unordered_set<uint64_t> TLSObjects; // XXX

  unordered_set<std::string> CopyRelSyms;

  unordered_map<llvm::Function *, llvm::Function *> CtorStubMap;

  unordered_set<llvm::Function *> MustInlineSjStubs;

  struct {
    unordered_map<std::string, unordered_set<std::string>> Table;
  } VersionScript;

  // set {int}0x08053ebc = 0xf7fa83f0
  std::map<std::pair<uint64_t, unsigned>,
           std::pair<binary_index_t, std::pair<uint64_t, unsigned>>>
      CopyRelocMap;

  std::vector<uint64_t> possible_tramps_vec;

  unordered_map<std::string, std::set<unsigned>> ordinal_imports;

  llvm::Constant *__jove_fail_UnknownBranchTarget;
  llvm::Constant *__jove_fail_UnknownCallee;

  bool pcrel_flag = false; /* FIXME? !MT-safe */
  uint64_t lstaddr = 0;    /* FIXME? !MT-safe */

public:
  llvm_t(const jv_t &jv, const llvm_options_t &llvm_options,
         const analyzer_options_t &analyzer_options,
         tiny_code_generator_t &TCG,
         llvm::LLVMContext &Context,
         locator_t &locator_)
      : jv(jv), opts(llvm_options), analyzer_options(analyzer_options),
        locator_(locator_), Context(Context),
        state(jv), TCG(TCG), DL("") {}

  int go(void);

private:
  int TranslateFunction(const function_t &);
  int TranslateBasicBlock(TranslateContext &);
  int TranslateTCGOps(llvm::BasicBlock *ExitBB,
                      IRBuilderTy &,
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
  int CreateBinaryNamesTable(void);
  int FixupHelperStubs(void);
  int CreateNoAliasMetadata(void);
  int ProcessManualRelocations(void);
  int CreateCopyRelocationHack(void);
  int TranslateFunctions(void);
  int InlineSjStubs(void);
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
  int LinkInSoftFPU(void);
  int ForceCallConv(void);
  int WriteModule(void);

  void DumpModule(const char *);

  void ReloadGlobalVariables(void);
  int DoOptimize(void);
  int Debugify(void);

  bool IsVerbose(void) const { return opts.VerbosityLevel >= 1; };
  bool IsVeryVerbose(void) const { return opts.VerbosityLevel >= 2; };
  const std::string &temporary_dir(void) const { return opts.temp_dir; }
  locator_t &locator(void) { return locator_; }

  void curiosity(const std::string &message);
  void warning(const char *file, int line);
  [[noreturn]] void die(const std::string &reason);

  llvm::Type *VoidType(void);
  llvm::IntegerType *WordType(void);
  llvm::Type *PointerToWordType(void);
  llvm::Type *PPointerType(void);
  llvm::Type *VoidFunctionPointer(void);
  llvm::Constant *BigWord(void);

  llvm::IntegerType *TypeOfTCGGlobal(unsigned glb);

  llvm::Value *CPUStateGlobalPointer(IRBuilderTy &, unsigned glb);

  llvm::Value *BuildCPUStatePointer(IRBuilderTy &,
                                    llvm::Value *Env,
                                    unsigned glb);

  llvm::Value *GetEnv(IRBuilderTy &IRB) {
    if (CachedEnv)
      return CachedEnv;

    if (EnvGlobal)
      return EnvGlobal;

    assert(GetEnvFunc);
    return IRB.CreateCall(GetEnvFunc, std::nullopt, "env");
  }

  llvm::Value *GetCallStack(IRBuilderTy &IRB) {
    if (CachedCallStack)
      return CachedCallStack;

    if (CallStackGlobal)
      return CallStackGlobal;

    assert(GetCallStackFunc);
    return IRB.CreateCall(GetCallStackFunc, std::nullopt, "callstack");
  }

  llvm::Value *GetTrace(IRBuilderTy &IRB) {
    if (CachedTrace)
      return CachedTrace;

    if (TraceGlobal)
      return TraceGlobal;

    assert(GetTraceFunc);
    return IRB.CreateCall(GetTraceFunc, std::nullopt, "trace");
  }

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

#if 0 /* we could do this... */
    if (Binary.IsExecutable && !Binary.IsPIC)
      return llvm::ConstantInt::get(WordType(), Addr);
#endif

    int64_t off =
        static_cast<int64_t>(Addr) -
        static_cast<int64_t>(state.for_binary(Binary).SectsStartAddr);

    return llvm::ConstantExpr::getAdd(
        llvm::ConstantExpr::getPtrToInt(SectionsTop(), WordType()),
        llvm::ConstantInt::getSigned(WordType(), off));
  }

  bool DynTargetNeedsThunkPred(dynamic_target_t DynTarget) {
    binary_index_t BIdx = DynTarget.first;
    const auto &binary = jv.Binaries.at(BIdx);

    if (opts.ForeignLibs)
      return !binary.IsExecutable;

    return binary.IsDynamicLinker || binary.IsVDSO;
  }

  template <bool Callable>
  llvm::Value *
  GetDynTargetAddress(IRBuilderTy &IRB,
                      std::pair<binary_index_t, function_index_t> IdxPair,
                      llvm::BasicBlock *FailBlock = nullptr) {
    struct {
      binary_index_t BIdx;
      function_index_t FIdx;
    } DynTarget;

    std::tie(DynTarget.BIdx, DynTarget.FIdx) = IdxPair;

    auto &binary = jv.Binaries.at(DynTarget.BIdx);

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
                                          IRBuilderTy &,
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
      IRBuilderTy IRB(&JoveNoDCEFunc->getEntryBlock().front());

      llvm::Value *Ptr = IRB.CreateConstInBoundsGEP1_32(
          IRB.getPtrTy()->getPointerTo(), OutArg, Idx++);

      IRB.CreateStore(V, Ptr);
    }
  }

  void fillInFunctionBody(llvm::Function *F,
                          std::function<void(IRBuilderTy &)> funcBuilder,
                          bool internalize = true);

  llvm::Type *type_of_arg_info(const hook_t::arg_info_t &info) {
    if (info.isPointer)
      return llvm::PointerType::get(llvm::Type::getInt8Ty(Context), 0);

    return llvm::Type::getIntNTy(Context, info.Size * 8);
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

  llvm::GlobalIFunc *buildGlobalIFunc(const function_t &f,
                                      dynamic_target_t,
                                      llvm::StringRef SymName);

  bool shouldExpandOperationWithSize(llvm::Value *Size);
  void expandMemIntrinsicUses(llvm::Function &);

  tcg_global_set_t DetermineFunctionArgs(const function_t &);
  tcg_global_set_t DetermineFunctionRets(const function_t &);

  void ExplodeFunctionArgs(const function_t &f, std::vector<unsigned> &glbv);
  void ExplodeFunctionRets(const function_t &f, std::vector<unsigned> &glbv);

  llvm::FunctionType *FunctionTypeOfArgsAndRets(tcg_global_set_t args,
                                                tcg_global_set_t rets);

  llvm::FunctionType *DetermineFunctionType(const function_t &f) {
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

  void elf_compute_manual_relocation(IRBuilderTy &,
                                     const elf::Relocation &,
                                     const elf::RelSymbol &);

  void elf_compute_tpoff_relocation(IRBuilderTy &,
                                    const elf::RelSymbol &,
                                    unsigned Offset);

  void elf_compute_irelative_relocation(IRBuilderTy &,
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

  llvm::Value *insertThreadPointerInlineAsm(IRBuilderTy &);

  std::string dyn_target_desc(dynamic_target_t IdxPair);

  llvm::Function *bswap_i(unsigned bits) {
    assert(bits > 8);

    llvm::Type *Tys[] = {llvm::Type::getIntNTy(Context, bits)};

    llvm::Function *bswap =
        llvm::Intrinsic::getDeclaration(Module.get(), llvm::Intrinsic::bswap,
                                        llvm::ArrayRef<llvm::Type *>(Tys, 1));
    return bswap;
  }
};

}
#endif /* JOVE_NO_BACKEND */
