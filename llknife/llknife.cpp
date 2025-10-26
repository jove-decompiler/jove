#include <llvm/ADT/SmallVector.h>
#include <llvm/ADT/StringSwitch.h>
#include <llvm/AsmParser/Parser.h>
#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/GlobalAlias.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/ToolOutputFile.h>
#include <llvm/Support/WithColor.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Transforms/Utils/ModuleUtils.h>

#include <string>
#include <string_view>
#include <regex>
#include <fstream>

namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

class KnifeTool {
  struct Cmdline {
    cl::opt<bool> Verbose;
    cl::alias VerboseAlias;

    cl::opt<std::string> PathToSymList;
    cl::opt<std::string> Output;
    cl::alias OutputAlias;
    cl::opt<std::string> Input;
    cl::alias InputAlias;

    cl::opt<std::string> CallConv;
    cl::opt<bool> DLLExport;

    cl::opt<bool> ForVimDiff;

    cl::opt<bool> MoveCtorsAndDtors;
    cl::opt<bool> EraseCtorsAndDtors;
    cl::opt<std::string> OnlyExternal;
    cl::opt<std::string> OnlyMakeExternal;

    cl::opt<bool> PrintExternal;
    cl::opt<bool> EraseExternal;

    cl::opt<bool> MakeInternalizedUsed;

    cl::opt<std::string> PrintOnly;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Verbose("verbose", llvm::cl::desc("Print debugging messages"),
                  llvm::cl::cat(JoveCategory)),

          VerboseAlias("v", llvm::cl::desc("Alias for -verbose."),
                       llvm::cl::aliasopt(Verbose),
                       llvm::cl::cat(JoveCategory)),

          PathToSymList(cl::Positional, cl::desc("symbol list"),
                        cl::value_desc("filename"), cl::cat(JoveCategory)),

          Output("output", cl::desc("Output bitcode"), cl::Required,
                 cl::value_desc("filename"), cl::cat(JoveCategory)),

          OutputAlias("o", cl::desc("Alias for -output."), cl::aliasopt(Output),
                      cl::cat(JoveCategory)),

          Input("input", cl::desc("Input bitcode"), cl::Required,
                cl::value_desc("filename"), cl::cat(JoveCategory)),

          InputAlias("i", cl::desc("Alias for -input."), cl::aliasopt(Input),
                     cl::cat(JoveCategory)),

          CallConv("calling-convention",
                   cl::desc("Force calling convention on selected functions"),
                   cl::cat(JoveCategory)),

          DLLExport("dllexport",
                    cl::desc("Force dllexport on selected functions"),
                    cl::cat(JoveCategory)),

          ForVimDiff(
              "for-vimdiff",
              cl::desc("In a vimdiff session of two .ll files there may be a "
                       "large number of insignificant differences that may "
                       "hinder one's ability to spot important differences. "
                       "Selecting this option will produce a semantically "
                       "nonequivalent \"normalization\" of the LLVM IR."),
              cl::cat(JoveCategory)),

          MoveCtorsAndDtors(
              "move-ctors-and-dtors",
              cl::desc(
                  "Copy and rename @llvm.global_ctors and @llvm.global_dtors"),
              cl::cat(JoveCategory)),

          EraseCtorsAndDtors(
              "erase-ctors-and-dtors",
              cl::desc("Erase @llvm.global_ctors and @llvm.global_dtors"),
              cl::cat(JoveCategory)),

          OnlyExternal(
              "only-external",
              cl::desc(
                  "Force everything not matching regex to be internal globals"),
              cl::value_desc("regex"), cl::cat(JoveCategory)),

          OnlyMakeExternal("only-make-external",
                           cl::desc("Force everything matching regex to be "
                                    "only external globals"),
                           cl::value_desc("regex"), cl::cat(JoveCategory)),

          PrintExternal(
              "print-external",
              cl::desc("Print names of every externally visible global"),
              cl::cat(JoveCategory)),

          EraseExternal(
              "erase-external",
              cl::desc("Erase definitions of specified external functions"),
              cl::cat(JoveCategory)),

          MakeInternalizedUsed("make-internalized-used",
                               cl::desc("Mark functions whose linkage is being "
                                        "set to internal as used"),
                               cl::cat(JoveCategory)),

          PrintOnly("print-only",
                    cl::desc("Print all external functions matching regex"),
                    cl::value_desc("regex"), cl::cat(JoveCategory)) {}

  } opts;

  bool IsVerbose(void) const { return opts.Verbose; }

public:
  KnifeTool(llvm::cl::OptionCategory &JoveCategory) : opts(JoveCategory) {}

  int parseSymbolList(const char *filepath, std::vector<std::string> &out);

  int Run(void);
};

static void exportListAnyway(llvm::Module &M,
                             llvm::StringRef From,
                             llvm::StringRef To) {
  llvm::LLVMContext &Ctx = M.getContext();

  llvm::Type *const I32Ty = llvm::Type::getInt32Ty(Ctx);

  llvm::Constant *Init = nullptr;
  llvm::ArrayType *ArrTy = nullptr;
  llvm::StructType *EltTy = nullptr;

  llvm::GlobalVariable *Src = M.getGlobalVariable(From, /*AllowInternal*/ true);
  if (Src && Src->hasInitializer()) {
    Init = llvm::dyn_cast<llvm::ConstantArray>(Src->getInitializer());
    ArrTy = llvm::dyn_cast<llvm::ArrayType>(Init->getType());
    EltTy = llvm::dyn_cast<llvm::StructType>(ArrTy->getElementType());
  } else {
    llvm::Type *PtrTy = llvm::PointerType::get(Ctx, 0);

    EltTy = llvm::StructType::get(Ctx, {I32Ty, PtrTy, PtrTy});
    ArrTy = llvm::ArrayType::get(EltTy, 0);
	Init = llvm::ConstantArray::get(ArrTy, {});
  }

  assert(Init);
  assert(ArrTy);
  assert(EltTy);

  //
  // make a copy with appending linkage (so multiple modules concatenate).
  //
  auto *Copy =
      new llvm::GlobalVariable(M, Init->getType(), /*isConstant=*/false,
                               llvm::GlobalValue::ExternalLinkage, Init, To);
  if (Src) {
    if (std::optional<llvm::MaybeAlign> A = Src->getAlign())
      Copy->setAlignment(*A);
  }

  // keep it alive
  appendToUsed(M, {Copy});
  appendToCompilerUsed(M, {Copy});

  llvm::Constant *Zero = llvm::ConstantInt::get(I32Ty, 0);
  llvm::Constant *BegIdx[2] = {Zero, Zero};
  llvm::Constant *EndIdx[2] = {
      Zero, llvm::ConstantInt::get(I32Ty, ArrTy->getNumElements())};

  llvm::Constant *BeginGEP =
      llvm::ConstantExpr::getGetElementPtr(Copy->getValueType(), Copy, BegIdx);
  llvm::Constant *EndGEP =
      llvm::ConstantExpr::getGetElementPtr(Copy->getValueType(), Copy, EndIdx);

  llvm::Type *EltPtrTy = llvm::PointerType::getUnqual(EltTy);

  auto *BeginAlias =
      llvm::GlobalAlias::create(EltPtrTy, 0, llvm::GlobalValue::ExternalLinkage,
                                (To + "_begin").str(), BeginGEP, &M);
  auto *EndAlias =
      llvm::GlobalAlias::create(EltPtrTy, 0, llvm::GlobalValue::ExternalLinkage,
                                (To + "_end").str(), EndGEP, &M);

  // keep aliases alive
  appendToUsed(M, {BeginAlias, EndAlias});
  appendToCompilerUsed(M, {BeginAlias, EndAlias});
}

int KnifeTool::Run(void) {
  llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> BufferOrErr =
      llvm::MemoryBuffer::getFile(opts.Input);
  if (!BufferOrErr) {
    WithColor::error() << llvm::formatv("could not open {0}: {1}\n",
                                        opts.Input,
                                        BufferOrErr.getError().message());
    return 1;
  }

  bool IsAssembly = true;
  llvm::MemoryBuffer &MB = *BufferOrErr.get();

  llvm::LLVMContext Context;
  std::unique_ptr<llvm::Module> MyModule;
  if (llvm::isBitcode((const unsigned char *)MB.getBufferStart(),
                      (const unsigned char *)MB.getBufferEnd())) {
    IsAssembly = false;

    llvm::Expected<std::unique_ptr<llvm::Module>> ModuleOrErr =
        llvm::parseBitcodeFile(MB.getMemBufferRef(), Context);
    if (llvm::Error Err = ModuleOrErr.takeError()) {
      WithColor::error() << llvm::formatv("could not parse bitcode: {0}\n",
                                          llvm::toString(std::move(Err)));
      return 1;
    }

    MyModule = std::move(ModuleOrErr.get());
  } else {
    llvm::SMDiagnostic Err;
    std::unique_ptr<llvm::Module> Module =
        llvm::parseAssembly(MB.getMemBufferRef(), Err, Context);

    if (!Module) {
      WithColor::error() << llvm::formatv("could not parse\n");
      return 1;
    }

    MyModule = std::move(Module);
  }

  llvm::Module &M = *MyModule;

  //
  // Commands
  //
  auto ForVimDiff = [&](void) -> void {
    // TODO strip debug

    for (llvm::Function &F : M) {
      F.setAttributes(llvm::AttributeList());

      for (llvm::BasicBlock &BB : F) {
        for (llvm::Instruction &I : BB) {
          // clear metadata
          I.setMetadata(llvm::LLVMContext::MD_noalias, nullptr);
          I.setMetadata(llvm::LLVMContext::MD_alias_scope, nullptr);

          // Clear attributes on call instructions
          if (llvm::CallBase *CB = llvm::dyn_cast<llvm::CallBase>(&I)) {
            CB->setAttributes(llvm::AttributeList());
          }

          // Clear tail
          if (llvm::CallInst *CI = llvm::dyn_cast<llvm::CallInst>(&I)) {
            CI->setTailCall(false);
          }
        }
      }
    }
  };

  //
  // Commands over list of globals
  //
  std::vector<std::string> SymsVec;

  struct {
    llvm::CallingConv::ID ID;
  } _CallConv;

  auto ForceCallConv = [&](llvm::GlobalValue *G) {
    llvm::Function *F = llvm::dyn_cast<llvm::Function>(G);
    if (!F) {
      if (IsVerbose())
        WithColor::warning() << llvm::formatv(
            "requested to change calling convention of non-function \"{0}\"",
            G->getName());
      return;
    }

    F->setCallingConv(_CallConv.ID);

    for (llvm::User *FU : F->users()) {
      if (!llvm::isa<llvm::CallInst>(FU))
        continue;

      llvm::CallInst *CI = llvm::cast<llvm::CallInst>(FU);
      if (CI->getCalledFunction() != F)
        continue;

      CI->setCallingConv(_CallConv.ID);
    }
  };

  auto ForceDLLExport = [&](llvm::GlobalValue *G) {
    G->setDLLStorageClass(llvm::GlobalValue::DLLExportStorageClass);
  };

  auto EraseExternal = [&](llvm::GlobalValue *G) {
    llvm::Function *F = llvm::dyn_cast<llvm::Function>(G);
    if (!F)
      return;

    if (IsVerbose())
      WithColor::note() << llvm::formatv("erasing body of {0}\n", G->getName());

    F->deleteBody();
  };

  //
  // Commands
  //
  auto EraseCtorsAndDtors = [&](void) -> void {
    if (auto *GV = M.getGlobalVariable("llvm.global_ctors")) {
      if (IsVerbose())
        WithColor::note() << "removing @llvm.global_ctors\n";
      GV->eraseFromParent();
    }

    if (auto *GV = M.getGlobalVariable("llvm.global_dtors")) {
      if (IsVerbose())
        WithColor::note() << "removing @llvm.global_dtors\n";
      GV->eraseFromParent();
    }
  };

  //
  // Parse command args
  //
  if (opts.ForVimDiff.getNumOccurrences() > 0) {
    ForVimDiff();
  } else if (opts.MoveCtorsAndDtors.getNumOccurrences() > 0) {
    exportListAnyway(M, "llvm.global_ctors", "__jove_global_ctors");
    exportListAnyway(M, "llvm.global_dtors", "__jove_global_dtors");

    EraseCtorsAndDtors();
  } else if (opts.EraseCtorsAndDtors.getNumOccurrences() > 0) {
    EraseCtorsAndDtors();
  } else if (opts.OnlyExternal.getNumOccurrences() > 0 ||
             opts.OnlyMakeExternal.getNumOccurrences() > 0) {
    const bool Make = opts.OnlyMakeExternal.getNumOccurrences() > 0;

    std::regex external_re(Make ? opts.OnlyMakeExternal : opts.OnlyExternal);

    auto isIntrinsicGlobal = [](const llvm::GlobalValue &GV) {
      return std::string_view(GV.getName().str()).starts_with("llvm.");
    };

    auto maybe_adjust_linkage = [&](llvm::GlobalValue &GV) {
      if (GV.isDeclaration())
        return;
      if (isIntrinsicGlobal(GV))
        return;

      std::string name = GV.getName().str();
      if (std::regex_match(name, external_re)) {
        if (IsVerbose()) {
          if (!GV.hasExternalLinkage())
            WithColor::warning() << llvm::formatv(
                "{0} isn't external. it is {1}\n", name, GV.getLinkage());
        }

        if (Make) {
          if (IsVerbose())
            llvm::outs() << llvm::formatv("making {0} external\n", name);

          GV.setLinkage(llvm::GlobalValue::ExternalLinkage);
        }
      } else {
        if (IsVerbose())
          llvm::outs() << llvm::formatv("making {0} internal\n", name);

        if (opts.MakeInternalizedUsed)
          llvm::appendToUsed(M, {&GV});

        GV.setLinkage(llvm::GlobalValue::InternalLinkage);
      }
    };

    for (llvm::Function &F : M.functions())
      maybe_adjust_linkage(F);

    for (llvm::GlobalVariable &GV : M.globals())
      maybe_adjust_linkage(GV);

    for (llvm::GlobalAlias &GA : M.aliases())
      maybe_adjust_linkage(GA);
  } else if (opts.PrintExternal.getNumOccurrences() > 0) {
    std::error_code FileErr;
    llvm::raw_fd_ostream OS(opts.Output, FileErr, llvm::sys::fs::OF_Text);

    for (const llvm::Function &F : M.functions()) {
      if (F.isDeclaration())
        continue;

      if (F.hasExternalLinkage())
        OS << F.getName() << "\n";
    }

    return 0;
  } else if (opts.PrintOnly.getNumOccurrences() > 0) {
    std::error_code FileErr;
    llvm::raw_fd_ostream OS(opts.Output, FileErr, llvm::sys::fs::OF_Text);

    std::regex only(opts.PrintOnly);

    for (llvm::Function &F : M.functions()) {
      std::string name = F.getName().str();
      if (std::regex_match(name, only))
        OS << name << '\n';
    }

    return 0;
  } else {
    if (opts.PathToSymList.getNumOccurrences() == 0) {
      WithColor::error() << "no file containing global names provided\n";
      return 1;
    }

    if (int ret = parseSymbolList(opts.PathToSymList.c_str(), SymsVec))
      return ret;

    std::function<void(llvm::GlobalValue *)> Op;

    if (opts.CallConv.getNumOccurrences() > 0) {
      Op = ForceCallConv;

#define _CCC(x) Case(#x, llvm::CallingConv::x)

      _CallConv.ID = llvm::StringSwitch<llvm::CallingConv::ID>(opts.CallConv)
                         ._CCC(C)
                         ._CCC(Fast)
                         ._CCC(PreserveMost)
                         ._CCC(PreserveAll)
                         ._CCC(X86_StdCall)
                         ._CCC(X86_FastCall)
                         ._CCC(X86_64_SysV)
                         .Default(llvm::CallingConv::MaxID);

#undef _CCC

      if (_CallConv.ID == llvm::CallingConv::MaxID) {
        WithColor::error() << "invalid calling convention\n";
        return 1;
      }
    } else if (opts.DLLExport.getNumOccurrences() > 0) {
      Op = ForceDLLExport;
    } else if (opts.EraseExternal.getNumOccurrences() > 0) {
      Op = EraseExternal;
    }

    if (!Op) {
      WithColor::error() << "no command provided\n";
      return 1;
    }


    //
    // Transform the module
    //
    for (const std::string &Nm : SymsVec) {
      llvm::GlobalValue *G = M.getNamedValue(Nm);
      if (!G) {
        if (IsVerbose())
          WithColor::warning()
              << llvm::formatv("{0} not found in module\n", Nm);
        continue;
      }

      Op(G);
    }
  }

  //
  // We are done.
  //
  if (llvm::verifyModule(M, &llvm::errs())) {
    WithColor::error() << "Broken module!";
    return 1;
  }

  std::error_code EC;
  llvm::ToolOutputFile Out(opts.Output, EC, llvm::sys::fs::OF_None);
  if (EC) {
    WithColor::error() << EC.message() << '\n';
    return 1;
  }

  if (IsAssembly) {
    M.print(Out.os(), nullptr, false /* ShouldPreserveUseListOrder */);
  } else {
    llvm::WriteBitcodeToFile(M, Out.os());
  }

  // Declare success.
  Out.keep();

  return 0;
}

int KnifeTool::parseSymbolList(const char *filepath,
                                 std::vector<std::string> &out) {
  std::ifstream ifs(filepath);
  if (!ifs.is_open()) {
    WithColor::error() << "failed to open file\n";
    return 1;
  }

  std::string line;
  while (std::getline(ifs, line))
    out.push_back(std::move(line));

  return 0;
}

}

int main(int argc, char **argv) {
  llvm::cl::OptionCategory JoveCategory("Specific Options");
  jove::KnifeTool Tool(JoveCategory);

  llvm::cl::ParseCommandLineOptions(argc, argv, "llknife");
  return Tool.Run();
}
