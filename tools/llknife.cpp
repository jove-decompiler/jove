#include "tool.h"

#include <llvm/AsmParser/Parser.h>
#include <llvm/ADT/StringSwitch.h>
#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/ToolOutputFile.h>
#include <llvm/Support/WithColor.h>
#include <llvm/Support/SourceMgr.h>

#include <string>

namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

class KnifeTool : public Tool {
  struct Cmdline {
    cl::opt<std::string> PathToSymList;
    cl::opt<std::string> Output;
    cl::alias OutputAlias;
    cl::opt<std::string> Input;
    cl::alias InputAlias;

    cl::opt<std::string> CallConv;
    cl::opt<bool> DLLExport;

    cl::opt<bool> ForVimDiff;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : PathToSymList(cl::Positional, cl::desc("symbol list"),
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
              cl::cat(JoveCategory)) {}
  } opts;

public:
  KnifeTool() : opts(JoveCategory) {}

  int parseSymbolList(const char *filepath, std::vector<std::string> &out);

  int Run(void) override;
};

JOVE_REGISTER_TOOL("llknife", KnifeTool);

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

    F->setCallingConv(llvm::CallingConv::X86_64_SysV);

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

  //
  // Parse command args
  //
  if (opts.ForVimDiff.getNumOccurrences() > 0) {
    ForVimDiff();
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
