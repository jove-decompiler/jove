#include "tool.h"

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

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : PathToSymList(cl::Positional, cl::desc("symbol list"), cl::Required,
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
    WithColor::error() << llvm::formatv("could not open bitcode at {0}: {1}\n",
                                        opts.Input,
                                        BufferOrErr.getError().message());
    return 1;
  }

  llvm::LLVMContext Context;

  llvm::Expected<std::unique_ptr<llvm::Module>> ModuleOrErr =
      llvm::parseBitcodeFile(BufferOrErr.get()->getMemBufferRef(), Context);
  if (llvm::Error Err = ModuleOrErr.takeError()) {
    WithColor::error() << llvm::formatv("could not open bitcode: {0}\n",
                                        llvm::toString(std::move(Err)));
    return 1;
  }

  std::vector<std::string> SymsVec;
  if (int ret = parseSymbolList(opts.PathToSymList.c_str(), SymsVec))
    return ret;

  //
  // Commands
  //
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
  llvm::Module &M = *ModuleOrErr.get();

  for (const std::string &Nm : SymsVec) {
    llvm::GlobalValue *G = M.getNamedValue(Nm);
    if (!G) {
      if (IsVerbose())
        WithColor::warning()
            << llvm::formatv("global value \"{0}\" not found in module\n", Nm);
      continue;
    }

    Op(G);
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

  llvm::WriteBitcodeToFile(M, Out.os());

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
