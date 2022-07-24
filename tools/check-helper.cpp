#include "tool.h"

#include <boost/dll/runtime_symbol_info.hpp>

#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/WithColor.h>

#include <string>
#include <unordered_set>

namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

class CheckHelpersTool : public Tool {
  struct Cmdline {
    cl::list<std::string> InputHelpers;
    cl::opt<bool> Verbose;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : InputHelpers(cl::Positional, cl::desc("<helper>"), cl::OneOrMore,
                       cl::cat(JoveCategory)),

          Verbose("verbose",
                  cl::desc("Print extra information for debugging purposes"),
                  cl::cat(JoveCategory)) {}
  } opts;

  llvm::LLVMContext Context;

public:
  CheckHelpersTool() : opts(JoveCategory) {}

  int Run(void);

  void checkHelper(const std::string &helper_nm);
};

JOVE_REGISTER_TOOL("check-helpers", CheckHelpersTool);

int CheckHelpersTool::Run(void) {
  for (const std::string &nm : opts.InputHelpers)
    checkHelper(nm);
  return 0;
}

void CheckHelpersTool::checkHelper(const std::string &helper_nm) {
  std::string helperModulePath =
      (boost::dll::program_location().parent_path() / "helpers" / (helper_nm + ".bc"))
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
      llvm::parseBitcodeFile(Buffer->getMemBufferRef(), Context);
  if (!helperModuleOr) {
    llvm::logAllUnhandledErrors(helperModuleOr.takeError(), llvm::errs(),
                                "could not parse helper bitcode: ");
    exit(1);
  }

  std::unique_ptr<llvm::Module> &helperModule = helperModuleOr.get();

  std::unordered_set<std::string> syms;

  {
    llvm::Module &helperM = *helperModule;

    for (llvm::Function &F : helperM.functions()) {
      if (F.isIntrinsic())
        continue;

      if (F.empty()) { /* is declaration? */
        if (opts.Verbose)
          llvm::errs() << helperM << '\n';

#if 0
        if (F.getName() == "memcpy")
          continue;
        if (F.getName() == "memset")
          continue;
        if (F.getName() == "memmove")
          continue;
#endif

        syms.insert(F.getName().str());

        WithColor::error() << "undefined function " << F.getName()
                           << " in helper module " << helper_nm << '\n';
      }
    }

    for (llvm::GlobalVariable &GV : helperM.globals()) {
      if (!GV.hasInitializer()) {
        WithColor::error() << "undefined global variable " << GV.getName()
                           << " in helper module " << helper_nm << '\n';

        //syms.insert(GV.getName());
      }
    }
  }

  if (syms.empty())
    return;

  llvm::outs() << llvm::formatv(TARGET_ARCH_NAME "-{0}_EXTRICATE_ARGS :=",
                                helper_nm);

  for (const std::string &sym : syms)
    llvm::outs() << ' ' << sym;

  llvm::outs() << '\n';
}

}
