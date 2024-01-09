#include "tool.h"

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
    cl::opt<bool> Vars;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : InputHelpers(cl::Positional, cl::desc("<helper>"), cl::OneOrMore,
                       cl::cat(JoveCategory)),

          Vars("vars", cl::desc("List undefined variables"),
               cl::cat(JoveCategory)) {}

  } opts;

  llvm::LLVMContext Context;

public:
  CheckHelpersTool() : opts(JoveCategory) {}

  int Run(void) override;

  void checkHelper(const std::string &helper_nm);
};

JOVE_REGISTER_TOOL("check-helper", CheckHelpersTool);

int CheckHelpersTool::Run(void) {
  for (const std::string &nm : opts.InputHelpers)
    checkHelper(nm);
  return 0;
}

void CheckHelpersTool::checkHelper(const std::string &helper_nm) {
  llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> BufferOr =
      llvm::MemoryBuffer::getFile(locator().helper_bitcode(helper_nm));
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

  std::unordered_set<std::string> fun_syms;
  std::unordered_set<std::string> var_syms;

  {
    llvm::Module &helperM = *helperModule;

    for (llvm::Function &F : helperM.functions()) {
      if (F.isIntrinsic())
        continue;

      if (F.empty()) { /* is declaration? */
        if (IsVerbose())
          llvm::errs() << helperM << '\n';

#if 0
        if (F.getName() == "memcpy")
          continue;
        if (F.getName() == "memset")
          continue;
        if (F.getName() == "memmove")
          continue;
#endif

        fun_syms.insert(F.getName().str());

#if 0
        WithColor::error() << "undefined function " << F.getName()
                           << " in helper module " << helper_nm << '\n';
#endif
      }
    }

    for (llvm::GlobalVariable &GV : helperM.globals()) {
      if (!GV.hasInitializer()) {
#if 0
        WithColor::error() << "undefined global variable " << GV.getName()
                           << " in helper module " << helper_nm << '\n';
#endif

        var_syms.insert(GV.getName().str());
      }
    }
  }

  if (!fun_syms.empty()) {
    llvm::outs() << llvm::formatv(TARGET_ARCH_NAME "-{0}_EXTRICATE_ARGS :=",
                                  helper_nm);

    for (const std::string &sym : fun_syms)
      llvm::outs() << ' ' << sym;

    llvm::outs() << '\n';
  }

  if (opts.Vars && !var_syms.empty()) {
    llvm::outs() << llvm::formatv(TARGET_ARCH_NAME "-{0}_UNDEF_VARS :=",
                                  helper_nm);

    for (const std::string &sym : var_syms)
      llvm::outs() << ' ' << sym;

    llvm::outs() << '\n';
  }
}

}
