#include <boost/dll/runtime_symbol_info.hpp>
#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/WithColor.h>
#include <llvm/Support/FormatVariadic.h>
#include <unordered_set>
#include <string>

namespace cl = llvm::cl;

using llvm::WithColor;

namespace opts {
static cl::OptionCategory JoveCategory("Specific Options");

static cl::list<std::string> InputHelpers(cl::Positional, cl::desc("<helper>"),
                                          cl::OneOrMore, cl::cat(JoveCategory));

static cl::opt<bool>
    Verbose("verbose",
            cl::desc("Print extra information for debugging purposes"),
            cl::cat(JoveCategory));

} // namespace opts

namespace jove {

static llvm::LLVMContext Context;

static void checkHelper(const std::string &helper_nm) {
  std::string helperModulePath =
      (boost::dll::program_location().parent_path() / (helper_nm + ".bc"))
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
        if (opts::Verbose)
          llvm::errs() << helperM << '\n';

#if 0
        if (F.getName() == "memcpy")
          continue;
        if (F.getName() == "memset")
          continue;
        if (F.getName() == "memmove")
          continue;
#endif

        syms.insert(F.getName());

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

  llvm::outs() << llvm::formatv(___JOVE_ARCH_NAME "-{0}_EXTRICATE_ARGS :=",
                                helper_nm);

  for (const std::string &sym : syms)
    llvm::outs() << ' ' << sym;

  llvm::outs() << '\n';

  exit(1);
}

}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::HideUnrelatedOptions({&opts::JoveCategory, &llvm::ColorCategory});
  cl::AddExtraVersionPrinter([](llvm::raw_ostream &OS) -> void {
    OS << "jove version " JOVE_VERSION "\n";
  });
  cl::ParseCommandLineOptions(argc, argv, "Helper Bitcode Checker\n");

  llvm::for_each(opts::InputHelpers, jove::checkHelper);

  return 0;
}
