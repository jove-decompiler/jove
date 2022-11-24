#include "tool.h"

#include <boost/filesystem.hpp>

#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

namespace fs = boost::filesystem;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

class InvalidateTool : public Tool {
  struct Cmdline {
    cl::list<std::string> InputFilenames;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : InputFilenames(cl::Positional,
                         cl::desc("<input jove decompilations>"), cl::OneOrMore,
                         cl::cat(JoveCategory)) {}
  } opts;

public:
  InvalidateTool() : opts(JoveCategory) {}

  int Run(void);

  void invalidateInput(const std::string &path);
};

JOVE_REGISTER_TOOL("invalidate", InvalidateTool);

int InvalidateTool::Run(void) {
  for (const std::string &path : opts.InputFilenames) {
    if (!fs::exists(path)) {
      WithColor::error() << path << " does not exist\n";
      continue;
    }

    invalidateInput(path);
  }

  return 0;
}

void InvalidateTool::invalidateInput(const std::string &jvfp) {
  ReadDecompilationFromFile(jvfp, jv);

  jv.InvalidateFunctionAnalyses();
  for_each_binary(jv, [&](binary_t &binary) {
    binary.InvalidateBasicBlockAnalyses();
  });

  WriteDecompilationToFile(jvfp, jv);
}

}
