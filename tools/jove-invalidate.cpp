#include "tool.h"

#include <boost/filesystem.hpp>
#include <boost/format.hpp>

#include <llvm/Support/CommandLine.h>
#include <llvm/Support/DataTypes.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

#include <algorithm>
#include <fstream>

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

typedef boost::format fmt;

int InvalidateTool::Run(void) {
  for (const std::string &Path : opts.InputFilenames) {
    if (!fs::exists(Path)) {
      WithColor::error() << Path << " does not exist\n";
      return 1;
    }
  }

  for (const std::string &path : opts.InputFilenames)
    invalidateInput(path);

  return 0;
}

void InvalidateTool::invalidateInput(const std::string &jvfp) {
  decompilation_t Decompilation;
  ReadDecompilationFromFile(jvfp, Decompilation);

  Decompilation.InvalidateFunctionAnalyses();
  for_each_binary(Decompilation, [&](binary_t &binary) {
    binary.InvalidateBasicBlockAnalyses();
  });

  WriteDecompilationToFile(jvfp, Decompilation);
}

}
