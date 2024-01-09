#include "tool.h"

#include <boost/filesystem.hpp>

#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

namespace fs = boost::filesystem;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

struct InvalidateTool : public JVTool {
  int Run(void) override;

  void invalidateInput(const std::string &path);
};

JOVE_REGISTER_TOOL("invalidate", InvalidateTool);

int InvalidateTool::Run(void) {
  jv.InvalidateFunctionAnalyses();
  for_each_binary(jv, [&](binary_t &binary) {
    binary.InvalidateBasicBlockAnalyses();
  });

  return 0;
}

}
