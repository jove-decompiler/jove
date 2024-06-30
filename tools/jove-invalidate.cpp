#include "tool.h"

#include <boost/filesystem.hpp>

#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

namespace fs = boost::filesystem;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

struct InvalidateTool : public JVTool<ToolKind::Standard> {
  int Run(void) override;

  void invalidateInput(const std::string &path);
};

JOVE_REGISTER_TOOL("invalidate", InvalidateTool);

int InvalidateTool::Run(void) {
  for_each_binary(std::execution::par_unseq, jv, [&](binary_t &b) {
    for_each_function_in_binary(std::execution::par_unseq, b,
                                [&](function_t &f) { f.InvalidateAnalysis(); });

    for_each_basic_block_in_binary(
        std::execution::par_unseq, b,
        [&](basic_block_t bb) { b.Analysis.ICFG[bb].InvalidateAnalysis(); });
  });

  return 0;
}

}
