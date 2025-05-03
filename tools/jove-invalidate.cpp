#include "tool.h"

#include <boost/filesystem.hpp>

#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

namespace fs = boost::filesystem;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

struct InvalidateTool : public JVTool<ToolKind::Standard> {
  struct Cmdline {
    cl::opt<bool> Blocks;
    cl::alias BlocksAlias;
    cl::opt<bool> Functions;
    cl::alias FunctionsAlias;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Blocks("blocks", cl::desc("Invalidate block analyses."),
                 cl::init(true), cl::cat(JoveCategory)),
          BlocksAlias("b", cl::desc("Alias for -blocks."), cl::aliasopt(Blocks),
                      cl::cat(JoveCategory)),
          Functions("functions", cl::desc("Invalidate function analyses."),
                    cl::init(true), cl::cat(JoveCategory)),
          FunctionsAlias("f", cl::desc("Alias for -functions."),
                         cl::aliasopt(Functions), cl::cat(JoveCategory)) {}

  } opts;

  InvalidateTool() : opts(JoveCategory) {}

  int Run(void) override;

  void invalidateInput(const std::string &path);
};

JOVE_REGISTER_TOOL("invalidate", InvalidateTool);

int InvalidateTool::Run(void) {
  for_each_binary(std::execution::par_unseq, jv, [&](binary_t &b) {
    if (opts.Functions)
      for_each_function_in_binary(
          std::execution::par_unseq, b,
          [&](function_t &f) { f.InvalidateAnalysis(); });

    if (opts.Blocks)
      for_each_basic_block_in_binary(
          std::execution::par_unseq, b, [&](basic_block_t bb) {
            b.Analysis.ICFG[bb].InvalidateAnalysis(jv, b);
          });
  });

  return 0;
}

}
