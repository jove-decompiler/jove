#include "tool.h"
#include "B.h"

#include <llvm/Support/WithColor.h>
#include <llvm/Support/FormatVariadic.h>

namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

class Block : public JVTool<ToolKind::CopyOnWrite> {
  struct Cmdline {
    cl::list<std::string> Args;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Args(cl::Positional, cl::desc("Binary/Block Index"), cl::OneOrMore,
              cl::value_desc("index"), cl::cat(JoveCategory)) {}
  } opts;

public:
  Block() : opts(JoveCategory) {}

  int Run(void) override;
};

JOVE_REGISTER_TOOL("block", Block);

int Block::Run(void) {
  if (opts.Args.size() != 2) {
    WithColor::error() << "must provide index of binary and block\n";
    return 1;
  }

  binary_index_t BIdx       = strtoull(opts.Args[0].c_str(), nullptr, 10);
  basic_block_index_t BBIdx = strtoull(opts.Args[1].c_str(), nullptr, 10);

  const binary_t &b = jv.Binaries.at(BIdx);

  const auto &bbprop =
      b.Analysis.ICFG[basic_block_of_index(BBIdx, b)];

  llvm::outs() << llvm::formatv("{0} in {1}\n", description_of_block(bbprop),
                                b.Name.c_str());
  return 0;
}

}
