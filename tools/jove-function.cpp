#include "tool.h"
#include "B.h"

#include <llvm/Support/WithColor.h>
#include <llvm/Support/FormatVariadic.h>

namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

class Function : public JVTool<ToolKind::CopyOnWrite> {
  struct Cmdline {
    cl::list<std::string> Args;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Args(cl::Positional, cl::desc("Binary/Function Index"), cl::OneOrMore,
              cl::value_desc("index"), cl::cat(JoveCategory)) {}
  } opts;

  binary_index_t BinaryIndex = invalid_binary_index;

public:
  Function() : opts(JoveCategory) {}

  int Run(void) override;
};

JOVE_REGISTER_TOOL("function", Function);

int Function::Run(void) {
  if (opts.Args.size() != 2) {
    WithColor::error() << "must provide index of binary and function\n";
    return 1;
  }

  binary_index_t BIdx   = strtoull(opts.Args[0].c_str(), nullptr, 10);
  function_index_t FIdx = strtoull(opts.Args[1].c_str(), nullptr, 10);

  const binary_t &b = jv.Binaries.at(BIdx);
  const function_t &f = b.Analysis.Functions.at(FIdx);

  llvm::outs() << llvm::formatv(
      "{0:x} in {1}\n", entry_address_of_function(f, b), b.Name.c_str());

  return 0;
}

}
