#include "tool.h"
#include "xml.h"

#include <boost/dynamic_bitset.hpp>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>

#include <llvm/Support/DataTypes.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

#include <fstream>
#include <memory>
#include <algorithm>

namespace fs = boost::filesystem;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

struct jv2xmlTool : public JVTool<ToolKind::CopyOnWrite> {
  using jv_t = BaseJVTool::jv_t;

  struct Cmdline {
    cl::opt<std::string> InputFilename;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : InputFilename(cl::Positional, cl::desc("<input jove database>"),
                        cl::Required, cl::cat(JoveCategory)) {}
  } opts;

public:
  jv2xmlTool() : opts(JoveCategory) {}

  int Run(void) override;
};

JOVE_REGISTER_TOOL("jv2xml", jv2xmlTool);

int jv2xmlTool::Run(void) {
  // destructively modify data so the output is printable FIXME
  for_each_binary(jv, [&](binary_t &binary) {
    std::fill(binary.Data.begin(), binary.Data.end(), ' ');
  });

  std::ostringstream oss;
  jv2xml(jv, oss);

  llvm::outs() << oss.str() /* oss.view() */;

  return 0;
}

}
