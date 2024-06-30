#include "tool.h"
#include "score.h"

#include <boost/filesystem.hpp>
#include <boost/format.hpp>

#include <llvm/Support/WithColor.h>
#include <llvm/Support/FormatVariadic.h>

namespace cl = llvm::cl;
namespace fs = boost::filesystem;

using llvm::WithColor;

namespace jove {

class ScoreTool : public JVTool<ToolKind::Standard> {
  struct Cmdline {
    cl::opt<std::string> Binary;
    cl::alias BinaryAlias;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Binary("binary", cl::desc("Operate on single given binary"),
                 cl::value_desc("path"), cl::cat(JoveCategory)),

          BinaryAlias("b", cl::desc("Alias for -binary."), cl::aliasopt(Binary),
                      cl::cat(JoveCategory)) {}

  } opts;

  binary_index_t SingleBinaryIndex = invalid_binary_index;

public:
  ScoreTool() : opts(JoveCategory) {}

  int Run(void) override;
};

JOVE_REGISTER_TOOL("score", ScoreTool);

typedef boost::format fmt;

int ScoreTool::Run(void) {
  //
  // operate on single binary? (cmdline)
  //
  if (!opts.Binary.empty()) {
    binary_index_t BinaryIndex = invalid_binary_index;

    for (binary_index_t BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx) {
      const binary_t &binary = jv.Binaries.at(BIdx);
      if (binary.path_str().find(opts.Binary) == std::string::npos)
        continue;

      BinaryIndex = BIdx;
      break;
    }

    if (!is_binary_index_valid(BinaryIndex)) {
      WithColor::error() << llvm::formatv("failed to find binary \"{0}\"\n",
                                          opts.Binary);
      return 1;
    }

    SingleBinaryIndex = BinaryIndex;
  }

  if (is_binary_index_valid(SingleBinaryIndex)) {
    binary_t &binary = jv.Binaries.at(SingleBinaryIndex);

    HumanOut() << (fmt("%.3f\n") % compute_score(jv, binary)).str();
  } else {
    for_each_binary(jv, [&](binary_t &binary) {
      if (binary.IsVDSO)
        return;

      HumanOut() << (fmt("%.3f %s\n")
                     % compute_score(jv, binary)
                     % binary.Name).str();
    });
  }

  return 0;
}

}
