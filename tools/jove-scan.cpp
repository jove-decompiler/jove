#include "tool.h"
#include "B.h"
#include "explore.h"
#include "tcg.h"
#include "sjlj.h"

#include <boost/filesystem.hpp>

#include <llvm/Support/WithColor.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/FileSystem.h>

namespace fs = boost::filesystem;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

class ScanTool : public JVTool<ToolKind::Standard> {
  struct Cmdline {
    cl::opt<std::string> What;
    cl::opt<std::string> Binary;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : What(cl::Positional, cl::desc("what to search for"), cl::Required,
               cl::value_desc("{sjlj}"), cl::cat(JoveCategory)),

          Binary("binary", cl::desc("Confine search to given binary"),
                 cl::value_desc("filename"), cl::cat(JoveCategory)) {}
  } opts;

public:
  tiny_code_generator_t tcg;
  disas_t disas;
  explorer_t<IsToolMT> E;

  ScanTool() : opts(JoveCategory), E(jv, disas, tcg, IsVeryVerbose()) {}

  int Run(void) override;

  void ScanBinary(binary_t &);
};

JOVE_REGISTER_TOOL("scan", ScanTool);

int ScanTool::Run(void) {
  if (opts.Binary.empty()) {
    for_each_binary(std::execution::par_unseq, jv,
                    [&](binary_t &b) { ScanBinary(b); });
  } else {
    binary_index_t BinaryIndex = invalid_binary_index;

    for (binary_index_t BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx) {
      if (!strstr(jv.Binaries.at(BIdx).Name.c_str(), opts.Binary.c_str()))
        continue;

      BinaryIndex = BIdx;
      break;
    }

    if (BinaryIndex == invalid_binary_index) {
      WithColor::error() << llvm::formatv("failed to find binary \"{0}\"\n",
                                          opts.Binary);
      return 1;
    }

    ScanBinary(jv.Binaries.at(BinaryIndex));
  }

  return 0;
}

void ScanTool::ScanBinary(binary_t &b) {
  auto Bin = B::Create(b.data());

  if (opts.What == "sjlj") {
    ScanForSjLj(b, *Bin, E);
  } else {
    WithColor::error() << llvm::formatv(
        "do not know how to interpret \"{0}\"\n", opts.What);
  }
}

}
