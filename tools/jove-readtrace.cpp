#include "tool.h"
#include <boost/filesystem.hpp>
#include <fstream>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

namespace fs = boost::filesystem;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

class ReadTraceTool : public Tool {
  struct Cmdline {
    cl::opt<std::string> TraceBinPath;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : TraceBinPath(cl::Positional, cl::desc("trace.bin"), cl::Required,
                       cl::value_desc("filename"), cl::cat(JoveCategory)) {}
  } opts;

public:
  ReadTraceTool() : opts(JoveCategory) {}

  int Run(void);
};

JOVE_REGISTER_TOOL("readtrace", ReadTraceTool);

int ReadTraceTool::Run(void) {
  if (!fs::exists(opts.TraceBinPath)) {
    WithColor::error() << "trace.bin does not exist\n";
    return 1;
  }

  std::ifstream ifs(opts.TraceBinPath.c_str());

  uint64_t X;
  while (ifs.read(reinterpret_cast<char *>(&X), sizeof(X))) {
    struct {
      uint32_t BIdx;
      uint32_t BBIdx;
    } Trace;

    Trace.BIdx  = X >> 32;
    Trace.BBIdx = X & 0xffffffff;

    llvm::outs() << llvm::formatv("JV_{0}_{1}\n",
                                  Trace.BIdx,
                                  Trace.BBIdx);
  }

  return 0;
}

}
