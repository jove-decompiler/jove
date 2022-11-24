#include "tool.h"

#include <boost/filesystem.hpp>

#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

namespace fs = boost::filesystem;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

class Trace2AddrsTool : public Tool {
  struct Cmdline {
    cl::opt<std::string> TracePath;
    cl::opt<std::string> jv;
    cl::alias jvAlias;
    cl::opt<bool> SkipRepeated;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : TracePath(cl::Positional, cl::desc("trace.txt"), cl::Required,
                    cl::value_desc("filename"), cl::cat(JoveCategory)),

          jv("jv", cl::desc("Jove jv"), cl::Required,
             cl::value_desc("filename"), cl::cat(JoveCategory)),

          jvAlias("d", cl::desc("Alias for -jv."), cl::aliasopt(jv),
                  cl::cat(JoveCategory)),

          SkipRepeated("skip-repeated", cl::desc("Skip repeated blocks"),
                       cl::cat(JoveCategory)) {}
  } opts;

public:
  Trace2AddrsTool() : opts(JoveCategory) {}

  int Run(void);
};

JOVE_REGISTER_TOOL("trace2addrs", Trace2AddrsTool);

int Trace2AddrsTool::Run(void) {
  if (!fs::exists(opts.TracePath)) {
    WithColor::error() << "trace does not exist\n";
    return 1;
  }

  if (!fs::exists(opts.jv)) {
    WithColor::error() << "jv does not exist\n";
    return 1;
  }

  llvm::raw_ostream &OutputStream = llvm::outs();

  //
  // parse trace.txt
  //
  std::vector<std::pair<binary_index_t, basic_block_index_t>> trace;

  {
    std::ifstream trace_ifs(opts.TracePath.c_str());

    if (!trace_ifs) {
      WithColor::error() << llvm::formatv("failed to open trace file '{0}'\n",
                                          opts.TracePath.c_str());
      return 1;
    }

    struct {
      binary_index_t BIdx;
      basic_block_index_t BBIdx;
    } Last;

    Last.BIdx = invalid_binary_index;
    Last.BBIdx = invalid_basic_block_index;

    std::string line;
    while (std::getline(trace_ifs, line)) {
      if (line.size() < sizeof("JV_") || line[0] != 'J' || line[1] != 'V' ||
          line[2] != '_') {
        WithColor::error()
            << llvm::formatv("bad input line: '{0}'\n", line.c_str());
        return 1;
      }

      uint32_t BIdx, BBIdx;
      int fields = sscanf(line.c_str(), "JV_%" PRIu32 "_%" PRIu32, &BIdx, &BBIdx);

      if (fields != 2)
        break;

      if (opts.SkipRepeated) {
        if (Last.BIdx == BIdx && Last.BBIdx == BBIdx)
          continue;
      }

      trace.push_back({BIdx, BBIdx});

      Last.BIdx = BIdx;
      Last.BBIdx = BBIdx;
    }
  }

  jv_t jv;
  ReadDecompilationFromFile(opts.jv, jv);

  //
  // for every block in the trace, print out its description.
  //
  for (const auto &pair : trace) {
    binary_index_t BIdx;
    basic_block_index_t BBIdx;

    std::tie(BIdx, BBIdx) = pair;

    const auto &binary = jv.Binaries.at(BIdx);
    const auto &ICFG = binary.Analysis.ICFG;
    basic_block_t bb = boost::vertex(BBIdx, ICFG);

    OutputStream << llvm::formatv("{0}+0x{1:x}\n",
                                  fs::path(binary.Path).filename().c_str(),
                                  ICFG[bb].Addr);
  }

  return 1;
}

}
