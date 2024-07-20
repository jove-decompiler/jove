#include "tool.h"

#include <boost/filesystem.hpp>

#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

namespace fs = boost::filesystem;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

class Trace2AddrsTool : public JVTool<ToolKind::Standard> {
  struct Cmdline {
    cl::opt<std::string> TracePath;
    cl::opt<bool> SkipRepeated;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : TracePath(cl::Positional, cl::desc("trace.txt"), cl::Required,
                    cl::value_desc("filename"), cl::cat(JoveCategory)),

          SkipRepeated("skip-repeated", cl::desc("Skip repeated blocks"),
                       cl::cat(JoveCategory)) {}
  } opts;

public:
  Trace2AddrsTool() : opts(JoveCategory) {}

  int Run(void) override;

  void ParseTraceFile(
      const char *filename,
      std::vector<std::pair<binary_index_t, basic_block_index_t>> &out);
};

JOVE_REGISTER_TOOL("trace2addrs", Trace2AddrsTool);

int Trace2AddrsTool::Run(void) {
  if (!fs::exists(opts.TracePath)) {
    WithColor::error() << "trace does not exist\n";
    return 1;
  }

  llvm::raw_ostream &OutputStream = llvm::outs();

  //
  // parse trace.txt
  //
  std::vector<std::pair<binary_index_t, basic_block_index_t>> trace;
  ParseTraceFile(opts.TracePath.c_str(), trace);

  //
  // for every block in the trace, print out its description.
  //
  for (const auto &pair : trace) {
    binary_index_t BIdx;
    basic_block_index_t BBIdx;

    std::tie(BIdx, BBIdx) = pair;

    const auto &binary = jv.Binaries.at(BIdx);
    const auto &ICFG = binary.Analysis.ICFG;
    basic_block_t bb = basic_block_of_index(BBIdx, ICFG);

    OutputStream << llvm::formatv("{0}+0x{1:x}\n",
                                  fs::path(binary.path_str()).filename().c_str(),
                                  ICFG[bb].Addr);
  }

  return 1;
}

void Trace2AddrsTool::ParseTraceFile(
    const char *filename,
    std::vector<std::pair<binary_index_t, basic_block_index_t>> &out) {
  std::ifstream ifs(filename);

  if (!ifs)
    die("failed to open trace file '" + std::string(filename) + "'");

  struct {
    binary_index_t BIdx;
    basic_block_index_t BBIdx;
  } Last;

  Last.BIdx = invalid_binary_index;
  Last.BBIdx = invalid_basic_block_index;

  std::string line;
  while (std::getline(ifs, line)) {
    if (line.size() < sizeof("JV_") ||
        line[0] != 'J' ||
        line[1] != 'V' ||
        line[2] != '_')
      die("bad input line: '" + line + "'");

    uint32_t BIdx, BBIdx;
    int fields = sscanf(line.c_str(), "JV_%" PRIu32 "_%" PRIu32, &BIdx, &BBIdx);

    if (fields != 2)
      break;

    if (opts.SkipRepeated) {
      if (Last.BIdx == BIdx && Last.BBIdx == BBIdx)
        continue;
    }

    out.emplace_back(BIdx, BBIdx);

    Last.BIdx = BIdx;
    Last.BBIdx = BBIdx;
  }
}
}
