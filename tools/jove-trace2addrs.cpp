#include "tool.h"
#include "B.h"

#include <boost/filesystem.hpp>
#include <boost/format.hpp>

#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

#include <iostream>

namespace fs = boost::filesystem;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

namespace {

struct binary_state_t {
  std::unique_ptr<llvm::object::Binary> Bin;
  binary_state_t(const auto &b) { Bin = B::Create(b.data()); }
};

}

class Trace2AddrsTool
    : public StatefulJVTool<ToolKind::CopyOnWrite, binary_state_t, void, void> {
  struct Cmdline {
    cl::opt<std::string> TracePath;
    cl::opt<bool> SkipRepeated;
    cl::opt<bool> Offsets;
    cl::alias OffsetsAlias;
    cl::opt<bool> Terms;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : TracePath(cl::Positional, cl::desc("trace.txt"),
                    cl::value_desc("filename"), cl::cat(JoveCategory)),

          SkipRepeated("skip-repeated", cl::desc("Skip repeated blocks"),
                       cl::cat(JoveCategory)),

          Offsets("offsets",
                  cl::desc("Print in offsets rather than virtual addresses"),
                  cl::cat(JoveCategory)),

          OffsetsAlias("o", cl::desc("Alias for --offsets."),
                       cl::aliasopt(Offsets), cl::cat(JoveCategory)),

          Terms("terms",
                cl::desc("Output addresses of terminators rather than blocks"),
                cl::cat(JoveCategory)) {}

  } opts;

  typedef std::vector<std::pair<binary_index_t, basic_block_index_t>> trace_t;

public:
  Trace2AddrsTool() : opts(JoveCategory) {}

  int Run(void) override;

  void Process(llvm::raw_ostream &out, std::istream &in);
  void ProcessBlock(llvm::raw_ostream &out,
                    binary_index_t BIdx,
                    basic_block_index_t BBIdx);

  taddr_t AddrOrOff(const auto &b, taddr_t);
};

JOVE_REGISTER_TOOL("trace2addrs", Trace2AddrsTool);

typedef boost::format fmt;

int Trace2AddrsTool::Run(void) {
  llvm::raw_ostream &os = llvm::outs();

  std::istream *is = nullptr;
  std::unique_ptr<std::ifstream> ifs;

  if (opts.TracePath.getNumOccurrences() > 0) {
    if (!fs::exists(opts.TracePath)) {
      WithColor::error() << "trace does not exist\n";
      return 1;
    }

    ifs = std::make_unique<std::ifstream>(opts.TracePath);

    if (!(*ifs))
      die("failed to open trace file '" + opts.TracePath + "'");

    is = ifs.get();
  } else {
    is = &std::cin;
  }

  assert(is);
  Process(os, *is);

  return 0;
}

void Trace2AddrsTool::ProcessBlock(llvm::raw_ostream &out,
                                   binary_index_t BIdx,
                                   basic_block_index_t BBIdx) {
  auto &b = jv.Binaries.at(BIdx);
  auto &ICFG = b.Analysis.ICFG;
  basic_block_t bb = basic_block_of_index(BBIdx, ICFG);

  uint64_t x;
  if (opts.Terms) {
    if (ICFG[bb].Term.Type == TERMINATOR::NONE)
      return;
    assert(ICFG[bb].Term.Addr);
    x = ICFG[bb].Term.Addr;
  } else {
    x = ICFG[bb].Addr;
  }

  out << llvm::formatv("{0}{1}{2:x}\n",
                       fs::path(b.path_str()).filename().c_str(),
                       opts.Offsets ? "+" : ":", AddrOrOff(b, x));
}

void Trace2AddrsTool::Process(llvm::raw_ostream &out, std::istream &in) {
  struct {
    binary_index_t BIdx;
    basic_block_index_t BBIdx;
  } Last;

  Last.BIdx = invalid_binary_index;
  Last.BBIdx = invalid_basic_block_index;

  std::string line;
  while (std::getline(in, line)) {
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

    ProcessBlock(out, BIdx, BBIdx);

    Last.BIdx = BIdx;
    Last.BBIdx = BBIdx;
  }
}

taddr_t Trace2AddrsTool::AddrOrOff(const auto &b, taddr_t Addr) {
  if (opts.Offsets)
    return B::offset_of_va(*state.for_binary(b).Bin, Addr);

  return Addr;
}

}
