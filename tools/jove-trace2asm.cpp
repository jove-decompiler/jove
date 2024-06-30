#include "tool.h"
#include "B.h"
#include "disas.h"

#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include <boost/graph/depth_first_search.hpp>

#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

#include <cstdlib>
#include <memory>

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

namespace {

struct binary_state_t {
  std::unique_ptr<llvm::object::Binary> ObjectFile;
};

}

class Trace2AsmTool : public StatefulJVTool<ToolKind::Standard, binary_state_t, void, void> {
  struct Cmdline {
    cl::opt<std::string> TracePath;
    cl::list<unsigned> ExcludeBinaries;
    cl::opt<bool> SkipRepeated;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : TracePath(cl::Positional, cl::desc("trace.txt"), cl::Required,
                    cl::value_desc("filename"), cl::cat(JoveCategory)),

          ExcludeBinaries("exclude-bins", cl::CommaSeparated,
                          cl::value_desc("bidx_1,bidx_2,...,bidx_n"),
                          cl::desc("Indices of binaries to exclude"),
                          cl::cat(JoveCategory)),

          SkipRepeated("skip-repeated", cl::desc("Skip repeated blocks"),
                       cl::cat(JoveCategory)) {}
  } opts;

public:
  Trace2AsmTool() : opts(JoveCategory) {}

  int Run(void) override;
};

JOVE_REGISTER_TOOL("trace2asm", Trace2AsmTool);

typedef boost::format fmt;

int Trace2AsmTool::Run(void) {
  if (!fs::exists(opts.TracePath)) {
    WithColor::error() << "trace does not exist\n";
    return 1;
  }

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
      int fields =
          sscanf(line.c_str(), "JV_%" PRIu32 "_%" PRIu32, &BIdx, &BBIdx);

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

  //
  // init state for binaries
  //
  for_each_binary(jv, [&](binary_t &binary) {
    ignore_exception([&]() {
      state.for_binary(binary).ObjectFile = B::Create(binary.data());
    });
  });

  disas_t disas;

  auto disassemble_basic_block = [&](binary_index_t BIdx,
                                     basic_block_index_t BBIdx) -> std::string {
    auto &binary = jv.Binaries.at(BIdx);
    auto &ICFG = binary.Analysis.ICFG;
    basic_block_t bb = basic_block_of_index(BBIdx, ICFG);

    const ELFF &Elf = llvm::cast<ELFO>(state.for_binary(binary).ObjectFile.get())->getELFFile();

    uint64_t Addr = ICFG[bb].Addr;
    unsigned Size = ICFG[bb].Size;

    //std::string res = (fmt("%08x [%u]\n\n") % ICFG[bb].Addr % ICFG[bb].Size).str();
    std::string res;

    uint64_t End = Addr + Size;

#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
    if (ICFG[bb].Term.Type != TERMINATOR::NONE)
      End += 4; /* delay slot */
#endif

    uint64_t InstLen = 0;
    for (uintptr_t A = Addr; A < End; A += InstLen) {
      llvm::Expected<const uint8_t *> ExpectedPtr = Elf.toMappedAddr(A);
      if (!ExpectedPtr)
        abort();

      llvm::MCInst Inst;

      std::string errmsg;
      bool Disassembled;
      {
        llvm::raw_string_ostream ErrorStrStream(errmsg);

        Disassembled = disas.DisAsm->getInstruction(
            Inst, InstLen, llvm::ArrayRef<uint8_t>(*ExpectedPtr, End - Addr), A,
            ErrorStrStream);
      }

      if (!Disassembled) {
        res.append("failed to disassemble");
        if (!errmsg.empty()) {
          res.append(": ");
          res.append(errmsg);
        }
        res.push_back('\n');
        break;
      }

      std::string line;
      {
        llvm::raw_string_ostream StrStream(line);
        disas.IP->printInst(&Inst, A, "", *disas.STI, StrStream);
      }
      boost::trim(line);

      res.append((fmt("%08x   ") % A).str());
      res.append(line);
      res.push_back('\n');
    }

    return res;
  };

  //
  // disassemble every block in the trace
  //
  for (const auto &pair : trace) {
    binary_index_t BIdx;
    basic_block_index_t BBIdx;

    std::tie(BIdx, BBIdx) = pair;

    if (std::find(opts.ExcludeBinaries.begin(),
                  opts.ExcludeBinaries.end(), BIdx) != opts.ExcludeBinaries.end())
      continue;

    llvm::outs() << '\n' << disassemble_basic_block(BIdx, BBIdx) << '\n';
  }

  return 0;
}

}
