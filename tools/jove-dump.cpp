#include "jove/jove.h"
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/DataTypes.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/ScopedPrinter.h>
#include <llvm/Support/WithColor.h>

#include <fstream>
#include <algorithm>
#include <boost/filesystem.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/graph/adj_list_serialize.hpp>
#include <boost/serialization/bitset.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/graph/breadth_first_search.hpp>
#include <boost/pending/indirect_cmp.hpp>
#include <boost/range/irange.hpp>
#include <boost/format.hpp>

namespace fs = boost::filesystem;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace opts {
static cl::OptionCategory JoveCategory("Specific Options");

static cl::list<std::string>
    InputFilenames(cl::Positional, cl::desc("<input jove decompilations>"),
                   cl::OneOrMore, cl::cat(JoveCategory));

static cl::opt<bool>
    Compact("compact",
            cl::desc("Print functions as list of basic-blocks addresses"),
            cl::cat(JoveCategory));

static cl::opt<bool>
    Graphviz("graphviz",
             cl::desc("Produce control-flow graphs for each function"),
             cl::cat(JoveCategory));

static cl::opt<bool> Statistics("binary-stats", cl::desc("Print statistics"),
                                cl::cat(JoveCategory));

static cl::opt<bool> ListBinaries("list-binaries",
                                  cl::desc("List binaries for decompilation"),
                                  cl::cat(JoveCategory));

static cl::alias ListBinariesAlias("l", cl::desc("Alias for -list-binaries."),
                                   cl::aliasopt(ListBinaries),
                                   cl::cat(JoveCategory));

static cl::opt<std::string>
    ListFunctions("list-functions", cl::desc("List functions for given binary"),
                  cl::cat(JoveCategory));

static cl::alias ListFunctionsAlias("f", cl::desc("Alias for -list-functions."),
                                    cl::aliasopt(ListFunctions),
                                    cl::cat(JoveCategory));

static cl::opt<std::string> ListFunctionBBs(
    "list-fn-bbs", cl::desc("List basic blocks for functions for given binary"),
    cl::cat(JoveCategory));

} // namespace opts

namespace jove {

typedef boost::format fmt;

struct reached_visitor : public boost::default_bfs_visitor {
  std::vector<basic_block_t> &out;

  reached_visitor(std::vector<basic_block_t> &out) : out(out) {}

  void discover_vertex(basic_block_t bb,
                       const interprocedural_control_flow_graph_t &) const {
    out.push_back(bb);
  }
};

static void dumpDecompilation(const decompilation_t& decompilation) {
  llvm::ScopedPrinter Writer(llvm::outs());
  llvm::ListScope _(Writer, (fmt("Binaries (%u)") % decompilation.Binaries.size()).str());

  for (const auto &B : decompilation.Binaries) {
    llvm::DictScope __(Writer, B.Path.c_str());

    Writer.printBoolean("IsDynamicLinker", B.IsDynamicLinker);
    Writer.printBoolean("IsExecutable", B.IsExecutable);
    Writer.printBoolean("IsVDSO", B.IsVDSO);

    const auto &ICFG = B.Analysis.ICFG;

    if (is_function_index_valid(B.Analysis.EntryFunction)) {
      const function_t &entryFunc =
          B.Analysis.Functions.at(B.Analysis.EntryFunction);
      Writer.printHex("Entry", ICFG[boost::vertex(entryFunc.Entry, ICFG)].Addr);
    }

    auto it_pair = boost::vertices(ICFG);

    std::vector<basic_block_t> blocks;
    blocks.resize(boost::num_vertices(ICFG));

    std::transform(it_pair.first, it_pair.second, blocks.begin(),
                   [](basic_block_t bb) -> basic_block_t { return bb; });

    {
      llvm::ListScope ___(Writer, (fmt("Basic Blocks (%u)") % blocks.size()).str());

      for (basic_block_t bb : blocks) {
        llvm::DictScope ____(Writer, (fmt("0x%lX") % ICFG[bb].Addr).str());

        {
          auto inv_adj_it_pair = boost::inv_adjacent_vertices(bb, ICFG);

          std::vector<uintptr_t> preds;
          preds.resize(
              std::distance(inv_adj_it_pair.first, inv_adj_it_pair.second));

          std::transform(inv_adj_it_pair.first, inv_adj_it_pair.second,
                         preds.begin(), [&](basic_block_t target) -> uintptr_t {
                           return ICFG[target].Addr;
                         });

          Writer.printHexList("Predecessors", preds);
        }

        Writer.getOStream() << '\n';

        //Writer.printHex("Address", ICFG[bb].Addr);
        Writer.printNumber("Size", ICFG[bb].Size);

        {
          llvm::DictScope _(Writer, (fmt("Term @ 0x%lX") % ICFG[bb].Term.Addr).str());

          //Writer.printHex("Address", ICFG[bb].Term.Addr);
          Writer.printString("Type", description_of_terminator(ICFG[bb].Term.Type));
        }

        Writer.getOStream() << '\n';

        if (!ICFG[bb].DynTargets.empty()) {
          std::vector<std::string> descv;
          descv.resize(ICFG[bb].DynTargets.size());

          std::transform(ICFG[bb].DynTargets.begin(), ICFG[bb].DynTargets.end(),
                         descv.begin(), [&](const auto &pair) -> std::string {
                           binary_index_t BIdx;
                           function_index_t FIdx;
                           std::tie(BIdx, FIdx) = pair;

                           auto &b = decompilation.Binaries[BIdx];
                           const auto &_ICFG = b.Analysis.ICFG;
                           auto &callee = b.Analysis.Functions[FIdx];
                           uintptr_t target_addr =
                               _ICFG[boost::vertex(callee.Entry, _ICFG)].Addr;

                           return (fmt("0x%lX @ %s") % target_addr %
                                   fs::path(b.Path).filename().string())
                               .str();
                         });

          Writer.printList("DynTargets", descv);
        }

        if (ICFG[bb].DynTargetsComplete)
          Writer.printBoolean("DynTargetsComplete",
                              ICFG[bb].DynTargetsComplete);

        {
          auto adj_it_pair = boost::adjacent_vertices(bb, ICFG);

          std::vector<uintptr_t> succs;
          succs.resize(std::distance(adj_it_pair.first, adj_it_pair.second));

          std::transform(adj_it_pair.first, adj_it_pair.second, succs.begin(),
                         [&](basic_block_t target) -> uintptr_t {
                           return ICFG[target].Addr;
                         });

          Writer.printHexList("Successors", succs);
        }
      }
    }

    {
      llvm::ListScope ___(Writer, (fmt("Functions (%u)") % B.Analysis.Functions.size()).str());

      for (const function_t &f : B.Analysis.Functions) {
        llvm::DictScope ____(Writer, (fmt("Func @ 0x%lX") % ICFG[boost::vertex(f.Entry, ICFG)].Addr).str());

        //Writer.printHex("Address", ICFG[boost::vertex(f.Entry, ICFG)].Addr);
        Writer.printBoolean("IsABI", f.IsABI);
      }
    }

    if (!B.Analysis.RelocDynTargets.empty()) {
      llvm::ListScope ___(Writer, "Relocation Dynamic Targets");

      for (const auto &pair : B.Analysis.RelocDynTargets) {
        llvm::DictScope ____(Writer);

        Writer.printHex("Relocation Address", pair.first);
        if (!pair.second.empty()) {
          std::vector<std::string> descv;
          descv.resize(pair.second.size());

          std::transform(pair.second.begin(), pair.second.end(), descv.begin(),
                         [&](const auto &pair) -> std::string {
                           binary_index_t BIdx;
                           function_index_t FIdx;
                           std::tie(BIdx, FIdx) = pair;

                           auto &b = decompilation.Binaries[BIdx];
                           const auto &_ICFG = b.Analysis.ICFG;
                           auto &callee = b.Analysis.Functions[FIdx];
                           uintptr_t target_addr =
                               _ICFG[boost::vertex(callee.Entry, _ICFG)].Addr;

                           return (fmt("0x%lX @ %s") % target_addr %
                                   fs::path(b.Path).filename().string())
                               .str();
                         });

          Writer.printList("Relocation DynTargets", descv);
        }
      }
    }

    if (!B.Analysis.IFuncDynTargets.empty()) {
      llvm::ListScope ___(Writer, "IFunc Dynamic Targets");

      for (const auto &pair : B.Analysis.IFuncDynTargets) {
        llvm::DictScope ____(Writer);

        Writer.printHex("Resolver Address", pair.first);
        if (!pair.second.empty()) {
          std::vector<std::string> descv;
          descv.resize(pair.second.size());

          std::transform(pair.second.begin(), pair.second.end(), descv.begin(),
                         [&](const auto &pair) -> std::string {
                           binary_index_t BIdx;
                           function_index_t FIdx;
                           std::tie(BIdx, FIdx) = pair;

                           auto &b = decompilation.Binaries[BIdx];
                           const auto &_ICFG = b.Analysis.ICFG;
                           auto &callee = b.Analysis.Functions[FIdx];
                           uintptr_t target_addr =
                               _ICFG[boost::vertex(callee.Entry, _ICFG)].Addr;

                           return (fmt("0x%lX @ %s") % target_addr %
                                   fs::path(b.Path).filename().string())
                               .str();
                         });

          Writer.printList("DynTargets", descv);
        }
      }
    }

    if (!B.Analysis.SymDynTargets.empty()) {
      llvm::ListScope ___(Writer, "Symbol Dynamic Targets");

      for (const auto &pair : B.Analysis.SymDynTargets) {
        llvm::DictScope ____(Writer);

        Writer.printString("Name", pair.first);
        if (!pair.second.empty()) {
          std::vector<std::string> descv;
          descv.resize(pair.second.size());

          std::transform(pair.second.begin(), pair.second.end(), descv.begin(),
                         [&](const auto &pair) -> std::string {
                           binary_index_t BIdx;
                           function_index_t FIdx;
                           std::tie(BIdx, FIdx) = pair;

                           auto &b = decompilation.Binaries[BIdx];
                           const auto &_ICFG = b.Analysis.ICFG;
                           auto &callee = b.Analysis.Functions[FIdx];
                           uintptr_t target_addr =
                               _ICFG[boost::vertex(callee.Entry, _ICFG)].Addr;

                           return (fmt("0x%lX @ %s") % target_addr %
                                   fs::path(b.Path).filename().string())
                               .str();
                         });

          Writer.printList("DynTargets", descv);
        }
      }
    }
  }
}

static void dumpInput(const std::string &Path) {
  decompilation_t decompilation;
  {
    std::ifstream ifs(fs::is_directory(Path) ? Path + "/decompilation.jv"
                                             : Path);

    boost::archive::binary_iarchive ia(ifs);
    ia >> decompilation;
  }

  if (opts::ListBinaries) {
    for (const auto &binary : decompilation.Binaries) {
      llvm::outs() << fs::path(binary.Path).filename().string() << '\n';
    }
  } else if (opts::Statistics) {
    for (const binary_t &binary : decompilation.Binaries) {
      llvm::outs() << llvm::formatv("Binary: {0}\n", binary.Path);
      llvm::outs() << llvm::formatv("  # of basic blocks: {0}\n",
                                    boost::num_vertices(binary.Analysis.ICFG));
      llvm::outs() << llvm::formatv("  # of functions: {0}\n",
                                    binary.Analysis.Functions.size());
    }
  } else if (!opts::ListFunctions.empty()) {
    for (unsigned BIdx = 0; BIdx < decompilation.Binaries.size(); ++BIdx) {
      const binary_t &binary = decompilation.Binaries[BIdx];

      if (fs::path(binary.Path).filename().string() != opts::ListFunctions)
        continue;

      const auto &ICFG = binary.Analysis.ICFG;

      for (unsigned FIdx = 0; FIdx < binary.Analysis.Functions.size(); ++FIdx) {
        const function_t &function = binary.Analysis.Functions[FIdx];
        uintptr_t Addr = ICFG[boost::vertex(function.Entry, ICFG)].Addr;

        llvm::outs() << llvm::formatv("{0},{1} @ {2:x}\n", BIdx, FIdx, Addr);
      }
    }
  } else if (!opts::ListFunctionBBs.empty()) {
    llvm::ScopedPrinter Writer(llvm::outs());

    for (unsigned BIdx = 0; BIdx < decompilation.Binaries.size(); ++BIdx) {
      const binary_t &binary = decompilation.Binaries[BIdx];

      if (fs::path(binary.Path).filename().string() != opts::ListFunctionBBs)
        continue;

      auto &ICFG = binary.Analysis.ICFG;

      for (const function_t &f : binary.Analysis.Functions) {
        basic_block_t entry = boost::vertex(f.Entry, ICFG);

        std::vector<basic_block_t> blocks;
        blocks.reserve(boost::num_vertices(ICFG));

        reached_visitor vis(blocks);
        boost::breadth_first_search(ICFG, entry, boost::visitor(vis));

        std::vector<uintptr_t> addrs;
        addrs.resize(blocks.size());

        std::transform(
            blocks.begin(), blocks.end(), addrs.begin(),
            [&](basic_block_t bb) -> uintptr_t { return ICFG[bb].Addr; });

        Writer.printHexList("Fn", addrs);
      }
    }
  } else {
    dumpDecompilation(decompilation);
  }
}

}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::HideUnrelatedOptions({&opts::JoveCategory, &llvm::ColorCategory});
  cl::ParseCommandLineOptions(argc, argv, "Jove Decompilation Reader\n");

  for (const std::string &Path : opts::InputFilenames) {
    if (!fs::exists(Path)) {
      WithColor::error() << Path << " does not exist\n";
      return 1;
    }
  }

  llvm::for_each(opts::InputFilenames, jove::dumpInput);

  return 0;
}
