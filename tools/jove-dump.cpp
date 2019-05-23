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

  for (const auto &B : decompilation.Binaries) {
    Writer.printString("Binary", B.Path);
    llvm::ListScope _(Writer);
    Writer.printBoolean("IsDynamicLinker", B.IsDynamicLinker);
    Writer.printBoolean("IsExecutable", B.IsExecutable);

    const auto &ICFG = B.Analysis.ICFG;

    if (is_function_index_valid(B.Analysis.EntryFunction)) {
      const function_t &entryFunc =
          B.Analysis.Functions.at(B.Analysis.EntryFunction);
      Writer.printHex("Entry", ICFG[boost::vertex(entryFunc.Entry, ICFG)].Addr);
    }

    for (const auto &F : B.Analysis.Functions) {
      basic_block_t entry = boost::vertex(F.Entry, ICFG);

      std::vector<basic_block_t> blocks;
      blocks.reserve(boost::num_vertices(ICFG));

      reached_visitor vis(blocks);
      boost::breadth_first_search(ICFG, entry, boost::visitor(vis));

      if (opts::Compact) {
        std::vector<uintptr_t> addrs;
        addrs.resize(blocks.size());

        std::transform(
            blocks.begin(), blocks.end(), addrs.begin(),
            [&](basic_block_t bb) -> uintptr_t { return ICFG[bb].Addr; });

        Writer.printHexList("Fn", addrs);
      } else {
        llvm::ListScope _(Writer);

        for (basic_block_t bb : blocks) {
          llvm::DictScope _(Writer);

          {
            auto inv_adj_it_pair = boost::inv_adjacent_vertices(bb, ICFG);

            std::vector<uintptr_t> preds;
            preds.resize(
                std::distance(inv_adj_it_pair.first, inv_adj_it_pair.second));

            std::transform(inv_adj_it_pair.first, inv_adj_it_pair.second,
                           preds.begin(),
                           [&](basic_block_t target) -> uintptr_t {
                             return ICFG[target].Addr;
                           });

            Writer.printHexList("Predecessors", preds);
          }

          Writer.getOStream() << '\n';

          Writer.printHex("Addr", ICFG[bb].Addr);
          Writer.printNumber("Size", ICFG[bb].Size);

          {
            llvm::DictScope _(Writer);

            Writer.printHex("Addr", ICFG[bb].Term.Addr);
            Writer.printString("Type",
                               description_of_terminator(ICFG[bb].Term.Type));
          }

          Writer.getOStream() << '\n';

          if (!ICFG[bb].DynTargets.empty()) {
            std::vector<std::string> descv;
            descv.resize(ICFG[bb].DynTargets.size());

            std::transform(
                ICFG[bb].DynTargets.begin(),
                ICFG[bb].DynTargets.end(),
                descv.begin(),
                [&](const auto &pair) -> std::string {
                  binary_index_t BIdx;
                  function_index_t FIdx;
                  std::tie(BIdx, FIdx) = pair;

                  auto &b = decompilation.Binaries[BIdx];
                  const auto &_ICFG = b.Analysis.ICFG;
                  auto &callee = b.Analysis.Functions[FIdx];
                  uintptr_t target_addr =
                      _ICFG[boost::vertex(callee.Entry, _ICFG)].Addr;

                  return (fmt("%#lx @ %s")
                          % target_addr
                          % fs::path(b.Path).filename().string()).str();
                });

            Writer.printList("DynTargets", descv);
          }

          if (boost::out_degree(bb, ICFG) > 0) {
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
  } else if (!opts::ListFunctions.empty()) {
    for (const auto &binary : decompilation.Binaries) {
      if (fs::path(binary.Path).filename().string() != opts::ListFunctions)
        continue;

      std::vector<uintptr_t> AddrVec;
      AddrVec.resize(binary.Analysis.Functions.size());

      const auto &ICFG = binary.Analysis.ICFG;

      std::transform(binary.Analysis.Functions.begin(),
                     binary.Analysis.Functions.end(), AddrVec.begin(),
                     [&](const function_t &function) -> uintptr_t {
                       return ICFG[boost::vertex(function.Entry, ICFG)].Addr;
                     });

      for (uintptr_t Addr : AddrVec)
        llvm::outs() << llvm::format_hex(Addr, 1) << '\n';
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
