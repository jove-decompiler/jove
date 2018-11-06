#include "jove/jove.h"
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/DataTypes.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/ScopedPrinter.h>

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

namespace opts {
  cl::list<std::string> InputFilenames(cl::Positional,
    cl::desc("<input jove files>"),
    cl::OneOrMore);

  cl::opt<bool> Compact("compact",
    cl::desc("Print functions as list of basic-blocks addresses"));

  cl::opt<bool> Graphviz("graphviz",
    cl::desc("Produce control-flow graphs for each function"));
}

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

    const auto &ICFG = B.Analysis.ICFG;

    for (const auto &F : B.Analysis.Functions) {
      basic_block_t entry = boost::vertex(F.Entry, ICFG);

      std::vector<basic_block_t> blocks;
      blocks.reserve(boost::num_vertices(ICFG));

      reached_visitor vis(blocks);
      boost::breadth_first_search(ICFG, entry, boost::visitor(vis));

      if (opts::Compact) {
        std::vector<uint64_t> addrs;
        addrs.resize(blocks.size());

        std::transform(
            blocks.begin(), blocks.end(), addrs.begin(),
            [&](basic_block_t bb) -> uint64_t { return ICFG[bb].Addr; });

        Writer.printHexList("Fn", addrs);
      } else {
        Writer.printHex("Function", ICFG[entry].Addr);
        llvm::ListScope _(Writer);

        for (basic_block_t bb : blocks) {
          llvm::DictScope _(Writer);

          Writer.printHex("Addr", ICFG[bb].Addr);
          Writer.printNumber("Size", ICFG[bb].Size);

          {
            llvm::DictScope _(Writer);

            Writer.printHex("Addr", ICFG[bb].Term.Addr);
            Writer.printString("Type",
                               description_of_terminator(ICFG[bb].Term.Type));
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

  dumpDecompilation(decompilation);
}

}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::ParseCommandLineOptions(argc, argv, "Jove Decompilation Reader\n");

  for (const std::string &Path : opts::InputFilenames) {
    if (!fs::exists(Path)) {
      llvm::errs() << Path << " does not exist\n";
      return 1;
    }
  }

  llvm::for_each(opts::InputFilenames, jove::dumpInput);

  return 0;
}
