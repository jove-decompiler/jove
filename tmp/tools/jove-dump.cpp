#include "jove/jove.h"
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/DataTypes.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/ScopedPrinter.h>

#include <fstream>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/graph/adj_list_serialize.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/graph/breadth_first_search.hpp>
#include <boost/pending/indirect_cmp.hpp>
#include <boost/range/irange.hpp>

namespace cl = llvm::cl;

namespace opts {
  cl::list<std::string> InputFilenames(cl::Positional,
    cl::desc("<input jove files>"),
    cl::OneOrMore);

  cl::opt<bool> Graphviz("graphviz",
    cl::desc("Produce control-flow graphs for each function"));
}

namespace jove {

struct reached_visitor : public boost::default_bfs_visitor {
  std::vector<basic_block_t> &out;

  reached_visitor(std::vector<basic_block_t> &out) : out(out) {}

  void discover_vertex(basic_block_t bb,
                       const interprocedural_control_flow_graph_t &) const {
    out.push_back(bb);
  }
};

struct ScopedIndent {
  llvm::ScopedPrinter &SP;

  ScopedIndent(llvm::ScopedPrinter &SP) : SP(SP) { SP.indent(); }
  ~ScopedIndent() { SP.unindent(); }
};

static void dumpDecompilation(const decompilation_t& decompilation) {
  llvm::ScopedPrinter Writer(llvm::outs());

  for (const auto &B : decompilation.Binaries) {
    Writer.printString("Binary", B.Path);
    ScopedIndent _(Writer);

    const auto &ICFG = B.Analysis.ICFG;

    for (const auto &F : B.Analysis.Functions) {
      basic_block_t entry = boost::vertex(F.Entry, ICFG);
      Writer.printHex("Function", ICFG[entry].Addr);
      ScopedIndent _(Writer);

      std::vector<basic_block_t> reached;
      reached.reserve(boost::num_vertices(ICFG));

      reached_visitor vis(reached);
      boost::breadth_first_search(ICFG, entry, boost::visitor(vis));

      for (basic_block_t bb : reached)
        Writer.printHex("BB", ICFG[bb].Addr);
    }
  }
}

static void dumpInput(llvm::StringRef File) {
  jove::decompilation_t decompilation;
  {
    std::ifstream ifs(File);

    boost::archive::binary_iarchive ia(ifs);
    ia >> decompilation;
  }

  dumpDecompilation(decompilation);
}

}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::ParseCommandLineOptions(argc, argv, "Jove Decompilation Reader\n");

  llvm::for_each(opts::InputFilenames, jove::dumpInput);
  return 0;
}
