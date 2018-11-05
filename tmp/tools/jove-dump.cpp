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

namespace cl = llvm::cl;

namespace opts {
  cl::list<std::string> InputFilenames(cl::Positional,
    cl::desc("<input jove files>"),
    cl::OneOrMore);

  cl::opt<bool> Graphviz("graphviz",
    cl::desc("Produce control-flow graphs for each function"));
}

static void dumpInput(llvm::StringRef File) {
  llvm::ScopedPrinter Writer(llvm::outs());

  jove::decompilation_t decompilation;
  {
    std::ifstream ifs(File);

    boost::archive::binary_iarchive ia(ifs);
    ia >> decompilation;
  }

  for (jove::binary_t &binary : decompilation.Binaries) {
    Writer.printString("File", binary.Path);
    Writer.printString("Arch", ___JOVE_ARCH_NAME);

#if 0
    printf("  %lu Functions.\n", binary.Analysis.Functions.size());
    printf("  %lu Basic Blocks.\n", boost::num_vertices(binary.Analysis.ICFG));
    printf("  %lu Branches.\n", boost::num_edges(binary.Analysis.ICFG));
#endif
  }
}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::ParseCommandLineOptions(argc, argv, "Jove Decompilation Reader\n");

  llvm::for_each(opts::InputFilenames, dumpInput);
  return 0;
}
