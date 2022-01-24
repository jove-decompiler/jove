#include "jove/jove.h"

#include <cstdlib>
#include <sys/wait.h>
#include <sys/vfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <boost/filesystem.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/graph/adj_list_serialize.hpp>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/WithColor.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/FormatVariadic.h>

namespace fs = boost::filesystem;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace opts {
static cl::OptionCategory JoveCategory("Specific Options");

static cl::opt<std::string> TraceBinPath(cl::Positional, cl::desc("trace.bin"),
                                         cl::Required,
                                         cl::value_desc("filename"),
                                         cl::cat(JoveCategory));

} // namespace opts

namespace jove {
static int readtrace(void);
}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::HideUnrelatedOptions({&opts::JoveCategory, &llvm::ColorCategory});
  cl::AddExtraVersionPrinter([](llvm::raw_ostream &OS) -> void {
    OS << "jove version " JOVE_VERSION "\n";
  });
  cl::ParseCommandLineOptions(argc, argv, "Jove Trace\n");

  if (!fs::exists(opts::TraceBinPath)) {
    WithColor::error() << "trace.bin does not exist\n";
    return 1;
  }

  return jove::readtrace();
}

namespace jove {

int readtrace(void) {

  std::ifstream ifs(opts::TraceBinPath.c_str());

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
