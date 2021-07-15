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

#if defined(TARGET_MIPS32) || defined(TARGET_MIPS64)
  std::ifstream ifs(opts::TraceBinPath.c_str());

  struct {
    uint32_t BIdx;
    uint32_t BBIdx;
  } Trace;

  while (ifs.read(reinterpret_cast<char *>(&Trace.BIdx), sizeof(uint32_t)) &&
         ifs.read(reinterpret_cast<char *>(&Trace.BBIdx), sizeof(uint32_t))) {
    llvm::outs() << llvm::formatv("JV_{0}_{1}\n", Trace.BIdx, Trace.BBIdx);
  }
#else
  int fd = open(opts::TraceBinPath.c_str(), O_RDONLY);
  if (fd < 0) {
    int err = errno;
    WithColor::error() << llvm::formatv("failed to open trace.bin: {0}\n",
                                        strerror(err));
    return 1;
  }

  off_t size = 1UL << 30; /* 2 GiB */
  void *trace_begin = mmap(nullptr, size, PROT_READ, MAP_SHARED, fd, 0);
  if (trace_begin == MAP_FAILED) {
    int err = errno;
    WithColor::error() << llvm::formatv("failed to open trace.bin: {0}\n",
                                        strerror(err));
    return 1;
  }

  for (uint32_t *p = reinterpret_cast<uint32_t *>(trace_begin);
       p[0] || p[1] || p[2] || p[3] || p[4] || p[5] || p[6] || p[7] || p[8];
       p += 2) {
    uint32_t BIdx = p[1];
    uint32_t BBIdx = p[0];

    llvm::outs() << llvm::formatv("JV_{0}_{1}\n", BIdx, BBIdx);
  }
#endif

  return 0;
}

}
