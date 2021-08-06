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
#include <boost/serialization/bitset.hpp>
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

static cl::opt<std::string> TracePath(cl::Positional, cl::desc("trace.txt"),
                                      cl::Required, cl::value_desc("filename"),
                                      cl::cat(JoveCategory));

static cl::opt<std::string> jv("decompilation", cl::desc("Jove decompilation"),
                               cl::Required, cl::value_desc("filename"),
                               cl::cat(JoveCategory));

static cl::alias jvAlias("d", cl::desc("Alias for -decompilation."),
                         cl::aliasopt(jv), cl::cat(JoveCategory));

static cl::opt<bool> SkipRepeated("skip-repeated",
                                  cl::desc("Skip repeated blocks"),
                                  cl::cat(JoveCategory));

} // namespace opts

namespace jove {
static int trace2addrs(void);
}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::HideUnrelatedOptions({&opts::JoveCategory, &llvm::ColorCategory});
  cl::AddExtraVersionPrinter([](llvm::raw_ostream &OS) -> void {
    OS << "jove version " JOVE_VERSION "\n";
  });
  cl::ParseCommandLineOptions(argc, argv, "Jove Trace\n");

  if (!fs::exists(opts::TracePath)) {
    WithColor::error() << "trace does not exist\n";
    return 1;
  }

  if (!fs::exists(opts::jv)) {
    WithColor::error() << "decompilation does not exist\n";
    return 1;
  }

  return jove::trace2addrs();
}

namespace jove {

static int await_process_completion(pid_t);

int trace2addrs(void) {
  llvm::raw_ostream &OutputStream = llvm::outs();

  //
  // parse trace.txt
  //
  std::vector<std::pair<binary_index_t, basic_block_index_t>> trace;

  {
    std::ifstream trace_ifs(opts::TracePath.c_str());

    if (!trace_ifs) {
      WithColor::error() << llvm::formatv("failed to open trace file '{0}'\n",
                                          opts::TracePath.c_str());
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
      int fields = sscanf(line.c_str(), "JV_%" PRIu32 "_%" PRIu32, &BIdx, &BBIdx);

      if (fields != 2)
        break;

      if (opts::SkipRepeated) {
        if (Last.BIdx == BIdx && Last.BBIdx == BBIdx)
          continue;
      }

      trace.push_back({BIdx, BBIdx});

      Last.BIdx = BIdx;
      Last.BBIdx = BBIdx;
    }
  }

  //
  // parse the given decompilation
  //
  decompilation_t decompilation;
  bool git = fs::is_directory(opts::jv);
  {
    std::ifstream ifs(git ? (opts::jv + "/decompilation.jv") : opts::jv);

    boost::archive::text_iarchive ia(ifs);
    ia >> decompilation;
  }

  //
  // for every block in the trace, print out its description.
  //
  for (const auto &pair : trace) {
    binary_index_t BIdx;
    basic_block_index_t BBIdx;

    std::tie(BIdx, BBIdx) = pair;

    const auto &binary = decompilation.Binaries.at(BIdx);
    const auto &ICFG = binary.Analysis.ICFG;
    basic_block_t bb = boost::vertex(BBIdx, ICFG);

    OutputStream << llvm::formatv("{0}+0x{1:x}\n",
                                  fs::path(binary.Path).filename().c_str(),
                                  ICFG[bb].Addr);
  }

  return 1;
}

int await_process_completion(pid_t pid) {
  int wstatus;
  do {
    if (waitpid(pid, &wstatus, WUNTRACED | WCONTINUED) < 0)
      abort();

    if (WIFEXITED(wstatus)) {
      //printf("exited, status=%d\n", WEXITSTATUS(wstatus));
      return WEXITSTATUS(wstatus);
    } else if (WIFSIGNALED(wstatus)) {
      //printf("killed by signal %d\n", WTERMSIG(wstatus));
      return 1;
    } else if (WIFSTOPPED(wstatus)) {
      //printf("stopped by signal %d\n", WSTOPSIG(wstatus));
      return 1;
    } else if (WIFCONTINUED(wstatus)) {
      //printf("continued\n");
    }
  } while (!WIFEXITED(wstatus) && !WIFSIGNALED(wstatus));

  abort();
}

}
