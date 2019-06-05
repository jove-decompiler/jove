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
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
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

} // namespace opts

namespace jove {
static int trace2lines(void);
}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::HideUnrelatedOptions({&opts::JoveCategory, &llvm::ColorCategory});
  cl::ParseCommandLineOptions(argc, argv, "Jove Trace\n");

  if (!fs::exists(opts::TracePath)) {
    WithColor::error() << "trace does not exist\n";
    return 1;
  }

  if (!fs::exists(opts::jv)) {
    WithColor::error() << "decompilation does not exist\n";
    return 1;
  }

  return jove::trace2lines();
}

namespace jove {

static int await_process_completion(pid_t);

int trace2lines(void) {
  //
  // parse trace.txt
  //
  std::vector<std::pair<binary_index_t, basic_block_index_t>> trace;

  {
    FILE *f = fopen(opts::TracePath.c_str(), "r");
    if (!f) {
      int err = errno;
      WithColor::error() << llvm::formatv("failed to open trace: {0}\n",
                                          strerror(err));
      return 1;
    }

    char *line = nullptr;
    size_t len = 0;
    ssize_t read;
    while ((read = getline(&line, &len, f)) != -1) {
      uint32_t BIdx, BBIdx;
      int fields = sscanf(line, "JV_%" PRIu32 "_%" PRIu32, &BIdx, &BBIdx);

      if (fields != 2)
        break;

      trace.push_back({BIdx, BBIdx});
    }

    free(line);
    fclose(f);
  }

  //
  // parse the existing decompilation file
  //
  decompilation_t decompilation;
  bool git = fs::is_directory(opts::jv);
  {
    std::ifstream ifs(git ? (opts::jv + "/decompilation.jv") : opts::jv);

    boost::archive::binary_iarchive ia(ifs);
    ia >> decompilation;
  }

  //
  // execute addr2line for every block in the trace
  //
  for (const auto &pair : trace) {
    binary_index_t BIdx;
    basic_block_index_t BBIdx;

    std::tie(BIdx, BBIdx) = pair;

    int pipefd[2];
    if (pipe(pipefd) < 0) {
      int err = errno;
      WithColor::error() << llvm::formatv("pipe failed: {0}\n", strerror(err));
      return 1;
    }

    pid_t pid = fork();

    //
    // are we the child?
    //
    if (!pid) {
      close(pipefd[1]); /* close unused write end */

      /* make stdin be the read end of the pipe */
      if (dup2(pipefd[0], STDIN_FILENO) < 0) {
	int err = errno;
        WithColor::error() << llvm::formatv("dup2 failed: {0}\n",
                                            strerror(err));
        exit(1);
      }

      const char *argv[] = {"/usr/bin/llvm-symbolizer",
                            "-print-source-context-lines=10",
			    nullptr};

      return execve(argv[0], const_cast<char **>(&argv[0]), ::environ);
    }

    close(pipefd[0]); /* close unused read end */

    const auto &binary = decompilation.Binaries.at(BIdx);
    const auto &ICFG = binary.Analysis.ICFG;
    basic_block_t bb = boost::vertex(BBIdx, ICFG);

    char buff[0x100];
    snprintf(buff, sizeof(buff), "%s 0x%lx",
	     binary.Path.c_str(),
             ICFG[bb].Addr);

    if (write(pipefd[1], buff, strlen(buff)) < 0) {
      int err = errno;
      WithColor::error() << llvm::formatv("write to pipe failed: {0}\n",
                                          strerror(err));
      return 1;
    }

    close(pipefd[1]); /* close write end */

    if (int ret = await_process_completion(pid))
      return 1;

//    llvm::outs() << llvm::formatv("JV_{0}_{1}\n", BIdx, BBIdx);
  }
  return 0;
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
