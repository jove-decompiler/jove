#include <vector>

#define JOVE_EXTRA_FN_PROPERTIES                                               \
  std::vector<basic_block_t> BasicBlocks;

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
#include <boost/serialization/bitset.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/graph/adj_list_serialize.hpp>
#include <boost/graph/depth_first_search.hpp>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/WithColor.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/FormatVariadic.h>

//#define JOVE_TRACE2LINES_USE_ADDR2LINE

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

static cl::list<unsigned>
    ExcludeFns("exclude-fns", cl::CommaSeparated,
               cl::value_desc("bidx_1,fidx_1,...,bidx_n,fidx_n"),
               cl::desc("Indices of functions to exclude"),
               cl::cat(JoveCategory));

static cl::list<unsigned>
    ExcludeBinaries("exclude-bins", cl::CommaSeparated,
               cl::value_desc("bidx_1,bidx_2,...,bidx_n"),
               cl::desc("Indices of binaries to exclude"),
               cl::cat(JoveCategory));

static cl::opt<bool> SkipRepeated("skip-repeated",
                                  cl::desc("Skip repeated blocks"),
                                  cl::cat(JoveCategory));

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

  if (opts::ExcludeFns.size() % 2 != 0) {
    WithColor::error() << "number of args given for exclude-fns is odd\n";
    return 1;
  }

  return jove::trace2lines();
}

namespace jove {

static int await_process_completion(pid_t);

template <typename GraphTy>
struct dfs_visitor : public boost::default_dfs_visitor {
  typedef typename GraphTy::vertex_descriptor VertTy;

  std::vector<VertTy> &out;

  dfs_visitor(std::vector<VertTy> &out) : out(out) {}

  void discover_vertex(VertTy v, const GraphTy &) const { out.push_back(v); }
};

static fs::path llvm_symbolizer_path;

int trace2lines(void) {
#ifndef JOVE_TRACE2LINES_USE_ADDR2LINE
  //
  // find symbolizer path
  //
  {
    llvm_symbolizer_path = "/usr/bin/llvm-symbolizer";
    if (!fs::exists(llvm_symbolizer_path))
      llvm_symbolizer_path = "/usr/bin/llvm-symbolizer-10";
    if (!fs::exists(llvm_symbolizer_path)) {
      WithColor::error() << "failed to find llvm-symbolizer\n";
      return 1;
    }
  }
#endif

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

    struct {
      binary_index_t BIdx;
      basic_block_index_t BBIdx;
    } Last;

    Last.BIdx = invalid_binary_index;
    Last.BBIdx = invalid_basic_block_index;

    char *line = nullptr;
    size_t len = 0;
    ssize_t read;
    while ((read = getline(&line, &len, f)) != -1) {
      uint32_t BIdx, BBIdx;
      int fields = sscanf(line, "JV_%" PRIu32 "_%" PRIu32, &BIdx, &BBIdx);

      if (fields != 2)
        break;

      if (opts::SkipRepeated) {
        if (Last.BIdx == BIdx &&
            Last.BBIdx == BBIdx)
          continue;
      }

      trace.push_back({BIdx, BBIdx});

      Last.BIdx = BIdx;
      Last.BBIdx = BBIdx;
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
  // compute the set of verts for each function
  //
  for (binary_t &binary : decompilation.Binaries) {
    auto &ICFG = binary.Analysis.ICFG;

    for (function_t &function : binary.Analysis.Functions) {
      //
      // BasicBlocks (in DFS order)
      //
      std::map<basic_block_t, boost::default_color_type> color;
      dfs_visitor<interprocedural_control_flow_graph_t> vis(
          function.BasicBlocks);
      depth_first_visit(
          ICFG, boost::vertex(function.Entry, ICFG), vis,
          boost::associative_property_map<
              std::map<basic_block_t, boost::default_color_type>>(color));
    }
  }

  std::vector<std::unordered_set<basic_block_index_t>> Excludes;
  Excludes.resize(decompilation.Binaries.size());

  for (unsigned i = 0; i < opts::ExcludeFns.size(); i += 2) {
    binary_index_t   BIdx = opts::ExcludeFns[i + 0];
    function_index_t FIdx = opts::ExcludeFns[i + 1];

    binary_t &binary = decompilation.Binaries.at(BIdx);
    function_t &function = binary.Analysis.Functions.at(FIdx);

    const auto &ICFG = binary.Analysis.ICFG;

    boost::property_map<interprocedural_control_flow_graph_t,
                        boost::vertex_index_t>::type bb_idx_map =
        boost::get(boost::vertex_index, ICFG);

    for (basic_block_t bb : function.BasicBlocks) {
      basic_block_index_t BBIdx = bb_idx_map[bb];

      Excludes[BIdx].insert(BBIdx);
    }
  }

#ifndef JOVE_TRACE2LINES_USE_ADDR2LINE
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
      WithColor::error() << llvm::formatv("dup2 failed: {0}\n", strerror(err));
      exit(1);
    }

    const char *argv[] = {
      llvm_symbolizer_path.c_str(),
      "-print-address",
      "-inlining=0",
      "-pretty-print",
      "-print-source-context-lines=10",
      nullptr
    };

    execve(argv[0], const_cast<char **>(&argv[0]), ::environ);

    int err = errno;
    WithColor::error() << llvm::formatv(
        "failed to exec llvm-symbolizer : {0}\n", strerror(err));

    return 1;
  }

  close(pipefd[0]); /* close unused read end */
#endif

  //
  // addr2line for every block in the trace
  //
  for (const auto &pair : trace) {
    binary_index_t BIdx;
    basic_block_index_t BBIdx;

    std::tie(BIdx, BBIdx) = pair;

    if (Excludes[BIdx].find(BBIdx) != Excludes[BIdx].end())
      continue;

    if (std::find(opts::ExcludeBinaries.begin(),
                  opts::ExcludeBinaries.end(), BIdx) != opts::ExcludeBinaries.end())
      continue;

    const auto &binary = decompilation.Binaries.at(BIdx);
    const auto &ICFG = binary.Analysis.ICFG;
    basic_block_t bb = boost::vertex(BBIdx, ICFG);

#ifdef JOVE_TRACE2LINES_USE_ADDR2LINE
    pid_t pid = fork();

    //
    // are we the child?
    //
    if (!pid) {
      write(1, binary.Path.c_str(), binary.Path.size());
      write(1, " ", strlen(" "));

      char buff[0x100];
      snprintf(buff, sizeof(buff), "0x%" PRIxPTR "\n", ICFG[bb].Addr);

      const char *argv[] = {
        "/usr/bin/addr2line",
        "-e", binary.Path.c_str(),
        "--addresses",
        "--pretty-print",
        "--functions",
        buff,
        nullptr
      };

      return execve(argv[0], const_cast<char **>(&argv[0]), ::environ);
    }

    if (int ret = await_process_completion(pid)) {
      WithColor::error() << llvm::formatv(
          "addr2line failed with exit status {0}\n", ret);
      return 1;
    }
#else
    char buff[0x100];
    snprintf(buff, sizeof(buff), "%s 0x%" PRIxPTR "\n",
             binary.Path.c_str(),
             ICFG[bb].Addr);

    if (write(pipefd[1], buff, strlen(buff)) < 0) {
      int err = errno;
      WithColor::error() << llvm::formatv("write to pipe failed: {0}\n",
                                          strerror(err));
      return 1;
    }
#endif

//    llvm::outs() << llvm::formatv("JV_{0}_{1}\n", BIdx, BBIdx);
  }

#ifndef JOVE_TRACE2LINES_USE_ADDR2LINE
  close(pipefd[1]); /* close write end */

  if (int ret = await_process_completion(pid))
    return 1;
#endif

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
