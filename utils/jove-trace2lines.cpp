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
#include <llvm/DebugInfo/Symbolize/Symbolize.h>

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

static cl::opt<bool> PrintSource("print-source",
                                 cl::desc("Print actual source code"),
                                 cl::cat(JoveCategory));

static cl::opt<bool> Vim("vim",
                         cl::desc("Start vim in quickFix mode"),
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

static fs::path path_to_vim;

static char tmpdir[] = {'/', 't', 'm', 'p', '/', 'X',
                        'X', 'X', 'X', 'X', 'X', '\0'};

static fs::path path_to_tmpfile;
static std::unique_ptr<llvm::raw_fd_ostream> tmpfile_ostream;

int trace2lines(void) {
  if (opts::Vim) {
    path_to_vim = fs::path("/") / "usr" / "bin" / "vim";
    if (!fs::exists(path_to_vim)) {
      WithColor::error() << "--vim provided on the command-line but could not "
                            "find vim executable\n";
      return 1;
    }

    if (!mkdtemp(tmpdir)) {
      int err = errno;
      WithColor::error() << llvm::formatv("mkdtemp failed : {0}\n",
                                          strerror(err));
      return 1;
    }

    path_to_tmpfile = fs::path(tmpdir) / "Trace.txt";
    std::error_code EC;

    tmpfile_ostream.reset(
        new llvm::raw_fd_ostream(path_to_tmpfile.c_str(), EC));
  }

  {
    llvm::raw_ostream &OutputStream =
        opts::Vim ? *tmpfile_ostream : llvm::outs();

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
        int fields =
            sscanf(line.c_str(), "JV_%" PRIu32 "_%" PRIu32, &BIdx, &BBIdx);

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
      binary_index_t BIdx = opts::ExcludeFns[i + 0];
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

    llvm::symbolize::LLVMSymbolizer::Options Opts;
    Opts.PrintFunctions = llvm::symbolize::FunctionNameKind::None;
    Opts.UseSymbolTable = false;
    Opts.Demangle = false;
    Opts.RelativeAddresses = true;
#if 0
  Opts.FallbackDebugPath = ""; // ClFallbackDebugPath
  Opts.DebugFileDirectory = ""; // ClDebugFileDirectory;
#endif

    llvm::symbolize::LLVMSymbolizer Symbolizer(Opts);

    //
    // addr2line for every block in the trace
    //
    for (const auto &pair : trace) {
      binary_index_t BIdx;
      basic_block_index_t BBIdx;

      std::tie(BIdx, BBIdx) = pair;

      if (Excludes[BIdx].find(BBIdx) != Excludes[BIdx].end())
        continue;

      if (std::find(opts::ExcludeBinaries.begin(), opts::ExcludeBinaries.end(),
                    BIdx) != opts::ExcludeBinaries.end())
        continue;

      const auto &binary = decompilation.Binaries.at(BIdx);
      const auto &ICFG = binary.Analysis.ICFG;
      basic_block_t bb = boost::vertex(BBIdx, ICFG);

      auto ResOrErr = Symbolizer.symbolizeCode(
          binary.Path,
          {ICFG[bb].Addr, llvm::object::SectionedAddress::UndefSection});
      if (!ResOrErr)
        continue;

      llvm::DILineInfo &LnInfo = ResOrErr.get();

      if (LnInfo.FileName == llvm::DILineInfo::BadString)
        continue;

      if (fs::path(LnInfo.FileName).is_relative()) {
        fs::path FileName = fs::path("/usr/src/debug") /
                            fs::path(binary.Path).stem().c_str() /
                            LnInfo.FileName;

        OutputStream << llvm::formatv("{0}:{1}:{2}\n", FileName.c_str(),
                                      LnInfo.Line, LnInfo.Column);
      } else {
        OutputStream << llvm::formatv("{0}:{1}:{2}\n", LnInfo.FileName,
                                      LnInfo.Line, LnInfo.Column);
      }
    }
  }

  if (!opts::Vim)
    return 0;

  tmpfile_ostream.reset(nullptr);

  const char *arg_arr[] = {
    path_to_vim.c_str(),

    "--cmd", "set errorformat=%f:%l:%c",
    "-q", path_to_tmpfile.c_str(),
    nullptr
  };

  execve(arg_arr[0], const_cast<char **>(&arg_arr[0]), ::environ);

  /* if we got here, execve failed */
  int err = errno;
  WithColor::error() << llvm::formatv(
      "failed to execve vim in quickFix mode (reason: {0})", strerror(err));

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
