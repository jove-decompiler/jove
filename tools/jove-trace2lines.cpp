#include "tool.h"

#include <boost/filesystem.hpp>

#include <llvm/Support/FormatVariadic.h>
#include <llvm/DebugInfo/Symbolize/Symbolize.h>
#include <llvm/Support/WithColor.h>

namespace fs = boost::filesystem;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

struct function_state_t {
  basic_block_vec_t BasicBlocks;
};

class Trace2LinesTool : public Tool {
  struct Cmdline {
    cl::opt<std::string> TracePath;
    cl::opt<std::string> jv;
    cl::alias jvAlias;
    cl::list<unsigned> ExcludeFns;
    cl::list<unsigned> ExcludeBinaries;
    cl::opt<bool> SkipRepeated;
    cl::opt<bool> PrintSource;
    cl::opt<bool> Vim;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : TracePath(cl::Positional, cl::desc("trace.txt"), cl::Required,
                    cl::value_desc("filename"), cl::cat(JoveCategory)),

          jv("decompilation", cl::desc("Jove decompilation"), cl::Required,
             cl::value_desc("filename"), cl::cat(JoveCategory)),

          jvAlias("d", cl::desc("Alias for -decompilation."), cl::aliasopt(jv),
                  cl::cat(JoveCategory)),

          ExcludeFns("exclude-fns", cl::CommaSeparated,
                     cl::value_desc("bidx_1,fidx_1,...,bidx_n,fidx_n"),
                     cl::desc("Indices of functions to exclude"),
                     cl::cat(JoveCategory)),

          ExcludeBinaries("exclude-bins", cl::CommaSeparated,
                          cl::value_desc("bidx_1,bidx_2,...,bidx_n"),
                          cl::desc("Indices of binaries to exclude"),
                          cl::cat(JoveCategory)),

          SkipRepeated("skip-repeated", cl::desc("Skip repeated blocks"),
                       cl::cat(JoveCategory)),

          PrintSource("print-source", cl::desc("Print actual source code"),
                      cl::cat(JoveCategory)),

          Vim("vim", cl::desc("Start vim in quickFix mode"),
              cl::cat(JoveCategory)) {}
  } opts;

public:
  Trace2LinesTool() : opts(JoveCategory) {}

  int Run(void);
};

JOVE_REGISTER_TOOL("trace2lines", Trace2LinesTool);

static fs::path path_to_vim;

static char tmpdir[] = {'/', 't', 'm', 'p', '/', 'X',
                        'X', 'X', 'X', 'X', 'X', '\0'};

static fs::path path_to_tmpfile;
static std::unique_ptr<llvm::raw_fd_ostream> tmpfile_ostream;

int Trace2LinesTool::Run(void) {
  if (!fs::exists(opts.TracePath)) {
    WithColor::error() << "trace does not exist\n";
    return 1;
  }

  if (!fs::exists(opts.jv)) {
    WithColor::error() << "decompilation does not exist\n";
    return 1;
  }

  if (opts.ExcludeFns.size() % 2 != 0) {
    WithColor::error() << "number of args given for exclude-fns is odd\n";
    return 1;
  }

  if (opts.Vim) {
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
        opts.Vim ? *tmpfile_ostream : llvm::outs();

    //
    // parse trace.txt
    //
    std::vector<std::pair<binary_index_t, basic_block_index_t>> trace;

    {
      std::ifstream trace_ifs(opts.TracePath.c_str());

      if (!trace_ifs) {
        WithColor::error() << llvm::formatv("failed to open trace file '{0}'\n",
                                            opts.TracePath.c_str());
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

        if (opts.SkipRepeated) {
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
    ReadDecompilationFromFile(opts.jv, decompilation);

    //
    // compute the set of verts for each function
    //
    for (binary_t &b : decompilation.Binaries) {
      for (function_t &f : b.Analysis.Functions)
        basic_blocks_of_function(f, b, state_for_function(f).BasicBlocks);
    }

    std::vector<std::unordered_set<basic_block_index_t>> Excludes;
    Excludes.resize(decompilation.Binaries.size());

    for (unsigned i = 0; i < opts.ExcludeFns.size(); i += 2) {
      binary_index_t BIdx = opts.ExcludeFns[i + 0];
      function_index_t FIdx = opts.ExcludeFns[i + 1];

      binary_t &binary = decompilation.Binaries.at(BIdx);
      function_t &function = binary.Analysis.Functions.at(FIdx);

      const auto &ICFG = binary.Analysis.ICFG;

      boost::property_map<interprocedural_control_flow_graph_t,
                          boost::vertex_index_t>::type bb_idx_map =
          boost::get(boost::vertex_index, ICFG);

      for (basic_block_t bb : state_for_function(function).BasicBlocks) {
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

      if (std::find(opts.ExcludeBinaries.begin(), opts.ExcludeBinaries.end(),
                    BIdx) != opts.ExcludeBinaries.end())
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

      fs::path PrefixedFileName = fs::path("/usr/src/debug") /
                                  fs::path(binary.Path).stem().c_str() /
                                  LnInfo.FileName;

      OutputStream << llvm::formatv("{0}:{1}:{2}:{3}+{4:x}\n",
                                    fs::path(LnInfo.FileName).is_relative()
                                        ? PrefixedFileName.c_str()
                                        : LnInfo.FileName.c_str(),
                                    LnInfo.Line, LnInfo.Column,
                                    fs::path(binary.Path).filename().c_str(),
                                    ICFG[bb].Addr);
    }
  }

  if (!opts.Vim)
    return 0;

  tmpfile_ostream.reset(nullptr);

  const char *arg_arr[] = {
    path_to_vim.c_str(),

    "--cmd", "set errorformat=%f:%l:%c:%m",
    "-q", path_to_tmpfile.c_str(),

    nullptr
  };

  ::execve(arg_arr[0], const_cast<char **>(&arg_arr[0]), ::environ);

  /* if we got here, execve failed */
  int err = errno;
  WithColor::error() << llvm::formatv(
      "failed to execve vim in quickFix mode (reason: {0})", strerror(err));

  return 1;
}

}
