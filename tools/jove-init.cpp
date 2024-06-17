#include "tool.h"
#include "B.h"
#include "crypto.h"
#include "util.h"
#include "vdso.h"
#include "explore.h"
#include "tcg.h"

#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include <boost/graph/graphviz.hpp>
#include <boost/graph/topological_sort.hpp>
#include <boost/range/adaptor/reversed.hpp>

#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

#include <string>
#include <thread>
#include <functional>
#include <execution>
#include <numeric>

#include <fcntl.h>
#include <sys/stat.h>

#include "jove_macros.h"

namespace fs = boost::filesystem;
namespace cl = llvm::cl;
namespace obj = llvm::object;

using llvm::WithColor;

namespace jove {

class InitTool : public JVTool {
  struct Cmdline {
    cl::opt<std::string> Prog;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Prog(cl::Positional, cl::desc("prog"), cl::Required,
               cl::value_desc("filename"), cl::cat(JoveCategory)) {}
  } opts;

  tiny_code_generator_t tcg;
  disas_t disas;
  explorer_t E;

  int rtld_trace_loaded_objects(const char *prog, std::string &out);
  void parse_loaded_objects(const std::string &rtld_stdout,
                            std::vector<std::string> &out);

public:
  InitTool() : opts(JoveCategory), E(jv, disas, tcg, IsVeryVerbose()) {}

  int Run(void) override;
};

JOVE_REGISTER_TOOL("init", InitTool);

int InitTool::rtld_trace_loaded_objects(const char *prog, std::string &out) {
  std::string path_to_stdout = temporary_dir() + "/trace_loaded_objects.stdout.txt";
  std::string path_to_stderr = temporary_dir() + "/trace_loaded_objects.stderr.txt";

  int rc = RunExecutableToExit(
      prog,
      [&](auto Arg) { Arg(prog); },
      [&](auto Env) { Env("LD_TRACE_LOADED_OBJECTS=1"); },
      path_to_stdout,
      path_to_stderr);

  if (rc)
    return rc;

  out = read_file_into_string(path_to_stdout.c_str());
  return 0;
}

void InitTool::parse_loaded_objects(const std::string &rtld_stdout,
                                    std::vector<std::string> &out) {
  std::string::size_type pos = 0;
  for (;;) {
    std::string::size_type arrow_pos = std::min(rtld_stdout.find("\t/", pos),
                                                rtld_stdout.find(" /", pos));

    if (arrow_pos == std::string::npos)
      break;

    pos = arrow_pos + strlen(" /") - 1;

    /* path to dso cannot contain space FIXME */
    std::string::size_type space_pos = rtld_stdout.find(' ', pos);

    if (space_pos == std::string::npos)
      break;

    std::string path = rtld_stdout.substr(pos, space_pos - pos);
    if (!fs::exists(path)) {
      if (IsVerbose())
        WithColor::warning() << "path from dynamic linker '" << path << "' is bogus\n";
      continue;
    }

    std::string bin_path = fs::canonical(path).string();
    if (IsVeryVerbose())
      llvm::errs() << llvm::formatv("path = {0} bin_path = {1}\n", path, bin_path);

    insertSortedVec(out, bin_path);
  }
}

int InitTool::Run(void) {
  if (!fs::exists(opts.Prog)) {
    WithColor::error() << "binary does not exist\n";
    return 1;
  }

  fs::path prog = fs::canonical(opts.Prog);

  std::vector<uint8_t> BinBytes;
  auto Bin = B::CreateFromFile(opts.Prog.c_str(), BinBytes);

  std::vector<std::string> binary_paths; /* remains empty if COFF */

  std::string rtld = fs::canonical(B::_X(
    *Bin,

    [&](ELFO &O) -> std::string {
      //
      // run program with LD_TRACE_LOADED_OBJECTS=1 and no arguments. capture the
      // standard output, which will tell us what binaries are needed by prog.
      //
      std::string rtld_stdout;
      if (int rc = rtld_trace_loaded_objects(prog.c_str(), rtld_stdout)) {
        WithColor::error() << llvm::formatv(
            "failed to run {0} with LD_TRACE_LOADED_OBJECTS=1. can you run {0}?",
            opts.Prog);

        exit(rc);
      }

      assert(!rtld_stdout.empty());

      parse_loaded_objects(rtld_stdout, binary_paths);

      // look at "program interpreter" (i.e. dynamic linker)
      std::optional<std::string> MaybeRTLD = elf::program_interpreter_of_elf(O);
      if (!MaybeRTLD)
        die("binary is not dynamically linked");

      std::string res = *MaybeRTLD;

      {
        auto it = std::find_if(binary_paths.begin(),
                               binary_paths.end(),
                               [&](const std::string &bin_path) -> bool {
                                 return fs::equivalent(bin_path, res);
                               });

        if (it == binary_paths.end())
          die("dynamic linker not found in LD_TRACE_LOADED_OBJECTS=1 output");

        binary_paths.erase(it);
      }

      return res;
    },

    [&](COFFO &O) -> std::string {
      //
      // look at the program interpreter for the wine executable (which is elf)
      //
      std::vector<uint8_t> WineBytes;
      auto WineBin = B::CreateFromFile(locator().wine(IsTarget32).c_str(), WineBytes);

      std::optional<std::string> MaybeRTLD =
          B::_must_be_elf(*WineBin, elf::program_interpreter_of_elf);

      if (!MaybeRTLD)
        die("wine (not the preloader) is expected to be dynamically linked");

      return *MaybeRTLD;
    }
  )).string();

  jv.clear(); /* point of no return */

  unsigned N = binary_paths.size() + 3;

  {
    ip_scoped_lock<ip_sharable_mutex> e_lck(jv.Binaries._mtx);

    for (unsigned i = 0; i < N; ++i)
      jv.Binaries._deque.emplace_back(jv.get_allocator(),
                                      static_cast<binary_index_t>(i));
  }

  //
  // add them
  //
  std::vector<unsigned> idx_range;
  idx_range.resize(N);
  std::iota(idx_range.begin(), idx_range.end(), 0);

  std::for_each(
      std::execution::par_unseq,
      idx_range.begin(),
      idx_range.end(),
      [&](unsigned i) {
        switch (i) {
        case 0: jv.AddFromPath(E, prog.c_str(), static_cast<binary_index_t>(0)); return;
        case 1: jv.AddFromPath(E, rtld.c_str(), static_cast<binary_index_t>(1)); return;
        case 2: {
          auto VDSOPair = GetVDSO();
          std::string_view vdso_sv =
              VDSOPair.first
                  ? std::string_view((const char *)VDSOPair.first, VDSOPair.second)
                  : std::string_view((const char *)VDSOStandIn(), VDSOStandInLen());
          try {
            jv.AddFromData(E, vdso_sv, "[vdso]", static_cast<binary_index_t>(2));
          } catch (const std::exception &e) {
            llvm::errs() << llvm::formatv("failed on [vdso]: {0}\n", e.what());
            exit(1);
          }
          return;
        }

        default:
          assert(i >= 3);
          jv.AddFromPath(E, binary_paths.at(i - 3).c_str(),
                         static_cast<binary_index_t>(i));
          return;
        }
      });

  jv.Binaries.at(0).IsExecutable = true;
  jv.Binaries.at(1).IsDynamicLinker = true;
  jv.Binaries.at(2).IsVDSO = true;

  return 0;
}

}
