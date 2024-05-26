#include "tool.h"
#include "elf.h"
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

  obj::OwningBinary<obj::Binary> Bin;

  int rtld_trace_loaded_objects(const char *prog, std::string &out);
  void parse_loaded_objects(const std::string &rtld_stdout,
                            std::vector<std::string> &out);
  int add_loaded_objects(const fs::path &prog, const fs::path &rtld);

public:
  InitTool() : opts(JoveCategory) {}

  int Run(void) override;
};

JOVE_REGISTER_TOOL("init", InitTool);


int InitTool::Run(void) {
  if (!fs::exists(opts.Prog)) {
    WithColor::error() << "binary does not exist\n";
    return 1;
  }

  Bin = CreateBinaryFromFile(opts.Prog.c_str());

  std::optional<std::string> OptionalPathToRTLD =
      program_interpreter_of_elf(*llvm::cast<ELFO>(Bin.getBinary()));
  if (!OptionalPathToRTLD) {
    WithColor::error() << "binary is not dynamically linked\n";
    return 1;
  }

  fs::path rtld = fs::canonical(*OptionalPathToRTLD);
  fs::path prog = fs::canonical(opts.Prog);

  return add_loaded_objects(opts.Prog, rtld);
}

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

int InitTool::add_loaded_objects(const fs::path &prog, const fs::path &rtld) {
  //
  // run program with LD_TRACE_LOADED_OBJECTS=1 and no arguments. capture the
  // standard output, which will tell us what binaries are needed by prog.
  //
  std::string rtld_stdout;
  if (int rc = rtld_trace_loaded_objects(prog.c_str(), rtld_stdout)) {
    WithColor::error() << llvm::formatv(
        "failed to run {0} with LD_TRACE_LOADED_OBJECTS=1. can you run {0}?",
        opts.Prog);

    return rc;
  }

  assert(!rtld_stdout.empty());

  std::vector<std::string> binary_paths;
  parse_loaded_objects(rtld_stdout, binary_paths);

  //
  // make sure the rtld was found
  //
  {
    auto it = std::find_if(binary_paths.begin(),
                           binary_paths.end(),
                           [&](const std::string &path_s) -> bool {
                             return fs::equivalent(path_s, rtld);
                           });
    if (it == binary_paths.end()) {
      WithColor::error()
          << "dynamic linker not found in LD_TRACE_LOADED_OBJECTS=1 output\n";

      return 1;
    }

    binary_paths.erase(it);
  }

  //
  // [vdso]
  //
  auto VDSOPair = GetVDSO();
  std::string_view vdso_sv =
      VDSOPair.first
          ? std::string_view((const char *)VDSOPair.first, VDSOPair.second)
          : std::string_view((const char *)VDSOStandIn(), VDSOStandInLen());

  //
  // prepare to explore binaries
  //
  tiny_code_generator_t tcg;
  disas_t disas;
  explorer_t E(jv, disas, tcg, IsVeryVerbose());

  jv.clear(); /* point of no return */

  unsigned N = binary_paths.size() + 3;
  jv.Binaries.reserve(2*N);
  for (unsigned i = 0; i < N; ++i)
    jv.Binaries.emplace_back(jv.Binaries.get_allocator());

  //
  // add them
  //
  auto add_from_path = [&](const char *p, binary_index_t BIdx) -> void {
    try {
      jv.AddFromPath(E, p, BIdx);
    } catch (const std::exception &e) {
      llvm::errs() << llvm::formatv("failed on {0}: {1}\n", p, e.what());
      exit(1);
    }
  };

  std::vector<unsigned> idx_range;
  idx_range.resize(N);
  std::iota(idx_range.begin(), idx_range.end(), 0);

  std::for_each(
      std::execution::par_unseq,
      idx_range.begin(),
      idx_range.end(),
      [&](unsigned i) {
        if (i == 0) {
          add_from_path(prog.c_str(), 0);
        } else if (i == 1) {
          add_from_path(rtld.c_str(), 1);
        } else if (i == 2) {
          try {
            jv.AddFromData(E, vdso_sv, "[vdso]", 2);
          } catch (const std::exception &e) {
            llvm::errs() << llvm::formatv("failed on [vdso]: {0}\n", e.what());
            exit(1);
          }
        } else {
          assert(i >= 3);
          add_from_path(binary_paths.at(i - 3).c_str(), i);
        }
      });

  jv.Binaries.at(0).IsExecutable = true;
  jv.Binaries.at(1).IsDynamicLinker = true;
  jv.Binaries.at(2).IsVDSO = true;

  return 0;
}

}
