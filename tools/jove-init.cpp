#include "tool.h"
#include "B.h"
#include "crypto.h"
#include "util.h"
#include "vdso.h"
#include "explore.h"
#include "tcg.h"
#include "win.h"
#include "hash.h"
#include "signals.h"
#include "mt.h"

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
#include <iterator>

#include <fcntl.h>
#include <sys/stat.h>

namespace fs = boost::filesystem;
namespace cl = llvm::cl;
namespace obj = llvm::object;

using llvm::WithColor;

namespace jove {

class InitTool : public JVTool<ToolKind::Standard> {
  struct Cmdline {
    cl::opt<std::string> Prog;
    cl::opt<bool> Objdump;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Prog(cl::Positional, cl::desc("prog"), cl::Required,
               cl::value_desc("filename"), cl::cat(JoveCategory)),

          Objdump("objdump",
                  cl::desc("Run objdump and treat output as authoritative."),
                  cl::init(true), cl::cat(JoveCategory)) {}
  } opts;

  AddOptions_t AddOptions;

  int rtld_trace_loaded_objects(const char *prog, std::string &out);
  void parse_loaded_objects(const std::string &rtld_stdout,
                            std::vector<std::string> &out);

public:
  InitTool() : opts(JoveCategory) {}

  int Run(void) override;
};

JOVE_REGISTER_TOOL("init", InitTool);

int InitTool::rtld_trace_loaded_objects(const char *prog, std::string &out) {
  std::string path_to_stdout = temporary_dir() + "/trace_loaded_objects.stdout.txt";
  std::string path_to_stderr = temporary_dir() + "/trace_loaded_objects.stderr.txt";

  int rc = RunExecutableToExit(
      prog,
      process::no_args,
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

template <bool MT, bool MinSize>
static void init_binaries(unsigned N, jv_file_t &,
                          ip_binary_table_t<MT, MinSize> &Binaries) {
  Binaries.len_.store(N, boost::memory_order_relaxed);
  for (unsigned i = 0; i < N; ++i)
    Binaries[i].Idx = static_cast<binary_index_t>(i);
}

template <bool MT, bool MinSize>
static void init_binaries(unsigned N, jv_file_t &jv_file,
                          ip_binary_deque_t<MT, MinSize> &Binaries) {
  auto e_lck = Binaries.exclusive_access();

  assert(Binaries.container().empty());
  for (unsigned i = 0; i < N; ++i)
    Binaries.container().emplace_back(jv_file, static_cast<binary_index_t>(i));
}

int InitTool::Run(void) {
  if (!fs::exists(opts.Prog)) {
    WithColor::error() << "binary does not exist\n";
    return 1;
  }

  ConfigureVerbosity(AddOptions);
  AddOptions.Objdump = opts.Objdump;

  fs::path prog = fs::canonical(opts.Prog);

  std::vector<uint8_t> BinBytes;
  auto Bin = B::CreateFromFile(opts.Prog.c_str(), BinBytes);

  std::vector<std::string> binary_paths;

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
      std::optional<std::string> MaybeRTLD = elf::program_interpreter(O);
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
      std::string path_to_wine = locator().wine(IsTarget32);

      if (IsVerbose())
        HumanOut() << llvm::formatv("path to wine: \"{0}\"\n", path_to_wine);

      std::vector<uint8_t> WineBytes;
      auto WineBin = B::CreateFromFile(path_to_wine.c_str(), WineBytes);

      std::optional<std::string> MaybeRTLD =
          B::_must_be_elf(*WineBin, elf::program_interpreter);

      if (!MaybeRTLD)
        die("wine (not the preloader) is expected to be dynamically linked");

      //
      // find them the stupid way
      //
      std::vector<std::string> needed_vec;
      if (coff::needed_libs(O, needed_vec)) {
        for (const std::string &needed : needed_vec) {
          try {
            // anything in directory of exe takes precedence
            binary_paths.push_back(fs::canonical(prog.parent_path() / needed).string());
            continue;
          } catch (...) {}

          try {
            binary_paths.push_back(locator().wine_dll(IsTarget32, needed));
          } catch (const std::exception &e) {
            WithColor::warning() << llvm::formatv("can't locate wine dll \"{0}\"\n", needed);
          }
        }
      }

      return *MaybeRTLD;
    }
  )).string();

  if (IsVerbose()) {
    for (const std::string &binary_path : binary_paths)
      llvm::errs() << llvm::formatv("  \"{0}\"\n", binary_path);
  }

  const unsigned N = binary_paths.size() + 3;

  //
  // add them
  //
  tiny_code_generator_t tcg;
  disas_t disas;
  explorer_t<false, IsToolMinSize> explorer(jv_file, disas, tcg,
                                            GetVerbosityLevel());
  auto worker =
      [&](unsigned BIdx) -> void {
        binary_base_t<false, IsToolMinSize> b(jv_file, BIdx);

        //
        // Name
        //
        std::string path_to_bin;
        switch (BIdx) {
        case 0:  to_ips(b.Name, prog.c_str());           break;
        case 1:  to_ips(b.Name, rtld.c_str());           break;
        case 2:  to_ips(b.Name, "[vdso]");               break;
        default: to_ips(b.Name, binary_paths.at(BIdx - 3)); break;
        }

        //
        // Data
        //
        switch (BIdx) {
        case 2:
          if (capture_vdso(b.Data)) {
            if (b.Data.empty()) {
              // no [vdso]. we could be running under qemu-user. in this case
              // since some code in jove assumes the existence of [vdso], we'll
              // hallucinate one.
              if (IsVerbose())
                WithColor::note() << "hallucinating [vdso]\n";

              b.Data = hallucinate_vdso();
            }
          } else {
            die("utilities/dump-vdso failed. is qemu-user properly installed?");
          }
          break;

        default:
          assert(b.is_file());
          read_file_into_thing(b.path(), b.Data);
          break;
        }

        std::unique_ptr<llvm::object::Binary> Bin;
        if (catch_exception([&]() { Bin = B::Create(b.data()); })) {
          WithColor::error()
              << llvm::formatv("not valid binary: \"{0}\"\n", b.Name.c_str());
          exit(1);
        }

        b.Hash = hash_data(b.data());

        if (AddOptions.Objdump) {
          if (catch_exception([&]() {
                // TODO verbose print command
                b.Analysis.objdump_thinks.run(
                    b.is_file() ? b.Name.c_str() : nullptr, *Bin);
              })) {
            if (IsVerbose()) {
              WithColor::warning() << llvm::formatv(
                  "failed to run objdump on {0}\n", b.Name.c_str());
            }
          }
        }

        //
        // explore them for real
        //
        try {
          jv.DoAdd(b, explorer, *Bin, AddOptions);
        } catch (const std::exception &e) {
          die(std::string("failed to add \"") + b.Name.c_str() +
              std::string("\": ") + e.what());
        }

        bool isNewBinary = jv.TryHashToBinaryEmplace(b.Hash, BIdx);
        if (!isNewBinary) {
          WithColor::error()
              << llvm::formatv("not new binary: \"{0}\"\n", b.Name.c_str());
          exit(1);
        }

        ip_binary_index_set BIdxSet(jv_file.get_segment_manager());
        BIdxSet.insert(BIdx);

        const bool isNewName =
            jv.TryNameToBinariesEmplace(b.Name, boost::move(BIdxSet));
        if (!isNewName) {
          WithColor::error()
              << llvm::formatv("not new name: \"{0}\"\n", b.Name.c_str());
          exit(1);
        }

        jv.Binaries.at(BIdx) = std::move(b);
      };

  block_signals([&] {
    jv.clear(); /* point of no return */
    init_binaries(N, jv_file, jv.Binaries);
    mt::for_n(worker, N);

    jv.Binaries.at(0).IsExecutable = true;
    jv.Binaries.at(1).IsDynamicLinker = true;
    jv.Binaries.at(2).IsVDSO = true;

    assert(!explorer.get_jv());
    jv.fixup(jv_file); // XXX
  });

  return 0;
}

}
