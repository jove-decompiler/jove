#include "tool.h"
#include "elf.h"
#include "triple.h"

#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/DataTypes.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Function.h>

#include <algorithm>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include <boost/algorithm/string.hpp>
#include <fstream>
#include <thread>
#include <stdexcept>

#include <fcntl.h>

#include "jove_macros.h"

namespace fs = boost::filesystem;
namespace cl = llvm::cl;
namespace obj = llvm::object;

using llvm::WithColor;

namespace jove {

namespace {

struct binary_state_t {
  dynamic_linking_info_t dynl;

  std::unique_ptr<llvm::object::Binary> Bin;
};

}

class DecompileTool : public TransformerTool_Bin<binary_state_t> {
  struct Cmdline {
    cl::opt<std::string> Prog;
    cl::opt<std::string> Binary;
    cl::alias BinaryAlias;
    cl::opt<std::string> Output;
    cl::alias OutputAlias;
    cl::opt<bool> ClearOutputDir;
    cl::alias ClearOutputDirAlias;
    cl::opt<unsigned> Threads;
    cl::opt<bool> FakeLineNumbers;
    cl::opt<bool> MT;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Prog(cl::Positional, cl::desc("prog"), cl::value_desc("filename"),
               cl::cat(JoveCategory)),

          Binary("binary", cl::desc("Operate on single given binary"),
                 cl::value_desc("path"), cl::cat(JoveCategory), cl::Required),

          BinaryAlias("b", cl::desc("Alias for -binary."), cl::aliasopt(Binary),
                      cl::cat(JoveCategory)),

          Output("output", cl::desc("Output directory"), cl::Required,
                 cl::cat(JoveCategory)),

          OutputAlias("o", cl::desc("Alias for -output."), cl::aliasopt(Output),
                      cl::cat(JoveCategory)),

          ClearOutputDir(
              "clear-output-dir",
              cl::desc("Print extra information for debugging purposes"),
              cl::cat(JoveCategory)),

          ClearOutputDirAlias("c", cl::desc("Alias for -clear-output-dir."),
                              cl::aliasopt(ClearOutputDir),
                              cl::cat(JoveCategory)),

          Threads("num-threads", cl::desc("Number of CPU threads to use"),
                  cl::init(num_cpus()), cl::cat(JoveCategory)),

          FakeLineNumbers(
              "fake-line-numbers",
              cl::desc("Preserve \"debugging information\" from LLVM IR"),
              cl::cat(JoveCategory)),

          MT("mt", cl::desc("Thread model (multi)"), cl::cat(JoveCategory)) {}
  } opts;

  std::vector<binary_index_t> Q;
  std::mutex Q_mtx;

  binary_index_t SingleBinaryIndex = invalid_binary_index;

  std::atomic<bool> worker_failed = false;

public:
  DecompileTool() : opts(JoveCategory) {}

  int Run(void) override;

  void Worker(void);

  void queue_binaries(void);
  bool pop_binary(binary_index_t &out);
};

JOVE_REGISTER_TOOL("decompile", DecompileTool);

typedef boost::format fmt;

void DecompileTool::queue_binaries(void) {
  Q.clear();
  Q.reserve(jv.Binaries.size());

  if (is_binary_index_valid(SingleBinaryIndex)) {
    Q.push_back(SingleBinaryIndex);
    return;
  }

  for_each_binary(jv, [&](binary_t &binary) {
    if (binary.IsVDSO)
      return;
    if (binary.IsDynamicLinker)
      return;

    binary_index_t BIdx = index_of_binary(binary, jv);
    Q.push_back(BIdx);
  });
}

int DecompileTool::Run(void) {
  //
  // gather dynamic linking information
  //
  for_each_binary(jv, [&](binary_t &binary) {
    ignore_exception([&]() {
      auto &x = state.for_binary(binary);

      x.Bin = CreateBinary(binary.data());

      dynamic_linking_info_of_binary(*x.Bin, x.dynl);
    });
  });

  std::unordered_map<std::string, binary_index_t> soname_map;

  for_each_binary(jv, [&](binary_t &binary) {
    binary_index_t BIdx = index_of_binary(binary, jv);
    auto &_state = state.for_binary(binary);

    if (_state.dynl.soname.empty() && !binary.IsExecutable) {
      soname_map.insert(
          {fs::path(binary.path_str()).filename().string(), BIdx}); /* XXX */
      return;
    }

    if (soname_map.find(_state.dynl.soname) != soname_map.end()) {
      WithColor::error() << llvm::formatv(
          "same soname {0} occurs more than once\n", _state.dynl.soname);
      return;
    }

    soname_map.insert({_state.dynl.soname, BIdx});
  });

  //
  // operate on single binary? (cmdline)
  //
  if (!opts.Binary.empty()) {
    binary_index_t BinaryIndex = invalid_binary_index;

    for (binary_index_t BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx) {
      const binary_t &binary = jv.Binaries[BIdx];
      if (binary.path_str().find(opts.Binary) == std::string::npos)
        continue;

      BinaryIndex = BIdx;
      break;
    }

    if (!is_binary_index_valid(BinaryIndex)) {
      WithColor::error() << llvm::formatv("failed to find binary \"{0}\"\n",
                                          opts.Binary);
      return 1;
    }

    SingleBinaryIndex = BinaryIndex;
  }

  bool IsPIC = jv.Binaries.at(0).IsPIC;

  if (fs::exists(opts.Output)) {
    if (!fs::is_directory(opts.Output)) {
      WithColor::error() << llvm::formatv(
          "path to output ({0}) does not refer to a directory", opts.Output);
      return 1;
    }

    if (opts.ClearOutputDir)
      fs::remove_all(opts.Output);
  }

  fs::create_directories(opts.Output);
  fs::create_directories(fs::path(opts.Output) / ".obj");
  fs::create_directories(fs::path(opts.Output) / ".lib");

  if (RunToolToExit("extract", [&](auto Arg) {
        Arg((fs::path(opts.Output) / ".lib").string());
      })) {
    WithColor::error() << "jove-extract failed to run\n";
    return 1;
  }

  if (!IsVerbose())
    WithColor::note() << llvm::formatv(
        "Generating LLVM and running llvm-cbe on {0} {1}...",
        !opts.Binary.empty() ? 1 : jv.Binaries.size() - 2,
        !opts.Binary.empty() ? "binary" : "binaries");

  queue_binaries();
  {
    auto t1 = std::chrono::high_resolution_clock::now();

    {
      std::vector<std::thread> workers;

      unsigned N = opts.Threads;

      workers.reserve(N);
      for (unsigned i = 0; i < N; ++i)
        workers.push_back(std::thread(&DecompileTool::Worker, this));

      for (std::thread &t : workers)
        t.join();
    }

    auto t2 = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double> s_double = t2 - t1;

    bool Failed = worker_failed.load();
    if (Failed)
      return 1;

    if (!IsVerbose())
      llvm::errs() << llvm::formatv(" {0} s\n", s_double.count());
  }

  //
  // examine the bitcode to figure out which helpers are used
  //
  std::unordered_set<std::string> helper_nms;

  auto Context = std::make_unique<llvm::LLVMContext>();
  for_each_binary(jv, [&](binary_t &binary) {
    if (!binary.IsExecutable)
      return; /* FIXME */

    const fs::path chrooted_path = fs::path(temporary_dir()) / binary.path_str();
    std::string bcfp(chrooted_path.string() + ".bc");

    assert(fs::exists(bcfp));

    llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> BufferOr =
        llvm::MemoryBuffer::getFile(bcfp);
    if (!BufferOr)
      throw std::runtime_error("failed to open bitcode file " + bcfp + ": " +
                               BufferOr.getError().message());

    llvm::Expected<std::unique_ptr<llvm::Module>> moduleOr =
        llvm::parseBitcodeFile(BufferOr.get()->getMemBufferRef(), *Context);
    if (!moduleOr)
      throw std::runtime_error("failed to parse bitcode");

    std::unique_ptr<llvm::Module> &Module = moduleOr.get();

    for_each_if(
        Module->begin(),
        Module->end(),
        [&](llvm::Function &F) -> bool {
          if (F.isIntrinsic())
            return false;

          if (!F.empty())
            return false;

          if (boost::algorithm::starts_with(F.getName(), "helper_"))
            return true;

          return false;
        },
        [&](llvm::Function &F) {
          helper_nms.insert(F.getName().str().substr(sizeof("helper_") - 1));
        });
  });

  for (const std::string &helper_nm : helper_nms) {
    std::string helper_bc_fp = locator().helper_bitcode(helper_nm);

    std::string tmpbc_fp = (fs::path(temporary_dir()) / helper_nm).string() + ".bc";
    std::string o_fp = (fs::path(opts.Output) / ".obj" / helper_nm).string() + ".o";

    int rc;

    //
    // run opt to internalize things
    //
    rc = RunExecutableToExit(locator().opt(), [&](auto Arg) {
      Arg(locator().opt());

      Arg("-o");
      Arg(tmpbc_fp);

      Arg("-passes=internalize");
      Arg("--internalize-public-api-list=helper_" + helper_nm);

      Arg(helper_bc_fp);
    });

    if (rc) {
      WithColor::error() << "failed to run opt on helper\n";
      return 1;
    }

    assert(fs::exists(tmpbc_fp));

    //
    // run llc on helper bitcode
    //
    rc = RunExecutableToExit(locator().llc(), [&](auto Arg) {
      Arg(locator().llc());

      Arg("-o");
      Arg(o_fp);

      Arg(tmpbc_fp);

      Arg("--filetype=obj");

      Arg("--disable-simplify-libcalls");

      Arg(IsPIC ? "--relocation-model=pic" : "--relocation-model=static");
    });

    if (rc) {
      WithColor::error() << "failed to run llc on helper bitcode\n";
      return 1;
    }

    assert(fs::exists(o_fp));
  }

  fs::copy_file(locator().builtins(),
                fs::path(opts.Output) / ".obj" / "builtins.a",
                fs::copy_option::overwrite_if_exists);
  fs::copy_file(locator().softfloat_bitcode(),
                fs::path(opts.Output) / ".obj" / "libfpu_softfloat.a",
                fs::copy_option::overwrite_if_exists);
  fs::create_directories(fs::path(opts.Output) / ".lib" / "lib");
  fs::copy_file(locator().runtime(opts.MT),
                fs::path(opts.Output) / ".lib" / "lib" / "libjove_rt.so");

  //
  // compile jove starter bitcode
  //
  std::string jove_o_fp = (fs::path(opts.Output) / ".obj" / "jove.o").string();
  int rc = RunExecutableToExit(locator().llc(), [&](auto Arg) {
    Arg(locator().llc());

    Arg("-o");
    Arg(jove_o_fp);
    Arg(locator().starter_bitcode(opts.MT));

    Arg("--filetype=obj");

    Arg("--disable-simplify-libcalls");

    Arg(IsPIC ? "--relocation-model=pic" : "--relocation-model=static");
  });

  if (rc) {
    WithColor::error() << "llc on jove.bc failed\n";
    return 1;
  }

  std::string makefp = (fs::path(opts.Output) / "Makefile").string();
  {
    std::ofstream ofs(makefp);

#if 0
    ofs << "JOVE_DIR := " << jove_dir << '\n';
    ofs << "LLVM_DIR := $(JOVE_DIR)/llvm-project/install\n";
#endif

    ofs << '\n';

    ofs << "CC := clang" << '\n';
    ofs << "LD := ld.lld" << '\n';

    ofs << '\n';

    auto print_flags = [&](const char *var,
                           const std::vector<const char *> &flags) -> void {
      std::string preamble(var);
      preamble.append(" :=");

      ofs << preamble;

      for (const char *flag : flags) {
        if (flag)
          ofs << ' ' << flag;
        else
          ofs << " \\\n" << std::string(preamble.size(), ' ');
      }

      ofs << "\n";
    };

    std::string target_arg = "--target=" + getTargetTriple().normalize();
    {
      std::vector<const char *> cflags = {
        target_arg.c_str(),                        nullptr,
//      "-nostdinc",                               nullptr,
//      "-flto",                                   nullptr,
        "-O2",                                     nullptr,
        "-g",                                      nullptr,
        "-Wno-incompatible-library-redeclaration", nullptr,
        "-Wno-incompatible-pointer-types-discards-qualifiers", nullptr,
        "-Werror-implicit-function-declaration",   nullptr,
        "-Wno-builtin-requires-header",            nullptr,
        "-Wno-parentheses-equality"
      };

      print_flags("CFLAGS", cflags);
    }

    ofs << '\n';

    {
      std::vector<const char *> ldflags = {
        "-m", TargetStaticLinkerEmulation,           nullptr,

        "-nostdlib",                                 nullptr,

        "--push-state",
        "--as-needed", ".obj/builtins.a",
                       ".obj/libfpu_softfloat.a",
        "--pop-state",                               nullptr,

        "--exclude-libs", "ALL",                     nullptr,

        "-init", "_jove_init",
      };

      print_flags("LDFLAGS", ldflags);
    }

    ofs << '\n';

    {
      binary_t &binary = jv.Binaries.at(0);

      assert(binary.IsExecutable); /* FIXME */

      std::string binary_filename = fs::path(binary.path_str()).filename().string();

      ofs << binary_filename << ": " << binary_filename << ".o";
      ofs << " $(wildcard .obj/*.o)";
      ofs << "\n";

      ofs << "\t$(LD) -o $@ $^ $(LDFLAGS)";

      if (binary.IsExecutable) {
        if (binary.IsPIC) {
          ofs << " -pie";
        } else {
          //
          // the following has only been tested to work with the lld linker.
          //
          uint64_t Base, End;
          std::tie(Base, End) = bounds_of_binary(*state.for_binary(binary).Bin);

          ofs << " --section-start " << (fmt(".jove=0x%lx") % Base).str();
        }
      } else {
        assert(binary.IsPIC);
        ofs << " -shared";
      }

      ofs << " --allow-shlib-undefined";
      if (binary.IsExecutable)
        ofs << " --unresolved-symbols=ignore-all";

      std::string mapfp = (fs::path(opts.Output) / (binary_filename + ".map")).string();
      if (fs::exists(mapfp) && fs::is_regular_file(mapfp) && fs::file_size(mapfp) > 0)
        ofs << " --version-script " << binary_filename << ".map";

      if (is_function_index_valid(binary.Analysis.EntryFunction)) {
        ofs << " -e _jove_start";
      }

      //
      // include lib directories
      //
      std::unordered_set<std::string> needed_lib_dirs = {"/lib"};
      std::unordered_set<std::string> needed_sonames;
      for (std::string &needed : state.for_binary(binary).dynl.needed) {
        auto it = soname_map.find(needed);
        if (it == soname_map.end()) {
          WithColor::warning()
              << llvm::formatv("no entry in soname_map for {0}\n", needed);
          continue;
        }

        binary_t &needed_b = jv.Binaries.at((*it).second);

        const fs::path needed_path(needed_b.path_str());
        if (needed_path.filename() != needed) {
          if (IsVerbose())
            HumanOut() << llvm::formatv("creating symlink for {0}\n", needed);

          fs::create_symlink(needed_path.filename(),
                             fs::path(opts.Output) / ".lib" /
                                 needed_path.parent_path() / needed);
        }

        needed_lib_dirs.insert(needed_path.parent_path().string());

        needed_sonames.insert(needed);
      }

      for (const std::string &lib_dir : needed_lib_dirs) {
        ofs << " -L";
        ofs << ' ' << fs::path(".lib") / lib_dir;
      }

      ofs << " -ljove_rt";

      if (!state.for_binary(binary).dynl.soname.empty())
        ofs << " -soname=" << state.for_binary(binary).dynl.soname;

      std::vector<std::string> needed_arg_vec;

      for (const std::string &needed : needed_sonames) {
        ofs << " -l :" << needed;
      }

      if (!state.for_binary(binary).dynl.interp.empty()) {
        ofs << " -dynamic-linker "
            << fs::canonical(state.for_binary(binary).dynl.interp).string();
      }

      ofs << "\n\n";

      ofs << binary_filename << ".o: " << binary_filename << ".c" << '\n';
      ofs << "\t$(CC) -o $@ -c $(CFLAGS)";
      if (binary.IsPIC)
        ofs << " -fPIC";
      ofs << " $^\n";
    }
  }

  return 0;
}

bool DecompileTool::pop_binary(binary_index_t &out) {
  std::lock_guard<std::mutex> lck(Q_mtx);

  if (Q.empty()) {
    return false;
  } else {
    out = Q.back();
    Q.resize(Q.size() - 1);
    return true;
  }
}

void DecompileTool::Worker(void) {
  binary_index_t BIdx = invalid_binary_index;
  while (pop_binary(BIdx)) {
    binary_t &binary = jv.Binaries.at(BIdx);

    assert(binary.is_file());

    const fs::path chrooted_path = fs::path(temporary_dir()) / binary.path_str();
    fs::create_directories(chrooted_path.parent_path());

    std::string binary_filename = fs::path(binary.path_str()).filename().string();

    std::string bcfp(chrooted_path.string() + ".bc");
    std::string mapfp = (fs::path(opts.Output) / (binary_filename + ".map")).string();
    std::string cfp = (fs::path(opts.Output) / (binary_filename + ".c")).string();

    //
    // run jove-llvm
    //
    {
      std::string path_to_stdout = bcfp + ".stdout.llvm.txt";
      std::string path_to_stderr = bcfp + ".stderr.llvm.txt";

      int rc = RunToolToExit(
          "llvm",
          [&](auto Arg) {
            Arg("-o");
            Arg(bcfp);

            Arg("--version-script");
            Arg(mapfp);

            Arg("--binary-index");
            Arg(std::to_string(BIdx));

            Arg("--for-cbe");

            Arg("--foreign-libs"); /* FIXME */
          },
          path_to_stdout,
          path_to_stderr);

      //
      // check exit code
      //
      if (rc) {
        worker_failed.store(true);

        WithColor::error() << llvm::formatv(
            "jove llvm failed on {0}: see {1}\n", binary_filename,
            path_to_stderr);

        continue;
      }
    }

    assert(fs::exists(bcfp));

    //
    // run llvm-cbe
    //
    {
      std::string path_to_stdout = bcfp + ".stdout.cbe.txt";
      std::string path_to_stderr = bcfp + ".stderr.cbe.txt";

      int rc = RunExecutableToExit(
          locator().cbe(),
          [&](auto Arg) {
            Arg(locator().cbe());

            Arg("-o");
            Arg(cfp);

            if (opts.FakeLineNumbers)
              Arg("--cbe-print-debug-locs");

            Arg(bcfp);
          },
          path_to_stdout,
          path_to_stderr);

      //
      // check exit code
      //
      if (rc) {
        worker_failed.store(true);
        WithColor::error() << llvm::formatv("llvm-cbe failed on {0}: see {1}\n",
                                            binary_filename, path_to_stderr);
      }
    }
  }
}

}
