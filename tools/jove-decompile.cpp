#include "tool.h"
#include "elf.h"

#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/DataTypes.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

#include <algorithm>
#include <boost/dll/runtime_symbol_info.hpp>
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

struct binary_state_t {
  std::unique_ptr<obj::Binary> Bin;
  dynamic_linking_info_t dynl;
};

class DecompileTool : public Tool {
  struct Cmdline {
    cl::opt<std::string> jv;
    cl::opt<std::string> Binary;
    cl::alias BinaryAlias;
    cl::opt<bool> Verbose;
    cl::alias VerboseAlias;
    cl::opt<std::string> Output;
    cl::alias OutputAlias;
    cl::opt<bool> ClearOutputDir;
    cl::alias ClearOutputDirAlias;
    cl::opt<unsigned> Threads;
    cl::opt<bool> FakeLineNumbers;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : jv(cl::Positional, cl::desc("<input jove decompilations>"),
             cl::Required, cl::cat(JoveCategory)),

          Binary("binary", cl::desc("Operate on single given binary"),
                 cl::value_desc("path"), cl::cat(JoveCategory)),

          BinaryAlias("b", cl::desc("Alias for -binary."), cl::aliasopt(Binary),
                      cl::cat(JoveCategory)),

          Verbose("verbose",
                  cl::desc("Print extra information for debugging purposes"),
                  cl::cat(JoveCategory)),

          VerboseAlias("v", cl::desc("Alias for -verbose."),
                       cl::aliasopt(Verbose), cl::cat(JoveCategory)),

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
              cl::cat(JoveCategory)) {}

  } opts;

  std::vector<binary_index_t> Q;
  std::mutex Q_mtx;

  binary_index_t SingleBinaryIndex = invalid_binary_index;

  decompilation_t decompilation;

  std::string tmp_dir;

  std::string jove_dir, llvm_cbe_path, clang_path, lld_path, compiler_runtime_afp, jove_bc_fp, llc_path, opt_path;

  std::atomic<bool> worker_failed = false;

public:
  DecompileTool() : opts(JoveCategory) {}

  int Run(void);

  void Worker(void);

  void queue_binaries(void);
  bool pop_binary(binary_index_t &out);
};

JOVE_REGISTER_TOOL("decompile", DecompileTool);

typedef boost::format fmt;

void DecompileTool::queue_binaries(void) {
  Q.clear();
  Q.reserve(decompilation.Binaries.size());

  if (is_binary_index_valid(SingleBinaryIndex)) {
    Q.push_back(SingleBinaryIndex);
    return;
  }

  for_each_binary(decompilation, [&](binary_t &binary) {
    if (binary.IsVDSO)
      return;
    if (binary.IsDynamicLinker)
      return;

    binary_index_t BIdx = index_of_binary(binary, decompilation);
    Q.push_back(BIdx);
  });
}

int DecompileTool::Run(void) {
  jove_dir = boost::dll::program_location().parent_path().parent_path().parent_path().string();
  if (!fs::exists(jove_dir)) {
    WithColor::error() << "could not locate jove directory\n";
    return 1;
  }
  assert(fs::is_directory(jove_dir));

  llvm_cbe_path = (boost::dll::program_location().parent_path().parent_path().parent_path() /
               "llvm-project" / "install" / "bin" / "llvm-cbe")
                  .string();
  if (!fs::exists(llvm_cbe_path)) {
    WithColor::error() << "could not find llvm-cbe at " << llvm_cbe_path << '\n';
    return 1;
  }

  clang_path = (boost::dll::program_location().parent_path().parent_path().parent_path() /
               "llvm-project" / "install" / "bin" / "clang")
                  .string();
  if (!fs::exists(clang_path)) {
    WithColor::error() << "could not find clang at " << clang_path << '\n';
    return 1;
  }

  lld_path = (boost::dll::program_location().parent_path().parent_path().parent_path() /
               "llvm-project" / "install" / "bin" / "ld.lld")
                  .string();
  if (!fs::exists(lld_path)) {
    WithColor::error() << "could not find ld.lld at " << lld_path << '\n';
    return 1;
  }

  compiler_runtime_afp =
      (boost::dll::program_location().parent_path().parent_path().parent_path() /
       "prebuilts" / "obj" / ("libclang_rt.builtins-" TARGET_ARCH_NAME ".a"))
          .string();

  if (!fs::exists(compiler_runtime_afp) ||
      !fs::is_regular_file(compiler_runtime_afp)) {
    WithColor::error() << "compiler runtime does not exist at path '"
                       << compiler_runtime_afp
                       << "' (or is not regular file)\n";
    return 1;
  }

  jove_bc_fp = (boost::dll::program_location().parent_path() / "jove.bc").string();
  if (!fs::exists(jove_bc_fp)) {
    WithColor::error() << "could not find " << jove_bc_fp << '\n';
    return 1;
  }

  llc_path = (boost::dll::program_location().parent_path().parent_path().parent_path() /
              "llvm-project" / "install" / "bin" / "llc").string();
  if (!fs::exists(llc_path)) {
    WithColor::error() << "could not find llc\n";
    return 1;
  }

  opt_path = (boost::dll::program_location().parent_path().parent_path().parent_path() /
              "llvm-project" / "install" / "bin" / "opt").string();
  if (!fs::exists(opt_path)) {
    WithColor::error() << "could not find opt\n";
    return 1;
  }

  ReadDecompilationFromFile(opts.jv, decompilation);

  //
  // gather dynamic linking information
  //
  for_each_binary(decompilation, [&](binary_t &binary) {
    if (binary.IsVDSO)
      return;

    llvm::Expected<std::unique_ptr<obj::Binary>> BinOrErr =
        obj::createBinary(llvm::MemoryBufferRef(
            llvm::StringRef(reinterpret_cast<const char *>(&binary.Data[0]),
                            binary.Data.size()),
            binary.Path));
    if (!BinOrErr) {
      WithColor::error() << "failed to parse binary " << binary.Path << '\n';
      return;
    }

    auto &binary_state = state_for_binary(binary);
    binary_state.Bin = std::move(BinOrErr.get());

    dynamic_linking_info_of_binary(*binary_state.Bin, binary_state.dynl);
  });

  std::unordered_map<std::string, binary_index_t> soname_map;

  for_each_binary(decompilation, [&](binary_t &binary) {
    binary_index_t BIdx = index_of_binary(binary, decompilation);
    auto &state = state_for_binary(binary);

    if (state.dynl.soname.empty() && !binary.IsExecutable) {
      soname_map.insert(
          {fs::path(binary.Path).filename().string(), BIdx}); /* XXX */
      return;
    }

    if (soname_map.find(state.dynl.soname) != soname_map.end()) {
      WithColor::error() << llvm::formatv(
          "same soname {0} occurs more than once\n", state.dynl.soname);
      return;
    }

    soname_map.insert({state.dynl.soname, BIdx});
  });

  //
  // operate on single binary? (cmdline)
  //
  if (!opts.Binary.empty()) {
    binary_index_t BinaryIndex = invalid_binary_index;

    for (binary_index_t BIdx = 0; BIdx < decompilation.Binaries.size(); ++BIdx) {
      const binary_t &binary = decompilation.Binaries[BIdx];
      if (binary.Path.find(opts.Binary) == std::string::npos)
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

  bool IsPIC = decompilation.Binaries.at(0).IsPIC;

  tmp_dir = "/tmp/jXXXXXX";
  if (!mkdtemp(&tmp_dir[0])) {
    int err = errno;
    throw std::runtime_error("failed to make temporary directory: " +
                             std::string(strerror(err)));
  }
  assert(fs::exists(tmp_dir) && fs::is_directory(tmp_dir));

  WithColor::note() << llvm::formatv("temporary directory: {0}\n", tmp_dir);

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

  if (!opts.Verbose)
    WithColor::note() << llvm::formatv(
        "Generating LLVM and running llvm-cbe on {0} {1}...",
        !opts.Binary.empty() ? 1 : decompilation.Binaries.size() - 2,
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

    if (!opts.Verbose)
      llvm::errs() << llvm::formatv(" {0} s\n", s_double.count());
  }

  //
  // examine the bitcode to figure out which helpers are used
  //
  std::unordered_set<std::string> helper_nms;

  auto Context = std::make_unique<llvm::LLVMContext>();
  for_each_binary(decompilation, [&](binary_t &binary) {
    if (!binary.IsExecutable)
      return; /* FIXME */

    const fs::path chrooted_path = fs::path(tmp_dir) / binary.Path;
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
    std::string helper_bc_fp = (boost::dll::program_location().parent_path() / "helpers" / (helper_nm + ".bc")).string();
    if (!fs::exists(jove_bc_fp)) {
      WithColor::error() << "could not find " << jove_bc_fp << '\n';
      return 1;
    }

    std::string tmpbc_fp = (fs::path(tmp_dir) / helper_nm).string() + ".bc";
    std::string o_fp = (fs::path(opts.Output) / ".obj" / helper_nm).string() + ".o";

    //
    // run opt to internalize things
    //
    pid_t pid = fork();
    if (!pid) {
      IgnoreCtrlC();

      std::string internalize_arg("--internalize-public-api-list=helper_");
      internalize_arg.append(helper_nm);

      const char *arg_arr[] = {
        opt_path.c_str(),

        "-o", tmpbc_fp.c_str(),

        "--internalize", internalize_arg.c_str(),

        helper_bc_fp.c_str(),

        nullptr
      };

      if (opts.Verbose)
        print_command(&arg_arr[0]);

      close(STDIN_FILENO);
      execve(arg_arr[0], const_cast<char **>(&arg_arr[0]), ::environ);

      int err = errno;
      WithColor::error() << llvm::formatv("execve failed: {0}\n",
                                          strerror(err));
      exit(1);
    }

    if (int rc = WaitForProcessToExit(pid)) {
      WithColor::error() << "failed to run opt on helper\n";
      return 1;
    }

    assert(fs::exists(tmpbc_fp));

    //
    // run llc on helper bitcode
    //
    pid = fork();
    if (!pid) {
      IgnoreCtrlC();

      const char *arg_arr[] = {
        llc_path.c_str(),

        "-o", o_fp.c_str(),
        tmpbc_fp.c_str(),

        "--filetype=obj",

        "--disable-simplify-libcalls",

        IsPIC ? "--relocation-model=pic" :
                "--relocation-model=static",

        nullptr
      };

      if (opts.Verbose)
        print_command(&arg_arr[0]);

      close(STDIN_FILENO);
      execve(arg_arr[0], const_cast<char **>(&arg_arr[0]), ::environ);

      int err = errno;
      WithColor::error() << llvm::formatv("execve failed: {0}\n",
                                          strerror(err));
      exit(1);
    }

    if (int rc = WaitForProcessToExit(pid)) {
      WithColor::error() << "failed to run llc on helper bitcode\n";
      return 1;
    }

    assert(fs::exists(o_fp));
  }

  fs::copy_file(compiler_runtime_afp,
                fs::path(opts.Output) / ".obj" / "builtins.a",
                fs::copy_option::overwrite_if_exists);

  //
  // compile jove starter bitcode
  //
  std::string jove_o_fp = (fs::path(opts.Output) / ".obj" / "jove.o").string();
  pid_t pid = fork();
  if (!pid) {
    IgnoreCtrlC();

    const char *arg_arr[] = {
      llc_path.c_str(),

      "-o", jove_o_fp.c_str(),
      jove_bc_fp.c_str(),

      "--filetype=obj",

      "--disable-simplify-libcalls",

      IsPIC ? "--relocation-model=pic" :
              "--relocation-model=static",

      nullptr
    };

    if (opts.Verbose)
      print_command(&arg_arr[0]);

    close(STDIN_FILENO);
    execve(arg_arr[0], const_cast<char **>(&arg_arr[0]), ::environ);

    int err = errno;
    WithColor::error() << llvm::formatv("execve failed: {0}\n", strerror(err));
    exit(1);
  }

  if (int rc = WaitForProcessToExit(pid)) {
    WithColor::error() << "llc on jove.bc failed\n";
    return 1;
  }

  std::string makefp = (fs::path(opts.Output) / "Makefile").string();
  {
    std::ofstream ofs(makefp);

    ofs << "JOVE_DIR := " << jove_dir << '\n';
    ofs << "LLVM_DIR := $(JOVE_DIR)/llvm-project/install\n";

    ofs << '\n';

    ofs << "CC := $(LLVM_DIR)/bin/clang" << '\n';
    ofs << "LD := $(LLVM_DIR)/bin/ld.lld" << '\n';

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

    {
      std::vector<const char *> cflags = {
//      "-nostdinc",                               nullptr,
//      "-flto",                                   nullptr,
        "-O2",                                     nullptr,
        "-g",                                      nullptr,
        "-Wno-incompatible-library-redeclaration", nullptr,
        "-Werror-implicit-function-declaration",   nullptr,
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
        "--pop-state",                               nullptr,

        "--exclude-libs", "ALL",                     nullptr,

        "-init", "_jove_init",
      };

      print_flags("LDFLAGS", ldflags);
    }

    ofs << '\n';

    {
      binary_t &binary = decompilation.Binaries.at(0);

      std::unique_ptr<obj::Binary> &BinRef = state_for_binary(binary).Bin;

      assert(binary.IsExecutable); /* FIXME */

      std::string binary_filename = fs::path(binary.Path).filename().string();

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
          std::tie(Base, End) = bounds_of_binary(*BinRef);

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
      for (std::string &needed : state_for_binary(binary).dynl.needed) {
        auto it = soname_map.find(needed);
        if (it == soname_map.end()) {
          WithColor::warning()
              << llvm::formatv("no entry in soname_map for {0}\n", needed);
          continue;
        }

        binary_t &needed_b = decompilation.Binaries.at((*it).second);

        const fs::path needed_path(needed_b.Path);
        needed_lib_dirs.insert(needed_path.parent_path().string());

        needed_sonames.insert(needed);
      }

      for (const std::string &lib_dir : needed_lib_dirs) {
        ofs << " -L";
        ofs << ' ' << lib_dir.c_str();
      }

      ofs << " -ljove_rt";

      if (!state_for_binary(binary).dynl.soname.empty())
        ofs << " -soname=" << state_for_binary(binary).dynl.soname;

      std::vector<std::string> needed_arg_vec;

      for (const std::string &needed : needed_sonames) {
        ofs << " -l :" << needed;
      }

      if (!state_for_binary(binary).dynl.interp.empty()) {
        ofs << " -dynamic-linker "
            << fs::canonical(state_for_binary(binary).dynl.interp).string();
      }

      ofs << "\n\n";

      ofs << binary_filename << ".o: " << binary_filename << ".c" << '\n';
      ofs << "\t$(CC) -o $@ -c $(CFLAGS)";
      if (binary.IsPIC)
        ofs << " -fPIC";
      ofs << " $^\n";
    }
  }

  // ~/jove/llvm-project/install/bin/clang -nostdlib -fuse-ld=lld -flto -fPIE -Wl,-e,_jove_start -O2 -Wl,-init,_jove_init -Wl,-pie -o complex_num.decompiled/home/aeden/jove/tests/bin/complex_num x86_64/jove.bc complex_num.decompiled/home/aeden/jove/tests/bin/complex_num.cbe.c -L ~/jove/bin/x86_64 -ljove_rt -lc-2.33 ../prebuilts/obj/libclang_rt.builtins-x86_64.a ~/jove/bin/x86_64/helpers/{cc_compute_all,muluh_i64,divl_EAX,idivq_EAX}.bc

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
    binary_t &binary = decompilation.Binaries.at(BIdx);

    // make sure the path is absolute
    assert(binary.Path.at(0) == '/');

    const fs::path chrooted_path = fs::path(tmp_dir) / binary.Path;
    fs::create_directories(chrooted_path.parent_path());

    std::string binary_filename = fs::path(binary.Path).filename().string();

    std::string bcfp(chrooted_path.string() + ".bc");
    std::string mapfp = (fs::path(opts.Output) / (binary_filename + ".map")).string();
    std::string cfp = (fs::path(opts.Output) / (binary_filename + ".c")).string();

    //
    // run jove-llvm
    //
    pid_t pid = fork();
    if (!pid) {
      IgnoreCtrlC();

      std::string BIdx_arg(std::to_string(BIdx));

      std::vector<const char *> arg_vec = {
        "-o", bcfp.c_str(),
        "--version-script", mapfp.c_str(),

        "--binary-index", BIdx_arg.c_str(),

        "-d", opts.jv.c_str(),

        "--for-cbe",

        "--foreign-libs" /* FIXME */
      };

      if (opts.Verbose)
        print_tool_command("llvm", arg_vec);

      {
        std::string stdoutfp = bcfp + ".stdout.llvm.txt";
        int stdoutfd = open(stdoutfp.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0666);
        dup2(stdoutfd, STDOUT_FILENO);
        close(stdoutfd);
      }

      {
        std::string stderrfp = bcfp + ".stderr.llvm.txt";
        int stderrfd = open(stderrfp.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0666);
        dup2(stderrfd, STDERR_FILENO);
        close(stderrfd);
      }

      close(STDIN_FILENO);
      exec_tool("llvm", arg_vec);

      int err = errno;
      HumanOut() << llvm::formatv("execve failed: {0}\n", strerror(err));
      exit(1);
    }

    //
    // check exit code
    //
    if (int ret = WaitForProcessToExit(pid)) {
      worker_failed.store(true);
      WithColor::error() << llvm::formatv("jove-llvm failed on {0}: see {1}\n",
                                          binary_filename,
                                          bcfp + ".stderr.llvm.txt");
      continue;
    }

    assert(fs::exists(bcfp));

    //
    // run llvm-cbe
    //
    pid = fork();
    if (!pid) {
      IgnoreCtrlC();

      std::vector<const char *> arg_vec = {
        llvm_cbe_path.c_str(),

        "-o", cfp.c_str(),

         "--cbe-jove"
      };

      if (opts.FakeLineNumbers)
        arg_vec.push_back("--cbe-print-debug-locs");

      arg_vec.push_back(bcfp.c_str());
      arg_vec.push_back(nullptr);

      if (opts.Verbose)
        print_command(&arg_vec[0]);

      {
        std::string stdoutfp = bcfp + ".stdout.cbe.txt";
        int stdoutfd = open(stdoutfp.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0666);
        dup2(stdoutfd, STDOUT_FILENO);
        close(stdoutfd);
      }

      {
        std::string stderrfp = bcfp + ".stderr.cbe.txt";
        int stderrfd = open(stderrfp.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0666);
        dup2(stderrfd, STDERR_FILENO);
        close(stderrfd);
      }

      close(STDIN_FILENO);
      execve(llvm_cbe_path.c_str(), const_cast<char **>(&arg_vec[0]), ::environ);

      int err = errno;
      HumanOut() << llvm::formatv("execve failed: {0}\n", strerror(err));
      exit(1);
    }

    //
    // check exit code
    //
    if (int ret = WaitForProcessToExit(pid)) {
      worker_failed.store(true);
      WithColor::error() << llvm::formatv("llvm-cbe failed on {0}: see {1}\n",
                                          binary_filename,
                                          bcfp + ".stderr.cbe.txt");
    }
  }
}

}
