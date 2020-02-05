#include <string>
#include <vector>
#include <boost/graph/adjacency_list.hpp>

struct dso_properties_t {
  unsigned BIdx;
};

typedef boost::adjacency_list<boost::setS,           /* OutEdgeList */
                              boost::vecS,           /* VertexList */
                              boost::bidirectionalS, /* Directed */
                              dso_properties_t       /* VertexProperties */>
    dso_graph_t;

typedef dso_graph_t::vertex_descriptor dso_t;

struct dynamic_linking_info_t {
  std::string soname;
  std::vector<std::string> needed;
  std::string interp;
};

#define JOVE_EXTRA_BIN_PROPERTIES                                              \
  dynamic_linking_info_t dynl;                                                 \
  dso_t dso;

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sched.h>
#include <tuple>
#include <thread>
#include <chrono>
#include <memory>
#include <mutex>
#include <queue>
#include <sstream>
#include <fstream>
#include <unordered_set>
#include <boost/filesystem.hpp>
#include <boost/dll/runtime_symbol_info.hpp>
#include <llvm/ADT/StringRef.h>
#include <llvm/Object/ELF.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/WithColor.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "jove/jove.h"
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/serialization/bitset.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/set.hpp>
#include <boost/graph/adj_list_serialize.hpp>
#include <boost/range/adaptor/reversed.hpp>
#include <boost/graph/topological_sort.hpp>

#define JOVE_RT_SO "libjove_rt.so"
#define JOVE_RT_SONAME JOVE_RT_SO ".0"

namespace fs = boost::filesystem;
namespace cl = llvm::cl;
namespace obj = llvm::object;

using llvm::WithColor;

namespace jove {
static unsigned num_cpus(void);
}

namespace opts {
static cl::OptionCategory JoveCategory("Specific Options");

static cl::opt<std::string> jv("decompilation", cl::desc("Jove decompilation"),
                               cl::Required, cl::cat(JoveCategory));

static cl::alias jvAlias("d", cl::desc("Alias for -decompilation."),
                         cl::aliasopt(jv), cl::cat(JoveCategory));

static cl::opt<std::string> Output("output", cl::desc("Output directory"),
                                   cl::Required, cl::cat(JoveCategory));

static cl::alias OutputAlias("o", cl::desc("Alias for -output."),
                             cl::aliasopt(Output), cl::cat(JoveCategory));

static cl::opt<unsigned> Threads("num-threads",
                                 cl::desc("Number of CPU threads to use (hack)"),
                                 cl::init(1 /* jove::num_cpus() */),
                                 cl::cat(JoveCategory));

static cl::opt<bool>
    Trace("trace",
          cl::desc("Instrument code to output basic block execution trace"),
          cl::cat(JoveCategory));

static cl::opt<bool>
    Verbose("verbose",
            cl::desc("Print extra information for debugging purposes"),
            cl::cat(JoveCategory));

static cl::alias VerboseAlias("v", cl::desc("Alias for -verbose."),
                              cl::aliasopt(Verbose), cl::cat(JoveCategory));

static cl::opt<bool> DFSan("dfsan", cl::desc("Run dfsan on bitcode"),
                           cl::cat(JoveCategory));

static cl::opt<bool>
    CheckEmulatedStackReturnAddress("check-emulated-stack-return-address",
                                    cl::desc("Check for stack overrun"),
                                    cl::cat(JoveCategory));
} // namespace opts

namespace jove {
static int recompile(void);
}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::HideUnrelatedOptions({&opts::JoveCategory, &llvm::ColorCategory});
  cl::ParseCommandLineOptions(argc, argv, "Jove Recompile\n");

  return jove::recompile();
}

namespace jove {

static decompilation_t Decompilation;

static void spawn_workers(void);

static char tmpdir[] = {'/', 't', 'm', 'p', '/', 'X',
                        'X', 'X', 'X', 'X', 'X', '\0'};

static int await_process_completion(pid_t);

static void print_command(const char **argv);

static std::string compiler_runtime_afp, jove_llvm_path, jove_bin_path,
    jove_rt_path, jove_dfsan_path, llc_path, ld_path, opt_path;

static std::atomic<bool> Cancel(false);

static void handle_sigint(int);

static bool dynamic_linking_info_of_binary(binary_t &,
                                           dynamic_linking_info_t &out);

static void IgnoreCtrlC(void);

int recompile(void) {
  compiler_runtime_afp =
      (boost::dll::program_location().parent_path().parent_path() /
       "third_party" / "llvm-project" / "install" / "lib" / "clang" / "9.0.1" /
       "lib" / "linux" / ("libclang_rt.builtins-" ___JOVE_ARCH_NAME ".a"))
          .string();

  if (!fs::exists(compiler_runtime_afp) ||
      !fs::is_regular_file(compiler_runtime_afp)) {
    WithColor::error() << "compiler runtime does not exist at path '"
                       << compiler_runtime_afp
                       << "' (or is not regular file)\n";
    return 1;
  }

  //
  // sanity checks for output path
  //
  if (fs::exists(opts::Output))
    fs::remove_all(opts::Output);

  if (!fs::create_directory(opts::Output)) {
    WithColor::error() << "failed to create directory at \"" << opts::Output
                       << "\"\n";
    return 1;
  }

  //
  // create symlink back to jv
  //
  fs::create_symlink(fs::canonical(opts::jv), fs::path(opts::Output) / ".jv");

  //
  // get paths to stuff
  //
  jove_llvm_path =
      (boost::dll::program_location().parent_path() / std::string("jove-llvm"))
          .string();
  if (!fs::exists(jove_llvm_path)) {
    WithColor::error() << "could not find jove-llvm at " << jove_llvm_path
                       << '\n';
    return 1;
  }

  jove_bin_path = boost::dll::program_location().parent_path().string();

  jove_rt_path = (boost::dll::program_location().parent_path() /
                  std::string(JOVE_RT_SONAME))
                     .string();
  if (!fs::exists(jove_rt_path)) {
    WithColor::error() << "could not find JOVE_RT_SONAME\n";
    return 1;
  }

#if !defined(__x86_64__) && defined(__i386__)
  assert(!opts::DFSan);
#else
  jove_dfsan_path =
      (boost::dll::program_location().parent_path().parent_path() /
       "third_party" / "llvm-project" / "install" / "lib" / "clang" / "9.0.1" /
       "lib" / "linux" / ("libclang_rt.dfsan-" ___JOVE_ARCH_NAME ".so"))
          .string();
  if (!fs::exists(jove_dfsan_path)) {
    WithColor::error() << llvm::formatv("could not find {0}\n",
                                        jove_dfsan_path);
    return 1;
  }
#endif

  llc_path = (boost::dll::program_location().parent_path().parent_path() /
              "third_party" / "llvm-project" / "install" / "bin" / "llc")
                 .string();
  if (!fs::exists(llc_path)) {
    WithColor::error() << "could not find /usr/bin/llc\n";
    return 1;
  }

  std::string lld_path =
      (boost::dll::program_location().parent_path().parent_path() /
       "third_party" / "llvm-project" / "install" / "bin" / "ld.lld")
          .string();

  std::string ld_gold_path = "/usr/bin/ld.gold";
  std::string ld_bfd_path = "/usr/bin/ld.bfd";

#if defined(__x86_64__)
  ld_path = ld_bfd_path;
#elif defined(__i386__)
  ld_path = lld_path;
#elif defined(__aarch64__)
  ld_path = ld_bfd_path;
#endif

  if (!fs::exists(ld_path)) {
    WithColor::error() << llvm::formatv("could not find linker at {0}\n",
                                        ld_path);
    return 1;
  }

  opt_path = "/usr/bin/opt";
  if (!fs::exists(opt_path)) {
    WithColor::error() << "could not find /usr/bin/opt\n";
    return 1;
  }

  //
  // prepare to process the binaries by creating a unique temporary directory
  //
  if (!mkdtemp(tmpdir)) {
    WithColor::error() << "mkdtemp failed : " << strerror(errno) << '\n';
    return 1;
  }

  llvm::outs() << "tmpdir: " << tmpdir << '\n';

  if (!fs::exists(opts::jv)) {
    WithColor::error() << "can't find decompilation.jv\n";
    return 1;
  }

  //
  // install signal handler for Ctrl-C to gracefully cancel
  //
  {
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = handle_sigint;

    if (sigaction(SIGINT, &sa, nullptr) < 0) {
      int err = errno;
      WithColor::error() << llvm::formatv("{0}: sigaction failed ({1})\n",
                                          __func__, strerror(err));
    }
  }

  //
  // parse the existing decompilation file
  //
  {
    std::ifstream ifs(fs::is_directory(opts::jv)
                          ? (fs::path(opts::jv) / "decompilation.jv").string()
                          : opts::jv);

    boost::archive::binary_iarchive ia(ifs);
    ia >> Decompilation;
  }

  if (Cancel) {
    WithColor::note() << "Canceled.\n";
    return 1;
  }

  //
  // gather dynamic linking information
  //
  for (binary_t &b : Decompilation.Binaries) {
    if (!dynamic_linking_info_of_binary(b, b.dynl)) {
      WithColor::error() << llvm::formatv(
          "!dynamic_linking_info_of_binary({0})\n", b.Path.c_str());
      return 1;
    }
  }

  //
  // setup sysroot
  //

  //
  // (1) copy dynamic linker
  //
  std::string rtld_soname;

  for (binary_t &b : Decompilation.Binaries) {
    if (!b.IsDynamicLinker)
      continue;

    assert(fs::exists(b.Path) && fs::is_regular_file(b.Path));

    fs::path chrooted_path(opts::Output + b.Path);
    fs::create_directories(chrooted_path.parent_path());
    fs::copy(b.Path, chrooted_path);

    if (!b.dynl.soname.empty()) {
      rtld_soname = b.dynl.soname;

      std::string binary_filename = fs::path(b.Path).filename().string();

      if (binary_filename != b.dynl.soname)
        fs::create_symlink(binary_filename,
                           chrooted_path.parent_path() / b.dynl.soname);
    }

    break;
  }

  //
  // (2) copy jove runtime
  //
  {
    {
      fs::path chrooted_path =
          fs::path(opts::Output) / "usr" / "lib" / JOVE_RT_SONAME;

      fs::create_directories(chrooted_path.parent_path());
      fs::copy(jove_rt_path, chrooted_path);
    }

    {
      fs::path chrooted_path =
          fs::path(opts::Output) / "usr" / "lib" / JOVE_RT_SO;

      fs::create_directories(chrooted_path.parent_path());
      fs::create_symlink(JOVE_RT_SONAME, chrooted_path);
    }
  }

  //
  // (3) copy jove dfsan runtime
  //
  if (opts::DFSan) {
    fs::path chrooted_path =
        fs::path(opts::Output) / "usr" / "lib" / "libclang_rt.dfsan-x86_64.so";

    fs::create_directories(chrooted_path.parent_path());
    fs::copy(jove_dfsan_path, chrooted_path);
  }

  //
  // (4) create basic directories (for chroot)
  //
  {
    fs::create_directories(fs::path(opts::Output) / "proc");
    fs::create_directories(fs::path(opts::Output) / "sys");
    fs::create_directories(fs::path(opts::Output) / "dev");
    fs::create_directories(fs::path(opts::Output) / "run");
    fs::create_directories(fs::path(opts::Output) / "tmp");
    fs::create_directories(fs::path(opts::Output) / "etc");
    fs::create_directories(fs::path(opts::Output) / "usr" / "bin");
    fs::create_directories(fs::path(opts::Output) / "usr" / "lib");
  }

  //
  // additional stuff for DFSan
  //
  {
    fs::create_directories(fs::path(opts::Output) / "jove");

    {
      std::ofstream ofs(
          (fs::path(opts::Output) / "jove" / "BinaryPathsTable.txt").c_str());

      for (const binary_t &binary : Decompilation.Binaries)
	ofs << binary.Path << '\n';
    }

    fs::create_directories(fs::path(opts::Output) / "jove" / "BinaryBlockAddrTables");

    for (binary_index_t BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx) {
      binary_t &binary = Decompilation.Binaries[BIdx];
      auto &ICFG = binary.Analysis.ICFG;

      {
        std::ofstream ofs((fs::path(opts::Output) / "jove" /
                           "BinaryBlockAddrTables" / std::to_string(BIdx))
                              .c_str());

        for (basic_block_index_t BBIdx = 0; BBIdx < boost::num_vertices(ICFG);
             ++BBIdx) {
          basic_block_t bb = boost::vertex(BBIdx, ICFG);
          uintptr_t Addr = ICFG[bb].Addr;
          ofs.write(reinterpret_cast<char *>(&Addr), sizeof(Addr));
        }
      }
    }
  }

  //
  // build dynamic linking graph
  //
  dso_graph_t dso_graph;
  for (binary_index_t BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx) {
    binary_t &b = Decompilation.Binaries[BIdx];

    b.dso = boost::add_vertex(dso_graph);
    dso_graph[b.dso].BIdx = BIdx;
  }

  //
  // topological sort of dynamic linking graph
  //
  std::unordered_map<std::string, binary_index_t> soname_map;

  for (binary_index_t BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx) {
    binary_t &b = Decompilation.Binaries[BIdx];

    if (b.dynl.soname.empty())
      continue;

    if (soname_map.find(b.dynl.soname) != soname_map.end()) {
      WithColor::error() << llvm::formatv(
          "same soname {0} occurs more than once\n", b.dynl.soname);
      continue;
    }

    soname_map.insert({b.dynl.soname, BIdx});
  }

  for (binary_index_t BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx) {
    binary_t &b = Decompilation.Binaries[BIdx];

    for (const std::string &sonm : b.dynl.needed) {
      auto it = soname_map.find(sonm);
      if (it == soname_map.end()) {
        WithColor::warning() << llvm::formatv(
            "unknown soname {0} needed by {1}\n", sonm, b.Path);
        continue;
      }

      boost::add_edge(b.dso, Decompilation.Binaries[(*it).second].dso,
                      dso_graph);
    }
  }

  std::vector<dso_t> top_sorted;

  try {
    std::map<dso_t, boost::default_color_type> clr_map;

    boost::topological_sort(
        dso_graph, std::back_inserter(top_sorted),
        boost::color_map(boost::associative_property_map<
                         std::map<dso_t, boost::default_color_type>>(clr_map)));
  } catch (const boost::not_a_dag &) {
    WithColor::error() << "dynamic linking graph is not a DAG.\n";
    return 1;
  }

  for (dso_t dso : top_sorted) {
    WithColor::note() << llvm::formatv(
        "{0}\n", Decompilation.Binaries.at(dso_graph[dso].BIdx).Path);
  }

  //
  // process each binary in the appropriate order
  //
  for (dso_t dso : top_sorted) {
    binary_index_t BIdx = dso_graph[dso].BIdx;

    binary_t &b = Decompilation.Binaries.at(BIdx);

    if (b.IsDynamicLinker)
      continue;
    if (b.IsVDSO)
      continue;

    pid_t pid;

    // make sure the path is absolute
    assert(b.Path.at(0) == '/');

    const fs::path chrooted_path(opts::Output + b.Path);
    fs::create_directories(chrooted_path.parent_path());

    std::string binary_filename = fs::path(b.Path).filename().string();

    //
    // run jove-llvm
    //
    if (Cancel) {
      WithColor::note() << "Canceled.\n";
      return 1;
    }

    std::string bcfp(chrooted_path.string() + ".bc");
    std::string mapfp(chrooted_path.string() + ".map");

    pid = fork();
    if (!pid) {
      IgnoreCtrlC();

      std::vector<const char *> arg_vec = {
        jove_llvm_path.c_str(),

        "-o", bcfp.c_str(),
        "--version-script", mapfp.c_str(),

        "-b", binary_filename.c_str(),

        "-d", opts::jv.c_str(),
      };

      if (opts::DFSan)
        arg_vec.push_back("-dfsan");
      if (opts::CheckEmulatedStackReturnAddress)
        arg_vec.push_back("--check-emulated-stack-return-address");
      if (opts::Trace)
        arg_vec.push_back("-trace");

      arg_vec.push_back(nullptr);

      print_command(&arg_vec[0]);

      std::string stdoutfp = bcfp + ".txt";
      int stdoutfd = open(stdoutfp.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0666);
      dup2(stdoutfd, STDOUT_FILENO);

      close(STDIN_FILENO);
      execve(arg_vec[0], const_cast<char **>(&arg_vec[0]), ::environ);

      int err = errno;
      WithColor::error() << llvm::formatv("execve failed: {0}\n",
                                          strerror(err));
      return 1;
    }

    //
    // check exit code
    //
    if (int ret = await_process_completion(pid)) {
      WithColor::error() << "jove-llvm failed for " << binary_filename << '\n';
      return ret;
    }

    std::string optbcfp = bcfp;

#if 0
    //
    // run opt
    //
    if (Cancel) {
      WithColor::note() << "Canceled.\n";
      return 1;
    }

    std::string optbcfp(chrooted_path.string() + ".opt.bc");
    if (!opts::DFSan) {
      optbcfp = bcfp;
      goto skip_dfsan;
    }

    pid = fork();
    if (!pid) {
      IgnoreCtrlC();

      const char *arg_vec[] = {
        opt_path.c_str(),
#if 0
        "-dfsan-abilist=dfsan_abilist.txt",
        "-dfsan-args-abi",
#endif
        "-dfsan",
        "-o", optbcfp.c_str(),
        bcfp.c_str(),
        nullptr
      };

      print_command(&arg_vec[0]);

      close(STDIN_FILENO);
      execve(arg_vec[0], const_cast<char **>(&arg_vec[0]), ::environ);
      return;
    }

    //
    // check exit code
    //
    if (int ret = await_process_completion(pid)) {
      WithColor::error() << llvm::formatv("opt -dfsan failed for {0}\n",
                                          binary_filename);
      continue;
    }

    if (Cancel)
      return;

skip_dfsan:
#endif

    if (Cancel) {
      WithColor::note() << "Canceled.\n";
      return 1;
    }

    //
    // run llc
    //
    std::string objfp(chrooted_path.string() + ".o");

    pid = fork();
    if (!pid) {
      IgnoreCtrlC();

      std::vector<const char *> arg_vec = {
        llc_path.c_str(),

        "-o", objfp.c_str(),
        optbcfp.c_str(),

        "--filetype=obj",
        "--relocation-model=pic",
        "--frame-pointer=all",

        "--disable-simplify-libcalls",

        "--exception-model=dwarf",
        "--generate-arange-section",

#if 0
        "--dwarf-version=4",
#endif
      };

      arg_vec.push_back(nullptr);

      print_command(&arg_vec[0]);

      close(STDIN_FILENO);
      execve(arg_vec[0], const_cast<char **>(&arg_vec[0]), ::environ);

      int err = errno;
      WithColor::error() << llvm::formatv("execve failed: {0}\n",
                                          strerror(err));
      return 1;
    }

    //
    // check exit code
    //
    if (int ret = await_process_completion(pid)) {
      WithColor::error() << "llc failed for " << binary_filename << '\n';
      return ret;
    }

    if (Cancel) {
      WithColor::note() << "Canceled.\n";
      return 1;
    }

    //
    // run ld
    //
    pid = fork();
    if (!pid) {
      IgnoreCtrlC();

      std::vector<const char *> arg_vec = {
          ld_path.c_str(),

          "-o", chrooted_path.c_str(),
          objfp.c_str(),

          "-m",

#if defined(__x86_64__) || defined(__i386__)
          "elf_" ___JOVE_ARCH_NAME,
#elif defined(__aarch64__)
          "aarch64linux",
#else
#error
#endif
          b.IsExecutable ?
            "-pie" :
            "-shared",

          "-nostdlib",

          "--push-state", "--as-needed", compiler_runtime_afp.c_str(),
          "--pop-state",

#if 0 /* __tls_get_addr... */
          "--no-undefined",
#endif
      };

      if (fs::exists(mapfp) && fs::is_regular_file(mapfp) &&
          fs::file_size(mapfp) > 0) {
        arg_vec.push_back("--version-script");
        arg_vec.push_back(mapfp.c_str());
      }

      if (is_function_index_valid(b.Analysis.EntryFunction)) {
        arg_vec.push_back("-e");
        arg_vec.push_back("_jove_start");
      }

      // include lib directories
#if 1
      std::unordered_set<std::string> lib_dirs({opts::Output + "/usr/lib"});
#else
      std::unordered_set<std::string> lib_dirs({jove_bin_path, "/usr/lib"});
#endif

      for (std::string &needed : b.dynl.needed) {
        auto it = soname_map.find(needed);
        if (it == soname_map.end()) {
          WithColor::warning()
              << llvm::formatv("no entry in soname_map for {0}\n", needed);
          continue;
        }

        binary_t &needed_b = Decompilation.Binaries.at((*it).second);
#if 1
        const fs::path needed_chrooted_path(opts::Output + needed_b.Path);
        lib_dirs.insert(needed_chrooted_path.parent_path().string());
#else
        const fs::path needed_path(needed_b.Path);
        lib_dirs.insert(needed_path.parent_path().string());
#endif
      }

      for (const std::string &lib_dir : lib_dirs) {
        arg_vec.push_back("-L");
        arg_vec.push_back(lib_dir.c_str());
      }

      arg_vec.push_back("-ljove_rt");
      if (opts::DFSan)
        arg_vec.push_back("-lclang_rt.dfsan-x86_64");

      std::string so_interp_canon = fs::canonical(b.dynl.interp).string();

      if (!b.dynl.interp.empty()) {
        arg_vec.push_back("-dynamic-linker");
        arg_vec.push_back(so_interp_canon.c_str());
      }

      std::string soname_arg = std::string("-soname=") + b.dynl.soname;

      if (!b.dynl.soname.empty()) {
        arg_vec.push_back(soname_arg.c_str());

        if (binary_filename != b.dynl.soname)
          fs::create_symlink(binary_filename,
                             chrooted_path.parent_path() / b.dynl.soname);
      }

#if 0
      std::string rtld_soname_arg = ":" + rtld_soname;
      if (!rtld_soname.empty()) {
        arg_vec.push_back("-l");
        arg_vec.push_back(rtld_soname_arg.c_str());
      }
#endif

      std::vector<std::string> needed_arg_vec;

      for (const std::string &needed : b.dynl.needed) {
#if 0
        if (needed == rtld_soname)
          continue;
#endif

        needed_arg_vec.push_back(std::string(":") + needed);
      }

      for (const std::string &needed_arg : needed_arg_vec) {
        arg_vec.push_back("-l");
        arg_vec.push_back(needed_arg.c_str());
      }

      arg_vec.push_back(nullptr);

      print_command(&arg_vec[0]);

      close(STDIN_FILENO);
      execve(arg_vec[0], const_cast<char **>(&arg_vec[0]), ::environ);

      int err = errno;
      WithColor::error() << llvm::formatv("execve failed: {0}\n",
                                          strerror(err));
      return 1;
    }

    //
    // check exit code
    //
    if (int ret = await_process_completion(pid)) {
      WithColor::error() << "ld failed for " << binary_filename << '\n';
      return ret;
    }
  }

  return 0;
}

void handle_sigint(int no) {
  Cancel = true;
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

void print_command(const char **argv) {
  for (const char **s = argv; *s; ++s)
    llvm::outs() << *s << ' ';

  llvm::outs() << '\n';
}

/// Represents a contiguous uniform range in the file. We cannot just create a
/// range directly because when creating one of these from the .dynamic table
/// the size, entity size and virtual address are different entries in arbitrary
/// order (DT_REL, DT_RELSZ, DT_RELENT for example).
struct DynRegionInfo {
  DynRegionInfo() = default;
  DynRegionInfo(const void *A, uint64_t S, uint64_t ES)
      : Addr(A), Size(S), EntSize(ES) {}

  /// Address in current address space.
  const void *Addr = nullptr;
  /// Size in bytes of the region.
  uint64_t Size = 0;
  /// Size of each entity in the region.
  uint64_t EntSize = 0;

  template <typename Type>
    llvm::ArrayRef<Type> getAsArrayRef() const {
    const Type *Start = reinterpret_cast<const Type *>(Addr);
    if (!Start)
      return {Start, Start};
    if (EntSize != sizeof(Type) || Size % EntSize)
      abort();
    return {Start, Start + (Size / EntSize)};
  }
};

template <class T>
static T unwrapOrError(llvm::Expected<T> EO) {
  if (EO)
    return *EO;

  std::string Buf;
  {
    llvm::raw_string_ostream OS(Buf);
    llvm::logAllUnhandledErrors(EO.takeError(), OS, "");
  }
  WithColor::error() << Buf << '\n';
  exit(1);
}

#if defined(__x86_64__) || defined(__aarch64__)
typedef typename obj::ELF64LEObjectFile ELFO;
typedef typename obj::ELF64LEFile ELFT;
#elif defined(__i386__)
typedef typename obj::ELF32LEObjectFile ELFO;
typedef typename obj::ELF32LEFile ELFT;
#endif

static bool verify_arch(const obj::ObjectFile &);

bool dynamic_linking_info_of_binary(binary_t &b, dynamic_linking_info_t &out) {
  //
  // parse the ELF
  //
  llvm::StringRef Buffer(reinterpret_cast<const char *>(&b.Data[0]),
                         b.Data.size());
  llvm::StringRef Identifier(b.Path);
  llvm::MemoryBufferRef MemBuffRef(Buffer, Identifier);

  llvm::Expected<std::unique_ptr<obj::Binary>> BinOrErr =
      obj::createBinary(MemBuffRef);

  if (!BinOrErr) {
    WithColor::error() << "failed to create binary from" << b.Path << '\n';
    return false;
  }

  std::unique_ptr<obj::Binary> &Bin = BinOrErr.get();

  if (!llvm::isa<ELFO>(Bin.get())) {
    WithColor::error() << "is not ELF of expected type\n";
    return false;
  }

  ELFO &O = *llvm::cast<ELFO>(Bin.get());

  if (!verify_arch(O)) {
    WithColor::error() << "architecture mismatch of input\n";
    return false;
  }

  const ELFT &E = *O.getELFFile();

  typedef typename ELFT::Elf_Dyn Elf_Dyn;
  typedef typename ELFT::Elf_Dyn_Range Elf_Dyn_Range;
  typedef typename ELFT::Elf_Phdr Elf_Phdr;
  typedef typename ELFT::Elf_Phdr_Range Elf_Phdr_Range;
  typedef typename ELFT::Elf_Shdr Elf_Shdr;
  typedef typename ELFT::Elf_Shdr_Range Elf_Shdr_Range;
  typedef typename ELFT::Elf_Sym Elf_Sym;
  typedef typename ELFT::Elf_Sym_Range Elf_Sym_Range;
  typedef typename ELFT::Elf_Rela Elf_Rela;

  auto checkDRI = [&E](DynRegionInfo DRI) -> DynRegionInfo {
    if (DRI.Addr < E.base() ||
        (const uint8_t *)DRI.Addr + DRI.Size > E.base() + E.getBufSize())
      abort();
    return DRI;
  };

  llvm::SmallVector<const Elf_Phdr *, 4> LoadSegments;
  DynRegionInfo DynamicTable;
  {
    auto createDRIFrom = [&E, &checkDRI](const Elf_Phdr *P,
                                         uint64_t EntSize) -> DynRegionInfo {
      return checkDRI({E.base() + P->p_offset, P->p_filesz, EntSize});
    };

    for (const Elf_Phdr &Phdr : unwrapOrError(E.program_headers())) {
      if (Phdr.p_type == llvm::ELF::PT_DYNAMIC) {
        DynamicTable = createDRIFrom(&Phdr, sizeof(Elf_Dyn));
        continue;
      }
      if (Phdr.p_type != llvm::ELF::PT_LOAD || Phdr.p_filesz == 0)
        continue;
      LoadSegments.push_back(&Phdr);
    }
  }

  assert(DynamicTable.Addr);

  //
  // parse dynamic table
  //
  auto dynamic_table = [&DynamicTable](void) -> Elf_Dyn_Range {
    return DynamicTable.getAsArrayRef<Elf_Dyn>();
  };

  llvm::StringRef DynamicStringTable;
  {

    auto toMappedAddr = [&](uint64_t VAddr) -> const uint8_t * {
      const Elf_Phdr *const *I =
          std::upper_bound(LoadSegments.begin(), LoadSegments.end(), VAddr,
                           [](uint64_t VAddr, const Elf_Phdr *Phdr) {
                             return VAddr < Phdr->p_vaddr;
                           });
      if (I == LoadSegments.begin())
        abort();
      --I;
      const Elf_Phdr &Phdr = **I;
      uint64_t Delta = VAddr - Phdr.p_vaddr;
      if (Delta >= Phdr.p_filesz)
        abort();
      return E.base() + Phdr.p_offset + Delta;
    };

    const char *StringTableBegin = nullptr;
    uint64_t StringTableSize = 0;
    for (const Elf_Dyn &Dyn : dynamic_table()) {
      switch (Dyn.d_tag) {
      case llvm::ELF::DT_STRTAB:
        StringTableBegin = (const char *)toMappedAddr(Dyn.getPtr());
        break;
      case llvm::ELF::DT_STRSZ:
        StringTableSize = Dyn.getVal();
        break;
      case llvm::ELF::DT_NEEDED:
        break;
      }
    };

    if (StringTableBegin)
      DynamicStringTable = llvm::StringRef(StringTableBegin, StringTableSize);
  }

  std::vector<uint64_t> needed_offsets;
  uint64_t SONameOffset = 0;

  for (const Elf_Dyn &Dyn : dynamic_table()) {
    switch (Dyn.d_tag) {
    case llvm::ELF::DT_SONAME:
      SONameOffset = Dyn.getVal();
      break;
    case llvm::ELF::DT_NEEDED:
      needed_offsets.push_back(Dyn.getVal());
      break;
    }
  }

  if (!SONameOffset || SONameOffset > DynamicStringTable.size())
    ; // no soname
  else
    out.soname = DynamicStringTable.data() + SONameOffset;

  for (uint64_t off : needed_offsets) {
    if (!off || off > DynamicStringTable.size())
      ; // no soname
    else
      out.needed.push_back(DynamicStringTable.data() + off);
  }

  for (const Elf_Phdr &Phdr : unwrapOrError(E.program_headers())) {
    if (Phdr.p_type == llvm::ELF::PT_INTERP) {
      out.interp = Buffer.data() + Phdr.p_offset;
      break;
    }
  }

  return true;
}

bool verify_arch(const obj::ObjectFile &Obj) {
#if defined(__x86_64__)
  const llvm::Triple::ArchType archty = llvm::Triple::ArchType::x86_64;
#elif defined(__i386__)
  const llvm::Triple::ArchType archty = llvm::Triple::ArchType::x86;
#elif defined(__aarch64__)
  const llvm::Triple::ArchType archty = llvm::Triple::ArchType::aarch64;
#endif
  return Obj.getArch() == archty;
}

void IgnoreCtrlC(void) {
  struct sigaction sa;

  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = SIG_IGN;

  if (sigaction(SIGINT, &sa, nullptr) < 0) {
    int err = errno;
    WithColor::error() << llvm::formatv("{0}: sigaction failed ({1})\n",
                                        __func__, strerror(err));
  }
}

}
