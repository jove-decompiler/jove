#include <string>
#include <vector>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/graphviz.hpp>

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
#include <llvm/Support/DataExtractor.h>
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
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/bitset.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/set.hpp>
#include <boost/graph/adj_list_serialize.hpp>
#include <boost/range/adaptor/reversed.hpp>
#include <boost/graph/topological_sort.hpp>
#include <boost/format.hpp>

#include "jove_macros.h"

#ifndef likely
#define likely(x)   __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

static void __warn(const char *file, int line);

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
                                 cl::init(jove::num_cpus()),
                                 cl::cat(JoveCategory));

static cl::opt<bool>
    Trace("trace",
          cl::desc("Instrument code to output basic block execution trace"),
          cl::cat(JoveCategory));

static cl::opt<std::string>
    UseLd("use-ld",
          cl::desc("Force using particular linker (lld,bfd,gold)"),
          cl::cat(JoveCategory));


static cl::opt<bool>
    Verbose("verbose",
            cl::desc("Print extra information for debugging purposes"),
            cl::cat(JoveCategory));

static cl::alias VerboseAlias("v", cl::desc("Alias for -verbose."),
                              cl::aliasopt(Verbose), cl::cat(JoveCategory));

static cl::opt<bool> DFSan("dfsan", cl::desc("Run dfsan on bitcode"),
                           cl::cat(JoveCategory));

static cl::opt<bool> Optimize("optimize", cl::desc("Run optimizations on bitcode"),
                              cl::cat(JoveCategory));

static cl::opt<bool> SkipCopyRelocHack("skip-copy-reloc-hack",
                                       cl::desc("Do not insert COPY relocations in output file (HACK)"),
                                       cl::cat(JoveCategory));

static cl::opt<bool> DebugSjlj("debug-sjlj",
                               cl::desc("Before setjmp/longjmp, dump information about the call"),
                               cl::cat(JoveCategory));

static cl::opt<bool>
    CheckEmulatedStackReturnAddress("check-emulated-stack-return-address",
                                    cl::desc("Check for stack overrun"),
                                    cl::cat(JoveCategory));

static cl::opt<bool> SkipLLVM(
    "skip-llvm",
    cl::desc("Skip running jove-llvm (careful when using this option)"),
    cl::cat(JoveCategory));

static cl::opt<bool>
    ForeignLibs("foreign-libs",
                cl::desc("only recompile the executable itself; "
                         "treat all other binaries as \"foreign\""),
                cl::cat(JoveCategory));

static cl::list<std::string>
    PinnedGlobals("pinned-globals", cl::CommaSeparated,
                  cl::value_desc("glb_1,glb_2,...,glb_n"),
                  cl::desc("force specified TCG globals to always go through CPUState"),
                  cl::cat(JoveCategory));

} // namespace opts

namespace jove {
static int recompile(void);
}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::HideUnrelatedOptions({&opts::JoveCategory, &llvm::ColorCategory});
  cl::AddExtraVersionPrinter([](llvm::raw_ostream &OS) -> void {
    OS << "jove version " JOVE_VERSION "\n";
  });
  cl::ParseCommandLineOptions(argc, argv, "Jove Recompile\n");

  return jove::recompile();
}

namespace jove {

typedef boost::format fmt;

static decompilation_t Decompilation;

static char tmpdir[] = {'/', 't', 'm', 'p', '/', 'X',
                        'X', 'X', 'X', 'X', 'X', '\0'};

static int await_process_completion(pid_t);

static void print_command(const char **argv);

static std::string compiler_runtime_afp, jove_llvm_path, jove_bin_path,
    jove_rt_path, jove_dfsan_path, llc_path, ld_path, opt_path, llvm_dis_path;

static std::atomic<bool> Cancel(false);

static void handle_sigint(int);

static bool dynamic_linking_info_of_binary(binary_t &,
                                           dynamic_linking_info_t &out);

static void IgnoreCtrlC(void);

static void write_dso_graphviz(std::ostream &out, const dso_graph_t &);

static std::vector<dso_t> Q;
static std::mutex Q_mtx;

static void worker(const dso_graph_t &dso_graph);

static std::atomic<bool> worker_failed(false);

static std::pair<tcg_uintptr_t, tcg_uintptr_t> base_of_executable(binary_t &);

int recompile(void) {
  compiler_runtime_afp =
      (boost::dll::program_location().parent_path().parent_path().parent_path() /
       "third_party" / "obj" / ("libclang_rt.builtins-" TARGET_ARCH_NAME ".a"))
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
  if (fs::exists(opts::Output)) {
    if (opts::Verbose)
      WithColor::note() << llvm::formatv("reusing output directory {}\n",
                                         opts::Output);
  } else {
    if (!fs::create_directory(opts::Output)) {
      WithColor::error() << "failed to create directory at \"" << opts::Output
                         << "\"\n";
      return 1;
    }
  }

  //
  // create symlink back to jv
  //
  if (fs::exists(fs::path(opts::Output) / ".jv")) // delete any stale symlinks
    fs::remove(fs::path(opts::Output) / ".jv");

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

  jove_dfsan_path =
      (boost::dll::program_location().parent_path().parent_path().parent_path() /
       "third_party" / "lib" / ("libclang_rt.dfsan.jove-" TARGET_ARCH_NAME ".so"))
	  .string();
  if (!fs::exists(jove_dfsan_path)) {
    WithColor::error() << llvm::formatv("could not find {0}\n",
					jove_dfsan_path);
    return 1;
  }

  llc_path = (boost::dll::program_location().parent_path().parent_path().parent_path() /
              "third_party" / "llvm-project" / "static_install" / "bin" / "llc")
                 .string();
  if (!fs::exists(llc_path)) {
    WithColor::error() << "could not find /usr/bin/llc\n";
    return 1;
  }

  llvm_dis_path =
      (boost::dll::program_location().parent_path().parent_path().parent_path() /
       "third_party" / "llvm-project" / "static_install" / "bin" / "llvm-dis")
          .string();
  if (!fs::exists(llvm_dis_path)) {
    WithColor::error() << "could not find llvm-dis\n";
    return 1;
  }

  // lld 9.0.1
  std::string lld_path =
      (boost::dll::program_location().parent_path().parent_path().parent_path() /
       "third_party" / "llvm-project" / "static_install" / "bin" / "ld.lld").string();

  std::string ld_gold_path = "/usr/bin/ld.gold";
  std::string ld_bfd_path = "/usr/bin/ld.bfd";

  ld_path = lld_path;

  if (!opts::UseLd.empty()) {
    if (opts::UseLd.compare("gold") == 0) {
      ld_path = ld_gold_path;
    } else if (opts::UseLd.compare("bfd") == 0) {
      ld_path = ld_bfd_path;
    } else if (opts::UseLd.compare("lld") == 0) {
      ld_path = lld_path;
    } else {
      WithColor::error() << llvm::formatv("unknown linker \"{0}\"\n", opts::UseLd);
      return 1;
    }
  }

  if (!fs::exists(ld_path)) {
    WithColor::error() << llvm::formatv("could not find linker at {0}\n",
                                        ld_path);
    return 1;
  }

  opt_path = (boost::dll::program_location().parent_path().parent_path().parent_path() /
              "third_party" / "llvm-project" / "static_install" / "bin" / "opt")
                 .string();
  if (!fs::exists(opt_path)) {
    WithColor::error() << llvm::formatv("could not find {0}\n", opt_path);
    return 1;
  }

  //
  // prepare to process the binaries by creating a unique temporary directory
  //
  if (!mkdtemp(tmpdir)) {
    WithColor::error() << "mkdtemp failed : " << strerror(errno) << '\n';
    return 1;
  }

  struct rm_tmpdir_t {
    rm_tmpdir_t () {}
    ~rm_tmpdir_t () {
      fs::remove_all(fs::path(tmpdir));
    }
  } rm_tmpdir;

  if (opts::Verbose)
    llvm::errs() << llvm::formatv("tmpdir: {0}\n", tmpdir);

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

    boost::archive::text_iarchive ia(ifs);
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
    if (b.IsVDSO)
      continue;

    if (!dynamic_linking_info_of_binary(b, b.dynl)) {
      WithColor::error() << llvm::formatv(
          "!dynamic_linking_info_of_binary({0})\n", b.Path.c_str());
      return 1;
    }
  }

  //
  // create basic directories for sysroot
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
    fs::create_directories(fs::path(opts::Output) / "lib"); /* XXX? */
    fs::create_directories(fs::path(opts::Output) / "var" / "run");
  }

  //
  // copy dynamic linker
  //
  std::string rtld_soname;

  for (binary_t &b : Decompilation.Binaries) {
    if (!b.IsDynamicLinker)
      continue;

#if 0
    assert(fs::exists(b.Path) && fs::is_regular_file(b.Path));
#else
    //
    // we have the binary data in the decompilation. let's use it
    //
    fs::path ldso_path = fs::path(tmpdir) / "ld.so";
    {
      std::ofstream ofs(ldso_path.c_str());

      ofs.write(reinterpret_cast<char *>(&b.Data[0]), b.Data.size());
    }

    //
    // make rtld executable (chmod)
    //
    fs::permissions(ldso_path, fs::others_read |
                               fs::others_exe |

                               fs::group_read |
                               fs::group_exe |

                               fs::owner_read |
                               fs::owner_write |
                               fs::owner_exe);
#endif

    fs::path chrooted_path(opts::Output + b.Path);
    fs::create_directories(chrooted_path.parent_path());

    fs::copy_file(ldso_path, chrooted_path, fs::copy_option::overwrite_if_exists);

    if (!b.dynl.soname.empty()) {
      rtld_soname = b.dynl.soname;

      std::string binary_filename = fs::path(b.Path).filename().string();

      if (binary_filename != b.dynl.soname) {
        fs::path dst = chrooted_path.parent_path() / b.dynl.soname;

        if (fs::exists(dst))
          fs::remove(dst);

        fs::create_symlink(binary_filename, dst);
      }
    }

    break;
  }

  //
  // copy jove runtime
  //
  {
    {
      fs::path chrooted_path =
          fs::path(opts::Output) / "usr" / "lib" / JOVE_RT_SONAME;

      fs::create_directories(chrooted_path.parent_path());
      fs::copy_file(jove_rt_path, chrooted_path,
                    fs::copy_option::overwrite_if_exists);
    }

    {
      fs::path chrooted_path =
          fs::path(opts::Output) / "usr" / "lib" / JOVE_RT_SO;

      fs::create_directories(chrooted_path.parent_path());

      if (fs::exists(chrooted_path))
        fs::remove(chrooted_path);

      fs::create_symlink(JOVE_RT_SONAME, chrooted_path);
    }
  }

  //
  // copy jove dfsan runtime
  //
  if (opts::DFSan) {
    const char *dfsan_rt_filename = "libclang_rt.dfsan.jove-" TARGET_ARCH_NAME ".so";

    {
      fs::path chrooted_path =
          fs::path(opts::Output) / "usr" / "lib" / dfsan_rt_filename;

      fs::copy_file(jove_dfsan_path, chrooted_path,
                    fs::copy_option::overwrite_if_exists);
    }

    if (!fs::equivalent(fs::path(opts::Output) / "usr" / "lib" / dfsan_rt_filename,
                        fs::path(opts::Output) / "lib" / dfsan_rt_filename)) {
      /* XXX some dynamic linkers only look in /lib */
      fs::path chrooted_path =
          fs::path(opts::Output) / "lib" / dfsan_rt_filename;

      fs::copy_file(jove_dfsan_path, chrooted_path,
                    fs::copy_option::overwrite_if_exists);
    }
  }

  //
  // additional stuff for DFSan
  //
  if (opts::DFSan) {
    fs::create_directories(fs::path(opts::Output) / "jove");
    fs::create_directories(fs::path(opts::Output) / "dfsan");

    {
      std::ofstream ofs(
          (fs::path(opts::Output) / "jove" / "BinaryPathsTable.txt").c_str());

      for (const binary_t &binary : Decompilation.Binaries)
        ofs << binary.Path << '\n';
    }

    fs::create_directories(fs::path(opts::Output) / "jove" /
                           "BinaryBlockAddrTables");

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
          tcg_uintptr_t Addr = ICFG[bb].Term.Addr; /* XXX */
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

  std::unordered_map<std::string, binary_index_t> soname_map;

  for (binary_index_t BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx) {
    binary_t &b = Decompilation.Binaries[BIdx];

    if (b.dynl.soname.empty() && !b.IsExecutable) {
      soname_map.insert({fs::path(b.Path).filename().string(), BIdx}); /* XXX */
      continue;
    }

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

  bool haveGraphEasy = fs::exists("/usr/bin/vendor_perl/graph-easy") ||
                       fs::exists("/usr/bin/graph-easy");
  if (opts::Verbose && haveGraphEasy) {
    //
    // graphviz
    //
    std::string dso_dot_path = (fs::path(tmpdir) /  "dso_graph.dot").string();

    {
      std::ofstream ofs(dso_dot_path);

      write_dso_graphviz(ofs, dso_graph);
    }

    //
    // graph-easy
    //

    pid_t pid = fork();
    if (!pid) {
      IgnoreCtrlC();

      std::string input_arg = "--input=" + dso_dot_path;

      const char *arg_arr[] = {
        fs::exists("/usr/bin/vendor_perl/graph-easy")
            ? "/usr/bin/vendor_perl/graph-easy"
            : "/usr/bin/graph-easy",

        input_arg.c_str(),
#if 0
        "--as=ascii",
#else
        "--as=boxart",
#endif

        nullptr
      };

      print_command(&arg_arr[0]);

      close(STDIN_FILENO);
      execve(arg_arr[0], const_cast<char **>(&arg_arr[0]), ::environ);

      int err = errno;
      WithColor::error() << llvm::formatv("execve failed: {0}\n",
                                          strerror(err));
      return 1;
    }

    //
    // check exit code
    //
    if (await_process_completion(pid))
      WithColor::warning() << "graph-easy failed for " << dso_dot_path << '\n';
  }

  //
  // topological sort of dynamic linking graph
  //
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

  Q.reserve(top_sorted.size());
  for (dso_t dso : boost::adaptors::reverse(top_sorted)) {
    binary_index_t BIdx = dso_graph[dso].BIdx;
    if (opts::ForeignLibs && !Decompilation.Binaries[BIdx].IsExecutable)
      continue;

    Q.push_back(dso);
  }

  WithColor::note() << llvm::formatv(
      "Recompiling {0} {1}...\n",
      (opts::ForeignLibs ? 3 : Decompilation.Binaries.size()) - 2,
      opts::ForeignLibs ? "binary" : "binaries");

  //
  // run jove-llvm and llc on all DSOs
  //
  {
    std::vector<std::thread> workers;

    unsigned N = opts::Threads;

    workers.reserve(N);
    for (unsigned i = 0; i < N; ++i)
      workers.push_back(std::thread(worker, std::cref(dso_graph)));

    for (std::thread &t : workers)
      t.join();
  }

  if (worker_failed.load())
    return 1;

  //
  // run ld on all the object files
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

    const fs::path chrooted_path = fs::path(opts::Output) / b.Path;
    fs::create_directories(chrooted_path.parent_path());

    std::string binary_filename = fs::path(b.Path).filename().string();

    std::string objfp(chrooted_path.string() + ".o");
    std::string mapfp(chrooted_path.string() + ".map");

    if (opts::ForeignLibs && !b.IsExecutable) {
      //
      // original lib
      //
      std::ofstream ofs(chrooted_path.c_str());
      ofs.write(&b.Data[0], b.Data.size());

      if (!b.dynl.soname.empty()) {
        //
        // create symlink
        //
        if (binary_filename != b.dynl.soname) {
          fs::path dst = chrooted_path.parent_path() / b.dynl.soname;
          if (fs::exists(dst))
            fs::remove(dst);

          try {
            fs::create_symlink(binary_filename, dst);
          } catch (...) {
              ;
          }
        }
      }

      continue;
    }

    if (!fs::exists(objfp)) {
      WithColor::warning() << llvm::formatv("{0} doesn't exist; skipping {1}\n",
                                            objfp, binary_filename);
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

#if defined(TARGET_X86_64)
          "elf_x86_64",
#elif defined(TARGET_I386)
          "elf_i386",
#elif defined(TARGET_AARCH64)
          "aarch64linux",
#elif defined(TARGET_MIPS64)
          "elf64ltsmip",
#elif defined(TARGET_MIPS32) && defined(TARGET_MIPSEL)
          "elf32ltsmip",
#elif defined(TARGET_MIPS32) && defined(TARGET_MIPS)
          "elf32btsmip",
#else
#error
#endif

          "-nostdlib",

          "--push-state", "--as-needed", compiler_runtime_afp.c_str(),
          "--pop-state",

          "--exclude-libs", "ALL",

          "-init", "_jove_init"
      };

      std::string _arg1, _arg2;

      if (b.IsExecutable) {
        if (b.IsPIC) {
          arg_vec.push_back("-pie");
        } else {
          //
          // the following has only been tested to work with the lld linker.
          //
          arg_vec[0] = lld_path.c_str();

          //arg_vec.push_back("-z");
          //arg_vec.push_back("nocopyreloc");

          tcg_uintptr_t Base, End;
          std::tie(Base, End) = base_of_executable(b);

          arg_vec.push_back("--section-start");
          _arg1 = (fmt(".jove=0x%lx") % Base).str();
          arg_vec.push_back(_arg1.c_str());

#if 0
#define ALIGN_DOWN(n, m) ((n) / (m) * (m))
#define ALIGN_UP(n, m) ALIGN_DOWN((n) + (m) - 1, (m))

          arg_vec.push_back("--image-base");
          _arg2 = (fmt("0x%lx") % (ALIGN_DOWN(Base, 4096))).str();
          arg_vec.push_back(_arg2.c_str());

#undef ALIGN_UP
#undef ALIGN_DOWN
#endif
        }
      } else {
        assert(b.IsPIC);
        arg_vec.push_back("-shared");
      }

#if 0
      arg_vec.push_back("-z");
      arg_vec.push_back("now");
#endif

      // XXX assuming lld
      arg_vec.push_back("--allow-shlib-undefined");
      if (b.IsExecutable)
        arg_vec.push_back("--unresolved-symbols=ignore-all");

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
        arg_vec.push_back("-lclang_rt.dfsan.jove-" TARGET_ARCH_NAME);

      const char *rtld_path = nullptr;
      if (!b.dynl.interp.empty()) {
        for (binary_t &b : Decompilation.Binaries) {
          if (b.IsDynamicLinker) {
            rtld_path = b.Path.c_str();
            break;
          }
        }
        assert(rtld_path);

        arg_vec.push_back("-dynamic-linker");
        arg_vec.push_back(rtld_path);
      }

      std::string soname_arg = std::string("-soname=") + b.dynl.soname;

      if (!b.dynl.soname.empty()) {
        arg_vec.push_back(soname_arg.c_str());

        //
        // create symlink
        //
        if (binary_filename != b.dynl.soname) {
          fs::path dst = chrooted_path.parent_path() / b.dynl.soname;
          if (fs::exists(dst))
            fs::remove(dst);

          try {
            fs::create_symlink(binary_filename, dst);
          } catch (...) {
            WithColor::warning()
                << llvm::formatv("{0}:{1}\n", __FILE__, __LINE__);
          }
        }
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

        auto it = soname_map.find(needed);
        if (it == soname_map.end()) {
          WithColor::warning()
              << llvm::formatv("no entry in soname_map for {0}\n", needed);
          continue;
        }

        needed_arg_vec.push_back(std::string(":") + needed);
      }

      for (const std::string &needed_arg : needed_arg_vec) {
        arg_vec.push_back("-l");
        arg_vec.push_back(needed_arg.c_str());
      }

      if (rtld_path && fs::exists(rtld_path)) /* XXX */
        arg_vec.push_back(rtld_path);

      if (opts::SkipCopyRelocHack)
        arg_vec.push_back("--skip-copy-reloc-hack");

      arg_vec.push_back(nullptr);

      if (opts::Verbose)
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
      WithColor::error() << llvm::formatv("ld failed for {0}; skipping {1}\n",
                                          objfp, binary_filename);
      return 1;
    }
  }

  return 0;
}

static bool pop_dso(dso_t &out);

void worker(const dso_graph_t &dso_graph) {
  dso_t dso;
  while (pop_dso(dso)) {
    binary_index_t BIdx = dso_graph[dso].BIdx;

    binary_t &b = Decompilation.Binaries.at(BIdx);

    if (b.IsDynamicLinker)
      continue;
    if (b.IsVDSO)
      continue;

    // make sure the path is absolute
    assert(b.Path.at(0) == '/');

    const fs::path chrooted_path = fs::path(opts::Output) / b.Path;
    fs::create_directories(chrooted_path.parent_path());

    std::string binary_filename = fs::path(b.Path).filename().string();

    std::string bcfp(chrooted_path.string() + ".bc");
    std::string llfp(chrooted_path.string() + ".ll");
    std::string ll_strip_fp(chrooted_path.string() + ".strip.ll");
    std::string objfp(chrooted_path.string() + ".o");
    std::string mapfp(chrooted_path.string() + ".map");
    std::string dfsan_modid_fp(chrooted_path.string() + ".modid");

    std::string bytecode_loc = (fs::path(opts::Output) / "dfsan").string();

    //
    // run jove-llvm
    //
    pid_t pid = fork();
    if (!pid) {
      IgnoreCtrlC();

      std::string BIdx_arg(std::to_string(BIdx));

      std::vector<const char *> arg_vec = {
        jove_llvm_path.c_str(),

        "-o", bcfp.c_str(),
        "--version-script", mapfp.c_str(),

        "--binary-index", BIdx_arg.c_str(),

        "-d", opts::jv.c_str(),
      };

      if (opts::Optimize)
        arg_vec.push_back("--optimize");

      std::string output_module_id_file_arg =
          "--dfsan-output-module-id=" + dfsan_modid_fp;

      std::string dfsan_bytecode_loc_arg =
          "--dfsan-bytecode-loc=" + bytecode_loc;

      if (opts::DFSan) {
        arg_vec.push_back("--dfsan");
        arg_vec.push_back(output_module_id_file_arg.c_str());
        arg_vec.push_back(dfsan_bytecode_loc_arg.c_str());
        arg_vec.push_back("--dfsan-no-loop-starts");
      }

      if (opts::CheckEmulatedStackReturnAddress)
        arg_vec.push_back("--check-emulated-stack-return-address");
      if (opts::Trace)
        arg_vec.push_back("--trace");
      if (opts::ForeignLibs)
        arg_vec.push_back("--foreign-libs");
      if (opts::DebugSjlj)
        arg_vec.push_back("--debug-sjlj");

      std::string pinned_globals_arg;
      if (!opts::PinnedGlobals.empty()) {
        pinned_globals_arg = "--pinned-globals=";
        for (const std::string &PinnedGlbStr : opts::PinnedGlobals) {
          pinned_globals_arg.append(PinnedGlbStr);
          pinned_globals_arg.push_back(',');
        }
        pinned_globals_arg.resize(pinned_globals_arg.size() - 1);

        arg_vec.push_back(pinned_globals_arg.c_str());
      }

      arg_vec.push_back(nullptr);

      if (opts::Verbose)
        print_command(&arg_vec[0]);

      {
        std::string stdoutfp = bcfp + ".stdout.txt";
        int stdoutfd = open(stdoutfp.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0666);
        dup2(stdoutfd, STDOUT_FILENO);
        close(stdoutfd);
      }

      {
        std::string stderrfp = bcfp + ".stderr.txt";
        int stderrfd = open(stderrfp.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0666);
        dup2(stderrfd, STDERR_FILENO);
        close(stderrfd);
      }

      close(STDIN_FILENO);
      execve(arg_vec[0], const_cast<char **>(&arg_vec[0]), ::environ);

      int err = errno;
      WithColor::error() << llvm::formatv("execve failed: {0}\n",
                                          strerror(err));
      exit(1);
    }

    //
    // check exit code
    //
    if (int ret = await_process_completion(pid)) {
      worker_failed.store(true);
      WithColor::error() << llvm::formatv("jove-llvm failed on {0}: see {1}\n",
                                          binary_filename,
                                          bcfp + ".stderr.txt");
      continue;
    }

    if (opts::DFSan) {
      std::ifstream ifs(dfsan_modid_fp);
      std::string dfsan_modid((std::istreambuf_iterator<char>(ifs)),
                              std::istreambuf_iterator<char>());

      WithColor::note() << llvm::formatv("ModuleID for {0} is {1}\n", bcfp,
                                         dfsan_modid);

      fs::copy_file(bcfp, opts::Output + "/dfsan/" + dfsan_modid,
                    fs::copy_option::overwrite_if_exists);
    }

    //
    // run llvm-dis on bitcode
    //
    std::thread t1([&](void) -> void {
      pid_t pid = fork();
      if (!pid) {
        IgnoreCtrlC();
        nice(10);

        const char *arg_arr[] = {
          llvm_dis_path.c_str(),

          "-o", llfp.c_str(),
          bcfp.c_str(),

          nullptr
        };

        if (opts::Verbose)
          print_command(&arg_arr[0]);

        close(STDIN_FILENO);
        execve(arg_arr[0], const_cast<char **>(&arg_arr[0]), ::environ);

        int err = errno;
        WithColor::error() << llvm::formatv("execve failed: {0}\n",
                                            strerror(err));
        exit(1);
      }

      (void)await_process_completion(pid);
    });

    //
    // run opt on bitcode to generate stripped ll
    //
    std::thread t2([&](void) -> void {
      pid_t pid = fork();
      if (!pid) {
        IgnoreCtrlC();
        nice(10);

        const char *arg_arr[] = {
          opt_path.c_str(),

          "-o", ll_strip_fp.c_str(),
          "-S", "--strip-debug",
          bcfp.c_str(),

          nullptr
        };

        if (opts::Verbose)
          print_command(&arg_arr[0]);

        close(STDIN_FILENO);
        execve(arg_arr[0], const_cast<char **>(&arg_arr[0]), ::environ);

        int err = errno;
        WithColor::error() << llvm::formatv("execve failed: {0}\n",
                                            strerror(err));
        exit(1);
      }

      (void)await_process_completion(pid);
    });

    //
    // run llc
    //
    pid = fork();
    if (!pid) {
      IgnoreCtrlC();

      std::vector<const char *> arg_vec = {
        llc_path.c_str(),

        "-o", objfp.c_str(),
        bcfp.c_str(),

        "--filetype=obj",

        "--disable-simplify-libcalls",
      };

      if (!opts::Optimize || opts::DFSan) {
        arg_vec.push_back("--fast-isel");
        arg_vec.push_back("-O0");
      }

      if (!opts::Optimize) {
        arg_vec.push_back("--frame-pointer=all");

#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
        arg_vec.push_back("--disable-mips-delay-filler"); /* make our life easier */
#endif
      }

      if (b.IsPIC) {
        arg_vec.push_back("--relocation-model=pic");
      } else {
        assert(b.IsExecutable);
        arg_vec.push_back("--relocation-model=static");
      }

#if defined(TARGET_X86_64) || defined(TARGET_I386)
      if (opts::DFSan) { /* XXX */
        arg_vec.push_back("--stack-alignment=16");
        arg_vec.push_back("--stackrealign");
      }
#endif

      arg_vec.push_back(nullptr);

      if (opts::Verbose)
        print_command(&arg_vec[0]);

      close(STDIN_FILENO);
      execve(arg_vec[0], const_cast<char **>(&arg_vec[0]), ::environ);

      int err = errno;
      WithColor::error() << llvm::formatv("execve failed: {0}\n",
                                          strerror(err));
      exit(1);
    }

    //
    // check exit code
    //
    if (int ret = await_process_completion(pid)) {
      worker_failed = true;
      WithColor::error() << llvm::formatv("llc failed for {0}\n",
                                          binary_filename);

      t1.join(); t2.join();
      continue;
    }

    t1.join(); t2.join();
  }
}

bool pop_dso(dso_t &out) {
  std::lock_guard<std::mutex> lck(Q_mtx);

  if (Q.empty()) {
    return false;
  } else {
    out = Q.back();
    Q.resize(Q.size() - 1);
    return true;
  }
}

struct graphviz_label_writer {
  const dso_graph_t &g;

  graphviz_label_writer(const dso_graph_t &g) : g(g) {}

  void operator()(std::ostream &out, dso_t v) const {
    std::string name =
        fs::path(Decompilation.Binaries.at(g[v].BIdx).Path).filename().string();

    boost::replace_all(name, "\\", "\\\\");
    boost::replace_all(name, "\r\n", "\\l");
    boost::replace_all(name, "\n", "\\l");
    boost::replace_all(name, "\"", "\\\"");
    boost::replace_all(name, "{", "\\{");
    boost::replace_all(name, "}", "\\}");
    boost::replace_all(name, "|", "\\|");
    boost::replace_all(name, "|", "\\|");
    boost::replace_all(name, "<", "\\<");
    boost::replace_all(name, ">", "\\>");
    boost::replace_all(name, "(", "\\(");
    boost::replace_all(name, ")", "\\)");
    boost::replace_all(name, ",", "\\,");
    boost::replace_all(name, ";", "\\;");
    boost::replace_all(name, ":", "\\:");
    boost::replace_all(name, " ", "\\ ");

    out << "[label=\"";
    out << name;
    out << "\"]";
  }
};

struct graphviz_edge_prop_writer {
  const dso_graph_t &g;
  graphviz_edge_prop_writer(const dso_graph_t &g) : g(g) {}

  template <class Edge>
  void operator()(std::ostream &out, const Edge &e) const {
    static const char *edge_type_styles[] = {
        "solid", "dashed", /*"invis"*/ "dotted"
    };

    out << "[style=\"" << edge_type_styles[0] << "\"]";
  }
};

struct graphviz_prop_writer {
  void operator()(std::ostream &out) const {
    out << "fontname = \"Courier\"\n"
           "fontsize = 10\n"
           "\n"
           "node [\n"
           "fontname = \"Courier\"\n"
           "fontsize = 10\n"
           "shape = \"record\"\n"
           "]\n"
           "\n"
           "edge [\n"
           "fontname = \"Courier\"\n"
           "fontsize = 10\n"
           "]\n"
           "\n";
  }
};

void write_dso_graphviz(std::ostream &out, const dso_graph_t &dso_graph) {
  boost::write_graphviz(
      out, dso_graph, graphviz_label_writer(dso_graph),
      graphviz_edge_prop_writer(dso_graph), graphviz_prop_writer());
}

void handle_sigint(int no) {
  Cancel.store(true);
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
  std::string msg;

  for (const char **s = argv; *s; ++s) {
    msg.append(*s);
    msg.push_back(' ');
  }

  if (msg.empty())
    return;

  msg[msg.size() - 1] = '\n';

  llvm::errs() << msg;
  llvm::errs().flush();
}

#include "elf.hpp"

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

  const ELFF &E = *O.getELFFile();

  DynRegionInfo DynamicTable(O.getFileName());
  loadDynamicTable(&E, &O, DynamicTable);

  assert(DynamicTable.Addr);

  auto dynamic_table = [&DynamicTable](void) -> Elf_Dyn_Range {
    return DynamicTable.getAsArrayRef<Elf_Dyn>();
  };

  llvm::StringRef DynamicStringTable;
  const Elf_Shdr *SymbolVersionSection;
  std::vector<VersionMapEntry> VersionMap;
  llvm::Optional<DynRegionInfo> OptionalDynSymRegion =
      loadDynamicSymbols(&E, &O,
                         DynamicTable,
                         DynamicStringTable,
                         SymbolVersionSection,
                         VersionMap);

  std::vector<uint64_t> needed_offsets;
  struct {
    bool Found;
    uint64_t Offset;
  } SOName = {false, 0};

  for (const Elf_Dyn &Dyn : dynamic_table()) {
    if (unlikely(Dyn.d_tag == llvm::ELF::DT_NULL))
      break; /* marks end of dynamic table. */

    switch (Dyn.d_tag) {
    case llvm::ELF::DT_SONAME:
      SOName.Offset = Dyn.getVal();
      SOName.Found = true;
      break;

    case llvm::ELF::DT_NEEDED:
      uint64_t needed_offset = Dyn.getVal();

      if (opts::Verbose)
        llvm::errs() << llvm::formatv("{0}: DT_NEEDED: {1}\n", b.Path, needed_offset);

      if (needed_offset >= DynamicStringTable.size()) {
        if (opts::Verbose)
          WithColor::warning() << llvm::formatv(
              "ignoring DT_NEEDED entry; offset is {0} >= {1}\n", needed_offset,
              DynamicStringTable.size());
        break;
      }

      needed_offsets.push_back(needed_offset);
      break;
    }
  }

  if (SOName.Found) {
    if (SOName.Offset >= DynamicStringTable.size()) {
      if (opts::Verbose)
        llvm::errs() << llvm::formatv("[{0}] bad SOName.Offset {1}\n", b.Path, SOName.Offset);
    } else {
      const char *soname_cstr = DynamicStringTable.data() + SOName.Offset;

      if (opts::Verbose)
        llvm::errs() << llvm::formatv("[{0}] out.soname=\"{1}\"\n", b.Path, soname_cstr);

      out.soname = soname_cstr;
    }
  }

  for (uint64_t off : needed_offsets) {
    if (off >= DynamicStringTable.size()) {
      if (opts::Verbose)
        llvm::errs() << llvm::formatv("[{0}] bad needed_offset {1}\n", b.Path, off);
      continue;
    }

    const char *needed_cstr = DynamicStringTable.data() + off;

    if (opts::Verbose)
      llvm::errs() << llvm::formatv("[{0}] out.needed=\"{1}\"\n", b.Path, needed_cstr);

    out.needed.emplace_back(needed_cstr);
  }

  llvm::Expected<Elf_Phdr_Range> ExpectedPrgHdrs = E.program_headers();
  for (const Elf_Phdr &Phdr : *ExpectedPrgHdrs) {
    if (Phdr.p_type == llvm::ELF::PT_INTERP) {
      out.interp = std::string(Buffer.data() + Phdr.p_offset);
      break;
    }
  }

  return true;
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

unsigned num_cpus(void) {
  cpu_set_t cpu_mask;
  if (sched_getaffinity(0, sizeof(cpu_mask), &cpu_mask) < 0) {
    WithColor::error() << "sched_getaffinity failed : " << strerror(errno)
                       << '\n';
    abort();
  }

  return CPU_COUNT(&cpu_mask);
}

std::pair<tcg_uintptr_t, tcg_uintptr_t> base_of_executable(binary_t &binary) {
  //
  // parse the ELF
  //
  llvm::StringRef Buffer(reinterpret_cast<const char *>(&binary.Data[0]),
                         binary.Data.size());
  llvm::StringRef Identifier(binary.Path);
  llvm::MemoryBufferRef MemBuffRef(Buffer, Identifier);

  llvm::Expected<std::unique_ptr<obj::Binary>> BinOrErr =
      obj::createBinary(MemBuffRef);
  if (!BinOrErr) {
    WithColor::error() << "failed to create binary from " << binary.Path
                       << '\n';
    abort();
  }

  std::unique_ptr<obj::Binary> &BinRef = BinOrErr.get();

  assert(llvm::isa<ELFO>(BinRef.get()));
  ELFO &O = *llvm::cast<ELFO>(BinRef.get());

  // TheTriple = O.makeTriple();
  // Features = O.getFeatures();

  const ELFF &E = *O.getELFFile();

  tcg_uintptr_t SectsStartAddr = std::numeric_limits<tcg_uintptr_t>::max();
  tcg_uintptr_t SectsEndAddr = 0;

  llvm::Expected<Elf_Shdr_Range> ExpectedSections = E.sections();
  if (ExpectedSections && !(*ExpectedSections).empty()) {
    for (const Elf_Shdr &Sec : *ExpectedSections) {
      if (!(Sec.sh_flags & llvm::ELF::SHF_ALLOC))
        continue;

      llvm::Expected<llvm::StringRef> ExpectedName = E.getSectionName(&Sec);

      if (!ExpectedName)
        continue;

      if ((Sec.sh_flags & llvm::ELF::SHF_TLS) &&
          *ExpectedName == std::string(".tbss"))
        continue;

      if (!Sec.sh_size)
        continue;

      SectsStartAddr = std::min<tcg_uintptr_t>(SectsStartAddr, Sec.sh_addr);
      SectsEndAddr   = std::max<tcg_uintptr_t>(SectsEndAddr, Sec.sh_addr + Sec.sh_size);
    }
  } else {
    llvm::SmallVector<const Elf_Phdr *, 4> LoadSegments;

    auto ProgramHeadersOrError = E.program_headers();
    if (!ProgramHeadersOrError)
      abort();

    for (const Elf_Phdr &Phdr : *ProgramHeadersOrError) {
      if (Phdr.p_type != llvm::ELF::PT_LOAD)
        continue;

      LoadSegments.push_back(&Phdr);
    }

    assert(!LoadSegments.empty());

    std::stable_sort(LoadSegments.begin(),
                     LoadSegments.end(),
                     [](const Elf_Phdr *A,
                        const Elf_Phdr *B) {
                       return A->p_vaddr < B->p_vaddr;
                     });

    SectsStartAddr = LoadSegments.front()->p_vaddr;
    SectsEndAddr = LoadSegments.back()->p_vaddr + LoadSegments.back()->p_memsz;
  }

  return {SectsStartAddr, SectsEndAddr};
}

} // namespace jove
