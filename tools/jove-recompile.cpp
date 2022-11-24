#include "tool.h"
#include "elf.h"

#include <boost/algorithm/string.hpp>
#include <boost/dll/runtime_symbol_info.hpp>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include <boost/graph/filtered_graph.hpp>
#include <boost/graph/graphviz.hpp>
#include <boost/graph/strong_components.hpp>
#include <boost/graph/topological_sort.hpp>
#include <boost/range/adaptor/reversed.hpp>

#include <llvm/ADT/StringRef.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

#include <chrono>
#include <mutex>
#include <queue>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_set>

#include <fcntl.h>
#include <unistd.h>

#include "jove_macros.h"

#ifndef likely
#define likely(x)   __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

static void __warn(const char *file, int line);

namespace fs = boost::filesystem;
namespace cl = llvm::cl;
namespace obj = llvm::object;

using llvm::WithColor;

namespace jove {

struct dso_properties_t {
  unsigned BIdx;
};

typedef boost::adjacency_list<boost::setS,           /* OutEdgeList */
                              boost::vecS,           /* VertexList */
                              boost::bidirectionalS, /* Directed */
                              dso_properties_t       /* VertexProperties */>
    dso_graph_t;

typedef dso_graph_t::vertex_descriptor dso_t;


namespace {

struct binary_state_t {
  dynamic_linking_info_t dynl;
  dso_t dso;
};

}

typedef boost::format fmt;

class RecompileTool : public TransformerTool<binary_state_t> {
  struct Cmdline {
    cl::opt<std::string> jv;
    cl::alias jvAlias;
    cl::opt<std::string> Output;
    cl::alias OutputAlias;
    cl::opt<unsigned> Threads;
    cl::opt<bool> Trace;
    cl::opt<std::string> UseLd;
    cl::opt<bool> Verbose;
    cl::alias VerboseAlias;
    cl::opt<bool> DFSan;
    cl::opt<bool> Optimize;
    cl::opt<bool> SkipCopyRelocHack;
    cl::opt<bool> DebugSjlj;
    cl::opt<bool> CheckEmulatedStackReturnAddress;
    cl::opt<bool> SkipLLVM;
    cl::opt<bool> ForeignLibs;
    cl::list<std::string> PinnedGlobals;
    cl::opt<bool> ABICalls;
    cl::opt<bool> InlineHelpers;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : jv("jv", cl::desc("Jove jv"), cl::Required,
             cl::cat(JoveCategory)),

          jvAlias("d", cl::desc("Alias for -jv."), cl::aliasopt(jv),
                  cl::cat(JoveCategory)),

          Output("output", cl::desc("Output directory"), cl::Required,
                 cl::cat(JoveCategory)),

          OutputAlias("o", cl::desc("Alias for -output."), cl::aliasopt(Output),
                      cl::cat(JoveCategory)),

          Threads("num-threads",
                  cl::desc("Number of CPU threads to use (hack)"),
                  cl::init(num_cpus()), cl::cat(JoveCategory)),

          Trace(
              "trace",
              cl::desc("Instrument code to output basic block execution trace"),
              cl::cat(JoveCategory)),

          UseLd("use-ld",
                cl::desc("Force using particular linker (lld,bfd,gold)"),
                cl::cat(JoveCategory)),

          Verbose("verbose",
                  cl::desc("Print extra information for debugging purposes"),
                  cl::cat(JoveCategory)),

          VerboseAlias("v", cl::desc("Alias for -verbose."),
                       cl::aliasopt(Verbose), cl::cat(JoveCategory)),

          DFSan("dfsan", cl::desc("Run dfsan on bitcode"),
                cl::cat(JoveCategory)),

          Optimize("optimize", cl::desc("Run optimizations on bitcode"),
                   cl::cat(JoveCategory)),

          SkipCopyRelocHack(
              "skip-copy-reloc-hack",
              cl::desc("Do not insert COPY relocations in output file (HACK)"),
              cl::cat(JoveCategory)),

          DebugSjlj(
              "debug-sjlj",
              cl::desc(
                  "Before setjmp/longjmp, dump information about the call"),
              cl::cat(JoveCategory)),

          CheckEmulatedStackReturnAddress("check-emulated-stack-return-address",
                                          cl::desc("Check for stack overrun"),
                                          cl::cat(JoveCategory)),

          SkipLLVM(
              "skip-llvm",
              cl::desc(
                  "Skip running jove-llvm (careful when using this option)"),
              cl::cat(JoveCategory)),

          ForeignLibs("foreign-libs",
                      cl::desc("only recompile the executable itself; "
                               "treat all other binaries as \"foreign\""),
                      cl::cat(JoveCategory)),

          PinnedGlobals(
              "pinned-globals", cl::CommaSeparated,
              cl::value_desc("glb_1,glb_2,...,glb_n"),
              cl::desc(
                  "force specified TCG globals to always go through CPUState"),
              cl::cat(JoveCategory)),

          ABICalls("abi-calls",
                   cl::desc("Call ABIs indirectly through _jove_call"),
                   cl::cat(JoveCategory), cl::init(true)),

          InlineHelpers("inline-helpers",
                        cl::desc("Try to inline all helper function calls"),
                        cl::cat(JoveCategory)) {}
  } opts;

public:
  RecompileTool() : opts(JoveCategory) {}

  int Run(void);

  void worker(const dso_graph_t &dso_graph);

  void write_dso_graphviz(std::ostream &out, const dso_graph_t &);
};

JOVE_REGISTER_TOOL("recompile", RecompileTool);

static char tmpdir[] = {'/', 't', 'm', 'p', '/', 'X',
                        'X', 'X', 'X', 'X', 'X', '\0'};

static std::string compiler_runtime_afp, libatomic_afp, jove_bin_path,
    jove_rt_path, jove_dfsan_path, llc_path, ld_path, opt_path, llvm_dis_path;

static std::atomic<bool> Cancel(false);

static void handle_sigint(int);

static std::vector<dso_t> Q;
static std::mutex Q_mtx;

static std::atomic<bool> worker_failed(false);

struct all_edges_t {
  template <typename Edge> bool operator()(const Edge &e) const {
    return true;
  }
};

struct vert_exists_in_set_t {
  const std::unordered_set<dso_t> *vert_set;

  vert_exists_in_set_t() : vert_set(nullptr) {}
  vert_exists_in_set_t(const std::unordered_set<dso_t> &vert_set)
      : vert_set(&vert_set) {}

  bool operator()(const dso_t &v) const {
    assert(this->vert_set);

    return vert_set->find(v) != vert_set->end();
  }
};

template <typename Graph>
struct graphviz_label_writer {
  Tool &tool;
  const Graph &g;

  graphviz_label_writer(Tool &tool, const Graph &g) : tool(tool), g(g) {}

  template <typename Vertex>
  void operator()(std::ostream &out, Vertex v) const {
    std::string name =
        fs::path(tool.jv.Binaries.at(g[v].BIdx).Path).filename().string();

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

struct no_bad_edges_t {
  const dso_graph_t *g_ptr;
  const std::unordered_map<dso_t, std::unordered_set<dso_t>> *bad_edges;

  no_bad_edges_t() : g_ptr(nullptr) {}
  no_bad_edges_t(
      const dso_graph_t *g_ptr,
      const std::unordered_map<dso_t, std::unordered_set<dso_t>> *bad_edges)
      : g_ptr(g_ptr), bad_edges(bad_edges) {}

  template <typename Edge> bool operator()(const Edge &e) const {
    assert(this->bad_edges);

    const dso_graph_t &g = *g_ptr;

    auto src_it = bad_edges->find(boost::source(e, g));
    if (src_it == bad_edges->end())
      return true;

    auto target_it = (*src_it).second.find(boost::target(e, g));
    if (target_it == (*src_it).second.end())
      return true;

    return false;
  }
};

template <typename Graph>
struct graphviz_edge_prop_writer {
  const Graph &g;

  graphviz_edge_prop_writer(const Graph &g) : g(g) {}

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

int RecompileTool::Run(void) {
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

  libatomic_afp =
      (boost::dll::program_location().parent_path().parent_path().parent_path() /
       "prebuilts" / "obj" / ("libatomic-" TARGET_ARCH_NAME ".a"))
          .string();

  //
  // sanity checks for output path
  //
  if (fs::exists(opts.Output)) {
    if (opts.Verbose)
      WithColor::note() << llvm::formatv("reusing output directory {0}\n",
                                         opts.Output);
  } else {
    if (!fs::create_directory(opts.Output)) {
      WithColor::error() << "failed to create directory at \"" << opts.Output
                         << "\"\n";
      return 1;
    }
  }

  //
  // create symlink back to jv
  //
  if (fs::exists(fs::path(opts.Output) / ".jv")) // delete any stale symlinks
    fs::remove(fs::path(opts.Output) / ".jv");

  fs::create_symlink(fs::canonical(opts.jv), fs::path(opts.Output) / ".jv");

  //
  // get paths to stuff
  //
  jove_bin_path = boost::dll::program_location().parent_path().string();

  jove_rt_path =
      (boost::dll::program_location().parent_path() / "libjove_rt.so").string();
  if (!fs::exists(jove_rt_path)) {
    WithColor::error() << "could not find libjove_rt.so\n";
    return 1;
  }

  jove_dfsan_path =
      (boost::dll::program_location().parent_path().parent_path().parent_path() /
       "prebuilts" / "lib" / ("libclang_rt.dfsan.jove-" TARGET_ARCH_NAME ".so")).string();
  if (!fs::exists(jove_dfsan_path)) {
    WithColor::error() << llvm::formatv("could not find {0}\n", jove_dfsan_path);
    return 1;
  }

  llc_path = (boost::dll::program_location().parent_path().parent_path().parent_path() /
              "llvm-project" / "static_install" / "bin" / "llc").string();
  if (!fs::exists(llc_path)) {
    WithColor::error() << "could not find /usr/bin/llc\n";
    return 1;
  }

  llvm_dis_path =
      (boost::dll::program_location().parent_path().parent_path().parent_path() /
       "llvm-project" / "static_install" / "bin" / "llvm-dis")
          .string();
  if (!fs::exists(llvm_dis_path)) {
    WithColor::error() << "could not find llvm-dis\n";
    return 1;
  }

  // lld 9.0.1
  std::string lld_path =
      (boost::dll::program_location().parent_path().parent_path().parent_path() /
       "llvm-project" / "static_install" / "bin" / "ld.lld").string();

  std::string ld_gold_path = "/usr/bin/ld.gold";
  std::string ld_bfd_path = "/usr/bin/ld.bfd";

  ld_path = lld_path;

  if (!opts.UseLd.empty()) {
    if (opts.UseLd.compare("gold") == 0) {
      ld_path = ld_gold_path;
    } else if (opts.UseLd.compare("bfd") == 0) {
      ld_path = ld_bfd_path;
    } else if (opts.UseLd.compare("lld") == 0) {
      ld_path = lld_path;
    } else {
      WithColor::error() << llvm::formatv("unknown linker \"{0}\"\n", opts.UseLd);
      return 1;
    }
  }

  if (!fs::exists(ld_path)) {
    WithColor::error() << llvm::formatv("could not find linker at {0}\n",
                                        ld_path);
    return 1;
  }

  opt_path = (boost::dll::program_location().parent_path().parent_path().parent_path() /
              "llvm-project" / "static_install" / "bin" / "opt")
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

  if (opts.Verbose)
    llvm::errs() << llvm::formatv("tmpdir: {0}\n", tmpdir);

  if (!fs::exists(opts.jv)) {
    WithColor::error() << "can't find jv.jv\n";
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

    if (::sigaction(SIGINT, &sa, nullptr) < 0) {
      int err = errno;
      WithColor::error() << llvm::formatv("{0}: sigaction failed ({1})\n",
                                          __func__, strerror(err));
    }
  }

  ReadDecompilationFromFile(opts.jv, jv);

  if (Cancel) {
    WithColor::note() << "Canceled.\n";
    return 1;
  }

  //
  // gather dynamic linking information
  //
  for (binary_t &b : jv.Binaries) {
    if (b.IsVDSO)
      continue;

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

    if (!dynamic_linking_info_of_binary(*Bin, state_for_binary(b).dynl)) {
      WithColor::error() << llvm::formatv(
          "!dynamic_linking_info_of_binary({0})\n", b.Path.c_str());
      return 1;
    }
  }

  //
  // create basic directories for sysroot
  //
  {
    fs::create_directories(fs::path(opts.Output) / "proc");
    fs::create_directories(fs::path(opts.Output) / "sys");
    fs::create_directories(fs::path(opts.Output) / "dev");
    fs::create_directories(fs::path(opts.Output) / "run");
    fs::create_directories(fs::path(opts.Output) / "tmp");
    fs::create_directories(fs::path(opts.Output) / "etc");
    fs::create_directories(fs::path(opts.Output) / "usr" / "bin");
    fs::create_directories(fs::path(opts.Output) / "usr" / "lib");
    fs::create_directories(fs::path(opts.Output) / "lib"); /* XXX? */
    fs::create_directories(fs::path(opts.Output) / "var" / "run");
  }

  //
  // copy dynamic linker
  //
  std::string rtld_soname;

  for (binary_t &b : jv.Binaries) {
    if (!b.IsDynamicLinker)
      continue;

    //
    // we have the binary data in the jv. let's use it
    //
    fs::path ldso_path = fs::path(tmpdir) / "ld.so";

    fs::path chrooted_path(opts.Output + b.Path);
    fs::create_directories(chrooted_path.parent_path());

    {
      std::ofstream ofs(chrooted_path.string());

      ofs.write(reinterpret_cast<char *>(&b.Data[0]), b.Data.size());
    }

    //
    // make rtld executable (chmod)
    //
    fs::permissions(chrooted_path, fs::others_read |
                                   fs::others_exe |

                                   fs::group_read |
                                   fs::group_exe |

                                   fs::owner_read |
                                   fs::owner_write |
                                   fs::owner_exe);

    if (!state_for_binary(b).dynl.soname.empty()) {
      rtld_soname = state_for_binary(b).dynl.soname;

      std::string binary_filename = fs::path(b.Path).filename().string();

      if (binary_filename != state_for_binary(b).dynl.soname) {
        fs::path dst = chrooted_path.parent_path() / state_for_binary(b).dynl.soname;

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
    fs::path chrooted_path =
	fs::path(opts.Output) / "usr" / "lib" / "libjove_rt.so";

    fs::create_directories(chrooted_path.parent_path());
    fs::copy_file(jove_rt_path, chrooted_path,
		  fs::copy_option::overwrite_if_exists);

    //
    // /lib could just be a symlink to usr/lib, in which case we don't want
    // the following
    //
    if (!fs::equivalent(chrooted_path,
                        fs::path(opts.Output) / "lib" / "libjove_rt.so")) {
      fs::create_directories(fs::path(opts.Output) / "lib");

      try {
        // XXX some dynamic linkers only look in /lib
        fs::copy_file(jove_rt_path,
                      fs::path(opts.Output) / "lib" / "libjove_rt.so",
                      fs::copy_option::overwrite_if_exists);
      } catch (...) {
        ;
      }
    }
  }

  //
  // copy jove dfsan runtime
  //
  if (opts.DFSan) {
    const char *dfsan_rt_filename = "libclang_rt.dfsan.jove-" TARGET_ARCH_NAME ".so";

    {
      fs::path chrooted_path =
          fs::path(opts.Output) / "usr" / "lib" / dfsan_rt_filename;

      fs::copy_file(jove_dfsan_path, chrooted_path,
                    fs::copy_option::overwrite_if_exists);
    }

    if (!fs::equivalent(fs::path(opts.Output) / "usr" / "lib" / dfsan_rt_filename,
                        fs::path(opts.Output) / "lib" / dfsan_rt_filename)) {
      /* XXX some dynamic linkers only look in /lib */
      fs::path chrooted_path =
          fs::path(opts.Output) / "lib" / dfsan_rt_filename;

      fs::copy_file(jove_dfsan_path, chrooted_path,
                    fs::copy_option::overwrite_if_exists);
    }
  }

  //
  // additional stuff for DFSan
  //
  if (opts.DFSan) {
    fs::create_directories(fs::path(opts.Output) / "jove");
    fs::create_directories(fs::path(opts.Output) / "dfsan");

    {
      std::ofstream ofs(
          (fs::path(opts.Output) / "jove" / "BinaryPathsTable.txt").c_str());

      for (const binary_t &binary : jv.Binaries)
        ofs << binary.Path << '\n';
    }

    fs::create_directories(fs::path(opts.Output) / "jove" /
                           "BinaryBlockAddrTables");

    for (binary_index_t BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx) {
      binary_t &binary = jv.Binaries[BIdx];
      auto &ICFG = binary.Analysis.ICFG;

      {
        std::ofstream ofs((fs::path(opts.Output) / "jove" /
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
  for (binary_index_t BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx) {
    binary_t &b = jv.Binaries[BIdx];

    state_for_binary(b).dso = boost::add_vertex(dso_graph);
    dso_graph[state_for_binary(b).dso].BIdx = BIdx;
  }

  std::unordered_map<std::string, binary_index_t> soname_map;

  for (binary_index_t BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx) {
    binary_t &b = jv.Binaries[BIdx];

    if (state_for_binary(b).dynl.soname.empty() && !b.IsExecutable) {
      soname_map.insert({fs::path(b.Path).filename().string(), BIdx}); /* XXX */
      continue;
    }

    if (soname_map.find(state_for_binary(b).dynl.soname) != soname_map.end()) {
      WithColor::error() << llvm::formatv(
          "same soname {0} occurs more than once\n", state_for_binary(b).dynl.soname);
      continue;
    }

    soname_map.insert({state_for_binary(b).dynl.soname, BIdx});
  }

  for (binary_index_t BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx) {
    binary_t &b = jv.Binaries[BIdx];

    for (const std::string &sonm : state_for_binary(b).dynl.needed) {
      auto it = soname_map.find(sonm);
      if (it == soname_map.end()) {
        WithColor::warning() << llvm::formatv(
            "unknown soname {0} needed by {1}\n", sonm, b.Path);
        continue;
      }

      boost::add_edge(
          state_for_binary(b).dso,
          state_for_binary(jv.Binaries[(*it).second]).dso,
          dso_graph);
    }
  }

  bool haveGraphEasy = fs::exists("/usr/bin/vendor_perl/graph-easy") ||
                       fs::exists("/usr/bin/graph-easy");
  if (opts.Verbose && haveGraphEasy) {
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

    pid_t pid = ::fork();
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

      ::close(STDIN_FILENO);
      ::execve(arg_arr[0], const_cast<char **>(&arg_arr[0]), ::environ);

      int err = errno;
      WithColor::error() << llvm::formatv("execve failed: {0}\n",
                                          strerror(err));
      return 1;
    }

    //
    // check exit code
    //
    if (WaitForProcessToExit(pid))
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
    std::map<dso_t, dso_graph_t::vertices_size_type> vert_comps;

    //
    // compute strongly-connected components
    //
    {
      std::map<dso_t, int> tm_map;
      std::map<dso_t, dso_t> rt_map;
      std::map<dso_t, boost::default_color_type> clr_map;
      std::map<dso_t, int> idx_map;

      boost::strong_components(
          dso_graph,
          boost::associative_property_map<
              std::map<dso_t, dso_graph_t::vertices_size_type>>(vert_comps),
          boost::root_map(boost::associative_property_map<std::map<dso_t, dso_t>>(rt_map))
                .discover_time_map(boost::associative_property_map<std::map<dso_t, int>>(tm_map))
                .color_map(boost::associative_property_map<std::map<dso_t, boost::default_color_type>>(clr_map))
                .vertex_index_map(boost::associative_property_map<std::map<dso_t, int>>(idx_map)));
    }

    std::map<dso_graph_t::vertices_size_type, std::unordered_set<dso_t>> comp_verts_map;
    for (const auto &el : vert_comps)
      comp_verts_map[el.second].insert(el.first);

    std::unordered_map<dso_t, std::unordered_set<dso_t>> bad_edges;

    //
    // examine edges in strongly-connected components
    //
    for (const auto &comp_verts : comp_verts_map) {
      if (comp_verts.second.size() == 1)
        continue;

      vert_exists_in_set_t vertex_filter(comp_verts.second);
      all_edges_t edge_filter;

      boost::filtered_graph<dso_graph_t, all_edges_t, vert_exists_in_set_t> fg(
          dso_graph, edge_filter, vertex_filter);

      if (opts.Verbose) {
        //
        // write graphviz file
        //
        std::string dotfp = std::string("/tmp/jove-recompile.scc.") +
                            std::to_string(comp_verts.first) + ".dot";
        std::ofstream out(dotfp);

        WithColor::note() << llvm::formatv(
            "writing scc of size {0} vertices ({1})\n",
            comp_verts.second.size(), dotfp);

        boost::write_graphviz(
            out, fg,
            graphviz_label_writer(*this, fg),
            graphviz_edge_prop_writer(fg),
            graphviz_prop_writer());
      }

      //
      // add to bad_edges
      //
      {
        auto eit_pair = boost::edges(fg);
        for (auto eit = eit_pair.first; eit != eit_pair.second; ++eit)
          bad_edges[boost::source(*eit, fg)].insert(boost::target(*eit, fg));
      }
    }

    //
    // try to topologically sort again, without offending edges
    //
    try {
      top_sorted.clear();

      no_bad_edges_t _edge_filter(&dso_graph, &bad_edges);
      boost::filtered_graph<dso_graph_t, no_bad_edges_t> _fg(dso_graph, _edge_filter);

      std::map<dso_t, boost::default_color_type> clr_map;

      boost::topological_sort(
          _fg, std::back_inserter(top_sorted),
          boost::color_map(
              boost::associative_property_map<
                  std::map<dso_t, boost::default_color_type>>(clr_map)));
    } catch (const boost::not_a_dag &) {
      WithColor::error() << "dynamic linking graph is not a DAG.\n";

      return 1;
    }
  }

  Q.reserve(top_sorted.size());
  for (dso_t dso : boost::adaptors::reverse(top_sorted)) {
    binary_index_t BIdx = dso_graph[dso].BIdx;
    if (opts.ForeignLibs && !jv.Binaries[BIdx].IsExecutable)
      continue;

    Q.push_back(dso);
  }

  if (!opts.Verbose)
    WithColor::note() << llvm::formatv(
        "Recompiling {0} {1}...",
        (opts.ForeignLibs ? 3 : jv.Binaries.size()) - 2,
        opts.ForeignLibs ? "binary" : "binaries");

  auto t1 = std::chrono::high_resolution_clock::now();

  //
  // run jove-llvm and llc on all DSOs
  //
  {
    std::vector<std::thread> workers;

    unsigned N = opts.Threads;

    workers.reserve(N);
    for (unsigned i = 0; i < N; ++i)
      workers.push_back(std::thread(&RecompileTool::worker, this, std::cref(dso_graph)));

    for (std::thread &t : workers)
      t.join();
  }

  auto t2 = std::chrono::high_resolution_clock::now();

  if (worker_failed.load())
    return 1;

  std::chrono::duration<double> s_double = t2 - t1;

  if (!opts.Verbose)
    llvm::errs() << llvm::formatv(" {0} s\n", s_double.count());

  //
  // to handle shared libraries needing each other (i.e. a cyclic dependency),
  // we copy the original binary data for each DSO before we run the static
  // linker to produce each recompiled DSO, this solves "unable to find library"
  // errors XXX
  //
  for (dso_t dso : top_sorted) {
    binary_index_t BIdx = dso_graph[dso].BIdx;

    binary_t &b = jv.Binaries.at(BIdx);

    // make sure the path is absolute
    assert(b.Path.at(0) == '/');

    const fs::path chrooted_path = fs::path(opts.Output) / b.Path;
    fs::create_directories(chrooted_path.parent_path());

    fs::remove(chrooted_path);

    {
      std::ofstream ofs(chrooted_path.c_str());

      ofs.write(&b.Data[0], b.Data.size());
    }

    fs::permissions(chrooted_path, fs::others_read |
                                   fs::others_exe |

                                   fs::group_read |
                                   fs::group_exe |

                                   fs::owner_read |
                                   fs::owner_write |
                                   fs::owner_exe);

    if (!state_for_binary(b).dynl.soname.empty()) {
      std::string binary_filename = fs::path(b.Path).filename().string();

      //
      // create symlink
      //
      if (binary_filename != state_for_binary(b).dynl.soname) {
        fs::path dst = chrooted_path.parent_path() / state_for_binary(b).dynl.soname;
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
  }

  //
  // run ld on all the object files
  //
  for (dso_t dso : top_sorted) {
    binary_index_t BIdx = dso_graph[dso].BIdx;

    binary_t &b = jv.Binaries.at(BIdx);

    if (b.IsDynamicLinker)
      continue;
    if (b.IsVDSO)
      continue;

    pid_t pid;

    // make sure the path is absolute
    assert(b.Path.at(0) == '/');

    const fs::path chrooted_path = fs::path(opts.Output) / b.Path;

    std::string binary_filename = fs::path(b.Path).filename().string();

    std::string objfp(chrooted_path.string() + ".o");
    std::string mapfp(chrooted_path.string() + ".map");

    if (opts.ForeignLibs && !b.IsExecutable)
      continue;

    if (!fs::exists(objfp)) {
      WithColor::warning() << llvm::formatv("{0} doesn't exist; skipping {1}\n",
                                            objfp, binary_filename);
      return 1;
    }

    fs::remove(chrooted_path);

    //
    // run ld
    //
    pid = ::fork();
    if (!pid) {
      IgnoreCtrlC();

      std::vector<const char *> arg_vec = {
          ld_path.c_str(),

          "-o", chrooted_path.c_str(),
          objfp.c_str(),

          "-m", TargetStaticLinkerEmulation,

          "-nostdlib",

          "-init", "_jove_init"
      };

      arg_vec.push_back("--push-state");
      arg_vec.push_back("--as-needed");
      arg_vec.push_back(compiler_runtime_afp.c_str());
      if (fs::exists(libatomic_afp))
        arg_vec.push_back(libatomic_afp.c_str());
      arg_vec.push_back("--pop-state");
      arg_vec.push_back("--exclude-libs");
      arg_vec.push_back("ALL");

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

          llvm::Expected<std::unique_ptr<obj::Binary>> BinOrErr =
              obj::createBinary(llvm::MemoryBufferRef(
                  llvm::StringRef(reinterpret_cast<const char *>(&b.Data[0]),
                                  b.Data.size()),
                  b.Path));
          if (!BinOrErr) {
            WithColor::error() << "failed to parse binary " << b.Path << '\n';
            return 1;
          }

          std::unique_ptr<obj::Binary> &BinRef = BinOrErr.get();

          uint64_t Base, End;
          std::tie(Base, End) = bounds_of_binary(*BinRef);

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
      std::unordered_set<std::string> lib_dirs({opts.Output + "/usr/lib"});
#else
      std::unordered_set<std::string> lib_dirs({jove_bin_path, "/usr/lib"});
#endif

      for (std::string &needed : state_for_binary(b).dynl.needed) {
        auto it = soname_map.find(needed);
        if (it == soname_map.end()) {
          WithColor::warning()
              << llvm::formatv("no entry in soname_map for {0}\n", needed);
          continue;
        }

        binary_t &needed_b = jv.Binaries.at((*it).second);
#if 1
        const fs::path needed_chrooted_path(opts.Output + needed_b.Path);
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
      if (opts.DFSan)
        arg_vec.push_back("-lclang_rt.dfsan.jove-" TARGET_ARCH_NAME);

      const char *rtld_path = nullptr;
      if (!state_for_binary(b).dynl.interp.empty()) {
        for (binary_t &b : jv.Binaries) {
          if (b.IsDynamicLinker) {
            rtld_path = b.Path.c_str();
            break;
          }
        }
        assert(rtld_path);

        arg_vec.push_back("-dynamic-linker");
        arg_vec.push_back(rtld_path);
      }

      std::string soname_arg = std::string("-soname=") + state_for_binary(b).dynl.soname;

      if (!state_for_binary(b).dynl.soname.empty())
        arg_vec.push_back(soname_arg.c_str());

#if 0
      std::string rtld_soname_arg = ":" + rtld_soname;
      if (!rtld_soname.empty()) {
        arg_vec.push_back("-l");
        arg_vec.push_back(rtld_soname_arg.c_str());
      }
#endif

      std::vector<std::string> needed_arg_vec;

      for (const std::string &needed : state_for_binary(b).dynl.needed) {
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

      if (opts.SkipCopyRelocHack)
        arg_vec.push_back("--skip-copy-reloc-hack");

      arg_vec.push_back(nullptr);

      if (opts.Verbose)
        print_command(&arg_vec[0]);

      ::close(STDIN_FILENO);
      ::execve(arg_vec[0], const_cast<char **>(&arg_vec[0]), ::environ);

      int err = errno;
      WithColor::error() << llvm::formatv("execve failed: {0}\n",
                                          strerror(err));
      return 1;
    }

    //
    // check exit code
    //
    if (int ret = WaitForProcessToExit(pid)) {
      WithColor::error() << llvm::formatv("ld failed for {0}; skipping {1}\n",
                                          objfp, binary_filename);
      return 1;
    }
  }

  return 0;
}

static bool pop_dso(dso_t &out);

void RecompileTool::worker(const dso_graph_t &dso_graph) {
  dso_t dso;
  while (pop_dso(dso)) {
    binary_index_t BIdx = dso_graph[dso].BIdx;

    binary_t &b = jv.Binaries.at(BIdx);

    if (b.IsDynamicLinker)
      continue;
    if (b.IsVDSO)
      continue;

    // make sure the path is absolute
    assert(b.Path.at(0) == '/');

    const fs::path chrooted_path = fs::path(opts.Output) / b.Path;
    fs::create_directories(chrooted_path.parent_path());

    std::string binary_filename = fs::path(b.Path).filename().string();

    std::string bcfp(chrooted_path.string() + ".bc");
    std::string llfp(chrooted_path.string() + ".ll");
    std::string ll_strip_fp(chrooted_path.string() + ".strip.ll");
    std::string objfp(chrooted_path.string() + ".o");
    std::string mapfp(chrooted_path.string() + ".map");
    std::string dfsan_modid_fp(chrooted_path.string() + ".modid");

    std::string bytecode_loc = (fs::path(opts.Output) / "dfsan").string();

    //
    // run jove-llvm
    //
    pid_t pid = ::fork();
    if (!pid) {
      IgnoreCtrlC();

      std::string BIdx_arg(std::to_string(BIdx));

      std::vector<const char *> arg_vec = {
        "-o", bcfp.c_str(),
        "--version-script", mapfp.c_str(),

        "--binary-index", BIdx_arg.c_str(),

        "-d", opts.jv.c_str(),
      };

      if (opts.Optimize)
        arg_vec.push_back("--optimize");

      std::string output_module_id_file_arg =
          "--dfsan-output-module-id=" + dfsan_modid_fp;

      std::string dfsan_bytecode_loc_arg =
          "--dfsan-bytecode-loc=" + bytecode_loc;

      if (opts.DFSan) {
        arg_vec.push_back("--dfsan");
        arg_vec.push_back(output_module_id_file_arg.c_str());
        arg_vec.push_back(dfsan_bytecode_loc_arg.c_str());
        arg_vec.push_back("--dfsan-no-loop-starts");
      }

      if (opts.CheckEmulatedStackReturnAddress)
        arg_vec.push_back("--check-emulated-stack-return-address");
      if (opts.Trace)
        arg_vec.push_back("--trace");
      if (opts.ForeignLibs)
        arg_vec.push_back("--foreign-libs");
      if (opts.DebugSjlj)
        arg_vec.push_back("--debug-sjlj");
      if (!opts.ABICalls)
        arg_vec.push_back("--abi-calls=0");
      if (opts.InlineHelpers)
        arg_vec.push_back("--inline-helpers");

      std::string pinned_globals_arg;
      if (!opts.PinnedGlobals.empty()) {
        pinned_globals_arg = "--pinned-globals=";
        for (const std::string &PinnedGlbStr : opts.PinnedGlobals) {
          pinned_globals_arg.append(PinnedGlbStr);
          pinned_globals_arg.push_back(',');
        }
        pinned_globals_arg.resize(pinned_globals_arg.size() - 1);

        arg_vec.push_back(pinned_globals_arg.c_str());
      }

      if (opts.Verbose)
        print_tool_command("llvm", arg_vec);

      {
        std::string stdoutfp = bcfp + ".stdout.txt";
        int stdoutfd = ::open(stdoutfp.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0666);
        ::dup2(stdoutfd, STDOUT_FILENO);
        ::close(stdoutfd);
      }

      {
        std::string stderrfp = bcfp + ".stderr.txt";
        int stderrfd = ::open(stderrfp.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0666);
        ::dup2(stderrfd, STDERR_FILENO);
        ::close(stderrfd);
      }

      ::close(STDIN_FILENO);
      exec_tool("llvm", arg_vec);

      int err = errno;
      WithColor::error() << llvm::formatv("execve failed: {0}\n",
                                          strerror(err));
      exit(1);
    }

    //
    // check exit code
    //
    if (int ret = WaitForProcessToExit(pid)) {
      worker_failed.store(true);
      WithColor::error() << llvm::formatv("jove-llvm failed on {0}: see {1}\n",
                                          binary_filename,
                                          bcfp + ".stderr.txt");
      continue;
    }

    if (opts.DFSan) {
      std::ifstream ifs(dfsan_modid_fp);
      std::string dfsan_modid((std::istreambuf_iterator<char>(ifs)),
                              std::istreambuf_iterator<char>());

      WithColor::note() << llvm::formatv("ModuleID for {0} is {1}\n", bcfp,
                                         dfsan_modid);

      fs::copy_file(bcfp, opts.Output + "/dfsan/" + dfsan_modid,
                    fs::copy_option::overwrite_if_exists);
    }

    //
    // run llvm-dis on bitcode
    //
    std::thread t1([&](void) -> void {
      pid_t pid = ::fork();
      if (!pid) {
        IgnoreCtrlC();
        nice(10);

        const char *arg_arr[] = {
          llvm_dis_path.c_str(),

          "-o", llfp.c_str(),
          bcfp.c_str(),

          nullptr
        };

        if (opts.Verbose)
          print_command(&arg_arr[0]);

        ::close(STDIN_FILENO);
        ::execve(arg_arr[0], const_cast<char **>(&arg_arr[0]), ::environ);

        int err = errno;
        WithColor::error() << llvm::formatv("execve failed: {0}\n",
                                            strerror(err));
        exit(1);
      }

      (void)WaitForProcessToExit(pid);
    });

    //
    // run opt on bitcode to generate stripped ll
    //
    std::thread t2([&](void) -> void {
      pid_t pid = ::fork();
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

        if (opts.Verbose)
          print_command(&arg_arr[0]);

        ::close(STDIN_FILENO);
        ::execve(arg_arr[0], const_cast<char **>(&arg_arr[0]), ::environ);

        int err = errno;
        WithColor::error() << llvm::formatv("execve failed: {0}\n",
                                            strerror(err));
        exit(1);
      }

      (void)WaitForProcessToExit(pid);
    });

    //
    // run llc
    //
    pid = ::fork();
    if (!pid) {
      IgnoreCtrlC();

      std::vector<const char *> arg_vec = {
        llc_path.c_str(),

        "-o", objfp.c_str(),
        bcfp.c_str(),

        "--filetype=obj",

        "--disable-simplify-libcalls",
      };

      if (!opts.Optimize || opts.DFSan) {
        arg_vec.push_back("--fast-isel");
        arg_vec.push_back("-O0");
      }

      if (!opts.Optimize) {
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
      if (opts.DFSan) { /* XXX */
        arg_vec.push_back("--stack-alignment=16");
        arg_vec.push_back("--stackrealign");
      }
#endif

      arg_vec.push_back(nullptr);

      if (opts.Verbose)
        print_command(&arg_vec[0]);

      ::close(STDIN_FILENO);
      ::execve(arg_vec[0], const_cast<char **>(&arg_vec[0]), ::environ);

      int err = errno;
      WithColor::error() << llvm::formatv("execve failed: {0}\n",
                                          strerror(err));
      exit(1);
    }

    //
    // check exit code
    //
    if (int ret = WaitForProcessToExit(pid)) {
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

void RecompileTool::write_dso_graphviz(std::ostream &out,
                                       const dso_graph_t &dso_graph) {
  boost::write_graphviz(
      out, dso_graph, graphviz_label_writer(*this, dso_graph),
      graphviz_edge_prop_writer(dso_graph), graphviz_prop_writer());
}

void handle_sigint(int no) {
  Cancel.store(true);
}

}
