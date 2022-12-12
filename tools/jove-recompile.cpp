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
    if (IsVerbose())
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

  ReadJvFromFile(opts.jv, jv);
  state.update();

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

    auto Bin = CreateBinary(b.Data);
    if (!dynamic_linking_info_of_binary(*Bin, state.for_binary(b).dynl)) {
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
    fs::path ldso_path = fs::path(temporary_dir()) / "ld.so";

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

    if (!state.for_binary(b).dynl.soname.empty()) {
      rtld_soname = state.for_binary(b).dynl.soname;

      std::string binary_filename = fs::path(b.Path).filename().string();

      if (binary_filename != state.for_binary(b).dynl.soname) {
        fs::path dst = chrooted_path.parent_path() / state.for_binary(b).dynl.soname;

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

    state.for_binary(b).dso = boost::add_vertex(dso_graph);
    dso_graph[state.for_binary(b).dso].BIdx = BIdx;
  }

  std::unordered_map<std::string, binary_index_t> soname_map;

  for (binary_index_t BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx) {
    binary_t &b = jv.Binaries[BIdx];

    if (state.for_binary(b).dynl.soname.empty() && !b.IsExecutable) {
      soname_map.insert({fs::path(b.Path).filename().string(), BIdx}); /* XXX */
      continue;
    }

    if (soname_map.find(state.for_binary(b).dynl.soname) != soname_map.end()) {
      WithColor::error() << llvm::formatv(
          "same soname {0} occurs more than once\n", state.for_binary(b).dynl.soname);
      continue;
    }

    soname_map[state.for_binary(b).dynl.soname] = BIdx;
  }

  for (binary_index_t BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx) {
    binary_t &b = jv.Binaries[BIdx];

    for (const std::string &sonm : state.for_binary(b).dynl.needed) {
      auto it = soname_map.find(sonm);
      if (it == soname_map.end()) {
        WithColor::warning() << llvm::formatv(
            "unknown soname {0} needed by {1}\n", sonm, b.Path);
        continue;
      }

      boost::add_edge(
          state.for_binary(b).dso,
          state.for_binary(jv.Binaries[(*it).second]).dso,
          dso_graph);
    }
  }

  bool haveGraphEasy = fs::exists("/usr/bin/vendor_perl/graph-easy") ||
                       fs::exists("/usr/bin/graph-easy");
  if (IsVerbose() && haveGraphEasy) {
    //
    // graphviz
    //
    std::string dso_dot_path = temporary_dir() + "/dso_graph.dot";

    {
      std::ofstream ofs(dso_dot_path);

      write_dso_graphviz(ofs, dso_graph);
    }

    //
    // graph-easy
    //
    const char *graph_easy_path = fs::exists("/usr/bin/vendor_perl/graph-easy")
                                      ? "/usr/bin/vendor_perl/graph-easy"
                                      : "/usr/bin/graph-easy";

    int rc = RunExecutableToExit(graph_easy_path, [&](auto Arg) {
      Arg(graph_easy_path);
      Arg("--input=" + dso_dot_path);
      // Arg("--as=ascii");
      Arg("--as=boxart");
    });

    if (rc)
      WithColor::warning() << llvm::formatv("graph-easy failed for {0}\n",
                                            dso_dot_path);
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

      if (IsVerbose()) {
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

  if (!IsVerbose())
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

  if (!IsVerbose())
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

    if (!state.for_binary(b).dynl.soname.empty()) {
      std::string binary_filename = fs::path(b.Path).filename().string();

      //
      // create symlink
      //
      if (binary_filename != state.for_binary(b).dynl.soname) {
        fs::path dst = chrooted_path.parent_path() / state.for_binary(b).dynl.soname;
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
    int rc = RunExecutableToExit(ld_path.c_str(), [&](auto Arg) {
      Arg(ld_path);

      Arg("-o");
      Arg(chrooted_path.string());

      Arg(objfp);

      Arg("-m");
      Arg(TargetStaticLinkerEmulation);

      Arg("-nostdlib");

      Arg("-init");
      Arg("_jove_init");

      Arg("--push-state");
      Arg("--as-needed");
      Arg(compiler_runtime_afp);
      if (fs::exists(libatomic_afp))
        Arg(libatomic_afp);
      Arg("--pop-state");
      Arg("--exclude-libs");
      Arg("ALL");

      if (b.IsExecutable) {
        if (b.IsPIC) {
          Arg("-pie");
        } else {
          // Arg("-z");
          // Arg("nocopyreloc");

          std::unique_ptr<obj::Binary> Bin = CreateBinary(b.Data);

          uint64_t Base, End;
          std::tie(Base, End) = bounds_of_binary(*Bin);

          Arg("--section-start");
          Arg((fmt(".jove=0x%lx") % Base).str());
        }
      } else {
        assert(b.IsPIC);
        Arg("-shared");
      }

#if 0
      Arg("-z");
      Arg("now");
#endif

      // XXX assuming lld
      Arg("--allow-shlib-undefined");
      if (b.IsExecutable)
        Arg("--unresolved-symbols=ignore-all");

      if (fs::exists(mapfp) && fs::is_regular_file(mapfp) &&
          fs::file_size(mapfp) > 0) {
        Arg("--version-script");
        Arg(mapfp);
      }

      if (is_function_index_valid(b.Analysis.EntryFunction)) {
        Arg("-e");
        Arg("_jove_start");
      }

      // include lib directories
#if 1
      std::unordered_set<std::string> lib_dirs({opts.Output + "/usr/lib"});
#else
      std::unordered_set<std::string> lib_dirs({jove_bin_path, "/usr/lib"});
#endif

      for (std::string &needed : state.for_binary(b).dynl.needed) {
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
        Arg("-L");
        Arg(lib_dir);
      }

      Arg("-ljove_rt");
      if (opts.DFSan)
        Arg("-lclang_rt.dfsan.jove-" TARGET_ARCH_NAME);

      const char *rtld_path = nullptr;
      if (!state.for_binary(b).dynl.interp.empty()) {
        for (binary_t &b : jv.Binaries) {
          if (b.IsDynamicLinker) {
            rtld_path = b.Path.c_str();
            break;
          }
        }
        assert(rtld_path);

        Arg("-dynamic-linker");
        Arg(rtld_path);
      }

      if (!state.for_binary(b).dynl.soname.empty())
        Arg(std::string("-soname=") + state.for_binary(b).dynl.soname);

#if 0
      if (!rtld_soname.empty()) {
        Arg("-l");
        Arg(":" + rtld_soname);
      }
#endif

      for (const std::string &needed : state.for_binary(b).dynl.needed) {
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

        Arg("-l");
        Arg(std::string(":") + needed);
      }

      if (rtld_path && fs::exists(rtld_path)) /* XXX */
        Arg(rtld_path);

      if (opts.SkipCopyRelocHack)
        Arg("--skip-copy-reloc-hack");
    });

    //
    // check exit code
    //
    if (rc) {
      WithColor::error() << llvm::formatv("ld failed for {0}; skipping {1}\n",
                                          objfp, binary_filename);
      return 1;
    }
  }

  return 0;
}

static bool pop_dso(dso_t &out);

void RecompileTool::worker(const dso_graph_t &dso_graph) {
  int rc;

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
    std::string path_to_stdout = bcfp + ".llvm.stdout.txt";
    std::string path_to_stderr = bcfp + ".llvm.stderr.txt";
    rc = RunToolToExit(
        "llvm",
        [&](auto Arg) {
          Arg("-o");
          Arg(bcfp);

          Arg("--version-script");
          Arg(mapfp);

          Arg("--binary-index");
          Arg(std::to_string(BIdx));

          Arg("-d");
          Arg(opts.jv);

          if (opts.Optimize)
            Arg("--optimize");

          if (opts.DFSan) {
            Arg("--dfsan");
            Arg("--dfsan-output-module-id=" + dfsan_modid_fp);
            Arg("--dfsan-bytecode-loc=" + bytecode_loc);
            Arg("--dfsan-no-loop-starts");
          }

          if (opts.CheckEmulatedStackReturnAddress)
            Arg("--check-emulated-stack-return-address");
          if (opts.Trace)
            Arg("--trace");
          if (opts.ForeignLibs)
            Arg("--foreign-libs");
          if (opts.DebugSjlj)
            Arg("--debug-sjlj");
          if (!opts.ABICalls)
            Arg("--abi-calls=0");
          if (opts.InlineHelpers)
            Arg("--inline-helpers");
        },
        path_to_stdout,
        path_to_stderr);

    //
    // check exit code
    //
    if (rc) {
      worker_failed.store(true);
      WithColor::error() << llvm::formatv("jove llvm failed! see {0}\n",
                                          path_to_stderr);
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
      RunExecutableToExit(llvm_dis_path.c_str(), [&](auto Arg) {
        nice(10);

        Arg(llvm_dis_path);
        Arg("-o");
        Arg(llfp);
        Arg(bcfp);
      });
    });

    //
    // run opt on bitcode to generate stripped ll
    //
    std::thread t2([&](void) -> void {
      RunExecutableToExit(opt_path.c_str(), [&](auto Arg) {
        nice(10);

        Arg(opt_path);
        Arg("-o");
        Arg(ll_strip_fp);
        Arg("-S");
        Arg("--strip-debug");
        Arg(bcfp);
      });
    });

    //
    // run llc
    //
    rc = RunExecutableToExit(llc_path.c_str(),
                             [&](auto Arg) {
      Arg(llc_path);

      Arg("-o");
      Arg(objfp);
      Arg(bcfp);

      Arg("--filetype=obj");

      Arg("--disable-simplify-libcalls");

      if (!opts.Optimize || opts.DFSan) {
        Arg("--fast-isel");
        Arg("-O0");
      }

      if (!opts.Optimize) {
        Arg("--frame-pointer=all");

#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
        Arg("--disable-mips-delay-filler"); /* make our life easier */
#endif
      }

      if (b.IsPIC) {
        Arg("--relocation-model=pic");
      } else {
        assert(b.IsExecutable);
        Arg("--relocation-model=static");
      }

#if defined(TARGET_X86_64) || defined(TARGET_I386)
      if (opts.DFSan) { /* XXX */
        Arg("--stack-alignment=16");
        Arg("--stackrealign");
      }
#endif
    });

    //
    // check exit code
    //
    if (rc) {
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
