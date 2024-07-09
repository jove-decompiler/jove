#include "tool.h"
#include "B.h"
#include "triple.h"

#include <boost/algorithm/string.hpp>
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
#include <execution>
#include <queue>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_set>
#include <filesystem>

#include <fcntl.h>
#include <unistd.h>

#include "jove_macros.h"

static void __warn(const char *file, int line);

namespace fs = std::filesystem;
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
  std::unique_ptr<llvm::object::Binary> Bin;

  uint64_t Base = 0, End = 0;

  struct {
    std::optional<std::string> interp;
  } _elf;

  std::vector<std::string> needed_vec;
  std::string soname;
  dso_t dso;
};

}

typedef boost::format fmt;

class RecompileTool : public StatefulJVTool<ToolKind::Standard, binary_state_t, void, void> {
  struct Cmdline {
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
    cl::alias ForeignLibsAlias;
    cl::list<std::string> PinnedGlobals;
    cl::opt<bool> ABICalls;
    cl::opt<bool> InlineHelpers;
    cl::opt<bool> MT;
    cl::opt<bool> BreakBeforeUnreachables;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Output("output", cl::desc("Output directory"), cl::Required,
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
                      cl::cat(JoveCategory), cl::init(true)),

          ForeignLibsAlias("x", cl::desc("Exe only. Alias for --foreign-libs."),
                           cl::aliasopt(ForeignLibs), cl::cat(JoveCategory)),

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
                        cl::cat(JoveCategory)),

          MT("mt", cl::desc("Thread model (multi)"), cl::cat(JoveCategory),
             cl::init(true)),

          BreakBeforeUnreachables("break-before-unreachables",
                                  cl::desc("Debugging purposes only"),
                                  cl::cat(JoveCategory)) {}
  } opts;

  bool IsCOFF = false;

  inline fs::path a2r(const std::string &ap) {
    return fs::relative(ap, "/");
  }

public:
  RecompileTool() : opts(JoveCategory) {}

  int Run(void) override;

  void worker(dso_t);

  void write_dso_graphviz(std::ostream &out, const dso_graph_t &);

  dso_graph_t dso_graph;

  std::atomic<bool> worker_failed = false;
};

JOVE_REGISTER_TOOL("recompile", RecompileTool);

static std::atomic<bool> Cancel(false);

static void handle_sigint(int);

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
  JVTool<ToolKind::Standard> &tool;
  const Graph &g;

  graphviz_label_writer(JVTool<ToolKind::Standard> &tool, const Graph &g) : tool(tool), g(g) {}

  template <typename Vertex>
  void operator()(std::ostream &out, Vertex v) const {
    binary_t &b = tool.jv.Binaries.at(g[v].BIdx);

    std::string name;
    if (b.is_file())
      name = fs::path(b.path()).filename().string();
    else
      name = b.Name;

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
  //
  // sanity checks for output path
  //
  if (fs::exists(fs::path(opts.Output.getValue()))) {
    if (IsVerbose())
      WithColor::note() << llvm::formatv("reusing output directory {0}\n",
                                         opts.Output);
  } else {
    if (!fs::create_directory(opts.Output.getValue())) {
      WithColor::error() << "failed to create directory at \"" << opts.Output
                         << "\"\n";
      return 1;
    }
  }

  //
  // create symlink back to jv
  //
  if (fs::exists(fs::path(opts.Output.getValue()) / ".jv")) // delete any stale symlinks
    fs::remove(fs::path(opts.Output.getValue()) / ".jv");

  fs::create_symlink(fs::canonical(path_to_jv()), fs::path(opts.Output.getValue()) / ".jv");

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

  if (Cancel) {
    WithColor::note() << "Canceled.\n";
    return 1;
  }

  for (binary_t &b : jv.Binaries) {
    binary_state_t &x = state.for_binary(b);
    x.Bin = B::Create(b.data());

    std::tie(x.Base, x.End) = B::bounds_of_binary(*x.Bin);
  }

  if (B::is_coff(*state.for_binary(jv.Binaries.at(0)).Bin)) {
    if (!opts.ForeignLibs)
      die("COFF is only supported in executable-only mode");

    IsCOFF = true;
  }

  //
  // gather dynamic linking information
  //
  for_each_binary(std::execution::par_unseq, jv, [&](binary_t &b) {
    if (b.IsVDSO)
      return;

    binary_state_t &x = state.for_binary(b);

    //
    // what is this binary called as far as dynamic linking goes?
    //
    B::_elf(*x.Bin, [&](ELFO &O) {
      x._elf.interp = elf::program_interpreter_of_elf(O);
      if (auto MaybeSoName = elf::soname_of_elf(O))
        x.soname = *MaybeSoName;
    });

    if (x.soname.empty() && b.is_file() && !b.IsExecutable) {
      //
      // if we don't have one, make an "soname" from the filename of the binary
      //
      x.soname = fs::path(b.path_str()).filename().string();
    }

    //
    // what does this binary need?
    //
    if (!B::needed_libs(*x.Bin, x.needed_vec))
      WithColor::warning() << llvm::formatv(
          "failed to get libraries needed by {0}\n", b.Name.c_str());
  });

  //
  // create basic directories for sysroot
  //
  {
    fs::create_directories(fs::path(opts.Output.getValue()) / "proc");
    fs::create_directories(fs::path(opts.Output.getValue()) / "sys");
    fs::create_directories(fs::path(opts.Output.getValue()) / "dev");
    fs::create_directories(fs::path(opts.Output.getValue()) / "run");
    fs::create_directories(fs::path(opts.Output.getValue()) / "tmp");
    fs::create_directories(fs::path(opts.Output.getValue()) / "etc");
    fs::create_directories(fs::path(opts.Output.getValue()) / "usr" / "bin");
    fs::create_directories(fs::path(opts.Output.getValue()) / "usr" / "lib");
    fs::create_directories(fs::path(opts.Output.getValue()) / "lib"); /* XXX? */
    fs::create_directories(fs::path(opts.Output.getValue()) / "var" / "run");
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

    fs::path chrooted_path(opts.Output + b.path_str());
    fs::create_directories(chrooted_path.parent_path());

    {
      std::ofstream ofs(chrooted_path.string());

      ofs.write(reinterpret_cast<char *>(&b.Data[0]), b.Data.size());
    }

    //
    // make rtld executable (chmod)
    //
    fs::permissions(chrooted_path, fs::perms::others_read |
                                   fs::perms::others_exec |

                                   fs::perms::group_read |
                                   fs::perms::group_exec |

                                   fs::perms::owner_read |
                                   fs::perms::owner_write |
                                   fs::perms::owner_exec);

    if (!state.for_binary(b).soname.empty()) {
      rtld_soname = state.for_binary(b).soname;

      std::string binary_filename = fs::path(b.path_str()).filename().string();

      if (binary_filename != state.for_binary(b).soname) {
        fs::path dst = chrooted_path.parent_path() / state.for_binary(b).soname;

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
  if (IsCOFF) {
    fs::path chrooted_path =
        fs::path(opts.Output.getValue()) / "usr" / "lib" / "libjove_rt.dll";

    fs::create_directories(chrooted_path.parent_path());
    fs::copy_file(locator().runtime_dll(opts.MT), chrooted_path,
                  fs::copy_options::overwrite_existing);
  }
  else
  {
    fs::path chrooted_path =
        fs::path(opts.Output.getValue()) / "usr" / "lib" / "libjove_rt.so";

    fs::create_directories(chrooted_path.parent_path());
    fs::copy_file(locator().runtime_so(opts.MT), chrooted_path,
                  fs::copy_options::overwrite_existing);

    //
    // /lib could just be a symlink to usr/lib, in which case we don't want
    // the following
    //
    if (!fs::equivalent(chrooted_path,
                        fs::path(opts.Output.getValue()) / "lib" / "libjove_rt.so")) {
      fs::create_directories(fs::path(opts.Output.getValue()) / "lib");

      try {
        // XXX some dynamic linkers only look in /lib
        fs::copy_file(locator().runtime_so(opts.MT),
                      fs::path(opts.Output.getValue()) / "lib" / "libjove_rt.so",
                      fs::copy_options::overwrite_existing);
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
          fs::path(opts.Output.getValue()) / "usr" / "lib" / dfsan_rt_filename;

      fs::copy_file(locator().dfsan_runtime(), chrooted_path,
                    fs::copy_options::overwrite_existing);
    }

    if (!fs::equivalent(fs::path(opts.Output.getValue()) / "usr" / "lib" / dfsan_rt_filename,
                        fs::path(opts.Output.getValue()) / "lib" / dfsan_rt_filename)) {
      /* XXX some dynamic linkers only look in /lib */
      fs::path chrooted_path =
          fs::path(opts.Output.getValue()) / "lib" / dfsan_rt_filename;

      fs::copy_file(locator().dfsan_runtime(), chrooted_path,
                    fs::copy_options::overwrite_existing);
    }
  }

  //
  // additional stuff for DFSan
  //
  if (opts.DFSan) {
    fs::create_directories(fs::path(opts.Output.getValue()) / "jove");
    fs::create_directories(fs::path(opts.Output.getValue()) / "dfsan");

    {
      std::ofstream ofs(
          (fs::path(opts.Output.getValue()) / "jove" / "BinaryPathsTable.txt").c_str());

      for (const binary_t &binary : jv.Binaries)
        ofs << binary.path_str() << '\n';
    }

    fs::create_directories(fs::path(opts.Output.getValue()) / "jove" /
                           "BinaryBlockAddrTables");

    for (binary_index_t BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx) {
      binary_t &binary = jv.Binaries.at(BIdx);
      auto &ICFG = binary.Analysis.ICFG;

      {
        std::ofstream ofs((fs::path(opts.Output.getValue()) / "jove" /
                           "BinaryBlockAddrTables" / std::to_string(BIdx))
                              .c_str());

        for (basic_block_index_t BBIdx = 0; BBIdx < boost::num_vertices(ICFG);
             ++BBIdx) {
          basic_block_t bb = basic_block_of_index(BBIdx, ICFG);
          uint64_t Addr = ICFG[bb].Term.Addr; /* XXX */
          ofs.write(reinterpret_cast<char *>(&Addr), sizeof(Addr));
        }
      }
    }
  }

  //
  // create mapping from "soname" to binary
  //
  std::unordered_map<std::string, binary_index_t> soname_map;
  for_each_binary(jv, [&](binary_t &b) {
    binary_state_t &x = state.for_binary(b);

    const std::string &soname = x.soname;
    if (soname.empty())
      return;

    bool success = soname_map.emplace(soname, index_of_binary(b, jv)).second;
    if (!success)
      die("same soname \"" + soname + "\" occurs more than once");
  });

  //
  // initialize dynamic linking graph
  //
  for_each_binary(jv, [&](binary_t &b) {
    binary_state_t &x = state.for_binary(b);
    binary_index_t BIdx = index_of_binary(b, jv);

    x.dso = boost::add_vertex(dso_graph);
    dso_graph[x.dso].BIdx = BIdx;
  });

  //
  // build dynamic linking graph
  //
  for_each_binary(jv, [&](binary_t &b) {
    if (!b.is_file())
      return;

    binary_state_t &x = state.for_binary(b);

    for (const std::string &needed : x.needed_vec) {
      auto it = soname_map.find(needed);
      if (it == soname_map.end()) {
        WithColor::warning() << llvm::formatv("unknown \"{0}\" needed by {1}\n",
                                              needed, b.path_str());
        return;
      }

      binary_t &needed_b = jv.Binaries.at((*it).second);
      binary_state_t &y = state.for_binary(needed_b);

      boost::add_edge(x.dso, y.dso, dso_graph);
    }
  });

  if (IsVeryVerbose() && fs::exists(locator().graph_easy())) {
    //
    // graphviz
    //
    std::string dso_dot_path = temporary_dir() + "/dso_graph.dot";

    {
      std::ofstream ofs(dso_dot_path);

      write_dso_graphviz(ofs, dso_graph);
    }

    int rc = RunExecutableToExit(locator().graph_easy(), [&](auto Arg) {
      Arg(locator().graph_easy());
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

  std::vector<dso_t> Q;

  Q.reserve(top_sorted.size());
  for (dso_t dso : boost::adaptors::reverse(top_sorted)) {
    binary_index_t BIdx = dso_graph[dso].BIdx;
    if (opts.ForeignLibs && !jv.Binaries.at(BIdx).IsExecutable)
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
  std::for_each(
    std::execution::par_unseq,
    Q.begin(),
    Q.end(),
    std::bind(&RecompileTool::worker, this, std::placeholders::_1));

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

    if (!b.is_file())
      continue;

    const fs::path chrooted_path = fs::path(opts.Output.getValue()) / a2r(b.path_str());
    fs::create_directories(chrooted_path.parent_path());

    fs::remove(chrooted_path);

    {
      std::ofstream ofs(chrooted_path.c_str());

      ofs.write(&b.Data[0], b.Data.size());
    }

    fs::permissions(chrooted_path, fs::perms::others_read |
                                   fs::perms::others_exec |

                                   fs::perms::group_read |
                                   fs::perms::group_exec |

                                   fs::perms::owner_read |
                                   fs::perms::owner_write |
                                   fs::perms::owner_exec);

    if (!state.for_binary(b).soname.empty()) {
      std::string binary_filename = fs::path(b.path_str()).filename().string();

      //
      // create symlink
      //
      if (binary_filename != state.for_binary(b).soname) {
        fs::path dst = chrooted_path.parent_path() / state.for_binary(b).soname;
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

    assert(b.is_file());

    binary_state_t &x = state.for_binary(b);

    const fs::path chrooted_path = fs::path(opts.Output.getValue()) / a2r(b.path_str());

    std::string binary_filename = fs::path(b.path_str()).filename().string();

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

#if 1
    std::unordered_set<std::string> lib_dirs({opts.Output + "/usr/lib"});
#else
    std::unordered_set<std::string> lib_dirs({jove_bin_path, "/usr/lib"});
#endif

    for (const std::string &needed : x.needed_vec) {
      auto it = soname_map.find(needed);
      if (it == soname_map.end()) {
        WithColor::warning()
            << llvm::formatv("no entry in soname_map for {0}\n", needed);
        continue;
      }

      binary_t &needed_b = jv.Binaries.at((*it).second);

#if 1
      const fs::path needed_chrooted_path(opts.Output + needed_b.path_str());
      lib_dirs.insert(needed_chrooted_path.parent_path().string());
#else
      const fs::path needed_path(needed_b.path_str());
      lib_dirs.insert(needed_path.parent_path().string());
#endif
    }

    //
    // run ld
    //
    auto linker_args = [&](auto Arg) {
      Arg("-o");
      Arg(chrooted_path.string());

      Arg(objfp);

      Arg("-m");
      Arg(TargetStaticLinkerEmulation(IsCOFF));

      if (!IsCOFF) {
      Arg("-nostdlib");

      Arg("-init");
      Arg("_jove_init");

      Arg("--push-state");
      }
      Arg("--as-needed");
      Arg(locator().builtins());
      Arg(locator().softfloat_bitcode(IsCOFF));
      if (fs::exists(locator().atomics()))
        Arg(locator().atomics());
      if (!IsCOFF) {
      Arg("--pop-state");
      Arg("--exclude-libs");
      Arg("ALL");
      }

      if (!IsCOFF) {
      if (b.IsExecutable) {
        if (b.IsPIC) {
          Arg("-pie");
        } else {
          Arg("-no-pie");

          // Arg("-z");
          // Arg("nocopyreloc");

          std::unique_ptr<obj::Binary> Bin = B::Create(b.data());

          uint64_t Base, End;
          std::tie(Base, End) = B::bounds_of_binary(*Bin);

          Arg("--section-start");
          Arg((fmt(".jove=0x%lx") % Base).str());
        }
      } else {
        assert(b.IsPIC);
        Arg("-shared");
      }

#if 1
      Arg("-z");
      Arg("now");
#endif

      Arg("-z");
      Arg("relro");

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
      }

      // include lib directories
      for (const std::string &lib_dir : lib_dirs) {
        Arg("-L");
        Arg(lib_dir);
      }

      //Arg("-ljove_rt" + std::string(opts.MT ? ".m" : ".s") + "t");
      Arg("-ljove_rt");
      if (opts.DFSan)
        Arg("-lclang_rt.dfsan.jove-" TARGET_ARCH_NAME);

      const char *rtld_path = nullptr;
      B::_elf(*x.Bin, [&](ELFO &O) {
        if (x._elf.interp) {
          for (binary_t &b : jv.Binaries) {
            if (b.IsDynamicLinker) {
              rtld_path = b.path();
              break;
            }
          }
          assert(rtld_path);

          Arg("-dynamic-linker");
          Arg(rtld_path);
        }

        if (!state.for_binary(b).soname.empty())
          Arg(std::string("-soname=") + state.for_binary(b).soname);
      });

#if 0
      if (!rtld_soname.empty()) {
        Arg("-l");
        Arg(":" + rtld_soname);
      }
#endif

      for (const std::string &needed : x.needed_vec) {
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
    };

    int rc;
    if (IsCOFF) {
      assert(IsX86Target);

      rc = RunExecutableToExit(locator().lld_link(), [&](auto Arg) {
        Arg(locator().lld_link());

        Arg("-lldmingw");
        Arg("-out:" + chrooted_path.string());
        Arg("-debug:dwarf");
        Arg("-WX:no");
        //Arg("-verbose");
        Arg("-opt:noref");
        Arg("-demangle");
        Arg("-auto-import");
        Arg("-runtime-pseudo-reloc");
        Arg("-opt:noicf");
        Arg("-noseh"); /* FIXME */
        Arg(std::string("-machine:") + (IsTarget32 ? "x86" : "x64"));
        Arg("-alternatename:__image_base__=__ImageBase");
        for (const std::string &lib_dir : lib_dirs) {
          Arg("-libpath:" + lib_dir);
        }
        Arg(objfp);

        Arg(locator().builtins());
        Arg(locator().softfloat_bitcode(IsCOFF));
        Arg(locator().runtime_dll(opts.MT));

#if 0
        for (const std::string &needed : x.needed_vec)
          Arg(locator().wine_dll(IsTarget32, needed));
#else
        for (const std::string &needed : x.needed_vec) {
          auto it = soname_map.find(needed);
          if (it == soname_map.end()) {
            WithColor::warning()
                << llvm::formatv("no entry in soname_map for {0}\n", needed);
            continue;
          }

          binary_t &needed_b = jv.Binaries.at((*it).second);

#if 1
          const fs::path needed_chrooted_path(opts.Output + needed_b.path_str());
          Arg(needed_chrooted_path.string());
#else
          const fs::path needed_path(needed_b.path_str());
          Arg(needed_path.parent_path().string());
#endif
        }
#endif

        std::vector<std::string> def_files;
        for (auto &entry : fs::directory_iterator(chrooted_path.parent_path())) {
          if (fs::is_regular_file(entry) && entry.path().extension() == ".def")
            Arg("-def:" + entry.path().string());
        }
      });
    } else {
    auto run_linker = [&](const char *linker_path) -> int {
      return RunExecutableToExit(linker_path, [&](auto Arg) {
        Arg(linker_path);
        linker_args(Arg);
      });
    };

    if (22) rc = run_linker(locator().lld().c_str());
    if (rc) rc = run_linker(locator().ld_gold().c_str()); /* ridiculous... */
    if (rc) rc = run_linker(locator().ld_bfd().c_str());  /* lol... */
    }

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

void RecompileTool::worker(dso_t dso) {
  int rc;

  binary_index_t BIdx = dso_graph[dso].BIdx;

  binary_t &b = jv.Binaries.at(BIdx);

  if (b.IsDynamicLinker)
    return;
  if (b.IsVDSO)
    return;

  assert(b.is_file());

  const fs::path chrooted_path =
      fs::path(opts.Output.getValue()) / a2r(b.path_str());
  fs::create_directories(chrooted_path.parent_path());

  std::string binary_filename = fs::path(b.path_str()).filename().string();

  std::string bcfp(chrooted_path.string() + ".bc");
  std::string llfp(chrooted_path.string() + ".ll");
  std::string ll_strip_fp(chrooted_path.string() + ".strip.ll");
  std::string objfp(chrooted_path.string() + ".o");
  std::string mapfp(chrooted_path.string() + ".map");
  std::string dfsan_modid_fp(chrooted_path.string() + ".modid");

  std::string bytecode_loc =
      (fs::path(opts.Output.getValue()) / "dfsan").string();

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
        if (!opts.ForeignLibs)
          Arg("--x=0");
        if (opts.DebugSjlj)
          Arg("--debug-sjlj");
        if (!opts.ABICalls)
          Arg("--abi-calls=0");
        if (opts.InlineHelpers)
          Arg("--inline-helpers");
        if (!opts.MT)
          Arg("--mt=0");
        if (opts.BreakBeforeUnreachables)
          Arg("--break-before-unreachables");
      },
      [&](auto Env) {
        InitWithEnviron(Env);

        Env("JVPATH=" + path_to_jv());
      },
      path_to_stdout, path_to_stderr);

  //
  // check exit code
  //
  if (rc) {
    worker_failed.store(true);
    WithColor::error() << llvm::formatv("jove llvm failed! see {0}\n",
                                        path_to_stderr);
    return;
  }

  if (opts.DFSan) {
    std::ifstream ifs(dfsan_modid_fp);
    std::string dfsan_modid((std::istreambuf_iterator<char>(ifs)),
                            std::istreambuf_iterator<char>());

    WithColor::note() << llvm::formatv("ModuleID for {0} is {1}\n", bcfp,
                                       dfsan_modid);

    fs::copy_file(bcfp, opts.Output + "/dfsan/" + dfsan_modid,
                  fs::copy_options::overwrite_existing);
  }

  static constexpr std::array<unsigned, 3> arr3{{0, 1, 2}};

  std::for_each(
      std::execution::par_unseq,
      arr3.begin(),
      arr3.end(),
      [&](unsigned i) {
        switch (i) {
        case 0:
          //
          // run llvm-dis on bitcode
          //
          RunExecutableToExit(locator().dis(), [&](auto Arg) {
            nice(10);

            Arg(locator().dis());
            Arg("-o");
            Arg(llfp);
            Arg(bcfp);
          });
          break;

        case 1:
          //
          // run opt on bitcode to generate stripped ll
          //
          RunExecutableToExit(locator().opt(), [&](auto Arg) {
            nice(10);

            Arg(locator().opt());
            Arg("-o");
            Arg(ll_strip_fp);
            Arg("-S");
            Arg("--strip-debug");
            Arg(bcfp);
          });
          break;

        case 2:
          //
          // run llc
          //
          rc = RunExecutableToExit(locator().llc(), [&](auto Arg) {
            Arg(locator().llc());

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

            //
            // XXX (On mips)
            // "The dynamic linker will use an undefined function symbol table entry
            // with STO_MIPS_PLT set to resolve all references to that symbol in
            // preference to the actual definition of that symbol"
            //
            if (true /* b.IsPIC */) {
              Arg("--relocation-model=pic");
            } else {
              assert(b.IsExecutable);
              Arg("--relocation-model=static");
            }

            if (IsCOFF)
              Arg("--mtriple=" + getTargetTriple(true).normalize()); /* force */

            Arg("--dwarf-version=4");
            Arg("--debugger-tune=gdb");

            if (IsX86Target) {
              //
              // FIXME... how is the stack getting unaligned??
              //

              Arg("--stackrealign");
            }
          });
          break;

        default:
          die("");
        }
      });

  //
  // check exit code
  //
  if (rc) {
    worker_failed = true;
    WithColor::error() << llvm::formatv("llc failed for {0}\n",
                                        binary_filename);

    return;
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
