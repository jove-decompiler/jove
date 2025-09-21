#include "tool.h"
#include "B.h"
#include "triple.h"
#include "recompile.h"
#include "llvm.h"

#ifndef JOVE_NO_BACKEND

#include <oneapi/tbb/parallel_invoke.h>

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

#include <fcntl.h>
#include <unistd.h>

namespace fs = boost::filesystem;
namespace cl = llvm::cl;
namespace obj = llvm::object;

using llvm::WithColor;

namespace jove {

static inline void print_command(const char **argv) {
  for (const char **argp = argv; *argp; ++argp) {
    llvm::errs() << *argp;

    if (*(argp + 1))
      llvm::errs() << ' ';
  }

  llvm::errs() << '\n';
}

typedef boost::format fmt;

static std::atomic<bool> Cancel(false);

static void handle_sigint(int);

struct all_edges_t {
  template <typename Edge> bool operator()(const Edge &e) const {
    return true;
  }
};

struct vert_exists_in_set_t {
  const boost::unordered::unordered_flat_set<dso_t> *vert_set;

  vert_exists_in_set_t() : vert_set(nullptr) {}
  vert_exists_in_set_t(const boost::unordered::unordered_flat_set<dso_t> &vert_set)
      : vert_set(&vert_set) {}

  bool operator()(const dso_t &v) const {
    assert(this->vert_set);

    return vert_set->find(v) != vert_set->end();
  }
};

template <bool MT, bool MinSize, typename Graph>
struct graphviz_label_writer {
  using jv_t = jv_base_t<MT, MinSize>;

  const jv_t &jv;
  const Graph &g;

  graphviz_label_writer(const jv_t &jv, const Graph &g) : jv(jv), g(g) {}

  template <typename Vertex>
  void operator()(std::ostream &out, Vertex v) const {
    auto &b = jv.Binaries.at(g[v].BIdx);

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
  const boost::unordered::unordered_flat_map<
      dso_t, boost::unordered::unordered_flat_set<dso_t>> *bad_edges;

  no_bad_edges_t() : g_ptr(nullptr) {}
  no_bad_edges_t(
      const dso_graph_t *g_ptr,
      const boost::unordered::unordered_flat_map<
          dso_t, boost::unordered::unordered_flat_set<dso_t>> *bad_edges)
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

template <bool MT, bool MinSize>
int recompiler_t<MT, MinSize>::go(void) {
  //
  // sanity checks for output path
  //
  if (fs::exists(fs::path(opts.Output))) {
    if (opts.IsVerbose())
      WithColor::note() << llvm::formatv("reusing output directory {0}\n",
                                         opts.Output);
  } else {
    if (!fs::create_directories(opts.Output)) {
      WithColor::error() << llvm::formatv(
          "failed to create directory at \"{0}\"", opts.Output);
      return 1;
    }
  }

#if 0
  //
  // create symlink back to jv
  //
  if (fs::exists(fs::path(opts.Output) / ".jv")) // delete any stale symlinks
    fs::remove(fs::path(opts.Output) / ".jv");

  fs::create_symlink(fs::canonical(get_path_to_jv()),
                     fs::path(opts.Output) / ".jv");
#endif

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

  //
  // gather dynamic linking information
  //
  for_each_binary(/* maybe_par_unseq, */ jv, [&](auto &b) {
    if (!b.is_file())
      return;

    binary_state_t &x = state.for_binary(b);

    x.Bin = B::Create(b.data());
    std::tie(x.Base, x.End) = B::bounds_of_binary(*x.Bin);

    if (b.is_file())
      x.chrooted_path = fs::path(opts.Output) / b.path_str();

    //
    // what is this binary called as far as dynamic linking goes?
    //
    B::_elf(*x.Bin, [&](ELFO &O) {
      x._elf.interp = elf::program_interpreter(O);
      if (auto MaybeSoName = elf::soname(O))
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

    B::_coff(*x.Bin, [&](COFFO &O) {
      coff::needed_delay_libs(O, x._coff.needed_delay_vec);
    });
  });

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

  for (auto &b : jv.Binaries) {
    if (!b.IsDynamicLinker)
      continue;

    binary_state_t &x = state.for_binary(b);

    const auto &chrooted_path = x.chrooted_path;

    //
    // we have the binary data in the jv. let's use it
    //
    fs::path ldso_path = fs::path(temporary_dir()) / "ld.so";

    fs::create_directories(chrooted_path.parent_path());

    {
      std::ofstream ofs(chrooted_path.string());

      ofs.write(static_cast<const char *>(&b.Data[0]), b.Data.size());
    }

    //
    // make rtld executable (chmod)
    //
    fs::permissions(chrooted_path, fs::perms::others_read |
                                   fs::perms::others_exe |

                                   fs::perms::group_read |
                                   fs::perms::group_exe |

                                   fs::perms::owner_read |
                                   fs::perms::owner_write |
                                   fs::perms::owner_exe);

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
        state.for_binary(jv.Binaries.at(0)).chrooted_path.parent_path() /
        "libjove_rt.dll";
    fs::create_directories(chrooted_path.parent_path());
    fs::copy_file(locator().runtime_dll(opts.RuntimeMT), chrooted_path,
                  fs::copy_options::overwrite_existing);
  }
  else
  {
    fs::path chrooted_path =
        fs::path(opts.Output) / "usr" / "lib" / "libjove_rt.so";

    fs::create_directories(chrooted_path.parent_path());
    fs::copy_file(locator().runtime_so(opts.RuntimeMT), chrooted_path,
                  fs::copy_options::overwrite_existing);

    //
    // /lib could just be a symlink to usr/lib, in which case we don't want
    // the following
    //
    if (!fs::equivalent(chrooted_path,
                        fs::path(opts.Output) / "lib" / "libjove_rt.so")) {
      fs::create_directories(fs::path(opts.Output) / "lib");

      try {
        // XXX some dynamic linkers only look in /lib
        fs::copy_file(locator().runtime_so(opts.RuntimeMT),
                      fs::path(opts.Output) / "lib" / "libjove_rt.so",
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
          fs::path(opts.Output) / "usr" / "lib" / dfsan_rt_filename;

      fs::copy_file(locator().dfsan_runtime(), chrooted_path,
                    fs::copy_options::overwrite_existing);
    }

    if (!fs::equivalent(fs::path(opts.Output) / "usr" / "lib" / dfsan_rt_filename,
                        fs::path(opts.Output) / "lib" / dfsan_rt_filename)) {
      /* XXX some dynamic linkers only look in /lib */
      fs::path chrooted_path =
          fs::path(opts.Output) / "lib" / dfsan_rt_filename;

      fs::copy_file(locator().dfsan_runtime(), chrooted_path,
                    fs::copy_options::overwrite_existing);
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

      for (const auto &binary : jv.Binaries)
        ofs << binary.Name.c_str() << '\n';
    }

    fs::create_directories(fs::path(opts.Output) / "jove" /
                           "BinaryBlockAddrTables");

    for (binary_index_t BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx) {
      auto &binary = jv.Binaries.at(BIdx);
      auto &ICFG = binary.Analysis.ICFG;

      {
        std::ofstream ofs((fs::path(opts.Output) / "jove" /
                           "BinaryBlockAddrTables" / std::to_string(BIdx))
                              .c_str());

        for (basic_block_index_t BBIdx = 0; BBIdx < ICFG.num_vertices(); ++BBIdx) {
          bb_t bb = basic_block_of_index(BBIdx, ICFG);
          uint64_t Addr = ICFG[bb].Term.Addr; /* XXX */
          ofs.write(reinterpret_cast<char *>(&Addr), sizeof(Addr));
        }
      }
    }
  }

  //
  // create mapping from "soname" to binary
  //
  for_each_binary(jv, [&](auto &b) {
    binary_state_t &x = state.for_binary(b);

    const std::string &soname = x.soname;
    if (soname.empty())
      return;

#if 0
    auto it = soname_map.find(soname);
    if (it != soname_map.end()) {
      WithColor::error() << llvm::formatv(
          "{0} and {1} have the same soname ({2})\n",
          jv.Binaries.at((*it).second).Name.c_str(), b.Name.c_str(), soname);
      return;
    }
#endif

    bool success = soname_map[soname].insert(index_of_binary(b, jv)).second;
    assert(success);
  });

  //
  // initialize dynamic linking graph
  //
  for_each_binary(jv, [&](auto &b) {
    binary_state_t &x = state.for_binary(b);
    binary_index_t BIdx = index_of_binary(b, jv);

    x.dso = boost::add_vertex(dso_graph);
    dso_graph[x.dso].BIdx = BIdx;
  });

  //
  // build dynamic linking graph
  //
  for_each_binary(jv, [&](auto &b) {
    if (!b.is_file())
      return;

    binary_state_t &x = state.for_binary(b);

    for (const std::string &needed : x.needed_vec) {
      binary_index_t ChosenBIdx = ChooseBinaryWithSoname(needed);

      if (!is_binary_index_valid(ChosenBIdx)) {
        if (opts.IsVeryVerbose())
        WithColor::warning() << llvm::formatv("unknown \"{0}\" needed by {1}\n",
                                              needed, b.path_str());
        return;
      }

      auto &needed_b = jv.Binaries.at(ChosenBIdx);
      binary_state_t &y = state.for_binary(needed_b);

      boost::add_edge(x.dso, y.dso, dso_graph);
    }
  });

  if (opts.IsVeryVerbose() && fs::exists(locator().graph_easy())) {
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

    std::map<dso_graph_t::vertices_size_type,
             boost::unordered::unordered_flat_set<dso_t>>
        comp_verts_map;
    for (const auto &el : vert_comps)
      comp_verts_map[el.second].insert(el.first);

    boost::unordered::unordered_flat_map<
        dso_t, boost::unordered::unordered_flat_set<dso_t>>
        bad_edges;

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

      if (opts.IsVerbose()) {
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
            graphviz_label_writer(jv, fg),
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
    if (opts.ForeignLibs && !jv.Binaries.at(BIdx).IsExecutable)
      continue;

    Q.push_back(dso);
  }

  if (opts.IsVerbose())
    WithColor::note() << llvm::formatv(
        "Recompiling {0} {1}...",
        (opts.ForeignLibs ? 3 : jv.Binaries.size()) - 2,
        opts.ForeignLibs ? "binary" : "binaries");

  auto t1 = std::chrono::high_resolution_clock::now();

  //
  // run jove-llvm and llc on all DSOs
  //
#if 0
  std::for_each(
    maybe_par_unseq,
    Q.begin(),
    Q.end(),
    std::bind(&recompiler_t::worker, this, std::placeholders::_1));
#else
  {
    std::vector<std::thread> workers;

    unsigned num_threads = num_cpus();

    workers.reserve(num_threads);
    for (unsigned i = 0; i < num_threads; ++i)
      //workers.emplace_back(&recompiler_t::worker, this);
      workers.push_back(std::thread(&recompiler_t::worker, this));

    for (std::thread &t : workers)
      t.join();
  }
#endif

  auto t2 = std::chrono::high_resolution_clock::now();

  if (worker_failed.load())
    return 1;

  std::chrono::duration<double> s_double = t2 - t1;

  if (opts.IsVerbose())
    llvm::errs() << llvm::formatv(" {0} s\n", s_double.count());

  //
  // to handle shared libraries needing each other (i.e. a cyclic dependency),
  // we copy the original binary data for each DSO before we run the static
  // linker to produce each recompiled DSO, this solves "unable to find library"
  // errors XXX
  //
  for_each_binary(maybe_par_unseq, jv, [&](auto &b) {
    if (!b.is_file())
      return;

    if (b.IsExecutable)
      return;

    const binary_state_t &x = state.for_binary(b);

    const auto &chrooted_path = x.chrooted_path;

    fs::create_directories(chrooted_path.parent_path());
    fs::remove(chrooted_path);

    {
      std::ofstream ofs(chrooted_path.c_str());

      ofs.write(&b.Data[0], b.Data.size());
    }

    fs::permissions(chrooted_path, fs::perms::others_read |
                                   fs::perms::others_exe |

                                   fs::perms::group_read |
                                   fs::perms::group_exe |

                                   fs::perms::owner_read |
                                   fs::perms::owner_write |
                                   fs::perms::owner_exe);

    B::_elf(*x.Bin, [&](ELFO &O) {

    if (!x.soname.empty()) {
      std::string binary_filename = fs::path(b.path_str()).filename().string();

      //
      // create symlink
      //
      if (binary_filename != x.soname) {
        fs::path dst = chrooted_path.parent_path() / x.soname;
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

    });

    B::_coff(*x.Bin, [&](COFFO &O) {
      std::string def_path =
          fs::path(chrooted_path).replace_extension("def").string();

      std::ofstream ofs(def_path);

      coff::gen_module_definition_for_dll(O, x.soname, ofs);
    });
  });

  for_each_binary(maybe_par_unseq, jv, [&](auto &b) {
    if (!b.is_file())
      return;

    if (b.IsExecutable)
      return;

    const binary_state_t &x = state.for_binary(b);

    B::_coff(*x.Bin, [&](COFFO &O) {
      std::string def_path =
          fs::path(x.chrooted_path).replace_extension("def").string();

      std::string imp_lib_path =
          fs::path(x.chrooted_path).replace_extension("lib").string();

      if (unlikely(RunExecutableToExit(locator().dlltool(), [&](auto Arg) {
            Arg(locator().dlltool());
            Arg("-m");
            Arg(IsTarget32 ? "i386" : "i386:x86-64");
            Arg("-d");
            Arg(def_path);
            Arg("-l");
            Arg(imp_lib_path);
          },
          std::string(),
          std::string(),
          [&](const char **argv, const char **envp) {
            if (opts.IsVeryVerbose()) {
              print_command(argv);
            }
          })))
        throw std::runtime_error("failed to run llvm-dlltool");
    });
  });

  //
  // run ld on all the object files
  //
  for (dso_t dso : top_sorted) {
    binary_index_t BIdx = dso_graph[dso].BIdx;

    auto &b = jv.Binaries.at(BIdx);

    if (b.IsDynamicLinker)
      continue;
    if (!b.is_file())
      continue;

    binary_state_t &x = state.for_binary(b);

    const auto &chrooted_path = x.chrooted_path;

    std::string binary_filename = fs::path(b.path_str()).filename().string();

    std::string objfp(chrooted_path.string() + ".o");
    std::string mapfp(chrooted_path.string() + ".map");
    std::string ldfp(chrooted_path.string() + ".ld");

    if (opts.ForeignLibs && !b.IsExecutable)
      continue;

    if (!fs::exists(objfp)) {
      WithColor::warning() << llvm::formatv("{0} doesn't exist; skipping {1}\n",
                                            objfp, binary_filename);
      return 1;
    }

    fs::remove(chrooted_path);

#if 1
    boost::unordered::unordered_flat_set<std::string> lib_dirs(
        {opts.Output + "/usr/lib"});
#else
    boost::unordered::unordered_flat_set<std::string> lib_dirs(
        {jove_bin_path, "/usr/lib"});
#endif

    for (const std::string &needed : x.needed_vec) {
      binary_index_t ChosenBIdx = ChooseBinaryWithSoname(needed);
      if (!is_binary_index_valid(ChosenBIdx)) {
        WithColor::warning()
            << llvm::formatv("no entry in soname_map for {0}\n", needed);
        continue;
      }

      auto &needed_b = jv.Binaries.at(ChosenBIdx);

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
      assert(!IsCOFF);

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
      Arg(locator().builtins(IsCOFF));
      if (!opts.SoftfpuBitcode)
        Arg(locator().softfloat_obj(IsCOFF));
      Arg(locator().atomics(IsCOFF));
      Arg("--pop-state");
      Arg("--exclude-libs");
      Arg("ALL");

      if (!IsCOFF) {
      if (b.IsExecutable) {
        if (b.IsPIC) {
          Arg("-pie");
        } else {
          Arg("-no-pie");

          // Arg("-z");
          // Arg("nocopyreloc");

          uint64_t Base, End;
          std::tie(Base, End) = B::bounds_of_binary(*x.Bin);

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

      //Arg("-ljove_rt" + std::string(opts.RuntimeMT ? ".m" : ".s") + "t");
      Arg("-ljove_rt");
      if (opts.DFSan)
        Arg("-lclang_rt.dfsan.jove-" TARGET_ARCH_NAME);

      const char *rtld_path = nullptr;
      B::_elf(*x.Bin, [&](ELFO &O) {
        if (x._elf.interp) {
          for (auto &b : jv.Binaries) {
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

      std::string subsystem;

      if (b.IsExecutable)
        subsystem = B::_must_be_coff(*x.Bin, coff::link_subsystem);

      rc = RunExecutableToExit(locator().lld_link(), [&](auto Arg) {
        Arg(locator().lld_link());

        assert(IsCOFF);

        Arg("-lldmingw");
        Arg("/out:" + chrooted_path.string());

        if (opts.IsVeryVerbose()) {
          Arg("/verbose");

          Arg("/map:" + chrooted_path.string() + ".link.map");
          Arg("/mapinfo:exports");
        }

        Arg(std::string("/machine:") + (IsTarget32 ? "x86" : "x64"));

        if (!subsystem.empty())
          Arg("/subsystem:" + subsystem);

        Arg("/entry:_jove_start");

        Arg("/debug:dwarf");
        Arg("/largeaddressaware");
        Arg("/nodefaultlib");
        Arg("/opt:noref");
        Arg("/opt:noicf");
        Arg("/safeseh:no");

        Arg("/force:unresolved");

        Arg("/section:.rdata,RW"); /* FIXME mingw */

        // Why do we do this, you may ask? Because if an app suddenly loads a
        // DLL without /NXCOMPAT (and every other DLL previously loaded *did*
        // have it), wine will immediately mprotect every section of the EXE and
        // every DLL currently in memory as being executable, and thus the
        // effect of *our* mprotect in _jove_make_sections_not_executable() is
        // no more. So, basically we do this to get one step ahead of wine.
        Arg("/nxcompat:no");

#if 0
        Arg("/auto-import:no");
        Arg("/runtime-pseudo-reloc:no");
#endif
        //Arg("/force:unresolved");
        //Arg("/opt:noref");
        //Arg("/demangle");
        //Arg("-alternatename:__image_base__=__ImageBase");

        if (b.IsExecutable && !b.IsPIC) { /* do we need to set base address? */
          uint64_t Base, End;
          std::tie(Base, End) = B::bounds_of_binary(*x.Bin);

          Arg("/dynamicbase:no");
          Arg("/fixed");

          Arg((fmt("/base:0x%lx") % (Base - 0x1000)).str());
        } else {
          Arg("/dynamicbase");
        }

        for (const std::string &lib_dir : lib_dirs)
          Arg("/libpath:" + lib_dir);

        Arg(objfp);

        Arg(locator().builtins(IsCOFF));
        if (!opts.SoftfpuBitcode)
          Arg(locator().softfloat_obj(IsCOFF));
        Arg(locator().atomics(IsCOFF));
        Arg(locator().runtime_implib(opts.RuntimeMT));

        for (const std::string &needed_delay : x._coff.needed_delay_vec)
          Arg("/delayload:" + needed_delay);

        if (!x._coff.needed_delay_vec.empty()) {
          const char *x = IsX86Target && IsTarget32 ? "___delayLoadHelper2@8"
                                                    : "__delayLoadHelper2";
          const char *y = IsX86Target && IsTarget32 ? "_JoveWinMain@0"
                                                    : "JoveWinMain";

          Arg(std::string("/alternatename:") + x + std::string("=") + y);
        }

        for (const std::string &needed : x.needed_vec) {
          binary_index_t ChosenBIdx = ChooseBinaryWithSoname(needed);

          if (!is_binary_index_valid(ChosenBIdx)) {
            WithColor::warning()
                << llvm::formatv("no entry in soname_map for {0}\n", needed);
            continue;
          }

          auto &needed_b = jv.Binaries.at(ChosenBIdx);

          fs::path needed_chrooted_path(opts.Output + needed_b.path_str());
          Arg(needed_chrooted_path.replace_extension("lib").string());
        }
        },
        std::string(),
        std::string(),
        [&](const char **argv, const char **envp) {
          if (opts.IsVerbose()) {
            print_command(argv);
          }
        });
    } else {
    auto run_linker = [&](const char *linker_path) -> int {
      return RunExecutableToExit(linker_path, [&](auto Arg) {
        Arg(linker_path);
        linker_args(Arg);
      },
      std::string(),
      std::string(),
      [&](const char **argv, const char **envp) {
        if (opts.IsVerbose()) {
          print_command(argv);
        }
      });
    };

    if (22) rc = run_linker(locator().lld().c_str());
    if (rc) rc = run_linker(locator().ld_gold().c_str()); /* XXX >_< */
    if (rc) rc = run_linker(locator().ld_bfd().c_str());  /* XXX O_O */
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

template <bool MT, bool MinSize>
void recompiler_t<MT, MinSize>::worker(void) {
  dso_t dso = ({
    std::lock_guard<std::mutex> lck(Q_mtx);

    if (Q.empty())
      return;

    dso_t the_dso = Q.back();
    Q.resize(Q.size() - 1);
    the_dso;
  });

  int rc;

  binary_index_t BIdx = dso_graph[dso].BIdx;

  auto &b = jv.Binaries.at(BIdx);

  if (b.IsDynamicLinker)
    return;
  if (b.IsVDSO)
    return;

  assert(b.is_file());

  const binary_state_t &x = state.for_binary(b);

  const auto &chrooted_path = x.chrooted_path;

  fs::create_directories(chrooted_path.parent_path());

  std::string binary_filename = fs::path(b.path_str()).filename().string();

  std::string bcfp(chrooted_path.string() + ".bc");
  std::string llfp(chrooted_path.string() + ".ll");
  std::string ll_strip_fp(chrooted_path.string() + ".strip.ll");
  std::string objfp(chrooted_path.string() + ".o");
  std::string mapfp(chrooted_path.string() + ".map");
  std::string ldfp(chrooted_path.string() + ".ld");
  std::string dfsan_modid_fp(chrooted_path.string() + ".modid");

  std::string bytecode_loc = (fs::path(opts.Output) / "dfsan").string();

  //
  // run jove-llvm
  //
  std::string path_to_stdout = bcfp + ".llvm.stdout.txt";
  std::string path_to_stderr = bcfp + ".llvm.stderr.txt";

#if 0
  if (MT == AreWeMT && MinSize == AreWeMinSize) {
  rc = RunExecutableToExit(
      "/proc/self/exe", /* FIXME */
      [&](auto Arg) {
        Arg("llvm");

        Arg("-o");
        Arg(bcfp);

        if (IsCOFF) {
          if (b.IsExecutable) {
            Arg("--linker-script");
            Arg(ldfp);
          }
        } else {
          Arg("--version-script");
          Arg(mapfp);
        }

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
        if (opts.CallStack) {
          Arg("--call-stack");
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
        if (!opts.RuntimeMT)
          Arg("--rtmt=0");
        if (opts.BreakBeforeUnreachables)
          Arg("--break-before-unreachables");
        if (opts.LayOutSections)
          Arg("--lay-out-sections");
        if (opts.PlaceSectionBreakpoints)
          Arg("--place-section-breakpoints");
        if (opts.SoftfpuBitcode)
          Arg("--softfpu-bitcode");
        if (opts.VerifyBitcode)
          Arg("--verify-bitcode");

#if 0
        if (!opts.PinnedGlobals.empty()) {
          std::string pinned_globals_arg = "--pinned-globals=";

          for (const std::string &PinnedGlbStr : opts.PinnedGlobals) {
            pinned_globals_arg.append(PinnedGlbStr);
            pinned_globals_arg.push_back(',');
          }

          pinned_globals_arg.resize(pinned_globals_arg.size() - 1);

          Arg(pinned_globals_arg);
        }
#endif
      },
      [&](auto Env) {
        InitWithEnviron(Env);

        Env("JVPATH=" + path_to_jv());
      },
      path_to_stdout, path_to_stderr,
      [&](const char **argv, const char **envp) {
        if (opts.IsVerbose()) {
          print_command(argv);
        }
      });
  } else {
#else
  {
#endif
    llvm::LLVMContext Context;

    llvm_options_t llvm_opts(llvm_options);

    if (B::is_coff(*state.for_binary(b).Bin)) {
      if (b.IsExecutable)
        llvm_opts.LinkerScript = ldfp;
    } else {
      llvm_opts.VersionScript = mapfp;
    }

    llvm_opts.Output = bcfp;
    llvm_opts.BinaryIndex = std::to_string(BIdx);

    llvm_t llvm(jv, llvm_opts, analyzer_options, disas, TCG, Context, locator());
    rc = llvm.go();
  }

  //
  // check exit code
  //
  if (rc) {
    worker_failed.store(true);
    if (opts.IsVerbose()) {
      WithColor::error() << llvm::formatv("jove llvm failed on {0}!\n",
                                          binary_filename);
      std::string stderr_contents;
      read_file_into_thing(path_to_stderr.c_str(), stderr_contents);
      llvm::errs() << stderr_contents;
    } else {
      WithColor::error() << llvm::formatv("jove llvm failed! see {0}\n",
                                          path_to_stderr);
    }
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

  oneapi::tbb::parallel_invoke(
        [&](void) -> void {
          //
          // run llvm-dis on bitcode
          //
          RunExecutableToExit(locator().dis(), [&](auto Arg) {
            nice(10);

            Arg(locator().dis());
            Arg("-o");
            Arg(llfp);
            Arg(bcfp);
          },
          std::string(),
          std::string(),
          [&](const char **argv, const char **envp) {
            if (opts.IsVerbose()) {
              print_command(argv);
            }
          });
        },
        [&](void) -> void {
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
          },
          std::string(),
          std::string(),
          [&](const char **argv, const char **envp) {
            if (opts.IsVerbose()) {
              print_command(argv);
            }
          });
        },
        [&](void) -> void {
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

              if (IsMIPSTarget)
                Arg("--disable-mips-delay-filler"); /* make our life easier */
            }

            if (b.IsPIC) {
              Arg("--relocation-model=pic");
            } else {
              assert(b.IsExecutable);

              if (IsMIPSTarget)
                Arg("--relocation-model=pic"); /* FIXME otherwise plt stubs broken */
              else
                Arg(IsCOFF ? "--relocation-model=dynamic-no-pic"
                           : "--relocation-model=static");
            }

            if (IsCOFF)
              Arg("--mtriple=" + getTargetTriple(true).normalize()); /* force */

            Arg("--trap-unreachable");

            Arg("--dwarf-version=4");
            Arg("--debugger-tune=gdb");

#if defined(TARGET_X86_64)
            Arg("-mattr=+cx16");
#elif defined(TARGET_I386)
            Arg("-mattr=+sse2");
#elif defined(TARGET_MIPS32)
            Arg("-mno-check-zero-division");
#endif
          },
          std::string(),
          std::string(),
          [&](const char **argv, const char **envp) {
            if (opts.IsVerbose()) {
              print_command(argv);
            }
          });
        }
      );

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

template <bool MT, bool MinSize>
void recompiler_t<MT, MinSize>::write_dso_graphviz(
    std::ostream &out,
    const dso_graph_t &dso_graph) {
  boost::write_graphviz(out, dso_graph,
                        graphviz_label_writer(jv, dso_graph),
                        graphviz_edge_prop_writer(dso_graph),
                        graphviz_prop_writer());
}

void handle_sigint(int no) {
  Cancel.store(true);
}

template <bool MT, bool MinSize>
binary_index_t
recompiler_t<MT, MinSize>::ChooseBinaryWithSoname(const std::string &soname) {
  auto it = soname_map.find(soname);
  if (it == soname_map.end())
    return invalid_binary_index;

  binary_index_t Res = invalid_binary_index;
  fs::path exe_parent = fs::path(jv.Binaries.at(0).path()).parent_path();
  const auto &BIdxSet = (*it).second;
  for (binary_index_t BIdx : BIdxSet) {
    auto &otherb = jv.Binaries.at(BIdx);
    fs::path parent = fs::path(otherb.path()).parent_path();
    if (exe_parent == parent) {
      Res = BIdx; /* in same dir */
      break;
    }
  }

  if (!is_binary_index_valid(Res))
    Res = *BIdxSet.begin(); /* arbitrary */

  return Res;
}

#define VALUES_TO_INSTANTIATE_WITH1                                            \
    ((true))                                                                   \
    ((false))
#define VALUES_TO_INSTANTIATE_WITH2                                            \
    ((true))                                                                   \
    ((false))
#define GET_VALUE(x) BOOST_PP_TUPLE_ELEM(0, x)

#define DO_INSTANTIATE(r, product)                                             \
  template struct recompiler_t<GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)),       \
                               GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))>;
BOOST_PP_SEQ_FOR_EACH_PRODUCT(DO_INSTANTIATE, (VALUES_TO_INSTANTIATE_WITH1)(VALUES_TO_INSTANTIATE_WITH2))

}
#endif /* JOVE_NO_BACKEND */
