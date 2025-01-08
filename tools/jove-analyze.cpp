#include "tool.h"
#include "B.h"
#include "tcg.h"
#include "calls.h"
#include "analyze.h"

#include <boost/filesystem.hpp>
#include <boost/format.hpp>

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

#include <chrono>
#include <execution>
#include <thread>
#include <condition_variable>

#include <sys/ioctl.h>

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

class AnalyzeTool : public JVTool<ToolKind::Standard> {
  struct Cmdline {
    cl::opt<bool> ForeignLibs;
    cl::alias ForeignLibsAlias;
    cl::list<std::string> PinnedGlobals;
    cl::opt<int> Conservative;
    cl::opt<unsigned> WaitMilli;
    cl::opt<bool> New;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : ForeignLibs("foreign-libs",
                      cl::desc("only analyze the executable itself"),
                      cl::cat(JoveCategory), cl::init(true)),

          ForeignLibsAlias("x", cl::desc("Exe only. Alias for --foreign-libs."),
                           cl::aliasopt(ForeignLibs), cl::cat(JoveCategory)),

          PinnedGlobals(
              "pinned-globals", cl::CommaSeparated,
              cl::value_desc("glb_1,glb_2,...,glb_n"),
              cl::desc(
                  "force specified TCG globals to always go through CPUState"),
              cl::cat(JoveCategory)),

          Conservative(
              "conservative",
              cl::desc(
                  "1 => assume any arg registers could be live for ABI calls."),
              cl::cat(JoveCategory), cl::init(1)),

          WaitMilli(
              "wait-for",
              cl::desc("Number of milliseconds to update message in -vv mode."),
              cl::cat(JoveCategory), cl::init(1000u)),

          New("new",
              cl::desc("Use newer version of algorithm which computes SCCs and "
                       "topologically sorts them"),
              cl::cat(JoveCategory)) {}
  } opts;

  boost::concurrent_flat_set<dynamic_target_t> inflight;
  std::atomic<uint64_t> done = 0;

  std::unique_ptr<tiny_code_generator_t> TCG;
  std::unique_ptr<analyzer_t<IsToolMT>> analyzer;

  analyzer_options_t analyzer_opts;

  int AnalyzeBlocks(void);
  int AnalyzeFunctions(void);
  int WriteDecompilation(void);

public:
  AnalyzeTool() : opts(JoveCategory) {}

  int Run(void) override;
};

JOVE_REGISTER_TOOL("analyze", AnalyzeTool);

typedef boost::format fmt;

int AnalyzeTool::Run(void) {
  //
  // initialize TCG
  //
  TCG.reset(new tiny_code_generator_t);

  for (const std::string &PinnedGlobalName : opts.PinnedGlobals) {
    int idx = TCG->tcg_index_of_named_global(PinnedGlobalName.c_str());
    if (idx < 0)
      die("unknown global to pin: " + PinnedGlobalName);

    analyzer_opts.PinnedEnvGlbs.set(idx);
  }

  analyzer_opts.Verbose = IsVerbose();
  analyzer_opts.VeryVerbose = IsVeryVerbose();

  analyzer = std::make_unique<analyzer_t<IsToolMT>>(analyzer_opts, *TCG, jv,
                                                    inflight, done);

  return AnalyzeBlocks()
      || AnalyzeFunctions();
}

int AnalyzeTool::AnalyzeBlocks(void) {
  return analyzer->analyze_blocks();
}

int AnalyzeTool::AnalyzeFunctions(void) {
#ifndef JOVE_TSAN /* FIXME */
  analyzer->update_callers();
  analyzer->update_parents();
  analyzer->identify_ABIs();
  analyzer->identify_Sjs();
#endif

#if 0 /* force initializing state upfront */
  for_each_binary(std::execution::par_unseq, jv, [&](binary_t &b) {
    (void)state.for_binary(b);

    for_each_function_in_binary(
        std::execution::par_unseq, b,
        [&](function_t &f) { (void)state.for_function(f); });
  });
#endif

#if 0 /* dump topo */
  for (call_graph_t::vertex_descriptor V : topo) {
    function_t &f = function_of_target(call_graph[V], jv);
    auto &b = binary_of_function(f, jv);

    HumanOut() << llvm::formatv("{0}.{1}\n", b.Name.c_str(),
                                index_of_function(f));
  }
#endif

  jv.InvalidateFunctionAnalyses();

#if 0
  call_graph_builder_t cg(jv);

  if (IsVeryVerbose()) {
    std::string dot_path = (fs::path(temporary_dir()) / "call_graph.dot").string();
    std::ofstream ofs(dot_path);
    cg.write_graphviz(ofs);
  }

  std::vector<call_graph_t::vertex_descriptor> topo;
  cg.best_toposort(topo);
#endif

  auto analyze_functions_in_binary = [&](auto &b) -> void {
    for_each_function_in_binary(
        std::execution::par_unseq, b, [&](function_t &f) {
          const dynamic_target_t X(index_of_binary(b),
                                   index_of_function(f));

          if (IsVeryVerbose())
            inflight.insert(X);

          BOOST_SCOPE_DEFER [&] {
            if (IsVerbose()) {
              done.fetch_add(1u, std::memory_order_relaxed);
              if (IsVeryVerbose())
                inflight.erase(X);
            }
          };

          if (!f.Analysis.Stale)
            return;

          analyzer->analyze_function(f);

          assert(!f.Analysis.Stale);
        });
  };

  auto do_work = [&](void) -> void {
    if (opts.New) {
      analyzer->analyze_functions();
    } else {
    if (opts.ForeignLibs)
      analyze_functions_in_binary(jv.Binaries.at(0));
    else
      for_each_binary(std::execution::par_unseq, jv,
                      [&](auto &b) { analyze_functions_in_binary(b); });
    }
  };

  const uint64_t N =
      !opts.New && opts.ForeignLibs
          ? jv.Binaries.at(0).Analysis.Functions.size()
          : std::accumulate(jv.Binaries.begin(),
                            jv.Binaries.end(), 0,
                            [](uint64_t x, const auto &b) {
                              return x + b.Analysis.Functions.size();
                            });

  auto t1 = std::chrono::high_resolution_clock::now();

  if (IsVerbose()) {
    const bool smartterm = is_smart_terminal();

    //
    // show progress to stdout
    //
    std::mutex m;
    std::condition_variable cv;
    oneapi::tbb::parallel_invoke(
        [&](void) -> void {
          unsigned lll = 0;
          std::string msg;
          std::unique_lock<std::mutex> lk(m);

          uint64_t did;
          for (;;) {
            did = done.load(std::memory_order_relaxed);
            if (did >= N)
              break;

            cv.wait_for(lk, std::chrono::milliseconds(opts.WaitMilli), [&](void) -> bool {
              return done.load(std::memory_order_relaxed) >= N;
            });

            did = done.load(std::memory_order_relaxed);
            if (did >= N)
              break;

            struct winsize term_sz;
            if (!smartterm || ioctl(STDOUT_FILENO, TIOCGWINSZ, &term_sz) < 0)
              term_sz.ws_col = 0;

            msg.clear();
            msg.append("Analyzing ");
            msg.append(std::to_string(did));
            msg.append(" / ");
            msg.append(std::to_string(N));
            msg.append(" functions...");

            if (IsVeryVerbose()) {
              msg.append(" (");

              auto t2 = std::chrono::high_resolution_clock::now();
              std::chrono::duration<double> s_double = t2 - t1;

              msg.append(std::to_string(s_double.count()));
              msg.append(" s)");
            }

            if (IsVeryVerbose()) {
              boost::container::flat_map<
                  binary_index_t, boost::container::flat_set<
                                      std::pair<uint64_t, function_index_t>>>
                  inflight_map;

              inflight.cvisit_all([&](dynamic_target_t X) -> void {
                auto &b = jv.Binaries.at(X.first);
                auto &f = b.Analysis.Functions.at(X.second);

                uint64_t Addr = entry_address_of_function(f, b);

                inflight_map[X.first].emplace(Addr, X.second);
              });

              msg.append(" [\n");
              for (auto it_ = inflight_map.begin(); it_ != inflight_map.end(); ++it_) {
                const auto &pair = *it_;

                auto &b = jv.Binaries.at(pair.first);

                std::string nm = b.is_file()
                                     ? fs::path(b.path()).filename().string()
                                     : b.Name.c_str();

                std::string ln;
                ln.append("  ");
                ln.append(nm);
                ln.append(": { ");

                const unsigned lnlen = ln.size() - 1;

                msg.append(ln);

                for (auto it = pair.second.begin(); it != pair.second.end(); ++it) {
                  const function_index_t FIdx = (*it).second;

                  auto &f = b.Analysis.Functions.at(FIdx);
                  uint64_t Addr = entry_address_of_function(f, b);

                  if (it != pair.second.begin()) {
                    msg.append(std::string(lnlen, ' '));
                    msg.append(" ");
                  }
                  msg.append((fmt("0x%lx") % Addr).str());
                  if (std::next(it) != pair.second.end()) {
                    msg.append(",");
                    msg.append("\n");
                  }
                }

                msg.append(" }");
                msg.append(std::next(it_) != inflight_map.end() ? ",\n" : "");
                msg.append("\n");
              }

              msg.append("]\n");

              printf("%s\n", msg.c_str());
            } else {
              const unsigned sav_lll = lll;
              lll = msg.size();

              if (!term_sz.ws_col || lll > term_sz.ws_col) {
                printf("%s\n", msg.c_str()); // the current line will be fucked
              } else {
                if (msg.size() < sav_lll) {
                  unsigned left = sav_lll - msg.size();
                  msg.append(std::string(left, ' '));
                }

                printf("\r%s", msg.c_str()); // Print over previous line, if any
              }
            }

            fflush(stdout);
          }

          struct winsize term_sz;
          if (!smartterm || ioctl(STDOUT_FILENO, TIOCGWINSZ, &term_sz) < 0)
            term_sz.ws_col = 0;

          // final message
          msg.clear();
          msg.append("Analyzed ");
          msg.append(std::to_string(N));
          msg.append(" functions. (");

          auto t2 = std::chrono::high_resolution_clock::now();
          std::chrono::duration<double> s_double = t2 - t1;

          msg.append(std::to_string(s_double.count()));
          msg.append(" s)");

          if (!term_sz.ws_col || lll > term_sz.ws_col) {
            printf("%s\n", msg.c_str()); // the current line will be fucked
          } else {
            if (msg.size() < lll) {
              unsigned left = lll - msg.size();
              msg.append(std::string(left, ' '));
            }
            printf("\r%s\n", msg.c_str());
          }
          fflush(stdout);
        },
        [&](void) -> void {
          do_work();
          cv.notify_one();
        });
  } else {
    do_work();
  }

#if 0

  HumanOut() << llvm::formatv(" {0} s\n", s_double.count());
#endif

  return 0;
}
}
