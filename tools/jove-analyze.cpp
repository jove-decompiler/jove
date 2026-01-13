#include "tool.h"
#include "B.h"
#include "tcg.h"
#include "calls.h"
#include "analyze.h"

#ifndef JOVE_NO_BACKEND

#include <oneapi/tbb/parallel_invoke.h>

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
    cl::opt<bool> BottomUp;

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
              cl::desc("Number of milliseconds to update message in -v mode."),
              cl::cat(JoveCategory), cl::init(1000u)),

          BottomUp("bottom-up",
                   cl::desc("direction of Kahn-style traversal in analyze_functions()"),
                   cl::cat(JoveCategory))
          {}
  } opts;

  boost::concurrent_flat_set<dynamic_target_t> inflight;
  std::atomic<uint64_t> done = 0;

  llvm::LLVMContext Context;
  tiny_code_generator_t TCG;
  analyzer_t<IsToolMT, IsToolMinSize> analyzer;

  analyzer_options_t analyzer_opts;

  int AnalyzeBlocks(void);
  int AnalyzeFunctions(void);
  int WriteDecompilation(void);

public:
  AnalyzeTool()
      : opts(JoveCategory),
        analyzer(analyzer_opts, TCG, Context, jv_file, jv, inflight, done) {}

  int Run(void) override;
};

JOVE_REGISTER_TOOL("analyze", AnalyzeTool);

typedef boost::format fmt;

int AnalyzeTool::Run(void) {
  for (const std::string &PinnedGlobalName : opts.PinnedGlobals) {
    int idx = TCG.tcg_index_of_named_global(PinnedGlobalName.c_str());
    if (idx < 0)
      die("unknown global to pin: " + PinnedGlobalName);

    analyzer_opts.PinnedEnvGlbs.set(idx);
  }

  analyzer_opts.VerbosityLevel = GetVerbosityLevel();
  analyzer_opts.Conservative = opts.Conservative;

  analyzer.examine_blocks();
  analyzer.examine_callers();
  analyzer.identify_ABIs();
  analyzer.identify_Sjs();

  return AnalyzeBlocks()
      || AnalyzeFunctions();
}

int AnalyzeTool::AnalyzeBlocks(void) {
  return analyzer.analyze_blocks();
}

int AnalyzeTool::AnalyzeFunctions(void) {
  auto go = [&](void) -> void {
    if (opts.BottomUp)
      analyzer.analyze_functions<true>();
    else
      analyzer.analyze_functions<false>();
  };

  if (IsVerbose()) {
    const bool smartterm = is_smart_terminal();

    auto count_stale_functions = [&](const binary_t &b) -> uint64_t {
      return std::accumulate(
          b.Analysis.Functions.begin(),
          b.Analysis.Functions.end(), 0u,
          [&](uint64_t n, const function_t &f) -> uint64_t {
            return n + static_cast<unsigned>(f.Analysis.Stale.test(boost::memory_order_relaxed));
          });
    };

    const uint64_t N = std::accumulate(jv.Binaries.begin(),
                                       jv.Binaries.end(), 0u,
                                       [&](uint64_t x, const binary_t &b) {
                                         return x + count_stale_functions(b);
                                       });
    if (!smartterm) {
      printf("Analyzing functions (%u)...\n", static_cast<unsigned>(N));
      go();
      printf("Analyzed functions (%u).\n", static_cast<unsigned>(N));
      return 0;
    }

    auto t1 = std::chrono::high_resolution_clock::now();

    //
    // show progress to stdout
    //
    std::mutex m;
    std::condition_variable cv;
    std::thread printer([&](void) -> void {
          unsigned lll = 0;
          std::string msg;

          uint64_t did;
          for (;;) {
            did = done.load(std::memory_order_relaxed);
            if (did >= N)
              break;

            {
            std::unique_lock<std::mutex> lk(m);
            cv.wait_for(lk, std::chrono::milliseconds(opts.WaitMilli), [&](void) -> bool {
              return done.load(std::memory_order_relaxed) >= N;
            });
            }

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
          msg.append(std::to_string(done.load(std::memory_order_relaxed)));
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
        });

    go();

    {
      std::unique_lock<std::mutex> lk(m);
      cv.notify_one();
    }

    printer.join();
  } else {
    go();
  }

  return 0;
}
}
#endif /* JOVE_NO_BACKEND */
