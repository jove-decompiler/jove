#include "tool.h"
#include "B.h"
#include "tcg.h"
#include "concurrent.h"

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

namespace {

struct function_state_t {
  basic_block_vec_t bbvec;
  basic_block_vec_t exit_bbvec;

  bool IsLeaf;

  bool IsSj, IsLj;

  function_state_t(const function_t &f, const binary_t &b) {
    basic_blocks_of_function(f, b, bbvec);
    exit_basic_blocks_of_function(f, b, bbvec, exit_bbvec);

    IsLeaf = IsLeafFunction(f, b, bbvec, exit_bbvec);
    IsSj = IsFunctionSetjmp(f, b, bbvec);
    IsLj = IsFunctionLongjmp(f, b, bbvec);

#if 0
    const function_index_t FIdx = index_of_function_in_binary(f, b);

    auto &ICFG = b.Analysis.ICFG;
    std::for_each(std::execution::par_unseq,
                  bbvec.begin(),
                  bbvec.end(),
                  [&](basic_block_t bb) {
                    if (!ICFG[bb].IsParent(FIdx))
                      ICFG[bb].AddParent(FIdx, jv);
                  });
#endif
  }
};

struct binary_state_t {
  std::unique_ptr<llvm::object::Binary> Bin;

  binary_state_t(const binary_t &b) { Bin = B::Create(b.data()); }
};

}

class AnalyzeTool
    : public StatefulJVTool<ToolKind::Standard, binary_state_t,
                            function_state_t, void, true, false, true, false> {
  struct Cmdline {
    cl::opt<bool> ForeignLibs;
    cl::alias ForeignLibsAlias;
    cl::list<std::string> PinnedGlobals;
    cl::opt<int> Conservative;

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
              cl::cat(JoveCategory), cl::init(1)) {}

  } opts;

  tcg_global_set_t PinnedEnvGlbs = InitPinnedEnvGlbs;

  std::unique_ptr<tiny_code_generator_t> TCG;
  std::unique_ptr<llvm::LLVMContext> Context;
  std::unique_ptr<llvm::Module> Module;

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
  identify_ABIs(jv);

  bool IsCOFF = B::_X(*state.for_binary(jv.Binaries.at(0)).Bin,
      [&](ELFO &O) -> bool { return false; },
      [&](COFFO &O) -> bool { return true; });
  //
  // create LLVM module (necessary to analyze helpers)
  //
  Context.reset(new llvm::LLVMContext);

  std::string path_to_bitcode = locator().starter_bitcode(false, IsCOFF);

  llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> BufferOr =
      llvm::MemoryBuffer::getFile(path_to_bitcode);
  if (!BufferOr) {
    WithColor::error() << llvm::formatv("failed to open {0}: {1}\n",
                                        path_to_bitcode,
                                        BufferOr.getError().message());
    return 1;
  }

  llvm::Expected<std::unique_ptr<llvm::Module>> moduleOr =
      llvm::parseBitcodeFile(BufferOr.get()->getMemBufferRef(), *Context);
  if (!moduleOr) {
    llvm::logAllUnhandledErrors(moduleOr.takeError(), HumanOut(),
                                "could not parse helper bitcode: ");
    return 1;
  }

  Module = std::move(moduleOr.get());

  //
  // initialize TCG
  //
  TCG.reset(new tiny_code_generator_t);

  for (const std::string &PinnedGlobalName : opts.PinnedGlobals) {
    int idx = TCG->tcg_index_of_named_global(PinnedGlobalName.c_str());
    if (idx < 0)
      die("unknown global to pin: " + PinnedGlobalName);

    PinnedEnvGlbs.set(idx);
  }

  return AnalyzeBlocks()
      || AnalyzeFunctions();
}

// defined in tools/llvm.cpp
template <bool MT>
void AnalyzeBasicBlock(tiny_code_generator_t &TCG,
                       llvm::Module &M,
                       binary_base_t<MT> &binary,
                       llvm::object::Binary &B,
                       basic_block_t bb,
                       bool DFSan = false,
                       bool ForCBE = false,
                       Tool *tool = nullptr);

template <bool MT>
void AnalyzeFunction(jv_base_t<MT> &jv,
                     tiny_code_generator_t &TCG,
                     llvm::Module &M,
                     function_t &f,
                     std::function<llvm::object::Binary &(binary_base_t<MT> &)> GetBinary,
                     std::function<std::pair<basic_block_vec_t &, basic_block_vec_t &>(function_t &)> GetBlocks,
                     bool DFSan = false,
                     bool ForCBE = false,
                     tcg_global_set_t PinnedEnvGlbs = InitPinnedEnvGlbs,
                     Tool *tool = nullptr);

int AnalyzeTool::AnalyzeBlocks(void) {
  std::atomic<unsigned> count = 0;

  for_each_basic_block(
      std::execution::seq, /* FIXME */
      jv, [&](binary_t &b, basic_block_t bb) {
        const auto &ICFG = b.Analysis.ICFG;
        if (ICFG[bb].Analysis.Stale)
          ++count;

        AnalyzeBasicBlock(*TCG, *Module, b, *state.for_binary(b).Bin, bb,
                          false, false, this);

        assert(!ICFG[bb].Analysis.Stale);
      });

  if (unsigned c = count.load())
    WithColor::note() << llvm::formatv("Analyzed {0} basic block{1}.\n", c,
                                       c == 1 ? "" : "s");

  if (opts.Conservative >= 1)
  for_each_function_if(std::execution::par_unseq, jv,
      [](function_t &f) { return f.IsABI; },
      [](function_t &f, binary_t &b) {
        auto &ICFG = b.Analysis.ICFG;
        assert(is_basic_block_index_valid(f.Entry));
        ICFG[basic_block_of_index(f.Entry, ICFG)].Analysis.live.use |= CallConvArgs;
      });

  return 0;
}

int AnalyzeTool::AnalyzeFunctions(void) {
  for_each_basic_block(
      std::execution::unseq, jv, [&](binary_t &b, basic_block_t bb) {
        auto &ICFG = b.Analysis.ICFG;
        taddr_t TermAddr = ICFG[bb].Term.Addr;

        if (ICFG[bb].Term.Type == TERMINATOR::CALL) {
          assert(TermAddr);
#if 0
          b.Analysis.Functions.at(ICFG[bb].Term._call.Target)
              .Callers.emplace(index_of_binary(b, jv), TermAddr);
#endif
          return;
        }

        if (!ICFG[bb].hasDynTarget())
          return;

        assert(TermAddr);
        ICFG[bb].DynTargetsForEach(
            std::execution::par_unseq, [&](const dynamic_target_t &X) {
              function_t &f = function_of_target(X, jv);
#if 0
              f.Callers.emplace(index_of_binary(b, jv), TermAddr);
#endif
            });
      });

  for_each_function(
      std::execution::par_unseq, jv, [&](function_t &f, binary_t &b) {
        function_index_t FIdx = index_of_function_in_binary(f, b);

        function_state_t &x = state.for_function(f);

        if (!x.exit_bbvec.empty())
          f.Returns = true;

        if (x.IsSj) {
          std::for_each(
              std::execution::par_unseq,
              f.Callers.cbegin(),
              f.Callers.cend(),
              [&](const caller_t &pair) -> void {
                binary_t &caller_b = jv.Binaries.at(
                    is_binary_index_valid(pair.first) ? pair.first
                                                      : index_of_binary(b, jv));

                if (&caller_b != &b)
                  return;

                auto &caller_ICFG = caller_b.Analysis.ICFG;
                basic_block_t caller_bb = basic_block_at_address(pair.second, caller_b);
                auto &caller_bbprop = caller_ICFG[caller_bb];

                if (caller_bbprop.Term.Type == TERMINATOR::INDIRECT_JUMP) {
                  concurrent::set(caller_bbprop.Sj);
                }
              });
        }
      });

#if 0 /* force initializing state upfront */
  for_each_binary(std::execution::par_unseq, jv, [&](binary_t &b) {
    (void)state.for_binary(b);

    for_each_function_in_binary(
        std::execution::par_unseq, b,
        [&](function_t &f) { (void)state.for_function(f); });
  });
#endif

  const bool smartterm = is_smart_terminal();
  const bool vv = IsVeryVerbose();
  boost::concurrent_flat_set<dynamic_target_t> inflight;

  std::atomic<uint64_t> done = 0;

  auto analyze_functions_in_binary = [&](auto &b) -> void {
    for_each_function_in_binary(
        std::execution::par_unseq, b, [&](function_t &f) {
          const dynamic_target_t X(index_of_binary(b, jv),
                                   index_of_function(f));

          if (smartterm && vv)
            inflight.insert(X);

          BOOST_SCOPE_DEFER [&] {
            if (smartterm) {
              done.fetch_add(1u, std::memory_order_relaxed);
              if (vv)
                inflight.erase(X);
            }
          };

          if (!f.Analysis.Stale)
            return;

          AnalyzeFunction<true>(
              jv, *TCG, *Module, f,
              [&](binary_t &b) -> llvm::object::Binary & {
                return *state.for_binary(b).Bin;
              },
              [&](function_t &f) -> std::pair<basic_block_vec_t &, basic_block_vec_t &> {
                function_state_t &x = state.for_function(f);
                return std::pair<basic_block_vec_t &, basic_block_vec_t &>(x.bbvec, x.exit_bbvec);
              },
              false, false, PinnedEnvGlbs, this);

          assert(!f.Analysis.Stale);
        });
  };

  auto do_work = [&](void) -> void {
    if (opts.ForeignLibs)
      analyze_functions_in_binary(jv.Binaries.at(0));
    else
      for_each_binary(std::execution::par_unseq, jv,
                      [&](binary_t &b) { analyze_functions_in_binary(b); });
  };

  const uint64_t N =
      opts.ForeignLibs
          ? jv.Binaries.at(0).Analysis.Functions.size()
          : std::accumulate(jv.Binaries.begin(), jv.Binaries.end(), 0,
                            [](uint64_t x, const binary_t &b) {
                              return x + b.Analysis.Functions.size();
                            });

#if 0
  WithColor::note() << "Analyzing functions...";
  auto t1 = std::chrono::high_resolution_clock::now();
#endif

  if (smartterm) {
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

            cv.wait_for(lk, /* std::chrono::seconds(1) */ std::chrono::milliseconds(500), [&](void) -> bool {
              return done.load(std::memory_order_relaxed) >= N;
            });

            did = done.load(std::memory_order_relaxed);
            if (did >= N)
              break;

            struct winsize term_sz;
            if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &term_sz) < 0)
              term_sz.ws_col = ~0UL;

            msg.clear();
            msg.append("Analyzing ");
            msg.append(std::to_string(did));
            msg.append(" / ");
            msg.append(std::to_string(N));
            msg.append(" ...");

            if (vv) {
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
            }

            const unsigned sav_lll = lll;
            lll = msg.size();

            if (lll > term_sz.ws_col) {
              printf("\n%s\n", msg.c_str()); // the current line will be fucked
            } else {
              if (msg.size() < sav_lll) {
                unsigned left = sav_lll - msg.size();
                msg.append(std::string(left, ' '));
              }

              printf("\r%s", msg.c_str()); // Print over previous line, if any
            }
            fflush(stdout);
          }

          struct winsize term_sz;
          if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &term_sz) < 0)
            term_sz.ws_col = ~0UL;

          // final message
          msg.clear();
          msg.append("Analyzed ");
          msg.append(std::to_string(N));
          msg.append(" functions.");

          if (lll > term_sz.ws_col) {
            printf("\n%s\n", msg.c_str()); // the current line will be fucked
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
  auto t2 = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> s_double = t2 - t1;

  HumanOut() << llvm::formatv(" {0} s\n", s_double.count());
#endif

  return 0;
}
}
