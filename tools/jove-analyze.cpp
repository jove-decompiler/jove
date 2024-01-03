#include "tool.h"
#include "elf.h"
#include "tcg.h"

#include <boost/filesystem.hpp>

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

#include <chrono>
#include <thread>
#include <unordered_set>

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
};

struct binary_state_t {
  std::unique_ptr<llvm::object::Binary> ObjectFile;
};

}

class AnalyzeTool : public TransformerTool_BinFn<binary_state_t, function_state_t> {
  struct Cmdline {
    cl::opt<bool> OnlyExecutable;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : OnlyExecutable("exe",
                         cl::desc("Only analyze functions in executable"),
                         cl::cat(JoveCategory)) {}
  } opts;

  std::unique_ptr<tiny_code_generator_t> TCG;
  std::unique_ptr<llvm::LLVMContext> Context;
  std::unique_ptr<llvm::Module> Module;

  int AnalyzeBlocks(void);
  int AnalyzeFunctions(void);
  int WriteDecompilation(void);

  void worker1(std::atomic<dynamic_target_t *> &Q_ptr, dynamic_target_t *const Q_end);
  void worker2(std::atomic<dynamic_target_t *>& Q_ptr, dynamic_target_t *const Q_end);

public:
  AnalyzeTool() : opts(JoveCategory) {}

  int Run(void);
};

JOVE_REGISTER_TOOL("analyze", AnalyzeTool);

int AnalyzeTool::Run(void) {
  identify_ABIs(jv);

  for_each_binary(jv, [&](binary_t &binary) {
    ignore_exception([&]() {
      state.for_binary(binary).ObjectFile = CreateBinary(binary.data());
    });
  });

  //
  // create LLVM module (necessary to analyze helpers)
  //
  Context.reset(new llvm::LLVMContext);

  llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> BufferOr =
      llvm::MemoryBuffer::getFile(locator().starter_bitcode());
  if (!BufferOr) {
    WithColor::error() << llvm::formatv("failed to open bitcode {0}: {1}\n",
                                        locator().starter_bitcode(),
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

  return AnalyzeBlocks()
      || AnalyzeFunctions();
}

// defined in tools/llvm.cpp
void AnalyzeBasicBlock(tiny_code_generator_t &TCG,
                       llvm::Module &M,
                       binary_t &binary,
                       llvm::object::Binary &B,
                       basic_block_t bb,
                       bool DFSan = false,
                       bool ForCBE = false,
                       Tool *tool = nullptr);

void AnalyzeFunction(jv_t &jv,
                     tiny_code_generator_t &TCG,
                     llvm::Module &M,
                     function_t &f,
                     std::function<llvm::object::Binary &(binary_t &)> GetBinary,
                     bool DFSan = false,
                     bool ForCBE = false,
                     Tool *tool = nullptr);

int AnalyzeTool::AnalyzeBlocks(void) {
  unsigned cnt = 0;

  auto t1 = std::chrono::high_resolution_clock::now();

  for (binary_index_t BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx) {
    auto &binary = jv.Binaries[BIdx];
    auto &ICFG = binary.Analysis.ICFG;

    icfg_t::vertex_iterator vi, vi_end;
    for (std::tie(vi, vi_end) = boost::vertices(ICFG); vi != vi_end; ++vi) {
      basic_block_t bb = *vi;

      if (ICFG[bb].Analysis.Stale)
        ++cnt;

      AnalyzeBasicBlock(*TCG, *Module, binary, *state.for_binary(binary).ObjectFile, bb, false, false, this);

      assert(!ICFG[bb].Analysis.Stale);
    }
  }

  auto t2 = std::chrono::high_resolution_clock::now();

  if (cnt)
    WithColor::note() << llvm::formatv("Analyzed {0} basic block{1}.\n", cnt,
                                       cnt == 1 ? "" : "s");

  //
  // XXX hack for _jove_call
  //
  for_each_function_if(jv,
      [](function_t &f) { return f.IsABI; },
      [](function_t &f, binary_t &b) {
        auto &ICFG = b.Analysis.ICFG;
        ICFG[boost::vertex(f.Entry, ICFG)].Analysis.live.use |= CallConvArgs;
      });

  return 0;
}

#if 0
static void worker1(std::atomic<dynamic_target_t *> &Q_ptr,
                    dynamic_target_t *const Q_end);
static void worker2(std::atomic<dynamic_target_t *> &Q_ptr,
                    dynamic_target_t *const Q_end);
#endif

int AnalyzeTool::AnalyzeFunctions(void) {
  // let N be the count of all functions (in all binaries)
  unsigned N = std::accumulate(
      jv.Binaries.begin(),
      jv.Binaries.end(), 0u,
      [&](unsigned res, const binary_t &binary) -> unsigned {
        return res + binary.Analysis.Functions.size();
      });

  {
    std::vector<dynamic_target_t> Q;
    Q.reserve(N);

    //
    // Build queue with all function pairs (b, f)
    //
    for (binary_index_t BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx)
      for (function_index_t FIdx = 0; FIdx < jv.Binaries[BIdx].Analysis.Functions.size(); ++FIdx)
        Q.emplace_back(BIdx, FIdx);

    if (!Q.empty()) {
      std::atomic<dynamic_target_t *> Q_ptr(Q.data());

      {
        std::vector<std::thread> workers;

        unsigned NumThreads = num_cpus();

        workers.reserve(NumThreads);
        for (unsigned i = 0; i < NumThreads; ++i)
          workers.emplace_back(&AnalyzeTool::worker1,
                               this,
                               std::ref(Q_ptr),
                               Q.data() + Q.size());

        for (std::thread &t : workers)
          t.join();
      }

      assert(Q_ptr.load() >= Q.data() + Q.size()); /* consumed all */
    }
  }

  {
    std::vector<dynamic_target_t> Q;
    Q.reserve(N);

    //
    // Build queue with functions having stale analyses in Q2.
    //
    for (binary_index_t BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx) {
      binary_t &binary = jv.Binaries[BIdx];
      if (opts.OnlyExecutable && !binary.IsExecutable)
        continue;

      for (function_index_t FIdx = 0; FIdx < binary.Analysis.Functions.size(); ++FIdx) {
        function_t &f = binary.Analysis.Functions[FIdx];
        if (f.Analysis.Stale)
          Q.emplace_back(BIdx, FIdx);
      }
    }

    if (!Q.empty()) {
      //
      // Analyze every function
      //
      std::atomic<dynamic_target_t *> Q_ptr(Q.data());

      WithColor::note() << llvm::formatv("Analyzing {0} functions...", Q.size());

      auto t1 = std::chrono::high_resolution_clock::now();

      {
        std::vector<std::thread> workers;

        unsigned NumThreads = num_cpus();

        workers.reserve(NumThreads);
        for (unsigned i = 0; i < NumThreads; ++i)
          workers.emplace_back(&AnalyzeTool::worker2,
                               this,
                               std::ref(Q_ptr),
                               Q.data() + Q.size());

        for (std::thread &t : workers)
          t.join();
      }

      assert(Q_ptr.load() >= Q.data() + Q.size()); /* consumed all */

      auto t2 = std::chrono::high_resolution_clock::now();

      std::chrono::duration<double> s_double = t2 - t1;

      HumanOut() << llvm::formatv(" {0} s\n", s_double.count());
    }
  }

  return 0;
}

void AnalyzeTool::worker1(std::atomic<dynamic_target_t *> &Q_ptr,
                          dynamic_target_t *const Q_end) {
  for (dynamic_target_t *p = Q_ptr++; p < Q_end; p = Q_ptr++) {
    dynamic_target_t X = *p;

    binary_t &b = jv.Binaries.at(X.first);
    function_t &f = function_of_target(X, jv);

    basic_blocks_of_function(f, b, state.for_function(f).bbvec);
    exit_basic_blocks_of_function(f, b, state.for_function(f).bbvec,
                                  state.for_function(f).exit_bbvec);

    state.for_function(f).IsLeaf =
        IsLeafFunction(f, b, state.for_function(f).bbvec);
  }
}

void AnalyzeTool::worker2(std::atomic<dynamic_target_t *>& Q_ptr,
                          dynamic_target_t *const Q_end) {
  for (dynamic_target_t *p = Q_ptr++; p < Q_end; p = Q_ptr++) {
    dynamic_target_t X = *p;

    AnalyzeFunction(jv, *TCG, *Module, function_of_target(X, jv), [&](binary_t &b) -> llvm::object::Binary & { return *state.for_binary(b).ObjectFile; }, false, false, this);
  }
}

}
