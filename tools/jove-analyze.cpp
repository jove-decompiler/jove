#include "tool.h"
#include "B.h"
#include "tcg.h"

#include <boost/filesystem.hpp>

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

#include <chrono>
#include <execution>
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

class AnalyzeTool : public StatefulJVTool<ToolKind::Standard, binary_state_t, function_state_t, void> {
  struct Cmdline {
    cl::opt<bool> ForeignLibs;
    cl::alias ForeignLibsAlias;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : ForeignLibs("foreign-libs",
                      cl::desc("only analyze the executable itself"),
                      cl::cat(JoveCategory), cl::init(true)),

          ForeignLibsAlias("x", cl::desc("Exe only. Alias for --foreign-libs."),
                           cl::aliasopt(ForeignLibs), cl::cat(JoveCategory)) {}
  } opts;

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

int AnalyzeTool::Run(void) {
  identify_ABIs(jv);

  for_each_binary(jv, [&](binary_t &binary) {
    ignore_exception([&]() {
      state.for_binary(binary).ObjectFile = B::Create(binary.data());
    });
  });

  //
  // create LLVM module (necessary to analyze helpers)
  //
  Context.reset(new llvm::LLVMContext);

  llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> BufferOr =
      llvm::MemoryBuffer::getFile(locator().starter_bitcode(false));
  if (!BufferOr) {
    WithColor::error() << llvm::formatv("failed to open bitcode {0}: {1}\n",
                                        locator().starter_bitcode(false),
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
                     std::function<std::pair<basic_block_vec_t &, basic_block_vec_t &>(function_t &)> GetBlocks,
                     bool DFSan = false,
                     bool ForCBE = false,
                     Tool *tool = nullptr);

int AnalyzeTool::AnalyzeBlocks(void) {
  std::atomic<unsigned> count = 0;

  for_each_basic_block(
      std::execution::par_unseq,
      jv, [&](binary_t &b, basic_block_t bb) {
        const auto &ICFG = b.Analysis.ICFG;
        if (ICFG[bb].Analysis.Stale)
          ++count;

        AnalyzeBasicBlock(*TCG, *Module, b, *state.for_binary(b).ObjectFile, bb,
                          false, false, this);

        assert(!ICFG[bb].Analysis.Stale);
      });

  if (unsigned c = count.load())
    WithColor::note() << llvm::formatv("Analyzed {0} basic block{1}.\n", c,
                                       c == 1 ? "" : "s");

  //
  // XXX hack for _jove_call
  //
  for_each_function_if(std::execution::par_unseq, jv,
      [](function_t &f) { return f.IsABI; },
      [](function_t &f, binary_t &b) {
        auto &ICFG = b.Analysis.ICFG;
        ICFG[basic_block_of_index(f.Entry, ICFG)].Analysis.live.use |= CallConvArgs;
      });

  return 0;
}

int AnalyzeTool::AnalyzeFunctions(void) {
  /* FIXME only necessary */
  for_each_function(
      std::execution::par_unseq, jv,
      [&](function_t &f, binary_t &b) {
        function_state_t &x = state.for_function(f);

        basic_blocks_of_function(f, b, x.bbvec);
        exit_basic_blocks_of_function(f, b, x.bbvec, x.exit_bbvec);

        x.IsLeaf = IsLeafFunction(f, b, x.bbvec);
      });

  WithColor::note() << "Analyzing functions...";
  auto t1 = std::chrono::high_resolution_clock::now();

  for_each_binary(std::execution::par_unseq, jv, [&](binary_t &binary) {
    if (opts.ForeignLibs && !binary.IsExecutable)
      return;

    for_each_function_in_binary(
        std::execution::par_unseq, binary,
        [&](function_t &f) {
          if (!f.Analysis.Stale)
            return;

          AnalyzeFunction(
              jv, *TCG, *Module, f,
              [&](binary_t &b) -> llvm::object::Binary & {
                return *state.for_binary(b).ObjectFile;
              },
              [&](function_t &f) -> std::pair<basic_block_vec_t &, basic_block_vec_t &> {
                function_state_t &x = state.for_function(f);
                return std::pair<basic_block_vec_t &, basic_block_vec_t &>(x.bbvec, x.exit_bbvec);
              },
              false, false, this);

          assert(!f.Analysis.Stale);
        });
  });

  auto t2 = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> s_double = t2 - t1;

  HumanOut() << llvm::formatv(" {0} s\n", s_double.count());

  return 0;
}
}
