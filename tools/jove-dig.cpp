#include "tool.h"
#include "recovery.h"
#include "B.h"
#include "symbolizer.h"
#include "tcg.h"
#include "explore.h"
#include "robust.h"
#include "signals.h"
#include "ansi.h"

#include <boost/filesystem.hpp>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

#include <atomic>
#include <execution>
#include <mutex>
#include <thread>
#include <fcntl.h>

namespace cl = llvm::cl;
namespace obj = llvm::object;
namespace fs = boost::filesystem;

using llvm::WithColor;

namespace jove {

namespace {

struct binary_state_t {
  uint64_t SectsStartAddr, SectsEndAddr;

  binary_state_t(const auto &b) {}
};

}

class CodeDigger : public StatefulJVTool<ToolKind::Standard, binary_state_t, void, void> {
  struct Cmdline {
    cl::opt<std::string> Binary;
    cl::alias BinaryAlias;
    cl::opt<unsigned> PathLength;
    cl::opt<bool> ListLocalGotos;
    cl::opt<std::string> SingleBBIdx;
    cl::opt<std::string> SolverBackend;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Binary("binary", cl::desc("Operate on single given binary"),
                 cl::value_desc("path"), cl::cat(JoveCategory)),

          BinaryAlias("b", cl::desc("Alias for -binary."), cl::aliasopt(Binary),
                      cl::cat(JoveCategory)),

          PathLength("path-length", cl::desc("Length of paths generated"),
                     cl::init(8), cl::cat(JoveCategory)),

          ListLocalGotos("list-local-gotos",
                         cl::desc("Print each local goto we know about"),
                         cl::cat(JoveCategory)),

          SingleBBIdx(
              "single-bbidx",
              cl::desc("Only analyze indirect jump at given basic block index"),
              cl::cat(JoveCategory)),

          SolverBackend(
              "solver-backend",
              cl::init("stp"),
              cl::cat(JoveCategory)) {}
  } opts;

  std::atomic<bool> worker_failed = false;

  std::vector<binary_index_t> Q;
  std::mutex Q_mtx;

  binary_index_t SingleBinaryIndex = invalid_binary_index;

  disas_t disas;
  tiny_code_generator_t tcg;
  symbolizer_t symbolizer;

  explorer_t<IsToolMT, IsToolMinSize> Explorer;
  CodeRecovery<IsToolMT, IsToolMinSize> Recovery;

public:
  CodeDigger()
      : opts(JoveCategory),
        symbolizer(locator()),
        Explorer(jv_file, jv, disas, tcg),
        Recovery(jv_file, jv, Explorer, symbolizer) {}

  int Run(void) override;

  int ListLocalGotos(void);

  void Worker(binary_index_t, int rfd, int wfd);
  void RecoverLoop(int reportfd);

  void queue_binaries(void);
};

JOVE_REGISTER_TOOL("dig", CodeDigger);

void CodeDigger::queue_binaries(void) {
  Q.clear();
  Q.reserve(jv.Binaries.size());

  if (is_binary_index_valid(SingleBinaryIndex)) {
    Q.push_back(SingleBinaryIndex);
    return;
  }

  for_each_binary(jv, [&](binary_t &binary) {
    if (binary.IsVDSO)
      return;
    if (binary.IsDynamicLinker)
      return;

    binary_index_t BIdx = index_of_binary(binary, jv);
    Q.push_back(BIdx);
  });
}

int CodeDigger::Run(void) {
  ConfigureVerbosity(Explorer);

  //
  // operate on single binary? (cmdline)
  //
  if (!opts.Binary.empty()) {
    binary_index_t BinaryIndex = invalid_binary_index;

    for (binary_index_t BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx) {
      const binary_t &binary = jv.Binaries.at(BIdx);
      if (binary.path_str().find(opts.Binary) == std::string::npos)
        continue;

      BinaryIndex = BIdx;
      break;
    }

    if (!is_binary_index_valid(BinaryIndex)) {
      WithColor::error() << llvm::formatv("failed to find binary \"{0}\"\n",
                                          opts.Binary);
      return 1;
    }

    SingleBinaryIndex = BinaryIndex;
  }

  for_each_binary(jv, [&](binary_t &b) {
    auto Bin = B::Create(b.data());

    std::tie(state.for_binary(b).SectsStartAddr,
             state.for_binary(b).SectsEndAddr) = B::bounds_of_binary(Bin.get());
  });

  if (opts.ListLocalGotos)
    return ListLocalGotos();

  int pipefd[2];
  if (::pipe(pipefd) < 0) {
    int err = errno;
    WithColor::error() << llvm::formatv("pipe failed: {0}\n", strerror(err));
    return 1;
  }

  scoped_fd rfd(pipefd[0]);
  scoped_fd wfd(pipefd[1]);

  std::thread recover_thread(&CodeDigger::RecoverLoop, this, rfd.get());

  if (!IsVerbose())
    WithColor::note() << llvm::formatv(
        "Generating LLVM and running KLEE on {0} {1}...",
        !opts.Binary.empty() ? 1 : jv.Binaries.size() - 2,
        !opts.Binary.empty() ? "binary" : "binaries");

  bool Failed = false;

  queue_binaries();

  {
    auto t1 = std::chrono::high_resolution_clock::now();

    std::for_each(Q.begin(),
                  Q.end(), [&](binary_index_t BIdx) -> void {
      Worker(BIdx, rfd.get(), wfd.get());
    });

    wfd.close();
    recover_thread.join();
    rfd.close();

    auto t2 = std::chrono::high_resolution_clock::now();

    Failed = worker_failed.load();

    std::chrono::duration<double> s_double = t2 - t1;

    if (!Failed && !IsVerbose())
      llvm::errs() << llvm::formatv(" {0} s\n", s_double.count());
  }

  return 0;
}

void CodeDigger::RecoverLoop(int recover_fd) {
  for (;;) {
    uint32_t BIdx  = invalid_binary_index;
    uint32_t BBIdx = invalid_basic_block_index;
    uint64_t Addr  = ~0ULL;

    if (robust::read(recover_fd, &BIdx,  sizeof(BIdx))  != sizeof(BIdx)  ||
        robust::read(recover_fd, &BBIdx, sizeof(BBIdx)) != sizeof(BBIdx) ||
        robust::read(recover_fd, &Addr,  sizeof(Addr))  != sizeof(Addr))
      break;

    try {
      std::string message;
      block_signals(
          [&] { message = Recovery.RecoverBasicBlock(BIdx, BBIdx, Addr); });

      HumanOut() << message << '\n';
    } catch (const std::exception &e) {
      HumanOut() << llvm::formatv(
          __ANSI_RED "failed to recover: {0}" __ANSI_NORMAL_COLOR "\n",
          e.what());
      break;
    }
  }
}

void CodeDigger::Worker(binary_index_t BIdx, int rfd, int wfd) {
  binary_t &binary = jv.Binaries.at(BIdx);

  assert(binary.is_file());

  const fs::path chrooted_path = fs::path(temporary_dir()) / binary.path_str();
  fs::create_directories(chrooted_path.parent_path());

  std::string binary_filename = fs::path(binary.path_str()).filename().string();

  std::string bcfp(chrooted_path.string() + ".bc");
  std::string mapfp(chrooted_path.string() + ".map"); /* XXX */

  //
  // run jove-llvm
  //
  {
    int rc = RunToolToExit(
        "llvm",
        [&](auto Arg) {
          Arg("-o");
          Arg(bcfp);
          Arg("--version-script");
          Arg(mapfp);

          Arg("--binary-index");
          Arg(std::to_string(BIdx));

          //Arg("--inline-helpers");
          //Arg("--optimize");
        },
        "", "",
        RunToolExtraArgs(),
        [&](const char **argv, const char **envp) {
          robust::close(rfd);
          robust::close(wfd);
        });

    //
    // check exit code
    //
    if (rc) {
      worker_failed.store(true);
      WithColor::error() << llvm::formatv("jove llvm failed on {0}\n",
                                          binary_filename);
      return;
    }
  }

  assert(fs::exists(bcfp));

  //
  // run klee
  //
  {
    int rc = RunExecutableToExit(
        locator().klee(),
        [&](auto Arg) {
          Arg(locator().klee());

          Arg("--entry-point=_jove_begin");
          Arg("--solver-backend=" + opts.SolverBackend);
          Arg("--write-no-tests");
          Arg("--output-stats=0");
          Arg("--output-istats=0");
          Arg("--check-div-zero=0");
          Arg("--check-overshift=0");
          Arg("--max-memory=0");
          Arg("--max-memory-inhibit=0");
          Arg("--use-forked-solver=0");

          Arg("--jove-output-dir=" + temporary_dir());
          Arg("--jove-pipefd=" + std::to_string(wfd));
          Arg("--jove-binary-index=" + std::to_string(BIdx));
          Arg("--jove-sects-start-addr=" + std::to_string(state.for_binary(binary).SectsStartAddr));
          Arg("--jove-sects-end-addr=" + std::to_string(state.for_binary(binary).SectsEndAddr));
          Arg("--jove-path-length=" + std::to_string(opts.PathLength));
          if (!opts.SingleBBIdx.empty())
            Arg("--jove-single-bbidx=" + opts.SingleBBIdx);
          Arg(bcfp);
        },
        "", "",
        [&](const char **argv, const char **envp) {
          robust::close(rfd);
        });

    //
    // check exit code
    //
    if (rc) {
      worker_failed.store(true);
      WithColor::error() << llvm::formatv("klee failed on {0}\n",
                                          binary_filename);
    }
  }
}

int CodeDigger::ListLocalGotos() {
  auto process_basic_block = [&](binary_t &binary, bb_t bb) -> void {
    auto &ICFG = binary.Analysis.ICFG;
    if (ICFG[bb].Term.Type != TERMINATOR::INDIRECT_JUMP)
      return;
    if (ICFG[bb].hasDynTarget())
      return;

    HumanOut() << symbolizer.addr2desc(binary, ICFG[bb].Term.Addr)
               << " #" << index_of_basic_block(ICFG, bb) << '\n';
  };

  if (is_binary_index_valid(SingleBinaryIndex)) {
    binary_t &binary = jv.Binaries.at(SingleBinaryIndex);
    for_each_basic_block_in_binary(
        binary, [&](bb_t bb) { process_basic_block(binary, bb); });
  } else {
    for_each_basic_block(jv, process_basic_block);
  }

  return 0;
}

}
