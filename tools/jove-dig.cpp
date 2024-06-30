#include "tool.h"
#include "recovery.h"
#include "B.h"
#include "symbolizer.h"
#include "tcg.h"
#include "explore.h"

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
};

}

class CodeDigger : public StatefulJVTool<ToolKind::Standard, binary_state_t, void, void> {
  struct Cmdline {
    cl::opt<unsigned> Threads;
    cl::opt<bool> NoSave;
    cl::opt<std::string> Binary;
    cl::alias BinaryAlias;
    cl::opt<unsigned> PathLength;
    cl::opt<bool> ListLocalGotos;
    cl::opt<std::string> SingleBBIdx;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Threads("num-threads",
                  cl::desc("Number of CPU threads to use (hack)"),
                  cl::init(num_cpus()), cl::cat(JoveCategory)),

          NoSave("no-save",
                 cl::desc("Do not overwrite jv before exiting"),
                 cl::cat(JoveCategory)),

          Binary("binary", cl::desc("Operate on single given binary"),
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
              cl::cat(JoveCategory)) {}
  } opts;

  std::atomic<bool> worker_failed = false;

  std::vector<binary_index_t> Q;
  std::mutex Q_mtx;

  binary_index_t SingleBinaryIndex = invalid_binary_index;

  int pipe_rdfd = -1;
  int pipe_wrfd = -1;

  disas_t disas;
  tiny_code_generator_t tcg;
  symbolizer_t symbolizer;

  explorer_t Explorer;
  CodeRecovery Recovery;

public:
  CodeDigger()
      : opts(JoveCategory),
        Explorer(jv, disas, tcg),
        Recovery(jv, Explorer, symbolizer) {}

  int Run(void) override;

  int ListLocalGotos(void);

  void Worker(binary_index_t);
  void RecoverLoop(void);

  void queue_binaries(void);
  bool pop_binary(binary_index_t &out);
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
    ignore_exception([&]() {
      auto Bin = B::Create(b.data());

      assert(llvm::isa<ELFO>(Bin.get()));

      std::tie(state.for_binary(b).SectsStartAddr,
               state.for_binary(b).SectsEndAddr) = B::bounds_of_binary(*Bin);
    });
  });

  if (opts.ListLocalGotos)
    return ListLocalGotos();

  int pipefd[2];
  if (::pipe(pipefd) < 0) {
    int err = errno;
    WithColor::error() << llvm::formatv("pipe failed: {0}\n", strerror(err));
    return 1;
  }

  pipe_rdfd = pipefd[0];
  pipe_wrfd = pipefd[1];

  std::thread recover_thread(&CodeDigger::RecoverLoop, this);

  if (!IsVerbose())
    WithColor::note() << llvm::formatv(
        "Generating LLVM and running KLEE on {0} {1}...",
        !opts.Binary.empty() ? 1 : jv.Binaries.size() - 2,
        !opts.Binary.empty() ? "binary" : "binaries");

  bool Failed = false;

  queue_binaries();
  {
    auto t1 = std::chrono::high_resolution_clock::now();

    std::for_each(
      std::execution::par_unseq,
      Q.begin(),
      Q.end(),
      std::bind(&CodeDigger::Worker, this, std::placeholders::_1));

    auto t2 = std::chrono::high_resolution_clock::now();

    Failed = worker_failed.load();

    std::chrono::duration<double> s_double = t2 - t1;

    if (!Failed && !IsVerbose())
      llvm::errs() << llvm::formatv(" {0} s\n", s_double.count());
  }

  ::close(pipe_wrfd);
  recover_thread.join();

  if (opts.NoSave)
    return 0;

  for_each_function(std::execution::par_unseq, jv,
                    [](function_t &f, binary_t &b) { f.InvalidateAnalysis(); });

  if (IsVerbose())
    WithColor::note() << "writing jv...\n";

  return 0;
}

void CodeDigger::RecoverLoop(void) {
  std::vector<std::set<std::pair<basic_block_index_t, uint64_t>>> records;
  records.resize(jv.Binaries.size());

  for (;;) {
    constexpr unsigned RECORD_LEN =
        2 * sizeof(uint32_t) + sizeof(uint64_t);

    uint8_t record[RECORD_LEN];

    ssize_t ret = robust_read(pipe_rdfd, &record[0], RECORD_LEN);
    if (ret != RECORD_LEN) {
      if (ret < 0) {
        if (ret != -EIO)
          WithColor::error() << llvm::formatv(
              "RecoverLoop: failed to read pipe: {0}\n", strerror(-ret));
      }
      break;
    }

    uint32_t BIdx  = *reinterpret_cast<uint32_t *>(&record[0 * sizeof(uint32_t)]);
    uint32_t BBIdx = *reinterpret_cast<uint32_t *>(&record[1 * sizeof(uint32_t)]);
    uint64_t Off   = *reinterpret_cast<uint64_t *>(&record[2 * sizeof(uint32_t)]);

    binary_t &binary = jv.Binaries.at(BIdx);

    {
      auto &bin_records = records.at(BIdx);

      if (bin_records.find(std::make_pair(BBIdx, Off)) != bin_records.end())
        continue; /* duplicate; skip */

      bin_records.emplace(BBIdx, Off);
    }

    uint64_t TermAddr = Recovery.AddressOfTerminatorAtBasicBlock(BIdx, BBIdx);

    uint64_t SectsLen = state.for_binary(binary).SectsEndAddr -
                        state.for_binary(binary).SectsStartAddr;
    if (!(Off < SectsLen)) {
      WithColor::error() << llvm::formatv(
          "invalid offset {0:x} for {1}\n", Off,
          symbolizer.addr2desc(binary, TermAddr));
      continue;
    }

    uint64_t DestAddr = Off + state.for_binary(binary).SectsStartAddr;

    if (IsVerbose())
      HumanOut() << llvm::formatv("{0} -> {1}\n",
                                  symbolizer.addr2desc(binary, TermAddr),
                                  symbolizer.addr2desc(binary, DestAddr));

    std::string recovery_msg;
    try {
      recovery_msg = Recovery.RecoverBasicBlock(BIdx, BBIdx, DestAddr);
    } catch (const std::exception &e) {
      WithColor::error() << llvm::formatv("{0} -> {1}: {2}\n",
                                          symbolizer.addr2desc(binary, TermAddr),
                                          symbolizer.addr2desc(binary, DestAddr),
                                          e.what());
    }

    if (!recovery_msg.empty())
      HumanOut() << recovery_msg << '\n';
  }

  ::close(pipe_rdfd);
}

bool CodeDigger::pop_binary(binary_index_t &out) {
  std::lock_guard<std::mutex> lck(Q_mtx);

  if (Q.empty()) {
    return false;
  } else {
    out = Q.back();
    Q.resize(Q.size() - 1);
    return true;
  }
}

void CodeDigger::Worker(binary_index_t BIdx) {
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
    std::string path_to_stdout = bcfp + ".stdout.llvm.txt";
    std::string path_to_stderr = bcfp + ".stderr.llvm.txt";

    int rc = RunToolToExit(
        "llvm",
        [&](auto Arg) {
          ::close(pipe_rdfd);
          ::close(pipe_wrfd);

          Arg("-o");
          Arg(bcfp);
          Arg("--version-script");
          Arg(mapfp);

          Arg("--binary-index");
          Arg(std::to_string(BIdx));

          //Arg("--inline-helpers");
          //Arg("--optimize");
        },
        path_to_stdout,
        path_to_stderr);

    //
    // check exit code
    //
    if (rc) {
      worker_failed.store(true);
      WithColor::error() << llvm::formatv(
          "jove llvm failed on {0}: see {1}\n", binary_filename,
          path_to_stderr);
      return;
    }
  }

  assert(fs::exists(bcfp));

  //
  // run klee
  //
  {
    std::string path_to_stdout = bcfp + ".stdout.klee.txt";
    std::string path_to_stderr = bcfp + ".stderr.klee.txt";

    int rc = RunExecutableToExit(
        locator().klee(),
        [&](auto Arg) {
          ::close(pipe_rdfd);

          Arg(locator().klee());

          Arg("--entry-point=_jove_begin");
          Arg("--solver-backend=stp");
          Arg("--write-no-tests");
          Arg("--output-stats=0");
          Arg("--output-istats=0");
          Arg("--check-div-zero=0");
          Arg("--check-overshift=0");
          Arg("--max-memory=0");
          Arg("--max-memory-inhibit=0");
          Arg("--use-forked-solver=0");

          Arg("--jove-output-dir=" + temporary_dir());
          Arg("--jove-pipefd=" + std::to_string(pipe_wrfd));
          Arg("--jove-binary-index=" + std::to_string(BIdx));
          Arg("--jove-sects-start-addr=" + std::to_string(state.for_binary(binary).SectsStartAddr));
          Arg("--jove-sects-end-addr=" + std::to_string(state.for_binary(binary).SectsEndAddr));
          Arg("--jove-path-length=" + std::to_string(opts.PathLength));
          if (!opts.SingleBBIdx.empty())
            Arg("--jove-single-bbidx=" + opts.SingleBBIdx);
          Arg(bcfp);
        },
        path_to_stdout,
        path_to_stderr);

    //
    // check exit code
    //
    if (rc) {
      worker_failed.store(true);
      WithColor::error() << llvm::formatv("klee failed on {0}: see {1}\n",
                                          binary_filename, path_to_stderr);
    }
  }
}

int CodeDigger::ListLocalGotos() {
  auto process_basic_block = [&](binary_t &binary, basic_block_t bb) -> void {
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
        binary, [&](basic_block_t bb) { process_basic_block(binary, bb); });
  } else {
    for_each_basic_block(jv, process_basic_block);
  }

  return 0;
}

}
