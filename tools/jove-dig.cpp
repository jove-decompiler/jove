#include "tool.h"
#include "recovery.h"
#include "elf.h"

#include <atomic>
#include <boost/dll/runtime_symbol_info.hpp>
#include <boost/filesystem.hpp>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCObjectFileInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/WithColor.h>
#include <mutex>
#include <thread>
#include <fcntl.h>
#include <sched.h>

namespace cl = llvm::cl;
namespace obj = llvm::object;
namespace fs = boost::filesystem;

using llvm::WithColor;

namespace jove {

struct binary_state_t {
  tcg_uintptr_t SectsStartAddr, SectsEndAddr;
};

static unsigned num_cpus(void);

class CodeDigger : public Tool {
  struct Cmdline {
    cl::opt<std::string> jv;
    cl::alias jvAlias;
    cl::opt<bool> Verbose;
    cl::alias VerboseAlias;
    cl::opt<unsigned> Threads;
    cl::opt<bool> NoSave;
    cl::opt<std::string> Binary;
    cl::alias BinaryAlias;
    cl::opt<unsigned> PathLength;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : jv("decompilation", cl::desc("Jove Decompilation"), cl::Required,
             cl::value_desc("filename"), cl::cat(JoveCategory)),

          jvAlias("d", cl::desc("Alias for -Decompilation."), cl::aliasopt(jv),
                  cl::cat(JoveCategory)),

          Verbose("verbose",
                  cl::desc("Print extra information for debugging purposes"),
                  cl::cat(JoveCategory)),

          VerboseAlias("v", cl::desc("Alias for -verbose."),
                       cl::aliasopt(Verbose), cl::cat(JoveCategory)),

          Threads("num-threads",
                  cl::desc("Number of CPU threads to use (hack)"),
                  cl::init(num_cpus()), cl::cat(JoveCategory)),

          NoSave("no-save",
                 cl::desc("Do not overwrite decompilation before exiting"),
                 cl::cat(JoveCategory)),

          Binary("binary", cl::desc("Operate on single given binary"),
                 cl::value_desc("path"), cl::cat(JoveCategory)),

          BinaryAlias("b", cl::desc("Alias for -binary."), cl::aliasopt(Binary),
                      cl::cat(JoveCategory)),

          PathLength("path-length", cl::desc("Length of paths generated"),
                     cl::init(8), cl::cat(JoveCategory)) {}

  } opts;

  decompilation_t decompilation;

  std::atomic<bool> worker_failed = false;

  std::vector<binary_index_t> Q;
  std::mutex Q_mtx;

  binary_index_t SingleBinaryIndex = invalid_binary_index;

  fs::path tmp_dir;
  std::string klee_path;

  int pipe_rdfd = -1;
  int pipe_wrfd = -1;

  llvm::Triple TheTriple;
  llvm::SubtargetFeatures Features;

  const llvm::Target *TheTarget = nullptr;
  std::unique_ptr<const llvm::MCRegisterInfo> MRI;
  std::unique_ptr<const llvm::MCAsmInfo> AsmInfo;
  std::unique_ptr<const llvm::MCSubtargetInfo> STI;
  std::unique_ptr<const llvm::MCInstrInfo> MII;
  std::unique_ptr<llvm::MCContext> MCCtx;
  std::unique_ptr<llvm::MCDisassembler> DisAsm;
  std::unique_ptr<llvm::MCInstPrinter> IP;

  std::unique_ptr<CodeRecovery> Recovery;

public:
  CodeDigger() : opts(JoveCategory) {}

  int Run(void);

  void Worker(void);
  void RecoverLoop(void);

  void queue_binaries(void);
  bool pop_binary(binary_index_t &out);
};

JOVE_REGISTER_TOOL("dig", CodeDigger);

void CodeDigger::queue_binaries(void) {
  Q.clear();
  Q.reserve(decompilation.Binaries.size());

  if (is_binary_index_valid(SingleBinaryIndex)) {
    Q.push_back(SingleBinaryIndex);
    return;
  }

  for_each_binary(decompilation, [&](binary_t &binary) {
    if (binary.IsVDSO)
      return;
    if (binary.IsDynamicLinker)
      return;

    binary_index_t BIdx = index_of_binary(binary, decompilation);
    Q.push_back(BIdx);
  });
}

int CodeDigger::Run(void) {
  klee_path = (boost::dll::program_location().parent_path().parent_path().parent_path() /
               "klee" / "build" / "bin" / "klee")
                  .string();
  if (!fs::exists(klee_path)) {
    WithColor::error() << "could not find klee at " << klee_path << '\n';
    return 1;
  }

  ReadDecompilationFromFile(opts.jv, decompilation);

  //
  // operate on single binary? (cmdline)
  //
  if (!opts.Binary.empty()) {
    binary_index_t BinaryIndex = invalid_binary_index;

    for (binary_index_t BIdx = 0; BIdx < decompilation.Binaries.size(); ++BIdx) {
      const binary_t &binary = decompilation.Binaries[BIdx];
      if (binary.Path.find(opts.Binary) == std::string::npos)
        continue;

      BinaryIndex = BIdx;
      break;
    }

    if (BinaryIndex == invalid_binary_index) {
      WithColor::error() << llvm::formatv("failed to find binary \"{0}\"\n",
                                          opts.Binary);
      return 1;
    }

    SingleBinaryIndex = BinaryIndex;
  }

  for_each_binary(decompilation, [&](binary_t &binary) {
    llvm::StringRef Buffer(reinterpret_cast<char *>(&binary.Data[0]),
                           binary.Data.size());
    llvm::StringRef Identifier(binary.Path);

    llvm::Expected<std::unique_ptr<obj::Binary>> BinOrErr =
        obj::createBinary(llvm::MemoryBufferRef(Buffer, Identifier));
    if (!BinOrErr) {
      if (!binary.IsVDSO)
        HumanOut() << llvm::formatv("failed to create binary from {0}\n", binary.Path);
      return;
    }

    std::unique_ptr<obj::Binary> &BinRef = BinOrErr.get();

    assert(llvm::isa<ELFO>(BinRef.get()));
    ELFO &O = *llvm::cast<ELFO>(BinRef.get());

    TheTriple = O.makeTriple();
    Features = O.getFeatures();

    const ELFF &E = *O.getELFFile();

    auto &SectsStartAddr = state_for_binary(binary).SectsStartAddr;
    auto &SectsEndAddr   = state_for_binary(binary).SectsEndAddr;

    llvm::Expected<Elf_Shdr_Range> ExpectedSections = E.sections();
    if (ExpectedSections && !(*ExpectedSections).empty()) {
      tcg_uintptr_t minAddr = std::numeric_limits<tcg_uintptr_t>::max(),
                    maxAddr = 0;

      for (const Elf_Shdr &Sec : *ExpectedSections) {
        if (!(Sec.sh_flags & llvm::ELF::SHF_ALLOC))
          continue;

        llvm::Expected<llvm::StringRef> name = E.getSectionName(&Sec);

        if (!name)
          continue;

        if ((Sec.sh_flags & llvm::ELF::SHF_TLS) &&
            *name == std::string(".tbss"))
          continue;

        if (!Sec.sh_size)
          continue;

        minAddr = std::min<tcg_uintptr_t>(minAddr, Sec.sh_addr);
        maxAddr = std::max<tcg_uintptr_t>(maxAddr, Sec.sh_addr + Sec.sh_size);
      }

      SectsStartAddr = minAddr;
      SectsEndAddr = maxAddr;
    } else {
      llvm::SmallVector<const Elf_Phdr *, 4> LoadSegments;

      auto ProgramHeadersOrError = E.program_headers();
      if (!ProgramHeadersOrError)
        abort();

      for (const Elf_Phdr &Phdr : *ProgramHeadersOrError) {
        if (Phdr.p_type != llvm::ELF::PT_LOAD)
          continue;

        LoadSegments.push_back(&Phdr);
      }

      assert(!LoadSegments.empty());

      std::stable_sort(LoadSegments.begin(),
                       LoadSegments.end(),
                       [](const Elf_Phdr *A,
                          const Elf_Phdr *B) {
                         return A->p_vaddr < B->p_vaddr;
                       });

      SectsStartAddr = LoadSegments.front()->p_vaddr;
      SectsEndAddr = LoadSegments.back()->p_vaddr + LoadSegments.back()->p_memsz;
    }
  });

  // Initialize targets and assembly printers/parsers.
  llvm::InitializeAllTargets();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllAsmPrinters();
  llvm::InitializeAllAsmParsers();
  llvm::InitializeAllDisassemblers();

  //
  // initialize the LLVM objects necessary for disassembling instructions
  //
  std::string ArchName;
  std::string Error;

  this->TheTarget =
      llvm::TargetRegistry::lookupTarget(ArchName, TheTriple, Error);
  if (!TheTarget) {
    HumanOut() << "failed to lookup target: " << Error << '\n';
    return 1;
  }

  std::string TripleName = TheTriple.getTriple();
  std::string MCPU;

  MRI.reset(TheTarget->createMCRegInfo(TripleName));
  if (!MRI) {
    HumanOut() << "no register info for target\n";
    return 1;
  }

  llvm::MCTargetOptions Options;
  AsmInfo.reset(TheTarget->createMCAsmInfo(*MRI, TripleName, Options));
  if (!AsmInfo) {
    HumanOut() << "no assembly info\n";
    return 1;
  }

  STI.reset(TheTarget->createMCSubtargetInfo(TripleName, MCPU, Features.getString()));
  if (!STI) {
    HumanOut() << "no subtarget info\n";
    return 1;
  }

  MII.reset(TheTarget->createMCInstrInfo());
  if (!MII) {
    HumanOut() << "no instruction info\n";
    return 1;
  }

  llvm::MCObjectFileInfo MOFI;

  MCCtx = std::make_unique<llvm::MCContext>(AsmInfo.get(), MRI.get(), &MOFI);

  DisAsm.reset(TheTarget->createMCDisassembler(*STI, *MCCtx));
  if (!DisAsm) {
    HumanOut() << "no disassembler for target\n";
    return 1;
  }

  IP.reset(TheTarget->createMCInstPrinter(llvm::Triple(TripleName),
                                          AsmInfo->getAssemblerDialect(),
                                          *AsmInfo, *MII, *MRI));
  if (!IP) {
    HumanOut() << "no instruction printer\n";
    return 1;
  }

  Recovery = std::make_unique<CodeRecovery>(
      decompilation, disas_t(*DisAsm, std::cref(*STI), *IP));

  //
  // prepare to process the binaries by creating a unique temporary directory
  //
  {
    static char tmpdir[] = {'/', 't', 'm', 'p', '/', 'X',
                            'X', 'X', 'X', 'X', 'X', '\0'};

    if (!mkdtemp(tmpdir)) {
      int err = errno;
      WithColor::error() << "mkdtemp failed : " << strerror(err) << '\n';
      return 1;
    }

    tmp_dir = fs::path(tmpdir);

    HumanOut() << llvm::formatv("Temporary directory: {0}\n", tmp_dir.string());
  }
  assert(fs::exists(tmp_dir) && fs::is_directory(tmp_dir));

  int pipefd[2];
  if (pipe(pipefd) < 0) {
    int err = errno;
    WithColor::error() << llvm::formatv("pipe failed: {0}\n", strerror(err));
    return 1;
  }

  pipe_rdfd = pipefd[0];
  pipe_wrfd = pipefd[1];

  std::thread recover_thread(&CodeDigger::RecoverLoop, this);

  if (!opts.Verbose)
    WithColor::note() << llvm::formatv(
        "Generating LLVM and running KLEE on {0} binaries...",
        decompilation.Binaries.size() - 1);

  queue_binaries();
  {
    auto t1 = std::chrono::high_resolution_clock::now();

    //
    // run jove-llvm on all DSOs
    //
    {
      std::vector<std::thread> workers;

      unsigned N = opts.Threads;

      workers.reserve(N);
      for (unsigned i = 0; i < N; ++i)
        workers.push_back(std::thread(&CodeDigger::Worker, this));

      for (std::thread &t : workers)
        t.join();
    }

    auto t2 = std::chrono::high_resolution_clock::now();

    if (worker_failed.load())
      return 1;

    std::chrono::duration<double> s_double = t2 - t1;

    if (!opts.Verbose)
      llvm::errs() << llvm::formatv(" {0} s\n", s_double.count());
  }

  close(pipe_wrfd);
  recover_thread.join();

  if (opts.NoSave)
    return 0;

  if (opts.Verbose)
    WithColor::note() << "writing decompilation...\n";

  for_each_function(decompilation,
                    [](function_t &f, binary_t b) { f.InvalidateAnalysis(); });

  if (!opts.jv.empty())
    WriteDecompilationToFile(opts.jv, decompilation);

  return 0;
}

void CodeDigger::RecoverLoop(void) {
  std::vector<std::set<std::pair<basic_block_index_t, uint64_t>>> records;
  records.resize(decompilation.Binaries.size());

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

    binary_t &binary = decompilation.Binaries.at(BIdx);
    uint64_t Addr = Off + state_for_binary(binary).SectsStartAddr;

    {
      auto &bin_records = records.at(BIdx);
      if (bin_records.find(std::make_pair(BBIdx, Addr)) != bin_records.end())
        continue;

      bin_records.emplace(BBIdx, Addr);
    }

    if (opts.Verbose)
      HumanOut() << llvm::formatv("RecoverLoop: record: {0:x} @ ({1}, {2})\n",
                                  Addr, BIdx, BBIdx);

#if 0
    {
      tcg_uintptr_t IndJmpAddr =
          Recovery->bin_state_vec.at(BIdx).block_term_addr_vec.at(BBIdx);
      if (Addr < IndJmpAddr) {
        WithColor::warning() << llvm::formatv("({0},{1}): {2:x} -> {3:x}\n",
                                            BIdx, BBIdx, IndJmpAddr, Addr);
      }
    }
#endif

    if (!(Addr >= state_for_binary(binary).SectsStartAddr &&
          Addr < state_for_binary(binary).SectsEndAddr)) {
      if (opts.Verbose)
        WithColor::error() << llvm::formatv("CodeDigger: invalid target {0:x}\n", Off);
      continue;
    }

    try {
      std::string msg = Recovery->RecoverBasicBlock(BIdx, BBIdx, Addr);

      if (!msg.empty())
        HumanOut() << msg << '\n';
    } catch (const std::exception &e) {
      WithColor::error() << llvm::formatv("CodeDigger: {0} ({1},{2}): {3:x}\n",
                                          e.what(), BIdx, BBIdx, Addr);
    }
  }

  close(pipe_rdfd);
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

void CodeDigger::Worker(void) {
  binary_index_t BIdx = invalid_binary_index;
  while (pop_binary(BIdx)) {
    binary_t &binary = decompilation.Binaries.at(BIdx);

    // make sure the path is absolute
    assert(binary.Path.at(0) == '/');

    const fs::path chrooted_path = tmp_dir / binary.Path;
    fs::create_directories(chrooted_path.parent_path());

    std::string binary_filename = fs::path(binary.Path).filename().string();

    std::string bcfp(chrooted_path.string() + ".bc");
    std::string mapfp(chrooted_path.string() + ".map"); /* XXX */

    //
    // run jove-llvm
    //
    pid_t pid = fork();
    if (!pid) {
      IgnoreCtrlC();
      close(pipe_rdfd);
      close(pipe_wrfd);

      std::string BIdx_arg(std::to_string(BIdx));

      std::vector<const char *> arg_vec = {
        "-o", bcfp.c_str(),
        "--version-script", mapfp.c_str(),

        "--binary-index", BIdx_arg.c_str(),

        "-d", opts.jv.c_str(),

#if 0
        "--inline-helpers",
#endif
#if 0
        "--optimize"
#endif
      };

      if (opts.Verbose)
        print_tool_command("llvm", arg_vec);

      {
        std::string stdoutfp = bcfp + ".stdout.llvm.txt";
        int stdoutfd = open(stdoutfp.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0666);
        dup2(stdoutfd, STDOUT_FILENO);
        close(stdoutfd);
      }

      {
        std::string stderrfp = bcfp + ".stderr.llvm.txt";
        int stderrfd = open(stderrfp.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0666);
        dup2(stderrfd, STDERR_FILENO);
        close(stderrfd);
      }

      close(STDIN_FILENO);
      exec_tool("llvm", arg_vec);

      int err = errno;
      HumanOut() << llvm::formatv("execve failed: {0}\n", strerror(err));
      exit(1);
    }

    //
    // check exit code
    //
    if (int ret = WaitForProcessToExit(pid)) {
      worker_failed.store(true);
      WithColor::error() << llvm::formatv("jove-llvm failed on {0}: see {1}\n",
                                          binary_filename,
                                          bcfp + ".stderr.txt");
      continue;
    }

    assert(fs::exists(bcfp));

    //
    // run klee
    //
    pid = fork();
    if (!pid) {
      IgnoreCtrlC();
      close(pipe_rdfd);

      std::vector<const char *> arg_vec = {
        klee_path.c_str(),

        "--entry-point=_jove_begin",
        "--solver-backend=stp",
        "--write-no-tests",
        "--output-stats=0",
        "--output-istats=0",
        "--check-div-zero=0",
        "--check-overshift=0",
      };

      std::string out_dir_arg = "--jove-output-dir=" + tmp_dir.string();
      arg_vec.push_back(out_dir_arg.c_str());

      std::string pipefd_arg = "--jove-pipefd=" + std::to_string(pipe_wrfd);
      arg_vec.push_back(pipefd_arg.c_str());

      std::string bin_index_arg = "--jove-binary-index=" + std::to_string(BIdx);
      arg_vec.push_back(bin_index_arg.c_str());

      std::string sects_start_arg =
          "--jove-sects-start-addr=" +
          std::to_string(state_for_binary(binary).SectsStartAddr);
      arg_vec.push_back(sects_start_arg.c_str());

      std::string sects_end_arg =
          "--jove-sects-end-addr=" +
          std::to_string(state_for_binary(binary).SectsEndAddr);
      arg_vec.push_back(sects_end_arg.c_str());

      std::string path_length_arg =
          "--jove-path-length=" + std::to_string(opts.PathLength);
      arg_vec.push_back(path_length_arg.c_str());

      arg_vec.push_back(bcfp.c_str());
      arg_vec.push_back(nullptr);

      if (opts.Verbose)
        print_command(&arg_vec[0]);

      {
        std::string stdoutfp = bcfp + ".stdout.klee.txt";
        int stdoutfd = open(stdoutfp.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0666);
        dup2(stdoutfd, STDOUT_FILENO);
        close(stdoutfd);
      }

      {
        std::string stderrfp = bcfp + ".stderr.klee.txt";
        int stderrfd = open(stderrfp.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0666);
        dup2(stderrfd, STDERR_FILENO);
        close(stderrfd);
      }

      close(STDIN_FILENO);
      execve(klee_path.c_str(), const_cast<char **>(&arg_vec[0]), ::environ);

      int err = errno;
      HumanOut() << llvm::formatv("execve failed: {0}\n", strerror(err));
      exit(1);
    }

    //
    // check exit code
    //
    if (int ret = WaitForProcessToExit(pid)) {
      worker_failed.store(true);
      WithColor::error() << llvm::formatv("klee failed on {0}: see {1}\n",
                                          binary_filename,
                                          bcfp + ".stderr.klee.txt");
    }
  }
}

unsigned num_cpus(void) {
  cpu_set_t cpu_mask;
  if (sched_getaffinity(0, sizeof(cpu_mask), &cpu_mask) < 0) {
    WithColor::error() << "sched_getaffinity failed : " << strerror(errno)
                       << '\n';
    abort();
  }

  return CPU_COUNT(&cpu_mask);
}

}
