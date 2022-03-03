#include <llvm/Object/ELFObjectFile.h>
#include <boost/icl/split_interval_map.hpp>

#define JOVE_EXTRA_BIN_PROPERTIES                                              \
  bbmap_t bbmap;                                                               \
  fnmap_t fnmap;                                                               \
                                                                               \
  std::unique_ptr<llvm::object::Binary> ObjectFile;

#include "tcgcommon.hpp"

#include <tuple>
#include <numeric>
#include <memory>
#include <sstream>
#include <fstream>
#include <cinttypes>
#include <array>
#include <boost/filesystem.hpp>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/Support/DataExtractor.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCObjectFileInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/DataTypes.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/ScopedPrinter.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/WithColor.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <asm/unistd.h>
#include <sys/uio.h>
#if !defined(__x86_64__) && defined(__i386__)
#include <asm/ldt.h>
#endif

#include "jove/jove.h"
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/dynamic_bitset.hpp>
#include <boost/format.hpp>
#include <boost/graph/adj_list_serialize.hpp>
#include <boost/graph/depth_first_search.hpp>
#include <boost/icl/interval_set.hpp>
#include <boost/icl/split_interval_map.hpp>
#include <boost/preprocessor/cat.hpp>
#include <boost/preprocessor/repetition/repeat.hpp>
#include <boost/preprocessor/repetition/repeat_from_to.hpp>
#include <boost/serialization/bitset.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>

#include "jove_macros.h"

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace opts {
static cl::OptionCategory JoveCategory("Specific Options");

static cl::opt<std::string> jv("decompilation", cl::desc("Jove decompilation"),
                               cl::Required, cl::value_desc("filename"),
                               cl::cat(JoveCategory));

static cl::alias jvAlias("d", cl::desc("Alias for -decompilation."),
                         cl::aliasopt(jv), cl::cat(JoveCategory));

static cl::list<std::string>
    DynTarget("dyn-target", cl::CommaSeparated,
              cl::value_desc("CallerBIdx,CallerBBIdx,CalleeBIdx,CalleeFIdx"),
              cl::desc("New target for indirect branch"),
              cl::cat(JoveCategory));

static cl::list<std::string>
    BasicBlock("basic-block", cl::CommaSeparated,
               cl::value_desc("IndBrBIdx,IndBrBBIdx,FileAddr"),
               cl::desc("New target for indirect branch"),
               cl::cat(JoveCategory));

static cl::list<std::string> Returns("returns", cl::CommaSeparated,
                                     cl::value_desc("CallBIdx,CallBBIdx"),
                                     cl::desc("A call has returned"),
                                     cl::cat(JoveCategory));

static cl::list<std::string>
    Function("function", cl::CommaSeparated,
               cl::value_desc("IndCallBIdx,IndCallBBIdx,CalleeBIdx,CalleeAddr"),
               cl::desc("New target for indirect branch that is a function"),
               cl::cat(JoveCategory));

static cl::list<std::string>
    ABI("abi", cl::CommaSeparated,
        cl::value_desc("FuncBIdx,FIdx"),
        cl::desc("Specified function is an ABI"),
        cl::cat(JoveCategory));

} // namespace opts

namespace jove {

static int recover(void);

}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::HideUnrelatedOptions({&opts::JoveCategory, &llvm::ColorCategory});
  cl::AddExtraVersionPrinter([](llvm::raw_ostream &OS) -> void {
    OS << "jove version " JOVE_VERSION "\n";
  });
  cl::ParseCommandLineOptions(argc, argv, "Jove Recover\n");

  {
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = SIG_IGN;

    sigaction(SIGINT, &sa, nullptr);
  }

  if (!fs::exists(opts::jv)) {
    WithColor::error() << "decompilation does not exist\n";
    return 1;
  }

  if (opts::DynTarget.size() > 0 && opts::DynTarget.size() != 4) {
    WithColor::error() << "-dyn-target: invalid tuple\n";
    return 1;
  }

  if (opts::BasicBlock.size() > 0 && opts::BasicBlock.size() != 3) {
    WithColor::error() << "-basic-block: invalid tuple\n";
    return 1;
  }

  if (opts::Function.size() > 0 && opts::Function.size() != 4) {
    WithColor::error() << "-function: invalid tuple\n";
    return 1;
  }

  if (opts::ABI.size() > 0 && opts::ABI.size() != 2) {
    WithColor::error() << "-abi: invalid tuple\n";
    return 1;
  }

  return jove::recover();
}

namespace jove {

typedef boost::format fmt;

static decompilation_t Decompilation;

static void InvalidateAllFunctionAnalyses(void) {
  for (binary_t &binary : Decompilation.Binaries)
    for (function_t &f : binary.Analysis.Functions)
      f.InvalidateAnalysis();
}

#include "elf.hpp"
#include "translate.hpp"

static std::string DescribeFunction(binary_index_t, function_index_t);
static std::string DescribeBasicBlock(binary_index_t, basic_block_index_t);

static int await_process_completion(pid_t);

int recover(void) {
  bool git = fs::is_directory(opts::jv);

  //
  // parse the existing decompilation file
  //
  {
    std::string path = fs::is_directory(opts::jv)
                           ? (opts::jv + "/decompilation.jv")
                           : opts::jv;

    std::ifstream ifs(path);

    boost::archive::text_iarchive ia(ifs);
    ia >> Decompilation;
  }

  tiny_code_generator_t tcg;

  // Initialize targets and assembly printers/parsers.
  llvm::InitializeAllTargets();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllAsmPrinters();
  llvm::InitializeAllAsmParsers();
  llvm::InitializeAllDisassemblers();

  llvm::Triple TheTriple;
  llvm::SubtargetFeatures Features;

  //
  // initialize state associated with every binary
  //
  for (binary_index_t i = 0; i < Decompilation.Binaries.size(); ++i) {
    binary_t &b = Decompilation.Binaries[i];

    construct_fnmap(Decompilation, b, b.fnmap);
    construct_bbmap(Decompilation, b, b.bbmap);

    //
    // build section map
    //
    llvm::StringRef Buffer(reinterpret_cast<char *>(&b.Data[0]),
                           b.Data.size());
    llvm::StringRef Identifier(b.Path);
    llvm::MemoryBufferRef MemBuffRef(Buffer, Identifier);

    llvm::Expected<std::unique_ptr<obj::Binary>> BinOrErr =
        obj::createBinary(MemBuffRef);
    if (!BinOrErr) {
      if (!b.IsVDSO)
        WithColor::warning()
            << llvm::formatv("failed to create binary from {0}\n", b.Path);

      continue;
    }

    std::unique_ptr<obj::Binary> &BinRef = BinOrErr.get();

    b.ObjectFile = std::move(BinRef);

    if (!llvm::isa<ELFO>(b.ObjectFile.get())) {
      WithColor::error() << b.Path << " is not ELF of expected type\n";
      return 1;
    }

    assert(llvm::isa<ELFO>(b.ObjectFile.get()));
    ELFO &O = *llvm::cast<ELFO>(b.ObjectFile.get());

    TheTriple = O.makeTriple();
    Features = O.getFeatures();
  }

  //
  // initialize the LLVM objects necessary for disassembling instructions
  //
  std::string ArchName;
  std::string Error;

  const llvm::Target *TheTarget =
      llvm::TargetRegistry::lookupTarget(ArchName, TheTriple, Error);
  if (!TheTarget) {
    WithColor::error() << "failed to lookup target: " << Error << '\n';
    return 1;
  }

  std::string TripleName = TheTriple.getTriple();
  std::string MCPU;

  std::unique_ptr<const llvm::MCRegisterInfo> MRI(
      TheTarget->createMCRegInfo(TripleName));
  if (!MRI) {
    WithColor::error() << "no register info for target\n";
    return 1;
  }

  llvm::MCTargetOptions Options;
  std::unique_ptr<const llvm::MCAsmInfo> AsmInfo(
      TheTarget->createMCAsmInfo(*MRI, TripleName, Options));
  if (!AsmInfo) {
    WithColor::error() << "no assembly info\n";
    return 1;
  }

  std::unique_ptr<const llvm::MCSubtargetInfo> STI(
      TheTarget->createMCSubtargetInfo(TripleName, MCPU,
                                       Features.getString()));
  if (!STI) {
    WithColor::error() << "no subtarget info\n";
    return 1;
  }

  std::unique_ptr<const llvm::MCInstrInfo> MII(
      TheTarget->createMCInstrInfo());
  if (!MII) {
    WithColor::error() << "no instruction info\n";
    return 1;
  }

  llvm::MCObjectFileInfo MOFI;
  llvm::MCContext Ctx(AsmInfo.get(), MRI.get(), &MOFI);
  // FIXME: for now initialize MCObjectFileInfo with default values
  MOFI.InitMCObjectFileInfo(llvm::Triple(TripleName), false, Ctx);

  std::unique_ptr<llvm::MCDisassembler> DisAsm(
      TheTarget->createMCDisassembler(*STI, Ctx));
  if (!DisAsm) {
    WithColor::error() << "no disassembler for target\n";
    return 1;
  }

  int AsmPrinterVariant = 1 /* AsmInfo->getAssemblerDialect() */; // Intel
  std::unique_ptr<llvm::MCInstPrinter> IP(TheTarget->createMCInstPrinter(
      llvm::Triple(TripleName), AsmPrinterVariant, *AsmInfo, *MII, *MRI));
  if (!IP) {
    WithColor::error() << "no instruction printer\n";
    return 1;
  }

  disas_t dis(*DisAsm, std::cref(*STI), *IP);

  std::string msg;

  if (opts::DynTarget.size() > 0) {
    struct {
      binary_index_t BIdx;
      basic_block_index_t BBIdx;
    } Caller;

    struct {
      binary_index_t BIdx;
      function_index_t FIdx;
    } Callee;

    Caller.BIdx = strtoul(opts::DynTarget[0].c_str(), nullptr, 10);
    Caller.BBIdx = strtoul(opts::DynTarget[1].c_str(), nullptr, 10);

    Callee.BIdx = strtoul(opts::DynTarget[2].c_str(), nullptr, 10);
    Callee.FIdx = strtoul(opts::DynTarget[3].c_str(), nullptr, 10);

    // Check that Callee is valid
    (void)Decompilation.Binaries.at(Callee.BIdx)
             .Analysis.Functions.at(Callee.FIdx);

    binary_t &CallerBinary = Decompilation.Binaries.at(Caller.BIdx);
    auto &ICFG = CallerBinary.Analysis.ICFG;
    basic_block_t CallerBB = boost::vertex(Caller.BBIdx, ICFG);
    bool wasDynTargetsEmpty = ICFG[CallerBB].DynTargets.empty();

    bool isNewTarget = ICFG[CallerBB]
                           .DynTargets.insert({Callee.BIdx, Callee.FIdx})
                           .second;

    //
    // check to see if this is an ambiguous indirect jump XXX duplicated code with jove-bootstrap
    //
    if (ICFG[CallerBB].Term.Type == TERMINATOR::INDIRECT_JUMP &&
        IsDefinitelyTailCall(ICFG, CallerBB) &&
        boost::out_degree(CallerBB, ICFG) > 0) {
      //
      // we thought this was a goto, but now we know it's definitely a tail call.
      // translate all sucessors as functions, then store them into the dynamic
      // targets set for this bb. afterwards, delete the edges in the ICFG that
      // would originate from this basic block.
      //
      icfg_t::out_edge_iterator e_it, e_it_end;
      for (std::tie(e_it, e_it_end) = boost::out_edges(CallerBB, ICFG);
           e_it != e_it_end; ++e_it) {
        control_flow_t cf(*e_it);

        basic_block_t succ = boost::target(cf, ICFG);

        function_index_t FIdx =
            translate_function(CallerBinary, tcg, dis, ICFG[succ].Addr,
                               CallerBinary.fnmap,
                               CallerBinary.bbmap);
        assert(is_function_index_valid(FIdx));
        ICFG[CallerBB].DynTargets.insert({Caller.BIdx, FIdx});
      }

      boost::clear_out_edges(CallerBB, ICFG);
    }

    msg = (fmt(__ANSI_CYAN "(call) %s -> %s" __ANSI_NORMAL_COLOR) %
           DescribeBasicBlock(Caller.BIdx, Caller.BBIdx) %
           DescribeFunction(Callee.BIdx, Callee.FIdx))
              .str();
  } else if (opts::BasicBlock.size() > 0) {
    struct {
      binary_index_t BIdx;
      basic_block_index_t BBIdx;

      uint64_t Target;
    } IndBr;

    IndBr.BIdx = strtoul(opts::BasicBlock[0].c_str(), nullptr, 10);
    IndBr.BBIdx = strtoul(opts::BasicBlock[1].c_str(), nullptr, 10);

    IndBr.Target = strtoul(opts::BasicBlock[2].c_str(), nullptr, 10);

    binary_t &indbr_binary = Decompilation.Binaries.at(IndBr.BIdx);
    auto &ICFG = indbr_binary.Analysis.ICFG;

    basic_block_t bb = boost::vertex(IndBr.BBIdx, ICFG);

    uintptr_t TermAddr = ICFG[bb].Term.Addr;

    assert(ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP);
    basic_block_index_t target_bb_idx =
        translate_basic_block(indbr_binary, tcg, dis, IndBr.Target,
                              indbr_binary.fnmap,
                              indbr_binary.bbmap);
    if (!is_basic_block_index_valid(target_bb_idx)) {
      WithColor::error() << llvm::formatv(
          "failed to recover control flow -> {0:x}\n", IndBr.Target);
      return 1;
    }

    basic_block_t target_bb = boost::vertex(target_bb_idx, ICFG);

    auto &bbmap = indbr_binary.bbmap;
    {
      auto it = bbmap.find(TermAddr);
      assert(it != bbmap.end());

      basic_block_index_t bbidx = (*it).second - 1;
      bb = boost::vertex(bbidx, ICFG);
    }

    assert(ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP);

    bool isNewTarget = boost::add_edge(bb, target_bb, ICFG).second;

    msg = (fmt(__ANSI_GREEN "(goto) %s -> %s" __ANSI_NORMAL_COLOR) %
           DescribeBasicBlock(IndBr.BIdx, IndBr.BBIdx) %
           DescribeBasicBlock(IndBr.BIdx, target_bb_idx))
              .str();
  } else if (opts::Function.size() > 0) {
    assert(opts::Function.size() == 4);

    struct {
      binary_index_t BIdx;
      basic_block_index_t BBIdx;
    } IndCall;

    struct {
      binary_index_t BIdx;
      target_ulong FileAddr;
    } Callee;

    IndCall.BIdx  = strtoul(opts::Function[0].c_str(), nullptr, 10);
    IndCall.BBIdx = strtoul(opts::Function[1].c_str(), nullptr, 10);

    Callee.BIdx     = strtoul(opts::Function[2].c_str(), nullptr, 10);
    Callee.FileAddr = strtoul(opts::Function[3].c_str(), nullptr, 10);

    binary_t &CalleeBinary = Decompilation.Binaries.at(Callee.BIdx);

    function_index_t TargetFIdx =
        translate_function(CalleeBinary, tcg, dis, Callee.FileAddr,
                           CalleeBinary.fnmap,
                           CalleeBinary.bbmap);
    if (!is_function_index_valid(TargetFIdx)) {
      WithColor::error() << llvm::formatv(
          "failed to translate indirect call target {0:x}\n", Callee.FileAddr);
      return 1;
    }

    auto &ICFG = Decompilation.Binaries.at(IndCall.BIdx).Analysis.ICFG;

    basic_block_t bb = boost::vertex(IndCall.BBIdx, ICFG);

    bool wasDynTargetsEmpty =
        ICFG[boost::vertex(IndCall.BBIdx, ICFG)].DynTargets.empty();


    bool isNewTarget = ICFG[boost::vertex(IndCall.BBIdx, ICFG)]
                           .DynTargets.insert({Callee.BIdx, TargetFIdx})
                           .second;

    msg = (fmt(__ANSI_CYAN "(call*) %s -> %s" __ANSI_NORMAL_COLOR) %
           DescribeBasicBlock(IndCall.BIdx, IndCall.BBIdx) %
           DescribeFunction(Callee.BIdx, TargetFIdx))
              .str();
  } else if (opts::ABI.size() > 0) {
    assert(opts::ABI.size() == 2);

    dynamic_target_t NewABI = {strtoul(opts::ABI[0].c_str(), nullptr, 10),
                               strtoul(opts::ABI[1].c_str(), nullptr, 10)};

    function_t &f = function_of_target(NewABI, Decompilation);

    if (f.IsABI) {
      WithColor::warning() << "given function already marked as an ABI\n";
      return 1;
    }

    f.IsABI = true;

    msg = (fmt(__ANSI_BLUE "[ABI] %s" __ANSI_NORMAL_COLOR) %
           DescribeFunction(NewABI.first, NewABI.second))
              .str();
  } else if (opts::Returns.size() > 0) {
    struct {
      binary_index_t BIdx;
      basic_block_index_t BBIdx;
    } Call;

    Call.BIdx = strtoul(opts::Returns[0].c_str(), nullptr, 10);
    Call.BBIdx = strtoul(opts::Returns[1].c_str(), nullptr, 10);

    binary_t &CallBinary = Decompilation.Binaries.at(Call.BIdx);
    auto &ICFG = CallBinary.Analysis.ICFG;

    basic_block_t bb = boost::vertex(Call.BBIdx, ICFG);

    uintptr_t NextAddr = ICFG[bb].Addr + ICFG[bb].Size;

#if defined(TARGET_MIPS32) || defined(TARGET_MIPS64)
    NextAddr += 4; /* delay slot */
#endif

    uintptr_t TermAddr = ICFG[bb].Term.Addr;

    bool isCall =
      ICFG[bb].Term.Type == TERMINATOR::CALL;
    bool isIndirectCall =
      ICFG[bb].Term.Type == TERMINATOR::INDIRECT_CALL;

    assert(isCall || isIndirectCall);
    assert(TermAddr);

    if (isCall)
      ICFG[bb].Term._call.Returns = true;
    if (isIndirectCall)
      ICFG[bb].Term._indirect_call.Returns = true;

    unsigned deg = boost::out_degree(bb, ICFG);
    if (deg != 0) {
      WithColor::warning() << llvm::formatv("unexpected out degree {0}\n", deg);
      return 1;
    }

#if 0
    assert(CallBinary.bbmap.find(NextAddr) == CallBinary.bbmap.end());
#endif

    basic_block_index_t next_bb_idx =
      translate_basic_block(CallBinary, tcg, dis, NextAddr,
                            CallBinary.fnmap,
                            CallBinary.bbmap);

    auto &bbmap = CallBinary.bbmap;
    {
      auto it = bbmap.find(TermAddr);
      assert(it != bbmap.end());

      basic_block_index_t bbidx = (*it).second - 1;
      bb = boost::vertex(bbidx, ICFG);
    }

    if (ICFG[bb].Term.Type == TERMINATOR::CALL &&
        is_function_index_valid(ICFG[bb].Term._call.Target)) {
      function_t &f = CallBinary.Analysis.Functions.at(ICFG[bb].Term._call.Target);
      f.Returns = true;
    }

    assert(is_basic_block_index_valid(next_bb_idx));
    basic_block_t next_bb = boost::vertex(next_bb_idx, ICFG);

    //assert(boost::out_degree(bb, ICFG) == 0);
    bool isNewTarget = boost::add_edge(bb, next_bb, ICFG).second;

    msg = (fmt(__ANSI_YELLOW "(returned) %s" __ANSI_NORMAL_COLOR) %
           DescribeBasicBlock(Call.BIdx, next_bb_idx))
              .str();
  } else {
    WithColor::error() << "no command provided\n";
    return 1;
  }

  assert(!msg.empty());
  llvm::outs() << msg << '\n';

  InvalidateAllFunctionAnalyses();

  //
  // write decompilation
  //
  {
    std::string path = fs::is_directory(opts::jv)
                           ? (opts::jv + "/decompilation.jv")
                           : opts::jv;

    std::ofstream ofs(path);

    boost::archive::text_oarchive oa(ofs);
    oa << Decompilation;
  }
  //
  // git commit
  //
  if (git) {
    pid_t pid = fork();
    if (!pid) { /* child */
      chdir(opts::jv.c_str());

      const char *argv[] = {"/usr/bin/git", "commit",    ".",
                            "-m",           msg.c_str(), nullptr};

      return execve(argv[0], const_cast<char **>(argv), ::environ);
    }

    if (int ret = await_process_completion(pid))
      return ret;
  }

  return 0;
}

int await_process_completion(pid_t pid) {
  int wstatus;
  do {
    if (waitpid(pid, &wstatus, WUNTRACED | WCONTINUED) < 0)
      abort();

    if (WIFEXITED(wstatus)) {
      //printf("exited, status=%d\n", WEXITSTATUS(wstatus));
      return WEXITSTATUS(wstatus);
    } else if (WIFSIGNALED(wstatus)) {
      //printf("killed by signal %d\n", WTERMSIG(wstatus));
      return 1;
    } else if (WIFSTOPPED(wstatus)) {
      //printf("stopped by signal %d\n", WSTOPSIG(wstatus));
      return 1;
    } else if (WIFCONTINUED(wstatus)) {
      //printf("continued\n");
    }
  } while (!WIFEXITED(wstatus) && !WIFSIGNALED(wstatus));

  abort();
}

template <typename GraphTy>
struct dfs_visitor : public boost::default_dfs_visitor {
  typedef typename GraphTy::vertex_descriptor VertTy;

  std::vector<VertTy> &out;

  dfs_visitor(std::vector<VertTy> &out) : out(out) {}

  void discover_vertex(VertTy v, const GraphTy &) const { out.push_back(v); }
};

std::string DescribeFunction(binary_index_t BIdx,
                             function_index_t FIdx) {
  auto &binary = Decompilation.Binaries.at(BIdx);
  function_t &f = binary.Analysis.Functions.at(FIdx);

  auto &ICFG = binary.Analysis.ICFG;
  uintptr_t Addr = ICFG[boost::vertex(f.Entry, ICFG)].Addr;

  return (fmt("%s+%#lx") % fs::path(binary.Path).filename().string() % Addr).str();
}

std::string DescribeBasicBlock(binary_index_t BIdx,
                               basic_block_index_t BBIdx) {
  auto &binary = Decompilation.Binaries.at(BIdx);

  auto &ICFG = binary.Analysis.ICFG;
  uintptr_t Addr = ICFG[boost::vertex(BBIdx, ICFG)].Addr;

  return (fmt("%s+%#lx") % fs::path(binary.Path).filename().string() % Addr).str();
}

void _qemu_log(const char *cstr) { llvm::errs() << cstr; }

}
