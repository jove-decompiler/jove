#include "tool.h"
#include "elf.h"
#include "explore.h"
#include <boost/filesystem.hpp>
#include <boost/format.hpp>
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
#include <llvm/Support/DataTypes.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/WithColor.h>
#include <numeric>
#include <sstream>
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

#include "jove_macros.h"

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

struct binary_state_t {
  bbmap_t bbmap;
  fnmap_t fnmap;

  std::unique_ptr<llvm::object::Binary> ObjectFile;
};

class RecoverTool : public Tool {
  struct Cmdline {
    cl::opt<std::string> jv;
    cl::alias jvAlias;

    cl::list<std::string> DynTarget;
    cl::list<std::string> BasicBlock;
    cl::list<std::string> Returns;
    cl::list<std::string> Function;
    cl::list<std::string> ABI;

    cl::opt<std::string> HumanOutput;
    cl::opt<bool> Silent;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : jv("decompilation", cl::desc("Jove decompilation"), cl::Required,
             cl::value_desc("filename"), cl::cat(JoveCategory)),

          jvAlias("d", cl::desc("Alias for -decompilation."), cl::aliasopt(jv),
                  cl::cat(JoveCategory)),

          DynTarget(
              "dyn-target", cl::CommaSeparated,
              cl::value_desc("CallerBIdx,CallerBBIdx,CalleeBIdx,CalleeFIdx"),
              cl::desc("New target for indirect branch"),
              cl::cat(JoveCategory)),

          BasicBlock("basic-block", cl::CommaSeparated,
                     cl::value_desc("IndBrBIdx,IndBrBBIdx,FileAddr"),
                     cl::desc("New target for indirect branch"),
                     cl::cat(JoveCategory)),

          Returns("returns", cl::CommaSeparated,
                  cl::value_desc("CallBIdx,CallBBIdx"),
                  cl::desc("A call has returned"), cl::cat(JoveCategory)),

          Function(
              "function", cl::CommaSeparated,
              cl::value_desc("IndCallBIdx,IndCallBBIdx,CalleeBIdx,CalleeAddr"),
              cl::desc("New target for indirect branch that is a function"),
              cl::cat(JoveCategory)),

          ABI("abi", cl::CommaSeparated, cl::value_desc("FuncBIdx,FIdx"),
              cl::desc("Specified function is an ABI"), cl::cat(JoveCategory)),

          HumanOutput("human-output",
                      cl::desc("Print messages to the given file path"),
                      cl::cat(JoveCategory)),

          Silent("silent",
                 cl::desc(
                     "Leave the stdout/stderr of the application undisturbed"),
                 cl::cat(JoveCategory)) {}

  } opts;

  decompilation_t Decompilation;

public:
  RecoverTool() : opts(JoveCategory) {}

  int Run(void);

  std::string DescribeFunction(binary_index_t, function_index_t);
  std::string DescribeBasicBlock(binary_index_t, basic_block_index_t);
};

JOVE_REGISTER_TOOL("recover", RecoverTool);

typedef boost::format fmt;

int RecoverTool::Run(void) {
  if (!fs::exists(opts.jv)) {
    WithColor::error() << "decompilation does not exist\n";
    return 1;
  }

  if (opts.DynTarget.size() > 0 && opts.DynTarget.size() != 4) {
    WithColor::error() << "-dyn-target: invalid tuple\n";
    return 1;
  }

  if (opts.BasicBlock.size() > 0 && opts.BasicBlock.size() != 3) {
    WithColor::error() << "-basic-block: invalid tuple\n";
    return 1;
  }

  if (opts.Function.size() > 0 && opts.Function.size() != 4) {
    WithColor::error() << "-function: invalid tuple\n";
    return 1;
  }

  if (opts.ABI.size() > 0 && opts.ABI.size() != 2) {
    WithColor::error() << "-abi: invalid tuple\n";
    return 1;
  }

  if (!opts.Silent) {
    if (!opts.HumanOutput.empty()) {
      HumanOutToFile(opts.HumanOutput);
    }
  }

  IgnoreCtrlC();

  bool git = fs::is_directory(opts.jv);
  std::string jvfp = git ? (opts.jv + "/decompilation.jv") : opts.jv;

  ReadDecompilationFromFile(jvfp, Decompilation);

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

    construct_fnmap(Decompilation, b, state_for_binary(b).fnmap);
    construct_bbmap(Decompilation, b, state_for_binary(b).bbmap);

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
        HumanOut()
            << llvm::formatv("failed to create binary from {0}\n", b.Path);

      continue;
    }

    std::unique_ptr<obj::Binary> &BinRef = BinOrErr.get();

    state_for_binary(b).ObjectFile = std::move(BinRef);

    if (!llvm::isa<ELFO>(state_for_binary(b).ObjectFile.get())) {
      HumanOut() << b.Path << " is not ELF of expected type\n";
      return 1;
    }

    assert(llvm::isa<ELFO>(state_for_binary(b).ObjectFile.get()));
    ELFO &O = *llvm::cast<ELFO>(state_for_binary(b).ObjectFile.get());

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
    HumanOut() << "failed to lookup target: " << Error << '\n';
    return 1;
  }

  std::string TripleName = TheTriple.getTriple();
  std::string MCPU;

  std::unique_ptr<const llvm::MCRegisterInfo> MRI(
      TheTarget->createMCRegInfo(TripleName));
  if (!MRI) {
    HumanOut() << "no register info for target\n";
    return 1;
  }

  llvm::MCTargetOptions Options;
  std::unique_ptr<const llvm::MCAsmInfo> AsmInfo(
      TheTarget->createMCAsmInfo(*MRI, TripleName, Options));
  if (!AsmInfo) {
    HumanOut() << "no assembly info\n";
    return 1;
  }

  std::unique_ptr<const llvm::MCSubtargetInfo> STI(
      TheTarget->createMCSubtargetInfo(TripleName, MCPU,
                                       Features.getString()));
  if (!STI) {
    HumanOut() << "no subtarget info\n";
    return 1;
  }

  std::unique_ptr<const llvm::MCInstrInfo> MII(
      TheTarget->createMCInstrInfo());
  if (!MII) {
    HumanOut() << "no instruction info\n";
    return 1;
  }

  llvm::MCObjectFileInfo MOFI;
  llvm::MCContext Ctx(AsmInfo.get(), MRI.get(), &MOFI);
  // FIXME: for now initialize MCObjectFileInfo with default values
  MOFI.InitMCObjectFileInfo(llvm::Triple(TripleName), false, Ctx);

  std::unique_ptr<llvm::MCDisassembler> DisAsm(
      TheTarget->createMCDisassembler(*STI, Ctx));
  if (!DisAsm) {
    HumanOut() << "no disassembler for target\n";
    return 1;
  }

  int AsmPrinterVariant = 1 /* AsmInfo->getAssemblerDialect() */; // Intel
  std::unique_ptr<llvm::MCInstPrinter> IP(TheTarget->createMCInstPrinter(
      llvm::Triple(TripleName), AsmPrinterVariant, *AsmInfo, *MII, *MRI));
  if (!IP) {
    HumanOut() << "no instruction printer\n";
    return 1;
  }

  disas_t dis(*DisAsm, std::cref(*STI), *IP);

  std::string msg;

  if (opts.DynTarget.size() > 0) {
    struct {
      binary_index_t BIdx;
      basic_block_index_t BBIdx;
    } Caller;

    struct {
      binary_index_t BIdx;
      function_index_t FIdx;
    } Callee;

    Caller.BIdx = strtoul(opts.DynTarget[0].c_str(), nullptr, 10);
    Caller.BBIdx = strtoul(opts.DynTarget[1].c_str(), nullptr, 10);

    Callee.BIdx = strtoul(opts.DynTarget[2].c_str(), nullptr, 10);
    Callee.FIdx = strtoul(opts.DynTarget[3].c_str(), nullptr, 10);

    // Check that Callee is valid
    (void)Decompilation.Binaries.at(Callee.BIdx)
             .Analysis.Functions.at(Callee.FIdx);

    binary_t &CallerBinary = Decompilation.Binaries.at(Caller.BIdx);
    binary_t &CalleeBinary = Decompilation.Binaries.at(Callee.BIdx);

    function_t &callee = CalleeBinary.Analysis.Functions.at(Callee.FIdx);

    auto &ICFG = CallerBinary.Analysis.ICFG;
    basic_block_t bb = boost::vertex(Caller.BBIdx, ICFG);

    tcg_uintptr_t TermAddr = ICFG[bb].Term.Addr;

    bool isNewTarget =
        ICFG[bb].DynTargets.insert({Callee.BIdx, Callee.FIdx}).second;

    //
    // check to see if this is an ambiguous indirect jump XXX duplicated code with jove-bootstrap
    //
    if (ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP &&
        IsDefinitelyTailCall(ICFG, bb) &&
        boost::out_degree(bb, ICFG) > 0) {
      //
      // we thought this was a goto, but now we know it's definitely a tail call.
      // translate all sucessors as functions, then store them into the dynamic
      // targets set for this bb. afterwards, delete the edges in the ICFG that
      // would originate from this basic block.
      //
      icfg_t::out_edge_iterator e_it, e_it_end;
      for (std::tie(e_it, e_it_end) = boost::out_edges(bb, ICFG);
           e_it != e_it_end; ++e_it) {
        control_flow_t cf(*e_it);

        basic_block_t succ = boost::target(cf, ICFG);

        function_index_t FIdx =
            explore_function(CallerBinary, *state_for_binary(CallerBinary).ObjectFile,
                             tcg, dis, ICFG[succ].Addr,
                             state_for_binary(CallerBinary).fnmap,
                             state_for_binary(CallerBinary).bbmap);
        assert(is_function_index_valid(FIdx));

        /* term bb may been split */
        bb = basic_block_at_address(TermAddr, CallerBinary, state_for_binary(CallerBinary).bbmap);
        ICFG[bb].DynTargets.insert({Caller.BIdx, FIdx});
      }

      boost::clear_out_edges(bb, ICFG);
    } else if (ICFG[bb].Term.Type == TERMINATOR::INDIRECT_CALL &&
               isNewTarget &&
               boost::out_degree(bb, ICFG) == 0 &&
               does_function_return(callee, CalleeBinary)) {
      //
      // this call instruction will return, so explore the return block
      //
      basic_block_index_t NextBBIdx =
          explore_basic_block(CallerBinary, *state_for_binary(CallerBinary).ObjectFile, tcg, dis,
                              ICFG[bb].Addr + ICFG[bb].Size + (unsigned)IsMIPSTarget * 4,
                              state_for_binary(CallerBinary).fnmap,
                              state_for_binary(CallerBinary).bbmap);

      assert(is_basic_block_index_valid(NextBBIdx));

      /* term bb may been split */
      bb = basic_block_at_address(TermAddr, CallerBinary, state_for_binary(CallerBinary).bbmap);
      assert(ICFG[bb].Term.Type == TERMINATOR::INDIRECT_CALL);

      boost::add_edge(bb, boost::vertex(NextBBIdx, ICFG), ICFG);
    }

    msg = (fmt(__ANSI_CYAN "(call) %s -> %s" __ANSI_NORMAL_COLOR) %
           DescribeBasicBlock(Caller.BIdx, Caller.BBIdx) %
           DescribeFunction(Callee.BIdx, Callee.FIdx))
              .str();
  } else if (opts.BasicBlock.size() > 0) {
    struct {
      binary_index_t BIdx;
      basic_block_index_t BBIdx;

      uint64_t Target;
    } IndBr;

    IndBr.BIdx = strtoul(opts.BasicBlock[0].c_str(), nullptr, 10);
    IndBr.BBIdx = strtoul(opts.BasicBlock[1].c_str(), nullptr, 10);

    IndBr.Target = strtoul(opts.BasicBlock[2].c_str(), nullptr, 10);

    binary_t &indbr_binary = Decompilation.Binaries.at(IndBr.BIdx);
    auto &ICFG = indbr_binary.Analysis.ICFG;

    basic_block_t bb = boost::vertex(IndBr.BBIdx, ICFG);

    tcg_uintptr_t TermAddr = ICFG[bb].Term.Addr;

    assert(ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP);
    basic_block_index_t target_bb_idx =
        explore_basic_block(indbr_binary, *state_for_binary(indbr_binary).ObjectFile,
                            tcg, dis, IndBr.Target,
                            state_for_binary(indbr_binary).fnmap,
                            state_for_binary(indbr_binary).bbmap);
    if (!is_basic_block_index_valid(target_bb_idx)) {
      HumanOut() << llvm::formatv(
          "failed to recover control flow -> {0:x}\n", IndBr.Target);
      return 1;
    }

    basic_block_t target_bb = boost::vertex(target_bb_idx, ICFG);

    /* term bb may been split */
    bb = basic_block_at_address(TermAddr, indbr_binary, state_for_binary(indbr_binary).bbmap);

    assert(ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP);

    bool isNewTarget = boost::add_edge(bb, target_bb, ICFG).second;

    msg = (fmt(__ANSI_GREEN "(goto) %s -> %s" __ANSI_NORMAL_COLOR) %
           DescribeBasicBlock(IndBr.BIdx, IndBr.BBIdx) %
           DescribeBasicBlock(IndBr.BIdx, target_bb_idx))
              .str();
  } else if (opts.Function.size() > 0) {
    assert(opts.Function.size() == 4);

    struct {
      binary_index_t BIdx;
      basic_block_index_t BBIdx;
    } IndCall;

    struct {
      binary_index_t BIdx;
      tcg_uintptr_t FileAddr;
    } Callee;

    IndCall.BIdx  = strtoul(opts.Function[0].c_str(), nullptr, 10);
    IndCall.BBIdx = strtoul(opts.Function[1].c_str(), nullptr, 10);

    Callee.BIdx     = strtoul(opts.Function[2].c_str(), nullptr, 10);
    Callee.FileAddr = strtoul(opts.Function[3].c_str(), nullptr, 10);

    binary_t &CalleeBinary = Decompilation.Binaries.at(Callee.BIdx);
    binary_t &CallerBinary = Decompilation.Binaries.at(IndCall.BIdx);

    auto &ICFG = CallerBinary.Analysis.ICFG;
    basic_block_t bb = boost::vertex(IndCall.BBIdx, ICFG);
    tcg_uintptr_t TermAddr = ICFG[bb].Term.Addr;

    function_index_t CalleeFIdx =
        explore_function(CalleeBinary, *state_for_binary(CalleeBinary).ObjectFile,
                         tcg, dis, Callee.FileAddr,
                         state_for_binary(CalleeBinary).fnmap,
                         state_for_binary(CalleeBinary).bbmap);
    if (!is_function_index_valid(CalleeFIdx)) {
      HumanOut() << llvm::formatv(
          "failed to translate indirect call target {0:x}\n", Callee.FileAddr);
      return 1;
    }

    function_t &callee = CalleeBinary.Analysis.Functions.at(CalleeFIdx);

    /* term bb may been split */
    bb = basic_block_at_address(TermAddr, CallerBinary, state_for_binary(CallerBinary).bbmap);

    bool isNewTarget = ICFG[bb].DynTargets.insert({Callee.BIdx, CalleeFIdx}).second;

    assert(isNewTarget);
    assert(boost::out_degree(bb, ICFG) == 0);

    if (ICFG[bb].Term.Type == TERMINATOR::INDIRECT_CALL &&
        does_function_return(callee, CalleeBinary)) {
      //
      // this call instruction will return, so explore the return block
      //
      basic_block_index_t NextBBIdx =
          explore_basic_block(CallerBinary, *state_for_binary(CallerBinary).ObjectFile, tcg, dis,
                              ICFG[bb].Addr + ICFG[bb].Size + (unsigned)IsMIPSTarget * 4,
                              state_for_binary(CallerBinary).fnmap,
                              state_for_binary(CallerBinary).bbmap);

      assert(is_basic_block_index_valid(NextBBIdx));

      /* term bb may been split */
      bb = basic_block_at_address(TermAddr, CallerBinary, state_for_binary(CallerBinary).bbmap);
      assert(ICFG[bb].Term.Type == TERMINATOR::INDIRECT_CALL);

      boost::add_edge(bb, boost::vertex(NextBBIdx, ICFG), ICFG);
    }

    msg = (fmt(__ANSI_CYAN "(call*) %s -> %s" __ANSI_NORMAL_COLOR) %
           DescribeBasicBlock(IndCall.BIdx, IndCall.BBIdx) %
           DescribeFunction(Callee.BIdx, CalleeFIdx))
              .str();
  } else if (opts.ABI.size() > 0) {
    assert(opts.ABI.size() == 2);

    dynamic_target_t NewABI = {strtoul(opts.ABI[0].c_str(), nullptr, 10),
                               strtoul(opts.ABI[1].c_str(), nullptr, 10)};

    function_t &f = function_of_target(NewABI, Decompilation);

    if (f.IsABI)
      return 1; // given function already marked as an ABI

    f.IsABI = true;

    msg = (fmt(__ANSI_BLUE "(abi) %s" __ANSI_NORMAL_COLOR) %
           DescribeFunction(NewABI.first, NewABI.second))
              .str();
  } else if (opts.Returns.size() > 0) {
    struct {
      binary_index_t BIdx;
      basic_block_index_t BBIdx;
    } Call;

    Call.BIdx = strtoul(opts.Returns[0].c_str(), nullptr, 10);
    Call.BBIdx = strtoul(opts.Returns[1].c_str(), nullptr, 10);

    binary_t &CallBinary = Decompilation.Binaries.at(Call.BIdx);
    auto &ICFG = CallBinary.Analysis.ICFG;

    basic_block_t bb = boost::vertex(Call.BBIdx, ICFG);

    tcg_uintptr_t NextAddr = ICFG[bb].Addr + ICFG[bb].Size + (unsigned)IsMIPSTarget * 4;
    tcg_uintptr_t TermAddr = ICFG[bb].Term.Addr;

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
      HumanOut() << llvm::formatv("unexpected out degree {0}\n", deg);
      return 1;
    }

    basic_block_index_t next_bb_idx =
      explore_basic_block(CallBinary, *state_for_binary(CallBinary).ObjectFile, tcg, dis, NextAddr,
                          state_for_binary(CallBinary).fnmap,
                          state_for_binary(CallBinary).bbmap);

    /* term bb may been split */
    bb = basic_block_at_address(TermAddr, CallBinary, state_for_binary(CallBinary).bbmap);

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
    HumanOut() << "no command provided\n";
    return 1;
  }

  assert(!msg.empty());
  HumanOut() << msg << '\n';

  auto InvalidateAllFunctionAnalyses = [&](void) -> void {
    for (binary_t &binary : Decompilation.Binaries)
      for (function_t &f : binary.Analysis.Functions)
        f.InvalidateAnalysis();
  };

  InvalidateAllFunctionAnalyses();

  WriteDecompilationToFile(jvfp, Decompilation);

  //
  // git commit
  //
  if (git) {
    pid_t pid = fork();
    if (!pid) { /* child */
      chdir(opts.jv.c_str());

      const char *argv[] = {"/usr/bin/git", "commit",    ".",
                            "-m",           msg.c_str(), nullptr};

      return execve(argv[0], const_cast<char **>(argv), ::environ);
    }

    if (int ret = WaitForProcessToExit(pid))
      return ret;
  }

  return 0;
}

std::string RecoverTool::DescribeFunction(binary_index_t BIdx,
                                          function_index_t FIdx) {
  auto &binary = Decompilation.Binaries.at(BIdx);
  function_t &f = binary.Analysis.Functions.at(FIdx);

  auto &ICFG = binary.Analysis.ICFG;
  tcg_uintptr_t Addr = ICFG[boost::vertex(f.Entry, ICFG)].Addr;

  return (fmt("%s+%#lx") % fs::path(binary.Path).filename().string() % Addr).str();
}

std::string RecoverTool::DescribeBasicBlock(binary_index_t BIdx,
                                            basic_block_index_t BBIdx) {
  auto &binary = Decompilation.Binaries.at(BIdx);

  auto &ICFG = binary.Analysis.ICFG;
  tcg_uintptr_t Addr = ICFG[boost::vertex(BBIdx, ICFG)].Addr;

  return (fmt("%s+%#lx") % fs::path(binary.Path).filename().string() % Addr).str();
}
}
