#include "tool.h"
#include "elf.h"
#include "recovery.h"
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

#include "jove_macros.h"

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

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
  {
    binary_t &binary = Decompilation.Binaries.at(0);

    llvm::StringRef Buffer(reinterpret_cast<char *>(&binary.Data[0]),
                           binary.Data.size());
    llvm::StringRef Identifier(binary.Path);

    llvm::Expected<std::unique_ptr<obj::Binary>> BinOrErr =
        obj::createBinary(llvm::MemoryBufferRef(Buffer, Identifier));
    if (!BinOrErr) {
      HumanOut() << llvm::formatv("failed to create binary from {0}\n",
                                  binary.Path);

      return 1;
    }

    std::unique_ptr<obj::Binary> &BinRef = BinOrErr.get();

    if (!llvm::isa<ELFO>(BinRef.get())) {
      HumanOut() << binary.Path << " is not ELF of expected type\n";
      return 1;
    }

    assert(llvm::isa<ELFO>(BinRef.get()));
    ELFO &O = *llvm::cast<ELFO>(BinRef.get());

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

  CodeRecovery Recovery(Decompilation, disas_t(*DisAsm, std::cref(*STI), *IP));

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

    msg = Recovery.RecoverDynamicTarget(Caller.BIdx,
                                        Caller.BBIdx,
                                        Callee.BIdx,
                                        Callee.FIdx);
  } else if (opts.BasicBlock.size() > 0) {
    struct {
      binary_index_t BIdx;
      basic_block_index_t BBIdx;

      uint64_t Target;
    } IndBr;

    IndBr.BIdx = strtoul(opts.BasicBlock[0].c_str(), nullptr, 10);
    IndBr.BBIdx = strtoul(opts.BasicBlock[1].c_str(), nullptr, 10);

    IndBr.Target = strtoul(opts.BasicBlock[2].c_str(), nullptr, 10);

    msg = Recovery.RecoverBasicBlock(IndBr.BIdx,
                                     IndBr.BBIdx,
                                     IndBr.Target);
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

    Recovery.RecoverFunction(IndCall.BIdx,
                             IndCall.BBIdx,
                             Callee.BIdx,
                             Callee.FileAddr);
  } else if (opts.ABI.size() > 0) {
    assert(opts.ABI.size() == 2);

    dynamic_target_t NewABI = {strtoul(opts.ABI[0].c_str(), nullptr, 10),
                               strtoul(opts.ABI[1].c_str(), nullptr, 10)};
    msg = Recovery.RecoverABI(NewABI.first, NewABI.second);
  } else if (opts.Returns.size() > 0) {
    struct {
      binary_index_t BIdx;
      basic_block_index_t BBIdx;
    } Call;

    Call.BIdx = strtoul(opts.Returns[0].c_str(), nullptr, 10);
    Call.BBIdx = strtoul(opts.Returns[1].c_str(), nullptr, 10);

    msg = Recovery.Returns(Call.BIdx,
                           Call.BBIdx);
  } else {
    HumanOut() << "no command provided\n";
    return 1;
  }

  if (msg.empty())
    return 0;

  HumanOut() << msg << '\n';

  for (binary_t &binary : Decompilation.Binaries)
    for (function_t &f : binary.Analysis.Functions)
      f.InvalidateAnalysis();

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

}
