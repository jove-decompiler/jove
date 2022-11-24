#include "tool.h"
#include "elf.h"
#include "recovery.h"

#include <boost/filesystem.hpp>

#include <llvm/Support/DataTypes.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/FormatVariadic.h>
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
        : jv("jv", cl::desc("Jove jv"), cl::Required,
             cl::value_desc("filename"), cl::cat(JoveCategory)),

          jvAlias("d", cl::desc("Alias for -jv."), cl::aliasopt(jv),
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

  disas_t disas;

public:
  RecoverTool() : opts(JoveCategory) {}

  int Run(void);

  std::string DescribeFunction(binary_index_t, function_index_t);
  std::string DescribeBasicBlock(binary_index_t, basic_block_index_t);
};

JOVE_REGISTER_TOOL("recover", RecoverTool);

int RecoverTool::Run(void) {
  if (!fs::exists(opts.jv)) {
    WithColor::error() << "jv does not exist\n";
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

  ReadDecompilationFromFile(opts.jv, jv);

  IgnoreCtrlC();

  tiny_code_generator_t tcg;
  symbolizer_t symbolizer;

  CodeRecovery Recovery(jv, disas, tcg, symbolizer);

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

  jv.InvalidateFunctionAnalyses();
  WriteDecompilationToFile(opts.jv, jv);

  return 0;
}

}
