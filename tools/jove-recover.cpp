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
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/dynamic_bitset.hpp>
#include <boost/format.hpp>
#include <boost/graph/adj_list_serialize.hpp>
#include <boost/icl/interval_set.hpp>
#include <boost/icl/split_interval_map.hpp>
#include <boost/preprocessor/cat.hpp>
#include <boost/preprocessor/repetition/repeat.hpp>
#include <boost/preprocessor/repetition/repeat_from_to.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>

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

} // namespace opts

namespace jove {

static int recover(void);

}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::HideUnrelatedOptions({&opts::JoveCategory, &llvm::ColorCategory});
  cl::ParseCommandLineOptions(argc, argv, "Jove Recover\n");

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

  return jove::recover();
}

namespace jove {

typedef boost::format fmt;

static decompilation_t Decompilation;

int recover(void) {
  bool git = fs::is_directory(opts::jv);

  //
  // parse the existing decompilation file
  //
  {
    std::ifstream ifs(git ? (opts::jv + "/decompilation.jv") : opts::jv);

    boost::archive::binary_iarchive ia(ifs);
    ia >> Decompilation;
  }

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

    auto &ICFG = Decompilation.Binaries.at(Caller.BIdx).Analysis.ICFG;
    ICFG[boost::vertex(Caller.BBIdx, ICFG)].DynTargets.insert(
        {Callee.BIdx, Callee.FIdx});
  } else if (opts::BasicBlock.size() > 0) {
    struct {
      binary_index_t BIdx;
      basic_block_index_t BBIdx;

      basic_block_t bb;
    } IndBr;

    IndBr.BIdx = strtoul(opts::BasicBlock[0].c_str(), nullptr, 10);
    IndBr.BBIdx = strtoul(opts::BasicBlock[1].c_str(), nullptr, 10);

    uint64_t Target = strtoul(opts::BasicBlock[2].c_str(), nullptr, 10);

    auto &ICFG = Decompilation.Binaries.at(IndBr.BIdx).Analysis.ICFG;
    IndBr.bb = boost::vertex(IndBr.BBIdx, ICFG);

    llvm::outs() << llvm::formatv("ICFG[IndBr.bb].Addr={0:x}\n"
                                  "Target={1:x}\n",
                                  ICFG[IndBr.bb].Addr,
                                  Target);
  } else {
    WithColor::error() << "no command provided\n";
    return 1;
  }

  //
  // write decompilation
  //
  {
    std::ofstream ofs(git ? (opts::jv + "/decompilation.jv") : opts::jv);

    boost::archive::binary_oarchive oa(ofs);
    oa << Decompilation;
  }

  return 0;
}

template <class T>
static T unwrapOrError(llvm::Expected<T> EO) {
  if (EO)
    return *EO;

  std::string Buf;
  {
    llvm::raw_string_ostream OS(Buf);
    llvm::logAllUnhandledErrors(EO.takeError(), OS, "");
  }
  WithColor::error() << Buf << '\n';
  exit(1);
}

void _qemu_log(const char *cstr) { llvm::errs() << cstr; }

}
