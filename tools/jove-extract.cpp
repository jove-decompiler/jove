#include "tool.h"
#include <array>
#include <boost/dynamic_bitset.hpp>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include <boost/icl/interval_set.hpp>
#include <boost/icl/split_interval_map.hpp>
#include <boost/preprocessor/cat.hpp>
#include <boost/preprocessor/repetition/repeat.hpp>
#include <boost/preprocessor/repetition/repeat_from_to.hpp>
#include <cinttypes>
#include <fstream>
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
#include <llvm/Support/ScopedPrinter.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/WithColor.h>
#include <memory>
#include <numeric>
#include <sstream>
#include <tuple>
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

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

class ExtractTool : public Tool {
  struct Cmdline {
    cl::opt<std::string> OutDir;
    cl::opt<std::string> jv;
    cl::alias jvAlias;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : OutDir(cl::Positional, cl::desc("outdir"), cl::Required,
                 cl::value_desc("filename"), cl::cat(JoveCategory)),

          jv("decompilation", cl::desc("Jove decompilation"), cl::Required,
             cl::value_desc("filename"), cl::cat(JoveCategory)),

          jvAlias("d", cl::desc("Alias for -decompilation."), cl::aliasopt(jv),
                  cl::cat(JoveCategory)) {}
  } opts;

  decompilation_t Decompilation;

public:
  ExtractTool() : opts(JoveCategory) {}

  int Run(void);
};

JOVE_REGISTER_TOOL("extract", ExtractTool);

typedef boost::format fmt;

int ExtractTool::Run(void) {
  if (!fs::exists(opts.jv)) {
    WithColor::error() << "decompilation does not exist\n";
    return 1;
  }

  bool git = fs::is_directory(opts.jv);
  std::string jvfp = git ? (opts.jv + "/decompilation.jv") : opts.jv;

  ReadDecompilationFromFile(jvfp, Decompilation);

  if (fs::exists(opts.OutDir))
    fs::remove_all(opts.OutDir);

  if (!fs::create_directory(opts.OutDir)) {
    WithColor::error() << llvm::formatv("failed to create directory at \"{0}\"",
                                        opts.OutDir);
    return 1;
  }

  WithColor::note() << llvm::formatv("extracting binaries into {0}\n",
                                     opts.OutDir.c_str());

  for (binary_t &b : Decompilation.Binaries) {
    assert(b.Path[0] == '/');

    fs::path chrooted_path(std::string(opts.OutDir) + b.Path);
    fs::create_directories(chrooted_path.parent_path());

    {
      std::ofstream ofs(chrooted_path.c_str());

      ofs.write(reinterpret_cast<const char *>(&b.Data[0]), b.Data.size());
    }
  }

  return 0;
}

}
