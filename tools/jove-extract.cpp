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
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/dynamic_bitset.hpp>
#include <boost/format.hpp>
#include <boost/graph/adj_list_serialize.hpp>
#include <boost/icl/interval_set.hpp>
#include <boost/icl/split_interval_map.hpp>
#include <boost/preprocessor/cat.hpp>
#include <boost/preprocessor/repetition/repeat.hpp>
#include <boost/preprocessor/repetition/repeat_from_to.hpp>
#include <boost/serialization/bitset.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace opts {
static cl::OptionCategory JoveCategory("Specific Options");

static cl::opt<std::string> OutDir(cl::Positional, cl::desc("outdir"),
                                   cl::Required, cl::value_desc("filename"),
                                   cl::cat(JoveCategory));

static cl::opt<std::string> jv("decompilation", cl::desc("Jove decompilation"),
                               cl::Required, cl::value_desc("filename"),
                               cl::cat(JoveCategory));

static cl::alias jvAlias("d", cl::desc("Alias for -decompilation."),
                         cl::aliasopt(jv), cl::cat(JoveCategory));

} // namespace opts

namespace jove {

static int extract(void);

}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::HideUnrelatedOptions({&opts::JoveCategory, &llvm::ColorCategory});
  cl::AddExtraVersionPrinter([](llvm::raw_ostream &OS) -> void {
    OS << "jove version " JOVE_VERSION "\n";
  });
  cl::ParseCommandLineOptions(argc, argv, "Jove Recover\n");

  if (!fs::exists(opts::jv)) {
    WithColor::error() << "decompilation does not exist\n";
    return 1;
  }

  return jove::extract();
}

namespace jove {

typedef boost::format fmt;

static decompilation_t Decompilation;

int extract(void) {
  bool git = fs::is_directory(opts::jv);

  //
  // parse the existing decompilation file
  //
  {
    std::ifstream ifs(git ? (opts::jv + "/decompilation.jv") : opts::jv);

    boost::archive::text_iarchive ia(ifs);
    ia >> Decompilation;
  }

  if (fs::exists(opts::OutDir))
    fs::remove_all(opts::OutDir);

  if (!fs::create_directory(opts::OutDir)) {
    WithColor::error() << llvm::formatv("failed to create directory at \"{0}\"",
                                        opts::OutDir);
    return 1;
  }

  WithColor::note() << llvm::formatv("extracting binaries into {0}\n",
                                     opts::OutDir.c_str());

  for (binary_t &b : Decompilation.Binaries) {
    assert(b.Path[0] == '/');

    fs::path chrooted_path(std::string(opts::OutDir) + b.Path);
    fs::create_directories(chrooted_path.parent_path());

    {
      std::ofstream ofs(chrooted_path.c_str());

      ofs.write(reinterpret_cast<const char *>(&b.Data[0]), b.Data.size());
    }
  }

  return 0;
}

void _qemu_log(const char *cstr) { llvm::errs() << cstr; }

}
