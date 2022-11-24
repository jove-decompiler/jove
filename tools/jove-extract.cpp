#include "tool.h"
#include <boost/dynamic_bitset.hpp>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include <boost/icl/interval_set.hpp>
#include <boost/icl/split_interval_map.hpp>
#include <boost/preprocessor/cat.hpp>
#include <boost/preprocessor/repetition/repeat.hpp>
#include <boost/preprocessor/repetition/repeat_from_to.hpp>

#include <llvm/Support/CommandLine.h>
#include <llvm/Support/DataTypes.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/ScopedPrinter.h>
#include <llvm/Support/WithColor.h>

#include <cinttypes>
#include <fstream>

namespace fs = boost::filesystem;
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

  decompilation_t jv;

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

  ReadDecompilationFromFile(opts.jv, jv);

  if (fs::exists(opts.OutDir))
    fs::remove_all(opts.OutDir);

  if (!fs::create_directory(opts.OutDir)) {
    WithColor::error() << llvm::formatv("failed to create directory at \"{0}\"",
                                        opts.OutDir);
    return 1;
  }

  WithColor::note() << llvm::formatv("extracting binaries into {0}\n",
                                     opts.OutDir.c_str());

  for (binary_t &b : jv.Binaries) {
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
