#include "tool.h"
#include <sstream>
#include <boost/filesystem.hpp>
#include <boost/dll/runtime_symbol_info.hpp>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

namespace cl = llvm::cl;
namespace fs = boost::filesystem;

using llvm::WithColor;

namespace jove {

class StubTool : public Tool {
  struct Cmdline {
    cl::opt<std::string> jv;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : jv(cl::Positional, cl::desc("<input jove decompilations>"),
             cl::Required, cl::cat(JoveCategory)) {}
  } opts;

  decompilation_t decompilation;

public:
  StubTool() : opts(JoveCategory) {}

  int Run(void);
};

JOVE_REGISTER_TOOL("stub", StubTool);

int StubTool::Run(void) {
  bool git = fs::is_directory(opts.jv);
  std::string jvfp =
      fs::canonical(git ? (opts.jv + "/decompilation.jv") : opts.jv).string();

  ReadDecompilationFromFile(jvfp, decompilation);

  binary_t &binary = decompilation.Binaries.at(0);
  assert(binary.IsExecutable);

  //
  // before replacing the executable, make sure it is what we expect it to be
  //
  {
    llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> FileOrErr =
        llvm::MemoryBuffer::getFileOrSTDIN(binary.Path);

    if (std::error_code EC = FileOrErr.getError()) {
      HumanOut() << llvm::formatv("failed to open binary {0}\n", binary.Path);
      return 1;
    }

    std::unique_ptr<llvm::MemoryBuffer> &Buffer = FileOrErr.get();
    if (binary.Data.size() != Buffer->getBufferSize() ||
        memcmp(&binary.Data[0], Buffer->getBufferStart(), binary.Data.size())) {
      HumanOut() << llvm::formatv(
          "file {0} does not match binary found in decompilation ; refusing\n",
          binary.Path);
      return 1;
    }
  }

  std::string jove_path =
      fs::canonical(boost::dll::program_location()).string();

  std::ostringstream oss;

  oss
    << "#!/bin/sh"                               "\n"
    << "#"                                       "\n"
    << "# NOTE: FILE OVERWRITTEN BY 'jove stub'" "\n"
    << "# RESTORE VIA 'jove unstub'"             "\n"
    << "#"                                       "\n"
    << "exec " << jove_path << " bootstrap -d " << jvfp << " --human-output " << binary.Path << ".bootstrap.log " << binary.Path << " -- $@\n"
    << "\n"
    << "\n";

  std::string prologue = oss.str();

  {
    std::ofstream ofs(binary.Path,
                      std::ofstream::out
                    | std::ofstream::binary
                    | std::ofstream::trunc);

    if (!ofs) {
      WithColor::error() << "failed to open " << binary.Path << '\n';
      return 1;
    }

    WithColor::note() << "overwriting " << binary.Path << '\n';

    ofs.write(&prologue[0], prologue.size());
    ofs.write(&binary.Data[0], binary.Data.size());
  }

  return 0;
}

}
