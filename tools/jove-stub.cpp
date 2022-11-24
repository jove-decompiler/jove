#include "tool.h"
#include "crypto.h"

#include <boost/filesystem.hpp>
#include <boost/dll/runtime_symbol_info.hpp>

#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

#include <sstream>

namespace cl = llvm::cl;
namespace fs = boost::filesystem;

using llvm::WithColor;

namespace jove {

class StubTool : public Tool {
  struct Cmdline {
    cl::opt<std::string> Prog;
    cl::opt<std::string> jv;
    cl::alias jvAlias;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Prog(cl::Positional, cl::desc("prog"), cl::Required,
               cl::value_desc("filename"), cl::cat(JoveCategory)),

          jv("decompilation", cl::desc("Jove jv"),
             cl::value_desc("filename"), cl::cat(JoveCategory)),

          jvAlias("d", cl::desc("Alias for -jv."), cl::aliasopt(jv),
                  cl::cat(JoveCategory)) {}
  } opts;

  decompilation_t decompilation;

public:
  StubTool() : opts(JoveCategory) {}

  int Run(void);
};

JOVE_REGISTER_TOOL("stub", StubTool);

int StubTool::Run(void) {
  std::string jvfp = opts.jv;
  if (jvfp.empty())
    jvfp = path_to_jv(opts.Prog.c_str());

  if (!fs::exists(jvfp)) {
    WithColor::error() << llvm::formatv("{0} not found\n", jvfp);
    return 1;
  }

  ReadDecompilationFromFile(jvfp, decompilation);

  binary_t &binary = decompilation.Binaries.at(0);
  assert(binary.IsExecutable);

  //
  // before replacing the executable, make sure it is what we expect it to be
  //
  {
    std::vector<uint8_t> buff;
    read_file_into_vector(binary.Path.c_str(), buff);

    if (binary.Data.size() != buff.size() ||
        memcmp(&binary.Data[0], &buff[0], binary.Data.size())) {
      HumanOut() << llvm::formatv(
          "file {0} does not match binary found in decompilation ; did you already run 'jove stub'?\n",
          binary.Path);
      return 1;
    }
  }

  std::string jove_path =
      fs::canonical(boost::dll::program_location()).string();
  std::string digest = crypto::sha3(&binary.Data[0], binary.Data.size());

  std::ostringstream oss;

  oss
    << "#!/bin/sh"                               "\n"
    << "#"                                       "\n"
    << "# NOTE: FILE OVERWRITTEN BY 'jove stub'" "\n"
    << "# RESTORE VIA 'jove unstub'"             "\n"
    << "#"                                       "\n"
    << "exec " << jove_path << " bootstrap -d " <<
                  fs::canonical(jvfp).string() << " --human-output " <<
                  binary.Path << ".bootstrap.log " << binary.Path << " -- $@\n"
    << "\n"
    << "# " << digest << "\n"
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
