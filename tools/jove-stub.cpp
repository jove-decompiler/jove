#include "tool.h"
#include "crypto.h"

#include <boost/filesystem.hpp>

#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

#include <sstream>

namespace cl = llvm::cl;
namespace fs = boost::filesystem;

using llvm::WithColor;

namespace jove {

class StubTool : public JVTool {
  struct Cmdline {
    cl::opt<std::string> Prog;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Prog(cl::Positional, cl::desc("prog"), cl::Required,
               cl::value_desc("filename"), cl::cat(JoveCategory)) {}
  } opts;

public:
  StubTool() : opts(JoveCategory) {}

  int Run(void) override;
};

JOVE_REGISTER_TOOL("stub", StubTool);

int StubTool::Run(void) {
  binary_t &binary = jv.Binaries.at(0);
  assert(binary.IsExecutable);

  const char *const binary_path = binary.path();
  //
  // before replacing the executable, make sure it is what we expect it to be
  //
  {
    std::vector<uint8_t> buff;
    read_file_into_vector(binary_path, buff);

    if (binary.Data.size() != buff.size() ||
        memcmp(&binary.Data[0], &buff[0], binary.Data.size())) {
      HumanOut() << llvm::formatv(
          "file {0} does not match binary found in jv ; did you already run 'jove stub'?\n",
          binary_path);
      return 1;
    }
  }

  std::string digest = crypto::hash(&binary.Data[0], binary.Data.size());

  std::ostringstream oss;

  oss
    << "#!/bin/sh"                               "\n"
    << "#"                                       "\n"
    << "# NOTE: FILE OVERWRITTEN BY 'jove stub'" "\n"
    << "# RESTORE VIA 'jove unstub'"             "\n"
    << "#"                                       "\n"
    << "exec " << locator().tool() << " bootstrap -d " <<
                  fs::canonical("~/.jv").string() << " --human-output " <<
                  binary_path << ".bootstrap.log " << binary_path << " -- $@\n"
    << "\n"
    << "# " << digest << "\n"
    << "\n";

  std::string prologue = oss.str();

  {
    std::ofstream ofs(binary_path,
                      std::ofstream::out
                    | std::ofstream::binary
                    | std::ofstream::trunc);

    if (!ofs) {
      WithColor::error() << "failed to open " << binary_path << '\n';
      return 1;
    }

    WithColor::note() << "overwriting " << binary_path << '\n';

    ofs.write(&prologue[0], prologue.size());
    ofs.write(&binary.Data[0], binary.Data.size());
  }

  return 0;
}

}
