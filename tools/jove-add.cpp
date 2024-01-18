#include "tool.h"
#include "elf.h"
#include "explore.h"
#include "tcg.h"

#include <boost/filesystem.hpp>

#include <llvm/Support/WithColor.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/FileSystem.h>

#include "jove_macros.h"

namespace fs = boost::filesystem;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

class AddTool : public JVTool {
  struct Cmdline {
    cl::opt<std::string> DSO;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : DSO(cl::Positional, cl::desc("DSO"), cl::Required,
              cl::value_desc("filename"), cl::cat(JoveCategory)) {}
  } opts;

public:
  AddTool() : opts(JoveCategory) {}

  int Run(void) override;
};

JOVE_REGISTER_TOOL("add", AddTool);

int AddTool::Run(void) {
  if (!fs::exists(opts.DSO)) {
    WithColor::error() << "binary does not exist\n";
    return 1;
  }

  tiny_code_generator_t tcg;
  disas_t disas;
  explorer_t E(jv, disas, tcg, IsVerbose());

  jv.AddFromPath(E, opts.DSO.c_str());

  return 0;
}

}
