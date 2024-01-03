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
    cl::opt<std::string> Input;
    cl::alias InputAlias;

    cl::opt<std::string> Output;
    cl::alias OutputAlias;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Input("input", cl::desc("Path to DSO"), cl::Required,
                cl::value_desc("filename"), cl::cat(JoveCategory)),

          InputAlias("i", cl::desc("Alias for -input."), cl::aliasopt(Input),
                     cl::cat(JoveCategory)),

          Output("output", cl::desc("Jove jv"),
                 cl::value_desc("filename"), cl::cat(JoveCategory)),

          OutputAlias("o", cl::desc("Alias for -output."), cl::aliasopt(Output),
                      cl::cat(JoveCategory)) {}
  } opts;

public:
  AddTool() : opts(JoveCategory) {}

  int Run(void);
};

JOVE_REGISTER_TOOL("add", AddTool);

int AddTool::Run(void) {
  if (!fs::exists(opts.Input)) {
    WithColor::error() << "input binary does not exist\n";
    return 1;
  }

  tiny_code_generator_t tcg;
  disas_t disas;
  explorer_t E(jv, disas, tcg, IsVerbose());

  jv.Add(opts.Input.c_str(), E);

  return 0;
}

} // namespace jove
