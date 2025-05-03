#include "tool.h"
#include "B.h"
#include "explore.h"
#include "tcg.h"

#include <boost/filesystem.hpp>

#include <llvm/Support/WithColor.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/FileSystem.h>

namespace fs = boost::filesystem;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

class AddTool : public JVTool<ToolKind::Standard> {
  struct Cmdline {
    cl::list<std::string> DSO;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : DSO(cl::Positional, cl::desc("DSO"), cl::OneOrMore,
              cl::value_desc("filename"), cl::cat(JoveCategory)) {}
  } opts;

public:
  AddTool() : opts(JoveCategory) {}

  int Run(void) override;
};

JOVE_REGISTER_TOOL("add", AddTool);

int AddTool::Run(void) {
  tiny_code_generator_t tcg;
  disas_t disas;
  explorer_t E(jv, disas, tcg, IsVeryVerbose());

  for (const std::string &filename : opts.DSO) {
    if (!fs::exists(filename)) {
      WithColor::error() << llvm::formatv("\"{0}\" does not exist\n", filename);
      return 1;
    }

    if (IsVerbose())
      HumanOut() << llvm::formatv("adding \"{0}\"\n", filename);

    jv.AddFromPath(E, jv_file, filename.c_str());
  }

  return 0;
}

}
