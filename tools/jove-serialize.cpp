#include "tool.h"
#include "serialize.h"
#include <iostream>

namespace cl = llvm::cl;

namespace jove {

class SerializeTool : public JVTool {
  struct Cmdline {
    cl::opt<bool> Text;
    cl::opt<std::string> Path;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Text("text", cl::desc("Serialize to text (portable)"), cl::init(true),
               cl::cat(JoveCategory)),
          Path(cl::Positional, cl::desc("Path to write serialization"),
               cl::value_desc("filename"), cl::cat(JoveCategory)) {}
  } opts;

public:
  SerializeTool() : opts(JoveCategory) {}

  int Run(void) override;
};

JOVE_REGISTER_TOOL("serialize", SerializeTool);

int SerializeTool::Run(void) {
  if (opts.Path.empty()) {
    SerializeJV(jv, std::cout, opts.Text);
    return 0;
  }

  SerializeJVToFile(jv, opts.Path.c_str(), opts.Text);
  return 0;
}

}

