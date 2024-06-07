#include "tool.h"
#include "serialize.h"
#include <iostream>

namespace cl = llvm::cl;

namespace jove {

class UnserializeTool : public JVTool {
  struct Cmdline {
    cl::opt<bool> Text;
    cl::opt<std::string> Path;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Text("text", cl::desc("Unserialize to text (portable)"),
               cl::init(true), cl::cat(JoveCategory)),
          Path(cl::Positional, cl::desc("Path to output of jove-serialize"),
               cl::value_desc("filename"), cl::cat(JoveCategory)) {}
  } opts;

public:
  UnserializeTool() : opts(JoveCategory) {}

  int Run(void) override;
};

JOVE_REGISTER_TOOL("unserialize", UnserializeTool);

int UnserializeTool::Run(void) {
  if (opts.Path.empty()) {
    UnserializeJV(jv, std::cin, opts.Text);
    return 0;
  }

  UnserializeJVFromFile(jv, opts.Path.c_str(), opts.Text);
  return 0;
}

}

