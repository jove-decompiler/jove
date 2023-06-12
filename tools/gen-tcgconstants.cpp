#include "tool.h"
#include "tcg.h"

namespace jove {

struct GenTCGConstantsTool : public Tool {
  GenTCGConstantsTool() {}

  int Run(void);
};

JOVE_REGISTER_TOOL("gen-tcgconstants", GenTCGConstantsTool);

int GenTCGConstantsTool::Run(void) {
  tiny_code_generator_t tcg;
  tcg.print_shit();

  return 0;
}

}
