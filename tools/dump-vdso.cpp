#include "tool.h"
#include "vdso.h"

#include <llvm/Support/WithColor.h>

using llvm::WithColor;

namespace jove {

struct DumpVDSO : public Tool {
  int Run(void) override;
};

JOVE_REGISTER_TOOL("dump-vdso", DumpVDSO);

int DumpVDSO::Run(void) {
  std::string_view vdso = get_vdso();

  if (vdso.empty()) {
    WithColor::error() << "no [vdso]\n";
    return 1;
  }

  llvm::outs() << vdso;

  return 0;
}

}
