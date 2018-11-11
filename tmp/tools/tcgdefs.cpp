#include "tcgcommon.hpp"

#include <llvm/Support/InitLLVM.h>

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  jove::tiny_code_generator_t tcg;

  auto string_of_tcg_type = [](TCGType ty) -> const char * {
#define __CHK_TY(NM)                                                           \
  do {                                                                         \
    if (ty == TCG_TYPE_##NM)                                                   \
      return #NM;                                                              \
  } while (0)

    __CHK_TY(I32);
    __CHK_TY(I64);
    __CHK_TY(V64);
    __CHK_TY(V128);
    __CHK_TY(V256);

#undef __CHK_TY

    return "";
  };

  int N = tcg._ctx.nb_globals;
  for (int i = 0; i < N; i++) {
    TCGTemp &ts = tcg._ctx.temps[i];

    printf("%s %s", string_of_tcg_type(ts.type), ts.name);
    if (ts.mem_base)
      printf(" @ %s+%#lx", ts.mem_base->name,
             static_cast<unsigned long>(ts.mem_offset));
    printf("\n");
  }

  return 0;
}
