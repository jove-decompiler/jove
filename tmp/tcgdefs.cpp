#include "tcgcommon.cpp"

#include <llvm/ADT/StringRef.h>
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/ManagedStatic.h>

int main(int argc, char** argv) {
  llvm::StringRef ToolName = argv[0];
  llvm::sys::PrintStackTraceOnErrorSignal(ToolName);
  llvm::PrettyStackTraceProgram X(argc, argv);
  llvm::llvm_shutdown_obj Y;

  if (argc != 1) {
    printf("usage: %s\n", argv[0]);
    return 1;
  }

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
