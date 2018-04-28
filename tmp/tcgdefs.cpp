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

  for (int i = 0, n = tcg._tcg_ctx.nb_globals; i < n; i++) {
    TCGTemp &ts = tcg._tcg_ctx.temps[i];
    printf("%s\n", ts.name);
  }

  return 0;
}
