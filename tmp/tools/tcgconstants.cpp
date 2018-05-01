#include "tcgcommon.hpp"

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

  auto num_globals = [&](void) -> int { return tcg._ctx.nb_globals; };
  auto num_helpers = [&](void) -> int { return ARRAY_SIZE(all_helpers); };
  auto max_temps = [&](void) -> int { return TCG_MAX_TEMPS; };

  auto tcg_index_of_named_global = [&](const char *nm) -> int {
    int N = tcg._ctx.nb_globals;
    for (int i = 0; i < N; i++) {
      TCGTemp &ts = tcg._ctx.temps[i];
      if (strcmp(ts.name, nm) == 0)
        return i;
    }

    return -1;
  };

  auto env_index = [&](void) -> int {
    return tcg_index_of_named_global("env");
  };
  auto program_counter_index = [&](void) -> int {
    return tcg_index_of_named_global("pc");
  };
  auto stack_pointer_index = [&](void) -> int {
#if defined(TARGET_X86_64)
    return tcg_index_of_named_global("rsp");
#else
    return tcg_index_of_named_global("sp");
#endif
  };
  auto program_counter_env_offset = [&](void) -> int {
#if defined(TARGET_X86_64)
    return offsetof(CPUX86State, eip);
#else
    return -1;
#endif
  };

  printf("#pragma once\n"
         "\n"
         "namespace jove {\n");

#define __TCG_CONST(NM) printf("constexpr int tcg_" #NM " = %d;\n", NM())

  __TCG_CONST(num_globals);
  __TCG_CONST(num_helpers);
  __TCG_CONST(max_temps);
  __TCG_CONST(env_index);
  __TCG_CONST(program_counter_index);
  __TCG_CONST(stack_pointer_index);
  __TCG_CONST(program_counter_env_offset);

#undef __TCG_CONST

  printf("}\n");

  return 0;
}
