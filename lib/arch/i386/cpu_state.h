#include "env.copy.h"

static inline target_ulong *emulated_stack_pointer_of_cpu_state(CPUX86State *env) {
  return &env->regs[R_ESP];
}
