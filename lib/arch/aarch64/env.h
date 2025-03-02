#include "env.copy.h"

static inline target_ulong *emulated_stack_pointer_of_cpu_state(CPUARMState *env) {
  return &env->xregs[31];
}
