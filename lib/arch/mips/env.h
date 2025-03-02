#include "env.copy.h"

static inline target_ulong *emulated_stack_pointer_of_cpu_state(CPUMIPSState *env) {
  return &env->active_tc.gpr[29];
}
