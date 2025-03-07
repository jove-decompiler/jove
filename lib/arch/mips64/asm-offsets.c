#include "gen-asm-offsets.h"

#include <boost/preprocessor/repetition/repeat.hpp>

int main(void) {
  DEFINE(ASMOFF_ENV_active_tc_PC, offsetof(CPUMIPSState, active_tc.PC));
  DEFINE(ASMOFF_ENV_active_tc_CP0_UserLocal, offsetof(CPUMIPSState, active_tc.CP0_UserLocal));
  DEFINE(ASMOFF_ENV_lladdr, offsetof(CPUMIPSState, lladdr));
  DEFINE(ASMOFF_ENV_llval, offsetof(CPUMIPSState, llval));
  DEFINE(ASMOFF_ENV_error_code, offsetof(CPUMIPSState, error_code));

#define FPU_THING_FROM_SP(n, idx, data) \
  DEFINE(ASMOFF_ENV_FROM_SP_active_fpu_fpr_##idx##__d,\
         offsetof(CPUMIPSState, active_fpu.fpr[idx].d) - offsetof(CPUMIPSState, active_tc.gpr[29]));

  BOOST_PP_REPEAT(32, FPU_THING_FROM_SP, void)

  return 0;
}
