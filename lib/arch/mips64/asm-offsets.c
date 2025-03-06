#include "gen-asm-offsets.h"

int main(void) {
  DEFINE(ASMOFF_ENV_active_tc_PC, offsetof(CPUMIPSState, active_tc.PC));
  DEFINE(ASMOFF_ENV_active_tc_CP0_UserLocal, offsetof(CPUMIPSState, active_tc.CP0_UserLocal));
  DEFINE(ASMOFF_ENV_lladdr, offsetof(CPUMIPSState, lladdr));
  DEFINE(ASMOFF_ENV_llval, offsetof(CPUMIPSState, llval));
  DEFINE(ASMOFF_ENV_error_code, offsetof(CPUMIPSState, error_code));

  return 0;
}
