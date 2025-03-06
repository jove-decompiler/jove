#include "gen-asm-offsets.h"

int main(void) {
  DEFINE(ASMOFF_ENV_cp15_tpidr_el_0_, offsetof(CPUARMState, cp15.tpidr_el[0]));
  DEFINE(ASMOFF_ENV_vfp_zregs_0_, offsetof(CPUARMState, vfp.zregs[0]));
  DEFINE(ASMOFF_ENV_vfp_zregs_32_, offsetof(CPUARMState, vfp.zregs[32]));
  DEFINE(ASMOFF_ENV_btype, offsetof(CPUARMState, btype));

  return 0;
}
