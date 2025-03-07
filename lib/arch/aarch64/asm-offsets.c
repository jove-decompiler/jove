#include "gen-asm-offsets.h"

#include <boost/preprocessor/repetition/repeat.hpp>

int main(void) {
  DEFINE(ASMOFF_ENV_cp15_tpidr_el_0_, offsetof(CPUARMState, cp15.tpidr_el[0]));
  DEFINE(ASMOFF_ENV_vfp_zregs_0_, offsetof(CPUARMState, vfp.zregs[0]));
  DEFINE(ASMOFF_ENV_vfp_zregs_32_, offsetof(CPUARMState, vfp.zregs[32]));
  DEFINE(ASMOFF_ENV_btype, offsetof(CPUARMState, btype));

#define VFP_THING_FROM_SP(n, idx, data) \
  DEFINE(ASMOFF_ENV_FROM_SP_vfp_zregs_##idx##_,\
         offsetof(CPUARMState, vfp.zregs[idx]) - offsetof(CPUARMState, xregs[31]));

  BOOST_PP_REPEAT(33, VFP_THING_FROM_SP, void)

  return 0;
}
