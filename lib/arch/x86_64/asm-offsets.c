#include "gen-asm-offsets.h"

#include <boost/preprocessor/repetition/repeat.hpp>

int main(void) {
  DEFINE(ASMOFF_ENV_df, offsetof(CPUX86State, df));
  DEFINE(ASMOFF_ENV_eip, offsetof(CPUX86State, eip));
  DEFINE(ASMOFF_ENV_xmm_regs_0___x_ZMMReg_0___q_XMMReg_0_, offsetof(CPUX86State, xmm_regs[0]._x_ZMMReg[0]._q_XMMReg[0]));
  DEFINE(ASMOFF_ENV_regs_R_ESP_, offsetof(CPUX86State, regs[R_ESP]));

#define XMM_THING_FROM_SP(n, idx, data) \
  DEFINE(ASMOFF_ENV_FROM_SP_xmm_regs_##idx##___x_ZMMReg_0___q_XMMReg_0_, \
         offsetof(CPUX86State, xmm_regs[idx]._x_ZMMReg[0]._q_XMMReg[0]) - offsetof(CPUX86State, regs[R_ESP]));

  BOOST_PP_REPEAT(8, XMM_THING_FROM_SP, void)

  DEFINE(ASMOFF_ENV_FROM_SP_regs_R_EAX_, offsetof(CPUX86State, regs[R_EAX]) - offsetof(CPUX86State, regs[R_ESP]));

  return 0;
}
