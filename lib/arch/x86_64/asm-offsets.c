#include "gen-asm-offsets.h"

#include <boost/preprocessor/repetition/repeat.hpp>

int main(void) {
  DEFINE(ASMOFF_ENV_df, offsetof(CPUX86State, df));
  DEFINE(ASMOFF_ENV_eip, offsetof(CPUX86State, eip));
  DEFINE(ASMOFF_ENV_eflags, offsetof(CPUX86State, eflags));
  DEFINE(ASMOFF_ENV_cc_dst, offsetof(CPUX86State, cc_dst));
  DEFINE(ASMOFF_ENV_cc_src, offsetof(CPUX86State, cc_src));
  DEFINE(ASMOFF_ENV_cc_src2, offsetof(CPUX86State, cc_src2));
  DEFINE(ASMOFF_ENV_cc_op, offsetof(CPUX86State, cc_op));
  DEFINE(ASMOFF_ENV_xmm_regs_0___x_ZMMReg_0___q_XMMReg_0_, offsetof(CPUX86State, xmm_regs[0]._x_ZMMReg[0]._q_XMMReg[0]));
  DEFINE(ASMOFF_ENV_regs_R_ESP_, offsetof(CPUX86State, regs[R_ESP]));

  DEFINE(ASMOFF_ENV_segs, offsetof(CPUX86State, segs));
  DEFINE(ASMOFF_ENV_segs_end, offsetofend(CPUX86State, segs));

  DEFINE(ASMOFF_ENV_xmm_regs, offsetof(CPUX86State, xmm_regs));
  DEFINE(ASMOFF_ENV_xmm_regs_end, offsetofend(CPUX86State, xmm_regs));

  DEFINE(ASMOFF_ENV_xmm_t0, offsetof(CPUX86State, xmm_t0));
  DEFINE(ASMOFF_ENV_xmm_t0_end, offsetofend(CPUX86State, xmm_t0));

  DEFINE(ASMOFF_ENV_mmx_t0, offsetof(CPUX86State, mmx_t0));
  DEFINE(ASMOFF_ENV_mmx_t0_end, offsetofend(CPUX86State, mmx_t0));

  DEFINE(ASMOFF_ENV_fpop, offsetof(CPUX86State, fpop));
  DEFINE(ASMOFF_ENV_fpcs, offsetof(CPUX86State, fpcs));
  DEFINE(ASMOFF_ENV_fpds, offsetof(CPUX86State, fpds));
  DEFINE(ASMOFF_ENV_fpip, offsetof(CPUX86State, fpip));
  DEFINE(ASMOFF_ENV_fpdp, offsetof(CPUX86State, fpdp));

#define XMM_THING_FROM_SP(n, idx, data) \
  DEFINE(ASMOFF_ENV_FROM_SP_xmm_regs_##idx##___x_ZMMReg_0___q_XMMReg_0_, \
         offsetof(CPUX86State, xmm_regs[idx]._x_ZMMReg[0]._q_XMMReg[0]) - offsetof(CPUX86State, regs[R_ESP]));

  BOOST_PP_REPEAT(8, XMM_THING_FROM_SP, void)

  DEFINE(ASMOFF_ENV_FROM_SP_regs_R_EAX_, offsetof(CPUX86State, regs[R_EAX]) - offsetof(CPUX86State, regs[R_ESP]));

  return 0;
}
