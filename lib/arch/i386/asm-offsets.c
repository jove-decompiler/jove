#include "gen-asm-offsets.h"

int main(void) {
  DEFINE(ASMOFF_ENV_df, offsetof(CPUX86State, df));
  DEFINE(ASMOFF_ENV_eip, offsetof(CPUX86State, eip));
  DEFINE(ASMOFF_ENV_eflags, offsetof(CPUX86State, eflags));

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

  return 0;
}
