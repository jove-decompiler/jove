#include "gen-asm-offsets.h"

int main(void) {
  DEFINE(ASMOFF_ENV_df, offsetof(CPUX86State, df));
  DEFINE(ASMOFF_ENV_eip, offsetof(CPUX86State, eip));

  return 0;
}
