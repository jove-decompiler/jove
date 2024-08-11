#pragma once
#include <stdbool.h>

struct jove_opts_t {
  struct {
    bool Signals;
    bool Thunks;
    bool Tramps;
    bool Calls;
    bool Stack;
    bool Inits;
    bool Verbose;
    bool Insn;
  } Debug;

  bool DumpOpts;
  char OnCrash; /* a=abort, s=sleep */

  const char *Trace;
};
