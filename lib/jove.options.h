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
    bool Interactive;
    bool Detailed;
  } Debug;

  struct {
    bool Begin;
    bool Call;
    bool UnknownCallee;
  } Pause;

  bool DumpOpts;
  char OnCrash; /* a=abort,s=sleep,x=exit */

  const char *Trace;
  const char *CallS;
  bool Hoard;
  bool SectsExe;
};
