#ifndef JOVE_TYPES_H
#define JOVE_TYPES_H
#include <stdint.h>
#include <stdbool.h>
#include <linux/limits.h> /* ARG_MAX and PATH_MAX */

struct jove_opts_t {
  struct {
    bool Signals;
    bool Thunks;
    bool Tramps;
    bool Calls;
    bool Stack;
    bool Inits;
    bool Verbose;
  } Debug;

  bool DumpOpts;
  char OnCrash; /* a=abort, s=sleep */

  const char *Trace;
};

#endif /* JOVE_TYPES_H */
