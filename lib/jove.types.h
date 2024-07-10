#ifndef JOVE_TYPES_H
#define JOVE_TYPES_H
#include <stdint.h>
#include <linux/limits.h> /* ARG_MAX and PATH_MAX */
#include "jove.hashtable.h"

struct jove_opts_t {
  struct {
    bool Signals;
    bool Thunks;
    bool Stubs;
    bool Calls;
    bool Stack;
  } Debug;

  bool DumpOpts;
  char OnCrash; /* a=abort, s=sleep */
};

struct jove_function_info_t {
  uint32_t BIdx;
  uint32_t FIdx;

  unsigned IsForeign : 1;

  union {
    uintptr_t pc;

    struct {
      uintptr_t Func;
    } Foreign;

    struct {
      uintptr_t SectPtr;
    } Recompiled;
  };

  uintptr_t RecompiledFunc;

  struct hlist_node hlist;
};

//
// windows
//
typedef void* HMODULE;
typedef unsigned long DWORD;
typedef void* LPVOID;
typedef int BOOL;

//
// DFSan
//
typedef uint16_t dfsan_label;

struct shadow_t {
  uint16_t *X[JOVE_SHADOW_NUM_REGIONS];
};

#endif /* JOVE_TYPES_H */
