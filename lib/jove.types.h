#pragma once
#include <stdint.h>
#include "jove.hashtable.h"

struct _jove_function_info_t {
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
