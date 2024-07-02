#pragma once
#include <stdint.h>
#include <linux/limits.h>
#include "jove.hashtable.h"

struct jove_opts_t {
  struct {
    bool Signals;
    bool Thunks;
    bool Stubs;
    bool Calls;
  } Debug;

  bool ShouldSleepOnCrash;
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

typedef void* HMODULE;
typedef unsigned long DWORD;
typedef void* LPVOID;
typedef int BOOL;
