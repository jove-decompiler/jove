#pragma once
#include "linux.copy.h" /* data structures from linux kernel come first */

#include <stdint.h>
#include <stdbool.h>

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
// DFSan
//
#define JOVE_SHADOW_NUM_REGIONS 32
#define JOVE_SHADOW_REGION_SIZE (0x10000 / JOVE_SHADOW_NUM_REGIONS)
#define JOVE_SHADOW_SIZE (sizeof(dfsan_label) * JOVE_SHADOW_REGION_SIZE + 2 * JOVE_PAGE_SIZE)

typedef uint16_t dfsan_label;

struct shadow_t {
  uint16_t *X[JOVE_SHADOW_NUM_REGIONS];
};
