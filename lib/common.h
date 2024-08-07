#pragma once
#include "linux.copy.h" /* data structures from linux kernel come first */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

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
// tracking memory
//
struct jove_allocation_t {
  uintptr_t beg;
  size_t len;

  const char *desc;

  struct hlist_node hlist;
};

void _jove_rt_track_alloc(uintptr_t beg, size_t len, const char *desc);
void _jove_rt_track_free(uintptr_t beg, size_t len);
const char *_jove_rt_description_for_alloc(uintptr_t beg);

#define JOVE_TRACK_ALLOCATION(beg, len, desc) do {                             \
  _jove_rt_track_alloc(beg, len,                                               \
    desc /* " (" BOOST_PP_STRINGIZE(__FILE__) ":" */                           \
         /*      BOOST_PP_STRINGIZE(__LINE__) ")" */);                         \
  } while (false)
#define JOVE_UNTRACK_ALLOCATION(beg, len) do { \
    _jove_rt_track_free(beg, len);             \
  } while (false)

#define JOVE_TRACK_ALLOCATIONS

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
