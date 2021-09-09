#define _JOVE_MAX_BINARIES 512

uintptr_t *__jove_function_tables[_JOVE_MAX_BINARIES] = {
    [0 ... _JOVE_MAX_BINARIES - 1] = NULL
};

//
// DFSan
//
#define JOVE_SHADOW_NUM_REGIONS 32
#define JOVE_SHADOW_REGION_SIZE (0x10000 / JOVE_SHADOW_NUM_REGIONS)
#define JOVE_SHADOW_SIZE (sizeof(dfsan_label) * JOVE_SHADOW_REGION_SIZE + 2 * JOVE_PAGE_SIZE)

struct shadow_t {
  uint16_t *X[JOVE_SHADOW_NUM_REGIONS];
};

struct shadow_t __df32_shadow_mem[65536];

void (*__jove_dfsan_flush)(void) = NULL; /* XXX */
