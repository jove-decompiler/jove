#include <cpu.h>

#define MEMSUFFIX _data
#define DATA_SIZE 1
#include "runtime_ldst_template.h"

#define DATA_SIZE 2
#include "runtime_ldst_template.h"

#define DATA_SIZE 4
#include "runtime_ldst_template.h"

#define DATA_SIZE 8
#include "runtime_ldst_template.h"
#undef MEMSUFFIX

#define MEMSUFFIX _code
#define CODE_ACCESS
#define DATA_SIZE 1
#include "runtime_ldst_template.h"

#define DATA_SIZE 2
#include "runtime_ldst_template.h"

#define DATA_SIZE 4
#include "runtime_ldst_template.h"

#define DATA_SIZE 8
#include "runtime_ldst_template.h"
#undef MEMSUFFIX
#undef CODE_ACCESS

void *tlb_vaddr_to_host(struct CPUState *env, target_ulong addr,
                        int access_type, int mmu_idx) {
  return ((void *)((uintptr_t)addr));
}
