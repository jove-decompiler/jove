#include "cpu.h"
#include "tcg.h"

const uint8_t* code;
target_ulong code_pc;

/*
 * Generate inline load/store functions for all MMU modes (typically
 * at least _user and _kernel) as well as _data versions, for all data
 * sizes.
 *
 * Used by target op helpers.
 *
 * The syntax for the accessors is:
 *
 * load: cpu_ld{sign}{size}_{mmusuffix}(env, ptr)
 *
 * store: cpu_st{sign}{size}_{mmusuffix}(env, ptr, val)
 *
 * sign is:
 * (empty): for 32 and 64 bit sizes
 *   u    : unsigned
 *   s    : signed
 *
 * size is:
 *   b: 8 bits
 *   w: 16 bits
 *   l: 32 bits
 *   q: 64 bits
 *
 * mmusuffix is one of the generic suffixes "data" or "code", or
 * (for softmmu configs)  a target-specific MMU mode suffix as defined
 * in target cpu.h.
 */

uint32_t cpu_ldub_data(struct CPUState *env, target_ulong ptr);
int cpu_ldsb_data(struct CPUState *env, target_ulong ptr);
uint32_t cpu_lduw_data(struct CPUState *env, target_ulong ptr);
int cpu_ldsw_data(struct CPUState *env, target_ulong ptr);
uint32_t cpu_ldl_data(struct CPUState *env, target_ulong ptr);
uint64_t cpu_ldq_data(struct CPUState *env, target_ulong ptr);
uint32_t cpu_ldub_code(struct CPUState *env, target_ulong ptr);
int cpu_ldsb_code(struct CPUState *env, target_ulong ptr);
uint32_t cpu_lduw_code(struct CPUState *env, target_ulong ptr);
int cpu_ldsw_code(struct CPUState *env, target_ulong ptr);
uint32_t cpu_ldl_code(struct CPUState *env, target_ulong ptr);
uint64_t cpu_ldq_code(struct CPUState *env, target_ulong ptr);
uint32_t cpu_ldub_data_ra(struct CPUState *env, target_ulong ptr,
                          uintptr_t retaddr);
int cpu_ldsb_data_ra(struct CPUState *env, target_ulong ptr, uintptr_t retaddr);
uint32_t cpu_lduw_data_ra(struct CPUState *env, target_ulong ptr,
                          uintptr_t retaddr);
int cpu_ldsw_data_ra(struct CPUState *env, target_ulong ptr, uintptr_t retaddr);
uint32_t cpu_ldl_data_ra(struct CPUState *env, target_ulong ptr,
                         uintptr_t retaddr);
uint64_t cpu_ldq_data_ra(struct CPUState *env, target_ulong ptr,
                         uintptr_t retaddr);
uint32_t cpu_ldub_code_ra(struct CPUState *env, target_ulong ptr,
                          uintptr_t retaddr);
uint32_t cpu_ldl_code_ra(struct CPUState *env, target_ulong ptr,
                         uintptr_t retaddr);
uint64_t cpu_ldq_code_ra(struct CPUState *env, target_ulong ptr,
                         uintptr_t retaddr);
int cpu_ldsb_code_ra(struct CPUState *env, target_ulong ptr, uintptr_t retaddr);
uint32_t cpu_lduw_code_ra(struct CPUState *env, target_ulong ptr,
                          uintptr_t retaddr);
int cpu_ldsw_code_ra(struct CPUState *env, target_ulong ptr, uintptr_t retaddr);

void *tlb_vaddr_to_host(struct CPUState *env, target_ulong addr,
                        int access_type, int mmu_idx);

void cpu_stq_data(struct CPUState *env, target_ulong ptr, uint64_t v);
void cpu_stq_data_ra(struct CPUState *env, target_ulong ptr, uint64_t v,
                     uintptr_t retaddr);
void cpu_stl_data(struct CPUState *env, target_ulong ptr, uint32_t v);
void cpu_stl_data_ra(struct CPUState *env, target_ulong ptr, uint32_t v,
                     uintptr_t retaddr);
void cpu_stw_data(struct CPUState *env, target_ulong ptr, uint32_t v);
void cpu_stw_data_ra(struct CPUState *env, target_ulong ptr, uint32_t v,
                     uintptr_t retaddr);
void cpu_stb_data(struct CPUState *env, target_ulong ptr, uint32_t v);
void cpu_stb_data_ra(struct CPUState *env, target_ulong ptr, uint32_t v,
                     uintptr_t retaddr);

/*
 * implementations of load/store functions
 */

uint32_t cpu_ldub_data(struct CPUState *env, target_ulong ptr) {
  return ldub_p((ptr - code_pc) + code);
}

int cpu_ldsb_data(struct CPUState *env, target_ulong ptr) {
  return ldsb_p((ptr - code_pc) + code);
}

uint32_t cpu_lduw_data(struct CPUState *env, target_ulong ptr) {
  return lduw_le_p((ptr - code_pc) + code);
}

int cpu_ldsw_data(struct CPUState *env, target_ulong ptr) {
  return ldsw_le_p((ptr - code_pc) + code);
}

uint32_t cpu_ldl_data(struct CPUState *env, target_ulong ptr) {
  return ldl_le_p((ptr - code_pc) + code);
}

uint64_t cpu_ldq_data(struct CPUState *env, target_ulong ptr) {
  return ldq_le_p((ptr - code_pc) + code);
}

uint32_t cpu_ldub_code(struct CPUState *env, target_ulong ptr) {
  return ldub_p((ptr - code_pc) + code);
}

int cpu_ldsb_code(struct CPUState *env, target_ulong ptr) {
  return ldsb_p((ptr - code_pc) + code);
}

uint32_t cpu_lduw_code(struct CPUState *env, target_ulong ptr) {
  return lduw_le_p((ptr - code_pc) + code);
}

int cpu_ldsw_code(struct CPUState *env, target_ulong ptr) {
  return ldsw_le_p((ptr - code_pc) + code);
}

uint32_t cpu_ldl_code(struct CPUState *env, target_ulong ptr) {
  return ldl_le_p((ptr - code_pc) + code);
}

uint64_t cpu_ldq_code(struct CPUState *env, target_ulong ptr) {
  return ldq_le_p((ptr - code_pc) + code);
}

uint32_t cpu_ldub_data_ra(struct CPUState *env, target_ulong ptr,
                          uintptr_t retaddr) {
  return cpu_ldub_data(env, ptr);
}

int cpu_ldsb_data_ra(struct CPUState *env, target_ulong ptr,
                     uintptr_t retaddr) {
  return cpu_ldsb_data(env, ptr);
}

uint32_t cpu_lduw_data_ra(struct CPUState *env, target_ulong ptr,
                          uintptr_t retaddr) {
  return cpu_lduw_data(env, ptr);
}

int cpu_ldsw_data_ra(struct CPUState *env, target_ulong ptr,
                     uintptr_t retaddr) {
  return cpu_ldsw_data(env, ptr);
}

uint32_t cpu_ldl_data_ra(struct CPUState *env, target_ulong ptr,
                         uintptr_t retaddr) {
  return cpu_ldl_data(env, ptr);
}

uint64_t cpu_ldq_data_ra(struct CPUState *env, target_ulong ptr,
                         uintptr_t retaddr) {
  return cpu_ldq_data(env, ptr);
}

uint32_t cpu_ldub_code_ra(struct CPUState *env, target_ulong ptr,
                          uintptr_t retaddr) {
  return cpu_ldub_code(env, ptr);
}

uint32_t cpu_ldl_code_ra(struct CPUState *env, target_ulong ptr,
                         uintptr_t retaddr) {
  return cpu_ldl_code(env, ptr);
}

uint64_t cpu_ldq_code_ra(struct CPUState *env, target_ulong ptr,
                         uintptr_t retaddr) {
  return cpu_ldq_code(env, ptr);
}

int cpu_ldsb_code_ra(struct CPUState *env, target_ulong ptr,
                     uintptr_t retaddr) {
  return cpu_ldsb_code(env, ptr);
}

uint32_t cpu_lduw_code_ra(struct CPUState *env, target_ulong ptr,
                          uintptr_t retaddr) {
  return cpu_lduw_code(env, ptr);
}

int cpu_ldsw_code_ra(struct CPUState *env, target_ulong ptr,
                     uintptr_t retaddr) {
  return cpu_ldsw_code(env, ptr);
}

void *tlb_vaddr_to_host(struct CPUState *env, target_ulong addr,
                        int access_type, int mmu_idx) {
  return NULL;
}

void cpu_stq_data(struct CPUState *env, target_ulong ptr, uint64_t v) {}
void cpu_stq_data_ra(struct CPUState *env, target_ulong ptr, uint64_t v,
                     uintptr_t retaddr) {}
void cpu_stl_data(struct CPUState *env, target_ulong ptr, uint32_t v) {}
void cpu_stl_data_ra(struct CPUState *env, target_ulong ptr, uint32_t v,
                     uintptr_t retaddr) {}
void cpu_stw_data(struct CPUState *env, target_ulong ptr, uint32_t v) {}
void cpu_stw_data_ra(struct CPUState *env, target_ulong ptr, uint32_t v,
                     uintptr_t retaddr) {}
void cpu_stb_data(struct CPUState *env, target_ulong ptr, uint32_t v) {}
void cpu_stb_data_ra(struct CPUState *env, target_ulong ptr, uint32_t v,
                     uintptr_t retaddr) {}
