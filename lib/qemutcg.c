#include "cpu.h"
#include "tcg.h"
#include <libgen.h>
#include "qemutcg.h"

static const uint8_t* code;
static target_ulong code_pc;

void object_do_qemu_init_register_types(void);
void object_interfaces_do_qemu_init_register_types(void);
void do_qemu_init_cpu_register_types(void);
void do_qemu_init_container_register_types(void);
void do_qemu_init_fw_path_provider_register_types(void);
void do_qemu_init_hotplug_handler_register_types(void);
void do_qemu_init_irq_register_types(void);
void do_qemu_init_nmi_register_types(void);
void do_qemu_init_qdev_register_types(void);
void init_get_clock(void);
void qemu_thread_atexit_init(void);
void rcu_init(void);

#if defined(TARGET_I386)
void do_qemu_init_x86_cpu_register_types(void);
#elif defined(TARGET_ARM)
void do_qemu_init_arm_cpu_register_types(void);
#if defined(TARGET_AARCH64)
void do_qemu_init_aarch64_cpu_register_types(void);
#endif
#endif

void libqemutcg_init(void) {
  const char *cpu_model;
  CPUState *cpu;
  CPUArchState *env;

  object_do_qemu_init_register_types();
  object_interfaces_do_qemu_init_register_types();
  do_qemu_init_cpu_register_types();
  do_qemu_init_container_register_types();
  do_qemu_init_fw_path_provider_register_types();
  do_qemu_init_hotplug_handler_register_types();
  do_qemu_init_irq_register_types();
  do_qemu_init_nmi_register_types();
  do_qemu_init_qdev_register_types();
  init_get_clock();
  qemu_thread_atexit_init();
  rcu_init();

#if defined(TARGET_I386)
  do_qemu_init_x86_cpu_register_types();
#elif defined(TARGET_ARM)
  do_qemu_init_arm_cpu_register_types();
#if defined(TARGET_AARCH64)
  do_qemu_init_aarch64_cpu_register_types();
#endif
#endif

  module_call_init(MODULE_INIT_QOM);

#if defined(TARGET_I386)
#ifdef TARGET_X86_64
  cpu_model = "qemu64";
#else
  cpu_model = "qemu32";
#endif
#else
  cpu_model = "any";
#endif

  tcg_exec_init(0);

  /* NOTE: we need to init the CPU at this stage to get
          qemu_host_page_size */
  cpu = cpu_init(cpu_model);
  if (!cpu)
    exit(22);
  env = cpu->env_ptr;
  cpu_reset(cpu);


#if defined(TARGET_I386)
  env->cr[0] = CR0_PG_MASK | CR0_WP_MASK | CR0_PE_MASK;
  env->hflags |= HF_PE_MASK | HF_CPL_MASK;
  if (env->features[FEAT_1_EDX] & CPUID_SSE) {
    env->cr[4] |= CR4_OSFXSR_MASK;
    env->hflags |= HF_OSFXSR_MASK;
  }
#ifndef TARGET_ABI32
  /* enable 64 bit mode if possible */
  if (!(env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_LM))
    exit(23);
  env->cr[4] |= CR4_PAE_MASK;
  env->efer |= MSR_EFER_LMA | MSR_EFER_LME;
  env->hflags |= HF_LMA_MASK;
#endif
  /* flags setup : we activate the IRQs by default as in user mode */
  env->eflags |= IF_MASK;
  memset(env->segs, 0, sizeof(env->segs));
#elif defined(TARGET_ARM)
  memset(env->regs, 0, sizeof(env->regs));
  // XXX TODO BE8 if ELF flags has EF_ARM_BE8
#if defined(TARGET_AARCH64)
  if (!(arm_feature(env, ARM_FEATURE_AARCH64)) || !env->aarch64)
    exit(24);

  memset(env->xregs, 0, sizeof(env->xregs));
#endif
#endif
}

void libqemutcg_set_code(const uint8_t* p, unsigned long pc) {
  code = p;
  code_pc = pc;
}

void libqemutcg_translate(unsigned long _pc) {
  target_ulong pc = _pc;

  CPUArchState *env = first_cpu->env_ptr;

#if defined(TARGET_AARCH64)
  env->pc = pc;
#elif defined(TARGET_ARM)
  env->regs[15] = pc;
#elif defined(TARGET_I386)
  env->eip = pc;
#endif

  target_ulong cs_base;
  int flags;
  int cflags = 0;
  cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);

  TranslationBlock tb;
  tb.pc = pc;
  tb.tc_ptr = tcg_ctx.code_gen_ptr;
  tb.cs_base = cs_base;
  tb.flags = flags;
  tb.cflags = cflags;

  tcg_func_start(&tcg_ctx);

  gen_intermediate_code(env, &tb);

  qemu_log_set_file(stdout);
  tcg_dump_ops(&tcg_ctx);
}

static const char *tcg_type_nm_map[] = {"i32", "i64", "count"};

void libqemutcg_test(void) {
  printf("tcg globals:\n");
  for (unsigned i = 0; i < tcg_ctx.nb_globals; ++i) {
    TCGTemp* ts = &tcg_ctx.temps[i];
    printf("%s %s\n", tcg_type_nm_map[ts->type], ts->name);
  }
  printf("end of tcg globals\n");
}

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
