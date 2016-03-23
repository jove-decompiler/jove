#include "cpu.h"
#include "tcg.h"
#include <libgen.h>
#include "qemutcg.h"

static const uint8_t* code;

#if defined(TARGET_I386)
void x86_cpu_register_types(void);
#elif defined(TARGET_ARM)
void arm_cpu_register_types(void);
#elif defined(TARGET_AARCH64)
void aarch64_cpu_register_types(void);
#endif
void register_types(void);
void qdev_register_types(void);
void cpu_register_types(void);

static MachineState *current_machine;
static MachineClass *machine_class;

void libqemutcg_init(void) {
  const char *cpu_model;
  CPUArchState *env;

  module_call_init(MODULE_INIT_QOM);
  module_call_init(MODULE_INIT_MACHINE);
  machine_class = find_default_machine();
  current_machine = MACHINE(object_new(object_class_get_name(OBJECT_CLASS(machine_class))));
  current_machine->cpu_model = cpu_model;
  current_machine->ram_size = machine_class->default_ram_size;
  current_machine->maxram_size = machine_class->default_ram_size;
  current_machine->ram_slots = 0;
  current_machine->boot_order = machine_class->default_boot_order;
#if defined(TARGET_I386)
#ifdef TARGET_X86_64
  current_machine->cpu_model = "qemu64";
#else
  current_machine->cpu_model = "qemu32";
#endif
#elif defined(TARGET_AARCH64) || defined(TARGET_ARM)
  current_machine->cpu_model = NULL;
#endif

  tcg_context_init(&tcg_ctx);
  tcg_prologue_init(&tcg_ctx);

#if defined(TARGET_I386)
  env = 
#elif defined(TARGET_AARCH64)
  current_machine->cpu_model = NULL;
#endif

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

#elif defined(TARGET_AARCH64)
    {
        if (!(arm_feature(env, ARM_FEATURE_AARCH64)))
            exit(24);
    }
#elif defined(TARGET_ARM)
    {
        // XXX TODO
#if 0
        /* Enable BE8.  */
        if (EF_ARM_EABI_VERSION(info->elf_flags) >= EF_ARM_EABI_VER4
            && (info->elf_flags & EF_ARM_BE8)) {
            env->bswap_code = 1;
        }
#endif
    }
#else
#error unsupported target CPU
#endif
}

void libqemutcg_set_code(const uint8_t* p) {
  code = p;
}

void libqemutcg_translate(unsigned off) {
  target_ulong pc = off;
  CPUArchState *env = first_cpu->env_ptr;

#if defined(TARGET_ARM)
  env->pc = pc;
#elif defined(TARGET_I386)
  env->eip = pc;
#else
#error "unsupported architecture"
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
  return ldub_p(ptr + code);
}

int cpu_ldsb_data(struct CPUState *env, target_ulong ptr) {
  return ldsb_p(ptr + code);
}

uint32_t cpu_lduw_data(struct CPUState *env, target_ulong ptr) {
  return lduw_le_p(ptr + code);
}

int cpu_ldsw_data(struct CPUState *env, target_ulong ptr) {
  return ldsw_le_p(ptr + code);
}

uint32_t cpu_ldl_data(struct CPUState *env, target_ulong ptr) {
  return ldl_le_p(ptr + code);
}

uint64_t cpu_ldq_data(struct CPUState *env, target_ulong ptr) {
  return ldq_le_p(ptr + code);
}

uint32_t cpu_ldub_code(struct CPUState *env, target_ulong ptr) {
  return ldub_p(ptr + code);
}

int cpu_ldsb_code(struct CPUState *env, target_ulong ptr) {
  return ldsb_p(ptr + code);
}

uint32_t cpu_lduw_code(struct CPUState *env, target_ulong ptr) {
  return lduw_le_p(ptr + code);
}

int cpu_ldsw_code(struct CPUState *env, target_ulong ptr) {
  return ldsw_le_p(ptr + code);
}

uint32_t cpu_ldl_code(struct CPUState *env, target_ulong ptr) {
  return ldl_le_p(ptr + code);
}

uint64_t cpu_ldq_code(struct CPUState *env, target_ulong ptr) {
  return ldq_le_p(ptr + code);
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
