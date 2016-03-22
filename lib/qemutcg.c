#include "cpu.h"
#include "tcg.h"
#include <libgen.h>

void libqemutcg_init(const char *binfp);
void libqemutcg_translate(uint64_t);
void libqemutcg_test(void);

void libqemutcg_init(const char *binfp) {
  const char *cpu_model;
  CPUState *cpu;
  CPUArchState *env;

#if defined(TARGET_I386)
#ifdef TARGET_X86_64
  cpu_model = "qemu64";
#else
  cpu_model = "qemu32";
#endif
#else
  cpu_model = "any";
#endif
  tcg_context_init(&tcg_ctx);

  /* NOTE: we need to init the CPU at this stage to get
     qemu_host_page_size */
  cpu = cpu_init(cpu_model);
  if (!cpu)
    exit(22);
  env = cpu->env_ptr;
  cpu_reset(cpu);

  tcg_prologue_init(&tcg_ctx);

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

void libqemutcg_translate(uint64_t _pc) {
  target_ulong pc = _pc;
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
