#include "cpu.h"
#include "tcg.h"
#include <libgen.h>
#include "qemutcg.h"

extern const uint8_t* code;
extern unsigned long code_len;
extern target_ulong code_pc;

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
#elif defined(TARGET_MIPS)
void do_qemu_init_mips_cpu_register_types(void);
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
#elif defined(TARGET_MIPS)
  do_qemu_init_mips_cpu_register_types();
#endif

  module_call_init(MODULE_INIT_QOM);

#if defined(TARGET_X86_64)
  cpu_model = "qemu64";
#elif defined(TARGET_I386)
  cpu_model = "qemu32";
#elif defined(TARGET_MIPS)
#if defined(TARGET_ABI_MIPSN32) || defined(TARGET_ABI_MIPSN64)
  cpu_model = "5KEf";
#else
  cpu_model = "24Kf";
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

#if defined(TARGET_X86_64)
  env->cr[0] = CR0_PG_MASK | CR0_WP_MASK | CR0_PE_MASK;
  if (env->features[FEAT_1_EDX] & CPUID_SSE) {
    env->cr[4] |= CR4_OSFXSR_MASK;
    env->hflags |= HF_OSFXSR_MASK;
  }
  memset(env->segs, 0, sizeof(env->segs));

  env->cr[4] |= CR4_PAE_MASK;
  env->efer |= MSR_EFER_LMA | MSR_EFER_LME;
  env->hflags |= HF_LMA_MASK | HF_CS32_MASK | HF_CS64_MASK | HF_SS32_MASK | HF_PE_MASK | HF_CPL_MASK;
  env->eflags |= IF_MASK;
#elif defined(TARGET_I386)
  env->cr[0] = CR0_PG_MASK | CR0_WP_MASK | CR0_PE_MASK;
  if (env->features[FEAT_1_EDX] & CPUID_SSE) {
    env->cr[4] |= CR4_OSFXSR_MASK;
    env->hflags |= HF_OSFXSR_MASK;
  }
  memset(env->segs, 0, sizeof(env->segs));

  env->hflags |= HF_CS32_MASK | HF_PE_MASK | HF_CPL_MASK;
#elif defined(TARGET_ARM)
  memset(env->regs, 0, sizeof(env->regs));
  // XXX TODO enable BE8 based on ELF flags (has EF_ARM_BE8)
  // XXX TODO enable thumb based on ELF flags
  cpsr_write(env, CPSR_T, 0xffffffff);
#if defined(TARGET_AARCH64)
  if (!(arm_feature(env, ARM_FEATURE_AARCH64)) || !env->aarch64)
    exit(24);

  memset(env->xregs, 0, sizeof(env->xregs));
#else
  env->thumb = 1;
#endif
#elif defined(TARGET_MIPS)
  memset(env->active_tc.gpr, 0, sizeof(env->active_tc.gpr));
#endif
}

void libqemutcg_set_code(const uint8_t *p, unsigned long len,
                         unsigned long pc) {
  code = p;
  code_pc = pc;
  code_len = len;
}

unsigned libqemutcg_translate(unsigned long _pc) {
  target_ulong pc = _pc;

  CPUArchState *env = first_cpu->env_ptr;

#if defined(TARGET_AARCH64)
  env->pc = pc;
#elif defined(TARGET_ARM)
  env->regs[15] = pc;
#elif defined(TARGET_I386)
  env->eip = pc;
#elif defined(TARGET_MIPS)
  env->active_tc.PC = pc;
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

  /* XXX we delete call to gen_tb_end() to get rid of using tcg_exit_req, but
   * we need this line here.
   */
  /* Terminate the linked list.  */
  tcg_ctx.gen_op_buf[tcg_ctx.gen_last_op_idx].next = -1;

  return tb.size;
}
