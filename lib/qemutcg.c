#include "qemutcg.h"
#include "qemu/osdep.h"
#include "cpu.h"
#include "tcg.h"
#include <libgen.h>

char *tcg_get_arg_str_idx(TCGContext *s, char *buf, int buf_size, int idx);
const char *tcg_find_helper(TCGContext *s, uintptr_t val);

extern const uint8_t* code;
extern unsigned long code_len;
extern target_ulong code_pc;

extern const char *const cond_name[];
extern const char *const ldst_name[];

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
  env->hflags |= HF_LMA_MASK | HF_CS32_MASK | HF_CS64_MASK | HF_SS32_MASK |
                 HF_PE_MASK | HF_CPL_MASK;
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
  cpsr_write(env, CPSR_T, 0xffffffff, CPSRWriteByInstr);
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

unsigned libqemutcg_max_ops() {
  return OPC_BUF_SIZE;
}

unsigned libqemutcg_max_params() {
  return OPPARAM_BUF_SIZE;
}

unsigned libqemutcg_num_tmps() {
  return tcg_ctx.nb_temps;
}

unsigned libqemutcg_num_labels() {
  return tcg_ctx.nb_labels;
}

unsigned libqemutcg_first_op_index() {
  return tcg_ctx.gen_first_op_idx;
}

#ifndef max
#define max(a,b) ((a) > (b) ? (a) : (b))
#endif

void libqemutcg_copy_ops(void* dst) {
#if 0
  //
  // determine the max index which is used
  //

  int oi = tcg_ctx.gen_first_op_idx;
  int max_oi = oi;
  TCGOp *op;
  do {
    op = &tcg_ctx.gen_op_buf[oi];
    oi = op->next;
    max_oi = max(max_oi, oi);
  } while (oi >= 0);

#if 0
  int oi = tcg_ctx.gen_first_op_idx;
  for (;;) {
    TCGOp *op = &tcg_ctx.gen_op_buf[oi];
    if (op->next < 0)
      break;
    oi = op->next;
  }
#endif

  memcpy(dst, tcg_ctx.gen_op_buf, (max_oi + 1) * sizeof(TCGOp));
#else
  memcpy(dst, tcg_ctx.gen_op_buf, OPC_BUF_SIZE * sizeof(TCGOp));
#endif
}

void libqemutcg_copy_params(void* dst) {
#if 0
  //
  // determine the max index which is used
  //
  int oi = tcg_ctx.gen_first_op_idx;
  int max_args_idx = 0;
  TCGOp *op;
  do {
    op = &tcg_ctx.gen_op_buf[oi];
    oi = op->next;
    max_args_idx = max(max_args_idx, op->args + tcg_op_defs[op->opc].nb_args);
  } while (oi >= 0);

  memcpy(dst, tcg_ctx.gen_opparam_buf, (max_args_idx + 1) * sizeof(TCGArg));
#else
  memcpy(dst, tcg_ctx.gen_opparam_buf, OPPARAM_BUF_SIZE * sizeof(TCGArg));
#endif
}

void libqemutcg_copy_tmps(void* dst) {
  memcpy(((uint8_t *)dst) + tcg_ctx.nb_globals * sizeof(TCGTemp),
         tcg_ctx.temps + tcg_ctx.nb_globals,
         (tcg_ctx.nb_temps - tcg_ctx.nb_globals) * sizeof(TCGTemp));
}

void libqemutcg_print_ops(void) {
  TCGContext *const s = &tcg_ctx;
  char buf[128];
  char asmbuf[128];
  TCGOp *op;
  int oi;

  for (oi = s->gen_first_op_idx; oi >= 0; oi = op->next) {
    int i, k, nb_oargs, nb_iargs, nb_cargs;
    const TCGOpDef *def;
    const TCGArg *args;
    TCGOpcode c;

    op = &s->gen_op_buf[oi];
    c = op->opc;
    def = &tcg_op_defs[c];
    args = &s->gen_opparam_buf[op->args];

    if (c == INDEX_op_insn_start) {
      i = 0;
      target_ulong a;
#if TARGET_LONG_BITS > TCG_TARGET_REG_BITS
      a = ((target_ulong)args[i * 2 + 1] << 32) | args[i * 2];
#else
      a = args[i];
#endif
#if 0
      printf(" " TARGET_FMT_lx, a);

      printf("|%d", (int)(s->gen_first_op_idx - code_pc));
      printf("|%s", libmc_instr_asm((s->gen_first_op_idx - code_pc) + code,
                                    s->gen_first_op_idx - code_pc, asmbuf));
#endif

      if (a == 0x7FFFFFFF)
        continue;

      if (oi != s->gen_first_op_idx)
        printf("|\n"); /* make empty row */

#if 0
      if (a >= code_pc)
        printf("%s", libmc_instr_asm((a - code_pc) + code, a, asmbuf));
#endif

      continue;
    } else {
      printf("|");

      if (c == INDEX_op_call) {
        /* variable number of arguments */
        nb_oargs = op->callo;
        nb_iargs = op->calli;
        nb_cargs = def->nb_cargs;

        /* function name, flags, out args */
        printf("%s %s,$0x%" TCG_PRIlx ",$%d", def->name,
               tcg_find_helper(s, args[nb_oargs + nb_iargs]),
               args[nb_oargs + nb_iargs + 1], nb_oargs);

        for (i = 0; i < nb_oargs; i++)
          printf(",%s", tcg_get_arg_str_idx(s, buf, sizeof(buf), args[i]));

        for (i = 0; i < nb_iargs; i++) {
          TCGArg arg = args[nb_oargs + i];
          const char *t = "<dummy>";

          if (arg != TCG_CALL_DUMMY_ARG)
            t = tcg_get_arg_str_idx(s, buf, sizeof(buf), arg);

          printf(",%s", t);
        }
      } else {
        printf("%s ", def->name);

        nb_oargs = def->nb_oargs;
        nb_iargs = def->nb_iargs;
        nb_cargs = def->nb_cargs;

        k = 0;
        for (i = 0; i < nb_oargs; i++) {
          if (k != 0) {
            printf(",");
          }
          printf("%s", tcg_get_arg_str_idx(s, buf, sizeof(buf), args[k++]));
        }
        for (i = 0; i < nb_iargs; i++) {
          if (k != 0) {
            printf(",");
          }
          printf("%s", tcg_get_arg_str_idx(s, buf, sizeof(buf), args[k++]));
        }
        switch (c) {
        case INDEX_op_brcond_i32:
        case INDEX_op_setcond_i32:
        case INDEX_op_movcond_i32:
        case INDEX_op_brcond2_i32:
        case INDEX_op_setcond2_i32:
        case INDEX_op_brcond_i64:
        case INDEX_op_setcond_i64:
        case INDEX_op_movcond_i64:
          printf(",%s", cond_name[args[k++]]);
          i = 1;
          break;
        case INDEX_op_qemu_ld_i32:
        case INDEX_op_qemu_st_i32:
        case INDEX_op_qemu_ld_i64:
        case INDEX_op_qemu_st_i64: {
          TCGMemOpIdx oi = args[k++];
          TCGMemOp op = get_memop(oi);
          unsigned ix = get_mmuidx(oi);

          if (op & ~(MO_AMASK | MO_BSWAP | MO_SSIZE)) {
            printf(",$0x%x,%u", op, ix);
          } else {
            const char *s_al = "", *s_op;
            if (op & MO_AMASK) {
              if ((op & MO_AMASK) == MO_ALIGN) {
                s_al = "al+";
              } else {
                s_al = "un+";
              }
            }
            s_op = ldst_name[op & (MO_BSWAP | MO_SSIZE)];
            printf(",%s%s,%u", s_al, s_op, ix);
          }
          i = 1;
        } break;
        default:
          i = 0;
          break;
        }
        switch (c) {
        case INDEX_op_set_label:
        case INDEX_op_br:
        case INDEX_op_brcond_i32:
        case INDEX_op_brcond_i64:
        case INDEX_op_brcond2_i32:
          printf("%s$L%d", k ? "," : "", arg_label(args[k])->id);
          i++, k++;
          break;
        default:
          break;
        }
        for (; i < nb_cargs; i++, k++) {
          printf("%s$%s0x%" TCG_PRIlx, k ? "," : "",
                 ((tcg_target_long)args[k]) < 0 ? "-" : "",
                 ((tcg_target_long)args[k]) < 0 ? -((tcg_target_long)args[k])
                                                : args[k]);
        }
      }
    }
    printf("\n");
  }
}

uint64_t libqemutcg_last_tcg_op_addr(void) {
  uint64_t res = 0;
  TCGContext *const s = &tcg_ctx;
  TCGOp *op;

  for (int oi = s->gen_first_op_idx; oi >= 0; oi = op->next) {
    op = &s->gen_op_buf[oi];
    TCGOpcode c = op->opc;
    const TCGArg *args = &s->gen_opparam_buf[op->args];

    if (c == INDEX_op_insn_start) {
      int i = 0;
      target_ulong a;
#if TARGET_LONG_BITS > TCG_TARGET_REG_BITS
      a = ((target_ulong)args[i * 2 + 1] << 32) | args[i * 2];
#else
      a = args[i];
#endif

      if (a == 0x7FFFFFFF)
        continue;

      res = a;
    }
  }

  return res;
}

uint64_t libqemutcg_second_to_last_tcg_op_addr(void) {
  uint64_t res = 0, last_res = 0;
  TCGContext *const s = &tcg_ctx;
  TCGOp *op;

  for (int oi = s->gen_first_op_idx; oi >= 0; oi = op->next) {
    op = &s->gen_op_buf[oi];
    TCGOpcode c = op->opc;
    const TCGArg *args = &s->gen_opparam_buf[op->args];

    if (c == INDEX_op_insn_start) {
      int i = 0;
      target_ulong a;
#if TARGET_LONG_BITS > TCG_TARGET_REG_BITS
      a = ((target_ulong)args[i * 2 + 1] << 32) | args[i * 2];
#else
      a = args[i];
#endif

      if (a == 0x7FFFFFFF)
        continue;

      last_res = res;
      res = a;
    }
  }

  return last_res;
}

GHashTable *libqemutcg_helpers() { return tcg_ctx.helpers; }

extern TCGOpDef tcg_op_defs[];

void* libqemutcg_def_of_opcode(unsigned opc) {
  return &tcg_op_defs[opc];
}

const char* libqemutcg_find_helper(uintptr_t ptr) {
  return tcg_find_helper(&tcg_ctx, ptr);
}
