#include "obj2llvmdump_c.h"
#include "mc.h"
#include <tcg.h>

extern const uint8_t *code;
extern target_ulong code_pc;
uint64_t cpu_ldq_code(struct CPUState *env, target_ulong ptr);
char *tcg_get_arg_str_idx(TCGContext *s, char *buf, int buf_size, int idx);
const char *tcg_find_helper(TCGContext *s, uintptr_t val);
extern const char *const cond_name[];
extern const char *const ldst_name[];

void obj2llvmdump_print_ops() {
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

      printf(":%d", (int)(s->gen_first_op_idx - code_pc));
      printf(":%s", libmc_instr_asm((s->gen_first_op_idx - code_pc) + code,
                                    s->gen_first_op_idx - code_pc, asmbuf));
#endif
      if (oi != s->gen_first_op_idx)
        printf(":\n"); /* empty row */
      if (a > code_pc)
        printf("%s", libmc_instr_asm((a - code_pc) + code, a, asmbuf));

      continue;
    } else {
      printf(":");

      if (c == INDEX_op_call) {
        /* variable number of arguments */
        nb_oargs = op->callo;
        nb_iargs = op->calli;
        nb_cargs = def->nb_cargs;

        /* function name, flags, out args */
        printf("%s %s,$0x%" TCG_PRIlx ",$%d", def->name,
               tcg_find_helper(s, args[nb_oargs + nb_iargs]),
               args[nb_oargs + nb_iargs + 1], nb_oargs);
        for (i = 0; i < nb_oargs; i++) {
          printf(",%s", tcg_get_arg_str_idx(s, buf, sizeof(buf), args[i]));
        }
        for (i = 0; i < nb_iargs; i++) {
          TCGArg arg = args[nb_oargs + i];
          const char *t = "<dummy>";
          if (arg != TCG_CALL_DUMMY_ARG) {
            t = tcg_get_arg_str_idx(s, buf, sizeof(buf), arg);
          }
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

uint64_t obj2llvmdump_last_tcg_op_addr() {
  uint64_t res = 0xdeadbeef;
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
      res = a;
    }
  }

  return res;
}
