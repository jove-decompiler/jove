#include "qemutcg.h"
#include "tcg.h"

static const char *tcg_type_nm_map[] = {"I32", "I64", "COUNT"};

static void dump_tcg_globals(void) {
  for (unsigned i = 0; i < tcg_ctx.nb_globals; ++i) {
    TCGTemp* ts = &tcg_ctx.temps[i];
    printf("type: %s name: %s reg: %u mem_reg: %u fixed_reg: %u mem_coherent: "
           "%u mem_allocated: %u mem_offset: %u\n",
           tcg_type_nm_map[ts->type], ts->name, (unsigned)ts->reg,
           (unsigned)ts->mem_reg, (unsigned)ts->fixed_reg,
           (unsigned)ts->mem_coherent, (unsigned)ts->mem_allocated,
           (unsigned)ts->mem_offset);
  }
}

static void print_tcg_globals(void) {
  for (unsigned i = 0; i < tcg_ctx.nb_globals; ++i) {
    TCGTemp* ts = &tcg_ctx.temps[i];

    // 
    // we are interested in TCG global memory regs, not TCG global regs (e.g. env).
    // From target-i386/translate.c:7865, we can see that a TCG global reg has
    // fixed_reg = 1
    //

    if (ts->fixed_reg)
      continue;

    printf("%s\n%u\n%s\n", tcg_type_nm_map[ts->type], (unsigned)ts->mem_offset,
           ts->name);
  }
}

int main(int argc, char** argv) {
  libqemutcg_init();
  print_tcg_globals();

  return 0;
}
