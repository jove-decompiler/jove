#include "tcg.h"
#include "qemutcg.h"

static const char *tcg_global_enum_map[] = {
    "tcg::GLOBAL_I32", "tcg::GLOBAL_I64", "tcg::UNDEFINED"};

static void print_tcg_globals_definition(void) {
  for (unsigned i = 0; i < tcg_ctx.nb_globals; ++i) {
    TCGTemp *ts = &tcg_ctx.temps[i];

    //
    // we are interested in TCG global memory regs, not TCG global regs (e.g.
    // env).
    // From target-i386/translate.c:7865, we can see that a TCG global reg has
    // fixed_reg = 1
    //

    printf("{%s, %u, \"%s\"}%s\n",
           ts->fixed_reg ? tcg_global_enum_map[2]
                         : tcg_global_enum_map[ts->type],
           ts->fixed_reg ? 0xdead : (unsigned)ts->mem_offset,
           ts->name,
           i + 1 == tcg_ctx.nb_globals ? "" : ",");
  }
}

static unsigned num_globals(void) {
  // don't include CPUState pointer
  return tcg_ctx.nb_globals;
}

static unsigned num_helpers(void) { return g_hash_table_size(tcg_ctx.helpers); }

int main(int argc, char **argv) {
  libqemutcg_init();

  if (argc > 1)
    print_tcg_globals_definition();
  else
    printf("#pragma once\n"
           "\n"
           "namespace jove {\n"
           "namespace tcg {\n"
           "constexpr unsigned num_globals = %u;\n"
           "constexpr unsigned num_helpers = %u;\n"
           "}\n"
           "}",
           num_globals(), num_helpers());

  return 0;
}
