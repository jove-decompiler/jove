#include "qemutcg.h"
#include "tcg.h"

static unsigned num_globals(void) {
  // don't include CPUState pointer
  return tcg_ctx.nb_globals - 1;
}

static unsigned num_helpers(void) {
  return g_hash_table_size(tcg_ctx.helpers);
}

int main(int argc, char** argv) {
  libqemutcg_init();

  printf("#pragma once\n"
         "\n"
         "namespace jove {\n"
         "namespace tcg {\n"
         "constexpr unsigned num_globals = %u;\n"
         "constexpr unsigned num_helpers = %u;\n"
         "}\n"
         "}",
         num_globals(),
         num_helpers());

  return 0;
}
