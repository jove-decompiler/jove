#include "tcg.h"
#include "qemutcg.h"

enum OUTPUT_TYPE {
  OUTPUT_TYPE_HEADER = 1,
  OUTPUT_TYPE_ARG_REGS_ARRAY = 2,
  OUTPUT_TYPE_RET_REGS_ARRAY = 3
};

static unsigned tcg_global_of_name(const char *name) {
  for (unsigned i = 0; i < tcg_ctx.nb_globals; ++i) {
    TCGTemp *ts = &tcg_ctx.temps[i];

    //
    // we are interested in TCG global memory regs, not TCG global regs (e.g.
    // env).
    // From target-i386/translate.c:7865, we can see that a TCG global reg has
    // fixed_reg = 1
    //

    if (ts->fixed_reg)
      continue;

    if (strcmp(ts->name, name) == 0)
      return i;
  }

  fprintf(stderr, "no match for tcg global with name %s\n", name);
  exit(1);
}

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: abi-callingconv outputtype callconvfile\n");
    return 1;
  }

  int output_ty = atoi(argv[1]);

  libqemutcg_init();

  FILE *f = fopen(argv[2], "r");

  char line1[256];
  char line2[256];

  fgets(line1, sizeof(line1), f);
  fgets(line2, sizeof(line2), f);

  char *word;
  switch (output_ty) {
  case OUTPUT_TYPE_HEADER: {
    unsigned n_arg_regs = 1;
    unsigned n_ret_regs = 1;

    word = strtok(line1, " ");
    while ((word = strtok(NULL, " ")) != NULL)
      ++n_arg_regs;

    word = strtok(line2, " ");
    while ((word = strtok(NULL, " ")) != NULL)
      ++n_ret_regs;

    printf("#pragma once\n"
           "\n"
           "namespace jove {\n"
           "constexpr unsigned call_conv_num_arg_regs = %u;\n"
           "constexpr unsigned call_conv_num_ret_regs = %u;\n"
           "}",
           n_arg_regs,
           n_ret_regs
           );
    break;
  }
  case OUTPUT_TYPE_ARG_REGS_ARRAY:
    word = strtok(line1, " ");
    printf("%u,\n", tcg_global_of_name(word));
    while ((word = strtok(NULL, " ")) != NULL) {
      if (word[strlen(word)-1] == '\n') {
        word[strlen(word)-1] = '\0';
        printf("%u,\n", tcg_global_of_name(word));
        break;
      } else {
        printf("%u,\n", tcg_global_of_name(word));
      }
    }

    break;
  case OUTPUT_TYPE_RET_REGS_ARRAY:
    word = strtok(line2, " ");
    printf("%u,\n", tcg_global_of_name(word));
    while ((word = strtok(NULL, " ")) != NULL) {
      if (word[strlen(word)-1] == '\n') {
        word[strlen(word)-1] = '\0';
        printf("%u,\n", tcg_global_of_name(word));
        break;
      } else {
        printf("%u,\n", tcg_global_of_name(word));
      }
    }

    break;
  default:
    fprintf(stderr, "unknown output type\n");
    exit(1);
  }

  fclose(f);
  return 0;
}
