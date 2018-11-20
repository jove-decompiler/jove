#include "qemu/osdep.h"
#include "cpu.h"
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

static unsigned num_globals(void) {
  return tcg_ctx.nb_globals;
}

#define SET_NTH_BIT(number, n)                                                 \
  do {                                                                         \
    number |= 1ull << n;                                                       \
  } while (0)

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

    unsigned long long arg_regs = 0;
    unsigned long long ret_regs = 0;

    word = strtok(line1, " ");
    SET_NTH_BIT(arg_regs, tcg_global_of_name(word));
    while ((word = strtok(NULL, " ")) != NULL) {
      ++n_arg_regs;
      if (word[strlen(word)-1] == '\n') {
        word[strlen(word)-1] = '\0';
        SET_NTH_BIT(arg_regs, tcg_global_of_name(word));
        break;
      } else {
        SET_NTH_BIT(arg_regs, tcg_global_of_name(word));
      }
    }

    word = strtok(line2, " ");
    SET_NTH_BIT(ret_regs, tcg_global_of_name(word));
    while ((word = strtok(NULL, " ")) != NULL) {
      ++n_ret_regs;
      if (word[strlen(word)-1] == '\n') {
        word[strlen(word)-1] = '\0';
        SET_NTH_BIT(ret_regs, tcg_global_of_name(word));
        break;
      } else {
        SET_NTH_BIT(ret_regs, tcg_global_of_name(word));
      }
    }

    printf("#pragma once\n"
           "\n"
           "#include <bitset>\n"
           "\n"
           "namespace jove {\n"
           "constexpr unsigned call_conv_num_arg_regs = %u;\n"
           "constexpr unsigned call_conv_num_ret_regs = %u;\n"
           "constexpr std::bitset<%u> call_conv_arg_regs(%lluull);\n"
           "constexpr std::bitset<%u> call_conv_ret_regs(%lluull);\n"
           "}",
           n_arg_regs,
           n_ret_regs,
           num_globals(),
           arg_regs,
           num_globals(),
           ret_regs
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
