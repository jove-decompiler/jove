#include "tcgcommon.hpp"

#include <llvm/Support/InitLLVM.h>
#include <array>

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  jove::tiny_code_generator_t tcg;

  auto num_globals = [&](void) -> int { return tcg._ctx.nb_globals; };
  auto num_helpers = [&](void) -> int { return ARRAY_SIZE(all_helpers); };
  auto max_temps = [&](void) -> int { return TCG_MAX_TEMPS; };

  auto tcg_index_of_named_global = [&](const char *nm) -> int {
    int N = tcg._ctx.nb_globals;
    for (int i = 0; i < N; i++) {
      TCGTemp &ts = tcg._ctx.temps[i];
      if (strcmp(ts.name, nm) == 0)
        return i;
    }

    return -1;
  };

  auto print_call_conv_sets = [&](void) -> void {
    assert(num_globals() < 64);

#if defined(__x86_64__)
    const std::array<const char *, 6> arg_regs{"rdi", "rsi", "rdx", "rcx", "r8", "r9"};
    const std::array<const char *, 2> ret_regs{"rax", "rdx"};
#elif defined(__aarch64__)
    const std::array<const char *, 8> arg_regs = {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"};
    const std::array<const char *, 8> ret_regs = {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"};
#endif

    {
      std::bitset<64> s;
      for (const char *nm : arg_regs) {
        int idx = tcg_index_of_named_global(nm);
        assert(idx >= 0 && idx < s.size());
        s.set(idx);
      }

      printf("constexpr tcg_global_set_t CallConvArgs(%llu);\n", s.to_ullong());
    }

    {
      printf("constexpr std::array<unsigned, %u> CallConvArgArray{",
             static_cast<unsigned>(arg_regs.size()));

      bool first = true;
      for (const char *nm : arg_regs) {
        if (!first)
          printf(", ");

        int idx = tcg_index_of_named_global(nm);
        printf("%u", static_cast<unsigned>(idx));

        first = false;
      }

      printf("};\n");
    }

    {
      std::bitset<64> s;
      for (const char *nm : ret_regs) {
        int idx = tcg_index_of_named_global(nm);
        assert(idx >= 0 && idx < s.size());
        s.set(idx);
      }

      printf("constexpr tcg_global_set_t CallConvRets(%llu);\n", s.to_ullong());
    }

    {
      printf("constexpr std::array<unsigned, %u> CallConvRetArray{",
             static_cast<unsigned>(ret_regs.size()));

      bool first = true;
      for (const char *nm : ret_regs) {
        if (!first)
          printf(", ");

        int idx = tcg_index_of_named_global(nm);
        printf("%u", static_cast<unsigned>(idx));

        first = false;
      }

      printf("};\n");
    }
  };

  auto env_index = [&](void) -> int {
    return tcg_index_of_named_global("env");
  };
  auto program_counter_index = [&](void) -> int {
    return tcg_index_of_named_global("pc");
  };
  auto stack_pointer_index = [&](void) -> int {
#if defined(__x86_64__)
    return tcg_index_of_named_global("rsp");
#elif defined(__aarch64__)
    return tcg_index_of_named_global("sp");
#endif
  };
  auto program_counter_env_offset = [&](void) -> int {
#if defined(__x86_64__)
    return offsetof(CPUX86State, eip);
#elif defined(__aarch64__)
    return -1;
#endif
  };

  printf("#pragma once\n"
         "#include <bitset>\n"
         "#include <array>\n"
         "\n"
         "namespace jove {\n");

#define __TCG_CONST(NM) printf("constexpr int tcg_" #NM " = %d;\n", NM())

  __TCG_CONST(num_globals);
  __TCG_CONST(num_helpers);
  __TCG_CONST(max_temps);
  __TCG_CONST(env_index);
  __TCG_CONST(program_counter_index);
  __TCG_CONST(stack_pointer_index);
  __TCG_CONST(program_counter_env_offset);

#undef __TCG_CONST

  printf("typedef std::bitset<tcg_num_globals> tcg_global_set_t;\n");
  print_call_conv_sets();

  printf("}\n");

  return 0;
}
