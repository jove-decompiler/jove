#define JOVE_H // XXX

#include <llvm/Support/InitLLVM.h>
#include <array>

#include "tcgcommon.hpp"

namespace jove {
void _qemu_log(const char *cstr) { fputs(cstr, stdout); }
} // namespace jove

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  jove::tiny_code_generator_t tcg;

  auto num_globals = [&](void) -> int { return tcg._ctx.nb_globals; };
  auto num_helpers = [&](void) -> int { return ARRAY_SIZE(all_helpers); };
  auto max_temps = [&](void) -> int { return TCG_MAX_TEMPS; };

  auto tcg_index_of_named_global = [&](const char *nm) -> int {
    int res = -1;

    int N = tcg._ctx.nb_globals;
    for (int i = 0; i < N; i++) {
      TCGTemp &ts = tcg._ctx.temps[i];
      if (strcmp(ts.name, nm) == 0)
        res = i;
    }

    return res;
  };

  auto print_call_conv_sets = [&](void) -> void {
    assert(num_globals() < 64);

#if defined(__x86_64__)
    const std::array<const char *, 6> arg_regs{"rdi", "rsi", "rdx", "rcx", "r8", "r9"};
    //const std::array<const char *, 2> ret_regs{"rax", "rdx"};
    const std::array<const char *, 1> ret_regs{"rax"};
#elif defined(__i386__)
    const std::array<const char *, 0> arg_regs{};
    const std::array<const char *, 1> ret_regs{"eax"};
#elif defined(__aarch64__)
    const std::array<const char *, 8> arg_regs = {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"};
    //const std::array<const char *, 8> ret_regs = {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"};
    const std::array<const char *, 1> ret_regs = {"x0"};
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
      printf("typedef std::array<unsigned, %u> CallConvArgArrayTy;\n",
             static_cast<unsigned>(arg_regs.size()));
      printf("static const CallConvArgArrayTy CallConvArgArray{");

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
      printf("typedef std::array<unsigned, %u> CallConvRetArrayTy;\n",
             static_cast<unsigned>(ret_regs.size()));
      printf("static const CallConvRetArrayTy CallConvRetArray{");

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

  auto print_lookup_by_mem_offset = [&](void) -> void {
    unsigned max_offset = 0;

    for (int i = 0; i < tcg._ctx.nb_globals; i++) {
      TCGTemp &ts = tcg._ctx.temps[i];
      max_offset = std::max<unsigned>(max_offset, ts.mem_offset);
    }

    printf("static const int8_t tcg_global_by_offset_lookup_table[%u] = {\n"
           "[0 ... %u] = -1,\n", max_offset + 1, max_offset);

    for (int i = 0; i < tcg._ctx.nb_globals; i++) {
      TCGTemp &ts = tcg._ctx.temps[i];

      if (!ts.mem_base)
        continue;

      if (strcmp(ts.mem_base->name, "env") != 0)
        continue;

      printf("[%u] = %d,\n", static_cast<unsigned>(ts.mem_offset), i);
    }

    printf("};\n");
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
#elif defined(__i386__)
    return tcg_index_of_named_global("esp");
#elif defined(__aarch64__)
    return tcg_index_of_named_global("sp");
#endif
  };
  auto frame_pointer_index = [&](void) -> int {
#if defined(__x86_64__)
    return tcg_index_of_named_global("rbp");
#elif defined(__i386__)
    return tcg_index_of_named_global("ebp");
#elif defined(__aarch64__)
    return tcg_index_of_named_global("x29");
#endif
  };
  auto program_counter_env_offset = [&](void) -> int {
#if defined(__x86_64__) || defined(__i386__)
    return offsetof(CPUX86State, eip);
#elif defined(__aarch64__)
    return -1;
#endif
  };
  auto syscall_number_index = [&](void) -> int {
#if defined(__x86_64__)
    return tcg_index_of_named_global("rax");
#elif defined(__i386__)
    return tcg_index_of_named_global("eax");
#elif defined(__aarch64__)
    return tcg_index_of_named_global("x8");
#endif
  };

  auto syscall_arg1_index = [&](void) -> int {
#if defined(__x86_64__)
    return tcg_index_of_named_global("rdi");
#elif defined(__i386__)
    return tcg_index_of_named_global("ebx");
#elif defined(__aarch64__)
    return tcg_index_of_named_global("x0");
#endif
  };
  auto syscall_arg2_index = [&](void) -> int {
#if defined(__x86_64__)
    return tcg_index_of_named_global("rsi");
#elif defined(__i386__)
    return tcg_index_of_named_global("ecx");
#elif defined(__aarch64__)
    return tcg_index_of_named_global("x1");
#endif
  };
  auto syscall_arg3_index = [&](void) -> int {
#if defined(__x86_64__)
    return tcg_index_of_named_global("rdx");
#elif defined(__i386__)
    return tcg_index_of_named_global("edx");
#elif defined(__aarch64__)
    return tcg_index_of_named_global("x2");
#endif
  };
  auto syscall_arg4_index = [&](void) -> int {
#if defined(__x86_64__)
    return tcg_index_of_named_global("r10");
#elif defined(__i386__)
    return tcg_index_of_named_global("esi");
#elif defined(__aarch64__)
    return tcg_index_of_named_global("x3");
#endif
  };
  auto syscall_arg5_index = [&](void) -> int {
#if defined(__x86_64__)
    return tcg_index_of_named_global("r8");
#elif defined(__i386__)
    return tcg_index_of_named_global("edi");
#elif defined(__aarch64__)
    return tcg_index_of_named_global("x4");
#endif
  };
  auto syscall_arg6_index = [&](void) -> int {
#if defined(__x86_64__)
    return tcg_index_of_named_global("r9");
#elif defined(__i386__)
    return tcg_index_of_named_global("ebp");
#elif defined(__aarch64__)
    return tcg_index_of_named_global("x5");
#endif
  };

#if defined(__x86_64__)
  auto fs_base_index = [&](void) -> int {
    return tcg_index_of_named_global("fs_base");
  };

  auto r12_index = [&](void) -> int {
    return tcg_index_of_named_global("r12");
  };

  auto r13_index = [&](void) -> int {
    return tcg_index_of_named_global("r13");
  };

  auto r14_index = [&](void) -> int {
    return tcg_index_of_named_global("r14");
  };

  auto r15_index = [&](void) -> int {
    return tcg_index_of_named_global("r15");
  };
#endif

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
  __TCG_CONST(frame_pointer_index);
  __TCG_CONST(stack_pointer_index);
  __TCG_CONST(program_counter_env_offset);
  __TCG_CONST(syscall_number_index);
  __TCG_CONST(syscall_arg1_index);
  __TCG_CONST(syscall_arg2_index);
  __TCG_CONST(syscall_arg3_index);
  __TCG_CONST(syscall_arg4_index);
  __TCG_CONST(syscall_arg5_index);
  __TCG_CONST(syscall_arg6_index);

#if defined(__x86_64__)
  __TCG_CONST(fs_base_index);
  __TCG_CONST(r12_index);
  __TCG_CONST(r13_index);
  __TCG_CONST(r14_index);
  __TCG_CONST(r15_index);
#endif

#undef __TCG_CONST

  printf("typedef std::bitset<tcg_num_globals> tcg_global_set_t;\n");
  print_call_conv_sets();
  print_lookup_by_mem_offset();

  printf("}\n");

  return 0;
}
