#include "tcgcommon.hpp"
#include <llvm/Support/InitLLVM.h>
#include <array>

namespace jove {
void _qemu_log(const char *cstr) { fputs(cstr, stdout); }
} // namespace jove

static const char *cstr_of_tcg_type(TCGType x) {
#define ___CASE(text)                                                          \
  if (x == BOOST_PP_CAT(TCG_TYPE_, text))                                      \
    return BOOST_PP_STRINGIZE(text);

  ___CASE(I32);
  ___CASE(I64);
  ___CASE(V64);
  ___CASE(V128);
  ___CASE(V256);

#undef ___CASE

  abort();
}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  jove::tiny_code_generator_t tcg;

  auto num_globals = [&](void) -> int { return tcg._ctx.nb_globals; };
  auto num_helpers = [&](void) -> int { return ARRAY_SIZE(all_helpers); };
  auto max_temps = [&](void) -> int { return TCG_MAX_TEMPS; };

  auto tcg_index_of_named_global = [&](const char *nm) -> int {
    for (int i = 0; i < tcg._ctx.nb_globals; i++) {
      if (strcmp(tcg._ctx.temps[i].name, nm) == 0)
        return i;
    }

    return -1;
  };

  auto print_call_conv_sets = [&](void) -> void {
#if defined(TARGET_X86_64)
    const std::array<const char *, 6> arg_regs{"rdi", "rsi", "rdx", "rcx", "r8", "r9"};
    const std::array<const char *, 2> ret_regs{"rax", "rdx"};
#elif defined(TARGET_I386)
    const std::array<const char *, 3> arg_regs{"eax", "edx", "ecx"};
    const std::array<const char *, 2> ret_regs{"eax", "edx"};
#elif defined(TARGET_AARCH64)
    const std::array<const char *, 8> arg_regs = {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"};
    const std::array<const char *, 8> ret_regs = {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"};
#elif defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
    const std::array<const char *, 4> arg_regs = {"a0", "a1", "a2", "a3"};
    const std::array<const char *, 2> ret_regs = {"v0", "v1"};
#else
#error
#endif

    {
      jove::tcg_global_set_t s;
      for (const char *nm : arg_regs) {
        int idx = tcg_index_of_named_global(nm);
        assert(idx >= 0 && idx < s.size());
        s.set(idx);
      }

      try {
        printf("constexpr tcg_global_set_t CallConvArgs(%llu);\n", s.to_ullong());
      } catch (...) {
        std::string str = s.to_string();
        printf("static const tcg_global_set_t CallConvArgs(\"%s\");\n", str.c_str());
      }
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
      jove::tcg_global_set_t s;
      for (const char *nm : ret_regs) {
        int idx = tcg_index_of_named_global(nm);
        assert(idx >= 0 && idx < s.size());
        s.set(idx);
      }

      try {
        printf("constexpr tcg_global_set_t CallConvRets(%llu);\n", s.to_ullong());
      } catch (...) {
        std::string str = s.to_string();
        printf("static const tcg_global_set_t CallConvRets(\"%s\");\n", str.c_str());
      }
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

  auto print_not_sets = [&](void) -> void {
#if defined(TARGET_X86_64)
    const std::array<const char *, 16> not_arg_or_ret_regs{
      "_frame",
      "env",
      "es_base",
      "cs_base",
      "ss_base",
      "ds_base",
      "fs_base",
      "gs_base",
      "bnd0_lb",
      "bnd0_ub",
      "bnd1_lb",
      "bnd1_ub",
      "bnd2_lb",
      "bnd2_ub",
      "bnd3_lb",
      "bnd3_ub"
    };

    const auto &not_ret_regs = not_arg_or_ret_regs;
    const auto &not_arg_regs = not_arg_or_ret_regs;
#elif defined(TARGET_I386)
    const std::array<const char *, 24> not_arg_or_ret_regs{
      "_frame",
      "env",
      "es_base",
      "cs_base",
      "ss_base",
      "ds_base",
      "fs_base",
      "gs_base",
      "bnd0_lb_0",
      "bnd0_lb_1",
      "bnd0_ub_0",
      "bnd0_ub_1",
      "bnd1_lb_0",
      "bnd1_lb_1",
      "bnd1_ub_0",
      "bnd1_ub_1",
      "bnd2_lb_0",
      "bnd2_lb_1",
      "bnd2_ub_0",
      "bnd2_ub_1",
      "bnd3_lb_0",
      "bnd3_lb_1",
      "bnd3_ub_0",
      "bnd3_ub_1",
    };

    const auto &not_ret_regs = not_arg_or_ret_regs;
    const auto &not_arg_regs = not_arg_or_ret_regs;
#elif defined(TARGET_AARCH64)
    const std::array<const char *, 3> not_arg_regs{
      "env",
      "pc",
      "PC"
    };

    const std::array<const char *, 4> not_ret_regs{
      "env",
      "pc",
      "PC",
      "lr"
    };
#elif defined(TARGET_MIPS64)
    const std::array<const char *, 3> not_arg_or_ret_regs{
      "_frame",
      "env",
      "PC",
    };

    const auto &not_ret_regs = not_arg_or_ret_regs;
    const auto &not_arg_regs = not_arg_or_ret_regs;
#elif defined(TARGET_MIPS32)
    const std::array<const char *, 3> not_arg_regs{
      "_frame",
      "env",
      "PC",
    };

    const std::array<const char *, 5> not_ret_regs{
      "_frame",
      "env",
      "PC",
      "ra",
      "gp",
    };
#else
#error
#endif

    {
      jove::tcg_global_set_t s;
      for (const char *nm : not_arg_regs) {
        int idx = tcg_index_of_named_global(nm);
        assert(idx >= 0 && idx < s.size());
        s.set(idx);
      }

      try {
        printf("constexpr tcg_global_set_t NotArgs(%llu);\n", s.to_ullong());
      } catch (...) {
        std::string str = s.to_string();
        printf("static const tcg_global_set_t NotArgs(\"%s\");\n", str.c_str());
      }
    }

    {
      jove::tcg_global_set_t s;
      for (const char *nm : not_ret_regs) {
        int idx = tcg_index_of_named_global(nm);
        assert(idx >= 0 && idx < s.size());
        s.set(idx);
      }

      try {
        printf("constexpr tcg_global_set_t NotRets(%llu);\n", s.to_ullong());
      } catch (...) {
        std::string str = s.to_string();
        printf("static const tcg_global_set_t NotRets(\"%s\");\n", str.c_str());
      }
    }
  };

  auto print_callee_saved_registers = [&](void) -> void {
#if defined(TARGET_X86_64)
    const std::array<const char *, 6> callee_saved_regs{
      "rbx",
      "rbp",
      "r12",
      "r13",
      "r14",
      "r15"
    };
#elif defined(TARGET_I386)
    const std::array<const char *, 4> callee_saved_regs{
      "ebx",
      "ebp",
      "esi",
      "edi",
    };
#elif defined(TARGET_AARCH64)
    const std::array<const char *, 10> callee_saved_regs{
      "x19",
      "x20",
      "x21",
      "x22",
      "x23",
      "x24",
      "x25",
      "x26",
      "x27",
      "x28",
    };
#elif defined(TARGET_MIPS64)
    const std::array<const char *, 8> callee_saved_regs{
      "s0",
      "s1",
      "s2",
      "s3",
      "s4",
      "s5",
      "s6",
      "s7",
    };
#elif defined(TARGET_MIPS32)
    const std::array<const char *, 8> callee_saved_regs{
      "s0",
      "s1",
      "s2",
      "s3",
      "s4",
      "s5",
      "s6",
      "s7",
    };
#else
#error
#endif

    {
      jove::tcg_global_set_t s;
      for (const char *nm : callee_saved_regs) {
        int idx = tcg_index_of_named_global(nm);
        assert(idx >= 0 && idx < s.size());
        s.set(idx);
      }

      try {
        printf("constexpr tcg_global_set_t CalleeSavedRegs(%llu);\n", s.to_ullong());
      } catch (...) {
        std::string str = s.to_string();
        printf("static const tcg_global_set_t CalleeSavedRegs(\"%s\");\n", str.c_str());
      }
    }
  };

  auto print_lookup_by_mem_offset = [&](void) -> void {
    unsigned max_offset = 0;

    for (int i = 0; i < tcg._ctx.nb_globals; i++) {
      TCGTemp &ts = tcg._ctx.temps[i];
      max_offset = std::max<unsigned>(max_offset, ts.mem_offset);
    }

    printf("static const uint8_t tcg_global_by_offset_lookup_table[%u] = {\n"
           "[0 ... %u] = 0xff,\n", max_offset + 1, max_offset);

    for (int i = 0; i < tcg._ctx.nb_globals; i++) {
      TCGTemp &ts = tcg._ctx.temps[i];

      if (!ts.mem_base || strcmp(ts.mem_base->name, "env") != 0)
        continue;

      // global index must fit in a uint8_t
      assert(i < 0xff);

      printf("[%u] = %d,\n", static_cast<unsigned>(ts.mem_offset), i);
    }

    printf("};\n");
  };

  auto print_pinned_env_globals = [&](void) -> void {
#if defined(TARGET_MIPS32)
    const std::array<const char *, 131> pinned_env_glbs{
      "w0.d0_0",
      "w0.d0_1",
      "w0.d1_0",
      "w0.d1_1",
      "w1.d0_0",
      "w1.d0_1",
      "w1.d1_0",
      "w1.d1_1",
      "w2.d0_0",
      "w2.d0_1",
      "w2.d1_0",
      "w2.d1_1",
      "w3.d0_0",
      "w3.d0_1",
      "w3.d1_0",
      "w3.d1_1",
      "w4.d0_0",
      "w4.d0_1",
      "w4.d1_0",
      "w4.d1_1",
      "w5.d0_0",
      "w5.d0_1",
      "w5.d1_0",
      "w5.d1_1",
      "w6.d0_0",
      "w6.d0_1",
      "w6.d1_0",
      "w6.d1_1",
      "w7.d0_0",
      "w7.d0_1",
      "w7.d1_0",
      "w7.d1_1",
      "w8.d0_0",
      "w8.d0_1",
      "w8.d1_0",
      "w8.d1_1",
      "w9.d0_0",
      "w9.d0_1",
      "w9.d1_0",
      "w9.d1_1",
      "w10.d0_0",
      "w10.d0_1",
      "w10.d1_0",
      "w10.d1_1",
      "w11.d0_0",
      "w11.d0_1",
      "w11.d1_0",
      "w11.d1_1",
      "w12.d0_0",
      "w12.d0_1",
      "w12.d1_0",
      "w12.d1_1",
      "w13.d0_0",
      "w13.d0_1",
      "w13.d1_0",
      "w13.d1_1",
      "w14.d0_0",
      "w14.d0_1",
      "w14.d1_0",
      "w14.d1_1",
      "w15.d0_0",
      "w15.d0_1",
      "w15.d1_0",
      "w15.d1_1",
      "w16.d0_0",
      "w16.d0_1",
      "w16.d1_0",
      "w16.d1_1",
      "w17.d0_0",
      "w17.d0_1",
      "w17.d1_0",
      "w17.d1_1",
      "w18.d0_0",
      "w18.d0_1",
      "w18.d1_0",
      "w18.d1_1",
      "w19.d0_0",
      "w19.d0_1",
      "w19.d1_0",
      "w19.d1_1",
      "w20.d0_0",
      "w20.d0_1",
      "w20.d1_0",
      "w20.d1_1",
      "w21.d0_0",
      "w21.d0_1",
      "w21.d1_0",
      "w21.d1_1",
      "w22.d0_0",
      "w22.d0_1",
      "w22.d1_0",
      "w22.d1_1",
      "w23.d0_0",
      "w23.d0_1",
      "w23.d1_0",
      "w23.d1_1",
      "w24.d0_0",
      "w24.d0_1",
      "w24.d1_0",
      "w24.d1_1",
      "w25.d0_0",
      "w25.d0_1",
      "w25.d1_0",
      "w25.d1_1",
      "w26.d0_0",
      "w26.d0_1",
      "w26.d1_0",
      "w26.d1_1",
      "w27.d0_0",
      "w27.d0_1",
      "w27.d1_0",
      "w27.d1_1",
      "w28.d0_0",
      "w28.d0_1",
      "w28.d1_0",
      "w28.d1_1",
      "w29.d0_0",
      "w29.d0_1",
      "w29.d1_0",
      "w29.d1_1",
      "w30.d0_0",
      "w30.d0_1",
      "w30.d1_0",
      "w30.d1_1",
      "w31.d0_0",
      "w31.d0_1",
      "w31.d1_0",
      "w31.d1_1",
      "hflags",
      "fcr0",
      "fcr31"
    };
#else
    const std::array<const char *, 0> pinned_env_glbs{};
#endif

    {
      jove::tcg_global_set_t s;
      for (const char *nm : pinned_env_glbs) {
        int idx = tcg_index_of_named_global(nm);
        assert(idx >= 0 && idx < s.size());
        s.set(idx);
      }

      try {
        printf("constexpr tcg_global_set_t PinnedEnvGlbs(%llu);\n", s.to_ullong());
      } catch (...) {
        std::string str = s.to_string();
        printf("static const tcg_global_set_t PinnedEnvGlbs(\"%s\");\n", str.c_str());
      }
    }
  };

  auto env_index = [&](void) -> int {
    return tcg_index_of_named_global("env");
  };
  auto program_counter_index = [&](void) -> int {
#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32) || defined(TARGET_AARCH64)
    return tcg_index_of_named_global("PC");
#else
    return tcg_index_of_named_global("pc");
#endif
  };
  auto stack_pointer_index = [&](void) -> int {
#if defined(TARGET_X86_64)
    return tcg_index_of_named_global("rsp");
#elif defined(TARGET_I386)
    return tcg_index_of_named_global("esp");
#elif defined(TARGET_AARCH64)
    return tcg_index_of_named_global("sp");
#elif defined(TARGET_MIPS64)
    return tcg_index_of_named_global("sp");
#elif defined(TARGET_MIPS32)
    return tcg_index_of_named_global("sp");
#else
#error
#endif
  };
  auto frame_pointer_index = [&](void) -> int {
#if defined(TARGET_X86_64)
    return tcg_index_of_named_global("rbp");
#elif defined(TARGET_I386)
    return tcg_index_of_named_global("ebp");
#elif defined(TARGET_AARCH64)
    return tcg_index_of_named_global("x29");
#elif defined(TARGET_MIPS64)
    return tcg_index_of_named_global("s8");
#elif defined(TARGET_MIPS32)
    return tcg_index_of_named_global("s8");
#else
#error
#endif
  };
  auto program_counter_env_offset = [&](void) -> int {
#if defined(TARGET_X86_64) || defined(TARGET_I386)
    return offsetof(CPUX86State, eip);
#elif defined(TARGET_AARCH64)
    return -1;
#elif defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
    return offsetof(CPUMIPSState, active_tc.PC);
#else
#error
#endif
  };
  auto syscall_number_index = [&](void) -> int {
#if defined(TARGET_X86_64)
    return tcg_index_of_named_global("rax");
#elif defined(TARGET_I386)
    return tcg_index_of_named_global("eax");
#elif defined(TARGET_AARCH64)
    return tcg_index_of_named_global("x8");
#elif defined(TARGET_MIPS64)
    return tcg_index_of_named_global("v0");
#elif defined(TARGET_MIPS32)
    return tcg_index_of_named_global("v0");
#else
#error
#endif
  };

  auto syscall_return_index = [&](void) -> int {
#if defined(TARGET_X86_64)
    return tcg_index_of_named_global("rax");
#elif defined(TARGET_I386)
    return tcg_index_of_named_global("eax");
#elif defined(TARGET_AARCH64)
    return tcg_index_of_named_global("x0");
#elif defined(TARGET_MIPS64)
    return tcg_index_of_named_global("v0");
#elif defined(TARGET_MIPS32)
    return tcg_index_of_named_global("v0");
#else
#error
#endif
  };

  auto syscall_arg1_index = [&](void) -> int {
#if defined(TARGET_X86_64)
    return tcg_index_of_named_global("rdi");
#elif defined(TARGET_I386)
    return tcg_index_of_named_global("ebx");
#elif defined(TARGET_AARCH64)
    return tcg_index_of_named_global("x0");
#elif defined(TARGET_MIPS64)
    return tcg_index_of_named_global("a0");
#elif defined(TARGET_MIPS32)
    return tcg_index_of_named_global("a0");
#else
#error
#endif
  };
  auto syscall_arg2_index = [&](void) -> int {
#if defined(TARGET_X86_64)
    return tcg_index_of_named_global("rsi");
#elif defined(TARGET_I386)
    return tcg_index_of_named_global("ecx");
#elif defined(TARGET_AARCH64)
    return tcg_index_of_named_global("x1");
#elif defined(TARGET_MIPS64)
    return tcg_index_of_named_global("a1");
#elif defined(TARGET_MIPS32)
    return tcg_index_of_named_global("a1");
#else
#error
#endif
  };
  auto syscall_arg3_index = [&](void) -> int {
#if defined(TARGET_X86_64)
    return tcg_index_of_named_global("rdx");
#elif defined(TARGET_I386)
    return tcg_index_of_named_global("edx");
#elif defined(TARGET_AARCH64)
    return tcg_index_of_named_global("x2");
#elif defined(TARGET_MIPS64)
    return tcg_index_of_named_global("a2");
#elif defined(TARGET_MIPS32)
    return tcg_index_of_named_global("a2");
#else
#error
#endif
  };
  auto syscall_arg4_index = [&](void) -> int {
#if defined(TARGET_X86_64)
    return tcg_index_of_named_global("r10");
#elif defined(TARGET_I386)
    return tcg_index_of_named_global("esi");
#elif defined(TARGET_AARCH64)
    return tcg_index_of_named_global("x3");
#elif defined(TARGET_MIPS64)
    return tcg_index_of_named_global("a3");
#elif defined(TARGET_MIPS32)
    return tcg_index_of_named_global("a3");
#else
#error
#endif
  };
  auto syscall_arg5_index = [&](void) -> int {
#if defined(TARGET_X86_64)
    return tcg_index_of_named_global("r8");
#elif defined(TARGET_I386)
    return tcg_index_of_named_global("edi");
#elif defined(TARGET_AARCH64)
    return tcg_index_of_named_global("x4");
#elif defined(TARGET_MIPS64)
    return tcg_index_of_named_global("t0");
#elif defined(TARGET_MIPS32)
    return -1; /* on stack */
#else
#error
#endif
  };
  auto syscall_arg6_index = [&](void) -> int {
#if defined(TARGET_X86_64)
    return tcg_index_of_named_global("r9");
#elif defined(TARGET_I386)
    return tcg_index_of_named_global("ebp");
#elif defined(TARGET_AARCH64)
    return tcg_index_of_named_global("x5");
#elif defined(TARGET_MIPS64)
    return tcg_index_of_named_global("t1");
#elif defined(TARGET_MIPS32)
    return -1; /* on stack */
#else
#error
#endif
  };

#if defined(TARGET_X86_64)
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
#elif defined(TARGET_I386)
  auto gs_base_index = [&](void) -> int {
    return tcg_index_of_named_global("gs_base");
  };
#endif

#if defined(TARGET_AARCH64)
  auto tpidr_el0_env_offset = [&](void) -> int {
    return offsetof(CPUARMState, cp15.tpidr_el[0]);
  };
#endif

#if defined(TARGET_MIPS32)
  auto t9_index = [&](void) -> int {
    return tcg_index_of_named_global("t9");
  };

  auto ra_index = [&](void) -> int {
    return tcg_index_of_named_global("ra");
  };

  auto gp_index = [&](void) -> int {
    return tcg_index_of_named_global("gp");
  };

  auto lladdr_index = [&](void) -> int {
    return tcg_index_of_named_global("lladdr");
  };

  auto llval_index = [&](void) -> int {
    return tcg_index_of_named_global("llval");
  };
#endif

  printf("#pragma once\n"
         "#include <bitset>\n"
         "#include <array>\n"
         "#include <cstdint>\n"
         "\n"
         "/* NOTE: THIS FILE IS AUTO-GENERATED BY GEN-TCGCONSTANTS */\n"
         "namespace jove {\n");

  printf("\n//\n");
  for (int glb = 0; glb < tcg._ctx.nb_globals; glb++)
    printf("// %s %s\n", cstr_of_tcg_type(tcg._ctx.temps[glb].type), tcg._ctx.temps[glb].name);
  printf("//\n\n");

#define __TCG_CONST(NM) printf("constexpr int tcg_" #NM " = %d;\n", NM())

  printf("typedef uint%u_t tcg_uintptr_t;\n", static_cast<unsigned>(8 * sizeof(target_ulong)));

  __TCG_CONST(num_globals);
  __TCG_CONST(num_helpers);
  __TCG_CONST(max_temps);
  __TCG_CONST(env_index);
  __TCG_CONST(program_counter_index);
  __TCG_CONST(frame_pointer_index);
  __TCG_CONST(stack_pointer_index);
  __TCG_CONST(program_counter_env_offset);
  __TCG_CONST(syscall_number_index);
  __TCG_CONST(syscall_return_index);
  __TCG_CONST(syscall_arg1_index);
  __TCG_CONST(syscall_arg2_index);
  __TCG_CONST(syscall_arg3_index);
  __TCG_CONST(syscall_arg4_index);
  __TCG_CONST(syscall_arg5_index);
  __TCG_CONST(syscall_arg6_index);

#if defined(TARGET_X86_64)
  __TCG_CONST(fs_base_index);
  __TCG_CONST(r12_index);
  __TCG_CONST(r13_index);
  __TCG_CONST(r14_index);
  __TCG_CONST(r15_index);
#elif defined(TARGET_I386)
  __TCG_CONST(gs_base_index);
#endif

#if defined(TARGET_AARCH64)
  __TCG_CONST(tpidr_el0_env_offset);
#endif

#if defined(TARGET_MIPS32)
  __TCG_CONST(t9_index);
  __TCG_CONST(ra_index);
  __TCG_CONST(gp_index);
  __TCG_CONST(llval_index);
  __TCG_CONST(lladdr_index);
#endif

#undef __TCG_CONST

  printf("typedef std::bitset<tcg_num_globals> tcg_global_set_t;\n");
  print_not_sets();
  print_call_conv_sets();
  print_callee_saved_registers();
  print_lookup_by_mem_offset();
  print_pinned_env_globals();

  printf("}\n");

#if 0
#if defined(TARGET_MIPS32)
  {
    unsigned off = offsetof(CPUMIPSState, active_fpu.fpr[0].d) -
                   offsetof(CPUMIPSState, active_tc.gpr[29]);
    printf("magic offset1 is %u\n", off);
  }
  {
    unsigned off = offsetof(CPUMIPSState, active_fpu.fpr[12].d) -
                   offsetof(CPUMIPSState, active_tc.gpr[29]);
    printf("magic offset2 is %u\n", off);
  }
  {
    unsigned off = offsetof(CPUMIPSState, active_fpu.fpr[13].d) -
                   offsetof(CPUMIPSState, active_tc.gpr[29]);
    printf("magic offset3 is %u\n", off);
  }
  {
    unsigned off = offsetof(CPUMIPSState, active_fpu.fpr[14].d) -
                   offsetof(CPUMIPSState, active_tc.gpr[29]);
    printf("magic offset4 is %u\n", off);
  }
#endif
#endif

  return 0;
}
