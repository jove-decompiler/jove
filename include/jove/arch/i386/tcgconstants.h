#pragma once
#include <bitset>
#include <array>

namespace jove {
constexpr int tcg_num_globals = 35;
constexpr int tcg_num_helpers = 805;
constexpr int tcg_max_temps = 512;
constexpr int tcg_env_index = 0;
constexpr int tcg_program_counter_index = -1;
constexpr int tcg_frame_pointer_index = 10;
constexpr int tcg_stack_pointer_index = 9;
constexpr int tcg_program_counter_env_offset = 32;
constexpr int tcg_syscall_number_index = 5;
constexpr int tcg_syscall_return_index = 5;
constexpr int tcg_syscall_arg1_index = 8;
constexpr int tcg_syscall_arg2_index = 6;
constexpr int tcg_syscall_arg3_index = 7;
constexpr int tcg_syscall_arg4_index = 11;
constexpr int tcg_syscall_arg5_index = 12;
constexpr int tcg_syscall_arg6_index = 10;
constexpr int tcg_gs_base_index = 18;
typedef std::bitset<tcg_num_globals> tcg_global_set_t;
constexpr tcg_global_set_t CallConvArgs(0);
typedef std::array<unsigned, 0> CallConvArgArrayTy;
static const CallConvArgArrayTy CallConvArgArray{};
constexpr tcg_global_set_t CallConvRets(32);
typedef std::array<unsigned, 1> CallConvRetArrayTy;
static const CallConvRetArrayTy CallConvRetArray{5};
static const int8_t tcg_global_by_offset_lookup_table[313] = {
[0 ... 312] = -1,
[52] = 1,
[40] = 2,
[44] = 3,
[48] = 4,
[0] = 5,
[4] = 6,
[8] = 7,
[12] = 8,
[16] = 9,
[20] = 10,
[24] = 11,
[28] = 12,
[72] = 13,
[88] = 14,
[104] = 15,
[120] = 16,
[136] = 17,
[152] = 18,
[252] = 19,
[256] = 20,
[260] = 21,
[264] = 22,
[268] = 23,
[272] = 24,
[276] = 25,
[280] = 26,
[284] = 27,
[288] = 28,
[292] = 29,
[296] = 30,
[300] = 31,
[304] = 32,
[308] = 33,
[312] = 34,
};
}
