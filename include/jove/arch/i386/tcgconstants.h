#pragma once
#include <bitset>
#include <array>

namespace jove {
constexpr int tcg_num_globals = 36;
constexpr int tcg_num_helpers = 805;
constexpr int tcg_max_temps = 512;
constexpr int tcg_env_index = 1;
constexpr int tcg_program_counter_index = -1;
constexpr int tcg_frame_pointer_index = 11;
constexpr int tcg_stack_pointer_index = 10;
constexpr int tcg_program_counter_env_offset = 32;
constexpr int tcg_syscall_number_index = 6;
constexpr int tcg_syscall_return_index = 6;
constexpr int tcg_syscall_arg1_index = 9;
constexpr int tcg_syscall_arg2_index = 7;
constexpr int tcg_syscall_arg3_index = 8;
constexpr int tcg_syscall_arg4_index = 12;
constexpr int tcg_syscall_arg5_index = 13;
constexpr int tcg_syscall_arg6_index = 11;
constexpr int tcg_gs_base_index = 19;
typedef std::bitset<tcg_num_globals> tcg_global_set_t;
constexpr tcg_global_set_t NotArgs(68719460355);
constexpr tcg_global_set_t NotRets(68719460355);
constexpr tcg_global_set_t CallConvArgs(0);
typedef std::array<unsigned, 0> CallConvArgArrayTy;
static const CallConvArgArrayTy CallConvArgArray{};
constexpr tcg_global_set_t CallConvRets(64);
typedef std::array<unsigned, 1> CallConvRetArrayTy;
static const CallConvRetArrayTy CallConvRetArray{6};
constexpr tcg_global_set_t CalleeSavedRegs(14848);
static const uint8_t tcg_global_by_offset_lookup_table[313] = {
[0 ... 312] = 0xff,
[52] = 2,
[40] = 3,
[44] = 4,
[48] = 5,
[0] = 6,
[4] = 7,
[8] = 8,
[12] = 9,
[16] = 10,
[20] = 11,
[24] = 12,
[28] = 13,
[72] = 14,
[88] = 15,
[104] = 16,
[120] = 17,
[136] = 18,
[152] = 19,
[252] = 20,
[256] = 21,
[260] = 22,
[264] = 23,
[268] = 24,
[272] = 25,
[276] = 26,
[280] = 27,
[284] = 28,
[288] = 29,
[292] = 30,
[296] = 31,
[300] = 32,
[304] = 33,
[308] = 34,
[312] = 35,
};
}
