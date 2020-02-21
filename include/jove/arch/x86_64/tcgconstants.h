#pragma once
#include <bitset>
#include <array>

namespace jove {
constexpr int tcg_num_globals = 35;
constexpr int tcg_num_helpers = 728;
constexpr int tcg_max_temps = 512;
constexpr int tcg_env_index = 0;
constexpr int tcg_program_counter_index = -1;
constexpr int tcg_frame_pointer_index = 10;
constexpr int tcg_stack_pointer_index = 9;
constexpr int tcg_program_counter_env_offset = 128;
constexpr int tcg_syscall_number_index = 5;
constexpr int tcg_syscall_return_index = 5;
constexpr int tcg_syscall_arg1_index = 12;
constexpr int tcg_syscall_arg2_index = 11;
constexpr int tcg_syscall_arg3_index = 7;
constexpr int tcg_syscall_arg4_index = 15;
constexpr int tcg_syscall_arg5_index = 13;
constexpr int tcg_syscall_arg6_index = 14;
constexpr int tcg_fs_base_index = 25;
constexpr int tcg_r12_index = 17;
constexpr int tcg_r13_index = 18;
constexpr int tcg_r14_index = 19;
constexpr int tcg_r15_index = 20;
typedef std::bitset<tcg_num_globals> tcg_global_set_t;
constexpr tcg_global_set_t CallConvArgs(30912);
typedef std::array<unsigned, 6> CallConvArgArrayTy;
static const CallConvArgArrayTy CallConvArgArray{12, 11, 7, 6, 13, 14};
constexpr tcg_global_set_t CallConvRets(32);
typedef std::array<unsigned, 1> CallConvRetArrayTy;
static const CallConvRetArrayTy CallConvRetArray{5};
static const int8_t tcg_global_by_offset_lookup_table[529] = {
[0 ... 528] = -1,
[168] = 1,
[144] = 2,
[152] = 3,
[160] = 4,
[0] = 5,
[8] = 6,
[16] = 7,
[24] = 8,
[32] = 9,
[40] = 10,
[48] = 11,
[56] = 12,
[64] = 13,
[72] = 14,
[80] = 15,
[88] = 16,
[96] = 17,
[104] = 18,
[112] = 19,
[120] = 20,
[192] = 21,
[216] = 22,
[240] = 23,
[264] = 24,
[288] = 25,
[312] = 26,
[472] = 27,
[480] = 28,
[488] = 29,
[496] = 30,
[504] = 31,
[512] = 32,
[520] = 33,
[528] = 34,
};
}
