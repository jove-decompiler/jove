#pragma once
#include <bitset>
#include <array>

namespace jove {
constexpr int tcg_num_globals = 130;
constexpr int tcg_num_helpers = 1069;
constexpr int tcg_max_temps = 512;
constexpr int tcg_env_index = 1;
constexpr int tcg_program_counter_index = 97;
constexpr int tcg_frame_pointer_index = 31;
constexpr int tcg_stack_pointer_index = 30;
constexpr int tcg_program_counter_env_offset = 128;
constexpr int tcg_syscall_number_index = 3;
constexpr int tcg_syscall_return_index = 3;
constexpr int tcg_syscall_arg1_index = 5;
constexpr int tcg_syscall_arg2_index = 6;
constexpr int tcg_syscall_arg3_index = 7;
constexpr int tcg_syscall_arg4_index = 8;
constexpr int tcg_syscall_arg5_index = -1;
constexpr int tcg_syscall_arg6_index = -1;
constexpr int tcg_t9_index = 26;
constexpr int tcg_ra_index = 32;
constexpr int tcg_gp_index = 29;
constexpr int tcg_llval_index = 113;
constexpr int tcg_lladdr_index = 112;
typedef std::bitset<tcg_num_globals> tcg_global_set_t;
static const tcg_global_set_t NotArgs("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011");
static const tcg_global_set_t NotRets("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000011");
constexpr tcg_global_set_t CallConvArgs(480);
typedef std::array<unsigned, 4> CallConvArgArrayTy;
static const CallConvArgArrayTy CallConvArgArray{5, 6, 7, 8};
constexpr tcg_global_set_t CallConvRets(24);
typedef std::array<unsigned, 2> CallConvRetArrayTy;
static const CallConvRetArrayTy CallConvRetArray{3, 4};
constexpr tcg_global_set_t CalleeSavedRegs(33423360);
static const uint8_t tcg_global_by_offset_lookup_table[11133] = {
[0 ... 11132] = 0xff,
[4] = 2,
[8] = 3,
[12] = 4,
[16] = 5,
[20] = 6,
[24] = 7,
[28] = 8,
[32] = 9,
[36] = 10,
[40] = 11,
[44] = 12,
[48] = 13,
[52] = 14,
[56] = 15,
[60] = 16,
[64] = 17,
[68] = 18,
[72] = 19,
[76] = 20,
[80] = 21,
[84] = 22,
[88] = 23,
[92] = 24,
[96] = 25,
[100] = 26,
[104] = 27,
[108] = 28,
[112] = 29,
[116] = 30,
[120] = 31,
[124] = 32,
[552] = 33,
[560] = 34,
[568] = 35,
[576] = 36,
[584] = 37,
[592] = 38,
[600] = 39,
[608] = 40,
[616] = 41,
[624] = 42,
[632] = 43,
[640] = 44,
[648] = 45,
[656] = 46,
[664] = 47,
[672] = 48,
[680] = 49,
[688] = 50,
[696] = 51,
[704] = 52,
[712] = 53,
[720] = 54,
[728] = 55,
[736] = 56,
[744] = 57,
[752] = 58,
[760] = 59,
[768] = 60,
[776] = 61,
[784] = 62,
[792] = 63,
[800] = 64,
[808] = 65,
[816] = 66,
[824] = 67,
[832] = 68,
[840] = 69,
[848] = 70,
[856] = 71,
[864] = 72,
[872] = 73,
[880] = 74,
[888] = 75,
[896] = 76,
[904] = 77,
[912] = 78,
[920] = 79,
[928] = 80,
[936] = 81,
[944] = 82,
[952] = 83,
[960] = 84,
[968] = 85,
[976] = 86,
[984] = 87,
[992] = 88,
[1000] = 89,
[1008] = 90,
[1016] = 91,
[1024] = 92,
[1032] = 93,
[1040] = 94,
[1048] = 95,
[1056] = 96,
[128] = 97,
[132] = 98,
[148] = 99,
[136] = 100,
[152] = 101,
[140] = 102,
[156] = 103,
[144] = 104,
[160] = 105,
[180] = 106,
[11132] = 107,
[11128] = 108,
[11124] = 109,
[1072] = 110,
[1080] = 111,
[1564] = 112,
[1568] = 113,
[488] = 114,
[492] = 115,
[496] = 116,
[500] = 117,
[504] = 118,
[508] = 119,
[512] = 120,
[516] = 121,
[520] = 122,
[524] = 123,
[528] = 124,
[532] = 125,
[536] = 126,
[540] = 127,
[544] = 128,
[548] = 129,
};
}
