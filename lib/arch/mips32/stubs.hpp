void __attribute__ ((__noreturn__)) helper_raise_exception_err (CPUArchState *, uint32_t, int) { __builtin_trap(); }
void __attribute__ ((__noreturn__)) helper_raise_exception (CPUArchState *, uint32_t) { __builtin_trap(); }
void __attribute__ ((__noreturn__)) helper_raise_exception_debug (CPUArchState *) { __builtin_trap(); }
void helper_swl (CPUArchState *, target_ulong, target_ulong, int) {}
void helper_swr (CPUArchState *, target_ulong, target_ulong, int) {}
target_ulong helper_muls (CPUArchState *, target_ulong, target_ulong) { return 0; }
target_ulong helper_mulsu (CPUArchState *, target_ulong, target_ulong) { return 0; }
target_ulong helper_macc (CPUArchState *, target_ulong, target_ulong) { return 0; }
target_ulong helper_maccu (CPUArchState *, target_ulong, target_ulong) { return 0; }
target_ulong helper_msac (CPUArchState *, target_ulong, target_ulong) { return 0; }
target_ulong helper_msacu (CPUArchState *, target_ulong, target_ulong) { return 0; }
target_ulong helper_mulhi (CPUArchState *, target_ulong, target_ulong) { return 0; }
target_ulong helper_mulhiu (CPUArchState *, target_ulong, target_ulong) { return 0; }
target_ulong helper_mulshi (CPUArchState *, target_ulong, target_ulong) { return 0; }
target_ulong helper_mulshiu (CPUArchState *, target_ulong, target_ulong) { return 0; }
target_ulong helper_macchi (CPUArchState *, target_ulong, target_ulong) { return 0; }
target_ulong helper_macchiu (CPUArchState *, target_ulong, target_ulong) { return 0; }
target_ulong helper_msachi (CPUArchState *, target_ulong, target_ulong) { return 0; }
target_ulong helper_msachiu (CPUArchState *, target_ulong, target_ulong) { return 0; }
target_ulong helper_bitswap (target_ulong) { return 0; }
target_ulong helper_rotx (target_ulong, uint32_t, uint32_t, uint32_t) { return 0; }
void helper_lwm (CPUArchState *, target_ulong, target_ulong, uint32_t) {}
void helper_swm (CPUArchState *, target_ulong, target_ulong, uint32_t) {}
void helper_fork (target_ulong, target_ulong) {}
target_ulong helper_yield (CPUArchState *, target_ulong) { return 0; }
target_ulong helper_cfc1 (CPUArchState *, uint32_t) { return 0; }
void helper_ctc1 (CPUArchState *, target_ulong, uint32_t, uint32_t) {}
uint64_t helper_float_cvtd_s (CPUArchState *, uint32_t) { return 0; }
uint64_t helper_float_cvtd_w (CPUArchState *, uint32_t) { return 0; }
uint64_t helper_float_cvtd_l (CPUArchState *, uint64_t) { return 0; }
uint64_t helper_float_cvtps_pw (CPUArchState *, uint64_t) { return 0; }
uint64_t helper_float_cvtpw_ps (CPUArchState *, uint64_t) { return 0; }
uint32_t helper_float_cvts_d (CPUArchState *, uint64_t) { return 0; }
uint32_t helper_float_cvts_w (CPUArchState *, uint32_t) { return 0; }
uint32_t helper_float_cvts_l (CPUArchState *, uint64_t) { return 0; }
uint32_t helper_float_cvts_pl (CPUArchState *, uint32_t) { return 0; }
uint32_t helper_float_cvts_pu (CPUArchState *, uint32_t) { return 0; }
uint64_t helper_float_addr_ps (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_float_mulr_ps (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_float_class_s (CPUArchState *, uint32_t) { return 0; }
uint64_t helper_float_class_d (CPUArchState *, uint64_t) { return 0; }
uint32_t helper_float_maddf_s (CPUArchState *, uint32_t, uint32_t, uint32_t) { return 0; }
uint64_t helper_float_maddf_d (CPUArchState *, uint64_t, uint64_t, uint64_t) { return 0; }
uint32_t helper_float_msubf_s (CPUArchState *, uint32_t, uint32_t, uint32_t) { return 0; }
uint64_t helper_float_msubf_d (CPUArchState *, uint64_t, uint64_t, uint64_t) { return 0; }
uint32_t helper_float_max_s (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_float_max_d (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_float_maxa_s (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_float_maxa_d (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_float_min_s (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_float_min_d (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_float_mina_s (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_float_mina_d (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_float_cvt_l_s (CPUArchState *, uint32_t) { return 0; }
uint64_t helper_float_cvt_l_d (CPUArchState *, uint64_t) { return 0; }
uint32_t helper_float_cvt_w_s (CPUArchState *, uint32_t) { return 0; }
uint32_t helper_float_cvt_w_d (CPUArchState *, uint64_t) { return 0; }
uint64_t helper_float_round_l_s (CPUArchState *, uint32_t) { return 0; }
uint64_t helper_float_round_l_d (CPUArchState *, uint64_t) { return 0; }
uint32_t helper_float_round_w_s (CPUArchState *, uint32_t) { return 0; }
uint32_t helper_float_round_w_d (CPUArchState *, uint64_t) { return 0; }
uint64_t helper_float_trunc_l_s (CPUArchState *, uint32_t) { return 0; }
uint64_t helper_float_trunc_l_d (CPUArchState *, uint64_t) { return 0; }
uint32_t helper_float_trunc_w_s (CPUArchState *, uint32_t) { return 0; }
uint32_t helper_float_trunc_w_d (CPUArchState *, uint64_t) { return 0; }
uint64_t helper_float_ceil_l_s (CPUArchState *, uint32_t) { return 0; }
uint64_t helper_float_ceil_l_d (CPUArchState *, uint64_t) { return 0; }
uint32_t helper_float_ceil_w_s (CPUArchState *, uint32_t) { return 0; }
uint32_t helper_float_ceil_w_d (CPUArchState *, uint64_t) { return 0; }
uint64_t helper_float_floor_l_s (CPUArchState *, uint32_t) { return 0; }
uint64_t helper_float_floor_l_d (CPUArchState *, uint64_t) { return 0; }
uint32_t helper_float_floor_w_s (CPUArchState *, uint32_t) { return 0; }
uint32_t helper_float_floor_w_d (CPUArchState *, uint64_t) { return 0; }
uint64_t helper_float_cvt_2008_l_s (CPUArchState *, uint32_t) { return 0; }
uint64_t helper_float_cvt_2008_l_d (CPUArchState *, uint64_t) { return 0; }
uint32_t helper_float_cvt_2008_w_s (CPUArchState *, uint32_t) { return 0; }
uint32_t helper_float_cvt_2008_w_d (CPUArchState *, uint64_t) { return 0; }
uint64_t helper_float_round_2008_l_s (CPUArchState *, uint32_t) { return 0; }
uint64_t helper_float_round_2008_l_d (CPUArchState *, uint64_t) { return 0; }
uint32_t helper_float_round_2008_w_s (CPUArchState *, uint32_t) { return 0; }
uint32_t helper_float_round_2008_w_d (CPUArchState *, uint64_t) { return 0; }
uint64_t helper_float_trunc_2008_l_s (CPUArchState *, uint32_t) { return 0; }
uint64_t helper_float_trunc_2008_l_d (CPUArchState *, uint64_t) { return 0; }
uint32_t helper_float_trunc_2008_w_s (CPUArchState *, uint32_t) { return 0; }
uint32_t helper_float_trunc_2008_w_d (CPUArchState *, uint64_t) { return 0; }
uint64_t helper_float_ceil_2008_l_s (CPUArchState *, uint32_t) { return 0; }
uint64_t helper_float_ceil_2008_l_d (CPUArchState *, uint64_t) { return 0; }
uint32_t helper_float_ceil_2008_w_s (CPUArchState *, uint32_t) { return 0; }
uint32_t helper_float_ceil_2008_w_d (CPUArchState *, uint64_t) { return 0; }
uint64_t helper_float_floor_2008_l_s (CPUArchState *, uint32_t) { return 0; }
uint64_t helper_float_floor_2008_l_d (CPUArchState *, uint64_t) { return 0; }
uint32_t helper_float_floor_2008_w_s (CPUArchState *, uint32_t) { return 0; }
uint32_t helper_float_floor_2008_w_d (CPUArchState *, uint64_t) { return 0; }
uint32_t helper_float_sqrt_s (CPUArchState *, uint32_t) { return 0; }
uint64_t helper_float_sqrt_d (CPUArchState *, uint64_t) { return 0; }
uint32_t helper_float_rsqrt_s (CPUArchState *, uint32_t) { return 0; }
uint64_t helper_float_rsqrt_d (CPUArchState *, uint64_t) { return 0; }
uint32_t helper_float_recip_s (CPUArchState *, uint32_t) { return 0; }
uint64_t helper_float_recip_d (CPUArchState *, uint64_t) { return 0; }
uint32_t helper_float_rint_s (CPUArchState *, uint32_t) { return 0; }
uint64_t helper_float_rint_d (CPUArchState *, uint64_t) { return 0; }
uint32_t helper_float_abs_s (uint32_t) { return 0; }
uint64_t helper_float_abs_d (uint64_t) { return 0; }
uint64_t helper_float_abs_ps (uint64_t) { return 0; }
uint32_t helper_float_chs_s (uint32_t) { return 0; }
uint64_t helper_float_chs_d (uint64_t) { return 0; }
uint64_t helper_float_chs_ps (uint64_t) { return 0; }
uint32_t helper_float_recip1_s (CPUArchState *, uint32_t) { return 0; }
uint64_t helper_float_recip1_d (CPUArchState *, uint64_t) { return 0; }
uint64_t helper_float_recip1_ps (CPUArchState *, uint64_t) { return 0; }
uint32_t helper_float_rsqrt1_s (CPUArchState *, uint32_t) { return 0; }
uint64_t helper_float_rsqrt1_d (CPUArchState *, uint64_t) { return 0; }
uint64_t helper_float_rsqrt1_ps (CPUArchState *, uint64_t) { return 0; }
uint32_t helper_float_add_s (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_float_add_d (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_float_add_ps (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_float_sub_s (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_float_sub_d (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_float_sub_ps (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_float_mul_s (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_float_mul_d (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_float_mul_ps (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_float_div_s (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_float_div_d (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_float_div_ps (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_float_recip2_s (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_float_recip2_d (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_float_recip2_ps (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_float_rsqrt2_s (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_float_rsqrt2_d (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_float_rsqrt2_ps (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_float_madd_s (CPUArchState *, uint32_t, uint32_t, uint32_t) { return 0; }
uint64_t helper_float_madd_d (CPUArchState *, uint64_t, uint64_t, uint64_t) { return 0; }
uint64_t helper_float_madd_ps (CPUArchState *, uint64_t, uint64_t, uint64_t) { return 0; }
uint32_t helper_float_msub_s (CPUArchState *, uint32_t, uint32_t, uint32_t) { return 0; }
uint64_t helper_float_msub_d (CPUArchState *, uint64_t, uint64_t, uint64_t) { return 0; }
uint64_t helper_float_msub_ps (CPUArchState *, uint64_t, uint64_t, uint64_t) { return 0; }
uint32_t helper_float_nmadd_s (CPUArchState *, uint32_t, uint32_t, uint32_t) { return 0; }
uint64_t helper_float_nmadd_d (CPUArchState *, uint64_t, uint64_t, uint64_t) { return 0; }
uint64_t helper_float_nmadd_ps (CPUArchState *, uint64_t, uint64_t, uint64_t) { return 0; }
uint32_t helper_float_nmsub_s (CPUArchState *, uint32_t, uint32_t, uint32_t) { return 0; }
uint64_t helper_float_nmsub_d (CPUArchState *, uint64_t, uint64_t, uint64_t) { return 0; }
uint64_t helper_float_nmsub_ps (CPUArchState *, uint64_t, uint64_t, uint64_t) { return 0; }
void helper_cmp_d_f (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmpabs_d_f (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmp_s_f (CPUArchState *, uint32_t, uint32_t, int) {}
void helper_cmpabs_s_f (CPUArchState *, uint32_t, uint32_t, int) {}
void helper_cmp_ps_f (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmpabs_ps_f (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmp_d_un (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmpabs_d_un (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmp_s_un (CPUArchState *, uint32_t, uint32_t, int) {}
void helper_cmpabs_s_un (CPUArchState *, uint32_t, uint32_t, int) {}
void helper_cmp_ps_un (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmpabs_ps_un (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmp_d_eq (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmpabs_d_eq (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmp_s_eq (CPUArchState *, uint32_t, uint32_t, int) {}
void helper_cmpabs_s_eq (CPUArchState *, uint32_t, uint32_t, int) {}
void helper_cmp_ps_eq (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmpabs_ps_eq (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmp_d_ueq (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmpabs_d_ueq (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmp_s_ueq (CPUArchState *, uint32_t, uint32_t, int) {}
void helper_cmpabs_s_ueq (CPUArchState *, uint32_t, uint32_t, int) {}
void helper_cmp_ps_ueq (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmpabs_ps_ueq (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmp_d_olt (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmpabs_d_olt (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmp_s_olt (CPUArchState *, uint32_t, uint32_t, int) {}
void helper_cmpabs_s_olt (CPUArchState *, uint32_t, uint32_t, int) {}
void helper_cmp_ps_olt (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmpabs_ps_olt (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmp_d_ult (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmpabs_d_ult (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmp_s_ult (CPUArchState *, uint32_t, uint32_t, int) {}
void helper_cmpabs_s_ult (CPUArchState *, uint32_t, uint32_t, int) {}
void helper_cmp_ps_ult (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmpabs_ps_ult (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmp_d_ole (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmpabs_d_ole (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmp_s_ole (CPUArchState *, uint32_t, uint32_t, int) {}
void helper_cmpabs_s_ole (CPUArchState *, uint32_t, uint32_t, int) {}
void helper_cmp_ps_ole (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmpabs_ps_ole (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmp_d_ule (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmpabs_d_ule (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmp_s_ule (CPUArchState *, uint32_t, uint32_t, int) {}
void helper_cmpabs_s_ule (CPUArchState *, uint32_t, uint32_t, int) {}
void helper_cmp_ps_ule (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmpabs_ps_ule (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmp_d_sf (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmpabs_d_sf (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmp_s_sf (CPUArchState *, uint32_t, uint32_t, int) {}
void helper_cmpabs_s_sf (CPUArchState *, uint32_t, uint32_t, int) {}
void helper_cmp_ps_sf (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmpabs_ps_sf (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmp_d_ngle (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmpabs_d_ngle (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmp_s_ngle (CPUArchState *, uint32_t, uint32_t, int) {}
void helper_cmpabs_s_ngle (CPUArchState *, uint32_t, uint32_t, int) {}
void helper_cmp_ps_ngle (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmpabs_ps_ngle (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmp_d_seq (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmpabs_d_seq (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmp_s_seq (CPUArchState *, uint32_t, uint32_t, int) {}
void helper_cmpabs_s_seq (CPUArchState *, uint32_t, uint32_t, int) {}
void helper_cmp_ps_seq (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmpabs_ps_seq (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmp_d_ngl (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmpabs_d_ngl (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmp_s_ngl (CPUArchState *, uint32_t, uint32_t, int) {}
void helper_cmpabs_s_ngl (CPUArchState *, uint32_t, uint32_t, int) {}
void helper_cmp_ps_ngl (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmpabs_ps_ngl (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmp_d_lt (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmpabs_d_lt (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmp_s_lt (CPUArchState *, uint32_t, uint32_t, int) {}
void helper_cmpabs_s_lt (CPUArchState *, uint32_t, uint32_t, int) {}
void helper_cmp_ps_lt (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmpabs_ps_lt (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmp_d_nge (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmpabs_d_nge (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmp_s_nge (CPUArchState *, uint32_t, uint32_t, int) {}
void helper_cmpabs_s_nge (CPUArchState *, uint32_t, uint32_t, int) {}
void helper_cmp_ps_nge (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmpabs_ps_nge (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmp_d_le (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmpabs_d_le (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmp_s_le (CPUArchState *, uint32_t, uint32_t, int) {}
void helper_cmpabs_s_le (CPUArchState *, uint32_t, uint32_t, int) {}
void helper_cmp_ps_le (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmpabs_ps_le (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmp_d_ngt (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmpabs_d_ngt (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmp_s_ngt (CPUArchState *, uint32_t, uint32_t, int) {}
void helper_cmpabs_s_ngt (CPUArchState *, uint32_t, uint32_t, int) {}
void helper_cmp_ps_ngt (CPUArchState *, uint64_t, uint64_t, int) {}
void helper_cmpabs_ps_ngt (CPUArchState *, uint64_t, uint64_t, int) {}
uint64_t helper_r6_cmp_d_af (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_r6_cmp_s_af (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_r6_cmp_d_un (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_r6_cmp_s_un (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_r6_cmp_d_eq (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_r6_cmp_s_eq (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_r6_cmp_d_ueq (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_r6_cmp_s_ueq (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_r6_cmp_d_lt (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_r6_cmp_s_lt (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_r6_cmp_d_ult (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_r6_cmp_s_ult (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_r6_cmp_d_le (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_r6_cmp_s_le (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_r6_cmp_d_ule (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_r6_cmp_s_ule (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_r6_cmp_d_saf (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_r6_cmp_s_saf (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_r6_cmp_d_sun (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_r6_cmp_s_sun (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_r6_cmp_d_seq (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_r6_cmp_s_seq (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_r6_cmp_d_sueq (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_r6_cmp_s_sueq (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_r6_cmp_d_slt (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_r6_cmp_s_slt (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_r6_cmp_d_sult (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_r6_cmp_s_sult (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_r6_cmp_d_sle (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_r6_cmp_s_sle (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_r6_cmp_d_sule (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_r6_cmp_s_sule (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_r6_cmp_d_or (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_r6_cmp_s_or (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_r6_cmp_d_une (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_r6_cmp_s_une (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_r6_cmp_d_ne (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_r6_cmp_s_ne (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_r6_cmp_d_sor (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_r6_cmp_s_sor (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_r6_cmp_d_sune (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_r6_cmp_s_sune (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_r6_cmp_d_sne (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_r6_cmp_s_sne (CPUArchState *, uint32_t, uint32_t) { return 0; }
target_ulong helper_rdhwr_cpunum (CPUArchState *) { return 0; }
target_ulong helper_rdhwr_synci_step (CPUArchState *) { return 0; }
target_ulong helper_rdhwr_cc (CPUArchState *) { return 0; }
target_ulong helper_rdhwr_ccres (CPUArchState *) { return 0; }
target_ulong helper_rdhwr_performance (CPUArchState *) { return 0; }
target_ulong helper_rdhwr_xnp (CPUArchState *) { return 0; }
void helper_pmon (CPUArchState *, int) {}
void helper_wait (CPUArchState *) {}
uint64_t helper_paddsh (uint64_t, uint64_t) { return 0; }
uint64_t helper_paddush (uint64_t, uint64_t) { return 0; }
uint64_t helper_paddh (uint64_t, uint64_t) { return 0; }
uint64_t helper_paddw (uint64_t, uint64_t) { return 0; }
uint64_t helper_paddsb (uint64_t, uint64_t) { return 0; }
uint64_t helper_paddusb (uint64_t, uint64_t) { return 0; }
uint64_t helper_paddb (uint64_t, uint64_t) { return 0; }
uint64_t helper_psubsh (uint64_t, uint64_t) { return 0; }
uint64_t helper_psubush (uint64_t, uint64_t) { return 0; }
uint64_t helper_psubh (uint64_t, uint64_t) { return 0; }
uint64_t helper_psubw (uint64_t, uint64_t) { return 0; }
uint64_t helper_psubsb (uint64_t, uint64_t) { return 0; }
uint64_t helper_psubusb (uint64_t, uint64_t) { return 0; }
uint64_t helper_psubb (uint64_t, uint64_t) { return 0; }
uint64_t helper_pshufh (uint64_t, uint64_t) { return 0; }
uint64_t helper_packsswh (uint64_t, uint64_t) { return 0; }
uint64_t helper_packsshb (uint64_t, uint64_t) { return 0; }
uint64_t helper_packushb (uint64_t, uint64_t) { return 0; }
uint64_t helper_punpcklhw (uint64_t, uint64_t) { return 0; }
uint64_t helper_punpckhhw (uint64_t, uint64_t) { return 0; }
uint64_t helper_punpcklbh (uint64_t, uint64_t) { return 0; }
uint64_t helper_punpckhbh (uint64_t, uint64_t) { return 0; }
uint64_t helper_punpcklwd (uint64_t, uint64_t) { return 0; }
uint64_t helper_punpckhwd (uint64_t, uint64_t) { return 0; }
uint64_t helper_pavgh (uint64_t, uint64_t) { return 0; }
uint64_t helper_pavgb (uint64_t, uint64_t) { return 0; }
uint64_t helper_pmaxsh (uint64_t, uint64_t) { return 0; }
uint64_t helper_pminsh (uint64_t, uint64_t) { return 0; }
uint64_t helper_pmaxub (uint64_t, uint64_t) { return 0; }
uint64_t helper_pminub (uint64_t, uint64_t) { return 0; }
uint64_t helper_pcmpeqw (uint64_t, uint64_t) { return 0; }
uint64_t helper_pcmpgtw (uint64_t, uint64_t) { return 0; }
uint64_t helper_pcmpeqh (uint64_t, uint64_t) { return 0; }
uint64_t helper_pcmpgth (uint64_t, uint64_t) { return 0; }
uint64_t helper_pcmpeqb (uint64_t, uint64_t) { return 0; }
uint64_t helper_pcmpgtb (uint64_t, uint64_t) { return 0; }
uint64_t helper_psllw (uint64_t, uint64_t) { return 0; }
uint64_t helper_psllh (uint64_t, uint64_t) { return 0; }
uint64_t helper_psrlw (uint64_t, uint64_t) { return 0; }
uint64_t helper_psrlh (uint64_t, uint64_t) { return 0; }
uint64_t helper_psraw (uint64_t, uint64_t) { return 0; }
uint64_t helper_psrah (uint64_t, uint64_t) { return 0; }
uint64_t helper_pmullh (uint64_t, uint64_t) { return 0; }
uint64_t helper_pmulhh (uint64_t, uint64_t) { return 0; }
uint64_t helper_pmulhuh (uint64_t, uint64_t) { return 0; }
uint64_t helper_pmaddhw (uint64_t, uint64_t) { return 0; }
uint64_t helper_pasubub (uint64_t, uint64_t) { return 0; }
uint64_t helper_biadd (uint64_t) { return 0; }
uint64_t helper_pmovmskb (uint64_t) { return 0; }
target_ulong helper_addq_ph (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_addq_s_ph (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_addq_s_w (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_addu_qb (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_addu_s_qb (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_adduh_qb (target_ulong, target_ulong) { return 0; }
target_ulong helper_adduh_r_qb (target_ulong, target_ulong) { return 0; }
target_ulong helper_addu_ph (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_addu_s_ph (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_addqh_ph (target_ulong, target_ulong) { return 0; }
target_ulong helper_addqh_r_ph (target_ulong, target_ulong) { return 0; }
target_ulong helper_addqh_w (target_ulong, target_ulong) { return 0; }
target_ulong helper_addqh_r_w (target_ulong, target_ulong) { return 0; }
target_ulong helper_subq_ph (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_subq_s_ph (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_subq_s_w (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_subu_qb (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_subu_s_qb (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_subuh_qb (target_ulong, target_ulong) { return 0; }
target_ulong helper_subuh_r_qb (target_ulong, target_ulong) { return 0; }
target_ulong helper_subu_ph (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_subu_s_ph (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_subqh_ph (target_ulong, target_ulong) { return 0; }
target_ulong helper_subqh_r_ph (target_ulong, target_ulong) { return 0; }
target_ulong helper_subqh_w (target_ulong, target_ulong) { return 0; }
target_ulong helper_subqh_r_w (target_ulong, target_ulong) { return 0; }
target_ulong helper_addsc (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_addwc (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_modsub (target_ulong, target_ulong) { return 0; }
target_ulong helper_raddu_w_qb (target_ulong) { return 0; }
target_ulong helper_absq_s_qb (target_ulong, CPUArchState *) { return 0; }
target_ulong helper_absq_s_ph (target_ulong, CPUArchState *) { return 0; }
target_ulong helper_absq_s_w (target_ulong, CPUArchState *) { return 0; }
target_ulong helper_precr_qb_ph (target_ulong, target_ulong) { return 0; }
target_ulong helper_precrq_qb_ph (target_ulong, target_ulong) { return 0; }
target_ulong helper_precr_sra_ph_w (uint32_t, target_ulong, target_ulong) { return 0; }
target_ulong helper_precr_sra_r_ph_w (uint32_t, target_ulong, target_ulong) { return 0; }
target_ulong helper_precrq_ph_w (target_ulong, target_ulong) { return 0; }
target_ulong helper_precrq_rs_ph_w (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_precrqu_s_qb_ph (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_precequ_ph_qbl (target_ulong) { return 0; }
target_ulong helper_precequ_ph_qbr (target_ulong) { return 0; }
target_ulong helper_precequ_ph_qbla (target_ulong) { return 0; }
target_ulong helper_precequ_ph_qbra (target_ulong) { return 0; }
target_ulong helper_preceu_ph_qbl (target_ulong) { return 0; }
target_ulong helper_preceu_ph_qbr (target_ulong) { return 0; }
target_ulong helper_preceu_ph_qbla (target_ulong) { return 0; }
target_ulong helper_preceu_ph_qbra (target_ulong) { return 0; }
target_ulong helper_shll_qb (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_shll_ph (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_shll_s_ph (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_shll_s_w (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_shrl_qb (target_ulong, target_ulong) { return 0; }
target_ulong helper_shrl_ph (target_ulong, target_ulong) { return 0; }
target_ulong helper_shra_qb (target_ulong, target_ulong) { return 0; }
target_ulong helper_shra_r_qb (target_ulong, target_ulong) { return 0; }
target_ulong helper_shra_ph (target_ulong, target_ulong) { return 0; }
target_ulong helper_shra_r_ph (target_ulong, target_ulong) { return 0; }
target_ulong helper_shra_r_w (target_ulong, target_ulong) { return 0; }
target_ulong helper_muleu_s_ph_qbl (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_muleu_s_ph_qbr (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_mulq_rs_ph (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_muleq_s_w_phl (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_muleq_s_w_phr (target_ulong, target_ulong, CPUArchState *) { return 0; }
void helper_dpau_h_qbl (uint32_t, target_ulong, target_ulong, CPUArchState *) {}
void helper_dpau_h_qbr (uint32_t, target_ulong, target_ulong, CPUArchState *) {}
void helper_dpsu_h_qbl (uint32_t, target_ulong, target_ulong, CPUArchState *) {}
void helper_dpsu_h_qbr (uint32_t, target_ulong, target_ulong, CPUArchState *) {}
void helper_dpa_w_ph (uint32_t, target_ulong, target_ulong, CPUArchState *) {}
void helper_dpax_w_ph (uint32_t, target_ulong, target_ulong, CPUArchState *) {}
void helper_dpaq_s_w_ph (uint32_t, target_ulong, target_ulong, CPUArchState *) {}
void helper_dpaqx_s_w_ph (uint32_t, target_ulong, target_ulong, CPUArchState *) {}
void helper_dpaqx_sa_w_ph (uint32_t, target_ulong, target_ulong, CPUArchState *) {}
void helper_dps_w_ph (uint32_t, target_ulong, target_ulong, CPUArchState *) {}
void helper_dpsx_w_ph (uint32_t, target_ulong, target_ulong, CPUArchState *) {}
void helper_dpsq_s_w_ph (uint32_t, target_ulong, target_ulong, CPUArchState *) {}
void helper_dpsqx_s_w_ph (uint32_t, target_ulong, target_ulong, CPUArchState *) {}
void helper_dpsqx_sa_w_ph (uint32_t, target_ulong, target_ulong, CPUArchState *) {}
void helper_mulsaq_s_w_ph (uint32_t, target_ulong, target_ulong, CPUArchState *) {}
void helper_dpaq_sa_l_w (uint32_t, target_ulong, target_ulong, CPUArchState *) {}
void helper_dpsq_sa_l_w (uint32_t, target_ulong, target_ulong, CPUArchState *) {}
void helper_maq_s_w_phl (uint32_t, target_ulong, target_ulong, CPUArchState *) {}
void helper_maq_s_w_phr (uint32_t, target_ulong, target_ulong, CPUArchState *) {}
void helper_maq_sa_w_phl (uint32_t, target_ulong, target_ulong, CPUArchState *) {}
void helper_maq_sa_w_phr (uint32_t, target_ulong, target_ulong, CPUArchState *) {}
target_ulong helper_mul_ph (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_mul_s_ph (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_mulq_s_ph (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_mulq_s_w (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_mulq_rs_w (target_ulong, target_ulong, CPUArchState *) { return 0; }
void helper_mulsa_w_ph (uint32_t, target_ulong, target_ulong, CPUArchState *) {}
target_ulong helper_bitrev (target_ulong) { return 0; }
target_ulong helper_insv (CPUArchState *, target_ulong, target_ulong) { return 0; }
void helper_cmpu_eq_qb (target_ulong, target_ulong, CPUArchState *) {}
void helper_cmpu_lt_qb (target_ulong, target_ulong, CPUArchState *) {}
void helper_cmpu_le_qb (target_ulong, target_ulong, CPUArchState *) {}
target_ulong helper_cmpgu_eq_qb (target_ulong, target_ulong) { return 0; }
target_ulong helper_cmpgu_lt_qb (target_ulong, target_ulong) { return 0; }
target_ulong helper_cmpgu_le_qb (target_ulong, target_ulong) { return 0; }
void helper_cmp_eq_ph (target_ulong, target_ulong, CPUArchState *) {}
void helper_cmp_lt_ph (target_ulong, target_ulong, CPUArchState *) {}
void helper_cmp_le_ph (target_ulong, target_ulong, CPUArchState *) {}
target_ulong helper_pick_qb (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_pick_ph (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_packrl_ph (target_ulong, target_ulong) { return 0; }
target_ulong helper_extr_w (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_extr_r_w (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_extr_rs_w (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_extr_s_h (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_extp (target_ulong, target_ulong, CPUArchState *) { return 0; }
target_ulong helper_extpdp (target_ulong, target_ulong, CPUArchState *) { return 0; }
void helper_shilo (target_ulong, target_ulong, CPUArchState *) {}
void helper_mthlip (target_ulong, target_ulong, CPUArchState *) {}
void helper_wrdsp (target_ulong, target_ulong, CPUArchState *) {}
target_ulong helper_rddsp (target_ulong, CPUArchState *) { return 0; }
void helper_msa_nloc_b (CPUArchState *, uint32_t, uint32_t) {}
void helper_msa_nloc_h (CPUArchState *, uint32_t, uint32_t) {}
void helper_msa_nloc_w (CPUArchState *, uint32_t, uint32_t) {}
void helper_msa_nloc_d (CPUArchState *, uint32_t, uint32_t) {}
void helper_msa_nlzc_b (CPUArchState *, uint32_t, uint32_t) {}
void helper_msa_nlzc_h (CPUArchState *, uint32_t, uint32_t) {}
void helper_msa_nlzc_w (CPUArchState *, uint32_t, uint32_t) {}
void helper_msa_nlzc_d (CPUArchState *, uint32_t, uint32_t) {}
void helper_msa_pcnt_b (CPUArchState *, uint32_t, uint32_t) {}
void helper_msa_pcnt_h (CPUArchState *, uint32_t, uint32_t) {}
void helper_msa_pcnt_w (CPUArchState *, uint32_t, uint32_t) {}
void helper_msa_pcnt_d (CPUArchState *, uint32_t, uint32_t) {}
void helper_msa_binsl_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_binsl_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_binsl_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_binsl_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_binsr_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_binsr_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_binsr_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_binsr_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_bmnz_v (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_bmz_v (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_bsel_v (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_bclr_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_bclr_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_bclr_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_bclr_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_bneg_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_bneg_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_bneg_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_bneg_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_bset_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_bset_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_bset_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_bset_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_add_a_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_add_a_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_add_a_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_add_a_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_adds_a_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_adds_a_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_adds_a_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_adds_a_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_adds_s_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_adds_s_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_adds_s_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_adds_s_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_adds_u_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_adds_u_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_adds_u_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_adds_u_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_addv_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_addv_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_addv_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_addv_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_hadd_s_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_hadd_s_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_hadd_s_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_hadd_u_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_hadd_u_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_hadd_u_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ave_s_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ave_s_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ave_s_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ave_s_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ave_u_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ave_u_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ave_u_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ave_u_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_aver_s_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_aver_s_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_aver_s_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_aver_s_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_aver_u_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_aver_u_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_aver_u_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_aver_u_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ceq_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ceq_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ceq_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ceq_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_cle_s_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_cle_s_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_cle_s_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_cle_s_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_cle_u_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_cle_u_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_cle_u_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_cle_u_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_clt_s_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_clt_s_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_clt_s_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_clt_s_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_clt_u_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_clt_u_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_clt_u_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_clt_u_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_div_s_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_div_s_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_div_s_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_div_s_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_div_u_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_div_u_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_div_u_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_div_u_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_max_a_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_max_a_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_max_a_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_max_a_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_max_s_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_max_s_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_max_s_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_max_s_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_max_u_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_max_u_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_max_u_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_max_u_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_min_a_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_min_a_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_min_a_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_min_a_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_min_s_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_min_s_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_min_s_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_min_s_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_min_u_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_min_u_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_min_u_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_min_u_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_mod_u_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_mod_u_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_mod_u_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_mod_u_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_mod_s_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_mod_s_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_mod_s_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_mod_s_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_asub_s_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_asub_s_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_asub_s_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_asub_s_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_asub_u_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_asub_u_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_asub_u_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_asub_u_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_hsub_s_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_hsub_s_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_hsub_s_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_hsub_u_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_hsub_u_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_hsub_u_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ilvev_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ilvev_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ilvev_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ilvev_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ilvod_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ilvod_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ilvod_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ilvod_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ilvl_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ilvl_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ilvl_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ilvl_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ilvr_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ilvr_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ilvr_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ilvr_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_and_v (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_nor_v (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_or_v (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_xor_v (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_pckev_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_pckev_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_pckev_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_pckev_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_pckod_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_pckod_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_pckod_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_pckod_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_sll_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_sll_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_sll_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_sll_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_sra_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_sra_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_sra_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_sra_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_srar_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_srar_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_srar_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_srar_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_srl_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_srl_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_srl_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_srl_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_srlr_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_srlr_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_srlr_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_srlr_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_move_v (CPUArchState *, uint32_t, uint32_t) {}
void helper_msa_andi_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ori_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_nori_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_xori_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_bmnzi_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_bmzi_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_bseli_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_shf_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_addvi_df (CPUArchState *, uint32_t, uint32_t, uint32_t, int32_t) {}
void helper_msa_subvi_df (CPUArchState *, uint32_t, uint32_t, uint32_t, int32_t) {}
void helper_msa_maxi_s_df (CPUArchState *, uint32_t, uint32_t, uint32_t, int32_t) {}
void helper_msa_maxi_u_df (CPUArchState *, uint32_t, uint32_t, uint32_t, int32_t) {}
void helper_msa_mini_s_df (CPUArchState *, uint32_t, uint32_t, uint32_t, int32_t) {}
void helper_msa_mini_u_df (CPUArchState *, uint32_t, uint32_t, uint32_t, int32_t) {}
void helper_msa_ceqi_df (CPUArchState *, uint32_t, uint32_t, uint32_t, int32_t) {}
void helper_msa_clti_s_df (CPUArchState *, uint32_t, uint32_t, uint32_t, int32_t) {}
void helper_msa_clti_u_df (CPUArchState *, uint32_t, uint32_t, uint32_t, int32_t) {}
void helper_msa_clei_s_df (CPUArchState *, uint32_t, uint32_t, uint32_t, int32_t) {}
void helper_msa_clei_u_df (CPUArchState *, uint32_t, uint32_t, uint32_t, int32_t) {}
void helper_msa_ldi_df (CPUArchState *, uint32_t, uint32_t, int32_t) {}
void helper_msa_slli_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_srai_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_srli_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_bclri_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_bseti_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_bnegi_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_binsli_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_binsri_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_sat_s_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_sat_u_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_srari_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_srlri_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_binsl_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_binsr_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_subv_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_subs_s_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_subs_u_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_subsus_u_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_subsuu_s_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_mulv_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_maddv_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_msubv_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_dotp_s_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_dotp_u_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_dpadd_s_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_dpadd_u_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_dpsub_s_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_dpsub_u_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_sld_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_splat_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_vshf_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_sldi_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_splati_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_insve_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ctcmsa (CPUArchState *, target_ulong, uint32_t) {}
target_ulong helper_msa_cfcmsa (CPUArchState *, uint32_t) { return 0; }
void helper_msa_fcaf_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fcun_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fceq_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fcueq_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fclt_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fcult_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fcle_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fcule_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fsaf_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fsun_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fseq_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fsueq_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fslt_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fsult_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fsle_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fsule_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fadd_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fsub_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fmul_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fdiv_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fmadd_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fmsub_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fexp2_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fexdo_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ftq_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fmin_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fmin_a_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fmax_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fmax_a_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fcor_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fcune_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fcne_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_mul_q_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_madd_q_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_msub_q_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fsor_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fsune_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fsne_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_mulr_q_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_maddr_q_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_msubr_q_df (CPUArchState *, uint32_t, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fill_df (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_copy_s_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_copy_s_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_copy_s_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_copy_s_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_copy_u_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_copy_u_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_copy_u_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_insert_b (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_insert_h (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_insert_w (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_insert_d (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fclass_df (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ftrunc_s_df (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ftrunc_u_df (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fsqrt_df (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_frsqrt_df (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_frcp_df (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_frint_df (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_flog2_df (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fexupl_df (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_fexupr_df (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ffql_df (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ffqr_df (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ftint_s_df (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ftint_u_df (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ffint_s_df (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ffint_u_df (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_msa_ld_b (CPUArchState *, uint32_t, target_ulong) {}
void helper_msa_st_b (CPUArchState *, uint32_t, target_ulong) {}
void helper_msa_ld_h (CPUArchState *, uint32_t, target_ulong) {}
void helper_msa_st_h (CPUArchState *, uint32_t, target_ulong) {}
void helper_msa_ld_w (CPUArchState *, uint32_t, target_ulong) {}
void helper_msa_st_w (CPUArchState *, uint32_t, target_ulong) {}
void helper_msa_ld_d (CPUArchState *, uint32_t, target_ulong) {}
void helper_msa_st_d (CPUArchState *, uint32_t, target_ulong) {}
void helper_cache (CPUArchState *, target_ulong, uint32_t) {}
void helper_trace_guest_mem_before_exec_proxy (CPUArchState *, target_ulong, uint32_t) {}
int32_t helper_div_i32 (int32_t, int32_t) { return 0; }
int32_t helper_rem_i32 (int32_t, int32_t) { return 0; }
uint32_t helper_divu_i32 (uint32_t, uint32_t) { return 0; }
uint32_t helper_remu_i32 (uint32_t, uint32_t) { return 0; }
int64_t helper_div_i64 (int64_t, int64_t) { return 0; }
int64_t helper_rem_i64 (int64_t, int64_t) { return 0; }
uint64_t helper_divu_i64 (uint64_t, uint64_t) { return 0; }
uint64_t helper_remu_i64 (uint64_t, uint64_t) { return 0; }
uint64_t helper_shl_i64 (uint64_t, uint64_t) { return 0; }
uint64_t helper_shr_i64 (uint64_t, uint64_t) { return 0; }
int64_t helper_sar_i64 (int64_t, int64_t) { return 0; }
int64_t helper_mulsh_i64 (int64_t, int64_t) { return 0; }
uint64_t helper_muluh_i64 (uint64_t, uint64_t) { return 0; }
uint32_t helper_clz_i32 (uint32_t, uint32_t) { return 0; }
uint32_t helper_ctz_i32 (uint32_t, uint32_t) { return 0; }
uint64_t helper_clz_i64 (uint64_t, uint64_t) { return 0; }
uint64_t helper_ctz_i64 (uint64_t, uint64_t) { return 0; }
uint32_t helper_clrsb_i32 (uint32_t) { return 0; }
uint64_t helper_clrsb_i64 (uint64_t) { return 0; }
uint32_t helper_ctpop_i32 (uint32_t) { return 0; }
uint64_t helper_ctpop_i64 (uint64_t) { return 0; }
void * helper_lookup_tb_ptr (CPUArchState *) { return NULL; }
void __attribute__ ((__noreturn__)) helper_exit_atomic (CPUArchState *) { __builtin_trap(); }
uint32_t helper_atomic_cmpxchgb (CPUArchState *, target_ulong, uint32_t, uint32_t) { return 0; }
uint32_t helper_atomic_cmpxchgw_be (CPUArchState *, target_ulong, uint32_t, uint32_t) { return 0; }
uint32_t helper_atomic_cmpxchgw_le (CPUArchState *, target_ulong, uint32_t, uint32_t) { return 0; }
uint32_t helper_atomic_cmpxchgl_be (CPUArchState *, target_ulong, uint32_t, uint32_t) { return 0; }
uint32_t helper_atomic_cmpxchgl_le (CPUArchState *, target_ulong, uint32_t, uint32_t) { return 0; }
uint64_t helper_atomic_cmpxchgq_be (CPUArchState *, target_ulong, uint64_t, uint64_t) { return 0; }
uint64_t helper_atomic_cmpxchgq_le (CPUArchState *, target_ulong, uint64_t, uint64_t) { return 0; }
uint32_t helper_atomic_fetch_addb (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_addw_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_addw_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_addl_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_addl_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint64_t helper_atomic_fetch_addq_le (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint64_t helper_atomic_fetch_addq_be (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint32_t helper_atomic_fetch_andb (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_andw_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_andw_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_andl_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_andl_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint64_t helper_atomic_fetch_andq_le (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint64_t helper_atomic_fetch_andq_be (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint32_t helper_atomic_fetch_orb (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_orw_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_orw_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_orl_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_orl_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint64_t helper_atomic_fetch_orq_le (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint64_t helper_atomic_fetch_orq_be (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint32_t helper_atomic_fetch_xorb (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_xorw_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_xorw_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_xorl_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_xorl_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint64_t helper_atomic_fetch_xorq_le (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint64_t helper_atomic_fetch_xorq_be (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint32_t helper_atomic_fetch_sminb (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_sminw_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_sminw_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_sminl_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_sminl_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint64_t helper_atomic_fetch_sminq_le (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint64_t helper_atomic_fetch_sminq_be (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint32_t helper_atomic_fetch_uminb (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_uminw_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_uminw_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_uminl_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_uminl_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint64_t helper_atomic_fetch_uminq_le (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint64_t helper_atomic_fetch_uminq_be (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint32_t helper_atomic_fetch_smaxb (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_smaxw_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_smaxw_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_smaxl_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_smaxl_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint64_t helper_atomic_fetch_smaxq_le (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint64_t helper_atomic_fetch_smaxq_be (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint32_t helper_atomic_fetch_umaxb (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_umaxw_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_umaxw_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_umaxl_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_umaxl_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint64_t helper_atomic_fetch_umaxq_le (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint64_t helper_atomic_fetch_umaxq_be (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint32_t helper_atomic_add_fetchb (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_add_fetchw_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_add_fetchw_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_add_fetchl_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_add_fetchl_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint64_t helper_atomic_add_fetchq_le (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint64_t helper_atomic_add_fetchq_be (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint32_t helper_atomic_and_fetchb (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_and_fetchw_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_and_fetchw_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_and_fetchl_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_and_fetchl_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint64_t helper_atomic_and_fetchq_le (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint64_t helper_atomic_and_fetchq_be (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint32_t helper_atomic_or_fetchb (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_or_fetchw_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_or_fetchw_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_or_fetchl_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_or_fetchl_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint64_t helper_atomic_or_fetchq_le (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint64_t helper_atomic_or_fetchq_be (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint32_t helper_atomic_xor_fetchb (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_xor_fetchw_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_xor_fetchw_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_xor_fetchl_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_xor_fetchl_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint64_t helper_atomic_xor_fetchq_le (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint64_t helper_atomic_xor_fetchq_be (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint32_t helper_atomic_smin_fetchb (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_smin_fetchw_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_smin_fetchw_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_smin_fetchl_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_smin_fetchl_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint64_t helper_atomic_smin_fetchq_le (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint64_t helper_atomic_smin_fetchq_be (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint32_t helper_atomic_umin_fetchb (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_umin_fetchw_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_umin_fetchw_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_umin_fetchl_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_umin_fetchl_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint64_t helper_atomic_umin_fetchq_le (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint64_t helper_atomic_umin_fetchq_be (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint32_t helper_atomic_smax_fetchb (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_smax_fetchw_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_smax_fetchw_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_smax_fetchl_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_smax_fetchl_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint64_t helper_atomic_smax_fetchq_le (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint64_t helper_atomic_smax_fetchq_be (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint32_t helper_atomic_umax_fetchb (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_umax_fetchw_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_umax_fetchw_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_umax_fetchl_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_umax_fetchl_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint64_t helper_atomic_umax_fetchq_le (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint64_t helper_atomic_umax_fetchq_be (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint32_t helper_atomic_xchgb (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_xchgw_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_xchgw_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_xchgl_le (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_xchgl_be (CPUArchState *, target_ulong, uint32_t) { return 0; }
uint64_t helper_atomic_xchgq_le (CPUArchState *, target_ulong, uint64_t) { return 0; }
uint64_t helper_atomic_xchgq_be (CPUArchState *, target_ulong, uint64_t) { return 0; }
void helper_gvec_mov (void *, void *, uint32_t) {}
void helper_gvec_dup8 (void *, uint32_t, uint32_t) {}
void helper_gvec_dup16 (void *, uint32_t, uint32_t) {}
void helper_gvec_dup32 (void *, uint32_t, uint32_t) {}
void helper_gvec_dup64 (void *, uint32_t, uint64_t) {}
void helper_gvec_add8 (void *, void *, void *, uint32_t) {}
void helper_gvec_add16 (void *, void *, void *, uint32_t) {}
void helper_gvec_add32 (void *, void *, void *, uint32_t) {}
void helper_gvec_add64 (void *, void *, void *, uint32_t) {}
void helper_gvec_adds8 (void *, void *, uint64_t, uint32_t) {}
void helper_gvec_adds16 (void *, void *, uint64_t, uint32_t) {}
void helper_gvec_adds32 (void *, void *, uint64_t, uint32_t) {}
void helper_gvec_adds64 (void *, void *, uint64_t, uint32_t) {}
void helper_gvec_sub8 (void *, void *, void *, uint32_t) {}
void helper_gvec_sub16 (void *, void *, void *, uint32_t) {}
void helper_gvec_sub32 (void *, void *, void *, uint32_t) {}
void helper_gvec_sub64 (void *, void *, void *, uint32_t) {}
void helper_gvec_subs8 (void *, void *, uint64_t, uint32_t) {}
void helper_gvec_subs16 (void *, void *, uint64_t, uint32_t) {}
void helper_gvec_subs32 (void *, void *, uint64_t, uint32_t) {}
void helper_gvec_subs64 (void *, void *, uint64_t, uint32_t) {}
void helper_gvec_mul8 (void *, void *, void *, uint32_t) {}
void helper_gvec_mul16 (void *, void *, void *, uint32_t) {}
void helper_gvec_mul32 (void *, void *, void *, uint32_t) {}
void helper_gvec_mul64 (void *, void *, void *, uint32_t) {}
void helper_gvec_muls8 (void *, void *, uint64_t, uint32_t) {}
void helper_gvec_muls16 (void *, void *, uint64_t, uint32_t) {}
void helper_gvec_muls32 (void *, void *, uint64_t, uint32_t) {}
void helper_gvec_muls64 (void *, void *, uint64_t, uint32_t) {}
void helper_gvec_ssadd8 (void *, void *, void *, uint32_t) {}
void helper_gvec_ssadd16 (void *, void *, void *, uint32_t) {}
void helper_gvec_ssadd32 (void *, void *, void *, uint32_t) {}
void helper_gvec_ssadd64 (void *, void *, void *, uint32_t) {}
void helper_gvec_sssub8 (void *, void *, void *, uint32_t) {}
void helper_gvec_sssub16 (void *, void *, void *, uint32_t) {}
void helper_gvec_sssub32 (void *, void *, void *, uint32_t) {}
void helper_gvec_sssub64 (void *, void *, void *, uint32_t) {}
void helper_gvec_usadd8 (void *, void *, void *, uint32_t) {}
void helper_gvec_usadd16 (void *, void *, void *, uint32_t) {}
void helper_gvec_usadd32 (void *, void *, void *, uint32_t) {}
void helper_gvec_usadd64 (void *, void *, void *, uint32_t) {}
void helper_gvec_ussub8 (void *, void *, void *, uint32_t) {}
void helper_gvec_ussub16 (void *, void *, void *, uint32_t) {}
void helper_gvec_ussub32 (void *, void *, void *, uint32_t) {}
void helper_gvec_ussub64 (void *, void *, void *, uint32_t) {}
void helper_gvec_smin8 (void *, void *, void *, uint32_t) {}
void helper_gvec_smin16 (void *, void *, void *, uint32_t) {}
void helper_gvec_smin32 (void *, void *, void *, uint32_t) {}
void helper_gvec_smin64 (void *, void *, void *, uint32_t) {}
void helper_gvec_smax8 (void *, void *, void *, uint32_t) {}
void helper_gvec_smax16 (void *, void *, void *, uint32_t) {}
void helper_gvec_smax32 (void *, void *, void *, uint32_t) {}
void helper_gvec_smax64 (void *, void *, void *, uint32_t) {}
void helper_gvec_umin8 (void *, void *, void *, uint32_t) {}
void helper_gvec_umin16 (void *, void *, void *, uint32_t) {}
void helper_gvec_umin32 (void *, void *, void *, uint32_t) {}
void helper_gvec_umin64 (void *, void *, void *, uint32_t) {}
void helper_gvec_umax8 (void *, void *, void *, uint32_t) {}
void helper_gvec_umax16 (void *, void *, void *, uint32_t) {}
void helper_gvec_umax32 (void *, void *, void *, uint32_t) {}
void helper_gvec_umax64 (void *, void *, void *, uint32_t) {}
void helper_gvec_neg8 (void *, void *, uint32_t) {}
void helper_gvec_neg16 (void *, void *, uint32_t) {}
void helper_gvec_neg32 (void *, void *, uint32_t) {}
void helper_gvec_neg64 (void *, void *, uint32_t) {}
void helper_gvec_abs8 (void *, void *, uint32_t) {}
void helper_gvec_abs16 (void *, void *, uint32_t) {}
void helper_gvec_abs32 (void *, void *, uint32_t) {}
void helper_gvec_abs64 (void *, void *, uint32_t) {}
void helper_gvec_not (void *, void *, uint32_t) {}
void helper_gvec_and (void *, void *, void *, uint32_t) {}
void helper_gvec_or (void *, void *, void *, uint32_t) {}
void helper_gvec_xor (void *, void *, void *, uint32_t) {}
void helper_gvec_andc (void *, void *, void *, uint32_t) {}
void helper_gvec_orc (void *, void *, void *, uint32_t) {}
void helper_gvec_nand (void *, void *, void *, uint32_t) {}
void helper_gvec_nor (void *, void *, void *, uint32_t) {}
void helper_gvec_eqv (void *, void *, void *, uint32_t) {}
void helper_gvec_ands (void *, void *, uint64_t, uint32_t) {}
void helper_gvec_xors (void *, void *, uint64_t, uint32_t) {}
void helper_gvec_ors (void *, void *, uint64_t, uint32_t) {}
void helper_gvec_shl8i (void *, void *, uint32_t) {}
void helper_gvec_shl16i (void *, void *, uint32_t) {}
void helper_gvec_shl32i (void *, void *, uint32_t) {}
void helper_gvec_shl64i (void *, void *, uint32_t) {}
void helper_gvec_shr8i (void *, void *, uint32_t) {}
void helper_gvec_shr16i (void *, void *, uint32_t) {}
void helper_gvec_shr32i (void *, void *, uint32_t) {}
void helper_gvec_shr64i (void *, void *, uint32_t) {}
void helper_gvec_sar8i (void *, void *, uint32_t) {}
void helper_gvec_sar16i (void *, void *, uint32_t) {}
void helper_gvec_sar32i (void *, void *, uint32_t) {}
void helper_gvec_sar64i (void *, void *, uint32_t) {}
void helper_gvec_shl8v (void *, void *, void *, uint32_t) {}
void helper_gvec_shl16v (void *, void *, void *, uint32_t) {}
void helper_gvec_shl32v (void *, void *, void *, uint32_t) {}
void helper_gvec_shl64v (void *, void *, void *, uint32_t) {}
void helper_gvec_shr8v (void *, void *, void *, uint32_t) {}
void helper_gvec_shr16v (void *, void *, void *, uint32_t) {}
void helper_gvec_shr32v (void *, void *, void *, uint32_t) {}
void helper_gvec_shr64v (void *, void *, void *, uint32_t) {}
void helper_gvec_sar8v (void *, void *, void *, uint32_t) {}
void helper_gvec_sar16v (void *, void *, void *, uint32_t) {}
void helper_gvec_sar32v (void *, void *, void *, uint32_t) {}
void helper_gvec_sar64v (void *, void *, void *, uint32_t) {}
void helper_gvec_eq8 (void *, void *, void *, uint32_t) {}
void helper_gvec_eq16 (void *, void *, void *, uint32_t) {}
void helper_gvec_eq32 (void *, void *, void *, uint32_t) {}
void helper_gvec_eq64 (void *, void *, void *, uint32_t) {}
void helper_gvec_ne8 (void *, void *, void *, uint32_t) {}
void helper_gvec_ne16 (void *, void *, void *, uint32_t) {}
void helper_gvec_ne32 (void *, void *, void *, uint32_t) {}
void helper_gvec_ne64 (void *, void *, void *, uint32_t) {}
void helper_gvec_lt8 (void *, void *, void *, uint32_t) {}
void helper_gvec_lt16 (void *, void *, void *, uint32_t) {}
void helper_gvec_lt32 (void *, void *, void *, uint32_t) {}
void helper_gvec_lt64 (void *, void *, void *, uint32_t) {}
void helper_gvec_le8 (void *, void *, void *, uint32_t) {}
void helper_gvec_le16 (void *, void *, void *, uint32_t) {}
void helper_gvec_le32 (void *, void *, void *, uint32_t) {}
void helper_gvec_le64 (void *, void *, void *, uint32_t) {}
void helper_gvec_ltu8 (void *, void *, void *, uint32_t) {}
void helper_gvec_ltu16 (void *, void *, void *, uint32_t) {}
void helper_gvec_ltu32 (void *, void *, void *, uint32_t) {}
void helper_gvec_ltu64 (void *, void *, void *, uint32_t) {}
void helper_gvec_leu8 (void *, void *, void *, uint32_t) {}
void helper_gvec_leu16 (void *, void *, void *, uint32_t) {}
void helper_gvec_leu32 (void *, void *, void *, uint32_t) {}
void helper_gvec_leu64 (void *, void *, void *, uint32_t) {}
void helper_gvec_bitsel (void *, void *, void *, void *, uint32_t) {}
