#undef R_386_PC32 /* XXX */
#undef R_386_PC8  /* XXX */
#undef R_386_32   /* XXX */

uint32_t helper_sxtb16 (uint32_t) { return 0; }
uint32_t helper_uxtb16 (uint32_t) { return 0; }
uint32_t helper_add_setq (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_add_saturate (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_sub_saturate (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_add_usaturate (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_sub_usaturate (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_double_saturate (struct CPUARMState *, int32_t) { return 0; }
int32_t helper_sdiv (int32_t, int32_t) { return 0; }
uint32_t helper_udiv (uint32_t, uint32_t) { return 0; }
uint32_t helper_rbit (uint32_t) { return 0; }
uint32_t helper_sadd8 (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_ssub8 (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_ssub16 (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_sadd16 (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_saddsubx (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_ssubaddx (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_uadd8 (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_usub8 (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_usub16 (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_uadd16 (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_uaddsubx (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_usubaddx (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_qadd8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_qsub8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_qsub16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_qadd16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_qaddsubx (uint32_t, uint32_t) { return 0; }
uint32_t helper_qsubaddx (uint32_t, uint32_t) { return 0; }
uint32_t helper_shadd8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_shsub8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_shsub16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_shadd16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_shaddsubx (uint32_t, uint32_t) { return 0; }
uint32_t helper_shsubaddx (uint32_t, uint32_t) { return 0; }
uint32_t helper_uqadd8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_uqsub8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_uqsub16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_uqadd16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_uqaddsubx (uint32_t, uint32_t) { return 0; }
uint32_t helper_uqsubaddx (uint32_t, uint32_t) { return 0; }
uint32_t helper_uhadd8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_uhsub8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_uhsub16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_uhadd16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_uhaddsubx (uint32_t, uint32_t) { return 0; }
uint32_t helper_uhsubaddx (uint32_t, uint32_t) { return 0; }
uint32_t helper_ssat (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_usat (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_ssat16 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_usat16 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_usad8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_sel_flags (uint32_t, uint32_t, uint32_t) { return 0; }
void helper_exception_internal (struct CPUARMState *, uint32_t) {}
void helper_exception_with_syndrome (struct CPUARMState *, uint32_t, uint32_t, uint32_t) {}
void helper_exception_bkpt_insn (struct CPUARMState *, uint32_t) {}
void helper_setend (struct CPUARMState *) {}
void helper_wfi (struct CPUARMState *, uint32_t) {}
void helper_wfe (struct CPUARMState *) {}
void helper_yield (struct CPUARMState *) {}
void helper_pre_hvc (struct CPUARMState *) {}
void helper_pre_smc (struct CPUARMState *, uint32_t) {}
void helper_check_breakpoints (struct CPUARMState *) {}
void helper_cpsr_write (struct CPUARMState *, uint32_t, uint32_t) {}
void helper_cpsr_write_eret (struct CPUARMState *, uint32_t) {}
uint32_t helper_cpsr_read (struct CPUARMState *) { return 0; }
void helper_v7m_msr (struct CPUARMState *, uint32_t, uint32_t) {}
uint32_t helper_v7m_mrs (struct CPUARMState *, uint32_t) { return 0; }
void helper_v7m_bxns (struct CPUARMState *, uint32_t) {}
void helper_v7m_blxns (struct CPUARMState *, uint32_t) {}
uint32_t helper_v7m_tt (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
void helper_access_check_cp_reg (struct CPUARMState *, void *, uint32_t, uint32_t) {}
void helper_set_cp_reg (struct CPUARMState *, void *, uint32_t) {}
uint32_t helper_get_cp_reg (struct CPUARMState *, void *) { return 0; }
void helper_set_cp_reg64 (struct CPUARMState *, void *, uint64_t) {}
uint64_t helper_get_cp_reg64 (struct CPUARMState *, void *) { return 0; }
void helper_msr_i_pstate (struct CPUARMState *, uint32_t, uint32_t) {}
void helper_clear_pstate_ss (struct CPUARMState *) {}
void helper_exception_return (struct CPUARMState *) {}
uint32_t helper_get_r13_banked (struct CPUARMState *, uint32_t) { return 0; }
void helper_set_r13_banked (struct CPUARMState *, uint32_t, uint32_t) {}
uint32_t helper_mrs_banked (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
void helper_msr_banked (struct CPUARMState *, uint32_t, uint32_t, uint32_t) {}
uint32_t helper_get_user_reg (struct CPUARMState *, uint32_t) { return 0; }
void helper_set_user_reg (struct CPUARMState *, uint32_t, uint32_t) {}
uint32_t helper_vfp_get_fpscr (struct CPUARMState *) { return 0; }
void helper_vfp_set_fpscr (struct CPUARMState *, uint32_t) {}
float32 helper_vfp_adds (float32, float32, void *) { return (float32)0; }
float64 helper_vfp_addd (float64, float64, void *) { return (float64)0; }
float32 helper_vfp_subs (float32, float32, void *) { return (float32)0; }
float64 helper_vfp_subd (float64, float64, void *) { return (float64)0; }
float32 helper_vfp_muls (float32, float32, void *) { return (float32)0; }
float64 helper_vfp_muld (float64, float64, void *) { return (float64)0; }
float32 helper_vfp_divs (float32, float32, void *) { return (float32)0; }
float64 helper_vfp_divd (float64, float64, void *) { return (float64)0; }
float32 helper_vfp_maxs (float32, float32, void *) { return (float32)0; }
float64 helper_vfp_maxd (float64, float64, void *) { return (float64)0; }
float32 helper_vfp_mins (float32, float32, void *) { return (float32)0; }
float64 helper_vfp_mind (float64, float64, void *) { return (float64)0; }
float32 helper_vfp_maxnums (float32, float32, void *) { return (float32)0; }
float64 helper_vfp_maxnumd (float64, float64, void *) { return (float64)0; }
float32 helper_vfp_minnums (float32, float32, void *) { return (float32)0; }
float64 helper_vfp_minnumd (float64, float64, void *) { return (float64)0; }
float32 helper_vfp_negs (float32) { return (float32)0; }
float64 helper_vfp_negd (float64) { return (float64)0; }
float32 helper_vfp_abss (float32) { return (float32)0; }
float64 helper_vfp_absd (float64) { return (float64)0; }
float32 helper_vfp_sqrts (float32, struct CPUARMState *) { return (float32)0; }
float64 helper_vfp_sqrtd (float64, struct CPUARMState *) { return (float64)0; }
void helper_vfp_cmps (float32, float32, struct CPUARMState *) {}
void helper_vfp_cmpd (float64, float64, struct CPUARMState *) {}
void helper_vfp_cmpes (float32, float32, struct CPUARMState *) {}
void helper_vfp_cmped (float64, float64, struct CPUARMState *) {}
float64 helper_vfp_fcvtds (float32, struct CPUARMState *) { return (float64)0; }
float32 helper_vfp_fcvtsd (float64, struct CPUARMState *) { return (float32)0; }
float16 helper_vfp_uitoh (uint32_t, void *) { return 0; }
float32 helper_vfp_uitos (uint32_t, void *) { return 0; }
float64 helper_vfp_uitod (uint32_t, void *) { return 0; }
float16 helper_vfp_sitoh (uint32_t, void *) { return 0; }
float32 helper_vfp_sitos (uint32_t, void *) { return 0; }
float64 helper_vfp_sitod (uint32_t, void *) { return 0; }
uint32_t helper_vfp_touih (float16, void *) { return 0; }
uint32_t helper_vfp_touis (float32, void *) { return 0; }
uint32_t helper_vfp_touid (float64, void *) { return 0; }
uint32_t helper_vfp_touizh (float16, void *) { return 0; }
uint32_t helper_vfp_touizs (float32, void *) { return 0; }
uint32_t helper_vfp_touizd (float64, void *) { return 0; }
uint32_t helper_vfp_tosih (float16, void *) { return 0; }
uint32_t helper_vfp_tosis (float32, void *) { return 0; }
uint32_t helper_vfp_tosid (float64, void *) { return 0; }
uint32_t helper_vfp_tosizh (float16, void *) { return 0; }
uint32_t helper_vfp_tosizs (float32, void *) { return 0; }
uint32_t helper_vfp_tosizd (float64, void *) { return 0; }
uint32_t helper_vfp_toshs_round_to_zero (float32, uint32_t, void *) { return 0; }
uint32_t helper_vfp_tosls_round_to_zero (float32, uint32_t, void *) { return 0; }
uint32_t helper_vfp_touhs_round_to_zero (float32, uint32_t, void *) { return 0; }
uint32_t helper_vfp_touls_round_to_zero (float32, uint32_t, void *) { return 0; }
uint64_t helper_vfp_toshd_round_to_zero (float64, uint32_t, void *) { return 0; }
uint64_t helper_vfp_tosld_round_to_zero (float64, uint32_t, void *) { return 0; }
uint64_t helper_vfp_touhd_round_to_zero (float64, uint32_t, void *) { return 0; }
uint64_t helper_vfp_tould_round_to_zero (float64, uint32_t, void *) { return 0; }
uint32_t helper_vfp_toulh (float16, uint32_t, void *) { return 0; }
uint32_t helper_vfp_toslh (float16, uint32_t, void *) { return 0; }
uint32_t helper_vfp_toshs (float32, uint32_t, void *) { return 0; }
uint32_t helper_vfp_tosls (float32, uint32_t, void *) { return 0; }
uint64_t helper_vfp_tosqs (float32, uint32_t, void *) { return 0; }
uint32_t helper_vfp_touhs (float32, uint32_t, void *) { return 0; }
uint32_t helper_vfp_touls (float32, uint32_t, void *) { return 0; }
uint64_t helper_vfp_touqs (float32, uint32_t, void *) { return 0; }
uint64_t helper_vfp_toshd (float64, uint32_t, void *) { return 0; }
uint64_t helper_vfp_tosld (float64, uint32_t, void *) { return 0; }
uint64_t helper_vfp_tosqd (float64, uint32_t, void *) { return 0; }
uint64_t helper_vfp_touhd (float64, uint32_t, void *) { return 0; }
uint64_t helper_vfp_tould (float64, uint32_t, void *) { return 0; }
uint64_t helper_vfp_touqd (float64, uint32_t, void *) { return 0; }
float32 helper_vfp_shtos (uint32_t, uint32_t, void *) { return 0; }
float32 helper_vfp_sltos (uint32_t, uint32_t, void *) { return 0; }
float32 helper_vfp_sqtos (uint64_t, uint32_t, void *) { return 0; }
float32 helper_vfp_uhtos (uint32_t, uint32_t, void *) { return 0; }
float32 helper_vfp_ultos (uint32_t, uint32_t, void *) { return 0; }
float32 helper_vfp_uqtos (uint64_t, uint32_t, void *) { return 0; }
float64 helper_vfp_shtod (uint64_t, uint32_t, void *) { return 0; }
float64 helper_vfp_sltod (uint64_t, uint32_t, void *) { return 0; }
float64 helper_vfp_sqtod (uint64_t, uint32_t, void *) { return 0; }
float64 helper_vfp_uhtod (uint64_t, uint32_t, void *) { return 0; }
float64 helper_vfp_ultod (uint64_t, uint32_t, void *) { return 0; }
float64 helper_vfp_uqtod (uint64_t, uint32_t, void *) { return 0; }
float16 helper_vfp_sltoh (uint32_t, uint32_t, void *) { return 0; }
float16 helper_vfp_ultoh (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_set_rmode (uint32_t, void *) { return 0; }
uint32_t helper_set_neon_rmode (uint32_t, struct CPUARMState *) { return 0; }
float32 helper_vfp_fcvt_f16_to_f32 (uint32_t, struct CPUARMState *) { return 0; }
uint32_t helper_vfp_fcvt_f32_to_f16 (float32, struct CPUARMState *) { return 0; }
float32 helper_neon_fcvt_f16_to_f32 (uint32_t, struct CPUARMState *) { return 0; }
uint32_t helper_neon_fcvt_f32_to_f16 (float32, struct CPUARMState *) { return 0; }
float64 helper_vfp_fcvt_f16_to_f64 (uint32_t, struct CPUARMState *) { return 0; }
uint32_t helper_vfp_fcvt_f64_to_f16 (float64, struct CPUARMState *) { return 0; }
float64 helper_vfp_muladdd (float64, float64, float64, void *) { return (float64)0; }
float32 helper_vfp_muladds (float32, float32, float32, void *) { return (float32)0; }
float32 helper_recps_f32 (float32, float32, struct CPUARMState *) { return (float32)0; }
float32 helper_rsqrts_f32 (float32, float32, struct CPUARMState *) { return (float32)0; }
float16 helper_recpe_f16 (float16, void *) { return (float16)0; }
float32 helper_recpe_f32 (float32, void *) { return (float32)0; }
float64 helper_recpe_f64 (float64, void *) { return (float64)0; }
float16 helper_rsqrte_f16 (float16, void *) { return (float16)0; }
float32 helper_rsqrte_f32 (float32, void *) { return (float32)0; }
float64 helper_rsqrte_f64 (float64, void *) { return (float64)0; }
uint32_t helper_recpe_u32 (uint32_t, void *) { return 0; }
uint32_t helper_rsqrte_u32 (uint32_t, void *) { return 0; }
uint32_t helper_neon_tbl (uint32_t, uint32_t, void *, uint32_t) { return 0; }
uint32_t helper_shl_cc (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_shr_cc (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_sar_cc (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_ror_cc (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
float32 helper_rints_exact (float32, void *) { return (float32)0; }
float64 helper_rintd_exact (float64, void *) { return (float64)0; }
float32 helper_rints (float32, void *) { return (float32)0; }
float64 helper_rintd (float64, void *) { return (float64)0; }
uint32_t helper_neon_qadd_u8 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qadd_s8 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qadd_u16 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qadd_s16 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qadd_u32 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qadd_s32 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_uqadd_s8 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_uqadd_s16 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_uqadd_s32 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_neon_uqadd_s64 (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_neon_sqadd_u8 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_sqadd_u16 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_sqadd_u32 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_neon_sqadd_u64 (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_neon_qsub_u8 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qsub_s8 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qsub_u16 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qsub_s16 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qsub_u32 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qsub_s32 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_neon_qadd_u64 (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_neon_qadd_s64 (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_neon_qsub_u64 (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_neon_qsub_s64 (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_neon_hadd_s8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_hadd_u8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_hadd_s16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_hadd_u16 (uint32_t, uint32_t) { return 0; }
int32_t helper_neon_hadd_s32 (int32_t, int32_t) { return 0; }
uint32_t helper_neon_hadd_u32 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_rhadd_s8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_rhadd_u8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_rhadd_s16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_rhadd_u16 (uint32_t, uint32_t) { return 0; }
int32_t helper_neon_rhadd_s32 (int32_t, int32_t) { return 0; }
uint32_t helper_neon_rhadd_u32 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_hsub_s8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_hsub_u8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_hsub_s16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_hsub_u16 (uint32_t, uint32_t) { return 0; }
int32_t helper_neon_hsub_s32 (int32_t, int32_t) { return 0; }
uint32_t helper_neon_hsub_u32 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_cgt_u8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_cgt_s8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_cgt_u16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_cgt_s16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_cgt_u32 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_cgt_s32 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_cge_u8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_cge_s8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_cge_u16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_cge_s16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_cge_u32 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_cge_s32 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_min_u8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_min_s8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_min_u16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_min_s16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_min_u32 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_min_s32 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_max_u8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_max_s8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_max_u16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_max_s16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_max_u32 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_max_s32 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_pmin_u8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_pmin_s8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_pmin_u16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_pmin_s16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_pmax_u8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_pmax_s8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_pmax_u16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_pmax_s16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_abd_u8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_abd_s8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_abd_u16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_abd_s16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_abd_u32 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_abd_s32 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_shl_u8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_shl_s8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_shl_u16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_shl_s16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_shl_u32 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_shl_s32 (uint32_t, uint32_t) { return 0; }
uint64_t helper_neon_shl_u64 (uint64_t, uint64_t) { return 0; }
uint64_t helper_neon_shl_s64 (uint64_t, uint64_t) { return 0; }
uint32_t helper_neon_rshl_u8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_rshl_s8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_rshl_u16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_rshl_s16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_rshl_u32 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_rshl_s32 (uint32_t, uint32_t) { return 0; }
uint64_t helper_neon_rshl_u64 (uint64_t, uint64_t) { return 0; }
uint64_t helper_neon_rshl_s64 (uint64_t, uint64_t) { return 0; }
uint32_t helper_neon_qshl_u8 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qshl_s8 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qshl_u16 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qshl_s16 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qshl_u32 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qshl_s32 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_neon_qshl_u64 (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_neon_qshl_s64 (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_neon_qshlu_s8 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qshlu_s16 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qshlu_s32 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_neon_qshlu_s64 (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_neon_qrshl_u8 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qrshl_s8 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qrshl_u16 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qrshl_s16 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qrshl_u32 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qrshl_s32 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_neon_qrshl_u64 (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_neon_qrshl_s64 (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_neon_add_u8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_add_u16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_padd_u8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_padd_u16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_sub_u8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_sub_u16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_mul_u8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_mul_u16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_mul_p8 (uint32_t, uint32_t) { return 0; }
uint64_t helper_neon_mull_p8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_tst_u8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_tst_u16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_tst_u32 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_ceq_u8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_ceq_u16 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_ceq_u32 (uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_abs_s8 (uint32_t) { return 0; }
uint32_t helper_neon_abs_s16 (uint32_t) { return 0; }
uint32_t helper_neon_clz_u8 (uint32_t) { return 0; }
uint32_t helper_neon_clz_u16 (uint32_t) { return 0; }
uint32_t helper_neon_cls_s8 (uint32_t) { return 0; }
uint32_t helper_neon_cls_s16 (uint32_t) { return 0; }
uint32_t helper_neon_cls_s32 (uint32_t) { return 0; }
uint32_t helper_neon_cnt_u8 (uint32_t) { return 0; }
uint32_t helper_neon_rbit_u8 (uint32_t) { return 0; }
uint32_t helper_neon_qdmulh_s16 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qrdmulh_s16 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qrdmlah_s16 (struct CPUARMState *, uint32_t, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qrdmlsh_s16 (struct CPUARMState *, uint32_t, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qdmulh_s32 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qrdmulh_s32 (struct CPUARMState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qrdmlah_s32 (struct CPUARMState *, int32_t, int32_t, int32_t) { return 0; }
uint32_t helper_neon_qrdmlsh_s32 (struct CPUARMState *, int32_t, int32_t, int32_t) { return 0; }
uint32_t helper_neon_narrow_u8 (uint64_t) { return 0; }
uint32_t helper_neon_narrow_u16 (uint64_t) { return 0; }
uint32_t helper_neon_unarrow_sat8 (struct CPUARMState *, uint64_t) { return 0; }
uint32_t helper_neon_narrow_sat_u8 (struct CPUARMState *, uint64_t) { return 0; }
uint32_t helper_neon_narrow_sat_s8 (struct CPUARMState *, uint64_t) { return 0; }
uint32_t helper_neon_unarrow_sat16 (struct CPUARMState *, uint64_t) { return 0; }
uint32_t helper_neon_narrow_sat_u16 (struct CPUARMState *, uint64_t) { return 0; }
uint32_t helper_neon_narrow_sat_s16 (struct CPUARMState *, uint64_t) { return 0; }
uint32_t helper_neon_unarrow_sat32 (struct CPUARMState *, uint64_t) { return 0; }
uint32_t helper_neon_narrow_sat_u32 (struct CPUARMState *, uint64_t) { return 0; }
uint32_t helper_neon_narrow_sat_s32 (struct CPUARMState *, uint64_t) { return 0; }
uint32_t helper_neon_narrow_high_u8 (uint64_t) { return 0; }
uint32_t helper_neon_narrow_high_u16 (uint64_t) { return 0; }
uint32_t helper_neon_narrow_round_high_u8 (uint64_t) { return 0; }
uint32_t helper_neon_narrow_round_high_u16 (uint64_t) { return 0; }
uint64_t helper_neon_widen_u8 (uint32_t) { return 0; }
uint64_t helper_neon_widen_s8 (uint32_t) { return 0; }
uint64_t helper_neon_widen_u16 (uint32_t) { return 0; }
uint64_t helper_neon_widen_s16 (uint32_t) { return 0; }
uint64_t helper_neon_addl_u16 (uint64_t, uint64_t) { return 0; }
uint64_t helper_neon_addl_u32 (uint64_t, uint64_t) { return 0; }
uint64_t helper_neon_paddl_u16 (uint64_t, uint64_t) { return 0; }
uint64_t helper_neon_paddl_u32 (uint64_t, uint64_t) { return 0; }
uint64_t helper_neon_subl_u16 (uint64_t, uint64_t) { return 0; }
uint64_t helper_neon_subl_u32 (uint64_t, uint64_t) { return 0; }
uint64_t helper_neon_addl_saturate_s32 (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_neon_addl_saturate_s64 (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_neon_abdl_u16 (uint32_t, uint32_t) { return 0; }
uint64_t helper_neon_abdl_s16 (uint32_t, uint32_t) { return 0; }
uint64_t helper_neon_abdl_u32 (uint32_t, uint32_t) { return 0; }
uint64_t helper_neon_abdl_s32 (uint32_t, uint32_t) { return 0; }
uint64_t helper_neon_abdl_u64 (uint32_t, uint32_t) { return 0; }
uint64_t helper_neon_abdl_s64 (uint32_t, uint32_t) { return 0; }
uint64_t helper_neon_mull_u8 (uint32_t, uint32_t) { return 0; }
uint64_t helper_neon_mull_s8 (uint32_t, uint32_t) { return 0; }
uint64_t helper_neon_mull_u16 (uint32_t, uint32_t) { return 0; }
uint64_t helper_neon_mull_s16 (uint32_t, uint32_t) { return 0; }
uint64_t helper_neon_negl_u16 (uint64_t) { return 0; }
uint64_t helper_neon_negl_u32 (uint64_t) { return 0; }
uint32_t helper_neon_qabs_s8 (struct CPUARMState *, uint32_t) { return 0; }
uint32_t helper_neon_qabs_s16 (struct CPUARMState *, uint32_t) { return 0; }
uint32_t helper_neon_qabs_s32 (struct CPUARMState *, uint32_t) { return 0; }
uint64_t helper_neon_qabs_s64 (struct CPUARMState *, uint64_t) { return 0; }
uint32_t helper_neon_qneg_s8 (struct CPUARMState *, uint32_t) { return 0; }
uint32_t helper_neon_qneg_s16 (struct CPUARMState *, uint32_t) { return 0; }
uint32_t helper_neon_qneg_s32 (struct CPUARMState *, uint32_t) { return 0; }
uint64_t helper_neon_qneg_s64 (struct CPUARMState *, uint64_t) { return 0; }
uint32_t helper_neon_abd_f32 (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_neon_ceq_f32 (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_neon_cge_f32 (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_neon_cgt_f32 (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_neon_acge_f32 (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_neon_acgt_f32 (uint32_t, uint32_t, void *) { return 0; }
uint64_t helper_neon_acge_f64 (uint64_t, uint64_t, void *) { return 0; }
uint64_t helper_neon_acgt_f64 (uint64_t, uint64_t, void *) { return 0; }
uint64_t helper_iwmmxt_maddsq (uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_madduq (uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_sadb (uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_sadw (uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_mulslw (uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_mulshw (uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_mululw (uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_muluhw (uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_macsw (uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_macuw (uint64_t, uint64_t) { return 0; }
uint32_t helper_iwmmxt_setpsr_nz (uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpacklb (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpacklw (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpackll (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpackhb (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpackhw (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpackhl (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpacklub (struct CPUARMState *, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpackluw (struct CPUARMState *, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpacklul (struct CPUARMState *, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpackhub (struct CPUARMState *, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpackhuw (struct CPUARMState *, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpackhul (struct CPUARMState *, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpacklsb (struct CPUARMState *, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpacklsw (struct CPUARMState *, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpacklsl (struct CPUARMState *, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpackhsb (struct CPUARMState *, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpackhsw (struct CPUARMState *, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpackhsl (struct CPUARMState *, uint64_t) { return 0; }
uint64_t helper_iwmmxt_cmpeqb (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_cmpeqw (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_cmpeql (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_cmpgtub (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_cmpgtuw (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_cmpgtul (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_cmpgtsb (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_cmpgtsw (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_cmpgtsl (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_minsb (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_minsw (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_minsl (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_minub (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_minuw (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_minul (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_maxsb (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_maxsw (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_maxsl (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_maxub (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_maxuw (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_maxul (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_subnb (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_subnw (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_subnl (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_addnb (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_addnw (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_addnl (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_subub (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_subuw (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_subul (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_addub (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_adduw (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_addul (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_subsb (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_subsw (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_subsl (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_addsb (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_addsw (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_addsl (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_avgb0 (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_avgb1 (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_avgw0 (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_avgw1 (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_align (uint64_t, uint64_t, uint32_t) { return 0; }
uint64_t helper_iwmmxt_insr (uint64_t, uint32_t, uint32_t, uint32_t) { return 0; }
uint64_t helper_iwmmxt_bcstb (uint32_t) { return 0; }
uint64_t helper_iwmmxt_bcstw (uint32_t) { return 0; }
uint64_t helper_iwmmxt_bcstl (uint32_t) { return 0; }
uint64_t helper_iwmmxt_addcb (uint64_t) { return 0; }
uint64_t helper_iwmmxt_addcw (uint64_t) { return 0; }
uint64_t helper_iwmmxt_addcl (uint64_t) { return 0; }
uint32_t helper_iwmmxt_msbb (uint64_t) { return 0; }
uint32_t helper_iwmmxt_msbw (uint64_t) { return 0; }
uint32_t helper_iwmmxt_msbl (uint64_t) { return 0; }
uint64_t helper_iwmmxt_srlw (struct CPUARMState *, uint64_t, uint32_t) { return 0; }
uint64_t helper_iwmmxt_srll (struct CPUARMState *, uint64_t, uint32_t) { return 0; }
uint64_t helper_iwmmxt_srlq (struct CPUARMState *, uint64_t, uint32_t) { return 0; }
uint64_t helper_iwmmxt_sllw (struct CPUARMState *, uint64_t, uint32_t) { return 0; }
uint64_t helper_iwmmxt_slll (struct CPUARMState *, uint64_t, uint32_t) { return 0; }
uint64_t helper_iwmmxt_sllq (struct CPUARMState *, uint64_t, uint32_t) { return 0; }
uint64_t helper_iwmmxt_sraw (struct CPUARMState *, uint64_t, uint32_t) { return 0; }
uint64_t helper_iwmmxt_sral (struct CPUARMState *, uint64_t, uint32_t) { return 0; }
uint64_t helper_iwmmxt_sraq (struct CPUARMState *, uint64_t, uint32_t) { return 0; }
uint64_t helper_iwmmxt_rorw (struct CPUARMState *, uint64_t, uint32_t) { return 0; }
uint64_t helper_iwmmxt_rorl (struct CPUARMState *, uint64_t, uint32_t) { return 0; }
uint64_t helper_iwmmxt_rorq (struct CPUARMState *, uint64_t, uint32_t) { return 0; }
uint64_t helper_iwmmxt_shufh (struct CPUARMState *, uint64_t, uint32_t) { return 0; }
uint64_t helper_iwmmxt_packuw (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_packul (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_packuq (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_packsw (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_packsl (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_packsq (struct CPUARMState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_muladdsl (uint64_t, uint32_t, uint32_t) { return 0; }
uint64_t helper_iwmmxt_muladdsw (uint64_t, uint32_t, uint32_t) { return 0; }
uint64_t helper_iwmmxt_muladdswl (uint64_t, uint32_t, uint32_t) { return 0; }
void helper_neon_unzip8 (void *, void *) {}
void helper_neon_unzip16 (void *, void *) {}
void helper_neon_qunzip8 (void *, void *) {}
void helper_neon_qunzip16 (void *, void *) {}
void helper_neon_qunzip32 (void *, void *) {}
void helper_neon_zip8 (void *, void *) {}
void helper_neon_zip16 (void *, void *) {}
void helper_neon_qzip8 (void *, void *) {}
void helper_neon_qzip16 (void *, void *) {}
void helper_neon_qzip32 (void *, void *) {}
void helper_crypto_aese (void *, void *, uint32_t) {}
void helper_crypto_aesmc (void *, void *, uint32_t) {}
void helper_crypto_sha1_3reg (void *, void *, void *, uint32_t) {}
void helper_crypto_sha1h (void *, void *) {}
void helper_crypto_sha1su1 (void *, void *) {}
void helper_crypto_sha256h (void *, void *, void *) {}
void helper_crypto_sha256h2 (void *, void *, void *) {}
void helper_crypto_sha256su0 (void *, void *) {}
void helper_crypto_sha256su1 (void *, void *, void *) {}
void helper_crypto_sha512h (void *, void *, void *) {}
void helper_crypto_sha512h2 (void *, void *, void *) {}
void helper_crypto_sha512su0 (void *, void *) {}
void helper_crypto_sha512su1 (void *, void *, void *) {}
void helper_crypto_sm3tt (void *, void *, void *, uint32_t, uint32_t) {}
void helper_crypto_sm3partw1 (void *, void *, void *) {}
void helper_crypto_sm3partw2 (void *, void *, void *) {}
void helper_crypto_sm4e (void *, void *) {}
void helper_crypto_sm4ekey (void *, void *, void *) {}
uint32_t helper_crc32 (uint32_t, uint32_t, uint32_t) { return 0; }
uint32_t helper_crc32c (uint32_t, uint32_t, uint32_t) { return 0; }
void helper_dc_zva (struct CPUARMState *, uint64_t) {}
uint64_t helper_neon_pmull_64_lo (uint64_t, uint64_t) { return 0; }
uint64_t helper_neon_pmull_64_hi (uint64_t, uint64_t) { return 0; }
void helper_gvec_qrdmlah_s16 (void *, void *, void *, void *, uint32_t) {}
void helper_gvec_qrdmlsh_s16 (void *, void *, void *, void *, uint32_t) {}
void helper_gvec_qrdmlah_s32 (void *, void *, void *, void *, uint32_t) {}
void helper_gvec_qrdmlsh_s32 (void *, void *, void *, void *, uint32_t) {}
void helper_gvec_fcaddh (void *, void *, void *, void *, uint32_t) {}
void helper_gvec_fcadds (void *, void *, void *, void *, uint32_t) {}
void helper_gvec_fcaddd (void *, void *, void *, void *, uint32_t) {}
void helper_gvec_fcmlah (void *, void *, void *, void *, uint32_t) {}
void helper_gvec_fcmlah_idx (void *, void *, void *, void *, uint32_t) {}
void helper_gvec_fcmlas (void *, void *, void *, void *, uint32_t) {}
void helper_gvec_fcmlas_idx (void *, void *, void *, void *, uint32_t) {}
void helper_gvec_fcmlad (void *, void *, void *, void *, uint32_t) {}
uint64_t helper_udiv64 (uint64_t, uint64_t) { return 0; }
int64_t helper_sdiv64 (int64_t, int64_t) { return 0; }
uint64_t helper_rbit64 (uint64_t) { return 0; }
uint64_t helper_vfp_cmps_a64 (float32, float32, void *) { return 0; }
uint64_t helper_vfp_cmpes_a64 (float32, float32, void *) { return 0; }
uint64_t helper_vfp_cmpd_a64 (float64, float64, void *) { return 0; }
uint64_t helper_vfp_cmped_a64 (float64, float64, void *) { return 0; }
uint64_t helper_simd_tbl (struct CPUARMState *, uint64_t, uint64_t, uint32_t, uint32_t) { return 0; }
float32 helper_vfp_mulxs (float32, float32, void *) { return (float32)0; }
float64 helper_vfp_mulxd (float64, float64, void *) { return (float64)0; }
uint64_t helper_neon_ceq_f64 (uint64_t, uint64_t, void *) { return 0; }
uint64_t helper_neon_cge_f64 (uint64_t, uint64_t, void *) { return 0; }
uint64_t helper_neon_cgt_f64 (uint64_t, uint64_t, void *) { return 0; }
float16 helper_recpsf_f16 (float16, float16, void *) { return (float16)0; }
float32 helper_recpsf_f32 (float32, float32, void *) { return (float32)0; }
float64 helper_recpsf_f64 (float64, float64, void *) { return (float64)0; }
float16 helper_rsqrtsf_f16 (float16, float16, void *) { return (float16)0; }
float32 helper_rsqrtsf_f32 (float32, float32, void *) { return (float32)0; }
float64 helper_rsqrtsf_f64 (float64, float64, void *) { return (float64)0; }
uint64_t helper_neon_addlp_s8 (uint64_t) { return 0; }
uint64_t helper_neon_addlp_u8 (uint64_t) { return 0; }
uint64_t helper_neon_addlp_s16 (uint64_t) { return 0; }
uint64_t helper_neon_addlp_u16 (uint64_t) { return 0; }
float64 helper_frecpx_f64 (float64, void *) { return (float64)0; }
float32 helper_frecpx_f32 (float32, void *) { return (float32)0; }
float16 helper_frecpx_f16 (float16, void *) { return (float16)0; }
float32 helper_fcvtx_f64_to_f32 (float64, struct CPUARMState *) { return (float32)0; }
uint64_t helper_crc32_64 (uint64_t, uint64_t, uint32_t) { return 0; }
uint64_t helper_crc32c_64 (uint64_t, uint64_t, uint32_t) { return 0; }
uint64_t helper_paired_cmpxchg64_le (struct CPUARMState *, uint64_t, uint64_t, uint64_t) { return 0; }
uint64_t helper_paired_cmpxchg64_le_parallel (struct CPUARMState *, uint64_t, uint64_t, uint64_t) { return 0; }
uint64_t helper_paired_cmpxchg64_be (struct CPUARMState *, uint64_t, uint64_t, uint64_t) { return 0; }
uint64_t helper_paired_cmpxchg64_be_parallel (struct CPUARMState *, uint64_t, uint64_t, uint64_t) { return 0; }
float16 helper_advsimd_maxh (float16, float16, void *) { return (float16)0; }
float16 helper_advsimd_minh (float16, float16, void *) { return (float16)0; }
float16 helper_advsimd_maxnumh (float16, float16, void *) { return (float16)0; }
float16 helper_advsimd_minnumh (float16, float16, void *) { return (float16)0; }
float16 helper_advsimd_addh (float16, float16, void *) { return (float16)0; }
float16 helper_advsimd_subh (float16, float16, void *) { return (float16)0; }
float16 helper_advsimd_mulh (float16, float16, void *) { return (float16)0; }
float16 helper_advsimd_divh (float16, float16, void *) { return (float16)0; }
uint32_t helper_advsimd_ceq_f16 (float16, float16, void *) { return 0; }
uint32_t helper_advsimd_cge_f16 (float16, float16, void *) { return 0; }
uint32_t helper_advsimd_cgt_f16 (float16, float16, void *) { return 0; }
uint32_t helper_advsimd_acge_f16 (float16, float16, void *) { return 0; }
uint32_t helper_advsimd_acgt_f16 (float16, float16, void *) { return 0; }
float16 helper_advsimd_mulxh (float16, float16, void *) { return (float16)0; }
float16 helper_advsimd_muladdh (float16, float16, float16, void *) { return (float16)0; }
uint32_t helper_advsimd_add2h (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_advsimd_sub2h (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_advsimd_mul2h (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_advsimd_div2h (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_advsimd_max2h (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_advsimd_min2h (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_advsimd_maxnum2h (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_advsimd_minnum2h (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_advsimd_mulx2h (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_advsimd_muladd2h (uint32_t, uint32_t, uint32_t, void *) { return 0; }
float16 helper_advsimd_rinth_exact (float16, void *) { return (float16)0; }
float16 helper_advsimd_rinth (float16, void *) { return (float16)0; }
uint32_t helper_advsimd_f16tosinth (float16, void *) { return 0; }
uint32_t helper_advsimd_f16touinth (float16, void *) { return 0; }
float16 helper_sqrt_f16 (float16, void *) { return (float16)0; }
void helper_trace_guest_mem_before_exec_proxy (struct CPUARMState *, target_ulong, uint32_t) {}
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
void * helper_lookup_tb_ptr (struct CPUARMState *) { return nullptr; }
void helper_exit_atomic (struct CPUARMState *) { __builtin_unreachable(); }
uint32_t helper_atomic_cmpxchgb (struct CPUARMState *, target_ulong, uint32_t, uint32_t) { return 0; }
uint32_t helper_atomic_cmpxchgw_be (struct CPUARMState *, target_ulong, uint32_t, uint32_t) { return 0; }
uint32_t helper_atomic_cmpxchgw_le (struct CPUARMState *, target_ulong, uint32_t, uint32_t) { return 0; }
uint32_t helper_atomic_cmpxchgl_be (struct CPUARMState *, target_ulong, uint32_t, uint32_t) { return 0; }
uint32_t helper_atomic_cmpxchgl_le (struct CPUARMState *, target_ulong, uint32_t, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_addb (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_addw_le (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_addw_be (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_addl_le (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_addl_be (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_andb (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_andw_le (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_andw_be (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_andl_le (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_andl_be (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_orb (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_orw_le (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_orw_be (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_orl_le (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_orl_be (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_xorb (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_xorw_le (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_xorw_be (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_xorl_le (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_xorl_be (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_add_fetchb (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_add_fetchw_le (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_add_fetchw_be (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_add_fetchl_le (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_add_fetchl_be (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_and_fetchb (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_and_fetchw_le (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_and_fetchw_be (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_and_fetchl_le (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_and_fetchl_be (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_or_fetchb (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_or_fetchw_le (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_or_fetchw_be (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_or_fetchl_le (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_or_fetchl_be (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_xor_fetchb (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_xor_fetchw_le (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_xor_fetchw_be (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_xor_fetchl_le (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_xor_fetchl_be (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_xchgb (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_xchgw_le (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_xchgw_be (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_xchgl_le (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_xchgl_be (struct CPUARMState *, target_ulong, uint32_t) { return 0; }
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
void helper_gvec_neg8 (void *, void *, uint32_t) {}
void helper_gvec_neg16 (void *, void *, uint32_t) {}
void helper_gvec_neg32 (void *, void *, uint32_t) {}
void helper_gvec_neg64 (void *, void *, uint32_t) {}
void helper_gvec_not (void *, void *, uint32_t) {}
void helper_gvec_and (void *, void *, void *, uint32_t) {}
void helper_gvec_or (void *, void *, void *, uint32_t) {}
void helper_gvec_xor (void *, void *, void *, uint32_t) {}
void helper_gvec_andc (void *, void *, void *, uint32_t) {}
void helper_gvec_orc (void *, void *, void *, uint32_t) {}
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

const ARMCPRegInfo *get_arm_cp_reginfo(GHashTable *cpregs, uint32_t encoded_cp) { return nullptr; }
