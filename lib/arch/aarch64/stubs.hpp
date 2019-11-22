uint32_t helper_sxtb16 (uint32_t) { return 0; }
uint32_t helper_uxtb16 (uint32_t) { return 0; }
uint32_t helper_add_setq (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_add_saturate (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_sub_saturate (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_add_usaturate (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_sub_usaturate (CPUArchState *, uint32_t, uint32_t) { return 0; }
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
uint32_t helper_ssat (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_usat (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_ssat16 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_usat16 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_usad8 (uint32_t, uint32_t) { return 0; }
uint32_t helper_sel_flags (uint32_t, uint32_t, uint32_t) { return 0; }
void helper_exception_internal (CPUArchState *, uint32_t) { return; }
void helper_exception_with_syndrome (CPUArchState *, uint32_t, uint32_t, uint32_t) { return; }
void helper_exception_bkpt_insn (CPUArchState *, uint32_t) { return; }
void helper_setend (CPUArchState *) { return; }
void helper_wfi (CPUArchState *, uint32_t) { return; }
void helper_wfe (CPUArchState *) { return; }
void helper_yield (CPUArchState *) { return; }
void helper_pre_hvc (CPUArchState *) { return; }
void helper_pre_smc (CPUArchState *, uint32_t) { return; }
void helper_check_breakpoints (CPUArchState *) { return; }
void helper_cpsr_write (CPUArchState *, uint32_t, uint32_t) { return; }
void helper_cpsr_write_eret (CPUArchState *, uint32_t) { return; }
uint32_t helper_cpsr_read (CPUArchState *) { return 0; }
void helper_v7m_msr (CPUArchState *, uint32_t, uint32_t) { return; }
uint32_t helper_v7m_mrs (CPUArchState *, uint32_t) { return 0; }
void helper_v7m_bxns (CPUArchState *, uint32_t) { return; }
void helper_v7m_blxns (CPUArchState *, uint32_t) { return; }
uint32_t helper_v7m_tt (CPUArchState *, uint32_t, uint32_t) { return 0; }
void helper_v7m_preserve_fp_state (CPUArchState *) { return; }
void helper_v7m_vlstm (CPUArchState *, uint32_t) { return; }
void helper_v7m_vlldm (CPUArchState *, uint32_t) { return; }
void helper_v8m_stackcheck (CPUArchState *, uint32_t) { return; }
void helper_access_check_cp_reg (CPUArchState *, void *, uint32_t, uint32_t) { return; }
void helper_set_cp_reg (CPUArchState *, void *, uint32_t) { return; }
uint32_t helper_get_cp_reg (CPUArchState *, void *) { return 0; }
void helper_set_cp_reg64 (CPUArchState *, void *, uint64_t) { return; }
uint64_t helper_get_cp_reg64 (CPUArchState *, void *) { return 0; }
uint32_t helper_get_r13_banked (CPUArchState *, uint32_t) { return 0; }
void helper_set_r13_banked (CPUArchState *, uint32_t, uint32_t) { return; }
uint32_t helper_mrs_banked (CPUArchState *, uint32_t, uint32_t) { return 0; }
void helper_msr_banked (CPUArchState *, uint32_t, uint32_t, uint32_t) { return; }
uint32_t helper_get_user_reg (CPUArchState *, uint32_t) { return 0; }
void helper_set_user_reg (CPUArchState *, uint32_t, uint32_t) { return; }
void helper_rebuild_hflags_m32 (CPUArchState *, int) { return; }
void helper_rebuild_hflags_a32 (CPUArchState *, int) { return; }
void helper_rebuild_hflags_a64 (CPUArchState *, int) { return; }
uint32_t helper_vfp_get_fpscr (CPUArchState *) { return 0; }
void helper_vfp_set_fpscr (CPUArchState *, uint32_t) { return; }
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
float32 helper_vfp_sqrts (float32, CPUArchState *) { return (float32)0; }
float64 helper_vfp_sqrtd (float64, CPUArchState *) { return (float64)0; }
void helper_vfp_cmps (float32, float32, CPUArchState *) { return; }
void helper_vfp_cmpd (float64, float64, CPUArchState *) { return; }
void helper_vfp_cmpes (float32, float32, CPUArchState *) { return; }
void helper_vfp_cmped (float64, float64, CPUArchState *) { return; }
float64 helper_vfp_fcvtds (float32, CPUArchState *) { return (float64)0; }
float32 helper_vfp_fcvtsd (float64, CPUArchState *) { return (float32)0; }
uint32_t helper_vfp_uitoh (uint32_t, void *) { return 0; }
float32 helper_vfp_uitos (uint32_t, void *) { return (float32)0; }
float64 helper_vfp_uitod (uint32_t, void *) { return (float64)0; }
uint32_t helper_vfp_sitoh (uint32_t, void *) { return 0; }
float32 helper_vfp_sitos (uint32_t, void *) { return (float32)0; }
float64 helper_vfp_sitod (uint32_t, void *) { return (float64)0; }
uint32_t helper_vfp_touih (uint32_t, void *) { return 0; }
uint32_t helper_vfp_touis (float32, void *) { return 0; }
uint32_t helper_vfp_touid (float64, void *) { return 0; }
uint32_t helper_vfp_touizh (uint32_t, void *) { return 0; }
uint32_t helper_vfp_touizs (float32, void *) { return 0; }
uint32_t helper_vfp_touizd (float64, void *) { return 0; }
int32_t helper_vfp_tosih (uint32_t, void *) { return 0; }
int32_t helper_vfp_tosis (float32, void *) { return 0; }
int32_t helper_vfp_tosid (float64, void *) { return 0; }
int32_t helper_vfp_tosizh (uint32_t, void *) { return 0; }
int32_t helper_vfp_tosizs (float32, void *) { return 0; }
int32_t helper_vfp_tosizd (float64, void *) { return 0; }
uint32_t helper_vfp_toshs_round_to_zero (float32, uint32_t, void *) { return 0; }
uint32_t helper_vfp_tosls_round_to_zero (float32, uint32_t, void *) { return 0; }
uint32_t helper_vfp_touhs_round_to_zero (float32, uint32_t, void *) { return 0; }
uint32_t helper_vfp_touls_round_to_zero (float32, uint32_t, void *) { return 0; }
uint64_t helper_vfp_toshd_round_to_zero (float64, uint32_t, void *) { return 0; }
uint64_t helper_vfp_tosld_round_to_zero (float64, uint32_t, void *) { return 0; }
uint64_t helper_vfp_touhd_round_to_zero (float64, uint32_t, void *) { return 0; }
uint64_t helper_vfp_tould_round_to_zero (float64, uint32_t, void *) { return 0; }
uint32_t helper_vfp_touhh (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_vfp_toshh (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_vfp_toulh (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_vfp_toslh (uint32_t, uint32_t, void *) { return 0; }
uint64_t helper_vfp_touqh (uint32_t, uint32_t, void *) { return 0; }
uint64_t helper_vfp_tosqh (uint32_t, uint32_t, void *) { return 0; }
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
float32 helper_vfp_shtos (uint32_t, uint32_t, void *) { return (float32)0; }
float32 helper_vfp_sltos (uint32_t, uint32_t, void *) { return (float32)0; }
float32 helper_vfp_sqtos (uint64_t, uint32_t, void *) { return (float32)0; }
float32 helper_vfp_uhtos (uint32_t, uint32_t, void *) { return (float32)0; }
float32 helper_vfp_ultos (uint32_t, uint32_t, void *) { return (float32)0; }
float32 helper_vfp_uqtos (uint64_t, uint32_t, void *) { return (float32)0; }
float64 helper_vfp_shtod (uint64_t, uint32_t, void *) { return (float64)0; }
float64 helper_vfp_sltod (uint64_t, uint32_t, void *) { return (float64)0; }
float64 helper_vfp_sqtod (uint64_t, uint32_t, void *) { return (float64)0; }
float64 helper_vfp_uhtod (uint64_t, uint32_t, void *) { return (float64)0; }
float64 helper_vfp_ultod (uint64_t, uint32_t, void *) { return (float64)0; }
float64 helper_vfp_uqtod (uint64_t, uint32_t, void *) { return (float64)0; }
uint32_t helper_vfp_sltoh (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_vfp_ultoh (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_vfp_sqtoh (uint64_t, uint32_t, void *) { return 0; }
uint32_t helper_vfp_uqtoh (uint64_t, uint32_t, void *) { return 0; }
uint32_t helper_set_rmode (uint32_t, void *) { return 0; }
uint32_t helper_set_neon_rmode (uint32_t, CPUArchState *) { return 0; }
float32 helper_vfp_fcvt_f16_to_f32 (uint32_t, void *, uint32_t) { return (float32)0; }
uint32_t helper_vfp_fcvt_f32_to_f16 (float32, void *, uint32_t) { return 0; }
float64 helper_vfp_fcvt_f16_to_f64 (uint32_t, void *, uint32_t) { return (float64)0; }
uint32_t helper_vfp_fcvt_f64_to_f16 (float64, void *, uint32_t) { return 0; }
float64 helper_vfp_muladdd (float64, float64, float64, void *) { return (float64)0; }
float32 helper_vfp_muladds (float32, float32, float32, void *) { return (float32)0; }
float32 helper_recps_f32 (float32, float32, CPUArchState *) { return (float32)0; }
float32 helper_rsqrts_f32 (float32, float32, CPUArchState *) { return (float32)0; }
uint32_t helper_recpe_f16 (uint32_t, void *) { return 0; }
float32 helper_recpe_f32 (float32, void *) { return (float32)0; }
float64 helper_recpe_f64 (float64, void *) { return (float64)0; }
uint32_t helper_rsqrte_f16 (uint32_t, void *) { return 0; }
float32 helper_rsqrte_f32 (float32, void *) { return (float32)0; }
float64 helper_rsqrte_f64 (float64, void *) { return (float64)0; }
uint32_t helper_recpe_u32 (uint32_t, void *) { return 0; }
uint32_t helper_rsqrte_u32 (uint32_t, void *) { return 0; }
uint32_t helper_neon_tbl (uint32_t, uint32_t, void *, uint32_t) { return 0; }
uint32_t helper_shl_cc (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_shr_cc (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_sar_cc (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_ror_cc (CPUArchState *, uint32_t, uint32_t) { return 0; }
float32 helper_rints_exact (float32, void *) { return (float32)0; }
float64 helper_rintd_exact (float64, void *) { return (float64)0; }
float32 helper_rints (float32, void *) { return (float32)0; }
float64 helper_rintd (float64, void *) { return (float64)0; }
uint32_t helper_vjcvt (float64, CPUArchState *) { return 0; }
uint64_t helper_fjcvtzs (float64, void *) { return 0; }
uint32_t helper_neon_qadd_u8 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qadd_s8 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qadd_u16 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qadd_s16 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qadd_u32 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qadd_s32 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_uqadd_s8 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_uqadd_s16 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_uqadd_s32 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_neon_uqadd_s64 (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_neon_sqadd_u8 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_sqadd_u16 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_sqadd_u32 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_neon_sqadd_u64 (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_neon_qsub_u8 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qsub_s8 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qsub_u16 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qsub_s16 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qsub_u32 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qsub_s32 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_neon_qadd_u64 (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_neon_qadd_s64 (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_neon_qsub_u64 (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_neon_qsub_s64 (CPUArchState *, uint64_t, uint64_t) { return 0; }
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
uint32_t helper_neon_qshl_u8 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qshl_s8 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qshl_u16 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qshl_s16 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qshl_u32 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qshl_s32 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_neon_qshl_u64 (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_neon_qshl_s64 (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_neon_qshlu_s8 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qshlu_s16 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qshlu_s32 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_neon_qshlu_s64 (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint32_t helper_neon_qrshl_u8 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qrshl_s8 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qrshl_u16 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qrshl_s16 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qrshl_u32 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qrshl_s32 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint64_t helper_neon_qrshl_u64 (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_neon_qrshl_s64 (CPUArchState *, uint64_t, uint64_t) { return 0; }
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
uint32_t helper_neon_clz_u8 (uint32_t) { return 0; }
uint32_t helper_neon_clz_u16 (uint32_t) { return 0; }
uint32_t helper_neon_cls_s8 (uint32_t) { return 0; }
uint32_t helper_neon_cls_s16 (uint32_t) { return 0; }
uint32_t helper_neon_cls_s32 (uint32_t) { return 0; }
uint32_t helper_neon_cnt_u8 (uint32_t) { return 0; }
uint32_t helper_neon_rbit_u8 (uint32_t) { return 0; }
uint32_t helper_neon_qdmulh_s16 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qrdmulh_s16 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qrdmlah_s16 (CPUArchState *, uint32_t, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qrdmlsh_s16 (CPUArchState *, uint32_t, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qdmulh_s32 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qrdmulh_s32 (CPUArchState *, uint32_t, uint32_t) { return 0; }
uint32_t helper_neon_qrdmlah_s32 (CPUArchState *, int32_t, int32_t, int32_t) { return 0; }
uint32_t helper_neon_qrdmlsh_s32 (CPUArchState *, int32_t, int32_t, int32_t) { return 0; }
uint32_t helper_neon_narrow_u8 (uint64_t) { return 0; }
uint32_t helper_neon_narrow_u16 (uint64_t) { return 0; }
uint32_t helper_neon_unarrow_sat8 (CPUArchState *, uint64_t) { return 0; }
uint32_t helper_neon_narrow_sat_u8 (CPUArchState *, uint64_t) { return 0; }
uint32_t helper_neon_narrow_sat_s8 (CPUArchState *, uint64_t) { return 0; }
uint32_t helper_neon_unarrow_sat16 (CPUArchState *, uint64_t) { return 0; }
uint32_t helper_neon_narrow_sat_u16 (CPUArchState *, uint64_t) { return 0; }
uint32_t helper_neon_narrow_sat_s16 (CPUArchState *, uint64_t) { return 0; }
uint32_t helper_neon_unarrow_sat32 (CPUArchState *, uint64_t) { return 0; }
uint32_t helper_neon_narrow_sat_u32 (CPUArchState *, uint64_t) { return 0; }
uint32_t helper_neon_narrow_sat_s32 (CPUArchState *, uint64_t) { return 0; }
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
uint64_t helper_neon_addl_saturate_s32 (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_neon_addl_saturate_s64 (CPUArchState *, uint64_t, uint64_t) { return 0; }
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
uint32_t helper_neon_qabs_s8 (CPUArchState *, uint32_t) { return 0; }
uint32_t helper_neon_qabs_s16 (CPUArchState *, uint32_t) { return 0; }
uint32_t helper_neon_qabs_s32 (CPUArchState *, uint32_t) { return 0; }
uint64_t helper_neon_qabs_s64 (CPUArchState *, uint64_t) { return 0; }
uint32_t helper_neon_qneg_s8 (CPUArchState *, uint32_t) { return 0; }
uint32_t helper_neon_qneg_s16 (CPUArchState *, uint32_t) { return 0; }
uint32_t helper_neon_qneg_s32 (CPUArchState *, uint32_t) { return 0; }
uint64_t helper_neon_qneg_s64 (CPUArchState *, uint64_t) { return 0; }
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
uint64_t helper_iwmmxt_unpacklb (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpacklw (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpackll (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpackhb (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpackhw (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpackhl (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpacklub (CPUArchState *, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpackluw (CPUArchState *, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpacklul (CPUArchState *, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpackhub (CPUArchState *, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpackhuw (CPUArchState *, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpackhul (CPUArchState *, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpacklsb (CPUArchState *, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpacklsw (CPUArchState *, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpacklsl (CPUArchState *, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpackhsb (CPUArchState *, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpackhsw (CPUArchState *, uint64_t) { return 0; }
uint64_t helper_iwmmxt_unpackhsl (CPUArchState *, uint64_t) { return 0; }
uint64_t helper_iwmmxt_cmpeqb (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_cmpeqw (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_cmpeql (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_cmpgtub (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_cmpgtuw (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_cmpgtul (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_cmpgtsb (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_cmpgtsw (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_cmpgtsl (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_minsb (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_minsw (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_minsl (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_minub (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_minuw (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_minul (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_maxsb (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_maxsw (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_maxsl (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_maxub (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_maxuw (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_maxul (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_subnb (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_subnw (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_subnl (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_addnb (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_addnw (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_addnl (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_subub (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_subuw (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_subul (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_addub (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_adduw (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_addul (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_subsb (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_subsw (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_subsl (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_addsb (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_addsw (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_addsl (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_avgb0 (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_avgb1 (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_avgw0 (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_avgw1 (CPUArchState *, uint64_t, uint64_t) { return 0; }
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
uint64_t helper_iwmmxt_srlw (CPUArchState *, uint64_t, uint32_t) { return 0; }
uint64_t helper_iwmmxt_srll (CPUArchState *, uint64_t, uint32_t) { return 0; }
uint64_t helper_iwmmxt_srlq (CPUArchState *, uint64_t, uint32_t) { return 0; }
uint64_t helper_iwmmxt_sllw (CPUArchState *, uint64_t, uint32_t) { return 0; }
uint64_t helper_iwmmxt_slll (CPUArchState *, uint64_t, uint32_t) { return 0; }
uint64_t helper_iwmmxt_sllq (CPUArchState *, uint64_t, uint32_t) { return 0; }
uint64_t helper_iwmmxt_sraw (CPUArchState *, uint64_t, uint32_t) { return 0; }
uint64_t helper_iwmmxt_sral (CPUArchState *, uint64_t, uint32_t) { return 0; }
uint64_t helper_iwmmxt_sraq (CPUArchState *, uint64_t, uint32_t) { return 0; }
uint64_t helper_iwmmxt_rorw (CPUArchState *, uint64_t, uint32_t) { return 0; }
uint64_t helper_iwmmxt_rorl (CPUArchState *, uint64_t, uint32_t) { return 0; }
uint64_t helper_iwmmxt_rorq (CPUArchState *, uint64_t, uint32_t) { return 0; }
uint64_t helper_iwmmxt_shufh (CPUArchState *, uint64_t, uint32_t) { return 0; }
uint64_t helper_iwmmxt_packuw (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_packul (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_packuq (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_packsw (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_packsl (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_packsq (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_iwmmxt_muladdsl (uint64_t, uint32_t, uint32_t) { return 0; }
uint64_t helper_iwmmxt_muladdsw (uint64_t, uint32_t, uint32_t) { return 0; }
uint64_t helper_iwmmxt_muladdswl (uint64_t, uint32_t, uint32_t) { return 0; }
void helper_neon_unzip8 (void *, void *) { return; }
void helper_neon_unzip16 (void *, void *) { return; }
void helper_neon_qunzip8 (void *, void *) { return; }
void helper_neon_qunzip16 (void *, void *) { return; }
void helper_neon_qunzip32 (void *, void *) { return; }
void helper_neon_zip8 (void *, void *) { return; }
void helper_neon_zip16 (void *, void *) { return; }
void helper_neon_qzip8 (void *, void *) { return; }
void helper_neon_qzip16 (void *, void *) { return; }
void helper_neon_qzip32 (void *, void *) { return; }
void helper_crypto_aese (void *, void *, uint32_t) { return; }
void helper_crypto_aesmc (void *, void *, uint32_t) { return; }
void helper_crypto_sha1_3reg (void *, void *, void *, uint32_t) { return; }
void helper_crypto_sha1h (void *, void *) { return; }
void helper_crypto_sha1su1 (void *, void *) { return; }
void helper_crypto_sha256h (void *, void *, void *) { return; }
void helper_crypto_sha256h2 (void *, void *, void *) { return; }
void helper_crypto_sha256su0 (void *, void *) { return; }
void helper_crypto_sha256su1 (void *, void *, void *) { return; }
void helper_crypto_sha512h (void *, void *, void *) { return; }
void helper_crypto_sha512h2 (void *, void *, void *) { return; }
void helper_crypto_sha512su0 (void *, void *) { return; }
void helper_crypto_sha512su1 (void *, void *, void *) { return; }
void helper_crypto_sm3tt (void *, void *, void *, uint32_t, uint32_t) { return; }
void helper_crypto_sm3partw1 (void *, void *, void *) { return; }
void helper_crypto_sm3partw2 (void *, void *, void *) { return; }
void helper_crypto_sm4e (void *, void *) { return; }
void helper_crypto_sm4ekey (void *, void *, void *) { return; }
uint32_t helper_crc32 (uint32_t, uint32_t, uint32_t) { return 0; }
uint32_t helper_crc32c (uint32_t, uint32_t, uint32_t) { return 0; }
void helper_dc_zva (CPUArchState *, uint64_t) { return; }
uint64_t helper_neon_pmull_64_lo (uint64_t, uint64_t) { return 0; }
uint64_t helper_neon_pmull_64_hi (uint64_t, uint64_t) { return 0; }
void helper_gvec_qrdmlah_s16 (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_qrdmlsh_s16 (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_qrdmlah_s32 (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_qrdmlsh_s32 (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_sdot_b (void *, void *, void *, uint32_t) { return; }
void helper_gvec_udot_b (void *, void *, void *, uint32_t) { return; }
void helper_gvec_sdot_h (void *, void *, void *, uint32_t) { return; }
void helper_gvec_udot_h (void *, void *, void *, uint32_t) { return; }
void helper_gvec_sdot_idx_b (void *, void *, void *, uint32_t) { return; }
void helper_gvec_udot_idx_b (void *, void *, void *, uint32_t) { return; }
void helper_gvec_sdot_idx_h (void *, void *, void *, uint32_t) { return; }
void helper_gvec_udot_idx_h (void *, void *, void *, uint32_t) { return; }
void helper_gvec_fcaddh (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_fcadds (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_fcaddd (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_fcmlah (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_fcmlah_idx (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_fcmlas (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_fcmlas_idx (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_fcmlad (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_frecpe_h (void *, void *, void *, uint32_t) { return; }
void helper_gvec_frecpe_s (void *, void *, void *, uint32_t) { return; }
void helper_gvec_frecpe_d (void *, void *, void *, uint32_t) { return; }
void helper_gvec_frsqrte_h (void *, void *, void *, uint32_t) { return; }
void helper_gvec_frsqrte_s (void *, void *, void *, uint32_t) { return; }
void helper_gvec_frsqrte_d (void *, void *, void *, uint32_t) { return; }
void helper_gvec_fadd_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_fadd_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_fadd_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_fsub_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_fsub_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_fsub_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_fmul_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_fmul_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_fmul_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_ftsmul_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_ftsmul_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_ftsmul_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_fmul_idx_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_fmul_idx_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_fmul_idx_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_fmla_idx_h (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_fmla_idx_s (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_fmla_idx_d (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_uqadd_b (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_uqadd_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_uqadd_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_uqadd_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_sqadd_b (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_sqadd_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_sqadd_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_sqadd_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_uqsub_b (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_uqsub_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_uqsub_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_uqsub_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_sqsub_b (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_sqsub_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_sqsub_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_sqsub_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_fmlal_a32 (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_fmlal_a64 (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_fmlal_idx_a32 (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_fmlal_idx_a64 (void *, void *, void *, void *, uint32_t) { return; }
float32 helper_frint32_s (float32, void *) { return (float32)0; }
float32 helper_frint64_s (float32, void *) { return (float32)0; }
float64 helper_frint32_d (float64, void *) { return (float64)0; }
float64 helper_frint64_d (float64, void *) { return (float64)0; }
uint64_t helper_udiv64 (uint64_t, uint64_t) { return 0; }
int64_t helper_sdiv64 (int64_t, int64_t) { return 0; }
uint64_t helper_rbit64 (uint64_t) { return 0; }
void helper_msr_i_spsel (CPUArchState *, uint32_t) { return; }
void helper_msr_i_daifset (CPUArchState *, uint32_t) { return; }
void helper_msr_i_daifclear (CPUArchState *, uint32_t) { return; }
uint64_t helper_vfp_cmph_a64 (uint32_t, uint32_t, void *) { return 0; }
uint64_t helper_vfp_cmpeh_a64 (uint32_t, uint32_t, void *) { return 0; }
uint64_t helper_vfp_cmps_a64 (float32, float32, void *) { return 0; }
uint64_t helper_vfp_cmpes_a64 (float32, float32, void *) { return 0; }
uint64_t helper_vfp_cmpd_a64 (float64, float64, void *) { return 0; }
uint64_t helper_vfp_cmped_a64 (float64, float64, void *) { return 0; }
uint64_t helper_simd_tbl (CPUArchState *, uint64_t, uint64_t, uint32_t, uint32_t) { return 0; }
float32 helper_vfp_mulxs (float32, float32, void *) { return (float32)0; }
float64 helper_vfp_mulxd (float64, float64, void *) { return (float64)0; }
uint64_t helper_neon_ceq_f64 (uint64_t, uint64_t, void *) { return 0; }
uint64_t helper_neon_cge_f64 (uint64_t, uint64_t, void *) { return 0; }
uint64_t helper_neon_cgt_f64 (uint64_t, uint64_t, void *) { return 0; }
uint32_t helper_recpsf_f16 (uint32_t, uint32_t, void *) { return 0; }
float32 helper_recpsf_f32 (float32, float32, void *) { return (float32)0; }
float64 helper_recpsf_f64 (float64, float64, void *) { return (float64)0; }
uint32_t helper_rsqrtsf_f16 (uint32_t, uint32_t, void *) { return 0; }
float32 helper_rsqrtsf_f32 (float32, float32, void *) { return (float32)0; }
float64 helper_rsqrtsf_f64 (float64, float64, void *) { return (float64)0; }
uint64_t helper_neon_addlp_s8 (uint64_t) { return 0; }
uint64_t helper_neon_addlp_u8 (uint64_t) { return 0; }
uint64_t helper_neon_addlp_s16 (uint64_t) { return 0; }
uint64_t helper_neon_addlp_u16 (uint64_t) { return 0; }
float64 helper_frecpx_f64 (float64, void *) { return (float64)0; }
float32 helper_frecpx_f32 (float32, void *) { return (float32)0; }
uint32_t helper_frecpx_f16 (uint32_t, void *) { return 0; }
float32 helper_fcvtx_f64_to_f32 (float64, CPUArchState *) { return (float32)0; }
uint64_t helper_crc32_64 (uint64_t, uint64_t, uint32_t) { return 0; }
uint64_t helper_crc32c_64 (uint64_t, uint64_t, uint32_t) { return 0; }
uint64_t helper_paired_cmpxchg64_le (CPUArchState *, uint64_t, uint64_t, uint64_t) { return 0; }
uint64_t helper_paired_cmpxchg64_le_parallel (CPUArchState *, uint64_t, uint64_t, uint64_t) { return 0; }
uint64_t helper_paired_cmpxchg64_be (CPUArchState *, uint64_t, uint64_t, uint64_t) { return 0; }
uint64_t helper_paired_cmpxchg64_be_parallel (CPUArchState *, uint64_t, uint64_t, uint64_t) { return 0; }
void helper_casp_le_parallel (CPUArchState *, uint32_t, uint64_t, uint64_t, uint64_t) { return; }
void helper_casp_be_parallel (CPUArchState *, uint32_t, uint64_t, uint64_t, uint64_t) { return; }
uint32_t helper_advsimd_maxh (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_advsimd_minh (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_advsimd_maxnumh (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_advsimd_minnumh (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_advsimd_addh (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_advsimd_subh (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_advsimd_mulh (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_advsimd_divh (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_advsimd_ceq_f16 (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_advsimd_cge_f16 (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_advsimd_cgt_f16 (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_advsimd_acge_f16 (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_advsimd_acgt_f16 (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_advsimd_mulxh (uint32_t, uint32_t, void *) { return 0; }
uint32_t helper_advsimd_muladdh (uint32_t, uint32_t, uint32_t, void *) { return 0; }
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
uint32_t helper_advsimd_rinth_exact (uint32_t, void *) { return 0; }
uint32_t helper_advsimd_rinth (uint32_t, void *) { return 0; }
uint32_t helper_advsimd_f16tosinth (uint32_t, void *) { return 0; }
uint32_t helper_advsimd_f16touinth (uint32_t, void *) { return 0; }
uint32_t helper_sqrt_f16 (uint32_t, void *) { return 0; }
void helper_exception_return (CPUArchState *, uint64_t) { return; }
uint64_t helper_pacia (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_pacib (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_pacda (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_pacdb (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_pacga (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_autia (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_autib (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_autda (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_autdb (CPUArchState *, uint64_t, uint64_t) { return 0; }
uint64_t helper_xpaci (CPUArchState *, uint64_t) { return 0; }
uint64_t helper_xpacd (CPUArchState *, uint64_t) { return 0; }
uint32_t helper_sve_predtest1 (uint64_t, uint64_t) { return 0; }
uint32_t helper_sve_predtest (void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_pfirst (void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_pnext (void *, void *, uint32_t) { return 0; }
void helper_sve_and_zpzz_b (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_and_zpzz_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_and_zpzz_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_and_zpzz_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_eor_zpzz_b (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_eor_zpzz_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_eor_zpzz_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_eor_zpzz_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_orr_zpzz_b (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_orr_zpzz_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_orr_zpzz_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_orr_zpzz_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_bic_zpzz_b (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_bic_zpzz_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_bic_zpzz_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_bic_zpzz_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_add_zpzz_b (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_add_zpzz_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_add_zpzz_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_add_zpzz_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_sub_zpzz_b (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_sub_zpzz_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_sub_zpzz_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_sub_zpzz_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_smax_zpzz_b (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_smax_zpzz_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_smax_zpzz_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_smax_zpzz_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_umax_zpzz_b (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_umax_zpzz_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_umax_zpzz_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_umax_zpzz_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_smin_zpzz_b (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_smin_zpzz_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_smin_zpzz_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_smin_zpzz_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_umin_zpzz_b (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_umin_zpzz_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_umin_zpzz_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_umin_zpzz_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_sabd_zpzz_b (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_sabd_zpzz_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_sabd_zpzz_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_sabd_zpzz_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_uabd_zpzz_b (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_uabd_zpzz_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_uabd_zpzz_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_uabd_zpzz_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_mul_zpzz_b (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_mul_zpzz_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_mul_zpzz_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_mul_zpzz_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_smulh_zpzz_b (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_smulh_zpzz_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_smulh_zpzz_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_smulh_zpzz_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_umulh_zpzz_b (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_umulh_zpzz_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_umulh_zpzz_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_umulh_zpzz_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_sdiv_zpzz_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_sdiv_zpzz_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_udiv_zpzz_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_udiv_zpzz_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_asr_zpzz_b (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_asr_zpzz_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_asr_zpzz_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_asr_zpzz_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_lsr_zpzz_b (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_lsr_zpzz_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_lsr_zpzz_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_lsr_zpzz_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_lsl_zpzz_b (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_lsl_zpzz_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_lsl_zpzz_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_lsl_zpzz_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_sel_zpzz_b (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_sel_zpzz_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_sel_zpzz_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_sel_zpzz_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_asr_zpzw_b (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_asr_zpzw_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_asr_zpzw_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_lsr_zpzw_b (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_lsr_zpzw_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_lsr_zpzw_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_lsl_zpzw_b (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_lsl_zpzw_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_lsl_zpzw_s (void *, void *, void *, void *, uint32_t) { return; }
uint64_t helper_sve_orv_b (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_orv_h (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_orv_s (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_orv_d (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_eorv_b (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_eorv_h (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_eorv_s (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_eorv_d (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_andv_b (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_andv_h (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_andv_s (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_andv_d (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_saddv_b (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_saddv_h (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_saddv_s (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_uaddv_b (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_uaddv_h (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_uaddv_s (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_uaddv_d (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_smaxv_b (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_smaxv_h (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_smaxv_s (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_smaxv_d (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_umaxv_b (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_umaxv_h (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_umaxv_s (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_umaxv_d (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_sminv_b (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_sminv_h (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_sminv_s (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_sminv_d (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_uminv_b (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_uminv_h (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_uminv_s (void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_uminv_d (void *, void *, uint32_t) { return 0; }
void helper_sve_clr_b (void *, void *, uint32_t) { return; }
void helper_sve_clr_h (void *, void *, uint32_t) { return; }
void helper_sve_clr_s (void *, void *, uint32_t) { return; }
void helper_sve_clr_d (void *, void *, uint32_t) { return; }
void helper_sve_movz_b (void *, void *, void *, uint32_t) { return; }
void helper_sve_movz_h (void *, void *, void *, uint32_t) { return; }
void helper_sve_movz_s (void *, void *, void *, uint32_t) { return; }
void helper_sve_movz_d (void *, void *, void *, uint32_t) { return; }
void helper_sve_asr_zpzi_b (void *, void *, void *, uint32_t) { return; }
void helper_sve_asr_zpzi_h (void *, void *, void *, uint32_t) { return; }
void helper_sve_asr_zpzi_s (void *, void *, void *, uint32_t) { return; }
void helper_sve_asr_zpzi_d (void *, void *, void *, uint32_t) { return; }
void helper_sve_lsr_zpzi_b (void *, void *, void *, uint32_t) { return; }
void helper_sve_lsr_zpzi_h (void *, void *, void *, uint32_t) { return; }
void helper_sve_lsr_zpzi_s (void *, void *, void *, uint32_t) { return; }
void helper_sve_lsr_zpzi_d (void *, void *, void *, uint32_t) { return; }
void helper_sve_lsl_zpzi_b (void *, void *, void *, uint32_t) { return; }
void helper_sve_lsl_zpzi_h (void *, void *, void *, uint32_t) { return; }
void helper_sve_lsl_zpzi_s (void *, void *, void *, uint32_t) { return; }
void helper_sve_lsl_zpzi_d (void *, void *, void *, uint32_t) { return; }
void helper_sve_asrd_b (void *, void *, void *, uint32_t) { return; }
void helper_sve_asrd_h (void *, void *, void *, uint32_t) { return; }
void helper_sve_asrd_s (void *, void *, void *, uint32_t) { return; }
void helper_sve_asrd_d (void *, void *, void *, uint32_t) { return; }
void helper_sve_cls_b (void *, void *, void *, uint32_t) { return; }
void helper_sve_cls_h (void *, void *, void *, uint32_t) { return; }
void helper_sve_cls_s (void *, void *, void *, uint32_t) { return; }
void helper_sve_cls_d (void *, void *, void *, uint32_t) { return; }
void helper_sve_clz_b (void *, void *, void *, uint32_t) { return; }
void helper_sve_clz_h (void *, void *, void *, uint32_t) { return; }
void helper_sve_clz_s (void *, void *, void *, uint32_t) { return; }
void helper_sve_clz_d (void *, void *, void *, uint32_t) { return; }
void helper_sve_cnt_zpz_b (void *, void *, void *, uint32_t) { return; }
void helper_sve_cnt_zpz_h (void *, void *, void *, uint32_t) { return; }
void helper_sve_cnt_zpz_s (void *, void *, void *, uint32_t) { return; }
void helper_sve_cnt_zpz_d (void *, void *, void *, uint32_t) { return; }
void helper_sve_cnot_b (void *, void *, void *, uint32_t) { return; }
void helper_sve_cnot_h (void *, void *, void *, uint32_t) { return; }
void helper_sve_cnot_s (void *, void *, void *, uint32_t) { return; }
void helper_sve_cnot_d (void *, void *, void *, uint32_t) { return; }
void helper_sve_fabs_h (void *, void *, void *, uint32_t) { return; }
void helper_sve_fabs_s (void *, void *, void *, uint32_t) { return; }
void helper_sve_fabs_d (void *, void *, void *, uint32_t) { return; }
void helper_sve_fneg_h (void *, void *, void *, uint32_t) { return; }
void helper_sve_fneg_s (void *, void *, void *, uint32_t) { return; }
void helper_sve_fneg_d (void *, void *, void *, uint32_t) { return; }
void helper_sve_not_zpz_b (void *, void *, void *, uint32_t) { return; }
void helper_sve_not_zpz_h (void *, void *, void *, uint32_t) { return; }
void helper_sve_not_zpz_s (void *, void *, void *, uint32_t) { return; }
void helper_sve_not_zpz_d (void *, void *, void *, uint32_t) { return; }
void helper_sve_sxtb_h (void *, void *, void *, uint32_t) { return; }
void helper_sve_sxtb_s (void *, void *, void *, uint32_t) { return; }
void helper_sve_sxtb_d (void *, void *, void *, uint32_t) { return; }
void helper_sve_uxtb_h (void *, void *, void *, uint32_t) { return; }
void helper_sve_uxtb_s (void *, void *, void *, uint32_t) { return; }
void helper_sve_uxtb_d (void *, void *, void *, uint32_t) { return; }
void helper_sve_sxth_s (void *, void *, void *, uint32_t) { return; }
void helper_sve_sxth_d (void *, void *, void *, uint32_t) { return; }
void helper_sve_uxth_s (void *, void *, void *, uint32_t) { return; }
void helper_sve_uxth_d (void *, void *, void *, uint32_t) { return; }
void helper_sve_sxtw_d (void *, void *, void *, uint32_t) { return; }
void helper_sve_uxtw_d (void *, void *, void *, uint32_t) { return; }
void helper_sve_abs_b (void *, void *, void *, uint32_t) { return; }
void helper_sve_abs_h (void *, void *, void *, uint32_t) { return; }
void helper_sve_abs_s (void *, void *, void *, uint32_t) { return; }
void helper_sve_abs_d (void *, void *, void *, uint32_t) { return; }
void helper_sve_neg_b (void *, void *, void *, uint32_t) { return; }
void helper_sve_neg_h (void *, void *, void *, uint32_t) { return; }
void helper_sve_neg_s (void *, void *, void *, uint32_t) { return; }
void helper_sve_neg_d (void *, void *, void *, uint32_t) { return; }
void helper_sve_mla_b (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_mla_h (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_mla_s (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_mla_d (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_mls_b (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_mls_h (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_mls_s (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_mls_d (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_index_b (void *, uint32_t, uint32_t, uint32_t) { return; }
void helper_sve_index_h (void *, uint32_t, uint32_t, uint32_t) { return; }
void helper_sve_index_s (void *, uint32_t, uint32_t, uint32_t) { return; }
void helper_sve_index_d (void *, uint64_t, uint64_t, uint32_t) { return; }
void helper_sve_asr_zzw_b (void *, void *, void *, uint32_t) { return; }
void helper_sve_asr_zzw_h (void *, void *, void *, uint32_t) { return; }
void helper_sve_asr_zzw_s (void *, void *, void *, uint32_t) { return; }
void helper_sve_lsr_zzw_b (void *, void *, void *, uint32_t) { return; }
void helper_sve_lsr_zzw_h (void *, void *, void *, uint32_t) { return; }
void helper_sve_lsr_zzw_s (void *, void *, void *, uint32_t) { return; }
void helper_sve_lsl_zzw_b (void *, void *, void *, uint32_t) { return; }
void helper_sve_lsl_zzw_h (void *, void *, void *, uint32_t) { return; }
void helper_sve_lsl_zzw_s (void *, void *, void *, uint32_t) { return; }
void helper_sve_adr_p32 (void *, void *, void *, uint32_t) { return; }
void helper_sve_adr_p64 (void *, void *, void *, uint32_t) { return; }
void helper_sve_adr_s32 (void *, void *, void *, uint32_t) { return; }
void helper_sve_adr_u32 (void *, void *, void *, uint32_t) { return; }
void helper_sve_fexpa_h (void *, void *, uint32_t) { return; }
void helper_sve_fexpa_s (void *, void *, uint32_t) { return; }
void helper_sve_fexpa_d (void *, void *, uint32_t) { return; }
void helper_sve_ftssel_h (void *, void *, void *, uint32_t) { return; }
void helper_sve_ftssel_s (void *, void *, void *, uint32_t) { return; }
void helper_sve_ftssel_d (void *, void *, void *, uint32_t) { return; }
void helper_sve_sqaddi_b (void *, void *, int32_t, uint32_t) { return; }
void helper_sve_sqaddi_h (void *, void *, int32_t, uint32_t) { return; }
void helper_sve_sqaddi_s (void *, void *, int64_t, uint32_t) { return; }
void helper_sve_sqaddi_d (void *, void *, int64_t, uint32_t) { return; }
void helper_sve_uqaddi_b (void *, void *, int32_t, uint32_t) { return; }
void helper_sve_uqaddi_h (void *, void *, int32_t, uint32_t) { return; }
void helper_sve_uqaddi_s (void *, void *, int64_t, uint32_t) { return; }
void helper_sve_uqaddi_d (void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_uqsubi_d (void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_cpy_m_b (void *, void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_cpy_m_h (void *, void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_cpy_m_s (void *, void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_cpy_m_d (void *, void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_cpy_z_b (void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_cpy_z_h (void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_cpy_z_s (void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_cpy_z_d (void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_ext (void *, void *, void *, uint32_t) { return; }
void helper_sve_insr_b (void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_insr_h (void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_insr_s (void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_insr_d (void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_rev_b (void *, void *, uint32_t) { return; }
void helper_sve_rev_h (void *, void *, uint32_t) { return; }
void helper_sve_rev_s (void *, void *, uint32_t) { return; }
void helper_sve_rev_d (void *, void *, uint32_t) { return; }
void helper_sve_tbl_b (void *, void *, void *, uint32_t) { return; }
void helper_sve_tbl_h (void *, void *, void *, uint32_t) { return; }
void helper_sve_tbl_s (void *, void *, void *, uint32_t) { return; }
void helper_sve_tbl_d (void *, void *, void *, uint32_t) { return; }
void helper_sve_sunpk_h (void *, void *, uint32_t) { return; }
void helper_sve_sunpk_s (void *, void *, uint32_t) { return; }
void helper_sve_sunpk_d (void *, void *, uint32_t) { return; }
void helper_sve_uunpk_h (void *, void *, uint32_t) { return; }
void helper_sve_uunpk_s (void *, void *, uint32_t) { return; }
void helper_sve_uunpk_d (void *, void *, uint32_t) { return; }
void helper_sve_zip_p (void *, void *, void *, uint32_t) { return; }
void helper_sve_uzp_p (void *, void *, void *, uint32_t) { return; }
void helper_sve_trn_p (void *, void *, void *, uint32_t) { return; }
void helper_sve_rev_p (void *, void *, uint32_t) { return; }
void helper_sve_punpk_p (void *, void *, uint32_t) { return; }
void helper_sve_zip_b (void *, void *, void *, uint32_t) { return; }
void helper_sve_zip_h (void *, void *, void *, uint32_t) { return; }
void helper_sve_zip_s (void *, void *, void *, uint32_t) { return; }
void helper_sve_zip_d (void *, void *, void *, uint32_t) { return; }
void helper_sve_uzp_b (void *, void *, void *, uint32_t) { return; }
void helper_sve_uzp_h (void *, void *, void *, uint32_t) { return; }
void helper_sve_uzp_s (void *, void *, void *, uint32_t) { return; }
void helper_sve_uzp_d (void *, void *, void *, uint32_t) { return; }
void helper_sve_trn_b (void *, void *, void *, uint32_t) { return; }
void helper_sve_trn_h (void *, void *, void *, uint32_t) { return; }
void helper_sve_trn_s (void *, void *, void *, uint32_t) { return; }
void helper_sve_trn_d (void *, void *, void *, uint32_t) { return; }
void helper_sve_compact_s (void *, void *, void *, uint32_t) { return; }
void helper_sve_compact_d (void *, void *, void *, uint32_t) { return; }
int32_t helper_sve_last_active_element (void *, uint32_t) { return 0; }
void helper_sve_revb_h (void *, void *, void *, uint32_t) { return; }
void helper_sve_revb_s (void *, void *, void *, uint32_t) { return; }
void helper_sve_revb_d (void *, void *, void *, uint32_t) { return; }
void helper_sve_revh_s (void *, void *, void *, uint32_t) { return; }
void helper_sve_revh_d (void *, void *, void *, uint32_t) { return; }
void helper_sve_revw_d (void *, void *, void *, uint32_t) { return; }
void helper_sve_rbit_b (void *, void *, void *, uint32_t) { return; }
void helper_sve_rbit_h (void *, void *, void *, uint32_t) { return; }
void helper_sve_rbit_s (void *, void *, void *, uint32_t) { return; }
void helper_sve_rbit_d (void *, void *, void *, uint32_t) { return; }
void helper_sve_splice (void *, void *, void *, void *, uint32_t) { return; }
uint32_t helper_sve_cmpeq_ppzz_b (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpne_ppzz_b (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpge_ppzz_b (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpgt_ppzz_b (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmphi_ppzz_b (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmphs_ppzz_b (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpeq_ppzz_h (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpne_ppzz_h (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpge_ppzz_h (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpgt_ppzz_h (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmphi_ppzz_h (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmphs_ppzz_h (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpeq_ppzz_s (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpne_ppzz_s (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpge_ppzz_s (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpgt_ppzz_s (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmphi_ppzz_s (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmphs_ppzz_s (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpeq_ppzz_d (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpne_ppzz_d (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpge_ppzz_d (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpgt_ppzz_d (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmphi_ppzz_d (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmphs_ppzz_d (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpeq_ppzw_b (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpne_ppzw_b (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpge_ppzw_b (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpgt_ppzw_b (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmphi_ppzw_b (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmphs_ppzw_b (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmple_ppzw_b (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmplt_ppzw_b (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmplo_ppzw_b (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpls_ppzw_b (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpeq_ppzw_h (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpne_ppzw_h (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpge_ppzw_h (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpgt_ppzw_h (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmphi_ppzw_h (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmphs_ppzw_h (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmple_ppzw_h (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmplt_ppzw_h (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmplo_ppzw_h (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpls_ppzw_h (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpeq_ppzw_s (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpne_ppzw_s (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpge_ppzw_s (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpgt_ppzw_s (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmphi_ppzw_s (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmphs_ppzw_s (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmple_ppzw_s (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmplt_ppzw_s (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmplo_ppzw_s (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpls_ppzw_s (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpeq_ppzi_b (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpne_ppzi_b (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpgt_ppzi_b (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpge_ppzi_b (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmplt_ppzi_b (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmple_ppzi_b (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmphs_ppzi_b (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmphi_ppzi_b (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmplo_ppzi_b (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpls_ppzi_b (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpeq_ppzi_h (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpne_ppzi_h (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpgt_ppzi_h (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpge_ppzi_h (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmplt_ppzi_h (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmple_ppzi_h (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmphs_ppzi_h (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmphi_ppzi_h (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmplo_ppzi_h (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpls_ppzi_h (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpeq_ppzi_s (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpne_ppzi_s (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpgt_ppzi_s (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpge_ppzi_s (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmplt_ppzi_s (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmple_ppzi_s (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmphs_ppzi_s (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmphi_ppzi_s (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmplo_ppzi_s (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpls_ppzi_s (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpeq_ppzi_d (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpne_ppzi_d (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpgt_ppzi_d (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpge_ppzi_d (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmplt_ppzi_d (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmple_ppzi_d (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmphs_ppzi_d (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmphi_ppzi_d (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmplo_ppzi_d (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_cmpls_ppzi_d (void *, void *, void *, uint32_t) { return 0; }
void helper_sve_and_pppp (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_bic_pppp (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_eor_pppp (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_sel_pppp (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_orr_pppp (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_orn_pppp (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_nor_pppp (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_nand_pppp (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_brkpa (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_brkpb (void *, void *, void *, void *, uint32_t) { return; }
uint32_t helper_sve_brkpas (void *, void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_brkpbs (void *, void *, void *, void *, uint32_t) { return 0; }
void helper_sve_brka_z (void *, void *, void *, uint32_t) { return; }
void helper_sve_brkb_z (void *, void *, void *, uint32_t) { return; }
void helper_sve_brka_m (void *, void *, void *, uint32_t) { return; }
void helper_sve_brkb_m (void *, void *, void *, uint32_t) { return; }
uint32_t helper_sve_brkas_z (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_brkbs_z (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_brkas_m (void *, void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_brkbs_m (void *, void *, void *, uint32_t) { return 0; }
void helper_sve_brkn (void *, void *, void *, uint32_t) { return; }
uint32_t helper_sve_brkns (void *, void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_cntp (void *, void *, uint32_t) { return 0; }
uint32_t helper_sve_while (void *, uint32_t, uint32_t) { return 0; }
void helper_sve_subri_b (void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_subri_h (void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_subri_s (void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_subri_d (void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_smaxi_b (void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_smaxi_h (void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_smaxi_s (void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_smaxi_d (void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_smini_b (void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_smini_h (void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_smini_s (void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_smini_d (void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_umaxi_b (void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_umaxi_h (void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_umaxi_s (void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_umaxi_d (void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_umini_b (void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_umini_h (void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_umini_s (void *, void *, uint64_t, uint32_t) { return; }
void helper_sve_umini_d (void *, void *, uint64_t, uint32_t) { return; }
void helper_gvec_recps_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_recps_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_recps_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_rsqrts_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_rsqrts_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_gvec_rsqrts_d (void *, void *, void *, void *, uint32_t) { return; }
uint64_t helper_sve_faddv_h (void *, void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_faddv_s (void *, void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_faddv_d (void *, void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_fmaxnmv_h (void *, void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_fmaxnmv_s (void *, void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_fmaxnmv_d (void *, void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_fminnmv_h (void *, void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_fminnmv_s (void *, void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_fminnmv_d (void *, void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_fmaxv_h (void *, void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_fmaxv_s (void *, void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_fmaxv_d (void *, void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_fminv_h (void *, void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_fminv_s (void *, void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_fminv_d (void *, void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_fadda_h (uint64_t, void *, void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_fadda_s (uint64_t, void *, void *, void *, uint32_t) { return 0; }
uint64_t helper_sve_fadda_d (uint64_t, void *, void *, void *, uint32_t) { return 0; }
void helper_sve_fcmge0_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcmge0_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcmge0_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcmgt0_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcmgt0_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcmgt0_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcmlt0_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcmlt0_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcmlt0_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcmle0_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcmle0_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcmle0_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcmeq0_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcmeq0_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcmeq0_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcmne0_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcmne0_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcmne0_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fadd_h (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fadd_s (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fadd_d (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fsub_h (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fsub_s (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fsub_d (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fmul_h (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fmul_s (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fmul_d (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fdiv_h (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fdiv_s (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fdiv_d (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fmin_h (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fmin_s (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fmin_d (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fmax_h (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fmax_s (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fmax_d (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fminnum_h (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fminnum_s (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fminnum_d (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fmaxnum_h (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fmaxnum_s (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fmaxnum_d (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fabd_h (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fabd_s (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fabd_d (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fscalbn_h (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fscalbn_s (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fscalbn_d (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fmulx_h (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fmulx_s (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fmulx_d (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fadds_h (void *, void *, void *, uint64_t, void *, uint32_t) { return; }
void helper_sve_fadds_s (void *, void *, void *, uint64_t, void *, uint32_t) { return; }
void helper_sve_fadds_d (void *, void *, void *, uint64_t, void *, uint32_t) { return; }
void helper_sve_fsubs_h (void *, void *, void *, uint64_t, void *, uint32_t) { return; }
void helper_sve_fsubs_s (void *, void *, void *, uint64_t, void *, uint32_t) { return; }
void helper_sve_fsubs_d (void *, void *, void *, uint64_t, void *, uint32_t) { return; }
void helper_sve_fmuls_h (void *, void *, void *, uint64_t, void *, uint32_t) { return; }
void helper_sve_fmuls_s (void *, void *, void *, uint64_t, void *, uint32_t) { return; }
void helper_sve_fmuls_d (void *, void *, void *, uint64_t, void *, uint32_t) { return; }
void helper_sve_fsubrs_h (void *, void *, void *, uint64_t, void *, uint32_t) { return; }
void helper_sve_fsubrs_s (void *, void *, void *, uint64_t, void *, uint32_t) { return; }
void helper_sve_fsubrs_d (void *, void *, void *, uint64_t, void *, uint32_t) { return; }
void helper_sve_fmaxnms_h (void *, void *, void *, uint64_t, void *, uint32_t) { return; }
void helper_sve_fmaxnms_s (void *, void *, void *, uint64_t, void *, uint32_t) { return; }
void helper_sve_fmaxnms_d (void *, void *, void *, uint64_t, void *, uint32_t) { return; }
void helper_sve_fminnms_h (void *, void *, void *, uint64_t, void *, uint32_t) { return; }
void helper_sve_fminnms_s (void *, void *, void *, uint64_t, void *, uint32_t) { return; }
void helper_sve_fminnms_d (void *, void *, void *, uint64_t, void *, uint32_t) { return; }
void helper_sve_fmaxs_h (void *, void *, void *, uint64_t, void *, uint32_t) { return; }
void helper_sve_fmaxs_s (void *, void *, void *, uint64_t, void *, uint32_t) { return; }
void helper_sve_fmaxs_d (void *, void *, void *, uint64_t, void *, uint32_t) { return; }
void helper_sve_fmins_h (void *, void *, void *, uint64_t, void *, uint32_t) { return; }
void helper_sve_fmins_s (void *, void *, void *, uint64_t, void *, uint32_t) { return; }
void helper_sve_fmins_d (void *, void *, void *, uint64_t, void *, uint32_t) { return; }
void helper_sve_fcvt_sh (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcvt_dh (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcvt_hs (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcvt_ds (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcvt_hd (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcvt_sd (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcvtzs_hh (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcvtzs_hs (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcvtzs_ss (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcvtzs_ds (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcvtzs_hd (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcvtzs_sd (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcvtzs_dd (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcvtzu_hh (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcvtzu_hs (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcvtzu_ss (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcvtzu_ds (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcvtzu_hd (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcvtzu_sd (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcvtzu_dd (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_frint_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_frint_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_frint_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_frintx_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_frintx_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_frintx_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_frecpx_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_frecpx_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_frecpx_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fsqrt_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fsqrt_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fsqrt_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_scvt_hh (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_scvt_sh (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_scvt_dh (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_scvt_ss (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_scvt_sd (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_scvt_ds (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_scvt_dd (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_ucvt_hh (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_ucvt_sh (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_ucvt_dh (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_ucvt_ss (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_ucvt_sd (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_ucvt_ds (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_ucvt_dd (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcmge_h (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcmge_s (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcmge_d (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcmgt_h (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcmgt_s (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcmgt_d (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcmeq_h (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcmeq_s (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcmeq_d (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcmne_h (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcmne_s (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcmne_d (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcmuo_h (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcmuo_s (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcmuo_d (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_facge_h (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_facge_s (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_facge_d (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_facgt_h (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_facgt_s (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_facgt_d (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcadd_h (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcadd_s (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fcadd_d (void *, void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_fmla_zpzzz_h (CPUArchState *, void *, uint32_t) { return; }
void helper_sve_fmla_zpzzz_s (CPUArchState *, void *, uint32_t) { return; }
void helper_sve_fmla_zpzzz_d (CPUArchState *, void *, uint32_t) { return; }
void helper_sve_fmls_zpzzz_h (CPUArchState *, void *, uint32_t) { return; }
void helper_sve_fmls_zpzzz_s (CPUArchState *, void *, uint32_t) { return; }
void helper_sve_fmls_zpzzz_d (CPUArchState *, void *, uint32_t) { return; }
void helper_sve_fnmla_zpzzz_h (CPUArchState *, void *, uint32_t) { return; }
void helper_sve_fnmla_zpzzz_s (CPUArchState *, void *, uint32_t) { return; }
void helper_sve_fnmla_zpzzz_d (CPUArchState *, void *, uint32_t) { return; }
void helper_sve_fnmls_zpzzz_h (CPUArchState *, void *, uint32_t) { return; }
void helper_sve_fnmls_zpzzz_s (CPUArchState *, void *, uint32_t) { return; }
void helper_sve_fnmls_zpzzz_d (CPUArchState *, void *, uint32_t) { return; }
void helper_sve_fcmla_zpzzz_h (CPUArchState *, void *, uint32_t) { return; }
void helper_sve_fcmla_zpzzz_s (CPUArchState *, void *, uint32_t) { return; }
void helper_sve_fcmla_zpzzz_d (CPUArchState *, void *, uint32_t) { return; }
void helper_sve_ftmad_h (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_ftmad_s (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_ftmad_d (void *, void *, void *, void *, uint32_t) { return; }
void helper_sve_ld1bb_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld2bb_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld3bb_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld4bb_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld1hh_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld2hh_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld3hh_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld4hh_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld1hh_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld2hh_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld3hh_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld4hh_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld1ss_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld2ss_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld3ss_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld4ss_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld1ss_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld2ss_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld3ss_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld4ss_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld1dd_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld2dd_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld3dd_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld4dd_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld1dd_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld2dd_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld3dd_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld4dd_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld1bhu_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld1bsu_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld1bdu_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld1bhs_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld1bss_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld1bds_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld1hsu_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld1hdu_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld1hss_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld1hds_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld1hsu_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld1hdu_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld1hss_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld1hds_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld1sdu_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld1sds_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld1sdu_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ld1sds_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldff1bb_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldff1bhu_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldff1bsu_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldff1bdu_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldff1bhs_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldff1bss_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldff1bds_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldff1hh_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldff1hsu_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldff1hdu_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldff1hss_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldff1hds_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldff1hh_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldff1hsu_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldff1hdu_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldff1hss_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldff1hds_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldff1ss_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldff1sdu_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldff1sds_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldff1ss_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldff1sdu_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldff1sds_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldff1dd_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldff1dd_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldnf1bb_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldnf1bhu_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldnf1bsu_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldnf1bdu_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldnf1bhs_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldnf1bss_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldnf1bds_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldnf1hh_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldnf1hsu_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldnf1hdu_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldnf1hss_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldnf1hds_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldnf1hh_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldnf1hsu_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldnf1hdu_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldnf1hss_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldnf1hds_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldnf1ss_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldnf1sdu_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldnf1sds_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldnf1ss_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldnf1sdu_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldnf1sds_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldnf1dd_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldnf1dd_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st1bb_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st2bb_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st3bb_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st4bb_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st1hh_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st2hh_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st3hh_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st4hh_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st1hh_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st2hh_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st3hh_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st4hh_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st1ss_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st2ss_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st3ss_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st4ss_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st1ss_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st2ss_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st3ss_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st4ss_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st1dd_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st2dd_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st3dd_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st4dd_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st1dd_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st2dd_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st3dd_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st4dd_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st1bh_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st1bs_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st1bd_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st1hs_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st1hd_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st1hs_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st1hd_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st1sd_le_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_st1sd_be_r (CPUArchState *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldbsu_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldhsu_le_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldhsu_be_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldss_le_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldss_be_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldbss_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldhss_le_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldhss_be_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldbsu_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldhsu_le_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldhsu_be_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldss_le_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldss_be_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldbss_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldhss_le_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldhss_be_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldbdu_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldhdu_le_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldhdu_be_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldsdu_le_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldsdu_be_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_lddd_le_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_lddd_be_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldbds_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldhds_le_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldhds_be_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldsds_le_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldsds_be_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldbdu_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldhdu_le_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldhdu_be_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldsdu_le_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldsdu_be_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_lddd_le_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_lddd_be_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldbds_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldhds_le_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldhds_be_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldsds_le_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldsds_be_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldbdu_zd (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldhdu_le_zd (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldhdu_be_zd (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldsdu_le_zd (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldsdu_be_zd (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_lddd_le_zd (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_lddd_be_zd (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldbds_zd (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldhds_le_zd (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldhds_be_zd (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldsds_le_zd (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldsds_be_zd (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffbsu_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffhsu_le_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffhsu_be_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffss_le_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffss_be_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffbss_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffhss_le_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffhss_be_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffbsu_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffhsu_le_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffhsu_be_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffss_le_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffss_be_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffbss_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffhss_le_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffhss_be_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffbdu_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffhdu_le_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffhdu_be_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffsdu_le_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffsdu_be_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffdd_le_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffdd_be_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffbds_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffhds_le_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffhds_be_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffsds_le_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffsds_be_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffbdu_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffhdu_le_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffhdu_be_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffsdu_le_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffsdu_be_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffdd_le_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffdd_be_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffbds_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffhds_le_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffhds_be_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffsds_le_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffsds_be_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffbdu_zd (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffhdu_le_zd (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffhdu_be_zd (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffsdu_le_zd (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffsdu_be_zd (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffdd_le_zd (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffdd_be_zd (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffbds_zd (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffhds_le_zd (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffhds_be_zd (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffsds_le_zd (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_ldffsds_be_zd (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_stbs_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_sths_le_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_sths_be_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_stss_le_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_stss_be_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_stbs_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_sths_le_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_sths_be_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_stss_le_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_stss_be_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_stbd_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_sthd_le_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_sthd_be_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_stsd_le_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_stsd_be_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_stdd_le_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_stdd_be_zsu (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_stbd_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_sthd_le_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_sthd_be_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_stsd_le_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_stsd_be_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_stdd_le_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_stdd_be_zss (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_stbd_zd (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_sthd_le_zd (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_sthd_be_zd (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_stsd_le_zd (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_stsd_be_zd (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_stdd_le_zd (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_sve_stdd_be_zd (CPUArchState *, void *, void *, void *, target_ulong, uint32_t) { return; }
void helper_trace_guest_mem_before_exec_proxy (CPUArchState *, target_ulong, uint32_t) { return; }
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
void * helper_lookup_tb_ptr (CPUArchState *) { return (void *)0; }
void helper_exit_atomic (CPUArchState *) { __builtin_trap(); __builtin_unreachable(); }
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
void helper_gvec_mov (void *, void *, uint32_t) { return; }
void helper_gvec_dup8 (void *, uint32_t, uint32_t) { return; }
void helper_gvec_dup16 (void *, uint32_t, uint32_t) { return; }
void helper_gvec_dup32 (void *, uint32_t, uint32_t) { return; }
void helper_gvec_dup64 (void *, uint32_t, uint64_t) { return; }
void helper_gvec_add8 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_add16 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_add32 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_add64 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_adds8 (void *, void *, uint64_t, uint32_t) { return; }
void helper_gvec_adds16 (void *, void *, uint64_t, uint32_t) { return; }
void helper_gvec_adds32 (void *, void *, uint64_t, uint32_t) { return; }
void helper_gvec_adds64 (void *, void *, uint64_t, uint32_t) { return; }
void helper_gvec_sub8 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_sub16 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_sub32 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_sub64 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_subs8 (void *, void *, uint64_t, uint32_t) { return; }
void helper_gvec_subs16 (void *, void *, uint64_t, uint32_t) { return; }
void helper_gvec_subs32 (void *, void *, uint64_t, uint32_t) { return; }
void helper_gvec_subs64 (void *, void *, uint64_t, uint32_t) { return; }
void helper_gvec_mul8 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_mul16 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_mul32 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_mul64 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_muls8 (void *, void *, uint64_t, uint32_t) { return; }
void helper_gvec_muls16 (void *, void *, uint64_t, uint32_t) { return; }
void helper_gvec_muls32 (void *, void *, uint64_t, uint32_t) { return; }
void helper_gvec_muls64 (void *, void *, uint64_t, uint32_t) { return; }
void helper_gvec_ssadd8 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_ssadd16 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_ssadd32 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_ssadd64 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_sssub8 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_sssub16 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_sssub32 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_sssub64 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_usadd8 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_usadd16 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_usadd32 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_usadd64 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_ussub8 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_ussub16 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_ussub32 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_ussub64 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_smin8 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_smin16 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_smin32 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_smin64 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_smax8 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_smax16 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_smax32 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_smax64 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_umin8 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_umin16 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_umin32 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_umin64 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_umax8 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_umax16 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_umax32 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_umax64 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_neg8 (void *, void *, uint32_t) { return; }
void helper_gvec_neg16 (void *, void *, uint32_t) { return; }
void helper_gvec_neg32 (void *, void *, uint32_t) { return; }
void helper_gvec_neg64 (void *, void *, uint32_t) { return; }
void helper_gvec_abs8 (void *, void *, uint32_t) { return; }
void helper_gvec_abs16 (void *, void *, uint32_t) { return; }
void helper_gvec_abs32 (void *, void *, uint32_t) { return; }
void helper_gvec_abs64 (void *, void *, uint32_t) { return; }
void helper_gvec_not (void *, void *, uint32_t) { return; }
void helper_gvec_and (void *, void *, void *, uint32_t) { return; }
void helper_gvec_or (void *, void *, void *, uint32_t) { return; }
void helper_gvec_xor (void *, void *, void *, uint32_t) { return; }
void helper_gvec_andc (void *, void *, void *, uint32_t) { return; }
void helper_gvec_orc (void *, void *, void *, uint32_t) { return; }
void helper_gvec_nand (void *, void *, void *, uint32_t) { return; }
void helper_gvec_nor (void *, void *, void *, uint32_t) { return; }
void helper_gvec_eqv (void *, void *, void *, uint32_t) { return; }
void helper_gvec_ands (void *, void *, uint64_t, uint32_t) { return; }
void helper_gvec_xors (void *, void *, uint64_t, uint32_t) { return; }
void helper_gvec_ors (void *, void *, uint64_t, uint32_t) { return; }
void helper_gvec_shl8i (void *, void *, uint32_t) { return; }
void helper_gvec_shl16i (void *, void *, uint32_t) { return; }
void helper_gvec_shl32i (void *, void *, uint32_t) { return; }
void helper_gvec_shl64i (void *, void *, uint32_t) { return; }
void helper_gvec_shr8i (void *, void *, uint32_t) { return; }
void helper_gvec_shr16i (void *, void *, uint32_t) { return; }
void helper_gvec_shr32i (void *, void *, uint32_t) { return; }
void helper_gvec_shr64i (void *, void *, uint32_t) { return; }
void helper_gvec_sar8i (void *, void *, uint32_t) { return; }
void helper_gvec_sar16i (void *, void *, uint32_t) { return; }
void helper_gvec_sar32i (void *, void *, uint32_t) { return; }
void helper_gvec_sar64i (void *, void *, uint32_t) { return; }
void helper_gvec_shl8v (void *, void *, void *, uint32_t) { return; }
void helper_gvec_shl16v (void *, void *, void *, uint32_t) { return; }
void helper_gvec_shl32v (void *, void *, void *, uint32_t) { return; }
void helper_gvec_shl64v (void *, void *, void *, uint32_t) { return; }
void helper_gvec_shr8v (void *, void *, void *, uint32_t) { return; }
void helper_gvec_shr16v (void *, void *, void *, uint32_t) { return; }
void helper_gvec_shr32v (void *, void *, void *, uint32_t) { return; }
void helper_gvec_shr64v (void *, void *, void *, uint32_t) { return; }
void helper_gvec_sar8v (void *, void *, void *, uint32_t) { return; }
void helper_gvec_sar16v (void *, void *, void *, uint32_t) { return; }
void helper_gvec_sar32v (void *, void *, void *, uint32_t) { return; }
void helper_gvec_sar64v (void *, void *, void *, uint32_t) { return; }
void helper_gvec_eq8 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_eq16 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_eq32 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_eq64 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_ne8 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_ne16 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_ne32 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_ne64 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_lt8 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_lt16 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_lt32 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_lt64 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_le8 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_le16 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_le32 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_le64 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_ltu8 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_ltu16 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_ltu32 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_ltu64 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_leu8 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_leu16 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_leu32 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_leu64 (void *, void *, void *, uint32_t) { return; }
void helper_gvec_bitsel (void *, void *, void *, void *, uint32_t) { return; }
