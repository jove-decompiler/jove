#undef R_386_PC32 /* XXX */
#undef R_386_PC8  /* XXX */
#undef R_386_32   /* XXX */

target_ulong helper_cc_compute_all (target_ulong, target_ulong, target_ulong, int) { return 0; }
target_ulong helper_cc_compute_c (target_ulong, target_ulong, target_ulong, int) { return 0; }
void helper_write_eflags (struct CPUX86State *, target_ulong, uint32_t) {}
target_ulong helper_read_eflags (struct CPUX86State *) { return 0; }
void helper_divb_AL (struct CPUX86State *, target_ulong) {}
void helper_idivb_AL (struct CPUX86State *, target_ulong) {}
void helper_divw_AX (struct CPUX86State *, target_ulong) {}
void helper_idivw_AX (struct CPUX86State *, target_ulong) {}
void helper_divl_EAX (struct CPUX86State *, target_ulong) {}
void helper_idivl_EAX (struct CPUX86State *, target_ulong) {}
void helper_cr4_testbit (struct CPUX86State *, uint32_t) {}
void helper_bndck (struct CPUX86State *, uint32_t) {}
uint64_t helper_bndldx32 (struct CPUX86State *, target_ulong, target_ulong) { return 0; }
uint64_t helper_bndldx64 (struct CPUX86State *, target_ulong, target_ulong) { return 0; }
void helper_bndstx32 (struct CPUX86State *, target_ulong, target_ulong, uint64_t, uint64_t) {}
void helper_bndstx64 (struct CPUX86State *, target_ulong, target_ulong, uint64_t, uint64_t) {}
void helper_bnd_jmp (struct CPUX86State *) {}
void helper_aam (struct CPUX86State *, int) {}
void helper_aad (struct CPUX86State *, int) {}
void helper_aaa (struct CPUX86State *) {}
void helper_aas (struct CPUX86State *) {}
void helper_daa (struct CPUX86State *) {}
void helper_das (struct CPUX86State *) {}
target_ulong helper_lsl (struct CPUX86State *, target_ulong) { return 0; }
target_ulong helper_lar (struct CPUX86State *, target_ulong) { return 0; }
void helper_verr (struct CPUX86State *, target_ulong) {}
void helper_verw (struct CPUX86State *, target_ulong) {}
void helper_lldt (struct CPUX86State *, int) {}
void helper_ltr (struct CPUX86State *, int) {}
void helper_load_seg (struct CPUX86State *, int, int) {}
void helper_ljmp_protected (struct CPUX86State *, int, target_ulong, target_ulong) {}
void helper_lcall_real (struct CPUX86State *, int, target_ulong, int, int) {}
void helper_lcall_protected (struct CPUX86State *, int, target_ulong, int, target_ulong) {}
void helper_iret_real (struct CPUX86State *, int) {}
void helper_iret_protected (struct CPUX86State *, int, int) {}
void helper_lret_protected (struct CPUX86State *, int, int) {}
target_ulong helper_read_crN (struct CPUX86State *, int) { return 0; }
void helper_write_crN (struct CPUX86State *, int, target_ulong) {}
void helper_lmsw (struct CPUX86State *, target_ulong) {}
void helper_clts (struct CPUX86State *) {}
void helper_set_dr (struct CPUX86State *, int, target_ulong) {}
target_ulong helper_get_dr (struct CPUX86State *, int) { return 0; }
void helper_invlpg (struct CPUX86State *, target_ulong) {}
void helper_sysenter (struct CPUX86State *) {}
void helper_sysexit (struct CPUX86State *, int) {}
void helper_hlt (struct CPUX86State *, int) {}
void helper_monitor (struct CPUX86State *, target_ulong) {}
void helper_mwait (struct CPUX86State *, int) {}
void helper_pause (struct CPUX86State *, int) {}
void helper_debug (struct CPUX86State *) {}
void helper_reset_rf (struct CPUX86State *) {}
void helper_raise_interrupt (struct CPUX86State *, int, int) {}
void helper_raise_exception (struct CPUX86State *, int) {}
void helper_cli (struct CPUX86State *) {}
void helper_sti (struct CPUX86State *) {}
void helper_clac (struct CPUX86State *) {}
void helper_stac (struct CPUX86State *) {}
void helper_boundw (struct CPUX86State *, target_ulong, int) {}
void helper_boundl (struct CPUX86State *, target_ulong, int) {}
void helper_rsm (struct CPUX86State *) {}
void helper_into (struct CPUX86State *, int) {}
void helper_cmpxchg8b_unlocked (struct CPUX86State *, target_ulong) {}
void helper_cmpxchg8b (struct CPUX86State *, target_ulong) {}
void helper_single_step (struct CPUX86State *) {}
void helper_rechecking_single_step (struct CPUX86State *) {}
void helper_cpuid (struct CPUX86State *) {}
void helper_rdtsc (struct CPUX86State *) {}
void helper_rdtscp (struct CPUX86State *) {}
void helper_rdpmc (struct CPUX86State *) {}
void helper_rdmsr (struct CPUX86State *) {}
void helper_wrmsr (struct CPUX86State *) {}
void helper_check_iob (struct CPUX86State *, uint32_t) {}
void helper_check_iow (struct CPUX86State *, uint32_t) {}
void helper_check_iol (struct CPUX86State *, uint32_t) {}
void helper_outb (struct CPUX86State *, uint32_t, uint32_t) {}
target_ulong helper_inb (struct CPUX86State *, uint32_t) { return 0; }
void helper_outw (struct CPUX86State *, uint32_t, uint32_t) {}
target_ulong helper_inw (struct CPUX86State *, uint32_t) { return 0; }
void helper_outl (struct CPUX86State *, uint32_t, uint32_t) {}
target_ulong helper_inl (struct CPUX86State *, uint32_t) { return 0; }
void helper_bpt_io (struct CPUX86State *, uint32_t, uint32_t, target_ulong) {}
void helper_svm_check_intercept_param (struct CPUX86State *, uint32_t, uint64_t) {}
void helper_svm_check_io (struct CPUX86State *, uint32_t, uint32_t, uint32_t) {}
void helper_vmrun (struct CPUX86State *, int, int) {}
void helper_vmmcall (struct CPUX86State *) {}
void helper_vmload (struct CPUX86State *, int) {}
void helper_vmsave (struct CPUX86State *, int) {}
void helper_stgi (struct CPUX86State *) {}
void helper_clgi (struct CPUX86State *) {}
void helper_skinit (struct CPUX86State *) {}
void helper_invlpga (struct CPUX86State *, int) {}
void helper_flds_FT0 (struct CPUX86State *, uint32_t) {}
void helper_fldl_FT0 (struct CPUX86State *, uint64_t) {}
void helper_fildl_FT0 (struct CPUX86State *, int32_t) {}
void helper_flds_ST0 (struct CPUX86State *, uint32_t) {}
void helper_fldl_ST0 (struct CPUX86State *, uint64_t) {}
void helper_fildl_ST0 (struct CPUX86State *, int32_t) {}
void helper_fildll_ST0 (struct CPUX86State *, int64_t) {}
uint32_t helper_fsts_ST0 (struct CPUX86State *) { return 0; }
uint64_t helper_fstl_ST0 (struct CPUX86State *) { return 0; }
int32_t helper_fist_ST0 (struct CPUX86State *) { return 0; }
int32_t helper_fistl_ST0 (struct CPUX86State *) { return 0; }
int64_t helper_fistll_ST0 (struct CPUX86State *) { return 0; }
int32_t helper_fistt_ST0 (struct CPUX86State *) { return 0; }
int32_t helper_fisttl_ST0 (struct CPUX86State *) { return 0; }
int64_t helper_fisttll_ST0 (struct CPUX86State *) { return 0; }
void helper_fldt_ST0 (struct CPUX86State *, target_ulong) {}
void helper_fstt_ST0 (struct CPUX86State *, target_ulong) {}
void helper_fpush (struct CPUX86State *) {}
void helper_fpop (struct CPUX86State *) {}
void helper_fdecstp (struct CPUX86State *) {}
void helper_fincstp (struct CPUX86State *) {}
void helper_ffree_STN (struct CPUX86State *, int) {}
void helper_fmov_ST0_FT0 (struct CPUX86State *) {}
void helper_fmov_FT0_STN (struct CPUX86State *, int) {}
void helper_fmov_ST0_STN (struct CPUX86State *, int) {}
void helper_fmov_STN_ST0 (struct CPUX86State *, int) {}
void helper_fxchg_ST0_STN (struct CPUX86State *, int) {}
void helper_fcom_ST0_FT0 (struct CPUX86State *) {}
void helper_fucom_ST0_FT0 (struct CPUX86State *) {}
void helper_fcomi_ST0_FT0 (struct CPUX86State *) {}
void helper_fucomi_ST0_FT0 (struct CPUX86State *) {}
void helper_fadd_ST0_FT0 (struct CPUX86State *) {}
void helper_fmul_ST0_FT0 (struct CPUX86State *) {}
void helper_fsub_ST0_FT0 (struct CPUX86State *) {}
void helper_fsubr_ST0_FT0 (struct CPUX86State *) {}
void helper_fdiv_ST0_FT0 (struct CPUX86State *) {}
void helper_fdivr_ST0_FT0 (struct CPUX86State *) {}
void helper_fadd_STN_ST0 (struct CPUX86State *, int) {}
void helper_fmul_STN_ST0 (struct CPUX86State *, int) {}
void helper_fsub_STN_ST0 (struct CPUX86State *, int) {}
void helper_fsubr_STN_ST0 (struct CPUX86State *, int) {}
void helper_fdiv_STN_ST0 (struct CPUX86State *, int) {}
void helper_fdivr_STN_ST0 (struct CPUX86State *, int) {}
void helper_fchs_ST0 (struct CPUX86State *) {}
void helper_fabs_ST0 (struct CPUX86State *) {}
void helper_fxam_ST0 (struct CPUX86State *) {}
void helper_fld1_ST0 (struct CPUX86State *) {}
void helper_fldl2t_ST0 (struct CPUX86State *) {}
void helper_fldl2e_ST0 (struct CPUX86State *) {}
void helper_fldpi_ST0 (struct CPUX86State *) {}
void helper_fldlg2_ST0 (struct CPUX86State *) {}
void helper_fldln2_ST0 (struct CPUX86State *) {}
void helper_fldz_ST0 (struct CPUX86State *) {}
void helper_fldz_FT0 (struct CPUX86State *) {}
uint32_t helper_fnstsw (struct CPUX86State *) { return 0; }
uint32_t helper_fnstcw (struct CPUX86State *) { return 0; }
void helper_fldcw (struct CPUX86State *, uint32_t) {}
void helper_fclex (struct CPUX86State *) {}
void helper_fwait (struct CPUX86State *) {}
void helper_fninit (struct CPUX86State *) {}
void helper_fbld_ST0 (struct CPUX86State *, target_ulong) {}
void helper_fbst_ST0 (struct CPUX86State *, target_ulong) {}
void helper_f2xm1 (struct CPUX86State *) {}
void helper_fyl2x (struct CPUX86State *) {}
void helper_fptan (struct CPUX86State *) {}
void helper_fpatan (struct CPUX86State *) {}
void helper_fxtract (struct CPUX86State *) {}
void helper_fprem1 (struct CPUX86State *) {}
void helper_fprem (struct CPUX86State *) {}
void helper_fyl2xp1 (struct CPUX86State *) {}
void helper_fsqrt (struct CPUX86State *) {}
void helper_fsincos (struct CPUX86State *) {}
void helper_frndint (struct CPUX86State *) {}
void helper_fscale (struct CPUX86State *) {}
void helper_fsin (struct CPUX86State *) {}
void helper_fcos (struct CPUX86State *) {}
void helper_fstenv (struct CPUX86State *, target_ulong, int) {}
void helper_fldenv (struct CPUX86State *, target_ulong, int) {}
void helper_fsave (struct CPUX86State *, target_ulong, int) {}
void helper_frstor (struct CPUX86State *, target_ulong, int) {}
void helper_fxsave (struct CPUX86State *, target_ulong) {}
void helper_fxrstor (struct CPUX86State *, target_ulong) {}
void helper_xsave (struct CPUX86State *, target_ulong, uint64_t) {}
void helper_xsaveopt (struct CPUX86State *, target_ulong, uint64_t) {}
void helper_xrstor (struct CPUX86State *, target_ulong, uint64_t) {}
uint64_t helper_xgetbv (struct CPUX86State *, uint32_t) { return 0; }
void helper_xsetbv (struct CPUX86State *, uint32_t, uint64_t) {}
uint64_t helper_rdpkru (struct CPUX86State *, uint32_t) { return 0; }
void helper_wrpkru (struct CPUX86State *, uint32_t, uint64_t) {}
target_ulong helper_pdep (target_ulong, target_ulong) { return 0; }
target_ulong helper_pext (target_ulong, target_ulong) { return 0; }
void helper_ldmxcsr (struct CPUX86State *, uint32_t) {}
void helper_enter_mmx (struct CPUX86State *) {}
void helper_emms (struct CPUX86State *) {}
void helper_movq (struct CPUX86State *, void *, void *) {}
void helper_psrlw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psraw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psllw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psrld_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psrad_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pslld_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psrlq_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psllq_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_paddb_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_paddw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_paddl_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_paddq_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psubb_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psubw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psubl_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psubq_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_paddusb_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_paddsb_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psubusb_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psubsb_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_paddusw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_paddsw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psubusw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psubsw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pminub_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pmaxub_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pminsw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pmaxsw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pand_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pandn_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_por_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pxor_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pcmpgtb_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pcmpgtw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pcmpgtl_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pcmpeqb_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pcmpeqw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pcmpeql_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pmullw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pmulhrw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pmulhuw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pmulhw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pavgb_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pavgw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pmuludq_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pmaddwd_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psadbw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_maskmov_mmx (struct CPUX86State *, MMXReg *, MMXReg *, target_ulong) {}
void helper_movl_mm_T0_mmx (MMXReg *, uint32_t) {}
void helper_pshufw_mmx (MMXReg *, MMXReg *, int) {}
uint32_t helper_pmovmskb_mmx (struct CPUX86State *, MMXReg *) { return 0; }
void helper_packsswb_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_packuswb_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_packssdw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_punpcklbw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_punpcklwd_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_punpckldq_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_punpckhbw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_punpckhwd_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_punpckhdq_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pi2fd (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pi2fw (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pf2id (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pf2iw (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pfacc (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pfadd (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pfcmpeq (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pfcmpge (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pfcmpgt (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pfmax (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pfmin (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pfmul (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pfnacc (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pfpnacc (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pfrcp (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pfrsqrt (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pfsub (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pfsubr (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pswapd (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_phaddw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_phaddd_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_phaddsw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_phsubw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_phsubd_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_phsubsw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pabsb_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pabsw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pabsd_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pmaddubsw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pmulhrsw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pshufb_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psignb_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psignw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psignd_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_palignr_mmx (struct CPUX86State *, MMXReg *, MMXReg *, int32_t) {}
void helper_psrlw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psraw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psllw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psrld_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psrad_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pslld_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psrlq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psllq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psrldq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pslldq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_paddb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_paddw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_paddl_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_paddq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psubb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psubw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psubl_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psubq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_paddusb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_paddsb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psubusb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psubsb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_paddusw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_paddsw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psubusw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psubsw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pminub_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmaxub_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pminsw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmaxsw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pand_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pandn_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_por_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pxor_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pcmpgtb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pcmpgtw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pcmpgtl_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pcmpeqb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pcmpeqw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pcmpeql_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmullw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmulhuw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmulhw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pavgb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pavgw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmuludq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmaddwd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psadbw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_maskmov_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, target_ulong) {}
void helper_movl_mm_T0_xmm (ZMMReg *, uint32_t) {}
void helper_shufps (ZMMReg *, ZMMReg *, int) {}
void helper_shufpd (ZMMReg *, ZMMReg *, int) {}
void helper_pshufd_xmm (ZMMReg *, ZMMReg *, int) {}
void helper_pshuflw_xmm (ZMMReg *, ZMMReg *, int) {}
void helper_pshufhw_xmm (ZMMReg *, ZMMReg *, int) {}
void helper_addps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_addss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_addpd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_addsd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_subps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_subss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_subpd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_subsd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_mulps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_mulss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_mulpd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_mulsd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_divps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_divss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_divpd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_divsd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_minps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_minss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_minpd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_minsd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_maxps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_maxss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_maxpd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_maxsd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_sqrtps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_sqrtss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_sqrtpd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_sqrtsd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cvtps2pd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cvtpd2ps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cvtss2sd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cvtsd2ss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cvtdq2ps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cvtdq2pd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cvtpi2ps (struct CPUX86State *, ZMMReg *, MMXReg *) {}
void helper_cvtpi2pd (struct CPUX86State *, ZMMReg *, MMXReg *) {}
void helper_cvtsi2ss (struct CPUX86State *, ZMMReg *, uint32_t) {}
void helper_cvtsi2sd (struct CPUX86State *, ZMMReg *, uint32_t) {}
void helper_cvtps2dq (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cvtpd2dq (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cvtps2pi (struct CPUX86State *, MMXReg *, ZMMReg *) {}
void helper_cvtpd2pi (struct CPUX86State *, MMXReg *, ZMMReg *) {}
int32_t helper_cvtss2si (struct CPUX86State *, ZMMReg *) { return 0; }
int32_t helper_cvtsd2si (struct CPUX86State *, ZMMReg *) { return 0; }
void helper_cvttps2dq (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cvttpd2dq (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cvttps2pi (struct CPUX86State *, MMXReg *, ZMMReg *) {}
void helper_cvttpd2pi (struct CPUX86State *, MMXReg *, ZMMReg *) {}
int32_t helper_cvttss2si (struct CPUX86State *, ZMMReg *) { return 0; }
int32_t helper_cvttsd2si (struct CPUX86State *, ZMMReg *) { return 0; }
void helper_rsqrtps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_rsqrtss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_rcpps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_rcpss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_extrq_r (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_extrq_i (struct CPUX86State *, ZMMReg *, int, int) {}
void helper_insertq_r (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_insertq_i (struct CPUX86State *, ZMMReg *, int, int) {}
void helper_haddps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_haddpd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_hsubps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_hsubpd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_addsubps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_addsubpd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpeqps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpeqss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpeqpd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpeqsd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpltps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpltss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpltpd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpltsd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpleps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpless (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmplepd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmplesd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpunordps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpunordss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpunordpd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpunordsd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpneqps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpneqss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpneqpd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpneqsd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpnltps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpnltss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpnltpd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpnltsd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpnleps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpnless (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpnlepd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpnlesd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpordps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpordss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpordpd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpordsd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_ucomiss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_comiss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_ucomisd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_comisd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
uint32_t helper_movmskps (struct CPUX86State *, ZMMReg *) { return 0; }
uint32_t helper_movmskpd (struct CPUX86State *, ZMMReg *) { return 0; }
uint32_t helper_pmovmskb_xmm (struct CPUX86State *, ZMMReg *) { return 0; }
void helper_packsswb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_packuswb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_packssdw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_punpcklbw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_punpcklwd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_punpckldq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_punpckhbw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_punpckhwd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_punpckhdq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_punpcklqdq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_punpckhqdq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_phaddw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_phaddd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_phaddsw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_phsubw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_phsubd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_phsubsw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pabsb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pabsw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pabsd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmaddubsw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmulhrsw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pshufb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psignb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psignw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psignd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_palignr_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, int32_t) {}
void helper_pblendvb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_blendvps_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_blendvpd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_ptest_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmovsxbw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmovsxbd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmovsxbq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmovsxwd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmovsxwq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmovsxdq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmovzxbw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmovzxbd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmovzxbq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmovzxwd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmovzxwq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmovzxdq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmuldq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pcmpeqq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_packusdw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pminsb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pminsd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pminuw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pminud_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmaxsb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmaxsd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmaxuw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmaxud_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmulld_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_phminposuw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_roundps_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_roundpd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_roundss_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_roundsd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_blendps_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_blendpd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_pblendw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_dpps_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_dppd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_mpsadbw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_pcmpgtq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pcmpestri_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_pcmpestrm_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_pcmpistri_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_pcmpistrm_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, uint32_t) {}
target_ulong helper_crc32 (uint32_t, target_ulong, uint32_t) { return 0; }
void helper_aesdec_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_aesdeclast_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_aesenc_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_aesenclast_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_aesimc_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_aeskeygenassist_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_pclmulqdq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, uint32_t) {}
target_ulong helper_rclb (struct CPUX86State *, target_ulong, target_ulong) { return 0; }
target_ulong helper_rclw (struct CPUX86State *, target_ulong, target_ulong) { return 0; }
target_ulong helper_rcll (struct CPUX86State *, target_ulong, target_ulong) { return 0; }
target_ulong helper_rcrb (struct CPUX86State *, target_ulong, target_ulong) { return 0; }
target_ulong helper_rcrw (struct CPUX86State *, target_ulong, target_ulong) { return 0; }
target_ulong helper_rcrl (struct CPUX86State *, target_ulong, target_ulong) { return 0; }
void helper_trace_guest_mem_before_exec_proxy (struct CPUX86State *, target_ulong, uint32_t) {}
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
void * helper_lookup_tb_ptr (struct CPUX86State *) { return nullptr; }
void helper_exit_atomic (struct CPUX86State *) { __builtin_unreachable(); }
uint32_t helper_atomic_cmpxchgb (struct CPUX86State *, target_ulong, uint32_t, uint32_t) { return 0; }
uint32_t helper_atomic_cmpxchgw_be (struct CPUX86State *, target_ulong, uint32_t, uint32_t) { return 0; }
uint32_t helper_atomic_cmpxchgw_le (struct CPUX86State *, target_ulong, uint32_t, uint32_t) { return 0; }
uint32_t helper_atomic_cmpxchgl_be (struct CPUX86State *, target_ulong, uint32_t, uint32_t) { return 0; }
uint32_t helper_atomic_cmpxchgl_le (struct CPUX86State *, target_ulong, uint32_t, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_addb (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_addw_le (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_addw_be (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_addl_le (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_addl_be (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_andb (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_andw_le (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_andw_be (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_andl_le (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_andl_be (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_orb (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_orw_le (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_orw_be (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_orl_le (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_orl_be (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_xorb (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_xorw_le (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_xorw_be (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_xorl_le (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_fetch_xorl_be (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_add_fetchb (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_add_fetchw_le (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_add_fetchw_be (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_add_fetchl_le (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_add_fetchl_be (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_and_fetchb (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_and_fetchw_le (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_and_fetchw_be (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_and_fetchl_le (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_and_fetchl_be (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_or_fetchb (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_or_fetchw_le (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_or_fetchw_be (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_or_fetchl_le (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_or_fetchl_be (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_xor_fetchb (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_xor_fetchw_le (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_xor_fetchw_be (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_xor_fetchl_le (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_xor_fetchl_be (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_xchgb (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_xchgw_le (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_xchgw_be (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_xchgl_le (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
uint32_t helper_atomic_xchgl_be (struct CPUX86State *, target_ulong, uint32_t) { return 0; }
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
