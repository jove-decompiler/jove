typedef TCGMemOp MemOp;

#undef R_386_PC32 /* XXX */
#undef R_386_PC8  /* XXX */
#undef R_386_32   /* XXX */

target_ulong helper_cc_compute_all (target_ulong, target_ulong, target_ulong, int) { return 0; }
target_ulong helper_cc_compute_c (target_ulong, target_ulong, target_ulong, int) { return 0; }
void helper_write_eflags (CPUArchState *, target_ulong, uint32_t) {}
target_ulong helper_read_eflags (CPUArchState *) { return 0; }
void helper_divb_AL (CPUArchState *, target_ulong) {}
void helper_idivb_AL (CPUArchState *, target_ulong) {}
void helper_divw_AX (CPUArchState *, target_ulong) {}
void helper_idivw_AX (CPUArchState *, target_ulong) {}
void helper_divl_EAX (CPUArchState *, target_ulong) {}
void helper_idivl_EAX (CPUArchState *, target_ulong) {}
void helper_divq_EAX (CPUArchState *, target_ulong) {}
void helper_idivq_EAX (CPUArchState *, target_ulong) {}
void helper_cr4_testbit (CPUArchState *, uint32_t) {}
void helper_bndck (CPUArchState *, uint32_t) {}
uint64_t helper_bndldx32 (CPUArchState *, target_ulong, target_ulong) { return 0; }
uint64_t helper_bndldx64 (CPUArchState *, target_ulong, target_ulong) { return 0; }
void helper_bndstx32 (CPUArchState *, target_ulong, target_ulong, uint64_t, uint64_t) {}
void helper_bndstx64 (CPUArchState *, target_ulong, target_ulong, uint64_t, uint64_t) {}
void helper_bnd_jmp (CPUArchState *) {}
void helper_aam (CPUArchState *, int) {}
void helper_aad (CPUArchState *, int) {}
void helper_aaa (CPUArchState *) {}
void helper_aas (CPUArchState *) {}
void helper_daa (CPUArchState *) {}
void helper_das (CPUArchState *) {}
target_ulong helper_lsl (CPUArchState *, target_ulong) { return 0; }
target_ulong helper_lar (CPUArchState *, target_ulong) { return 0; }
void helper_verr (CPUArchState *, target_ulong) {}
void helper_verw (CPUArchState *, target_ulong) {}
void helper_lldt (CPUArchState *, int) {}
void helper_ltr (CPUArchState *, int) {}
void helper_load_seg (CPUArchState *, int, int) {}
void helper_ljmp_protected (CPUArchState *, int, target_ulong, target_ulong) {}
void helper_lcall_real (CPUArchState *, int, target_ulong, int, int) {}
void helper_lcall_protected (CPUArchState *, int, target_ulong, int, target_ulong) {}
void helper_iret_real (CPUArchState *, int) {}
void helper_iret_protected (CPUArchState *, int, int) {}
void helper_lret_protected (CPUArchState *, int, int) {}
target_ulong helper_read_crN (CPUArchState *, int) { return 0; }
void helper_write_crN (CPUArchState *, int, target_ulong) {}
void helper_lmsw (CPUArchState *, target_ulong) {}
void helper_clts (CPUArchState *) {}
void helper_set_dr (CPUArchState *, int, target_ulong) {}
target_ulong helper_get_dr (CPUArchState *, int) { return 0; }
void helper_invlpg (CPUArchState *, target_ulong) {}
void helper_sysenter (CPUArchState *) {}
void helper_sysexit (CPUArchState *, int) {}
void helper_syscall (CPUArchState *, int) {}
void helper_sysret (CPUArchState *, int) {}
void helper_hlt (CPUArchState *, int) {}
void helper_monitor (CPUArchState *, target_ulong) {}
void helper_mwait (CPUArchState *, int) {}
void helper_pause (CPUArchState *, int) {}
void helper_debug (CPUArchState *) {}
void helper_reset_rf (CPUArchState *) {}
void helper_raise_interrupt (CPUArchState *, int, int) {}
void helper_raise_exception (CPUArchState *, int) {}
void helper_cli (CPUArchState *) {}
void helper_sti (CPUArchState *) {}
void helper_clac (CPUArchState *) {}
void helper_stac (CPUArchState *) {}
void helper_boundw (CPUArchState *, target_ulong, int) {}
void helper_boundl (CPUArchState *, target_ulong, int) {}
void helper_rsm (CPUArchState *) {}
void helper_into (CPUArchState *, int) {}
void helper_cmpxchg8b_unlocked (CPUArchState *, target_ulong) {}
void helper_cmpxchg8b (CPUArchState *, target_ulong) {}
void helper_cmpxchg16b_unlocked (CPUArchState *, target_ulong) {}
void helper_cmpxchg16b (CPUArchState *, target_ulong) {}
void helper_single_step (CPUArchState *) {}
void helper_rechecking_single_step (CPUArchState *) {}
void helper_cpuid (CPUArchState *) {}
void helper_rdtsc (CPUArchState *) {}
void helper_rdtscp (CPUArchState *) {}
void helper_rdpmc (CPUArchState *) {}
void helper_rdmsr (CPUArchState *) {}
void helper_wrmsr (CPUArchState *) {}
void helper_check_iob (CPUArchState *, uint32_t) {}
void helper_check_iow (CPUArchState *, uint32_t) {}
void helper_check_iol (CPUArchState *, uint32_t) {}
void helper_outb (CPUArchState *, uint32_t, uint32_t) {}
target_ulong helper_inb (CPUArchState *, uint32_t) { return 0; }
void helper_outw (CPUArchState *, uint32_t, uint32_t) {}
target_ulong helper_inw (CPUArchState *, uint32_t) { return 0; }
void helper_outl (CPUArchState *, uint32_t, uint32_t) {}
target_ulong helper_inl (CPUArchState *, uint32_t) { return 0; }
void helper_bpt_io (CPUArchState *, uint32_t, uint32_t, target_ulong) {}
void helper_svm_check_intercept_param (CPUArchState *, uint32_t, uint64_t) {}
void helper_svm_check_io (CPUArchState *, uint32_t, uint32_t, uint32_t) {}
void helper_vmrun (CPUArchState *, int, int) {}
void helper_vmmcall (CPUArchState *) {}
void helper_vmload (CPUArchState *, int) {}
void helper_vmsave (CPUArchState *, int) {}
void helper_stgi (CPUArchState *) {}
void helper_clgi (CPUArchState *) {}
void helper_skinit (CPUArchState *) {}
void helper_invlpga (CPUArchState *, int) {}
void helper_flds_FT0 (CPUArchState *, uint32_t) {}
void helper_fldl_FT0 (CPUArchState *, uint64_t) {}
void helper_fildl_FT0 (CPUArchState *, int32_t) {}
void helper_flds_ST0 (CPUArchState *, uint32_t) {}
void helper_fldl_ST0 (CPUArchState *, uint64_t) {}
void helper_fildl_ST0 (CPUArchState *, int32_t) {}
void helper_fildll_ST0 (CPUArchState *, int64_t) {}
uint32_t helper_fsts_ST0 (CPUArchState *) { return 0; }
uint64_t helper_fstl_ST0 (CPUArchState *) { return 0; }
int32_t helper_fist_ST0 (CPUArchState *) { return 0; }
int32_t helper_fistl_ST0 (CPUArchState *) { return 0; }
int64_t helper_fistll_ST0 (CPUArchState *) { return 0; }
int32_t helper_fistt_ST0 (CPUArchState *) { return 0; }
int32_t helper_fisttl_ST0 (CPUArchState *) { return 0; }
int64_t helper_fisttll_ST0 (CPUArchState *) { return 0; }
void helper_fldt_ST0 (CPUArchState *, target_ulong) {}
void helper_fstt_ST0 (CPUArchState *, target_ulong) {}
void helper_fpush (CPUArchState *) {}
void helper_fpop (CPUArchState *) {}
void helper_fdecstp (CPUArchState *) {}
void helper_fincstp (CPUArchState *) {}
void helper_ffree_STN (CPUArchState *, int) {}
void helper_fmov_ST0_FT0 (CPUArchState *) {}
void helper_fmov_FT0_STN (CPUArchState *, int) {}
void helper_fmov_ST0_STN (CPUArchState *, int) {}
void helper_fmov_STN_ST0 (CPUArchState *, int) {}
void helper_fxchg_ST0_STN (CPUArchState *, int) {}
void helper_fcom_ST0_FT0 (CPUArchState *) {}
void helper_fucom_ST0_FT0 (CPUArchState *) {}
void helper_fcomi_ST0_FT0 (CPUArchState *) {}
void helper_fucomi_ST0_FT0 (CPUArchState *) {}
void helper_fadd_ST0_FT0 (CPUArchState *) {}
void helper_fmul_ST0_FT0 (CPUArchState *) {}
void helper_fsub_ST0_FT0 (CPUArchState *) {}
void helper_fsubr_ST0_FT0 (CPUArchState *) {}
void helper_fdiv_ST0_FT0 (CPUArchState *) {}
void helper_fdivr_ST0_FT0 (CPUArchState *) {}
void helper_fadd_STN_ST0 (CPUArchState *, int) {}
void helper_fmul_STN_ST0 (CPUArchState *, int) {}
void helper_fsub_STN_ST0 (CPUArchState *, int) {}
void helper_fsubr_STN_ST0 (CPUArchState *, int) {}
void helper_fdiv_STN_ST0 (CPUArchState *, int) {}
void helper_fdivr_STN_ST0 (CPUArchState *, int) {}
void helper_fchs_ST0 (CPUArchState *) {}
void helper_fabs_ST0 (CPUArchState *) {}
void helper_fxam_ST0 (CPUArchState *) {}
void helper_fld1_ST0 (CPUArchState *) {}
void helper_fldl2t_ST0 (CPUArchState *) {}
void helper_fldl2e_ST0 (CPUArchState *) {}
void helper_fldpi_ST0 (CPUArchState *) {}
void helper_fldlg2_ST0 (CPUArchState *) {}
void helper_fldln2_ST0 (CPUArchState *) {}
void helper_fldz_ST0 (CPUArchState *) {}
void helper_fldz_FT0 (CPUArchState *) {}
uint32_t helper_fnstsw (CPUArchState *) { return 0; }
uint32_t helper_fnstcw (CPUArchState *) { return 0; }
void helper_fldcw (CPUArchState *, uint32_t) {}
void helper_fclex (CPUArchState *) {}
void helper_fwait (CPUArchState *) {}
void helper_fninit (CPUArchState *) {}
void helper_fbld_ST0 (CPUArchState *, target_ulong) {}
void helper_fbst_ST0 (CPUArchState *, target_ulong) {}
void helper_f2xm1 (CPUArchState *) {}
void helper_fyl2x (CPUArchState *) {}
void helper_fptan (CPUArchState *) {}
void helper_fpatan (CPUArchState *) {}
void helper_fxtract (CPUArchState *) {}
void helper_fprem1 (CPUArchState *) {}
void helper_fprem (CPUArchState *) {}
void helper_fyl2xp1 (CPUArchState *) {}
void helper_fsqrt (CPUArchState *) {}
void helper_fsincos (CPUArchState *) {}
void helper_frndint (CPUArchState *) {}
void helper_fscale (CPUArchState *) {}
void helper_fsin (CPUArchState *) {}
void helper_fcos (CPUArchState *) {}
void helper_fstenv (CPUArchState *, target_ulong, int) {}
void helper_fldenv (CPUArchState *, target_ulong, int) {}
void helper_fsave (CPUArchState *, target_ulong, int) {}
void helper_frstor (CPUArchState *, target_ulong, int) {}
void helper_fxsave (CPUArchState *, target_ulong) {}
void helper_fxrstor (CPUArchState *, target_ulong) {}
void helper_xsave (CPUArchState *, target_ulong, uint64_t) {}
void helper_xsaveopt (CPUArchState *, target_ulong, uint64_t) {}
void helper_xrstor (CPUArchState *, target_ulong, uint64_t) {}
uint64_t helper_xgetbv (CPUArchState *, uint32_t) { return 0; }
void helper_xsetbv (CPUArchState *, uint32_t, uint64_t) {}
uint64_t helper_rdpkru (CPUArchState *, uint32_t) { return 0; }
void helper_wrpkru (CPUArchState *, uint32_t, uint64_t) {}
target_ulong helper_pdep (target_ulong, target_ulong) { return 0; }
target_ulong helper_pext (target_ulong, target_ulong) { return 0; }
void helper_ldmxcsr (CPUArchState *, uint32_t) {}
void helper_enter_mmx (CPUArchState *) {}
void helper_emms (CPUArchState *) {}
void helper_movq (CPUArchState *, void *, void *) {}
void helper_psrlw_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_psraw_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_psllw_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_psrld_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_psrad_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pslld_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_psrlq_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_psllq_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_paddb_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_paddw_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_paddl_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_paddq_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_psubb_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_psubw_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_psubl_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_psubq_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_paddusb_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_paddsb_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_psubusb_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_psubsb_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_paddusw_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_paddsw_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_psubusw_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_psubsw_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pminub_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pmaxub_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pminsw_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pmaxsw_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pand_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pandn_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_por_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pxor_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pcmpgtb_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pcmpgtw_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pcmpgtl_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pcmpeqb_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pcmpeqw_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pcmpeql_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pmullw_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pmulhrw_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pmulhuw_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pmulhw_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pavgb_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pavgw_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pmuludq_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pmaddwd_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_psadbw_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_maskmov_mmx (CPUArchState *, MMXReg *, MMXReg *, target_ulong) {}
void helper_movl_mm_T0_mmx (MMXReg *, uint32_t) {}
void helper_movq_mm_T0_mmx (MMXReg *, uint64_t) {}
void helper_pshufw_mmx (MMXReg *, MMXReg *, int) {}
uint32_t helper_pmovmskb_mmx (CPUArchState *, MMXReg *) { return 0; }
void helper_packsswb_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_packuswb_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_packssdw_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_punpcklbw_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_punpcklwd_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_punpckldq_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_punpckhbw_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_punpckhwd_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_punpckhdq_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pi2fd (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pi2fw (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pf2id (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pf2iw (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pfacc (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pfadd (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pfcmpeq (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pfcmpge (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pfcmpgt (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pfmax (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pfmin (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pfmul (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pfnacc (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pfpnacc (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pfrcp (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pfrsqrt (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pfsub (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pfsubr (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pswapd (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_phaddw_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_phaddd_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_phaddsw_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_phsubw_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_phsubd_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_phsubsw_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pabsb_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pabsw_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pabsd_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pmaddubsw_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pmulhrsw_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_pshufb_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_psignb_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_psignw_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_psignd_mmx (CPUArchState *, MMXReg *, MMXReg *) {}
void helper_palignr_mmx (CPUArchState *, MMXReg *, MMXReg *, int32_t) {}
void helper_psrlw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_psraw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_psllw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_psrld_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_psrad_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pslld_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_psrlq_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_psllq_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_psrldq_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pslldq_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_paddb_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_paddw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_paddl_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_paddq_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_psubb_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_psubw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_psubl_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_psubq_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_paddusb_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_paddsb_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_psubusb_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_psubsb_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_paddusw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_paddsw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_psubusw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_psubsw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pminub_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pmaxub_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pminsw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pmaxsw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pand_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pandn_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_por_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pxor_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pcmpgtb_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pcmpgtw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pcmpgtl_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pcmpeqb_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pcmpeqw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pcmpeql_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pmullw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pmulhuw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pmulhw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pavgb_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pavgw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pmuludq_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pmaddwd_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_psadbw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_maskmov_xmm (CPUArchState *, ZMMReg *, ZMMReg *, target_ulong) {}
void helper_movl_mm_T0_xmm (ZMMReg *, uint32_t) {}
void helper_movq_mm_T0_xmm (ZMMReg *, uint64_t) {}
void helper_shufps (ZMMReg *, ZMMReg *, int) {}
void helper_shufpd (ZMMReg *, ZMMReg *, int) {}
void helper_pshufd_xmm (ZMMReg *, ZMMReg *, int) {}
void helper_pshuflw_xmm (ZMMReg *, ZMMReg *, int) {}
void helper_pshufhw_xmm (ZMMReg *, ZMMReg *, int) {}
void helper_addps (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_addss (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_addpd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_addsd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_subps (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_subss (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_subpd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_subsd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_mulps (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_mulss (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_mulpd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_mulsd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_divps (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_divss (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_divpd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_divsd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_minps (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_minss (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_minpd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_minsd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_maxps (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_maxss (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_maxpd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_maxsd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_sqrtps (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_sqrtss (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_sqrtpd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_sqrtsd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cvtps2pd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cvtpd2ps (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cvtss2sd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cvtsd2ss (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cvtdq2ps (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cvtdq2pd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cvtpi2ps (CPUArchState *, ZMMReg *, MMXReg *) {}
void helper_cvtpi2pd (CPUArchState *, ZMMReg *, MMXReg *) {}
void helper_cvtsi2ss (CPUArchState *, ZMMReg *, uint32_t) {}
void helper_cvtsi2sd (CPUArchState *, ZMMReg *, uint32_t) {}
void helper_cvtsq2ss (CPUArchState *, ZMMReg *, uint64_t) {}
void helper_cvtsq2sd (CPUArchState *, ZMMReg *, uint64_t) {}
void helper_cvtps2dq (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cvtpd2dq (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cvtps2pi (CPUArchState *, MMXReg *, ZMMReg *) {}
void helper_cvtpd2pi (CPUArchState *, MMXReg *, ZMMReg *) {}
int32_t helper_cvtss2si (CPUArchState *, ZMMReg *) { return 0; }
int32_t helper_cvtsd2si (CPUArchState *, ZMMReg *) { return 0; }
int64_t helper_cvtss2sq (CPUArchState *, ZMMReg *) { return 0; }
int64_t helper_cvtsd2sq (CPUArchState *, ZMMReg *) { return 0; }
void helper_cvttps2dq (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cvttpd2dq (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cvttps2pi (CPUArchState *, MMXReg *, ZMMReg *) {}
void helper_cvttpd2pi (CPUArchState *, MMXReg *, ZMMReg *) {}
int32_t helper_cvttss2si (CPUArchState *, ZMMReg *) { return 0; }
int32_t helper_cvttsd2si (CPUArchState *, ZMMReg *) { return 0; }
int64_t helper_cvttss2sq (CPUArchState *, ZMMReg *) { return 0; }
int64_t helper_cvttsd2sq (CPUArchState *, ZMMReg *) { return 0; }
void helper_rsqrtps (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_rsqrtss (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_rcpps (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_rcpss (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_extrq_r (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_extrq_i (CPUArchState *, ZMMReg *, int, int) {}
void helper_insertq_r (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_insertq_i (CPUArchState *, ZMMReg *, int, int) {}
void helper_haddps (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_haddpd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_hsubps (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_hsubpd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_addsubps (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_addsubpd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cmpeqps (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cmpeqss (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cmpeqpd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cmpeqsd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cmpltps (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cmpltss (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cmpltpd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cmpltsd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cmpleps (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cmpless (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cmplepd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cmplesd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cmpunordps (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cmpunordss (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cmpunordpd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cmpunordsd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cmpneqps (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cmpneqss (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cmpneqpd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cmpneqsd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cmpnltps (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cmpnltss (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cmpnltpd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cmpnltsd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cmpnleps (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cmpnless (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cmpnlepd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cmpnlesd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cmpordps (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cmpordss (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cmpordpd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_cmpordsd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_ucomiss (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_comiss (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_ucomisd (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_comisd (CPUArchState *, ZMMReg *, ZMMReg *) {}
uint32_t helper_movmskps (CPUArchState *, ZMMReg *) { return 0; }
uint32_t helper_movmskpd (CPUArchState *, ZMMReg *) { return 0; }
uint32_t helper_pmovmskb_xmm (CPUArchState *, ZMMReg *) { return 0; }
void helper_packsswb_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_packuswb_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_packssdw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_punpcklbw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_punpcklwd_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_punpckldq_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_punpckhbw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_punpckhwd_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_punpckhdq_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_punpcklqdq_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_punpckhqdq_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_phaddw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_phaddd_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_phaddsw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_phsubw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_phsubd_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_phsubsw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pabsb_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pabsw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pabsd_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pmaddubsw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pmulhrsw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pshufb_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_psignb_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_psignw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_psignd_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_palignr_xmm (CPUArchState *, ZMMReg *, ZMMReg *, int32_t) {}
void helper_pblendvb_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_blendvps_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_blendvpd_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_ptest_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pmovsxbw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pmovsxbd_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pmovsxbq_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pmovsxwd_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pmovsxwq_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pmovsxdq_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pmovzxbw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pmovzxbd_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pmovzxbq_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pmovzxwd_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pmovzxwq_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pmovzxdq_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pmuldq_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pcmpeqq_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_packusdw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pminsb_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pminsd_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pminuw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pminud_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pmaxsb_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pmaxsd_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pmaxuw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pmaxud_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pmulld_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_phminposuw_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_roundps_xmm (CPUArchState *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_roundpd_xmm (CPUArchState *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_roundss_xmm (CPUArchState *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_roundsd_xmm (CPUArchState *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_blendps_xmm (CPUArchState *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_blendpd_xmm (CPUArchState *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_pblendw_xmm (CPUArchState *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_dpps_xmm (CPUArchState *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_dppd_xmm (CPUArchState *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_mpsadbw_xmm (CPUArchState *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_pcmpgtq_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_pcmpestri_xmm (CPUArchState *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_pcmpestrm_xmm (CPUArchState *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_pcmpistri_xmm (CPUArchState *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_pcmpistrm_xmm (CPUArchState *, ZMMReg *, ZMMReg *, uint32_t) {}
target_ulong helper_crc32 (uint32_t, target_ulong, uint32_t) { return 0; }
void helper_aesdec_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_aesdeclast_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_aesenc_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_aesenclast_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_aesimc_xmm (CPUArchState *, ZMMReg *, ZMMReg *) {}
void helper_aeskeygenassist_xmm (CPUArchState *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_pclmulqdq_xmm (CPUArchState *, ZMMReg *, ZMMReg *, uint32_t) {}
target_ulong helper_rclb (CPUArchState *, target_ulong, target_ulong) { return 0; }
target_ulong helper_rclw (CPUArchState *, target_ulong, target_ulong) { return 0; }
target_ulong helper_rcll (CPUArchState *, target_ulong, target_ulong) { return 0; }
target_ulong helper_rcrb (CPUArchState *, target_ulong, target_ulong) { return 0; }
target_ulong helper_rcrw (CPUArchState *, target_ulong, target_ulong) { return 0; }
target_ulong helper_rcrl (CPUArchState *, target_ulong, target_ulong) { return 0; }
target_ulong helper_rclq (CPUArchState *, target_ulong, target_ulong) { return 0; }
target_ulong helper_rcrq (CPUArchState *, target_ulong, target_ulong) { return 0; }
target_ulong helper_rdrand (CPUArchState *) { return 0; }
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
