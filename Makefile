ARCH := $(subst i686,i386,$(shell uname -m))

#
# build flags
#
CXXFLAGS := -std=gnu++14 \
            -Wall \
            -Wno-macro-redefined \
            -Wno-shift-count-negative \
            -Wno-initializer-overrides \
            -fno-omit-frame-pointer \
            -fvisibility=hidden \
            -fexceptions \
            -Og \
            -g \
            -I bin \
            -I include \
            -I lib \
            -I lib/arch/$(ARCH) \
            -D___JOVE_ARCH_NAME=\"$(ARCH)\" \
            -D_GNU_SOURCE \
            -DBOOST_ICL_USE_STATIC_BOUNDED_INTERVALS

LDFLAGS := $(shell pkg-config --libs glib-2.0) \
           $(shell llvm-config --ldflags --libs) \
           -ldl \
           -pthread \
           -lboost_filesystem \
           -lboost_system \
           -lboost_serialization

#
# important directories
#
SRCDIR := tools
BINDIR := bin

#
# find tools
#
SRCS  := $(wildcard $(SRCDIR)/*.cpp)
TOOLS := $(patsubst $(SRCDIR)/%.cpp,%,$(SRCS))
BINS  := $(foreach tool,$(TOOLS),$(BINDIR)/$(tool))
DEPS  := $(foreach tool,$(TOOLS),$(BINDIR)/$(tool).d)

all: $(BINS)

$(BINDIR)/jove-llvm: $(BINDIR)/jove/tcgconstants.h
$(BINDIR)/jove-llvm: $(BINDIR)/jove/jove.bc.inc
define build_tool_template
$(BINDIR)/$(1): $(SRCDIR)/$(1).cpp Makefile
	@echo CXX $(1)
	@clang++ -o $$@ -MMD $(CXXFLAGS) $$< $(LDFLAGS)
endef
$(foreach tool,$(TOOLS),$(eval $(call build_tool_template,$(tool))))

$(BINDIR)/jove/tcgconstants.h: $(BINDIR)/gen-tcgconstants
	@mkdir -p $(BINDIR)/jove
	@echo GEN $@
	@$< > $@

$(BINDIR)/jove/jove.bc.inc: $(BINDIR)/jove.bc
	@mkdir -p $(BINDIR)/jove
	xxd -include < $< > $@

$(BINDIR)/jove.bc: lib/arch/$(ARCH)/helpers/jove.c
	clang -o $@ -c -emit-llvm -Oz -fPIC -fno-stack-protector -g $<

-include $(DEPS)

.PHONY: clean
clean:
	rm -rf $(BINS) $(DEPS) $(BINDIR)/jove $(BINDIR)/jove.bc

#
# for extricating QEMU code
#

CLANG_EXTRICATE := ~/clang-extricate
QEMU_SRC_DIR    := ~/qemu
QEMU_BUILD_DIR  := ~/qemu

_SL_TCG_GEN_ADDI_I64 := tcg/tcg-op.c:1175l
_SL_TCG_OPTIMIZE     := tcg/optimize.c:592l
_SL_TCG_OP_DEFS      := tcg/tcg-common.c:35l
_SL_TB_GEN_CODE      := accel/tcg/translate-all.c:1247l
_SL_TRANSLATOR_LOOP  := accel/tcg/translator.c:36l
_SL_PSTRCPY          := util/cutils.c:43l

COMMON_SOURCE_LOCATIONS := $(_SL_TCG_GEN_ADDI_I64) \
                           $(_SL_TCG_OPTIMIZE) \
                           $(_SL_TCG_OP_DEFS) \
                           $(_SL_TB_GEN_CODE) \
                           $(_SL_TRANSLATOR_LOOP) \
                           $(_SL_PSTRCPY)

_SL_X86_64_TCG_CONTEXT_INIT := tcg/tcg.c:2070l
_SL_X86_64_TCG_FUNC_START   := tcg/tcg.c:2256l
_SL_X86_64_TCG_GEN_CODE     := tcg/tcg.c:4633l

_SL_X86_64_GEN_INTERMEDIATE_CODE  := target/i386/translate.c:8573l
_SL_X86_64_TCG_X86_INIT           := target/i386/translate.c:8328l
# _SL_X86_64_TCG_GEN_GVEC_NOT       := tcg/tcg-op-gvec.c:1357l
# _SL_X86_64_TCG_GEN_LD_VEC         := tcg/tcg-op-vec.c:209l

x86_64_SOURCE_LOCATIONS := $(_SL_X86_64_TCG_CONTEXT_INIT) \
                           $(_SL_X86_64_TCG_FUNC_START) \
                           $(_SL_X86_64_TCG_GEN_CODE) \
                           $(_SL_X86_64_GEN_INTERMEDIATE_CODE) \
                           $(_SL_X86_64_TCG_X86_INIT)

i386_SOURCE_LOCATIONS := $(_SL_X86_64_TCG_CONTEXT_INIT) \
                         $(_SL_X86_64_TCG_FUNC_START) \
                         $(_SL_X86_64_TCG_GEN_CODE) \
                         $(_SL_X86_64_GEN_INTERMEDIATE_CODE) \
                         $(_SL_X86_64_TCG_X86_INIT)

x86_64_HELPER_CFLAGS := -DCONFIG_ATOMIC64=1 \
                        -DCONFIG_USER_ONLY=1

#                           $(_SL_X86_64_TCG_GEN_GVEC_NOT) \
#                           $(_SL_X86_64_TCG_GEN_LD_VEC)

_SL_AARCH64_TCG_CONTEXT_INIT := tcg/tcg.c:1808l
_SL_AARCH64_TCG_FUNC_START   := tcg/tcg.c:1994l
_SL_AARCH64_TCG_GEN_CODE     := tcg/tcg.c:4371l

_SL_AARCH64_GEN_INTERMEDIATE_CODE := target/arm/translate.c:12732l
_SL_AARCH64_TRANSLATOR_OPS        := target/arm/translate-a64.c:13448l
_SL_AARCH64_TRANSLATE_INIT        := target/arm/translate.c:85l
_SL_AARCH64_TCG_GEN_GVEC_NOT      := tcg/tcg-op-gvec.c:1357l
_SL_AARCH64_TCG_GEN_LD_VEC        := tcg/tcg-op-vec.c:209l

aarch64_SOURCE_LOCATIONS := $(_SL_AARCH64_TCG_CONTEXT_INIT) \
                            $(_SL_AARCH64_TCG_FUNC_START) \
                            $(_SL_AARCH64_TCG_GEN_CODE) \
                            $(_SL_AARCH64_GEN_INTERMEDIATE_CODE) \
                            $(_SL_AARCH64_TRANSLATOR_OPS) \
                            $(_SL_AARCH64_TRANSLATE_INIT) \
                            $(_SL_AARCH64_TCG_GEN_GVEC_NOT) \
                            $(_SL_AARCH64_TCG_GEN_LD_VEC)

.PHONY: extract-tcg-code
extract-tcg-code:
	$(CLANG_EXTRICATE)/extract/bin/carbon-extract --src $(QEMU_SRC_DIR) --bin $(QEMU_BUILD_DIR) $(COMMON_SOURCE_LOCATIONS) $($(ARCH)_SOURCE_LOCATIONS) > lib/arch/$(ARCH)/tcg.hpp

#
# TCG helpers
#
x86_64_HELPERS := cc_compute_all cc_compute_c write_eflags read_eflags divb_AL idivb_AL divw_AX idivw_AX divl_EAX idivl_EAX divq_EAX idivq_EAX cr4_testbit bndck bndldx32 bndldx64 bndstx32 bndstx64 bnd_jmp aam aad aaa aas daa das lsl lar verr verw lldt ltr load_seg ljmp_protected lcall_real lcall_protected iret_real iret_protected lret_protected read_crN write_crN lmsw clts set_dr get_dr invlpg sysenter sysexit syscall sysret hlt monitor mwait pause debug reset_rf raise_interrupt raise_exception cli sti clac stac boundw boundl rsm into cmpxchg8b_unlocked cmpxchg8b cmpxchg16b_unlocked cmpxchg16b single_step rechecking_single_step cpuid rdtsc rdtscp rdpmc rdmsr wrmsr check_iob check_iow check_iol outb inb outw inw outl inl bpt_io svm_check_intercept_param svm_check_io vmrun vmmcall vmload vmsave stgi clgi skinit invlpga flds_FT0 fldl_FT0 fildl_FT0 flds_ST0 fldl_ST0 fildl_ST0 fildll_ST0 fsts_ST0 fstl_ST0 fist_ST0 fistl_ST0 fistll_ST0 fistt_ST0 fisttl_ST0 fisttll_ST0 fldt_ST0 fstt_ST0 fpush fpop fdecstp fincstp ffree_STN fmov_ST0_FT0 fmov_FT0_STN fmov_ST0_STN fmov_STN_ST0 fxchg_ST0_STN fcom_ST0_FT0 fucom_ST0_FT0 fcomi_ST0_FT0 fucomi_ST0_FT0 fadd_ST0_FT0 fmul_ST0_FT0 fsub_ST0_FT0 fsubr_ST0_FT0 fdiv_ST0_FT0 fdivr_ST0_FT0 fadd_STN_ST0 fmul_STN_ST0 fsub_STN_ST0 fsubr_STN_ST0 fdiv_STN_ST0 fdivr_STN_ST0 fchs_ST0 fabs_ST0 fxam_ST0 fld1_ST0 fldl2t_ST0 fldl2e_ST0 fldpi_ST0 fldlg2_ST0 fldln2_ST0 fldz_ST0 fldz_FT0 fnstsw fnstcw fldcw fclex fwait fninit fbld_ST0 fbst_ST0 f2xm1 fyl2x fptan fpatan fxtract fprem1 fprem fyl2xp1 fsqrt fsincos frndint fscale fsin fcos fstenv fldenv fsave frstor fxsave fxrstor xsave xsaveopt xrstor xgetbv xsetbv rdpkru wrpkru pdep pext ldmxcsr enter_mmx emms movq psrlw_mmx psraw_mmx psllw_mmx psrld_mmx psrad_mmx pslld_mmx psrlq_mmx psllq_mmx paddb_mmx paddw_mmx paddl_mmx paddq_mmx psubb_mmx psubw_mmx psubl_mmx psubq_mmx paddusb_mmx paddsb_mmx psubusb_mmx psubsb_mmx paddusw_mmx paddsw_mmx psubusw_mmx psubsw_mmx pminub_mmx pmaxub_mmx pminsw_mmx pmaxsw_mmx pand_mmx pandn_mmx por_mmx pxor_mmx pcmpgtb_mmx pcmpgtw_mmx pcmpgtl_mmx pcmpeqb_mmx pcmpeqw_mmx pcmpeql_mmx pmullw_mmx pmulhrw_mmx pmulhuw_mmx pmulhw_mmx pavgb_mmx pavgw_mmx pmuludq_mmx pmaddwd_mmx psadbw_mmx maskmov_mmx movl_mm_T0_mmx movq_mm_T0_mmx pshufw_mmx pmovmskb_mmx packsswb_mmx packuswb_mmx packssdw_mmx punpcklbw_mmx punpcklwd_mmx punpckldq_mmx punpckhbw_mmx punpckhwd_mmx punpckhdq_mmx pi2fd pi2fw pf2id pf2iw pfacc pfadd pfcmpeq pfcmpge pfcmpgt pfmax pfmin pfmul pfnacc pfpnacc pfrcp pfrsqrt pfsub pfsubr pswapd phaddw_mmx phaddd_mmx phaddsw_mmx phsubw_mmx phsubd_mmx phsubsw_mmx pabsb_mmx pabsw_mmx pabsd_mmx pmaddubsw_mmx pmulhrsw_mmx pshufb_mmx psignb_mmx psignw_mmx psignd_mmx palignr_mmx psrlw_xmm psraw_xmm psllw_xmm psrld_xmm psrad_xmm pslld_xmm psrlq_xmm psllq_xmm psrldq_xmm pslldq_xmm paddb_xmm paddw_xmm paddl_xmm paddq_xmm psubb_xmm psubw_xmm psubl_xmm psubq_xmm paddusb_xmm paddsb_xmm psubusb_xmm psubsb_xmm paddusw_xmm paddsw_xmm psubusw_xmm psubsw_xmm pminub_xmm pmaxub_xmm pminsw_xmm pmaxsw_xmm pand_xmm pandn_xmm por_xmm pxor_xmm pcmpgtb_xmm pcmpgtw_xmm pcmpgtl_xmm pcmpeqb_xmm pcmpeqw_xmm pcmpeql_xmm pmullw_xmm pmulhuw_xmm pmulhw_xmm pavgb_xmm pavgw_xmm pmuludq_xmm pmaddwd_xmm psadbw_xmm maskmov_xmm movl_mm_T0_xmm movq_mm_T0_xmm shufps shufpd pshufd_xmm pshuflw_xmm pshufhw_xmm addps addss addpd addsd subps subss subpd subsd mulps mulss mulpd mulsd divps divss divpd divsd minps minss minpd minsd maxps maxss maxpd maxsd sqrtps sqrtss sqrtpd sqrtsd cvtps2pd cvtpd2ps cvtss2sd cvtsd2ss cvtdq2ps cvtdq2pd cvtpi2ps cvtpi2pd cvtsi2ss cvtsi2sd cvtsq2ss cvtsq2sd cvtps2dq cvtpd2dq cvtps2pi cvtpd2pi cvtss2si cvtsd2si cvtss2sq cvtsd2sq cvttps2dq cvttpd2dq cvttps2pi cvttpd2pi cvttss2si cvttsd2si cvttss2sq cvttsd2sq rsqrtps rsqrtss rcpps rcpss extrq_r extrq_i insertq_r insertq_i haddps haddpd hsubps hsubpd addsubps addsubpd cmpeqps cmpeqss cmpeqpd cmpeqsd cmpltps cmpltss cmpltpd cmpltsd cmpleps cmpless cmplepd cmplesd cmpunordps cmpunordss cmpunordpd cmpunordsd cmpneqps cmpneqss cmpneqpd cmpneqsd cmpnltps cmpnltss cmpnltpd cmpnltsd cmpnleps cmpnless cmpnlepd cmpnlesd cmpordps cmpordss cmpordpd cmpordsd ucomiss comiss ucomisd comisd movmskps movmskpd pmovmskb_xmm packsswb_xmm packuswb_xmm packssdw_xmm punpcklbw_xmm punpcklwd_xmm punpckldq_xmm punpckhbw_xmm punpckhwd_xmm punpckhdq_xmm punpcklqdq_xmm punpckhqdq_xmm phaddw_xmm phaddd_xmm phaddsw_xmm phsubw_xmm phsubd_xmm phsubsw_xmm pabsb_xmm pabsw_xmm pabsd_xmm pmaddubsw_xmm pmulhrsw_xmm pshufb_xmm psignb_xmm psignw_xmm psignd_xmm palignr_xmm pblendvb_xmm blendvps_xmm blendvpd_xmm ptest_xmm pmovsxbw_xmm pmovsxbd_xmm pmovsxbq_xmm pmovsxwd_xmm pmovsxwq_xmm pmovsxdq_xmm pmovzxbw_xmm pmovzxbd_xmm pmovzxbq_xmm pmovzxwd_xmm pmovzxwq_xmm pmovzxdq_xmm pmuldq_xmm pcmpeqq_xmm packusdw_xmm pminsb_xmm pminsd_xmm pminuw_xmm pminud_xmm pmaxsb_xmm pmaxsd_xmm pmaxuw_xmm pmaxud_xmm pmulld_xmm phminposuw_xmm roundps_xmm roundpd_xmm roundss_xmm roundsd_xmm blendps_xmm blendpd_xmm pblendw_xmm dpps_xmm dppd_xmm mpsadbw_xmm pcmpgtq_xmm pcmpestri_xmm pcmpestrm_xmm pcmpistri_xmm pcmpistrm_xmm crc32 aesdec_xmm aesdeclast_xmm aesenc_xmm aesenclast_xmm aesimc_xmm aeskeygenassist_xmm pclmulqdq_xmm rclb rclw rcll rcrb rcrw rcrl rclq rcrq trace_guest_mem_before_exec_proxy div_i32 rem_i32 divu_i32 remu_i32 div_i64 rem_i64 divu_i64 remu_i64 shl_i64 shr_i64 sar_i64 mulsh_i64 muluh_i64 clz_i32 ctz_i32 clz_i64 ctz_i64 clrsb_i32 clrsb_i64 ctpop_i32 ctpop_i64 lookup_tb_ptr exit_atomic atomic_cmpxchgb atomic_cmpxchgw_be atomic_cmpxchgw_le atomic_cmpxchgl_be atomic_cmpxchgl_le atomic_cmpxchgq_be atomic_cmpxchgq_le atomic_fetch_addb atomic_fetch_addw_le atomic_fetch_addw_be atomic_fetch_addl_le atomic_fetch_addl_be atomic_fetch_addq_le atomic_fetch_addq_be atomic_fetch_andb atomic_fetch_andw_le atomic_fetch_andw_be atomic_fetch_andl_le atomic_fetch_andl_be atomic_fetch_andq_le atomic_fetch_andq_be atomic_fetch_orb atomic_fetch_orw_le atomic_fetch_orw_be atomic_fetch_orl_le atomic_fetch_orl_be atomic_fetch_orq_le atomic_fetch_orq_be atomic_fetch_xorb atomic_fetch_xorw_le atomic_fetch_xorw_be atomic_fetch_xorl_le atomic_fetch_xorl_be atomic_fetch_xorq_le atomic_fetch_xorq_be atomic_add_fetchb atomic_add_fetchw_le atomic_add_fetchw_be atomic_add_fetchl_le atomic_add_fetchl_be atomic_add_fetchq_le atomic_add_fetchq_be atomic_and_fetchb atomic_and_fetchw_le atomic_and_fetchw_be atomic_and_fetchl_le atomic_and_fetchl_be atomic_and_fetchq_le atomic_and_fetchq_be atomic_or_fetchb atomic_or_fetchw_le atomic_or_fetchw_be atomic_or_fetchl_le atomic_or_fetchl_be atomic_or_fetchq_le atomic_or_fetchq_be atomic_xor_fetchb atomic_xor_fetchw_le atomic_xor_fetchw_be atomic_xor_fetchl_le atomic_xor_fetchl_be atomic_xor_fetchq_le atomic_xor_fetchq_be atomic_xchgb atomic_xchgw_le atomic_xchgw_be atomic_xchgl_le atomic_xchgl_be atomic_xchgq_le atomic_xchgq_be gvec_mov gvec_dup8 gvec_dup16 gvec_dup32 gvec_dup64 gvec_add8 gvec_add16 gvec_add32 gvec_add64 gvec_adds8 gvec_adds16 gvec_adds32 gvec_adds64 gvec_sub8 gvec_sub16 gvec_sub32 gvec_sub64 gvec_subs8 gvec_subs16 gvec_subs32 gvec_subs64 gvec_mul8 gvec_mul16 gvec_mul32 gvec_mul64 gvec_muls8 gvec_muls16 gvec_muls32 gvec_muls64 gvec_ssadd8 gvec_ssadd16 gvec_ssadd32 gvec_ssadd64 gvec_sssub8 gvec_sssub16 gvec_sssub32 gvec_sssub64 gvec_usadd8 gvec_usadd16 gvec_usadd32 gvec_usadd64 gvec_ussub8 gvec_ussub16 gvec_ussub32 gvec_ussub64 gvec_neg8 gvec_neg16 gvec_neg32 gvec_neg64 gvec_not gvec_and gvec_or gvec_xor gvec_andc gvec_orc gvec_ands gvec_xors gvec_ors gvec_shl8i gvec_shl16i gvec_shl32i gvec_shl64i gvec_shr8i gvec_shr16i gvec_shr32i gvec_shr64i gvec_sar8i gvec_sar16i gvec_sar32i gvec_sar64i gvec_eq8 gvec_eq16 gvec_eq32 gvec_eq64 gvec_ne8 gvec_ne16 gvec_ne32 gvec_ne64 gvec_lt8 gvec_lt16 gvec_lt32 gvec_lt64 gvec_le8 gvec_le16 gvec_le32 gvec_le64 gvec_ltu8 gvec_ltu16 gvec_ltu32 gvec_ltu64 gvec_leu8 gvec_leu16 gvec_leu32 gvec_leu64

i386_HELPERS := cc_compute_all cc_compute_c write_eflags read_eflags divb_AL idivb_AL divw_AX idivw_AX divl_EAX idivl_EAX cr4_testbit bndck bndldx32 bndldx64 bndstx32 bndstx64 bnd_jmp aam aad aaa aas daa das lsl lar verr verw lldt ltr load_seg ljmp_protected lcall_real lcall_protected iret_real iret_protected lret_protected read_crN write_crN lmsw clts set_dr get_dr invlpg sysenter sysexit hlt monitor mwait pause debug reset_rf raise_interrupt raise_exception cli sti clac stac boundw boundl rsm into cmpxchg8b_unlocked cmpxchg8b single_step rechecking_single_step cpuid rdtsc rdtscp rdpmc rdmsr wrmsr check_iob check_iow check_iol outb inb outw inw outl inl bpt_io svm_check_intercept_param svm_check_io vmrun vmmcall vmload vmsave stgi clgi skinit invlpga flds_FT0 fldl_FT0 fildl_FT0 flds_ST0 fldl_ST0 fildl_ST0 fildll_ST0 fsts_ST0 fstl_ST0 fist_ST0 fistl_ST0 fistll_ST0 fistt_ST0 fisttl_ST0 fisttll_ST0 fldt_ST0 fstt_ST0 fpush fpop fdecstp fincstp ffree_STN fmov_ST0_FT0 fmov_FT0_STN fmov_ST0_STN fmov_STN_ST0 fxchg_ST0_STN fcom_ST0_FT0 fucom_ST0_FT0 fcomi_ST0_FT0 fucomi_ST0_FT0 fadd_ST0_FT0 fmul_ST0_FT0 fsub_ST0_FT0 fsubr_ST0_FT0 fdiv_ST0_FT0 fdivr_ST0_FT0 fadd_STN_ST0 fmul_STN_ST0 fsub_STN_ST0 fsubr_STN_ST0 fdiv_STN_ST0 fdivr_STN_ST0 fchs_ST0 fabs_ST0 fxam_ST0 fld1_ST0 fldl2t_ST0 fldl2e_ST0 fldpi_ST0 fldlg2_ST0 fldln2_ST0 fldz_ST0 fldz_FT0 fnstsw fnstcw fldcw fclex fwait fninit fbld_ST0 fbst_ST0 f2xm1 fyl2x fptan fpatan fxtract fprem1 fprem fyl2xp1 fsqrt fsincos frndint fscale fsin fcos fstenv fldenv fsave frstor fxsave fxrstor xsave xsaveopt xrstor xgetbv xsetbv rdpkru wrpkru pdep pext ldmxcsr enter_mmx emms movq psrlw_mmx psraw_mmx psllw_mmx psrld_mmx psrad_mmx pslld_mmx psrlq_mmx psllq_mmx paddb_mmx paddw_mmx paddl_mmx paddq_mmx psubb_mmx psubw_mmx psubl_mmx psubq_mmx paddusb_mmx paddsb_mmx psubusb_mmx psubsb_mmx paddusw_mmx paddsw_mmx psubusw_mmx psubsw_mmx pminub_mmx pmaxub_mmx pminsw_mmx pmaxsw_mmx pand_mmx pandn_mmx por_mmx pxor_mmx pcmpgtb_mmx pcmpgtw_mmx pcmpgtl_mmx pcmpeqb_mmx pcmpeqw_mmx pcmpeql_mmx pmullw_mmx pmulhrw_mmx pmulhuw_mmx pmulhw_mmx pavgb_mmx pavgw_mmx pmuludq_mmx pmaddwd_mmx psadbw_mmx maskmov_mmx movl_mm_T0_mmx pshufw_mmx pmovmskb_mmx packsswb_mmx packuswb_mmx packssdw_mmx punpcklbw_mmx punpcklwd_mmx punpckldq_mmx punpckhbw_mmx punpckhwd_mmx punpckhdq_mmx pi2fd pi2fw pf2id pf2iw pfacc pfadd pfcmpeq pfcmpge pfcmpgt pfmax pfmin pfmul pfnacc pfpnacc pfrcp pfrsqrt pfsub pfsubr pswapd phaddw_mmx phaddd_mmx phaddsw_mmx phsubw_mmx phsubd_mmx phsubsw_mmx pabsb_mmx pabsw_mmx pabsd_mmx pmaddubsw_mmx pmulhrsw_mmx pshufb_mmx psignb_mmx psignw_mmx psignd_mmx palignr_mmx psrlw_xmm psraw_xmm psllw_xmm psrld_xmm psrad_xmm pslld_xmm psrlq_xmm psllq_xmm psrldq_xmm pslldq_xmm paddb_xmm paddw_xmm paddl_xmm paddq_xmm psubb_xmm psubw_xmm psubl_xmm psubq_xmm paddusb_xmm paddsb_xmm psubusb_xmm psubsb_xmm paddusw_xmm paddsw_xmm psubusw_xmm psubsw_xmm pminub_xmm pmaxub_xmm pminsw_xmm pmaxsw_xmm pand_xmm pandn_xmm por_xmm pxor_xmm pcmpgtb_xmm pcmpgtw_xmm pcmpgtl_xmm pcmpeqb_xmm pcmpeqw_xmm pcmpeql_xmm pmullw_xmm pmulhuw_xmm pmulhw_xmm pavgb_xmm pavgw_xmm pmuludq_xmm pmaddwd_xmm psadbw_xmm maskmov_xmm movl_mm_T0_xmm shufps shufpd pshufd_xmm pshuflw_xmm pshufhw_xmm addps addss addpd addsd subps subss subpd subsd mulps mulss mulpd mulsd divps divss divpd divsd minps minss minpd minsd maxps maxss maxpd maxsd sqrtps sqrtss sqrtpd sqrtsd cvtps2pd cvtpd2ps cvtss2sd cvtsd2ss cvtdq2ps cvtdq2pd cvtpi2ps cvtpi2pd cvtsi2ss cvtsi2sd cvtps2dq cvtpd2dq cvtps2pi cvtpd2pi cvtss2si cvtsd2si cvttps2dq cvttpd2dq cvttps2pi cvttpd2pi cvttss2si cvttsd2si rsqrtps rsqrtss rcpps rcpss extrq_r extrq_i insertq_r insertq_i haddps haddpd hsubps hsubpd addsubps addsubpd cmpeqps cmpeqss cmpeqpd cmpeqsd cmpltps cmpltss cmpltpd cmpltsd cmpleps cmpless cmplepd cmplesd cmpunordps cmpunordss cmpunordpd cmpunordsd cmpneqps cmpneqss cmpneqpd cmpneqsd cmpnltps cmpnltss cmpnltpd cmpnltsd cmpnleps cmpnless cmpnlepd cmpnlesd cmpordps cmpordss cmpordpd cmpordsd ucomiss comiss ucomisd comisd movmskps movmskpd pmovmskb_xmm packsswb_xmm packuswb_xmm packssdw_xmm punpcklbw_xmm punpcklwd_xmm punpckldq_xmm punpckhbw_xmm punpckhwd_xmm punpckhdq_xmm punpcklqdq_xmm punpckhqdq_xmm phaddw_xmm phaddd_xmm phaddsw_xmm phsubw_xmm phsubd_xmm phsubsw_xmm pabsb_xmm pabsw_xmm pabsd_xmm pmaddubsw_xmm pmulhrsw_xmm pshufb_xmm psignb_xmm psignw_xmm psignd_xmm palignr_xmm pblendvb_xmm blendvps_xmm blendvpd_xmm ptest_xmm pmovsxbw_xmm pmovsxbd_xmm pmovsxbq_xmm pmovsxwd_xmm pmovsxwq_xmm pmovsxdq_xmm pmovzxbw_xmm pmovzxbd_xmm pmovzxbq_xmm pmovzxwd_xmm pmovzxwq_xmm pmovzxdq_xmm pmuldq_xmm pcmpeqq_xmm packusdw_xmm pminsb_xmm pminsd_xmm pminuw_xmm pminud_xmm pmaxsb_xmm pmaxsd_xmm pmaxuw_xmm pmaxud_xmm pmulld_xmm phminposuw_xmm roundps_xmm roundpd_xmm roundss_xmm roundsd_xmm blendps_xmm blendpd_xmm pblendw_xmm dpps_xmm dppd_xmm mpsadbw_xmm pcmpgtq_xmm pcmpestri_xmm pcmpestrm_xmm pcmpistri_xmm pcmpistrm_xmm crc32 aesdec_xmm aesdeclast_xmm aesenc_xmm aesenclast_xmm aesimc_xmm aeskeygenassist_xmm pclmulqdq_xmm rclb rclw rcll rcrb rcrw rcrl trace_guest_mem_before_exec_proxy div_i32 rem_i32 divu_i32 remu_i32 div_i64 rem_i64 divu_i64 remu_i64 shl_i64 shr_i64 sar_i64 mulsh_i64 muluh_i64 clz_i32 ctz_i32 clz_i64 ctz_i64 clrsb_i32 clrsb_i64 ctpop_i32 ctpop_i64 lookup_tb_ptr exit_atomic atomic_cmpxchgb atomic_cmpxchgw_be atomic_cmpxchgw_le atomic_cmpxchgl_be atomic_cmpxchgl_le atomic_fetch_addb atomic_fetch_addw_le atomic_fetch_addw_be atomic_fetch_addl_le atomic_fetch_addl_be atomic_fetch_andb atomic_fetch_andw_le atomic_fetch_andw_be atomic_fetch_andl_le atomic_fetch_andl_be atomic_fetch_orb atomic_fetch_orw_le atomic_fetch_orw_be atomic_fetch_orl_le atomic_fetch_orl_be atomic_fetch_xorb atomic_fetch_xorw_le atomic_fetch_xorw_be atomic_fetch_xorl_le atomic_fetch_xorl_be atomic_add_fetchb atomic_add_fetchw_le atomic_add_fetchw_be atomic_add_fetchl_le atomic_add_fetchl_be atomic_and_fetchb atomic_and_fetchw_le atomic_and_fetchw_be atomic_and_fetchl_le atomic_and_fetchl_be atomic_or_fetchb atomic_or_fetchw_le atomic_or_fetchw_be atomic_or_fetchl_le atomic_or_fetchl_be atomic_xor_fetchb atomic_xor_fetchw_le atomic_xor_fetchw_be atomic_xor_fetchl_le atomic_xor_fetchl_be atomic_xchgb atomic_xchgw_le atomic_xchgw_be atomic_xchgl_le atomic_xchgl_be gvec_mov gvec_dup8 gvec_dup16 gvec_dup32 gvec_dup64 gvec_add8 gvec_add16 gvec_add32 gvec_add64 gvec_adds8 gvec_adds16 gvec_adds32 gvec_adds64 gvec_sub8 gvec_sub16 gvec_sub32 gvec_sub64 gvec_subs8 gvec_subs16 gvec_subs32 gvec_subs64 gvec_mul8 gvec_mul16 gvec_mul32 gvec_mul64 gvec_muls8 gvec_muls16 gvec_muls32 gvec_muls64 gvec_ssadd8 gvec_ssadd16 gvec_ssadd32 gvec_ssadd64 gvec_sssub8 gvec_sssub16 gvec_sssub32 gvec_sssub64 gvec_usadd8 gvec_usadd16 gvec_usadd32 gvec_usadd64 gvec_ussub8 gvec_ussub16 gvec_ussub32 gvec_ussub64 gvec_neg8 gvec_neg16 gvec_neg32 gvec_neg64 gvec_not gvec_and gvec_or gvec_xor gvec_andc gvec_orc gvec_ands gvec_xors gvec_ors gvec_shl8i gvec_shl16i gvec_shl32i gvec_shl64i gvec_shr8i gvec_shr16i gvec_shr32i gvec_shr64i gvec_sar8i gvec_sar16i gvec_sar32i gvec_sar64i gvec_eq8 gvec_eq16 gvec_eq32 gvec_eq64 gvec_ne8 gvec_ne16 gvec_ne32 gvec_ne64 gvec_lt8 gvec_lt16 gvec_lt32 gvec_lt64 gvec_le8 gvec_le16 gvec_le32 gvec_le64 gvec_ltu8 gvec_ltu16 gvec_ltu32 gvec_ltu64 gvec_leu8 gvec_leu16 gvec_leu32 gvec_leu64

aarch64_HELPERS := sxtb16 uxtb16 add_setq add_saturate sub_saturate add_usaturate sub_usaturate double_saturate sdiv udiv rbit sadd8 ssub8 ssub16 sadd16 saddsubx ssubaddx uadd8 usub8 usub16 uadd16 uaddsubx usubaddx qadd8 qsub8 qsub16 qadd16 qaddsubx qsubaddx shadd8 shsub8 shsub16 shadd16 shaddsubx shsubaddx uqadd8 uqsub8 uqsub16 uqadd16 uqaddsubx uqsubaddx uhadd8 uhsub8 uhsub16 uhadd16 uhaddsubx uhsubaddx ssat usat ssat16 usat16 usad8 sel_flags exception_internal exception_with_syndrome exception_bkpt_insn setend wfi wfe yield pre_hvc pre_smc check_breakpoints cpsr_write cpsr_write_eret cpsr_read v7m_msr v7m_mrs v7m_bxns v7m_blxns v7m_tt access_check_cp_reg set_cp_reg get_cp_reg set_cp_reg64 get_cp_reg64 msr_i_pstate clear_pstate_ss exception_return get_r13_banked set_r13_banked mrs_banked msr_banked get_user_reg set_user_reg vfp_get_fpscr vfp_set_fpscr vfp_adds vfp_addd vfp_subs vfp_subd vfp_muls vfp_muld vfp_divs vfp_divd vfp_maxs vfp_maxd vfp_mins vfp_mind vfp_maxnums vfp_maxnumd vfp_minnums vfp_minnumd vfp_negs vfp_negd vfp_abss vfp_absd vfp_sqrts vfp_sqrtd vfp_cmps vfp_cmpd vfp_cmpes vfp_cmped vfp_fcvtds vfp_fcvtsd vfp_uitoh vfp_uitos vfp_uitod vfp_sitoh vfp_sitos vfp_sitod vfp_touih vfp_touis vfp_touid vfp_touizh vfp_touizs vfp_touizd vfp_tosih vfp_tosis vfp_tosid vfp_tosizh vfp_tosizs vfp_tosizd vfp_toshs_round_to_zero vfp_tosls_round_to_zero vfp_touhs_round_to_zero vfp_touls_round_to_zero vfp_toshd_round_to_zero vfp_tosld_round_to_zero vfp_touhd_round_to_zero vfp_tould_round_to_zero vfp_toulh vfp_toslh vfp_toshs vfp_tosls vfp_tosqs vfp_touhs vfp_touls vfp_touqs vfp_toshd vfp_tosld vfp_tosqd vfp_touhd vfp_tould vfp_touqd vfp_shtos vfp_sltos vfp_sqtos vfp_uhtos vfp_ultos vfp_uqtos vfp_shtod vfp_sltod vfp_sqtod vfp_uhtod vfp_ultod vfp_uqtod vfp_sltoh vfp_ultoh set_rmode set_neon_rmode vfp_fcvt_f16_to_f32 vfp_fcvt_f32_to_f16 neon_fcvt_f16_to_f32 neon_fcvt_f32_to_f16 vfp_fcvt_f16_to_f64 vfp_fcvt_f64_to_f16 vfp_muladdd vfp_muladds recps_f32 rsqrts_f32 recpe_f16 recpe_f32 recpe_f64 rsqrte_f16 rsqrte_f32 rsqrte_f64 recpe_u32 rsqrte_u32 neon_tbl shl_cc shr_cc sar_cc ror_cc rints_exact rintd_exact rints rintd neon_qadd_u8 neon_qadd_s8 neon_qadd_u16 neon_qadd_s16 neon_qadd_u32 neon_qadd_s32 neon_uqadd_s8 neon_uqadd_s16 neon_uqadd_s32 neon_uqadd_s64 neon_sqadd_u8 neon_sqadd_u16 neon_sqadd_u32 neon_sqadd_u64 neon_qsub_u8 neon_qsub_s8 neon_qsub_u16 neon_qsub_s16 neon_qsub_u32 neon_qsub_s32 neon_qadd_u64 neon_qadd_s64 neon_qsub_u64 neon_qsub_s64 neon_hadd_s8 neon_hadd_u8 neon_hadd_s16 neon_hadd_u16 neon_hadd_s32 neon_hadd_u32 neon_rhadd_s8 neon_rhadd_u8 neon_rhadd_s16 neon_rhadd_u16 neon_rhadd_s32 neon_rhadd_u32 neon_hsub_s8 neon_hsub_u8 neon_hsub_s16 neon_hsub_u16 neon_hsub_s32 neon_hsub_u32 neon_cgt_u8 neon_cgt_s8 neon_cgt_u16 neon_cgt_s16 neon_cgt_u32 neon_cgt_s32 neon_cge_u8 neon_cge_s8 neon_cge_u16 neon_cge_s16 neon_cge_u32 neon_cge_s32 neon_min_u8 neon_min_s8 neon_min_u16 neon_min_s16 neon_min_u32 neon_min_s32 neon_max_u8 neon_max_s8 neon_max_u16 neon_max_s16 neon_max_u32 neon_max_s32 neon_pmin_u8 neon_pmin_s8 neon_pmin_u16 neon_pmin_s16 neon_pmax_u8 neon_pmax_s8 neon_pmax_u16 neon_pmax_s16 neon_abd_u8 neon_abd_s8 neon_abd_u16 neon_abd_s16 neon_abd_u32 neon_abd_s32 neon_shl_u8 neon_shl_s8 neon_shl_u16 neon_shl_s16 neon_shl_u32 neon_shl_s32 neon_shl_u64 neon_shl_s64 neon_rshl_u8 neon_rshl_s8 neon_rshl_u16 neon_rshl_s16 neon_rshl_u32 neon_rshl_s32 neon_rshl_u64 neon_rshl_s64 neon_qshl_u8 neon_qshl_s8 neon_qshl_u16 neon_qshl_s16 neon_qshl_u32 neon_qshl_s32 neon_qshl_u64 neon_qshl_s64 neon_qshlu_s8 neon_qshlu_s16 neon_qshlu_s32 neon_qshlu_s64 neon_qrshl_u8 neon_qrshl_s8 neon_qrshl_u16 neon_qrshl_s16 neon_qrshl_u32 neon_qrshl_s32 neon_qrshl_u64 neon_qrshl_s64 neon_add_u8 neon_add_u16 neon_padd_u8 neon_padd_u16 neon_sub_u8 neon_sub_u16 neon_mul_u8 neon_mul_u16 neon_mul_p8 neon_mull_p8 neon_tst_u8 neon_tst_u16 neon_tst_u32 neon_ceq_u8 neon_ceq_u16 neon_ceq_u32 neon_abs_s8 neon_abs_s16 neon_clz_u8 neon_clz_u16 neon_cls_s8 neon_cls_s16 neon_cls_s32 neon_cnt_u8 neon_rbit_u8 neon_qdmulh_s16 neon_qrdmulh_s16 neon_qrdmlah_s16 neon_qrdmlsh_s16 neon_qdmulh_s32 neon_qrdmulh_s32 neon_qrdmlah_s32 neon_qrdmlsh_s32 neon_narrow_u8 neon_narrow_u16 neon_unarrow_sat8 neon_narrow_sat_u8 neon_narrow_sat_s8 neon_unarrow_sat16 neon_narrow_sat_u16 neon_narrow_sat_s16 neon_unarrow_sat32 neon_narrow_sat_u32 neon_narrow_sat_s32 neon_narrow_high_u8 neon_narrow_high_u16 neon_narrow_round_high_u8 neon_narrow_round_high_u16 neon_widen_u8 neon_widen_s8 neon_widen_u16 neon_widen_s16 neon_addl_u16 neon_addl_u32 neon_paddl_u16 neon_paddl_u32 neon_subl_u16 neon_subl_u32 neon_addl_saturate_s32 neon_addl_saturate_s64 neon_abdl_u16 neon_abdl_s16 neon_abdl_u32 neon_abdl_s32 neon_abdl_u64 neon_abdl_s64 neon_mull_u8 neon_mull_s8 neon_mull_u16 neon_mull_s16 neon_negl_u16 neon_negl_u32 neon_qabs_s8 neon_qabs_s16 neon_qabs_s32 neon_qabs_s64 neon_qneg_s8 neon_qneg_s16 neon_qneg_s32 neon_qneg_s64 neon_abd_f32 neon_ceq_f32 neon_cge_f32 neon_cgt_f32 neon_acge_f32 neon_acgt_f32 neon_acge_f64 neon_acgt_f64 iwmmxt_maddsq iwmmxt_madduq iwmmxt_sadb iwmmxt_sadw iwmmxt_mulslw iwmmxt_mulshw iwmmxt_mululw iwmmxt_muluhw iwmmxt_macsw iwmmxt_macuw iwmmxt_setpsr_nz iwmmxt_unpacklb iwmmxt_unpacklw iwmmxt_unpackll iwmmxt_unpackhb iwmmxt_unpackhw iwmmxt_unpackhl iwmmxt_unpacklub iwmmxt_unpackluw iwmmxt_unpacklul iwmmxt_unpackhub iwmmxt_unpackhuw iwmmxt_unpackhul iwmmxt_unpacklsb iwmmxt_unpacklsw iwmmxt_unpacklsl iwmmxt_unpackhsb iwmmxt_unpackhsw iwmmxt_unpackhsl iwmmxt_cmpeqb iwmmxt_cmpeqw iwmmxt_cmpeql iwmmxt_cmpgtub iwmmxt_cmpgtuw iwmmxt_cmpgtul iwmmxt_cmpgtsb iwmmxt_cmpgtsw iwmmxt_cmpgtsl iwmmxt_minsb iwmmxt_minsw iwmmxt_minsl iwmmxt_minub iwmmxt_minuw iwmmxt_minul iwmmxt_maxsb iwmmxt_maxsw iwmmxt_maxsl iwmmxt_maxub iwmmxt_maxuw iwmmxt_maxul iwmmxt_subnb iwmmxt_subnw iwmmxt_subnl iwmmxt_addnb iwmmxt_addnw iwmmxt_addnl iwmmxt_subub iwmmxt_subuw iwmmxt_subul iwmmxt_addub iwmmxt_adduw iwmmxt_addul iwmmxt_subsb iwmmxt_subsw iwmmxt_subsl iwmmxt_addsb iwmmxt_addsw iwmmxt_addsl iwmmxt_avgb0 iwmmxt_avgb1 iwmmxt_avgw0 iwmmxt_avgw1 iwmmxt_align iwmmxt_insr iwmmxt_bcstb iwmmxt_bcstw iwmmxt_bcstl iwmmxt_addcb iwmmxt_addcw iwmmxt_addcl iwmmxt_msbb iwmmxt_msbw iwmmxt_msbl iwmmxt_srlw iwmmxt_srll iwmmxt_srlq iwmmxt_sllw iwmmxt_slll iwmmxt_sllq iwmmxt_sraw iwmmxt_sral iwmmxt_sraq iwmmxt_rorw iwmmxt_rorl iwmmxt_rorq iwmmxt_shufh iwmmxt_packuw iwmmxt_packul iwmmxt_packuq iwmmxt_packsw iwmmxt_packsl iwmmxt_packsq iwmmxt_muladdsl iwmmxt_muladdsw iwmmxt_muladdswl neon_unzip8 neon_unzip16 neon_qunzip8 neon_qunzip16 neon_qunzip32 neon_zip8 neon_zip16 neon_qzip8 neon_qzip16 neon_qzip32 crypto_aese crypto_aesmc crypto_sha1_3reg crypto_sha1h crypto_sha1su1 crypto_sha256h crypto_sha256h2 crypto_sha256su0 crypto_sha256su1 crypto_sha512h crypto_sha512h2 crypto_sha512su0 crypto_sha512su1 crypto_sm3tt crypto_sm3partw1 crypto_sm3partw2 crypto_sm4e crypto_sm4ekey crc32 crc32c dc_zva neon_pmull_64_lo neon_pmull_64_hi gvec_qrdmlah_s16 gvec_qrdmlsh_s16 gvec_qrdmlah_s32 gvec_qrdmlsh_s32 gvec_fcaddh gvec_fcadds gvec_fcaddd gvec_fcmlah gvec_fcmlah_idx gvec_fcmlas gvec_fcmlas_idx gvec_fcmlad udiv64 sdiv64 rbit64 vfp_cmps_a64 vfp_cmpes_a64 vfp_cmpd_a64 vfp_cmped_a64 simd_tbl vfp_mulxs vfp_mulxd neon_ceq_f64 neon_cge_f64 neon_cgt_f64 recpsf_f16 recpsf_f32 recpsf_f64 rsqrtsf_f16 rsqrtsf_f32 rsqrtsf_f64 neon_addlp_s8 neon_addlp_u8 neon_addlp_s16 neon_addlp_u16 frecpx_f64 frecpx_f32 frecpx_f16 fcvtx_f64_to_f32 crc32_64 crc32c_64 paired_cmpxchg64_le paired_cmpxchg64_le_parallel paired_cmpxchg64_be paired_cmpxchg64_be_parallel advsimd_maxh advsimd_minh advsimd_maxnumh advsimd_minnumh advsimd_addh advsimd_subh advsimd_mulh advsimd_divh advsimd_ceq_f16 advsimd_cge_f16 advsimd_cgt_f16 advsimd_acge_f16 advsimd_acgt_f16 advsimd_mulxh advsimd_muladdh advsimd_add2h advsimd_sub2h advsimd_mul2h advsimd_div2h advsimd_max2h advsimd_min2h advsimd_maxnum2h advsimd_minnum2h advsimd_mulx2h advsimd_muladd2h advsimd_rinth_exact advsimd_rinth advsimd_f16tosinth advsimd_f16touinth sqrt_f16 trace_guest_mem_before_exec_proxy div_i32 rem_i32 divu_i32 remu_i32 div_i64 rem_i64 divu_i64 remu_i64 shl_i64 shr_i64 sar_i64 mulsh_i64 muluh_i64 clz_i32 ctz_i32 clz_i64 ctz_i64 clrsb_i32 clrsb_i64 ctpop_i32 ctpop_i64 lookup_tb_ptr exit_atomic atomic_cmpxchgb atomic_cmpxchgw_be atomic_cmpxchgw_le atomic_cmpxchgl_be atomic_cmpxchgl_le atomic_fetch_addb atomic_fetch_addw_le atomic_fetch_addw_be atomic_fetch_addl_le atomic_fetch_addl_be atomic_fetch_andb atomic_fetch_andw_le atomic_fetch_andw_be atomic_fetch_andl_le atomic_fetch_andl_be atomic_fetch_orb atomic_fetch_orw_le atomic_fetch_orw_be atomic_fetch_orl_le atomic_fetch_orl_be atomic_fetch_xorb atomic_fetch_xorw_le atomic_fetch_xorw_be atomic_fetch_xorl_le atomic_fetch_xorl_be atomic_add_fetchb atomic_add_fetchw_le atomic_add_fetchw_be atomic_add_fetchl_le atomic_add_fetchl_be atomic_and_fetchb atomic_and_fetchw_le atomic_and_fetchw_be atomic_and_fetchl_le atomic_and_fetchl_be atomic_or_fetchb atomic_or_fetchw_le atomic_or_fetchw_be atomic_or_fetchl_le atomic_or_fetchl_be atomic_xor_fetchb atomic_xor_fetchw_le atomic_xor_fetchw_be atomic_xor_fetchl_le atomic_xor_fetchl_be atomic_xchgb atomic_xchgw_le atomic_xchgw_be atomic_xchgl_le atomic_xchgl_be gvec_mov gvec_dup8 gvec_dup16 gvec_dup32 gvec_dup64 gvec_add8 gvec_add16 gvec_add32 gvec_add64 gvec_adds8 gvec_adds16 gvec_adds32 gvec_adds64 gvec_sub8 gvec_sub16 gvec_sub32 gvec_sub64 gvec_subs8 gvec_subs16 gvec_subs32 gvec_subs64 gvec_mul8 gvec_mul16 gvec_mul32 gvec_mul64 gvec_muls8 gvec_muls16 gvec_muls32 gvec_muls64 gvec_ssadd8 gvec_ssadd16 gvec_ssadd32 gvec_ssadd64 gvec_sssub8 gvec_sssub16 gvec_sssub32 gvec_sssub64 gvec_usadd8 gvec_usadd16 gvec_usadd32 gvec_usadd64 gvec_ussub8 gvec_ussub16 gvec_ussub32 gvec_ussub64 gvec_neg8 gvec_neg16 gvec_neg32 gvec_neg64 gvec_not gvec_and gvec_or gvec_xor gvec_andc gvec_orc gvec_ands gvec_xors gvec_ors gvec_shl8i gvec_shl16i gvec_shl32i gvec_shl64i gvec_shr8i gvec_shr16i gvec_shr32i gvec_shr64i gvec_sar8i gvec_sar16i gvec_sar32i gvec_sar64i gvec_eq8 gvec_eq16 gvec_eq32 gvec_eq64 gvec_ne8 gvec_ne16 gvec_ne32 gvec_ne64 gvec_lt8 gvec_lt16 gvec_lt32 gvec_lt64 gvec_le8 gvec_le16 gvec_le32 gvec_le64 gvec_ltu8 gvec_ltu16 gvec_ltu32 gvec_ltu64 gvec_leu8 gvec_leu16 gvec_leu32 gvec_leu64

.PHONY: extract-helpers
extract-helpers: $(foreach helper,$($(ARCH)_HELPERS),lib/arch/$(ARCH)/helpers/$(helper).c)

define helper_template
.PHONY: lib/arch/$(ARCH)/helpers/$(1).c
lib/arch/$(ARCH)/helpers/$(1).c:
	-$(CLANG_EXTRICATE)/extract/bin/carbon-extract --src $(QEMU_SRC_DIR) --bin $(QEMU_BUILD_DIR) helper_$(1) > $$@
endef
$(foreach helper,$($(ARCH)_HELPERS),$(eval $(call helper_template,$(helper))))

.PHONY: build-helpers
build-helpers: $(foreach helper,$($(ARCH)_HELPERS),$(BINDIR)/$(helper).bc)

define build_helper_template
.PHONY: $(BINDIR)/$(1).bc
$(BINDIR)/$(1).bc:
	clang -o $$@ -c -emit-llvm -fPIC -g -Os -fno-stack-protector -Wall -Wno-macro-redefined -Wno-initializer-overrides $($(ARCH)_HELPER_CFLAGS) lib/arch/$(ARCH)/helpers/$(1).c
endef
$(foreach helper,$($(ARCH)_HELPERS),$(eval $(call build_helper_template,$(helper))))

.PHONY: check-helpers
check-helpers: $(foreach helper,$($(ARCH)_HELPERS),check-$(helper))

define check_helper_template
.PHONY: check-$(1)
check-$(1): $(BINDIR)/$(1).bc $(BINDIR)/check-helper
	-$(BINDIR)/check-helper $(1)
endef
$(foreach helper,$($(ARCH)_HELPERS),$(eval $(call check_helper_template,$(helper))))

#
# qemu configure command
#
# ./configure --target-list=x86_64-linux-user --cc=clang --host-cc=clang --cxx=clang++ --objcc=clang --disable-tcg-interpreter --disable-sdl --disable-gtk --disable-xen --disable-bluez --disable-kvm --disable-guest-agent --disable-vnc --disable-libssh2 --disable-jemalloc --disable-tcmalloc --disable-vhost-user --disable-opengl --disable-glusterfs --disable-gnutls --disable-nettle --disable-gcrypt --disable-curses --disable-libnfs --disable-libusb --disable-lzo --disable-bzip2 --disable-vhost-vsock --disable-smartcard --disable-usb-redir --disable-spice --disable-vhost-net --disable-snappy --disable-seccomp --disable-vhost-scsi --disable-virglrenderer --disable-vde --disable-rbd --disable-live-block-migration --disable-tools --disable-tpm --disable-numa --disable-cap-ng --disable-replication --disable-vte --disable-qom-cast-debug --disable-tpm --disable-xfsctl --disable-linux-aio --disable-attr --disable-coroutine-pool --disable-hax --enable-trace-backends=nop --disable-libxml2 --disable-vhost-crypto --disable-capstone --extra-cflags="-Xclang -load -Xclang $HOME/clang-extricate/collect/bin/carbon-collect.so -Xclang -add-plugin -Xclang carbon-collect -Xclang -plugin-arg-carbon-collect -Xclang $(pwd) -Xclang -plugin-arg-carbon-collect -Xclang $(pwd)"
#
