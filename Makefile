# this just obtains the directory this Makefile resides in
JOVE_ROOT_DIR := $(shell cd $(dir $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST)));pwd)

_LLVM_DIR         := $(JOVE_ROOT_DIR)/third_party/llvm-project
_LLVM_INSTALL_DIR := $(_LLVM_DIR)/install

_LLVM_CONFIG := $(_LLVM_INSTALL_DIR)/bin/llvm-config
_LLVM_DIS    := $(_LLVM_INSTALL_DIR)/bin/llvm-dis
_LLVM_CC     := $(_LLVM_INSTALL_DIR)/bin/clang
_LLVM_CXX    := $(_LLVM_INSTALL_DIR)/bin/clang++

LLVM_COMPONENTS := object \
                   native \
                   passes \
                   objcarcopts \
                   coroutines \
                   symbolize

GCC_TARGET := $(shell gcc -dumpmachine | tr -cd '0-9_a-z-')

ifeq "$(GCC_TARGET)" "x86_64-pc-linux-gnu"
ARCH := x86_64
else ifeq "$(GCC_TARGET)" "x86_64-linux-gnu"
ARCH := x86_64
else ifeq "$(GCC_TARGET)" "i686-pc-linux-gnu"
ARCH := i386
else ifeq "$(GCC_TARGET)" "i686-linux-gnu"
ARCH := i386
else ifeq "$(GCC_TARGET)" "aarch64-unknown-linux-gnu"
ARCH := aarch64
else ifeq "$(GCC_TARGET)" "armv7l-unknown-linux-gnueabihf"
ARCH := arm
else ifeq "$(GCC_TARGET)" "mips64el-linux-gnuabi64"
ARCH := mips64el
else ifeq "$(GCC_TARGET)" "mipsel-linux-gnu"
ARCH := mipsel
else
$(error "Unknown GCC target $(GCC_TARGET)")
endif

$(info GCC TARGET $(GCC_TARGET))
$(info ARCH       $(ARCH))

#
# build flags
#
CXXFLAGS := -std=gnu++17 \
            -Wall \
            -Wno-macro-redefined \
            -Wno-shift-count-negative \
            -Wno-initializer-overrides \
            -Wno-c99-designator \
            -fno-omit-frame-pointer \
            -fvisibility=hidden \
            -fexceptions \
            -fwrapv \
            -fno-common \
            -Ofast \
            -g \
            -I include \
            -I lib \
            -I lib/arch/$(ARCH) \
            -I $(_LLVM_INSTALL_DIR)/include \
            -D___JOVE_ARCH_NAME=\"$(ARCH)\" \
            -D_GNU_SOURCE \
            -DBOOST_ICL_USE_STATIC_BOUNDED_INTERVALS

LDFLAGS := -Wl,--no-undefined \
           $(shell $(_LLVM_CONFIG) --ldflags) \
           -Wl,--push-state \
           -Wl,--as-needed \
           $(shell $(_LLVM_CONFIG) --libs $(LLVM_COMPONENTS)) \
           -Wl,--pop-state, \
           $(shell pkg-config --libs glib-2.0) \
           -ldl \
           -pthread \
           -ltinfo \
           -lm \
           -lz \
           -lboost_filesystem \
           -lboost_system \
           -lboost_serialization \
           -fuse-ld=gold

#
# important directories
#
BINDIR := bin

#
# find tools
#
TOOLSRCDIR := tools
TOOLSRCS   := $(wildcard $(TOOLSRCDIR)/*.cpp)
TOOLS      := $(patsubst $(TOOLSRCDIR)/%.cpp,%,$(TOOLSRCS))
TOOLBINS   := $(foreach tool,$(TOOLS),$(BINDIR)/$(tool))
TOOLDEPS   := $(foreach tool,$(TOOLS),$(BINDIR)/$(tool).d)

#
# find utils
#
UTILSRCDIR := utils
UTILSRCS   := $(wildcard $(UTILSRCDIR)/*.cpp)
UTILS      := $(patsubst $(UTILSRCDIR)/%.cpp,%,$(UTILSRCS))
UTILBINS   := $(foreach util,$(UTILS),$(BINDIR)/$(util))
UTILDEPS   := $(foreach util,$(UTILS),$(BINDIR)/$(util).d)

JOVE_RT_SONAME := libjove_rt.so
JOVE_RT_SO     := $(JOVE_RT_SONAME).0
JOVE_RT        := $(BINDIR)/$(JOVE_RT_SO)

JOVE_DYN_PRELOAD_SONAME := libjove_dyn_preload.so
JOVE_DYN_PRELOAD_SO     := $(JOVE_DYN_PRELOAD_SONAME).0
JOVE_DYN_PRELOAD        := $(BINDIR)/$(JOVE_DYN_PRELOAD_SO)

#
# TCG helpers (for each architecture)
#
x86_64_HELPERS := cc_compute_all cc_compute_c write_eflags read_eflags divb_AL idivb_AL divw_AX idivw_AX divl_EAX idivl_EAX divq_EAX idivq_EAX cr4_testbit bndck bndldx32 bndldx64 bndstx32 bndstx64 bnd_jmp aam aad aaa aas daa das lsl lar verr verw lldt ltr load_seg ljmp_protected lcall_real lcall_protected iret_real iret_protected lret_protected read_crN write_crN lmsw clts set_dr get_dr invlpg sysenter sysexit syscall sysret hlt monitor mwait pause debug reset_rf raise_interrupt raise_exception cli sti clac stac boundw boundl rsm into cmpxchg8b_unlocked cmpxchg8b cmpxchg16b_unlocked cmpxchg16b single_step rechecking_single_step cpuid rdtsc rdtscp rdpmc rdmsr wrmsr check_iob check_iow check_iol outb inb outw inw outl inl bpt_io svm_check_intercept_param svm_check_io vmrun vmmcall vmload vmsave stgi clgi skinit invlpga flds_FT0 fldl_FT0 fildl_FT0 flds_ST0 fldl_ST0 fildl_ST0 fildll_ST0 fsts_ST0 fstl_ST0 fist_ST0 fistl_ST0 fistll_ST0 fistt_ST0 fisttl_ST0 fisttll_ST0 fldt_ST0 fstt_ST0 fpush fpop fdecstp fincstp ffree_STN fmov_ST0_FT0 fmov_FT0_STN fmov_ST0_STN fmov_STN_ST0 fxchg_ST0_STN fcom_ST0_FT0 fucom_ST0_FT0 fcomi_ST0_FT0 fucomi_ST0_FT0 fadd_ST0_FT0 fmul_ST0_FT0 fsub_ST0_FT0 fsubr_ST0_FT0 fdiv_ST0_FT0 fdivr_ST0_FT0 fadd_STN_ST0 fmul_STN_ST0 fsub_STN_ST0 fsubr_STN_ST0 fdiv_STN_ST0 fdivr_STN_ST0 fchs_ST0 fabs_ST0 fxam_ST0 fld1_ST0 fldl2t_ST0 fldl2e_ST0 fldpi_ST0 fldlg2_ST0 fldln2_ST0 fldz_ST0 fldz_FT0 fnstsw fnstcw fldcw fclex fwait fninit fbld_ST0 fbst_ST0 f2xm1 fyl2x fptan fpatan fxtract fprem1 fprem fyl2xp1 fsqrt fsincos frndint fscale fsin fcos fstenv fldenv fsave frstor fxsave fxrstor xsave xsaveopt xrstor xgetbv xsetbv rdpkru wrpkru pdep pext ldmxcsr enter_mmx emms movq psrlw_mmx psraw_mmx psllw_mmx psrld_mmx psrad_mmx pslld_mmx psrlq_mmx psllq_mmx paddb_mmx paddw_mmx paddl_mmx paddq_mmx psubb_mmx psubw_mmx psubl_mmx psubq_mmx paddusb_mmx paddsb_mmx psubusb_mmx psubsb_mmx paddusw_mmx paddsw_mmx psubusw_mmx psubsw_mmx pminub_mmx pmaxub_mmx pminsw_mmx pmaxsw_mmx pand_mmx pandn_mmx por_mmx pxor_mmx pcmpgtb_mmx pcmpgtw_mmx pcmpgtl_mmx pcmpeqb_mmx pcmpeqw_mmx pcmpeql_mmx pmullw_mmx pmulhrw_mmx pmulhuw_mmx pmulhw_mmx pavgb_mmx pavgw_mmx pmuludq_mmx pmaddwd_mmx psadbw_mmx maskmov_mmx movl_mm_T0_mmx movq_mm_T0_mmx pshufw_mmx pmovmskb_mmx packsswb_mmx packuswb_mmx packssdw_mmx punpcklbw_mmx punpcklwd_mmx punpckldq_mmx punpckhbw_mmx punpckhwd_mmx punpckhdq_mmx pi2fd pi2fw pf2id pf2iw pfacc pfadd pfcmpeq pfcmpge pfcmpgt pfmax pfmin pfmul pfnacc pfpnacc pfrcp pfrsqrt pfsub pfsubr pswapd phaddw_mmx phaddd_mmx phaddsw_mmx phsubw_mmx phsubd_mmx phsubsw_mmx pabsb_mmx pabsw_mmx pabsd_mmx pmaddubsw_mmx pmulhrsw_mmx pshufb_mmx psignb_mmx psignw_mmx psignd_mmx palignr_mmx psrlw_xmm psraw_xmm psllw_xmm psrld_xmm psrad_xmm pslld_xmm psrlq_xmm psllq_xmm psrldq_xmm pslldq_xmm paddb_xmm paddw_xmm paddl_xmm paddq_xmm psubb_xmm psubw_xmm psubl_xmm psubq_xmm paddusb_xmm paddsb_xmm psubusb_xmm psubsb_xmm paddusw_xmm paddsw_xmm psubusw_xmm psubsw_xmm pminub_xmm pmaxub_xmm pminsw_xmm pmaxsw_xmm pand_xmm pandn_xmm por_xmm pxor_xmm pcmpgtb_xmm pcmpgtw_xmm pcmpgtl_xmm pcmpeqb_xmm pcmpeqw_xmm pcmpeql_xmm pmullw_xmm pmulhuw_xmm pmulhw_xmm pavgb_xmm pavgw_xmm pmuludq_xmm pmaddwd_xmm psadbw_xmm maskmov_xmm movl_mm_T0_xmm movq_mm_T0_xmm shufps shufpd pshufd_xmm pshuflw_xmm pshufhw_xmm addps addss addpd addsd subps subss subpd subsd mulps mulss mulpd mulsd divps divss divpd divsd minps minss minpd minsd maxps maxss maxpd maxsd sqrtps sqrtss sqrtpd sqrtsd cvtps2pd cvtpd2ps cvtss2sd cvtsd2ss cvtdq2ps cvtdq2pd cvtpi2ps cvtpi2pd cvtsi2ss cvtsi2sd cvtsq2ss cvtsq2sd cvtps2dq cvtpd2dq cvtps2pi cvtpd2pi cvtss2si cvtsd2si cvtss2sq cvtsd2sq cvttps2dq cvttpd2dq cvttps2pi cvttpd2pi cvttss2si cvttsd2si cvttss2sq cvttsd2sq rsqrtps rsqrtss rcpps rcpss extrq_r extrq_i insertq_r insertq_i haddps haddpd hsubps hsubpd addsubps addsubpd cmpeqps cmpeqss cmpeqpd cmpeqsd cmpltps cmpltss cmpltpd cmpltsd cmpleps cmpless cmplepd cmplesd cmpunordps cmpunordss cmpunordpd cmpunordsd cmpneqps cmpneqss cmpneqpd cmpneqsd cmpnltps cmpnltss cmpnltpd cmpnltsd cmpnleps cmpnless cmpnlepd cmpnlesd cmpordps cmpordss cmpordpd cmpordsd ucomiss comiss ucomisd comisd movmskps movmskpd pmovmskb_xmm packsswb_xmm packuswb_xmm packssdw_xmm punpcklbw_xmm punpcklwd_xmm punpckldq_xmm punpckhbw_xmm punpckhwd_xmm punpckhdq_xmm punpcklqdq_xmm punpckhqdq_xmm phaddw_xmm phaddd_xmm phaddsw_xmm phsubw_xmm phsubd_xmm phsubsw_xmm pabsb_xmm pabsw_xmm pabsd_xmm pmaddubsw_xmm pmulhrsw_xmm pshufb_xmm psignb_xmm psignw_xmm psignd_xmm palignr_xmm pblendvb_xmm blendvps_xmm blendvpd_xmm ptest_xmm pmovsxbw_xmm pmovsxbd_xmm pmovsxbq_xmm pmovsxwd_xmm pmovsxwq_xmm pmovsxdq_xmm pmovzxbw_xmm pmovzxbd_xmm pmovzxbq_xmm pmovzxwd_xmm pmovzxwq_xmm pmovzxdq_xmm pmuldq_xmm pcmpeqq_xmm packusdw_xmm pminsb_xmm pminsd_xmm pminuw_xmm pminud_xmm pmaxsb_xmm pmaxsd_xmm pmaxuw_xmm pmaxud_xmm pmulld_xmm phminposuw_xmm roundps_xmm roundpd_xmm roundss_xmm roundsd_xmm blendps_xmm blendpd_xmm pblendw_xmm dpps_xmm dppd_xmm mpsadbw_xmm pcmpgtq_xmm pcmpestri_xmm pcmpestrm_xmm pcmpistri_xmm pcmpistrm_xmm crc32 aesdec_xmm aesdeclast_xmm aesenc_xmm aesenclast_xmm aesimc_xmm aeskeygenassist_xmm pclmulqdq_xmm rclb rclw rcll rcrb rcrw rcrl rclq rcrq rdrand trace_guest_mem_before_exec_proxy div_i32 rem_i32 divu_i32 remu_i32 div_i64 rem_i64 divu_i64 remu_i64 shl_i64 shr_i64 sar_i64 mulsh_i64 muluh_i64 clz_i32 ctz_i32 clz_i64 ctz_i64 clrsb_i32 clrsb_i64 ctpop_i32 ctpop_i64 lookup_tb_ptr exit_atomic atomic_cmpxchgb atomic_cmpxchgw_be atomic_cmpxchgw_le atomic_cmpxchgl_be atomic_cmpxchgl_le atomic_cmpxchgq_be atomic_cmpxchgq_le atomic_fetch_addb atomic_fetch_addw_le atomic_fetch_addw_be atomic_fetch_addl_le atomic_fetch_addl_be atomic_fetch_addq_le atomic_fetch_addq_be atomic_fetch_andb atomic_fetch_andw_le atomic_fetch_andw_be atomic_fetch_andl_le atomic_fetch_andl_be atomic_fetch_andq_le atomic_fetch_andq_be atomic_fetch_orb atomic_fetch_orw_le atomic_fetch_orw_be atomic_fetch_orl_le atomic_fetch_orl_be atomic_fetch_orq_le atomic_fetch_orq_be atomic_fetch_xorb atomic_fetch_xorw_le atomic_fetch_xorw_be atomic_fetch_xorl_le atomic_fetch_xorl_be atomic_fetch_xorq_le atomic_fetch_xorq_be atomic_fetch_sminb atomic_fetch_sminw_le atomic_fetch_sminw_be atomic_fetch_sminl_le atomic_fetch_sminl_be atomic_fetch_sminq_le atomic_fetch_sminq_be atomic_fetch_uminb atomic_fetch_uminw_le atomic_fetch_uminw_be atomic_fetch_uminl_le atomic_fetch_uminl_be atomic_fetch_uminq_le atomic_fetch_uminq_be atomic_fetch_smaxb atomic_fetch_smaxw_le atomic_fetch_smaxw_be atomic_fetch_smaxl_le atomic_fetch_smaxl_be atomic_fetch_smaxq_le atomic_fetch_smaxq_be atomic_fetch_umaxb atomic_fetch_umaxw_le atomic_fetch_umaxw_be atomic_fetch_umaxl_le atomic_fetch_umaxl_be atomic_fetch_umaxq_le atomic_fetch_umaxq_be atomic_add_fetchb atomic_add_fetchw_le atomic_add_fetchw_be atomic_add_fetchl_le atomic_add_fetchl_be atomic_add_fetchq_le atomic_add_fetchq_be atomic_and_fetchb atomic_and_fetchw_le atomic_and_fetchw_be atomic_and_fetchl_le atomic_and_fetchl_be atomic_and_fetchq_le atomic_and_fetchq_be atomic_or_fetchb atomic_or_fetchw_le atomic_or_fetchw_be atomic_or_fetchl_le atomic_or_fetchl_be atomic_or_fetchq_le atomic_or_fetchq_be atomic_xor_fetchb atomic_xor_fetchw_le atomic_xor_fetchw_be atomic_xor_fetchl_le atomic_xor_fetchl_be atomic_xor_fetchq_le atomic_xor_fetchq_be atomic_smin_fetchb atomic_smin_fetchw_le atomic_smin_fetchw_be atomic_smin_fetchl_le atomic_smin_fetchl_be atomic_smin_fetchq_le atomic_smin_fetchq_be atomic_umin_fetchb atomic_umin_fetchw_le atomic_umin_fetchw_be atomic_umin_fetchl_le atomic_umin_fetchl_be atomic_umin_fetchq_le atomic_umin_fetchq_be atomic_smax_fetchb atomic_smax_fetchw_le atomic_smax_fetchw_be atomic_smax_fetchl_le atomic_smax_fetchl_be atomic_smax_fetchq_le atomic_smax_fetchq_be atomic_umax_fetchb atomic_umax_fetchw_le atomic_umax_fetchw_be atomic_umax_fetchl_le atomic_umax_fetchl_be atomic_umax_fetchq_le atomic_umax_fetchq_be atomic_xchgb atomic_xchgw_le atomic_xchgw_be atomic_xchgl_le atomic_xchgl_be atomic_xchgq_le atomic_xchgq_be gvec_mov gvec_dup8 gvec_dup16 gvec_dup32 gvec_dup64 gvec_add8 gvec_add16 gvec_add32 gvec_add64 gvec_adds8 gvec_adds16 gvec_adds32 gvec_adds64 gvec_sub8 gvec_sub16 gvec_sub32 gvec_sub64 gvec_subs8 gvec_subs16 gvec_subs32 gvec_subs64 gvec_mul8 gvec_mul16 gvec_mul32 gvec_mul64 gvec_muls8 gvec_muls16 gvec_muls32 gvec_muls64 gvec_ssadd8 gvec_ssadd16 gvec_ssadd32 gvec_ssadd64 gvec_sssub8 gvec_sssub16 gvec_sssub32 gvec_sssub64 gvec_usadd8 gvec_usadd16 gvec_usadd32 gvec_usadd64 gvec_ussub8 gvec_ussub16 gvec_ussub32 gvec_ussub64 gvec_smin8 gvec_smin16 gvec_smin32 gvec_smin64 gvec_smax8 gvec_smax16 gvec_smax32 gvec_smax64 gvec_umin8 gvec_umin16 gvec_umin32 gvec_umin64 gvec_umax8 gvec_umax16 gvec_umax32 gvec_umax64 gvec_neg8 gvec_neg16 gvec_neg32 gvec_neg64 gvec_abs8 gvec_abs16 gvec_abs32 gvec_abs64 gvec_not gvec_and gvec_or gvec_xor gvec_andc gvec_orc gvec_nand gvec_nor gvec_eqv gvec_ands gvec_xors gvec_ors gvec_shl8i gvec_shl16i gvec_shl32i gvec_shl64i gvec_shr8i gvec_shr16i gvec_shr32i gvec_shr64i gvec_sar8i gvec_sar16i gvec_sar32i gvec_sar64i gvec_shl8v gvec_shl16v gvec_shl32v gvec_shl64v gvec_shr8v gvec_shr16v gvec_shr32v gvec_shr64v gvec_sar8v gvec_sar16v gvec_sar32v gvec_sar64v gvec_eq8 gvec_eq16 gvec_eq32 gvec_eq64 gvec_ne8 gvec_ne16 gvec_ne32 gvec_ne64 gvec_lt8 gvec_lt16 gvec_lt32 gvec_lt64 gvec_le8 gvec_le16 gvec_le32 gvec_le64 gvec_ltu8 gvec_ltu16 gvec_ltu32 gvec_ltu64 gvec_leu8 gvec_leu16 gvec_leu32 gvec_leu64 gvec_bitsel

i386_HELPERS := cc_compute_all cc_compute_c write_eflags read_eflags divb_AL idivb_AL divw_AX idivw_AX divl_EAX idivl_EAX cr4_testbit bndck bndldx32 bndldx64 bndstx32 bndstx64 bnd_jmp aam aad aaa aas daa das lsl lar verr verw lldt ltr load_seg ljmp_protected lcall_real lcall_protected iret_real iret_protected lret_protected read_crN write_crN lmsw clts set_dr get_dr invlpg sysenter sysexit hlt monitor mwait pause debug reset_rf raise_interrupt raise_exception cli sti clac stac boundw boundl rsm into cmpxchg8b_unlocked cmpxchg8b single_step rechecking_single_step cpuid rdtsc rdtscp rdpmc rdmsr wrmsr check_iob check_iow check_iol outb inb outw inw outl inl bpt_io svm_check_intercept_param svm_check_io vmrun vmmcall vmload vmsave stgi clgi skinit invlpga flds_FT0 fldl_FT0 fildl_FT0 flds_ST0 fldl_ST0 fildl_ST0 fildll_ST0 fsts_ST0 fstl_ST0 fist_ST0 fistl_ST0 fistll_ST0 fistt_ST0 fisttl_ST0 fisttll_ST0 fldt_ST0 fstt_ST0 fpush fpop fdecstp fincstp ffree_STN fmov_ST0_FT0 fmov_FT0_STN fmov_ST0_STN fmov_STN_ST0 fxchg_ST0_STN fcom_ST0_FT0 fucom_ST0_FT0 fcomi_ST0_FT0 fucomi_ST0_FT0 fadd_ST0_FT0 fmul_ST0_FT0 fsub_ST0_FT0 fsubr_ST0_FT0 fdiv_ST0_FT0 fdivr_ST0_FT0 fadd_STN_ST0 fmul_STN_ST0 fsub_STN_ST0 fsubr_STN_ST0 fdiv_STN_ST0 fdivr_STN_ST0 fchs_ST0 fabs_ST0 fxam_ST0 fld1_ST0 fldl2t_ST0 fldl2e_ST0 fldpi_ST0 fldlg2_ST0 fldln2_ST0 fldz_ST0 fldz_FT0 fnstsw fnstcw fldcw fclex fwait fninit fbld_ST0 fbst_ST0 f2xm1 fyl2x fptan fpatan fxtract fprem1 fprem fyl2xp1 fsqrt fsincos frndint fscale fsin fcos fstenv fldenv fsave frstor fxsave fxrstor xsave xsaveopt xrstor xgetbv xsetbv rdpkru wrpkru pdep pext ldmxcsr enter_mmx emms movq psrlw_mmx psraw_mmx psllw_mmx psrld_mmx psrad_mmx pslld_mmx psrlq_mmx psllq_mmx paddb_mmx paddw_mmx paddl_mmx paddq_mmx psubb_mmx psubw_mmx psubl_mmx psubq_mmx paddusb_mmx paddsb_mmx psubusb_mmx psubsb_mmx paddusw_mmx paddsw_mmx psubusw_mmx psubsw_mmx pminub_mmx pmaxub_mmx pminsw_mmx pmaxsw_mmx pand_mmx pandn_mmx por_mmx pxor_mmx pcmpgtb_mmx pcmpgtw_mmx pcmpgtl_mmx pcmpeqb_mmx pcmpeqw_mmx pcmpeql_mmx pmullw_mmx pmulhrw_mmx pmulhuw_mmx pmulhw_mmx pavgb_mmx pavgw_mmx pmuludq_mmx pmaddwd_mmx psadbw_mmx maskmov_mmx movl_mm_T0_mmx pshufw_mmx pmovmskb_mmx packsswb_mmx packuswb_mmx packssdw_mmx punpcklbw_mmx punpcklwd_mmx punpckldq_mmx punpckhbw_mmx punpckhwd_mmx punpckhdq_mmx pi2fd pi2fw pf2id pf2iw pfacc pfadd pfcmpeq pfcmpge pfcmpgt pfmax pfmin pfmul pfnacc pfpnacc pfrcp pfrsqrt pfsub pfsubr pswapd phaddw_mmx phaddd_mmx phaddsw_mmx phsubw_mmx phsubd_mmx phsubsw_mmx pabsb_mmx pabsw_mmx pabsd_mmx pmaddubsw_mmx pmulhrsw_mmx pshufb_mmx psignb_mmx psignw_mmx psignd_mmx palignr_mmx psrlw_xmm psraw_xmm psllw_xmm psrld_xmm psrad_xmm pslld_xmm psrlq_xmm psllq_xmm psrldq_xmm pslldq_xmm paddb_xmm paddw_xmm paddl_xmm paddq_xmm psubb_xmm psubw_xmm psubl_xmm psubq_xmm paddusb_xmm paddsb_xmm psubusb_xmm psubsb_xmm paddusw_xmm paddsw_xmm psubusw_xmm psubsw_xmm pminub_xmm pmaxub_xmm pminsw_xmm pmaxsw_xmm pand_xmm pandn_xmm por_xmm pxor_xmm pcmpgtb_xmm pcmpgtw_xmm pcmpgtl_xmm pcmpeqb_xmm pcmpeqw_xmm pcmpeql_xmm pmullw_xmm pmulhuw_xmm pmulhw_xmm pavgb_xmm pavgw_xmm pmuludq_xmm pmaddwd_xmm psadbw_xmm maskmov_xmm movl_mm_T0_xmm shufps shufpd pshufd_xmm pshuflw_xmm pshufhw_xmm addps addss addpd addsd subps subss subpd subsd mulps mulss mulpd mulsd divps divss divpd divsd minps minss minpd minsd maxps maxss maxpd maxsd sqrtps sqrtss sqrtpd sqrtsd cvtps2pd cvtpd2ps cvtss2sd cvtsd2ss cvtdq2ps cvtdq2pd cvtpi2ps cvtpi2pd cvtsi2ss cvtsi2sd cvtps2dq cvtpd2dq cvtps2pi cvtpd2pi cvtss2si cvtsd2si cvttps2dq cvttpd2dq cvttps2pi cvttpd2pi cvttss2si cvttsd2si rsqrtps rsqrtss rcpps rcpss extrq_r extrq_i insertq_r insertq_i haddps haddpd hsubps hsubpd addsubps addsubpd cmpeqps cmpeqss cmpeqpd cmpeqsd cmpltps cmpltss cmpltpd cmpltsd cmpleps cmpless cmplepd cmplesd cmpunordps cmpunordss cmpunordpd cmpunordsd cmpneqps cmpneqss cmpneqpd cmpneqsd cmpnltps cmpnltss cmpnltpd cmpnltsd cmpnleps cmpnless cmpnlepd cmpnlesd cmpordps cmpordss cmpordpd cmpordsd ucomiss comiss ucomisd comisd movmskps movmskpd pmovmskb_xmm packsswb_xmm packuswb_xmm packssdw_xmm punpcklbw_xmm punpcklwd_xmm punpckldq_xmm punpckhbw_xmm punpckhwd_xmm punpckhdq_xmm punpcklqdq_xmm punpckhqdq_xmm phaddw_xmm phaddd_xmm phaddsw_xmm phsubw_xmm phsubd_xmm phsubsw_xmm pabsb_xmm pabsw_xmm pabsd_xmm pmaddubsw_xmm pmulhrsw_xmm pshufb_xmm psignb_xmm psignw_xmm psignd_xmm palignr_xmm pblendvb_xmm blendvps_xmm blendvpd_xmm ptest_xmm pmovsxbw_xmm pmovsxbd_xmm pmovsxbq_xmm pmovsxwd_xmm pmovsxwq_xmm pmovsxdq_xmm pmovzxbw_xmm pmovzxbd_xmm pmovzxbq_xmm pmovzxwd_xmm pmovzxwq_xmm pmovzxdq_xmm pmuldq_xmm pcmpeqq_xmm packusdw_xmm pminsb_xmm pminsd_xmm pminuw_xmm pminud_xmm pmaxsb_xmm pmaxsd_xmm pmaxuw_xmm pmaxud_xmm pmulld_xmm phminposuw_xmm roundps_xmm roundpd_xmm roundss_xmm roundsd_xmm blendps_xmm blendpd_xmm pblendw_xmm dpps_xmm dppd_xmm mpsadbw_xmm pcmpgtq_xmm pcmpestri_xmm pcmpestrm_xmm pcmpistri_xmm pcmpistrm_xmm crc32 aesdec_xmm aesdeclast_xmm aesenc_xmm aesenclast_xmm aesimc_xmm aeskeygenassist_xmm pclmulqdq_xmm rclb rclw rcll rcrb rcrw rcrl rdrand trace_guest_mem_before_exec_proxy div_i32 rem_i32 divu_i32 remu_i32 div_i64 rem_i64 divu_i64 remu_i64 shl_i64 shr_i64 sar_i64 mulsh_i64 muluh_i64 clz_i32 ctz_i32 clz_i64 ctz_i64 clrsb_i32 clrsb_i64 ctpop_i32 ctpop_i64 lookup_tb_ptr exit_atomic atomic_cmpxchgb atomic_cmpxchgw_be atomic_cmpxchgw_le atomic_cmpxchgl_be atomic_cmpxchgl_le atomic_cmpxchgq_be atomic_cmpxchgq_le atomic_fetch_addb atomic_fetch_addw_le atomic_fetch_addw_be atomic_fetch_addl_le atomic_fetch_addl_be atomic_fetch_addq_le atomic_fetch_addq_be atomic_fetch_andb atomic_fetch_andw_le atomic_fetch_andw_be atomic_fetch_andl_le atomic_fetch_andl_be atomic_fetch_andq_le atomic_fetch_andq_be atomic_fetch_orb atomic_fetch_orw_le atomic_fetch_orw_be atomic_fetch_orl_le atomic_fetch_orl_be atomic_fetch_orq_le atomic_fetch_orq_be atomic_fetch_xorb atomic_fetch_xorw_le atomic_fetch_xorw_be atomic_fetch_xorl_le atomic_fetch_xorl_be atomic_fetch_xorq_le atomic_fetch_xorq_be atomic_fetch_sminb atomic_fetch_sminw_le atomic_fetch_sminw_be atomic_fetch_sminl_le atomic_fetch_sminl_be atomic_fetch_sminq_le atomic_fetch_sminq_be atomic_fetch_uminb atomic_fetch_uminw_le atomic_fetch_uminw_be atomic_fetch_uminl_le atomic_fetch_uminl_be atomic_fetch_uminq_le atomic_fetch_uminq_be atomic_fetch_smaxb atomic_fetch_smaxw_le atomic_fetch_smaxw_be atomic_fetch_smaxl_le atomic_fetch_smaxl_be atomic_fetch_smaxq_le atomic_fetch_smaxq_be atomic_fetch_umaxb atomic_fetch_umaxw_le atomic_fetch_umaxw_be atomic_fetch_umaxl_le atomic_fetch_umaxl_be atomic_fetch_umaxq_le atomic_fetch_umaxq_be atomic_add_fetchb atomic_add_fetchw_le atomic_add_fetchw_be atomic_add_fetchl_le atomic_add_fetchl_be atomic_add_fetchq_le atomic_add_fetchq_be atomic_and_fetchb atomic_and_fetchw_le atomic_and_fetchw_be atomic_and_fetchl_le atomic_and_fetchl_be atomic_and_fetchq_le atomic_and_fetchq_be atomic_or_fetchb atomic_or_fetchw_le atomic_or_fetchw_be atomic_or_fetchl_le atomic_or_fetchl_be atomic_or_fetchq_le atomic_or_fetchq_be atomic_xor_fetchb atomic_xor_fetchw_le atomic_xor_fetchw_be atomic_xor_fetchl_le atomic_xor_fetchl_be atomic_xor_fetchq_le atomic_xor_fetchq_be atomic_smin_fetchb atomic_smin_fetchw_le atomic_smin_fetchw_be atomic_smin_fetchl_le atomic_smin_fetchl_be atomic_smin_fetchq_le atomic_smin_fetchq_be atomic_umin_fetchb atomic_umin_fetchw_le atomic_umin_fetchw_be atomic_umin_fetchl_le atomic_umin_fetchl_be atomic_umin_fetchq_le atomic_umin_fetchq_be atomic_smax_fetchb atomic_smax_fetchw_le atomic_smax_fetchw_be atomic_smax_fetchl_le atomic_smax_fetchl_be atomic_smax_fetchq_le atomic_smax_fetchq_be atomic_umax_fetchb atomic_umax_fetchw_le atomic_umax_fetchw_be atomic_umax_fetchl_le atomic_umax_fetchl_be atomic_umax_fetchq_le atomic_umax_fetchq_be atomic_xchgb atomic_xchgw_le atomic_xchgw_be atomic_xchgl_le atomic_xchgl_be atomic_xchgq_le atomic_xchgq_be gvec_mov gvec_dup8 gvec_dup16 gvec_dup32 gvec_dup64 gvec_add8 gvec_add16 gvec_add32 gvec_add64 gvec_adds8 gvec_adds16 gvec_adds32 gvec_adds64 gvec_sub8 gvec_sub16 gvec_sub32 gvec_sub64 gvec_subs8 gvec_subs16 gvec_subs32 gvec_subs64 gvec_mul8 gvec_mul16 gvec_mul32 gvec_mul64 gvec_muls8 gvec_muls16 gvec_muls32 gvec_muls64 gvec_ssadd8 gvec_ssadd16 gvec_ssadd32 gvec_ssadd64 gvec_sssub8 gvec_sssub16 gvec_sssub32 gvec_sssub64 gvec_usadd8 gvec_usadd16 gvec_usadd32 gvec_usadd64 gvec_ussub8 gvec_ussub16 gvec_ussub32 gvec_ussub64 gvec_smin8 gvec_smin16 gvec_smin32 gvec_smin64 gvec_smax8 gvec_smax16 gvec_smax32 gvec_smax64 gvec_umin8 gvec_umin16 gvec_umin32 gvec_umin64 gvec_umax8 gvec_umax16 gvec_umax32 gvec_umax64 gvec_neg8 gvec_neg16 gvec_neg32 gvec_neg64 gvec_abs8 gvec_abs16 gvec_abs32 gvec_abs64 gvec_not gvec_and gvec_or gvec_xor gvec_andc gvec_orc gvec_nand gvec_nor gvec_eqv gvec_ands gvec_xors gvec_ors gvec_shl8i gvec_shl16i gvec_shl32i gvec_shl64i gvec_shr8i gvec_shr16i gvec_shr32i gvec_shr64i gvec_sar8i gvec_sar16i gvec_sar32i gvec_sar64i gvec_shl8v gvec_shl16v gvec_shl32v gvec_shl64v gvec_shr8v gvec_shr16v gvec_shr32v gvec_shr64v gvec_sar8v gvec_sar16v gvec_sar32v gvec_sar64v gvec_eq8 gvec_eq16 gvec_eq32 gvec_eq64 gvec_ne8 gvec_ne16 gvec_ne32 gvec_ne64 gvec_lt8 gvec_lt16 gvec_lt32 gvec_lt64 gvec_le8 gvec_le16 gvec_le32 gvec_le64 gvec_ltu8 gvec_ltu16 gvec_ltu32 gvec_ltu64 gvec_leu8 gvec_leu16 gvec_leu32 gvec_leu64 gvec_bitsel

aarch64_HELPERS := sxtb16 uxtb16 add_setq add_saturate sub_saturate add_usaturate sub_usaturate sdiv udiv rbit sadd8 ssub8 ssub16 sadd16 saddsubx ssubaddx uadd8 usub8 usub16 uadd16 uaddsubx usubaddx qadd8 qsub8 qsub16 qadd16 qaddsubx qsubaddx shadd8 shsub8 shsub16 shadd16 shaddsubx shsubaddx uqadd8 uqsub8 uqsub16 uqadd16 uqaddsubx uqsubaddx uhadd8 uhsub8 uhsub16 uhadd16 uhaddsubx uhsubaddx ssat usat ssat16 usat16 usad8 sel_flags exception_internal exception_with_syndrome exception_bkpt_insn setend wfi wfe yield pre_hvc pre_smc check_breakpoints cpsr_write cpsr_write_eret cpsr_read v7m_msr v7m_mrs v7m_bxns v7m_blxns v7m_tt v7m_preserve_fp_state v7m_vlstm v7m_vlldm v8m_stackcheck access_check_cp_reg set_cp_reg get_cp_reg set_cp_reg64 get_cp_reg64 get_r13_banked set_r13_banked mrs_banked msr_banked get_user_reg set_user_reg rebuild_hflags_m32 rebuild_hflags_a32 rebuild_hflags_a64 vfp_get_fpscr vfp_set_fpscr vfp_adds vfp_addd vfp_subs vfp_subd vfp_muls vfp_muld vfp_divs vfp_divd vfp_maxs vfp_maxd vfp_mins vfp_mind vfp_maxnums vfp_maxnumd vfp_minnums vfp_minnumd vfp_negs vfp_negd vfp_abss vfp_absd vfp_sqrts vfp_sqrtd vfp_cmps vfp_cmpd vfp_cmpes vfp_cmped vfp_fcvtds vfp_fcvtsd vfp_uitoh vfp_uitos vfp_uitod vfp_sitoh vfp_sitos vfp_sitod vfp_touih vfp_touis vfp_touid vfp_touizh vfp_touizs vfp_touizd vfp_tosih vfp_tosis vfp_tosid vfp_tosizh vfp_tosizs vfp_tosizd vfp_toshs_round_to_zero vfp_tosls_round_to_zero vfp_touhs_round_to_zero vfp_touls_round_to_zero vfp_toshd_round_to_zero vfp_tosld_round_to_zero vfp_touhd_round_to_zero vfp_tould_round_to_zero vfp_touhh vfp_toshh vfp_toulh vfp_toslh vfp_touqh vfp_tosqh vfp_toshs vfp_tosls vfp_tosqs vfp_touhs vfp_touls vfp_touqs vfp_toshd vfp_tosld vfp_tosqd vfp_touhd vfp_tould vfp_touqd vfp_shtos vfp_sltos vfp_sqtos vfp_uhtos vfp_ultos vfp_uqtos vfp_shtod vfp_sltod vfp_sqtod vfp_uhtod vfp_ultod vfp_uqtod vfp_sltoh vfp_ultoh vfp_sqtoh vfp_uqtoh set_rmode set_neon_rmode vfp_fcvt_f16_to_f32 vfp_fcvt_f32_to_f16 vfp_fcvt_f16_to_f64 vfp_fcvt_f64_to_f16 vfp_muladdd vfp_muladds recps_f32 rsqrts_f32 recpe_f16 recpe_f32 recpe_f64 rsqrte_f16 rsqrte_f32 rsqrte_f64 recpe_u32 rsqrte_u32 neon_tbl shl_cc shr_cc sar_cc ror_cc rints_exact rintd_exact rints rintd vjcvt fjcvtzs neon_qadd_u8 neon_qadd_s8 neon_qadd_u16 neon_qadd_s16 neon_qadd_u32 neon_qadd_s32 neon_uqadd_s8 neon_uqadd_s16 neon_uqadd_s32 neon_uqadd_s64 neon_sqadd_u8 neon_sqadd_u16 neon_sqadd_u32 neon_sqadd_u64 neon_qsub_u8 neon_qsub_s8 neon_qsub_u16 neon_qsub_s16 neon_qsub_u32 neon_qsub_s32 neon_qadd_u64 neon_qadd_s64 neon_qsub_u64 neon_qsub_s64 neon_hadd_s8 neon_hadd_u8 neon_hadd_s16 neon_hadd_u16 neon_hadd_s32 neon_hadd_u32 neon_rhadd_s8 neon_rhadd_u8 neon_rhadd_s16 neon_rhadd_u16 neon_rhadd_s32 neon_rhadd_u32 neon_hsub_s8 neon_hsub_u8 neon_hsub_s16 neon_hsub_u16 neon_hsub_s32 neon_hsub_u32 neon_cgt_u8 neon_cgt_s8 neon_cgt_u16 neon_cgt_s16 neon_cgt_u32 neon_cgt_s32 neon_cge_u8 neon_cge_s8 neon_cge_u16 neon_cge_s16 neon_cge_u32 neon_cge_s32 neon_pmin_u8 neon_pmin_s8 neon_pmin_u16 neon_pmin_s16 neon_pmax_u8 neon_pmax_s8 neon_pmax_u16 neon_pmax_s16 neon_abd_u8 neon_abd_s8 neon_abd_u16 neon_abd_s16 neon_abd_u32 neon_abd_s32 neon_shl_u8 neon_shl_s8 neon_shl_u16 neon_shl_s16 neon_shl_u32 neon_shl_s32 neon_shl_u64 neon_shl_s64 neon_rshl_u8 neon_rshl_s8 neon_rshl_u16 neon_rshl_s16 neon_rshl_u32 neon_rshl_s32 neon_rshl_u64 neon_rshl_s64 neon_qshl_u8 neon_qshl_s8 neon_qshl_u16 neon_qshl_s16 neon_qshl_u32 neon_qshl_s32 neon_qshl_u64 neon_qshl_s64 neon_qshlu_s8 neon_qshlu_s16 neon_qshlu_s32 neon_qshlu_s64 neon_qrshl_u8 neon_qrshl_s8 neon_qrshl_u16 neon_qrshl_s16 neon_qrshl_u32 neon_qrshl_s32 neon_qrshl_u64 neon_qrshl_s64 neon_add_u8 neon_add_u16 neon_padd_u8 neon_padd_u16 neon_sub_u8 neon_sub_u16 neon_mul_u8 neon_mul_u16 neon_mul_p8 neon_mull_p8 neon_tst_u8 neon_tst_u16 neon_tst_u32 neon_ceq_u8 neon_ceq_u16 neon_ceq_u32 neon_clz_u8 neon_clz_u16 neon_cls_s8 neon_cls_s16 neon_cls_s32 neon_cnt_u8 neon_rbit_u8 neon_qdmulh_s16 neon_qrdmulh_s16 neon_qrdmlah_s16 neon_qrdmlsh_s16 neon_qdmulh_s32 neon_qrdmulh_s32 neon_qrdmlah_s32 neon_qrdmlsh_s32 neon_narrow_u8 neon_narrow_u16 neon_unarrow_sat8 neon_narrow_sat_u8 neon_narrow_sat_s8 neon_unarrow_sat16 neon_narrow_sat_u16 neon_narrow_sat_s16 neon_unarrow_sat32 neon_narrow_sat_u32 neon_narrow_sat_s32 neon_narrow_high_u8 neon_narrow_high_u16 neon_narrow_round_high_u8 neon_narrow_round_high_u16 neon_widen_u8 neon_widen_s8 neon_widen_u16 neon_widen_s16 neon_addl_u16 neon_addl_u32 neon_paddl_u16 neon_paddl_u32 neon_subl_u16 neon_subl_u32 neon_addl_saturate_s32 neon_addl_saturate_s64 neon_abdl_u16 neon_abdl_s16 neon_abdl_u32 neon_abdl_s32 neon_abdl_u64 neon_abdl_s64 neon_mull_u8 neon_mull_s8 neon_mull_u16 neon_mull_s16 neon_negl_u16 neon_negl_u32 neon_qabs_s8 neon_qabs_s16 neon_qabs_s32 neon_qabs_s64 neon_qneg_s8 neon_qneg_s16 neon_qneg_s32 neon_qneg_s64 neon_abd_f32 neon_ceq_f32 neon_cge_f32 neon_cgt_f32 neon_acge_f32 neon_acgt_f32 neon_acge_f64 neon_acgt_f64 iwmmxt_maddsq iwmmxt_madduq iwmmxt_sadb iwmmxt_sadw iwmmxt_mulslw iwmmxt_mulshw iwmmxt_mululw iwmmxt_muluhw iwmmxt_macsw iwmmxt_macuw iwmmxt_setpsr_nz iwmmxt_unpacklb iwmmxt_unpacklw iwmmxt_unpackll iwmmxt_unpackhb iwmmxt_unpackhw iwmmxt_unpackhl iwmmxt_unpacklub iwmmxt_unpackluw iwmmxt_unpacklul iwmmxt_unpackhub iwmmxt_unpackhuw iwmmxt_unpackhul iwmmxt_unpacklsb iwmmxt_unpacklsw iwmmxt_unpacklsl iwmmxt_unpackhsb iwmmxt_unpackhsw iwmmxt_unpackhsl iwmmxt_cmpeqb iwmmxt_cmpeqw iwmmxt_cmpeql iwmmxt_cmpgtub iwmmxt_cmpgtuw iwmmxt_cmpgtul iwmmxt_cmpgtsb iwmmxt_cmpgtsw iwmmxt_cmpgtsl iwmmxt_minsb iwmmxt_minsw iwmmxt_minsl iwmmxt_minub iwmmxt_minuw iwmmxt_minul iwmmxt_maxsb iwmmxt_maxsw iwmmxt_maxsl iwmmxt_maxub iwmmxt_maxuw iwmmxt_maxul iwmmxt_subnb iwmmxt_subnw iwmmxt_subnl iwmmxt_addnb iwmmxt_addnw iwmmxt_addnl iwmmxt_subub iwmmxt_subuw iwmmxt_subul iwmmxt_addub iwmmxt_adduw iwmmxt_addul iwmmxt_subsb iwmmxt_subsw iwmmxt_subsl iwmmxt_addsb iwmmxt_addsw iwmmxt_addsl iwmmxt_avgb0 iwmmxt_avgb1 iwmmxt_avgw0 iwmmxt_avgw1 iwmmxt_align iwmmxt_insr iwmmxt_bcstb iwmmxt_bcstw iwmmxt_bcstl iwmmxt_addcb iwmmxt_addcw iwmmxt_addcl iwmmxt_msbb iwmmxt_msbw iwmmxt_msbl iwmmxt_srlw iwmmxt_srll iwmmxt_srlq iwmmxt_sllw iwmmxt_slll iwmmxt_sllq iwmmxt_sraw iwmmxt_sral iwmmxt_sraq iwmmxt_rorw iwmmxt_rorl iwmmxt_rorq iwmmxt_shufh iwmmxt_packuw iwmmxt_packul iwmmxt_packuq iwmmxt_packsw iwmmxt_packsl iwmmxt_packsq iwmmxt_muladdsl iwmmxt_muladdsw iwmmxt_muladdswl neon_unzip8 neon_unzip16 neon_qunzip8 neon_qunzip16 neon_qunzip32 neon_zip8 neon_zip16 neon_qzip8 neon_qzip16 neon_qzip32 crypto_aese crypto_aesmc crypto_sha1_3reg crypto_sha1h crypto_sha1su1 crypto_sha256h crypto_sha256h2 crypto_sha256su0 crypto_sha256su1 crypto_sha512h crypto_sha512h2 crypto_sha512su0 crypto_sha512su1 crypto_sm3tt crypto_sm3partw1 crypto_sm3partw2 crypto_sm4e crypto_sm4ekey crc32 crc32c dc_zva neon_pmull_64_lo neon_pmull_64_hi gvec_qrdmlah_s16 gvec_qrdmlsh_s16 gvec_qrdmlah_s32 gvec_qrdmlsh_s32 gvec_sdot_b gvec_udot_b gvec_sdot_h gvec_udot_h gvec_sdot_idx_b gvec_udot_idx_b gvec_sdot_idx_h gvec_udot_idx_h gvec_fcaddh gvec_fcadds gvec_fcaddd gvec_fcmlah gvec_fcmlah_idx gvec_fcmlas gvec_fcmlas_idx gvec_fcmlad gvec_frecpe_h gvec_frecpe_s gvec_frecpe_d gvec_frsqrte_h gvec_frsqrte_s gvec_frsqrte_d gvec_fadd_h gvec_fadd_s gvec_fadd_d gvec_fsub_h gvec_fsub_s gvec_fsub_d gvec_fmul_h gvec_fmul_s gvec_fmul_d gvec_ftsmul_h gvec_ftsmul_s gvec_ftsmul_d gvec_fmul_idx_h gvec_fmul_idx_s gvec_fmul_idx_d gvec_fmla_idx_h gvec_fmla_idx_s gvec_fmla_idx_d gvec_uqadd_b gvec_uqadd_h gvec_uqadd_s gvec_uqadd_d gvec_sqadd_b gvec_sqadd_h gvec_sqadd_s gvec_sqadd_d gvec_uqsub_b gvec_uqsub_h gvec_uqsub_s gvec_uqsub_d gvec_sqsub_b gvec_sqsub_h gvec_sqsub_s gvec_sqsub_d gvec_fmlal_a32 gvec_fmlal_a64 gvec_fmlal_idx_a32 gvec_fmlal_idx_a64 frint32_s frint64_s frint32_d frint64_d udiv64 sdiv64 rbit64 msr_i_spsel msr_i_daifset msr_i_daifclear vfp_cmph_a64 vfp_cmpeh_a64 vfp_cmps_a64 vfp_cmpes_a64 vfp_cmpd_a64 vfp_cmped_a64 simd_tbl vfp_mulxs vfp_mulxd neon_ceq_f64 neon_cge_f64 neon_cgt_f64 recpsf_f16 recpsf_f32 recpsf_f64 rsqrtsf_f16 rsqrtsf_f32 rsqrtsf_f64 neon_addlp_s8 neon_addlp_u8 neon_addlp_s16 neon_addlp_u16 frecpx_f64 frecpx_f32 frecpx_f16 fcvtx_f64_to_f32 crc32_64 crc32c_64 paired_cmpxchg64_le paired_cmpxchg64_le_parallel paired_cmpxchg64_be paired_cmpxchg64_be_parallel casp_le_parallel casp_be_parallel advsimd_maxh advsimd_minh advsimd_maxnumh advsimd_minnumh advsimd_addh advsimd_subh advsimd_mulh advsimd_divh advsimd_ceq_f16 advsimd_cge_f16 advsimd_cgt_f16 advsimd_acge_f16 advsimd_acgt_f16 advsimd_mulxh advsimd_muladdh advsimd_add2h advsimd_sub2h advsimd_mul2h advsimd_div2h advsimd_max2h advsimd_min2h advsimd_maxnum2h advsimd_minnum2h advsimd_mulx2h advsimd_muladd2h advsimd_rinth_exact advsimd_rinth advsimd_f16tosinth advsimd_f16touinth sqrt_f16 exception_return pacia pacib pacda pacdb pacga autia autib autda autdb xpaci xpacd sve_predtest1 sve_predtest sve_pfirst sve_pnext sve_and_zpzz_b sve_and_zpzz_h sve_and_zpzz_s sve_and_zpzz_d sve_eor_zpzz_b sve_eor_zpzz_h sve_eor_zpzz_s sve_eor_zpzz_d sve_orr_zpzz_b sve_orr_zpzz_h sve_orr_zpzz_s sve_orr_zpzz_d sve_bic_zpzz_b sve_bic_zpzz_h sve_bic_zpzz_s sve_bic_zpzz_d sve_add_zpzz_b sve_add_zpzz_h sve_add_zpzz_s sve_add_zpzz_d sve_sub_zpzz_b sve_sub_zpzz_h sve_sub_zpzz_s sve_sub_zpzz_d sve_smax_zpzz_b sve_smax_zpzz_h sve_smax_zpzz_s sve_smax_zpzz_d sve_umax_zpzz_b sve_umax_zpzz_h sve_umax_zpzz_s sve_umax_zpzz_d sve_smin_zpzz_b sve_smin_zpzz_h sve_smin_zpzz_s sve_smin_zpzz_d sve_umin_zpzz_b sve_umin_zpzz_h sve_umin_zpzz_s sve_umin_zpzz_d sve_sabd_zpzz_b sve_sabd_zpzz_h sve_sabd_zpzz_s sve_sabd_zpzz_d sve_uabd_zpzz_b sve_uabd_zpzz_h sve_uabd_zpzz_s sve_uabd_zpzz_d sve_mul_zpzz_b sve_mul_zpzz_h sve_mul_zpzz_s sve_mul_zpzz_d sve_smulh_zpzz_b sve_smulh_zpzz_h sve_smulh_zpzz_s sve_smulh_zpzz_d sve_umulh_zpzz_b sve_umulh_zpzz_h sve_umulh_zpzz_s sve_umulh_zpzz_d sve_sdiv_zpzz_s sve_sdiv_zpzz_d sve_udiv_zpzz_s sve_udiv_zpzz_d sve_asr_zpzz_b sve_asr_zpzz_h sve_asr_zpzz_s sve_asr_zpzz_d sve_lsr_zpzz_b sve_lsr_zpzz_h sve_lsr_zpzz_s sve_lsr_zpzz_d sve_lsl_zpzz_b sve_lsl_zpzz_h sve_lsl_zpzz_s sve_lsl_zpzz_d sve_sel_zpzz_b sve_sel_zpzz_h sve_sel_zpzz_s sve_sel_zpzz_d sve_asr_zpzw_b sve_asr_zpzw_h sve_asr_zpzw_s sve_lsr_zpzw_b sve_lsr_zpzw_h sve_lsr_zpzw_s sve_lsl_zpzw_b sve_lsl_zpzw_h sve_lsl_zpzw_s sve_orv_b sve_orv_h sve_orv_s sve_orv_d sve_eorv_b sve_eorv_h sve_eorv_s sve_eorv_d sve_andv_b sve_andv_h sve_andv_s sve_andv_d sve_saddv_b sve_saddv_h sve_saddv_s sve_uaddv_b sve_uaddv_h sve_uaddv_s sve_uaddv_d sve_smaxv_b sve_smaxv_h sve_smaxv_s sve_smaxv_d sve_umaxv_b sve_umaxv_h sve_umaxv_s sve_umaxv_d sve_sminv_b sve_sminv_h sve_sminv_s sve_sminv_d sve_uminv_b sve_uminv_h sve_uminv_s sve_uminv_d sve_clr_b sve_clr_h sve_clr_s sve_clr_d sve_movz_b sve_movz_h sve_movz_s sve_movz_d sve_asr_zpzi_b sve_asr_zpzi_h sve_asr_zpzi_s sve_asr_zpzi_d sve_lsr_zpzi_b sve_lsr_zpzi_h sve_lsr_zpzi_s sve_lsr_zpzi_d sve_lsl_zpzi_b sve_lsl_zpzi_h sve_lsl_zpzi_s sve_lsl_zpzi_d sve_asrd_b sve_asrd_h sve_asrd_s sve_asrd_d sve_cls_b sve_cls_h sve_cls_s sve_cls_d sve_clz_b sve_clz_h sve_clz_s sve_clz_d sve_cnt_zpz_b sve_cnt_zpz_h sve_cnt_zpz_s sve_cnt_zpz_d sve_cnot_b sve_cnot_h sve_cnot_s sve_cnot_d sve_fabs_h sve_fabs_s sve_fabs_d sve_fneg_h sve_fneg_s sve_fneg_d sve_not_zpz_b sve_not_zpz_h sve_not_zpz_s sve_not_zpz_d sve_sxtb_h sve_sxtb_s sve_sxtb_d sve_uxtb_h sve_uxtb_s sve_uxtb_d sve_sxth_s sve_sxth_d sve_uxth_s sve_uxth_d sve_sxtw_d sve_uxtw_d sve_abs_b sve_abs_h sve_abs_s sve_abs_d sve_neg_b sve_neg_h sve_neg_s sve_neg_d sve_mla_b sve_mla_h sve_mla_s sve_mla_d sve_mls_b sve_mls_h sve_mls_s sve_mls_d sve_index_b sve_index_h sve_index_s sve_index_d sve_asr_zzw_b sve_asr_zzw_h sve_asr_zzw_s sve_lsr_zzw_b sve_lsr_zzw_h sve_lsr_zzw_s sve_lsl_zzw_b sve_lsl_zzw_h sve_lsl_zzw_s sve_adr_p32 sve_adr_p64 sve_adr_s32 sve_adr_u32 sve_fexpa_h sve_fexpa_s sve_fexpa_d sve_ftssel_h sve_ftssel_s sve_ftssel_d sve_sqaddi_b sve_sqaddi_h sve_sqaddi_s sve_sqaddi_d sve_uqaddi_b sve_uqaddi_h sve_uqaddi_s sve_uqaddi_d sve_uqsubi_d sve_cpy_m_b sve_cpy_m_h sve_cpy_m_s sve_cpy_m_d sve_cpy_z_b sve_cpy_z_h sve_cpy_z_s sve_cpy_z_d sve_ext sve_insr_b sve_insr_h sve_insr_s sve_insr_d sve_rev_b sve_rev_h sve_rev_s sve_rev_d sve_tbl_b sve_tbl_h sve_tbl_s sve_tbl_d sve_sunpk_h sve_sunpk_s sve_sunpk_d sve_uunpk_h sve_uunpk_s sve_uunpk_d sve_zip_p sve_uzp_p sve_trn_p sve_rev_p sve_punpk_p sve_zip_b sve_zip_h sve_zip_s sve_zip_d sve_uzp_b sve_uzp_h sve_uzp_s sve_uzp_d sve_trn_b sve_trn_h sve_trn_s sve_trn_d sve_compact_s sve_compact_d sve_last_active_element sve_revb_h sve_revb_s sve_revb_d sve_revh_s sve_revh_d sve_revw_d sve_rbit_b sve_rbit_h sve_rbit_s sve_rbit_d sve_splice sve_cmpeq_ppzz_b sve_cmpne_ppzz_b sve_cmpge_ppzz_b sve_cmpgt_ppzz_b sve_cmphi_ppzz_b sve_cmphs_ppzz_b sve_cmpeq_ppzz_h sve_cmpne_ppzz_h sve_cmpge_ppzz_h sve_cmpgt_ppzz_h sve_cmphi_ppzz_h sve_cmphs_ppzz_h sve_cmpeq_ppzz_s sve_cmpne_ppzz_s sve_cmpge_ppzz_s sve_cmpgt_ppzz_s sve_cmphi_ppzz_s sve_cmphs_ppzz_s sve_cmpeq_ppzz_d sve_cmpne_ppzz_d sve_cmpge_ppzz_d sve_cmpgt_ppzz_d sve_cmphi_ppzz_d sve_cmphs_ppzz_d sve_cmpeq_ppzw_b sve_cmpne_ppzw_b sve_cmpge_ppzw_b sve_cmpgt_ppzw_b sve_cmphi_ppzw_b sve_cmphs_ppzw_b sve_cmple_ppzw_b sve_cmplt_ppzw_b sve_cmplo_ppzw_b sve_cmpls_ppzw_b sve_cmpeq_ppzw_h sve_cmpne_ppzw_h sve_cmpge_ppzw_h sve_cmpgt_ppzw_h sve_cmphi_ppzw_h sve_cmphs_ppzw_h sve_cmple_ppzw_h sve_cmplt_ppzw_h sve_cmplo_ppzw_h sve_cmpls_ppzw_h sve_cmpeq_ppzw_s sve_cmpne_ppzw_s sve_cmpge_ppzw_s sve_cmpgt_ppzw_s sve_cmphi_ppzw_s sve_cmphs_ppzw_s sve_cmple_ppzw_s sve_cmplt_ppzw_s sve_cmplo_ppzw_s sve_cmpls_ppzw_s sve_cmpeq_ppzi_b sve_cmpne_ppzi_b sve_cmpgt_ppzi_b sve_cmpge_ppzi_b sve_cmplt_ppzi_b sve_cmple_ppzi_b sve_cmphs_ppzi_b sve_cmphi_ppzi_b sve_cmplo_ppzi_b sve_cmpls_ppzi_b sve_cmpeq_ppzi_h sve_cmpne_ppzi_h sve_cmpgt_ppzi_h sve_cmpge_ppzi_h sve_cmplt_ppzi_h sve_cmple_ppzi_h sve_cmphs_ppzi_h sve_cmphi_ppzi_h sve_cmplo_ppzi_h sve_cmpls_ppzi_h sve_cmpeq_ppzi_s sve_cmpne_ppzi_s sve_cmpgt_ppzi_s sve_cmpge_ppzi_s sve_cmplt_ppzi_s sve_cmple_ppzi_s sve_cmphs_ppzi_s sve_cmphi_ppzi_s sve_cmplo_ppzi_s sve_cmpls_ppzi_s sve_cmpeq_ppzi_d sve_cmpne_ppzi_d sve_cmpgt_ppzi_d sve_cmpge_ppzi_d sve_cmplt_ppzi_d sve_cmple_ppzi_d sve_cmphs_ppzi_d sve_cmphi_ppzi_d sve_cmplo_ppzi_d sve_cmpls_ppzi_d sve_and_pppp sve_bic_pppp sve_eor_pppp sve_sel_pppp sve_orr_pppp sve_orn_pppp sve_nor_pppp sve_nand_pppp sve_brkpa sve_brkpb sve_brkpas sve_brkpbs sve_brka_z sve_brkb_z sve_brka_m sve_brkb_m sve_brkas_z sve_brkbs_z sve_brkas_m sve_brkbs_m sve_brkn sve_brkns sve_cntp sve_while sve_subri_b sve_subri_h sve_subri_s sve_subri_d sve_smaxi_b sve_smaxi_h sve_smaxi_s sve_smaxi_d sve_smini_b sve_smini_h sve_smini_s sve_smini_d sve_umaxi_b sve_umaxi_h sve_umaxi_s sve_umaxi_d sve_umini_b sve_umini_h sve_umini_s sve_umini_d gvec_recps_h gvec_recps_s gvec_recps_d gvec_rsqrts_h gvec_rsqrts_s gvec_rsqrts_d sve_faddv_h sve_faddv_s sve_faddv_d sve_fmaxnmv_h sve_fmaxnmv_s sve_fmaxnmv_d sve_fminnmv_h sve_fminnmv_s sve_fminnmv_d sve_fmaxv_h sve_fmaxv_s sve_fmaxv_d sve_fminv_h sve_fminv_s sve_fminv_d sve_fadda_h sve_fadda_s sve_fadda_d sve_fcmge0_h sve_fcmge0_s sve_fcmge0_d sve_fcmgt0_h sve_fcmgt0_s sve_fcmgt0_d sve_fcmlt0_h sve_fcmlt0_s sve_fcmlt0_d sve_fcmle0_h sve_fcmle0_s sve_fcmle0_d sve_fcmeq0_h sve_fcmeq0_s sve_fcmeq0_d sve_fcmne0_h sve_fcmne0_s sve_fcmne0_d sve_fadd_h sve_fadd_s sve_fadd_d sve_fsub_h sve_fsub_s sve_fsub_d sve_fmul_h sve_fmul_s sve_fmul_d sve_fdiv_h sve_fdiv_s sve_fdiv_d sve_fmin_h sve_fmin_s sve_fmin_d sve_fmax_h sve_fmax_s sve_fmax_d sve_fminnum_h sve_fminnum_s sve_fminnum_d sve_fmaxnum_h sve_fmaxnum_s sve_fmaxnum_d sve_fabd_h sve_fabd_s sve_fabd_d sve_fscalbn_h sve_fscalbn_s sve_fscalbn_d sve_fmulx_h sve_fmulx_s sve_fmulx_d sve_fadds_h sve_fadds_s sve_fadds_d sve_fsubs_h sve_fsubs_s sve_fsubs_d sve_fmuls_h sve_fmuls_s sve_fmuls_d sve_fsubrs_h sve_fsubrs_s sve_fsubrs_d sve_fmaxnms_h sve_fmaxnms_s sve_fmaxnms_d sve_fminnms_h sve_fminnms_s sve_fminnms_d sve_fmaxs_h sve_fmaxs_s sve_fmaxs_d sve_fmins_h sve_fmins_s sve_fmins_d sve_fcvt_sh sve_fcvt_dh sve_fcvt_hs sve_fcvt_ds sve_fcvt_hd sve_fcvt_sd sve_fcvtzs_hh sve_fcvtzs_hs sve_fcvtzs_ss sve_fcvtzs_ds sve_fcvtzs_hd sve_fcvtzs_sd sve_fcvtzs_dd sve_fcvtzu_hh sve_fcvtzu_hs sve_fcvtzu_ss sve_fcvtzu_ds sve_fcvtzu_hd sve_fcvtzu_sd sve_fcvtzu_dd sve_frint_h sve_frint_s sve_frint_d sve_frintx_h sve_frintx_s sve_frintx_d sve_frecpx_h sve_frecpx_s sve_frecpx_d sve_fsqrt_h sve_fsqrt_s sve_fsqrt_d sve_scvt_hh sve_scvt_sh sve_scvt_dh sve_scvt_ss sve_scvt_sd sve_scvt_ds sve_scvt_dd sve_ucvt_hh sve_ucvt_sh sve_ucvt_dh sve_ucvt_ss sve_ucvt_sd sve_ucvt_ds sve_ucvt_dd sve_fcmge_h sve_fcmge_s sve_fcmge_d sve_fcmgt_h sve_fcmgt_s sve_fcmgt_d sve_fcmeq_h sve_fcmeq_s sve_fcmeq_d sve_fcmne_h sve_fcmne_s sve_fcmne_d sve_fcmuo_h sve_fcmuo_s sve_fcmuo_d sve_facge_h sve_facge_s sve_facge_d sve_facgt_h sve_facgt_s sve_facgt_d sve_fcadd_h sve_fcadd_s sve_fcadd_d sve_fmla_zpzzz_h sve_fmla_zpzzz_s sve_fmla_zpzzz_d sve_fmls_zpzzz_h sve_fmls_zpzzz_s sve_fmls_zpzzz_d sve_fnmla_zpzzz_h sve_fnmla_zpzzz_s sve_fnmla_zpzzz_d sve_fnmls_zpzzz_h sve_fnmls_zpzzz_s sve_fnmls_zpzzz_d sve_fcmla_zpzzz_h sve_fcmla_zpzzz_s sve_fcmla_zpzzz_d sve_ftmad_h sve_ftmad_s sve_ftmad_d sve_ld1bb_r sve_ld2bb_r sve_ld3bb_r sve_ld4bb_r sve_ld1hh_le_r sve_ld2hh_le_r sve_ld3hh_le_r sve_ld4hh_le_r sve_ld1hh_be_r sve_ld2hh_be_r sve_ld3hh_be_r sve_ld4hh_be_r sve_ld1ss_le_r sve_ld2ss_le_r sve_ld3ss_le_r sve_ld4ss_le_r sve_ld1ss_be_r sve_ld2ss_be_r sve_ld3ss_be_r sve_ld4ss_be_r sve_ld1dd_le_r sve_ld2dd_le_r sve_ld3dd_le_r sve_ld4dd_le_r sve_ld1dd_be_r sve_ld2dd_be_r sve_ld3dd_be_r sve_ld4dd_be_r sve_ld1bhu_r sve_ld1bsu_r sve_ld1bdu_r sve_ld1bhs_r sve_ld1bss_r sve_ld1bds_r sve_ld1hsu_le_r sve_ld1hdu_le_r sve_ld1hss_le_r sve_ld1hds_le_r sve_ld1hsu_be_r sve_ld1hdu_be_r sve_ld1hss_be_r sve_ld1hds_be_r sve_ld1sdu_le_r sve_ld1sds_le_r sve_ld1sdu_be_r sve_ld1sds_be_r sve_ldff1bb_r sve_ldff1bhu_r sve_ldff1bsu_r sve_ldff1bdu_r sve_ldff1bhs_r sve_ldff1bss_r sve_ldff1bds_r sve_ldff1hh_le_r sve_ldff1hsu_le_r sve_ldff1hdu_le_r sve_ldff1hss_le_r sve_ldff1hds_le_r sve_ldff1hh_be_r sve_ldff1hsu_be_r sve_ldff1hdu_be_r sve_ldff1hss_be_r sve_ldff1hds_be_r sve_ldff1ss_le_r sve_ldff1sdu_le_r sve_ldff1sds_le_r sve_ldff1ss_be_r sve_ldff1sdu_be_r sve_ldff1sds_be_r sve_ldff1dd_le_r sve_ldff1dd_be_r sve_ldnf1bb_r sve_ldnf1bhu_r sve_ldnf1bsu_r sve_ldnf1bdu_r sve_ldnf1bhs_r sve_ldnf1bss_r sve_ldnf1bds_r sve_ldnf1hh_le_r sve_ldnf1hsu_le_r sve_ldnf1hdu_le_r sve_ldnf1hss_le_r sve_ldnf1hds_le_r sve_ldnf1hh_be_r sve_ldnf1hsu_be_r sve_ldnf1hdu_be_r sve_ldnf1hss_be_r sve_ldnf1hds_be_r sve_ldnf1ss_le_r sve_ldnf1sdu_le_r sve_ldnf1sds_le_r sve_ldnf1ss_be_r sve_ldnf1sdu_be_r sve_ldnf1sds_be_r sve_ldnf1dd_le_r sve_ldnf1dd_be_r sve_st1bb_r sve_st2bb_r sve_st3bb_r sve_st4bb_r sve_st1hh_le_r sve_st2hh_le_r sve_st3hh_le_r sve_st4hh_le_r sve_st1hh_be_r sve_st2hh_be_r sve_st3hh_be_r sve_st4hh_be_r sve_st1ss_le_r sve_st2ss_le_r sve_st3ss_le_r sve_st4ss_le_r sve_st1ss_be_r sve_st2ss_be_r sve_st3ss_be_r sve_st4ss_be_r sve_st1dd_le_r sve_st2dd_le_r sve_st3dd_le_r sve_st4dd_le_r sve_st1dd_be_r sve_st2dd_be_r sve_st3dd_be_r sve_st4dd_be_r sve_st1bh_r sve_st1bs_r sve_st1bd_r sve_st1hs_le_r sve_st1hd_le_r sve_st1hs_be_r sve_st1hd_be_r sve_st1sd_le_r sve_st1sd_be_r sve_ldbsu_zsu sve_ldhsu_le_zsu sve_ldhsu_be_zsu sve_ldss_le_zsu sve_ldss_be_zsu sve_ldbss_zsu sve_ldhss_le_zsu sve_ldhss_be_zsu sve_ldbsu_zss sve_ldhsu_le_zss sve_ldhsu_be_zss sve_ldss_le_zss sve_ldss_be_zss sve_ldbss_zss sve_ldhss_le_zss sve_ldhss_be_zss sve_ldbdu_zsu sve_ldhdu_le_zsu sve_ldhdu_be_zsu sve_ldsdu_le_zsu sve_ldsdu_be_zsu sve_lddd_le_zsu sve_lddd_be_zsu sve_ldbds_zsu sve_ldhds_le_zsu sve_ldhds_be_zsu sve_ldsds_le_zsu sve_ldsds_be_zsu sve_ldbdu_zss sve_ldhdu_le_zss sve_ldhdu_be_zss sve_ldsdu_le_zss sve_ldsdu_be_zss sve_lddd_le_zss sve_lddd_be_zss sve_ldbds_zss sve_ldhds_le_zss sve_ldhds_be_zss sve_ldsds_le_zss sve_ldsds_be_zss sve_ldbdu_zd sve_ldhdu_le_zd sve_ldhdu_be_zd sve_ldsdu_le_zd sve_ldsdu_be_zd sve_lddd_le_zd sve_lddd_be_zd sve_ldbds_zd sve_ldhds_le_zd sve_ldhds_be_zd sve_ldsds_le_zd sve_ldsds_be_zd sve_ldffbsu_zsu sve_ldffhsu_le_zsu sve_ldffhsu_be_zsu sve_ldffss_le_zsu sve_ldffss_be_zsu sve_ldffbss_zsu sve_ldffhss_le_zsu sve_ldffhss_be_zsu sve_ldffbsu_zss sve_ldffhsu_le_zss sve_ldffhsu_be_zss sve_ldffss_le_zss sve_ldffss_be_zss sve_ldffbss_zss sve_ldffhss_le_zss sve_ldffhss_be_zss sve_ldffbdu_zsu sve_ldffhdu_le_zsu sve_ldffhdu_be_zsu sve_ldffsdu_le_zsu sve_ldffsdu_be_zsu sve_ldffdd_le_zsu sve_ldffdd_be_zsu sve_ldffbds_zsu sve_ldffhds_le_zsu sve_ldffhds_be_zsu sve_ldffsds_le_zsu sve_ldffsds_be_zsu sve_ldffbdu_zss sve_ldffhdu_le_zss sve_ldffhdu_be_zss sve_ldffsdu_le_zss sve_ldffsdu_be_zss sve_ldffdd_le_zss sve_ldffdd_be_zss sve_ldffbds_zss sve_ldffhds_le_zss sve_ldffhds_be_zss sve_ldffsds_le_zss sve_ldffsds_be_zss sve_ldffbdu_zd sve_ldffhdu_le_zd sve_ldffhdu_be_zd sve_ldffsdu_le_zd sve_ldffsdu_be_zd sve_ldffdd_le_zd sve_ldffdd_be_zd sve_ldffbds_zd sve_ldffhds_le_zd sve_ldffhds_be_zd sve_ldffsds_le_zd sve_ldffsds_be_zd sve_stbs_zsu sve_sths_le_zsu sve_sths_be_zsu sve_stss_le_zsu sve_stss_be_zsu sve_stbs_zss sve_sths_le_zss sve_sths_be_zss sve_stss_le_zss sve_stss_be_zss sve_stbd_zsu sve_sthd_le_zsu sve_sthd_be_zsu sve_stsd_le_zsu sve_stsd_be_zsu sve_stdd_le_zsu sve_stdd_be_zsu sve_stbd_zss sve_sthd_le_zss sve_sthd_be_zss sve_stsd_le_zss sve_stsd_be_zss sve_stdd_le_zss sve_stdd_be_zss sve_stbd_zd sve_sthd_le_zd sve_sthd_be_zd sve_stsd_le_zd sve_stsd_be_zd sve_stdd_le_zd sve_stdd_be_zd trace_guest_mem_before_exec_proxy div_i32 rem_i32 divu_i32 remu_i32 div_i64 rem_i64 divu_i64 remu_i64 shl_i64 shr_i64 sar_i64 mulsh_i64 muluh_i64 clz_i32 ctz_i32 clz_i64 ctz_i64 clrsb_i32 clrsb_i64 ctpop_i32 ctpop_i64 lookup_tb_ptr exit_atomic atomic_cmpxchgb atomic_cmpxchgw_be atomic_cmpxchgw_le atomic_cmpxchgl_be atomic_cmpxchgl_le atomic_cmpxchgq_be atomic_cmpxchgq_le atomic_fetch_addb atomic_fetch_addw_le atomic_fetch_addw_be atomic_fetch_addl_le atomic_fetch_addl_be atomic_fetch_addq_le atomic_fetch_addq_be atomic_fetch_andb atomic_fetch_andw_le atomic_fetch_andw_be atomic_fetch_andl_le atomic_fetch_andl_be atomic_fetch_andq_le atomic_fetch_andq_be atomic_fetch_orb atomic_fetch_orw_le atomic_fetch_orw_be atomic_fetch_orl_le atomic_fetch_orl_be atomic_fetch_orq_le atomic_fetch_orq_be atomic_fetch_xorb atomic_fetch_xorw_le atomic_fetch_xorw_be atomic_fetch_xorl_le atomic_fetch_xorl_be atomic_fetch_xorq_le atomic_fetch_xorq_be atomic_fetch_sminb atomic_fetch_sminw_le atomic_fetch_sminw_be atomic_fetch_sminl_le atomic_fetch_sminl_be atomic_fetch_sminq_le atomic_fetch_sminq_be atomic_fetch_uminb atomic_fetch_uminw_le atomic_fetch_uminw_be atomic_fetch_uminl_le atomic_fetch_uminl_be atomic_fetch_uminq_le atomic_fetch_uminq_be atomic_fetch_smaxb atomic_fetch_smaxw_le atomic_fetch_smaxw_be atomic_fetch_smaxl_le atomic_fetch_smaxl_be atomic_fetch_smaxq_le atomic_fetch_smaxq_be atomic_fetch_umaxb atomic_fetch_umaxw_le atomic_fetch_umaxw_be atomic_fetch_umaxl_le atomic_fetch_umaxl_be atomic_fetch_umaxq_le atomic_fetch_umaxq_be atomic_add_fetchb atomic_add_fetchw_le atomic_add_fetchw_be atomic_add_fetchl_le atomic_add_fetchl_be atomic_add_fetchq_le atomic_add_fetchq_be atomic_and_fetchb atomic_and_fetchw_le atomic_and_fetchw_be atomic_and_fetchl_le atomic_and_fetchl_be atomic_and_fetchq_le atomic_and_fetchq_be atomic_or_fetchb atomic_or_fetchw_le atomic_or_fetchw_be atomic_or_fetchl_le atomic_or_fetchl_be atomic_or_fetchq_le atomic_or_fetchq_be atomic_xor_fetchb atomic_xor_fetchw_le atomic_xor_fetchw_be atomic_xor_fetchl_le atomic_xor_fetchl_be atomic_xor_fetchq_le atomic_xor_fetchq_be atomic_smin_fetchb atomic_smin_fetchw_le atomic_smin_fetchw_be atomic_smin_fetchl_le atomic_smin_fetchl_be atomic_smin_fetchq_le atomic_smin_fetchq_be atomic_umin_fetchb atomic_umin_fetchw_le atomic_umin_fetchw_be atomic_umin_fetchl_le atomic_umin_fetchl_be atomic_umin_fetchq_le atomic_umin_fetchq_be atomic_smax_fetchb atomic_smax_fetchw_le atomic_smax_fetchw_be atomic_smax_fetchl_le atomic_smax_fetchl_be atomic_smax_fetchq_le atomic_smax_fetchq_be atomic_umax_fetchb atomic_umax_fetchw_le atomic_umax_fetchw_be atomic_umax_fetchl_le atomic_umax_fetchl_be atomic_umax_fetchq_le atomic_umax_fetchq_be atomic_xchgb atomic_xchgw_le atomic_xchgw_be atomic_xchgl_le atomic_xchgl_be atomic_xchgq_le atomic_xchgq_be gvec_mov gvec_dup8 gvec_dup16 gvec_dup32 gvec_dup64 gvec_add8 gvec_add16 gvec_add32 gvec_add64 gvec_adds8 gvec_adds16 gvec_adds32 gvec_adds64 gvec_sub8 gvec_sub16 gvec_sub32 gvec_sub64 gvec_subs8 gvec_subs16 gvec_subs32 gvec_subs64 gvec_mul8 gvec_mul16 gvec_mul32 gvec_mul64 gvec_muls8 gvec_muls16 gvec_muls32 gvec_muls64 gvec_ssadd8 gvec_ssadd16 gvec_ssadd32 gvec_ssadd64 gvec_sssub8 gvec_sssub16 gvec_sssub32 gvec_sssub64 gvec_usadd8 gvec_usadd16 gvec_usadd32 gvec_usadd64 gvec_ussub8 gvec_ussub16 gvec_ussub32 gvec_ussub64 gvec_smin8 gvec_smin16 gvec_smin32 gvec_smin64 gvec_smax8 gvec_smax16 gvec_smax32 gvec_smax64 gvec_umin8 gvec_umin16 gvec_umin32 gvec_umin64 gvec_umax8 gvec_umax16 gvec_umax32 gvec_umax64 gvec_neg8 gvec_neg16 gvec_neg32 gvec_neg64 gvec_abs8 gvec_abs16 gvec_abs32 gvec_abs64 gvec_not gvec_and gvec_or gvec_xor gvec_andc gvec_orc gvec_nand gvec_nor gvec_eqv gvec_ands gvec_xors gvec_ors gvec_shl8i gvec_shl16i gvec_shl32i gvec_shl64i gvec_shr8i gvec_shr16i gvec_shr32i gvec_shr64i gvec_sar8i gvec_sar16i gvec_sar32i gvec_sar64i gvec_shl8v gvec_shl16v gvec_shl32v gvec_shl64v gvec_shr8v gvec_shr16v gvec_shr32v gvec_shr64v gvec_sar8v gvec_sar16v gvec_sar32v gvec_sar64v gvec_eq8 gvec_eq16 gvec_eq32 gvec_eq64 gvec_ne8 gvec_ne16 gvec_ne32 gvec_ne64 gvec_lt8 gvec_lt16 gvec_lt32 gvec_lt64 gvec_le8 gvec_le16 gvec_le32 gvec_le64 gvec_ltu8 gvec_ltu16 gvec_ltu32 gvec_ltu64 gvec_leu8 gvec_leu16 gvec_leu32 gvec_leu64 gvec_bitsel

mips64el_HELPERS := raise_exception_err raise_exception raise_exception_debug sdl sdr swl swr muls mulsu macc maccu msac msacu mulhi mulhiu mulshi mulshiu macchi macchiu msachi msachiu bitswap dbitswap rotx lwm swm ldm sdm fork yield cfc1 ctc1 float_cvtd_s float_cvtd_w float_cvtd_l float_cvtps_pw float_cvtpw_ps float_cvts_d float_cvts_w float_cvts_l float_cvts_pl float_cvts_pu float_addr_ps float_mulr_ps float_class_s float_class_d float_maddf_s float_maddf_d float_msubf_s float_msubf_d float_max_s float_max_d float_maxa_s float_maxa_d float_min_s float_min_d float_mina_s float_mina_d float_cvt_l_s float_cvt_l_d float_cvt_w_s float_cvt_w_d float_round_l_s float_round_l_d float_round_w_s float_round_w_d float_trunc_l_s float_trunc_l_d float_trunc_w_s float_trunc_w_d float_ceil_l_s float_ceil_l_d float_ceil_w_s float_ceil_w_d float_floor_l_s float_floor_l_d float_floor_w_s float_floor_w_d float_cvt_2008_l_s float_cvt_2008_l_d float_cvt_2008_w_s float_cvt_2008_w_d float_round_2008_l_s float_round_2008_l_d float_round_2008_w_s float_round_2008_w_d float_trunc_2008_l_s float_trunc_2008_l_d float_trunc_2008_w_s float_trunc_2008_w_d float_ceil_2008_l_s float_ceil_2008_l_d float_ceil_2008_w_s float_ceil_2008_w_d float_floor_2008_l_s float_floor_2008_l_d float_floor_2008_w_s float_floor_2008_w_d float_sqrt_s float_sqrt_d float_rsqrt_s float_rsqrt_d float_recip_s float_recip_d float_rint_s float_rint_d float_abs_s float_abs_d float_abs_ps float_chs_s float_chs_d float_chs_ps float_recip1_s float_recip1_d float_recip1_ps float_rsqrt1_s float_rsqrt1_d float_rsqrt1_ps float_add_s float_add_d float_add_ps float_sub_s float_sub_d float_sub_ps float_mul_s float_mul_d float_mul_ps float_div_s float_div_d float_div_ps float_recip2_s float_recip2_d float_recip2_ps float_rsqrt2_s float_rsqrt2_d float_rsqrt2_ps float_madd_s float_madd_d float_madd_ps float_msub_s float_msub_d float_msub_ps float_nmadd_s float_nmadd_d float_nmadd_ps float_nmsub_s float_nmsub_d float_nmsub_ps cmp_d_f cmpabs_d_f cmp_s_f cmpabs_s_f cmp_ps_f cmpabs_ps_f cmp_d_un cmpabs_d_un cmp_s_un cmpabs_s_un cmp_ps_un cmpabs_ps_un cmp_d_eq cmpabs_d_eq cmp_s_eq cmpabs_s_eq cmp_ps_eq cmpabs_ps_eq cmp_d_ueq cmpabs_d_ueq cmp_s_ueq cmpabs_s_ueq cmp_ps_ueq cmpabs_ps_ueq cmp_d_olt cmpabs_d_olt cmp_s_olt cmpabs_s_olt cmp_ps_olt cmpabs_ps_olt cmp_d_ult cmpabs_d_ult cmp_s_ult cmpabs_s_ult cmp_ps_ult cmpabs_ps_ult cmp_d_ole cmpabs_d_ole cmp_s_ole cmpabs_s_ole cmp_ps_ole cmpabs_ps_ole cmp_d_ule cmpabs_d_ule cmp_s_ule cmpabs_s_ule cmp_ps_ule cmpabs_ps_ule cmp_d_sf cmpabs_d_sf cmp_s_sf cmpabs_s_sf cmp_ps_sf cmpabs_ps_sf cmp_d_ngle cmpabs_d_ngle cmp_s_ngle cmpabs_s_ngle cmp_ps_ngle cmpabs_ps_ngle cmp_d_seq cmpabs_d_seq cmp_s_seq cmpabs_s_seq cmp_ps_seq cmpabs_ps_seq cmp_d_ngl cmpabs_d_ngl cmp_s_ngl cmpabs_s_ngl cmp_ps_ngl cmpabs_ps_ngl cmp_d_lt cmpabs_d_lt cmp_s_lt cmpabs_s_lt cmp_ps_lt cmpabs_ps_lt cmp_d_nge cmpabs_d_nge cmp_s_nge cmpabs_s_nge cmp_ps_nge cmpabs_ps_nge cmp_d_le cmpabs_d_le cmp_s_le cmpabs_s_le cmp_ps_le cmpabs_ps_le cmp_d_ngt cmpabs_d_ngt cmp_s_ngt cmpabs_s_ngt cmp_ps_ngt cmpabs_ps_ngt r6_cmp_d_af r6_cmp_s_af r6_cmp_d_un r6_cmp_s_un r6_cmp_d_eq r6_cmp_s_eq r6_cmp_d_ueq r6_cmp_s_ueq r6_cmp_d_lt r6_cmp_s_lt r6_cmp_d_ult r6_cmp_s_ult r6_cmp_d_le r6_cmp_s_le r6_cmp_d_ule r6_cmp_s_ule r6_cmp_d_saf r6_cmp_s_saf r6_cmp_d_sun r6_cmp_s_sun r6_cmp_d_seq r6_cmp_s_seq r6_cmp_d_sueq r6_cmp_s_sueq r6_cmp_d_slt r6_cmp_s_slt r6_cmp_d_sult r6_cmp_s_sult r6_cmp_d_sle r6_cmp_s_sle r6_cmp_d_sule r6_cmp_s_sule r6_cmp_d_or r6_cmp_s_or r6_cmp_d_une r6_cmp_s_une r6_cmp_d_ne r6_cmp_s_ne r6_cmp_d_sor r6_cmp_s_sor r6_cmp_d_sune r6_cmp_s_sune r6_cmp_d_sne r6_cmp_s_sne rdhwr_cpunum rdhwr_synci_step rdhwr_cc rdhwr_ccres rdhwr_performance rdhwr_xnp pmon wait paddsh paddush paddh paddw paddsb paddusb paddb psubsh psubush psubh psubw psubsb psubusb psubb pshufh packsswh packsshb packushb punpcklhw punpckhhw punpcklbh punpckhbh punpcklwd punpckhwd pavgh pavgb pmaxsh pminsh pmaxub pminub pcmpeqw pcmpgtw pcmpeqh pcmpgth pcmpeqb pcmpgtb psllw psllh psrlw psrlh psraw psrah pmullh pmulhh pmulhuh pmaddhw pasubub biadd pmovmskb addq_ph addq_s_ph addq_qh addq_s_qh addq_s_w addq_pw addq_s_pw addu_qb addu_s_qb adduh_qb adduh_r_qb addu_ph addu_s_ph addqh_ph addqh_r_ph addqh_w addqh_r_w addu_ob addu_s_ob adduh_ob adduh_r_ob addu_qh addu_s_qh subq_ph subq_s_ph subq_qh subq_s_qh subq_s_w subq_pw subq_s_pw subu_qb subu_s_qb subuh_qb subuh_r_qb subu_ph subu_s_ph subqh_ph subqh_r_ph subqh_w subqh_r_w subu_ob subu_s_ob subuh_ob subuh_r_ob subu_qh subu_s_qh addsc addwc modsub raddu_w_qb raddu_l_ob absq_s_qb absq_s_ph absq_s_w absq_s_ob absq_s_qh absq_s_pw precr_qb_ph precrq_qb_ph precr_sra_ph_w precr_sra_r_ph_w precrq_ph_w precrq_rs_ph_w precr_ob_qh precr_sra_qh_pw precr_sra_r_qh_pw precrq_ob_qh precrq_qh_pw precrq_rs_qh_pw precrq_pw_l precrqu_s_qb_ph precrqu_s_ob_qh preceq_pw_qhl preceq_pw_qhr preceq_pw_qhla preceq_pw_qhra precequ_ph_qbl precequ_ph_qbr precequ_ph_qbla precequ_ph_qbra precequ_qh_obl precequ_qh_obr precequ_qh_obla precequ_qh_obra preceu_ph_qbl preceu_ph_qbr preceu_ph_qbla preceu_ph_qbra preceu_qh_obl preceu_qh_obr preceu_qh_obla preceu_qh_obra shll_qb shll_ob shll_ph shll_s_ph shll_qh shll_s_qh shll_s_w shll_pw shll_s_pw shrl_qb shrl_ph shrl_ob shrl_qh shra_qb shra_r_qb shra_ob shra_r_ob shra_ph shra_r_ph shra_r_w shra_qh shra_r_qh shra_pw shra_r_pw muleu_s_ph_qbl muleu_s_ph_qbr muleu_s_qh_obl muleu_s_qh_obr mulq_rs_ph mulq_rs_qh muleq_s_w_phl muleq_s_w_phr muleq_s_pw_qhl muleq_s_pw_qhr dpau_h_qbl dpau_h_qbr dpau_h_obl dpau_h_obr dpsu_h_qbl dpsu_h_qbr dpsu_h_obl dpsu_h_obr dpa_w_ph dpa_w_qh dpax_w_ph dpaq_s_w_ph dpaq_s_w_qh dpaqx_s_w_ph dpaqx_sa_w_ph dps_w_ph dps_w_qh dpsx_w_ph dpsq_s_w_ph dpsq_s_w_qh dpsqx_s_w_ph dpsqx_sa_w_ph mulsaq_s_w_ph mulsaq_s_w_qh dpaq_sa_l_w dpaq_sa_l_pw dpsq_sa_l_w dpsq_sa_l_pw mulsaq_s_l_pw maq_s_w_phl maq_s_w_phr maq_sa_w_phl maq_sa_w_phr mul_ph mul_s_ph mulq_s_ph mulq_s_w mulq_rs_w mulsa_w_ph maq_s_w_qhll maq_s_w_qhlr maq_s_w_qhrl maq_s_w_qhrr maq_sa_w_qhll maq_sa_w_qhlr maq_sa_w_qhrl maq_sa_w_qhrr maq_s_l_pwl maq_s_l_pwr dmadd dmaddu dmsub dmsubu bitrev insv dinsv cmpu_eq_qb cmpu_lt_qb cmpu_le_qb cmpgu_eq_qb cmpgu_lt_qb cmpgu_le_qb cmp_eq_ph cmp_lt_ph cmp_le_ph cmpu_eq_ob cmpu_lt_ob cmpu_le_ob cmpgdu_eq_ob cmpgdu_lt_ob cmpgdu_le_ob cmpgu_eq_ob cmpgu_lt_ob cmpgu_le_ob cmp_eq_qh cmp_lt_qh cmp_le_qh cmp_eq_pw cmp_lt_pw cmp_le_pw pick_qb pick_ph pick_ob pick_qh pick_pw packrl_ph packrl_pw extr_w extr_r_w extr_rs_w dextr_w dextr_r_w dextr_rs_w dextr_l dextr_r_l dextr_rs_l extr_s_h dextr_s_h extp extpdp dextp dextpdp shilo dshilo mthlip dmthlip wrdsp rddsp msa_nloc_b msa_nloc_h msa_nloc_w msa_nloc_d msa_nlzc_b msa_nlzc_h msa_nlzc_w msa_nlzc_d msa_pcnt_b msa_pcnt_h msa_pcnt_w msa_pcnt_d msa_binsl_b msa_binsl_h msa_binsl_w msa_binsl_d msa_binsr_b msa_binsr_h msa_binsr_w msa_binsr_d msa_bmnz_v msa_bmz_v msa_bsel_v msa_bclr_b msa_bclr_h msa_bclr_w msa_bclr_d msa_bneg_b msa_bneg_h msa_bneg_w msa_bneg_d msa_bset_b msa_bset_h msa_bset_w msa_bset_d msa_add_a_b msa_add_a_h msa_add_a_w msa_add_a_d msa_adds_a_b msa_adds_a_h msa_adds_a_w msa_adds_a_d msa_adds_s_b msa_adds_s_h msa_adds_s_w msa_adds_s_d msa_adds_u_b msa_adds_u_h msa_adds_u_w msa_adds_u_d msa_addv_b msa_addv_h msa_addv_w msa_addv_d msa_hadd_s_h msa_hadd_s_w msa_hadd_s_d msa_hadd_u_h msa_hadd_u_w msa_hadd_u_d msa_ave_s_b msa_ave_s_h msa_ave_s_w msa_ave_s_d msa_ave_u_b msa_ave_u_h msa_ave_u_w msa_ave_u_d msa_aver_s_b msa_aver_s_h msa_aver_s_w msa_aver_s_d msa_aver_u_b msa_aver_u_h msa_aver_u_w msa_aver_u_d msa_ceq_b msa_ceq_h msa_ceq_w msa_ceq_d msa_cle_s_b msa_cle_s_h msa_cle_s_w msa_cle_s_d msa_cle_u_b msa_cle_u_h msa_cle_u_w msa_cle_u_d msa_clt_s_b msa_clt_s_h msa_clt_s_w msa_clt_s_d msa_clt_u_b msa_clt_u_h msa_clt_u_w msa_clt_u_d msa_div_s_b msa_div_s_h msa_div_s_w msa_div_s_d msa_div_u_b msa_div_u_h msa_div_u_w msa_div_u_d msa_max_a_b msa_max_a_h msa_max_a_w msa_max_a_d msa_max_s_b msa_max_s_h msa_max_s_w msa_max_s_d msa_max_u_b msa_max_u_h msa_max_u_w msa_max_u_d msa_min_a_b msa_min_a_h msa_min_a_w msa_min_a_d msa_min_s_b msa_min_s_h msa_min_s_w msa_min_s_d msa_min_u_b msa_min_u_h msa_min_u_w msa_min_u_d msa_mod_u_b msa_mod_u_h msa_mod_u_w msa_mod_u_d msa_mod_s_b msa_mod_s_h msa_mod_s_w msa_mod_s_d msa_asub_s_b msa_asub_s_h msa_asub_s_w msa_asub_s_d msa_asub_u_b msa_asub_u_h msa_asub_u_w msa_asub_u_d msa_hsub_s_h msa_hsub_s_w msa_hsub_s_d msa_hsub_u_h msa_hsub_u_w msa_hsub_u_d msa_ilvev_b msa_ilvev_h msa_ilvev_w msa_ilvev_d msa_ilvod_b msa_ilvod_h msa_ilvod_w msa_ilvod_d msa_ilvl_b msa_ilvl_h msa_ilvl_w msa_ilvl_d msa_ilvr_b msa_ilvr_h msa_ilvr_w msa_ilvr_d msa_and_v msa_nor_v msa_or_v msa_xor_v msa_pckev_b msa_pckev_h msa_pckev_w msa_pckev_d msa_pckod_b msa_pckod_h msa_pckod_w msa_pckod_d msa_sll_b msa_sll_h msa_sll_w msa_sll_d msa_sra_b msa_sra_h msa_sra_w msa_sra_d msa_srar_b msa_srar_h msa_srar_w msa_srar_d msa_srl_b msa_srl_h msa_srl_w msa_srl_d msa_srlr_b msa_srlr_h msa_srlr_w msa_srlr_d msa_move_v msa_andi_b msa_ori_b msa_nori_b msa_xori_b msa_bmnzi_b msa_bmzi_b msa_bseli_b msa_shf_df msa_addvi_df msa_subvi_df msa_maxi_s_df msa_maxi_u_df msa_mini_s_df msa_mini_u_df msa_ceqi_df msa_clti_s_df msa_clti_u_df msa_clei_s_df msa_clei_u_df msa_ldi_df msa_slli_df msa_srai_df msa_srli_df msa_bclri_df msa_bseti_df msa_bnegi_df msa_binsli_df msa_binsri_df msa_sat_s_df msa_sat_u_df msa_srari_df msa_srlri_df msa_binsl_df msa_binsr_df msa_subv_df msa_subs_s_df msa_subs_u_df msa_subsus_u_df msa_subsuu_s_df msa_mulv_df msa_maddv_df msa_msubv_df msa_dotp_s_df msa_dotp_u_df msa_dpadd_s_df msa_dpadd_u_df msa_dpsub_s_df msa_dpsub_u_df msa_sld_df msa_splat_df msa_vshf_df msa_sldi_df msa_splati_df msa_insve_df msa_ctcmsa msa_cfcmsa msa_fcaf_df msa_fcun_df msa_fceq_df msa_fcueq_df msa_fclt_df msa_fcult_df msa_fcle_df msa_fcule_df msa_fsaf_df msa_fsun_df msa_fseq_df msa_fsueq_df msa_fslt_df msa_fsult_df msa_fsle_df msa_fsule_df msa_fadd_df msa_fsub_df msa_fmul_df msa_fdiv_df msa_fmadd_df msa_fmsub_df msa_fexp2_df msa_fexdo_df msa_ftq_df msa_fmin_df msa_fmin_a_df msa_fmax_df msa_fmax_a_df msa_fcor_df msa_fcune_df msa_fcne_df msa_mul_q_df msa_madd_q_df msa_msub_q_df msa_fsor_df msa_fsune_df msa_fsne_df msa_mulr_q_df msa_maddr_q_df msa_msubr_q_df msa_fill_df msa_copy_s_b msa_copy_s_h msa_copy_s_w msa_copy_s_d msa_copy_u_b msa_copy_u_h msa_copy_u_w msa_insert_b msa_insert_h msa_insert_w msa_insert_d msa_fclass_df msa_ftrunc_s_df msa_ftrunc_u_df msa_fsqrt_df msa_frsqrt_df msa_frcp_df msa_frint_df msa_flog2_df msa_fexupl_df msa_fexupr_df msa_ffql_df msa_ffqr_df msa_ftint_s_df msa_ftint_u_df msa_ffint_s_df msa_ffint_u_df msa_ld_b msa_st_b msa_ld_h msa_st_h msa_ld_w msa_st_w msa_ld_d msa_st_d cache trace_guest_mem_before_exec_proxy div_i32 rem_i32 divu_i32 remu_i32 div_i64 rem_i64 divu_i64 remu_i64 shl_i64 shr_i64 sar_i64 mulsh_i64 muluh_i64 clz_i32 ctz_i32 clz_i64 ctz_i64 clrsb_i32 clrsb_i64 ctpop_i32 ctpop_i64 lookup_tb_ptr exit_atomic atomic_cmpxchgb atomic_cmpxchgw_be atomic_cmpxchgw_le atomic_cmpxchgl_be atomic_cmpxchgl_le atomic_cmpxchgq_be atomic_cmpxchgq_le atomic_fetch_addb atomic_fetch_addw_le atomic_fetch_addw_be atomic_fetch_addl_le atomic_fetch_addl_be atomic_fetch_addq_le atomic_fetch_addq_be atomic_fetch_andb atomic_fetch_andw_le atomic_fetch_andw_be atomic_fetch_andl_le atomic_fetch_andl_be atomic_fetch_andq_le atomic_fetch_andq_be atomic_fetch_orb atomic_fetch_orw_le atomic_fetch_orw_be atomic_fetch_orl_le atomic_fetch_orl_be atomic_fetch_orq_le atomic_fetch_orq_be atomic_fetch_xorb atomic_fetch_xorw_le atomic_fetch_xorw_be atomic_fetch_xorl_le atomic_fetch_xorl_be atomic_fetch_xorq_le atomic_fetch_xorq_be atomic_fetch_sminb atomic_fetch_sminw_le atomic_fetch_sminw_be atomic_fetch_sminl_le atomic_fetch_sminl_be atomic_fetch_sminq_le atomic_fetch_sminq_be atomic_fetch_uminb atomic_fetch_uminw_le atomic_fetch_uminw_be atomic_fetch_uminl_le atomic_fetch_uminl_be atomic_fetch_uminq_le atomic_fetch_uminq_be atomic_fetch_smaxb atomic_fetch_smaxw_le atomic_fetch_smaxw_be atomic_fetch_smaxl_le atomic_fetch_smaxl_be atomic_fetch_smaxq_le atomic_fetch_smaxq_be atomic_fetch_umaxb atomic_fetch_umaxw_le atomic_fetch_umaxw_be atomic_fetch_umaxl_le atomic_fetch_umaxl_be atomic_fetch_umaxq_le atomic_fetch_umaxq_be atomic_add_fetchb atomic_add_fetchw_le atomic_add_fetchw_be atomic_add_fetchl_le atomic_add_fetchl_be atomic_add_fetchq_le atomic_add_fetchq_be atomic_and_fetchb atomic_and_fetchw_le atomic_and_fetchw_be atomic_and_fetchl_le atomic_and_fetchl_be atomic_and_fetchq_le atomic_and_fetchq_be atomic_or_fetchb atomic_or_fetchw_le atomic_or_fetchw_be atomic_or_fetchl_le atomic_or_fetchl_be atomic_or_fetchq_le atomic_or_fetchq_be atomic_xor_fetchb atomic_xor_fetchw_le atomic_xor_fetchw_be atomic_xor_fetchl_le atomic_xor_fetchl_be atomic_xor_fetchq_le atomic_xor_fetchq_be atomic_smin_fetchb atomic_smin_fetchw_le atomic_smin_fetchw_be atomic_smin_fetchl_le atomic_smin_fetchl_be atomic_smin_fetchq_le atomic_smin_fetchq_be atomic_umin_fetchb atomic_umin_fetchw_le atomic_umin_fetchw_be atomic_umin_fetchl_le atomic_umin_fetchl_be atomic_umin_fetchq_le atomic_umin_fetchq_be atomic_smax_fetchb atomic_smax_fetchw_le atomic_smax_fetchw_be atomic_smax_fetchl_le atomic_smax_fetchl_be atomic_smax_fetchq_le atomic_smax_fetchq_be atomic_umax_fetchb atomic_umax_fetchw_le atomic_umax_fetchw_be atomic_umax_fetchl_le atomic_umax_fetchl_be atomic_umax_fetchq_le atomic_umax_fetchq_be atomic_xchgb atomic_xchgw_le atomic_xchgw_be atomic_xchgl_le atomic_xchgl_be atomic_xchgq_le atomic_xchgq_be gvec_mov gvec_dup8 gvec_dup16 gvec_dup32 gvec_dup64 gvec_add8 gvec_add16 gvec_add32 gvec_add64 gvec_adds8 gvec_adds16 gvec_adds32 gvec_adds64 gvec_sub8 gvec_sub16 gvec_sub32 gvec_sub64 gvec_subs8 gvec_subs16 gvec_subs32 gvec_subs64 gvec_mul8 gvec_mul16 gvec_mul32 gvec_mul64 gvec_muls8 gvec_muls16 gvec_muls32 gvec_muls64 gvec_ssadd8 gvec_ssadd16 gvec_ssadd32 gvec_ssadd64 gvec_sssub8 gvec_sssub16 gvec_sssub32 gvec_sssub64 gvec_usadd8 gvec_usadd16 gvec_usadd32 gvec_usadd64 gvec_ussub8 gvec_ussub16 gvec_ussub32 gvec_ussub64 gvec_smin8 gvec_smin16 gvec_smin32 gvec_smin64 gvec_smax8 gvec_smax16 gvec_smax32 gvec_smax64 gvec_umin8 gvec_umin16 gvec_umin32 gvec_umin64 gvec_umax8 gvec_umax16 gvec_umax32 gvec_umax64 gvec_neg8 gvec_neg16 gvec_neg32 gvec_neg64 gvec_abs8 gvec_abs16 gvec_abs32 gvec_abs64 gvec_not gvec_and gvec_or gvec_xor gvec_andc gvec_orc gvec_nand gvec_nor gvec_eqv gvec_ands gvec_xors gvec_ors gvec_shl8i gvec_shl16i gvec_shl32i gvec_shl64i gvec_shr8i gvec_shr16i gvec_shr32i gvec_shr64i gvec_sar8i gvec_sar16i gvec_sar32i gvec_sar64i gvec_shl8v gvec_shl16v gvec_shl32v gvec_shl64v gvec_shr8v gvec_shr16v gvec_shr32v gvec_shr64v gvec_sar8v gvec_sar16v gvec_sar32v gvec_sar64v gvec_eq8 gvec_eq16 gvec_eq32 gvec_eq64 gvec_ne8 gvec_ne16 gvec_ne32 gvec_ne64 gvec_lt8 gvec_lt16 gvec_lt32 gvec_lt64 gvec_le8 gvec_le16 gvec_le32 gvec_le64 gvec_ltu8 gvec_ltu16 gvec_ltu32 gvec_ltu64 gvec_leu8 gvec_leu16 gvec_leu32 gvec_leu64 gvec_bitsel

mipsel_HELPERS := raise_exception_err raise_exception raise_exception_debug swl swr muls mulsu macc maccu msac msacu mulhi mulhiu mulshi mulshiu macchi macchiu msachi msachiu bitswap rotx lwm swm fork yield cfc1 ctc1 float_cvtd_s float_cvtd_w float_cvtd_l float_cvtps_pw float_cvtpw_ps float_cvts_d float_cvts_w float_cvts_l float_cvts_pl float_cvts_pu float_addr_ps float_mulr_ps float_class_s float_class_d float_maddf_s float_maddf_d float_msubf_s float_msubf_d float_max_s float_max_d float_maxa_s float_maxa_d float_min_s float_min_d float_mina_s float_mina_d float_cvt_l_s float_cvt_l_d float_cvt_w_s float_cvt_w_d float_round_l_s float_round_l_d float_round_w_s float_round_w_d float_trunc_l_s float_trunc_l_d float_trunc_w_s float_trunc_w_d float_ceil_l_s float_ceil_l_d float_ceil_w_s float_ceil_w_d float_floor_l_s float_floor_l_d float_floor_w_s float_floor_w_d float_cvt_2008_l_s float_cvt_2008_l_d float_cvt_2008_w_s float_cvt_2008_w_d float_round_2008_l_s float_round_2008_l_d float_round_2008_w_s float_round_2008_w_d float_trunc_2008_l_s float_trunc_2008_l_d float_trunc_2008_w_s float_trunc_2008_w_d float_ceil_2008_l_s float_ceil_2008_l_d float_ceil_2008_w_s float_ceil_2008_w_d float_floor_2008_l_s float_floor_2008_l_d float_floor_2008_w_s float_floor_2008_w_d float_sqrt_s float_sqrt_d float_rsqrt_s float_rsqrt_d float_recip_s float_recip_d float_rint_s float_rint_d float_abs_s float_abs_d float_abs_ps float_chs_s float_chs_d float_chs_ps float_recip1_s float_recip1_d float_recip1_ps float_rsqrt1_s float_rsqrt1_d float_rsqrt1_ps float_add_s float_add_d float_add_ps float_sub_s float_sub_d float_sub_ps float_mul_s float_mul_d float_mul_ps float_div_s float_div_d float_div_ps float_recip2_s float_recip2_d float_recip2_ps float_rsqrt2_s float_rsqrt2_d float_rsqrt2_ps float_madd_s float_madd_d float_madd_ps float_msub_s float_msub_d float_msub_ps float_nmadd_s float_nmadd_d float_nmadd_ps float_nmsub_s float_nmsub_d float_nmsub_ps cmp_d_f cmpabs_d_f cmp_s_f cmpabs_s_f cmp_ps_f cmpabs_ps_f cmp_d_un cmpabs_d_un cmp_s_un cmpabs_s_un cmp_ps_un cmpabs_ps_un cmp_d_eq cmpabs_d_eq cmp_s_eq cmpabs_s_eq cmp_ps_eq cmpabs_ps_eq cmp_d_ueq cmpabs_d_ueq cmp_s_ueq cmpabs_s_ueq cmp_ps_ueq cmpabs_ps_ueq cmp_d_olt cmpabs_d_olt cmp_s_olt cmpabs_s_olt cmp_ps_olt cmpabs_ps_olt cmp_d_ult cmpabs_d_ult cmp_s_ult cmpabs_s_ult cmp_ps_ult cmpabs_ps_ult cmp_d_ole cmpabs_d_ole cmp_s_ole cmpabs_s_ole cmp_ps_ole cmpabs_ps_ole cmp_d_ule cmpabs_d_ule cmp_s_ule cmpabs_s_ule cmp_ps_ule cmpabs_ps_ule cmp_d_sf cmpabs_d_sf cmp_s_sf cmpabs_s_sf cmp_ps_sf cmpabs_ps_sf cmp_d_ngle cmpabs_d_ngle cmp_s_ngle cmpabs_s_ngle cmp_ps_ngle cmpabs_ps_ngle cmp_d_seq cmpabs_d_seq cmp_s_seq cmpabs_s_seq cmp_ps_seq cmpabs_ps_seq cmp_d_ngl cmpabs_d_ngl cmp_s_ngl cmpabs_s_ngl cmp_ps_ngl cmpabs_ps_ngl cmp_d_lt cmpabs_d_lt cmp_s_lt cmpabs_s_lt cmp_ps_lt cmpabs_ps_lt cmp_d_nge cmpabs_d_nge cmp_s_nge cmpabs_s_nge cmp_ps_nge cmpabs_ps_nge cmp_d_le cmpabs_d_le cmp_s_le cmpabs_s_le cmp_ps_le cmpabs_ps_le cmp_d_ngt cmpabs_d_ngt cmp_s_ngt cmpabs_s_ngt cmp_ps_ngt cmpabs_ps_ngt r6_cmp_d_af r6_cmp_s_af r6_cmp_d_un r6_cmp_s_un r6_cmp_d_eq r6_cmp_s_eq r6_cmp_d_ueq r6_cmp_s_ueq r6_cmp_d_lt r6_cmp_s_lt r6_cmp_d_ult r6_cmp_s_ult r6_cmp_d_le r6_cmp_s_le r6_cmp_d_ule r6_cmp_s_ule r6_cmp_d_saf r6_cmp_s_saf r6_cmp_d_sun r6_cmp_s_sun r6_cmp_d_seq r6_cmp_s_seq r6_cmp_d_sueq r6_cmp_s_sueq r6_cmp_d_slt r6_cmp_s_slt r6_cmp_d_sult r6_cmp_s_sult r6_cmp_d_sle r6_cmp_s_sle r6_cmp_d_sule r6_cmp_s_sule r6_cmp_d_or r6_cmp_s_or r6_cmp_d_une r6_cmp_s_une r6_cmp_d_ne r6_cmp_s_ne r6_cmp_d_sor r6_cmp_s_sor r6_cmp_d_sune r6_cmp_s_sune r6_cmp_d_sne r6_cmp_s_sne rdhwr_cpunum rdhwr_synci_step rdhwr_cc rdhwr_ccres rdhwr_performance rdhwr_xnp pmon wait paddsh paddush paddh paddw paddsb paddusb paddb psubsh psubush psubh psubw psubsb psubusb psubb pshufh packsswh packsshb packushb punpcklhw punpckhhw punpcklbh punpckhbh punpcklwd punpckhwd pavgh pavgb pmaxsh pminsh pmaxub pminub pcmpeqw pcmpgtw pcmpeqh pcmpgth pcmpeqb pcmpgtb psllw psllh psrlw psrlh psraw psrah pmullh pmulhh pmulhuh pmaddhw pasubub biadd pmovmskb addq_ph addq_s_ph addq_s_w addu_qb addu_s_qb adduh_qb adduh_r_qb addu_ph addu_s_ph addqh_ph addqh_r_ph addqh_w addqh_r_w subq_ph subq_s_ph subq_s_w subu_qb subu_s_qb subuh_qb subuh_r_qb subu_ph subu_s_ph subqh_ph subqh_r_ph subqh_w subqh_r_w addsc addwc modsub raddu_w_qb absq_s_qb absq_s_ph absq_s_w precr_qb_ph precrq_qb_ph precr_sra_ph_w precr_sra_r_ph_w precrq_ph_w precrq_rs_ph_w precrqu_s_qb_ph precequ_ph_qbl precequ_ph_qbr precequ_ph_qbla precequ_ph_qbra preceu_ph_qbl preceu_ph_qbr preceu_ph_qbla preceu_ph_qbra shll_qb shll_ph shll_s_ph shll_s_w shrl_qb shrl_ph shra_qb shra_r_qb shra_ph shra_r_ph shra_r_w muleu_s_ph_qbl muleu_s_ph_qbr mulq_rs_ph muleq_s_w_phl muleq_s_w_phr dpau_h_qbl dpau_h_qbr dpsu_h_qbl dpsu_h_qbr dpa_w_ph dpax_w_ph dpaq_s_w_ph dpaqx_s_w_ph dpaqx_sa_w_ph dps_w_ph dpsx_w_ph dpsq_s_w_ph dpsqx_s_w_ph dpsqx_sa_w_ph mulsaq_s_w_ph dpaq_sa_l_w dpsq_sa_l_w maq_s_w_phl maq_s_w_phr maq_sa_w_phl maq_sa_w_phr mul_ph mul_s_ph mulq_s_ph mulq_s_w mulq_rs_w mulsa_w_ph bitrev insv cmpu_eq_qb cmpu_lt_qb cmpu_le_qb cmpgu_eq_qb cmpgu_lt_qb cmpgu_le_qb cmp_eq_ph cmp_lt_ph cmp_le_ph pick_qb pick_ph packrl_ph extr_w extr_r_w extr_rs_w extr_s_h extp extpdp shilo mthlip wrdsp rddsp msa_nloc_b msa_nloc_h msa_nloc_w msa_nloc_d msa_nlzc_b msa_nlzc_h msa_nlzc_w msa_nlzc_d msa_pcnt_b msa_pcnt_h msa_pcnt_w msa_pcnt_d msa_binsl_b msa_binsl_h msa_binsl_w msa_binsl_d msa_binsr_b msa_binsr_h msa_binsr_w msa_binsr_d msa_bmnz_v msa_bmz_v msa_bsel_v msa_bclr_b msa_bclr_h msa_bclr_w msa_bclr_d msa_bneg_b msa_bneg_h msa_bneg_w msa_bneg_d msa_bset_b msa_bset_h msa_bset_w msa_bset_d msa_add_a_b msa_add_a_h msa_add_a_w msa_add_a_d msa_adds_a_b msa_adds_a_h msa_adds_a_w msa_adds_a_d msa_adds_s_b msa_adds_s_h msa_adds_s_w msa_adds_s_d msa_adds_u_b msa_adds_u_h msa_adds_u_w msa_adds_u_d msa_addv_b msa_addv_h msa_addv_w msa_addv_d msa_hadd_s_h msa_hadd_s_w msa_hadd_s_d msa_hadd_u_h msa_hadd_u_w msa_hadd_u_d msa_ave_s_b msa_ave_s_h msa_ave_s_w msa_ave_s_d msa_ave_u_b msa_ave_u_h msa_ave_u_w msa_ave_u_d msa_aver_s_b msa_aver_s_h msa_aver_s_w msa_aver_s_d msa_aver_u_b msa_aver_u_h msa_aver_u_w msa_aver_u_d msa_ceq_b msa_ceq_h msa_ceq_w msa_ceq_d msa_cle_s_b msa_cle_s_h msa_cle_s_w msa_cle_s_d msa_cle_u_b msa_cle_u_h msa_cle_u_w msa_cle_u_d msa_clt_s_b msa_clt_s_h msa_clt_s_w msa_clt_s_d msa_clt_u_b msa_clt_u_h msa_clt_u_w msa_clt_u_d msa_div_s_b msa_div_s_h msa_div_s_w msa_div_s_d msa_div_u_b msa_div_u_h msa_div_u_w msa_div_u_d msa_max_a_b msa_max_a_h msa_max_a_w msa_max_a_d msa_max_s_b msa_max_s_h msa_max_s_w msa_max_s_d msa_max_u_b msa_max_u_h msa_max_u_w msa_max_u_d msa_min_a_b msa_min_a_h msa_min_a_w msa_min_a_d msa_min_s_b msa_min_s_h msa_min_s_w msa_min_s_d msa_min_u_b msa_min_u_h msa_min_u_w msa_min_u_d msa_mod_u_b msa_mod_u_h msa_mod_u_w msa_mod_u_d msa_mod_s_b msa_mod_s_h msa_mod_s_w msa_mod_s_d msa_asub_s_b msa_asub_s_h msa_asub_s_w msa_asub_s_d msa_asub_u_b msa_asub_u_h msa_asub_u_w msa_asub_u_d msa_hsub_s_h msa_hsub_s_w msa_hsub_s_d msa_hsub_u_h msa_hsub_u_w msa_hsub_u_d msa_ilvev_b msa_ilvev_h msa_ilvev_w msa_ilvev_d msa_ilvod_b msa_ilvod_h msa_ilvod_w msa_ilvod_d msa_ilvl_b msa_ilvl_h msa_ilvl_w msa_ilvl_d msa_ilvr_b msa_ilvr_h msa_ilvr_w msa_ilvr_d msa_and_v msa_nor_v msa_or_v msa_xor_v msa_pckev_b msa_pckev_h msa_pckev_w msa_pckev_d msa_pckod_b msa_pckod_h msa_pckod_w msa_pckod_d msa_sll_b msa_sll_h msa_sll_w msa_sll_d msa_sra_b msa_sra_h msa_sra_w msa_sra_d msa_srar_b msa_srar_h msa_srar_w msa_srar_d msa_srl_b msa_srl_h msa_srl_w msa_srl_d msa_srlr_b msa_srlr_h msa_srlr_w msa_srlr_d msa_move_v msa_andi_b msa_ori_b msa_nori_b msa_xori_b msa_bmnzi_b msa_bmzi_b msa_bseli_b msa_shf_df msa_addvi_df msa_subvi_df msa_maxi_s_df msa_maxi_u_df msa_mini_s_df msa_mini_u_df msa_ceqi_df msa_clti_s_df msa_clti_u_df msa_clei_s_df msa_clei_u_df msa_ldi_df msa_slli_df msa_srai_df msa_srli_df msa_bclri_df msa_bseti_df msa_bnegi_df msa_binsli_df msa_binsri_df msa_sat_s_df msa_sat_u_df msa_srari_df msa_srlri_df msa_binsl_df msa_binsr_df msa_subv_df msa_subs_s_df msa_subs_u_df msa_subsus_u_df msa_subsuu_s_df msa_mulv_df msa_maddv_df msa_msubv_df msa_dotp_s_df msa_dotp_u_df msa_dpadd_s_df msa_dpadd_u_df msa_dpsub_s_df msa_dpsub_u_df msa_sld_df msa_splat_df msa_vshf_df msa_sldi_df msa_splati_df msa_insve_df msa_ctcmsa msa_cfcmsa msa_fcaf_df msa_fcun_df msa_fceq_df msa_fcueq_df msa_fclt_df msa_fcult_df msa_fcle_df msa_fcule_df msa_fsaf_df msa_fsun_df msa_fseq_df msa_fsueq_df msa_fslt_df msa_fsult_df msa_fsle_df msa_fsule_df msa_fadd_df msa_fsub_df msa_fmul_df msa_fdiv_df msa_fmadd_df msa_fmsub_df msa_fexp2_df msa_fexdo_df msa_ftq_df msa_fmin_df msa_fmin_a_df msa_fmax_df msa_fmax_a_df msa_fcor_df msa_fcune_df msa_fcne_df msa_mul_q_df msa_madd_q_df msa_msub_q_df msa_fsor_df msa_fsune_df msa_fsne_df msa_mulr_q_df msa_maddr_q_df msa_msubr_q_df msa_fill_df msa_copy_s_b msa_copy_s_h msa_copy_s_w msa_copy_s_d msa_copy_u_b msa_copy_u_h msa_copy_u_w msa_insert_b msa_insert_h msa_insert_w msa_insert_d msa_fclass_df msa_ftrunc_s_df msa_ftrunc_u_df msa_fsqrt_df msa_frsqrt_df msa_frcp_df msa_frint_df msa_flog2_df msa_fexupl_df msa_fexupr_df msa_ffql_df msa_ffqr_df msa_ftint_s_df msa_ftint_u_df msa_ffint_s_df msa_ffint_u_df msa_ld_b msa_st_b msa_ld_h msa_st_h msa_ld_w msa_st_w msa_ld_d msa_st_d cache trace_guest_mem_before_exec_proxy div_i32 rem_i32 divu_i32 remu_i32 div_i64 rem_i64 divu_i64 remu_i64 shl_i64 shr_i64 sar_i64 mulsh_i64 muluh_i64 clz_i32 ctz_i32 clz_i64 ctz_i64 clrsb_i32 clrsb_i64 ctpop_i32 ctpop_i64 lookup_tb_ptr exit_atomic atomic_cmpxchgb atomic_cmpxchgw_be atomic_cmpxchgw_le atomic_cmpxchgl_be atomic_cmpxchgl_le atomic_cmpxchgq_be atomic_cmpxchgq_le atomic_fetch_addb atomic_fetch_addw_le atomic_fetch_addw_be atomic_fetch_addl_le atomic_fetch_addl_be atomic_fetch_addq_le atomic_fetch_addq_be atomic_fetch_andb atomic_fetch_andw_le atomic_fetch_andw_be atomic_fetch_andl_le atomic_fetch_andl_be atomic_fetch_andq_le atomic_fetch_andq_be atomic_fetch_orb atomic_fetch_orw_le atomic_fetch_orw_be atomic_fetch_orl_le atomic_fetch_orl_be atomic_fetch_orq_le atomic_fetch_orq_be atomic_fetch_xorb atomic_fetch_xorw_le atomic_fetch_xorw_be atomic_fetch_xorl_le atomic_fetch_xorl_be atomic_fetch_xorq_le atomic_fetch_xorq_be atomic_fetch_sminb atomic_fetch_sminw_le atomic_fetch_sminw_be atomic_fetch_sminl_le atomic_fetch_sminl_be atomic_fetch_sminq_le atomic_fetch_sminq_be atomic_fetch_uminb atomic_fetch_uminw_le atomic_fetch_uminw_be atomic_fetch_uminl_le atomic_fetch_uminl_be atomic_fetch_uminq_le atomic_fetch_uminq_be atomic_fetch_smaxb atomic_fetch_smaxw_le atomic_fetch_smaxw_be atomic_fetch_smaxl_le atomic_fetch_smaxl_be atomic_fetch_smaxq_le atomic_fetch_smaxq_be atomic_fetch_umaxb atomic_fetch_umaxw_le atomic_fetch_umaxw_be atomic_fetch_umaxl_le atomic_fetch_umaxl_be atomic_fetch_umaxq_le atomic_fetch_umaxq_be atomic_add_fetchb atomic_add_fetchw_le atomic_add_fetchw_be atomic_add_fetchl_le atomic_add_fetchl_be atomic_add_fetchq_le atomic_add_fetchq_be atomic_and_fetchb atomic_and_fetchw_le atomic_and_fetchw_be atomic_and_fetchl_le atomic_and_fetchl_be atomic_and_fetchq_le atomic_and_fetchq_be atomic_or_fetchb atomic_or_fetchw_le atomic_or_fetchw_be atomic_or_fetchl_le atomic_or_fetchl_be atomic_or_fetchq_le atomic_or_fetchq_be atomic_xor_fetchb atomic_xor_fetchw_le atomic_xor_fetchw_be atomic_xor_fetchl_le atomic_xor_fetchl_be atomic_xor_fetchq_le atomic_xor_fetchq_be atomic_smin_fetchb atomic_smin_fetchw_le atomic_smin_fetchw_be atomic_smin_fetchl_le atomic_smin_fetchl_be atomic_smin_fetchq_le atomic_smin_fetchq_be atomic_umin_fetchb atomic_umin_fetchw_le atomic_umin_fetchw_be atomic_umin_fetchl_le atomic_umin_fetchl_be atomic_umin_fetchq_le atomic_umin_fetchq_be atomic_smax_fetchb atomic_smax_fetchw_le atomic_smax_fetchw_be atomic_smax_fetchl_le atomic_smax_fetchl_be atomic_smax_fetchq_le atomic_smax_fetchq_be atomic_umax_fetchb atomic_umax_fetchw_le atomic_umax_fetchw_be atomic_umax_fetchl_le atomic_umax_fetchl_be atomic_umax_fetchq_le atomic_umax_fetchq_be atomic_xchgb atomic_xchgw_le atomic_xchgw_be atomic_xchgl_le atomic_xchgl_be atomic_xchgq_le atomic_xchgq_be gvec_mov gvec_dup8 gvec_dup16 gvec_dup32 gvec_dup64 gvec_add8 gvec_add16 gvec_add32 gvec_add64 gvec_adds8 gvec_adds16 gvec_adds32 gvec_adds64 gvec_sub8 gvec_sub16 gvec_sub32 gvec_sub64 gvec_subs8 gvec_subs16 gvec_subs32 gvec_subs64 gvec_mul8 gvec_mul16 gvec_mul32 gvec_mul64 gvec_muls8 gvec_muls16 gvec_muls32 gvec_muls64 gvec_ssadd8 gvec_ssadd16 gvec_ssadd32 gvec_ssadd64 gvec_sssub8 gvec_sssub16 gvec_sssub32 gvec_sssub64 gvec_usadd8 gvec_usadd16 gvec_usadd32 gvec_usadd64 gvec_ussub8 gvec_ussub16 gvec_ussub32 gvec_ussub64 gvec_smin8 gvec_smin16 gvec_smin32 gvec_smin64 gvec_smax8 gvec_smax16 gvec_smax32 gvec_smax64 gvec_umin8 gvec_umin16 gvec_umin32 gvec_umin64 gvec_umax8 gvec_umax16 gvec_umax32 gvec_umax64 gvec_neg8 gvec_neg16 gvec_neg32 gvec_neg64 gvec_abs8 gvec_abs16 gvec_abs32 gvec_abs64 gvec_not gvec_and gvec_or gvec_xor gvec_andc gvec_orc gvec_nand gvec_nor gvec_eqv gvec_ands gvec_xors gvec_ors gvec_shl8i gvec_shl16i gvec_shl32i gvec_shl64i gvec_shr8i gvec_shr16i gvec_shr32i gvec_shr64i gvec_sar8i gvec_sar16i gvec_sar32i gvec_sar64i gvec_shl8v gvec_shl16v gvec_shl32v gvec_shl64v gvec_shr8v gvec_shr16v gvec_shr32v gvec_shr64v gvec_sar8v gvec_sar16v gvec_sar32v gvec_sar64v gvec_eq8 gvec_eq16 gvec_eq32 gvec_eq64 gvec_ne8 gvec_ne16 gvec_ne32 gvec_ne64 gvec_lt8 gvec_lt16 gvec_lt32 gvec_lt64 gvec_le8 gvec_le16 gvec_le32 gvec_le64 gvec_ltu8 gvec_ltu16 gvec_ltu32 gvec_ltu64 gvec_leu8 gvec_leu16 gvec_leu32 gvec_leu64 gvec_bitsel

HELPERS_BITCODE := $(foreach helper,$($(ARCH)_HELPERS),$(BINDIR)/$(helper).bc)
HELPERS_DFSAN_BITCODE := $(foreach helper,$($(ARCH)_HELPERS),$(BINDIR)/$(helper).dfsan.bc)

HELPERS_ASSEMBLY := $(foreach helper,$($(ARCH)_HELPERS),$(BINDIR)/$(helper).ll)
HELPERS_DFSAN_ASSEMBLY := $(foreach helper,$($(ARCH)_HELPERS),$(BINDIR)/$(helper).dfsan.ll)

all: $(UTILBINS) $(TOOLBINS) $(JOVE_RT) $(JOVE_DYN_PRELOAD) $(BINDIR)/jove.bc $(BINDIR)/jove.dfsan.bc $(HELPERS_BITCODE) $(HELPERS_DFSAN_BITCODE) $(HELPERS_ASSEMBLY) $(HELPERS_DFSAN_ASSEMBLY)

helpers: $(HELPERS_BITCODE)

define build_tool_template
$(BINDIR)/$(1): $(TOOLSRCDIR)/$(1).cpp
	@echo CXX $(1)
ifdef BUILD_STATIC
	@$(_LLVM_CXX) -o $$@ -pipe -MMD $(CXXFLAGS) $$< $(LDFLAGS) -fPIC -static
else
	@$(_LLVM_CXX) -o $$@ -pipe -MMD $(CXXFLAGS) $$< $(LDFLAGS)
endif
endef
$(foreach tool,$(TOOLS),$(eval $(call build_tool_template,$(tool))))

define build_util_template
$(BINDIR)/$(1): $(UTILSRCDIR)/$(1).cpp
	@echo CXX $(1)
ifdef BUILD_STATIC
	@$(_LLVM_CXX) -o $$@ -pipe -MMD $(CXXFLAGS) $$< $(LDFLAGS) -fPIC -static
else
	@$(_LLVM_CXX) -o $$@ -pipe -MMD $(CXXFLAGS) $$< $(LDFLAGS)
endif
endef
$(foreach util,$(UTILS),$(eval $(call build_util_template,$(util))))

.PHONY: gen-tcgconstants
gen-tcgconstants: $(BINDIR)/gen-tcgconstants
	@echo GEN $@
	@$< > include/jove/arch/$(ARCH)/tcgconstants.h

$(JOVE_RT): lib/arch/$(ARCH)/rt.c
	@echo CC $<
	@$(_LLVM_CC) -o $@ -shared -Wl,-soname=$(JOVE_RT_SONAME) -nostdlib -Ofast -ffreestanding -fno-stack-protector -fPIC -g -Wall -I lib -I lib/arch/$(ARCH) $<
	@ln -sf $(JOVE_RT_SO) $(BINDIR)/$(JOVE_RT_SONAME)

$(JOVE_DYN_PRELOAD): lib/jove-bootstrap/preload.c
	@echo CC $<
	@$(_LLVM_CC) -o $@ -shared -Wl,-soname=$(JOVE_DYN_PRELOAD_SONAME) -Ofast -fno-stack-protector -fPIC -g -Wall $<
	@ln -sf $(JOVE_DYN_PRELOAD_SO) $(BINDIR)/$(JOVE_DYN_PRELOAD_SONAME)

$(BINDIR)/jove.bc: lib/arch/$(ARCH)/jove.c
	@echo CC $<
	@$(_LLVM_CC) -o $@ -c -emit-llvm -I lib -Ofast -ffreestanding -fno-stack-protector -fPIC -g -Wall $<

$(BINDIR)/jove.dfsan.bc: lib/arch/$(ARCH)/jove.c
	@echo CC "(DFSAN)" $<
	@$(_LLVM_CC) -o $@ -c -emit-llvm -I lib -Ofast -ffreestanding -fno-stack-protector -fPIC -g -Wall -DJOVE_DFSAN $<

-include $(TOOLDEPS)
-include $(UTILDEPS)

VER := $(shell git log -n1 --format="%h")

.PHONY: package
package:
	tar cvf jove.$(VER)-$(ARCH).tar $(TOOLBINS) $(UTILBINS) $(JOVE_RT) $(BINDIR)/jove.bc $(BINDIR)/jove.dfsan.bc $(HELPERS_BITCODE) $(HELPERS_DFSAN_BITCODE) bin/dfsan_abilist.txt
ifndef PACKAGE_TARBALL
	xz --threads=0 jove.$(VER)-$(ARCH).tar
endif

.PHONY: clean
clean:
	rm -rf $(TOOLBINS) $(UTILBINS) $(JOVE_RT) $(BINDIR)/jove.bc $(BINDIR)/jove.dfsan.bc $(TOOLDEPS) $(UTILDEPS) $(HELPERS_BITCODE) $(HELPERS_ASSEMBLY) $(HELPERS_DFSAN_ASSEMBLY) $(HELPERS_DFSAN_BITCODE) $(JOVE_DYN_PRELOAD) $(BINDIR)/$(JOVE_DYN_PRELOAD_SONAME) $(BINDIR)/$(JOVE_RT_SONAME)

#
# for extricating QEMU code
#

CLANG_EXTRICATE := ~/clang-extricate
QEMU_SRC_DIR    := ~/qemu
QEMU_BUILD_DIR  := ~/qemu

_SL_TCG_GEN_ADDI_I64 := tcg/tcg-op.c:1243l
_SL_TCG_OPTIMIZE     := tcg/optimize.c:599l
_SL_TCG_OP_DEFS      := tcg/tcg-common.c:35l
_SL_TB_GEN_CODE      := accel/tcg/translate-all.c:1667l
_SL_TRANSLATOR_LOOP  := accel/tcg/translator.c:36l
_SL_PSTRCPY          := util/cutils.c:45l

COMMON_SOURCE_LOCATIONS := $(_SL_TCG_GEN_ADDI_I64) \
                           $(_SL_TCG_OPTIMIZE) \
                           $(_SL_TCG_OP_DEFS) \
                           $(_SL_TB_GEN_CODE) \
                           $(_SL_TRANSLATOR_LOOP) \
                           $(_SL_PSTRCPY)

_SL_X86_64_TCG_CONTEXT_INIT := tcg/tcg.c:2412l
_SL_X86_64_TCG_FUNC_START   := tcg/tcg.c:2602l
_SL_X86_64_TCG_GEN_CODE     := tcg/tcg.c:5492l

_SL_X86_64_GEN_INTERMEDIATE_CODE  := target/i386/translate.c:8616l
_SL_X86_64_TCG_X86_INIT           := target/i386/translate.c:8374l
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

#                           $(_SL_X86_64_TCG_GEN_GVEC_NOT) \
#                           $(_SL_X86_64_TCG_GEN_LD_VEC)

_SL_AARCH64_TCG_CONTEXT_INIT := tcg/tcg.c:3844l
_SL_AARCH64_TCG_FUNC_START   := tcg/tcg.c:4034l
_SL_AARCH64_TCG_GEN_CODE     := tcg/tcg.c:6924l

_SL_AARCH64_GEN_INTERMEDIATE_CODE := target/arm/translate.c:14082l
_SL_AARCH64_TRANSLATOR_OPS        := target/arm/translate-a64.c:14354l
_SL_AARCH64_TRANSLATE_INIT        := target/arm/translate.c:85l
_SL_AARCH64_TCG_GEN_GVEC_NOT      := tcg/tcg-op-gvec.c:1542l
_SL_AARCH64_TCG_GEN_LD_VEC        := tcg/tcg-op-vec.c:338l
_SL_AARCH64_TCG_DISAS_SVE         := target/arm/translate-sve.c:1913l
_SL_AARCH64_REGISTER_CP_REGS_FOR_FEATURES := target/arm/helper.c:5979l
_SL_AARCH64_INIT_CPREG_LIST := target/arm/helper.c:376l

aarch64_SOURCE_LOCATIONS := $(_SL_AARCH64_TCG_CONTEXT_INIT) \
                            $(_SL_AARCH64_TCG_FUNC_START) \
                            $(_SL_AARCH64_TCG_GEN_CODE) \
                            $(_SL_AARCH64_GEN_INTERMEDIATE_CODE) \
                            $(_SL_AARCH64_TRANSLATOR_OPS) \
                            $(_SL_AARCH64_TRANSLATE_INIT) \
                            $(_SL_AARCH64_TCG_GEN_GVEC_NOT) \
                            $(_SL_AARCH64_TCG_GEN_LD_VEC) \
                            $(_SL_AARCH64_TCG_DISAS_SVE) \
                            $(_SL_AARCH64_REGISTER_CP_REGS_FOR_FEATURES) \
                            $(_SL_AARCH64_INIT_CPREG_LIST)

.PHONY: extract-tcg-code
extract-tcg-code:
	$(CLANG_EXTRICATE)/extract/bin/carbon-extract --src $(QEMU_SRC_DIR) --bin $(QEMU_BUILD_DIR) $(COMMON_SOURCE_LOCATIONS) $($(ARCH)_SOURCE_LOCATIONS) > lib/arch/$(ARCH)/tcg.hpp


aarch64-setend_EXTRICATE_ARGS := target/arm/helper.c:11245l
aarch64-setend_EXTRICATE_ARGS += target/arm/m_helper.c:2717l
aarch64-setend_EXTRICATE_ARGS += util/bitops.c:131l

_SL_FLOAT32ADD := fpu/softfloat.c:1168l
_SL_FLOAT32MAX := fpu/softfloat.c:2890l
_SL_FLOAT32MIN := fpu/softfloat.c:2887l

aarch64-vfp_adds_EXTRICATE_ARGS := $(_SL_FLOAT32ADD)
aarch64-vfp_addd_EXTRICATE_ARGS := $(_SL_FLOAT32ADD)

aarch64-vfp_subs_EXTRICATE_ARGS := $(_SL_FLOAT32ADD)
aarch64-vfp_subd_EXTRICATE_ARGS := $(_SL_FLOAT32ADD)

aarch64-vfp_divs_EXTRICATE_ARGS := $(_SL_FLOAT32ADD)
aarch64-vfp_divd_EXTRICATE_ARGS := $(_SL_FLOAT32ADD)

aarch64-vfp_muls_EXTRICATE_ARGS := $(_SL_FLOAT32ADD)
aarch64-vfp_muld_EXTRICATE_ARGS := $(_SL_FLOAT32ADD)

aarch64-vfp_maxs_EXTRICATE_ARGS := $(_SL_FLOAT32MAX)
aarch64-vfp_maxd_EXTRICATE_ARGS := $(_SL_FLOAT32MAX)

aarch64-vfp_mins_EXTRICATE_ARGS := $(_SL_FLOAT32MIN)
aarch64-vfp_mind_EXTRICATE_ARGS := $(_SL_FLOAT32MIN)

aarch64-vfp_maxnums_EXTRICATE_ARGS := float32_maxnum
aarch64-vfp_maxnumd_EXTRICATE_ARGS := float64_maxnum

aarch64-vfp_minnums_EXTRICATE_ARGS := float32_minnum
aarch64-vfp_minnumd_EXTRICATE_ARGS := float64_minnum

aarch64-vfp_sqrts_EXTRICATE_ARGS := float32_sqrt
aarch64-vfp_sqrtd_EXTRICATE_ARGS := float64_sqrt

aarch64-vfp_cmps_EXTRICATE_ARGS := float32_compare float32_compare_quiet
aarch64-vfp_cmpd_EXTRICATE_ARGS := float64_compare float64_compare_quiet

aarch64-vfp_cmpes_EXTRICATE_ARGS := float32_compare float32_compare_quiet
aarch64-vfp_cmped_EXTRICATE_ARGS := float64_compare float64_compare_quiet

aarch64-vfp_fcvtds_EXTRICATE_ARGS := float32_to_float64
aarch64-vfp_fcvtsd_EXTRICATE_ARGS := float64_to_float32
aarch64-vfp_uitoh_EXTRICATE_ARGS := float16_to_uint32_round_to_zero float16_to_uint32 uint32_to_float16 float_raise
aarch64-vfp_uitos_EXTRICATE_ARGS := float32_to_uint32_round_to_zero float32_to_uint32 uint32_to_float32 float_raise
aarch64-vfp_uitod_EXTRICATE_ARGS := float64_to_uint32_round_to_zero float64_to_uint32 uint32_to_float64 float_raise
aarch64-vfp_sitoh_EXTRICATE_ARGS := float16_to_int32_round_to_zero float16_to_int32 int32_to_float16 float_raise
aarch64-vfp_sitos_EXTRICATE_ARGS := float32_to_int32_round_to_zero int32_to_float32 float32_to_int32 float_raise
aarch64-vfp_sitod_EXTRICATE_ARGS := float64_to_int32_round_to_zero float64_to_int32 int32_to_float64 float_raise
aarch64-vfp_touih_EXTRICATE_ARGS := float16_to_uint32_round_to_zero float16_to_uint32 uint32_to_float16 float_raise
aarch64-vfp_touis_EXTRICATE_ARGS := float32_to_uint32_round_to_zero float32_to_uint32 uint32_to_float32 float_raise
aarch64-vfp_touid_EXTRICATE_ARGS := float64_to_uint32_round_to_zero float64_to_uint32 uint32_to_float64 float_raise
aarch64-vfp_touizh_EXTRICATE_ARGS := float16_to_uint32_round_to_zero float16_to_uint32 uint32_to_float16 float_raise
aarch64-vfp_touizs_EXTRICATE_ARGS := float32_to_uint32_round_to_zero float32_to_uint32 uint32_to_float32 float_raise
aarch64-vfp_touizd_EXTRICATE_ARGS := float64_to_uint32_round_to_zero float64_to_uint32 uint32_to_float64 float_raise
aarch64-vfp_tosih_EXTRICATE_ARGS := float16_to_int32_round_to_zero float16_to_int32 int32_to_float16 float_raise
aarch64-vfp_tosis_EXTRICATE_ARGS := float32_to_int32_round_to_zero int32_to_float32 float32_to_int32 float_raise
aarch64-vfp_tosid_EXTRICATE_ARGS := float64_to_int32_round_to_zero float64_to_int32 int32_to_float64 float_raise
aarch64-vfp_tosizh_EXTRICATE_ARGS := float16_to_int32_round_to_zero float16_to_int32 int32_to_float16 float_raise
aarch64-vfp_tosizs_EXTRICATE_ARGS := float32_to_int32_round_to_zero int32_to_float32 float32_to_int32 float_raise
aarch64-vfp_tosizd_EXTRICATE_ARGS := float64_to_int32_round_to_zero float64_to_int32 int32_to_float64 float_raise
aarch64-vfp_toshs_round_to_zero_EXTRICATE_ARGS := float32_to_int16_scalbn int16_to_float32_scalbn float_raise
aarch64-vfp_tosls_round_to_zero_EXTRICATE_ARGS := float32_to_int32_scalbn int32_to_float32_scalbn float_raise
aarch64-vfp_touhs_round_to_zero_EXTRICATE_ARGS := float32_to_uint16_scalbn uint16_to_float32_scalbn float_raise
aarch64-vfp_touls_round_to_zero_EXTRICATE_ARGS := uint32_to_float32_scalbn float32_to_uint32_scalbn float_raise
aarch64-vfp_toshd_round_to_zero_EXTRICATE_ARGS := float64_to_int16_scalbn int16_to_float64_scalbn float_raise
aarch64-vfp_tosld_round_to_zero_EXTRICATE_ARGS := float64_to_int32_scalbn int32_to_float64_scalbn float_raise
aarch64-vfp_touhd_round_to_zero_EXTRICATE_ARGS := float64_to_uint16_scalbn uint16_to_float64_scalbn float_raise
aarch64-vfp_tould_round_to_zero_EXTRICATE_ARGS := uint32_to_float64_scalbn float64_to_uint32_scalbn float_raise
aarch64-vfp_touhh_EXTRICATE_ARGS := float16_to_uint16_scalbn float_raise
aarch64-vfp_toshh_EXTRICATE_ARGS := float16_to_int16_scalbn float_raise
aarch64-vfp_toulh_EXTRICATE_ARGS := float16_to_uint32_scalbn float_raise
aarch64-vfp_toslh_EXTRICATE_ARGS := float16_to_int32_scalbn float_raise
aarch64-vfp_touqh_EXTRICATE_ARGS := float16_to_uint64_scalbn float_raise
aarch64-vfp_tosqh_EXTRICATE_ARGS := float16_to_int64_scalbn float_raise
aarch64-vfp_toshs_EXTRICATE_ARGS := float32_to_int16_scalbn int16_to_float32_scalbn float_raise
aarch64-vfp_tosls_EXTRICATE_ARGS := float32_to_int32_scalbn int32_to_float32_scalbn float_raise
aarch64-vfp_tosqs_EXTRICATE_ARGS := float32_to_int64_scalbn int64_to_float32_scalbn float_raise
aarch64-vfp_touhs_EXTRICATE_ARGS := float32_to_uint16_scalbn uint16_to_float32_scalbn float_raise
aarch64-vfp_touls_EXTRICATE_ARGS := uint32_to_float32_scalbn float32_to_uint32_scalbn float_raise
aarch64-vfp_touqs_EXTRICATE_ARGS := float32_to_uint64_scalbn uint64_to_float32_scalbn float_raise
aarch64-vfp_toshd_EXTRICATE_ARGS := float64_to_int16_scalbn int16_to_float64_scalbn float_raise
aarch64-vfp_tosld_EXTRICATE_ARGS := float64_to_int32_scalbn int32_to_float64_scalbn float_raise
aarch64-vfp_tosqd_EXTRICATE_ARGS := float64_to_int64_scalbn int64_to_float64_scalbn float_raise
aarch64-vfp_touhd_EXTRICATE_ARGS := float64_to_uint16_scalbn uint16_to_float64_scalbn float_raise
aarch64-vfp_tould_EXTRICATE_ARGS := uint32_to_float64_scalbn float64_to_uint32_scalbn float_raise
aarch64-vfp_touqd_EXTRICATE_ARGS := float64_to_uint64_scalbn uint64_to_float64_scalbn float_raise
aarch64-vfp_shtos_EXTRICATE_ARGS := float32_to_int16_scalbn int16_to_float32_scalbn float_raise
aarch64-vfp_sltos_EXTRICATE_ARGS := float32_to_int32_scalbn int32_to_float32_scalbn float_raise
aarch64-vfp_sqtos_EXTRICATE_ARGS := float32_to_int64_scalbn int64_to_float32_scalbn float_raise
aarch64-vfp_uhtos_EXTRICATE_ARGS := float32_to_uint16_scalbn uint16_to_float32_scalbn float_raise
aarch64-vfp_ultos_EXTRICATE_ARGS := uint32_to_float32_scalbn float32_to_uint32_scalbn float_raise
aarch64-vfp_uqtos_EXTRICATE_ARGS := float32_to_uint64_scalbn uint64_to_float32_scalbn float_raise
aarch64-vfp_shtod_EXTRICATE_ARGS := float64_to_int16_scalbn int16_to_float64_scalbn float_raise
aarch64-vfp_sltod_EXTRICATE_ARGS := float64_to_int32_scalbn int32_to_float64_scalbn float_raise
aarch64-vfp_sqtod_EXTRICATE_ARGS := float64_to_int64_scalbn int64_to_float64_scalbn float_raise
aarch64-vfp_uhtod_EXTRICATE_ARGS := float64_to_uint16_scalbn uint16_to_float64_scalbn float_raise
aarch64-vfp_ultod_EXTRICATE_ARGS := uint32_to_float64_scalbn float64_to_uint32_scalbn float_raise
aarch64-vfp_uqtod_EXTRICATE_ARGS := float64_to_uint64_scalbn uint64_to_float64_scalbn float_raise
aarch64-vfp_sltoh_EXTRICATE_ARGS := int32_to_float16_scalbn
aarch64-vfp_ultoh_EXTRICATE_ARGS := uint32_to_float16_scalbn
aarch64-vfp_sqtoh_EXTRICATE_ARGS := int64_to_float16_scalbn
aarch64-vfp_uqtoh_EXTRICATE_ARGS := uint64_to_float16_scalbn
aarch64-vfp_fcvt_f16_to_f32_EXTRICATE_ARGS := float16_to_float32
aarch64-vfp_fcvt_f32_to_f16_EXTRICATE_ARGS := float32_to_float16
aarch64-vfp_fcvt_f16_to_f64_EXTRICATE_ARGS := float16_to_float64
aarch64-vfp_fcvt_f64_to_f16_EXTRICATE_ARGS := float64_to_float16
aarch64-vfp_muladdd_EXTRICATE_ARGS := float64_muladd
aarch64-vfp_muladds_EXTRICATE_ARGS := float32_muladd
aarch64-recps_f32_EXTRICATE_ARGS := float32_mul float_raise float32_sub
aarch64-rsqrts_f32_EXTRICATE_ARGS := float32_sub float32_div float_raise float32_mul
aarch64-recpe_f16_EXTRICATE_ARGS := float16_default_nan float16_silence_nan float16_squash_input_denormal float_raise float16_is_signaling_nan
aarch64-recpe_f32_EXTRICATE_ARGS := float32_default_nan float_raise float32_silence_nan float32_squash_input_denormal float32_is_signaling_nan
aarch64-recpe_f64_EXTRICATE_ARGS := float64_default_nan float64_silence_nan float_raise float64_squash_input_denormal float64_is_signaling_nan
aarch64-rsqrte_f16_EXTRICATE_ARGS := float16_default_nan float16_silence_nan float16_squash_input_denormal float_raise float16_is_signaling_nan
aarch64-rsqrte_f32_EXTRICATE_ARGS := float32_default_nan float_raise float32_silence_nan float32_squash_input_denormal float32_is_signaling_nan
aarch64-rsqrte_f64_EXTRICATE_ARGS := float64_default_nan float64_silence_nan float_raise float64_squash_input_denormal float64_is_signaling_nan
aarch64-rints_exact_EXTRICATE_ARGS := float32_round_to_int
aarch64-rintd_exact_EXTRICATE_ARGS := float64_round_to_int
aarch64-rints_EXTRICATE_ARGS := float32_round_to_int
aarch64-rintd_EXTRICATE_ARGS := float64_round_to_int
aarch64-vjcvt_EXTRICATE_ARGS := float_raise
aarch64-fjcvtzs_EXTRICATE_ARGS := float_raise
aarch64-neon_abd_f32_EXTRICATE_ARGS := float32_sub
aarch64-neon_ceq_f32_EXTRICATE_ARGS := float32_eq_quiet
aarch64-neon_cge_f32_EXTRICATE_ARGS := float32_le
aarch64-neon_cgt_f32_EXTRICATE_ARGS := float32_lt
aarch64-neon_acge_f32_EXTRICATE_ARGS := float32_le
aarch64-neon_acgt_f32_EXTRICATE_ARGS := float32_lt
aarch64-neon_acge_f64_EXTRICATE_ARGS := float64_le
aarch64-neon_acgt_f64_EXTRICATE_ARGS := float64_lt
aarch64-crc32_EXTRICATE_ARGS := crc32
aarch64-crc32c_EXTRICATE_ARGS := crc32c
aarch64-gvec_fcaddh_EXTRICATE_ARGS := float16_add
aarch64-gvec_fcadds_EXTRICATE_ARGS := float32_add
aarch64-gvec_fcaddd_EXTRICATE_ARGS := float64_add
aarch64-gvec_fcmlah_EXTRICATE_ARGS := float16_muladd
aarch64-gvec_fcmlah_idx_EXTRICATE_ARGS := float16_muladd
aarch64-gvec_fcmlas_EXTRICATE_ARGS := float32_muladd
aarch64-gvec_fcmlas_idx_EXTRICATE_ARGS := float32_muladd
aarch64-gvec_fcmlad_EXTRICATE_ARGS := float64_muladd
aarch64-gvec_frecpe_h_EXTRICATE_ARGS := helper_recpe_f16
aarch64-gvec_frecpe_s_EXTRICATE_ARGS := helper_recpe_f32
aarch64-gvec_frecpe_d_EXTRICATE_ARGS := helper_recpe_f64
aarch64-gvec_frsqrte_h_EXTRICATE_ARGS := helper_rsqrte_f16
aarch64-gvec_frsqrte_s_EXTRICATE_ARGS := helper_rsqrte_f32
aarch64-gvec_frsqrte_d_EXTRICATE_ARGS := helper_rsqrte_f64
aarch64-gvec_fadd_h_EXTRICATE_ARGS := float16_add
aarch64-gvec_fadd_s_EXTRICATE_ARGS := float32_add
aarch64-gvec_fadd_d_EXTRICATE_ARGS := float64_add
aarch64-gvec_fsub_h_EXTRICATE_ARGS := float16_sub
aarch64-gvec_fsub_s_EXTRICATE_ARGS := float32_sub
aarch64-gvec_fsub_d_EXTRICATE_ARGS := float64_sub
aarch64-gvec_fmul_h_EXTRICATE_ARGS := float16_mul
aarch64-gvec_fmul_s_EXTRICATE_ARGS := float32_mul
aarch64-gvec_fmul_d_EXTRICATE_ARGS := float64_mul
aarch64-gvec_ftsmul_h_EXTRICATE_ARGS := float16_mul
aarch64-gvec_ftsmul_s_EXTRICATE_ARGS := float32_mul
aarch64-gvec_ftsmul_d_EXTRICATE_ARGS := float64_mul
aarch64-gvec_fmul_idx_h_EXTRICATE_ARGS := float16_mul
aarch64-gvec_fmul_idx_s_EXTRICATE_ARGS := float32_mul
aarch64-gvec_fmul_idx_d_EXTRICATE_ARGS := float64_mul
aarch64-gvec_fmla_idx_h_EXTRICATE_ARGS := float16_muladd
aarch64-gvec_fmla_idx_s_EXTRICATE_ARGS := float32_muladd
aarch64-gvec_fmla_idx_d_EXTRICATE_ARGS := float64_muladd
aarch64-gvec_fmlal_a32_EXTRICATE_ARGS := float32_muladd
aarch64-gvec_fmlal_a64_EXTRICATE_ARGS := float32_muladd
aarch64-gvec_fmlal_idx_a32_EXTRICATE_ARGS := float32_muladd
aarch64-gvec_fmlal_idx_a64_EXTRICATE_ARGS := float32_muladd
aarch64-frint32_s_EXTRICATE_ARGS := float32_round_to_int
aarch64-frint64_s_EXTRICATE_ARGS := float32_round_to_int
aarch64-frint32_d_EXTRICATE_ARGS := float64_round_to_int
aarch64-frint64_d_EXTRICATE_ARGS := float64_round_to_int
aarch64-msr_i_daifset_EXTRICATE_ARGS := raise_exception_ra
aarch64-msr_i_daifclear_EXTRICATE_ARGS := raise_exception_ra
aarch64-vfp_cmph_a64_EXTRICATE_ARGS := float16_compare_quiet
aarch64-vfp_cmpeh_a64_EXTRICATE_ARGS := float16_compare
aarch64-vfp_cmps_a64_EXTRICATE_ARGS := float32_compare_quiet
aarch64-vfp_cmpes_a64_EXTRICATE_ARGS := float32_compare
aarch64-vfp_cmpd_a64_EXTRICATE_ARGS := float64_compare_quiet
aarch64-vfp_cmped_a64_EXTRICATE_ARGS := float64_compare
aarch64-vfp_mulxs_EXTRICATE_ARGS := float32_mul float32_squash_input_denormal
aarch64-vfp_mulxd_EXTRICATE_ARGS := float64_mul float64_squash_input_denormal
aarch64-neon_ceq_f64_EXTRICATE_ARGS := float64_eq_quiet
aarch64-neon_cge_f64_EXTRICATE_ARGS := float64_le
aarch64-neon_cgt_f64_EXTRICATE_ARGS := float64_lt
aarch64-recpsf_f16_EXTRICATE_ARGS := float16_muladd float16_squash_input_denormal
aarch64-recpsf_f32_EXTRICATE_ARGS := float32_muladd float32_squash_input_denormal
aarch64-recpsf_f64_EXTRICATE_ARGS := float64_muladd float64_squash_input_denormal
aarch64-rsqrtsf_f16_EXTRICATE_ARGS := float16_muladd float16_squash_input_denormal
aarch64-rsqrtsf_f32_EXTRICATE_ARGS := float32_muladd float32_squash_input_denormal
aarch64-rsqrtsf_f64_EXTRICATE_ARGS := float64_muladd float64_squash_input_denormal
aarch64-frecpx_f64_EXTRICATE_ARGS := float64_default_nan float64_silence_nan float64_squash_input_denormal float64_is_signaling_nan float_raise
aarch64-frecpx_f32_EXTRICATE_ARGS := float32_default_nan float32_squash_input_denormal float32_silence_nan float32_is_signaling_nan float_raise
aarch64-frecpx_f16_EXTRICATE_ARGS := float16_squash_input_denormal float16_default_nan float16_silence_nan float16_is_signaling_nan float_raise
aarch64-fcvtx_f64_to_f32_EXTRICATE_ARGS := float64_to_float32
aarch64-crc32_64_EXTRICATE_ARGS := crc32
aarch64-crc32c_64_EXTRICATE_ARGS := crc32c
aarch64-paired_cmpxchg64_le_EXTRICATE_ARGS := raise_exception_ra
aarch64-paired_cmpxchg64_be_EXTRICATE_ARGS := raise_exception_ra
aarch64-advsimd_maxh_EXTRICATE_ARGS := float16_max
aarch64-advsimd_minh_EXTRICATE_ARGS := float16_min
aarch64-advsimd_maxnumh_EXTRICATE_ARGS := float16_maxnum
aarch64-advsimd_minnumh_EXTRICATE_ARGS := float16_minnum
aarch64-advsimd_addh_EXTRICATE_ARGS := float16_add
aarch64-advsimd_subh_EXTRICATE_ARGS := float16_sub
aarch64-advsimd_mulh_EXTRICATE_ARGS := float16_mul
aarch64-advsimd_divh_EXTRICATE_ARGS := float16_div
aarch64-advsimd_ceq_f16_EXTRICATE_ARGS := float16_compare_quiet
aarch64-advsimd_cge_f16_EXTRICATE_ARGS := float16_compare
aarch64-advsimd_cgt_f16_EXTRICATE_ARGS := float16_compare
aarch64-advsimd_acge_f16_EXTRICATE_ARGS := float16_compare
aarch64-advsimd_acgt_f16_EXTRICATE_ARGS := float16_compare
aarch64-advsimd_mulxh_EXTRICATE_ARGS := float16_mul float16_squash_input_denormal
aarch64-advsimd_muladdh_EXTRICATE_ARGS := float16_muladd
aarch64-advsimd_add2h_EXTRICATE_ARGS := float16_add
aarch64-advsimd_sub2h_EXTRICATE_ARGS := float16_sub
aarch64-advsimd_mul2h_EXTRICATE_ARGS := float16_mul
aarch64-advsimd_div2h_EXTRICATE_ARGS := float16_div
aarch64-advsimd_max2h_EXTRICATE_ARGS := float16_max
aarch64-advsimd_min2h_EXTRICATE_ARGS := float16_min
aarch64-advsimd_maxnum2h_EXTRICATE_ARGS := float16_maxnum
aarch64-advsimd_minnum2h_EXTRICATE_ARGS := float16_minnum
aarch64-advsimd_mulx2h_EXTRICATE_ARGS := float16_mul float16_squash_input_denormal
aarch64-advsimd_muladd2h_EXTRICATE_ARGS := float16_muladd
aarch64-advsimd_rinth_exact_EXTRICATE_ARGS := float16_round_to_int
aarch64-advsimd_rinth_EXTRICATE_ARGS := float16_round_to_int
aarch64-advsimd_f16tosinth_EXTRICATE_ARGS := float16_to_int16 float_raise
aarch64-advsimd_f16touinth_EXTRICATE_ARGS := float16_to_uint16 float_raise
aarch64-sqrt_f16_EXTRICATE_ARGS := float16_sqrt
aarch64-pacia_EXTRICATE_ARGS := aa64_va_parameters arm_hcr_el2_eff raise_exception_ra
aarch64-pacib_EXTRICATE_ARGS := aa64_va_parameters arm_hcr_el2_eff raise_exception_ra
aarch64-pacda_EXTRICATE_ARGS := aa64_va_parameters arm_hcr_el2_eff raise_exception_ra
aarch64-pacdb_EXTRICATE_ARGS := aa64_va_parameters arm_hcr_el2_eff raise_exception_ra
aarch64-pacga_EXTRICATE_ARGS := aa64_va_parameters arm_hcr_el2_eff raise_exception_ra
aarch64-autia_EXTRICATE_ARGS := aa64_va_parameters arm_hcr_el2_eff raise_exception_ra
aarch64-autib_EXTRICATE_ARGS := aa64_va_parameters arm_hcr_el2_eff raise_exception_ra
aarch64-autda_EXTRICATE_ARGS := aa64_va_parameters arm_hcr_el2_eff raise_exception_ra
aarch64-autdb_EXTRICATE_ARGS := aa64_va_parameters arm_hcr_el2_eff raise_exception_ra
aarch64-xpaci_EXTRICATE_ARGS := aa64_va_parameters
aarch64-xpacd_EXTRICATE_ARGS := aa64_va_parameters
aarch64-gvec_recps_h_EXTRICATE_ARGS := helper_recpsf_f16
aarch64-gvec_recps_s_EXTRICATE_ARGS := helper_recpsf_f32
aarch64-gvec_recps_d_EXTRICATE_ARGS := helper_recpsf_f64
aarch64-gvec_rsqrts_h_EXTRICATE_ARGS := helper_rsqrtsf_f16
aarch64-gvec_rsqrts_s_EXTRICATE_ARGS := helper_rsqrtsf_f32
aarch64-gvec_rsqrts_d_EXTRICATE_ARGS := helper_rsqrtsf_f64
aarch64-sve_faddv_h_EXTRICATE_ARGS := float16_add
aarch64-sve_faddv_s_EXTRICATE_ARGS := float32_add
aarch64-sve_faddv_d_EXTRICATE_ARGS := float64_add
aarch64-sve_fmaxnmv_h_EXTRICATE_ARGS := float16_maxnum
aarch64-sve_fmaxnmv_s_EXTRICATE_ARGS := float32_maxnum
aarch64-sve_fmaxnmv_d_EXTRICATE_ARGS := float64_maxnum
aarch64-sve_fminnmv_h_EXTRICATE_ARGS := float16_minnum
aarch64-sve_fminnmv_s_EXTRICATE_ARGS := float32_minnum
aarch64-sve_fminnmv_d_EXTRICATE_ARGS := float64_minnum
aarch64-sve_fmaxv_h_EXTRICATE_ARGS := float16_max
aarch64-sve_fmaxv_s_EXTRICATE_ARGS := float32_max
aarch64-sve_fmaxv_d_EXTRICATE_ARGS := float64_max
aarch64-sve_fminv_h_EXTRICATE_ARGS := float16_min
aarch64-sve_fminv_s_EXTRICATE_ARGS := float32_min
aarch64-sve_fminv_d_EXTRICATE_ARGS := float64_min
aarch64-sve_fadda_h_EXTRICATE_ARGS := float16_add
aarch64-sve_fadda_s_EXTRICATE_ARGS := float32_add
aarch64-sve_fadda_d_EXTRICATE_ARGS := float64_add
aarch64-sve_fcmge0_h_EXTRICATE_ARGS := float64_compare float16_compare float32_compare
aarch64-sve_fcmge0_s_EXTRICATE_ARGS := float64_compare float16_compare float32_compare
aarch64-sve_fcmge0_d_EXTRICATE_ARGS := float64_compare float16_compare float32_compare
aarch64-sve_fcmgt0_h_EXTRICATE_ARGS := float64_compare float16_compare float32_compare
aarch64-sve_fcmgt0_s_EXTRICATE_ARGS := float64_compare float16_compare float32_compare
aarch64-sve_fcmgt0_d_EXTRICATE_ARGS := float64_compare float16_compare float32_compare
aarch64-sve_fcmlt0_h_EXTRICATE_ARGS := float64_compare float16_compare float32_compare
aarch64-sve_fcmlt0_s_EXTRICATE_ARGS := float64_compare float16_compare float32_compare
aarch64-sve_fcmlt0_d_EXTRICATE_ARGS := float64_compare float16_compare float32_compare
aarch64-sve_fcmle0_h_EXTRICATE_ARGS := float64_compare float16_compare float32_compare
aarch64-sve_fcmle0_s_EXTRICATE_ARGS := float64_compare float16_compare float32_compare
aarch64-sve_fcmle0_d_EXTRICATE_ARGS := float64_compare float16_compare float32_compare
aarch64-sve_fcmeq0_h_EXTRICATE_ARGS := float64_compare_quiet float16_compare_quiet float32_compare_quiet
aarch64-sve_fcmeq0_s_EXTRICATE_ARGS := float64_compare_quiet float16_compare_quiet float32_compare_quiet
aarch64-sve_fcmeq0_d_EXTRICATE_ARGS := float64_compare_quiet float16_compare_quiet float32_compare_quiet
aarch64-sve_fcmne0_h_EXTRICATE_ARGS := float64_compare_quiet float16_compare_quiet float32_compare_quiet
aarch64-sve_fcmne0_s_EXTRICATE_ARGS := float64_compare_quiet float16_compare_quiet float32_compare_quiet
aarch64-sve_fcmne0_d_EXTRICATE_ARGS := float64_compare_quiet float16_compare_quiet float32_compare_quiet
aarch64-sve_fadd_h_EXTRICATE_ARGS := float16_add
aarch64-sve_fadd_s_EXTRICATE_ARGS := float32_add
aarch64-sve_fadd_d_EXTRICATE_ARGS := float64_add
aarch64-sve_fsub_h_EXTRICATE_ARGS := float16_sub
aarch64-sve_fsub_s_EXTRICATE_ARGS := float32_sub
aarch64-sve_fsub_d_EXTRICATE_ARGS := float64_sub
aarch64-sve_fmul_h_EXTRICATE_ARGS := float16_mul
aarch64-sve_fmul_s_EXTRICATE_ARGS := float32_mul
aarch64-sve_fmul_d_EXTRICATE_ARGS := float64_mul
aarch64-sve_fdiv_h_EXTRICATE_ARGS := float16_div
aarch64-sve_fdiv_s_EXTRICATE_ARGS := float32_div
aarch64-sve_fdiv_d_EXTRICATE_ARGS := float64_div
aarch64-sve_fmin_h_EXTRICATE_ARGS := float16_min
aarch64-sve_fmin_s_EXTRICATE_ARGS := float32_min
aarch64-sve_fmin_d_EXTRICATE_ARGS := float64_min
aarch64-sve_fmax_h_EXTRICATE_ARGS := float16_max
aarch64-sve_fmax_s_EXTRICATE_ARGS := float32_max
aarch64-sve_fmax_d_EXTRICATE_ARGS := float64_max
aarch64-sve_fminnum_h_EXTRICATE_ARGS := float16_minnum
aarch64-sve_fminnum_s_EXTRICATE_ARGS := float32_minnum
aarch64-sve_fminnum_d_EXTRICATE_ARGS := float64_minnum
aarch64-sve_fmaxnum_h_EXTRICATE_ARGS := float16_maxnum
aarch64-sve_fmaxnum_s_EXTRICATE_ARGS := float32_maxnum
aarch64-sve_fmaxnum_d_EXTRICATE_ARGS := float64_maxnum
aarch64-sve_fabd_h_EXTRICATE_ARGS := float16_sub
aarch64-sve_fabd_s_EXTRICATE_ARGS := float32_sub
aarch64-sve_fabd_d_EXTRICATE_ARGS := float64_sub
aarch64-sve_fscalbn_h_EXTRICATE_ARGS := float16_scalbn
aarch64-sve_fscalbn_s_EXTRICATE_ARGS := float32_scalbn
aarch64-sve_fscalbn_d_EXTRICATE_ARGS := float64_scalbn
aarch64-sve_fmulx_h_EXTRICATE_ARGS := helper_advsimd_mulxh
aarch64-sve_fmulx_s_EXTRICATE_ARGS := helper_vfp_mulxs
aarch64-sve_fmulx_d_EXTRICATE_ARGS := helper_vfp_mulxd
aarch64-sve_fadds_h_EXTRICATE_ARGS := float16_add
aarch64-sve_fadds_s_EXTRICATE_ARGS := float32_add
aarch64-sve_fadds_d_EXTRICATE_ARGS := float64_add
aarch64-sve_fsubs_h_EXTRICATE_ARGS := float16_sub
aarch64-sve_fsubs_s_EXTRICATE_ARGS := float32_sub
aarch64-sve_fsubs_d_EXTRICATE_ARGS := float64_sub
aarch64-sve_fmuls_h_EXTRICATE_ARGS := float16_mul
aarch64-sve_fmuls_s_EXTRICATE_ARGS := float32_mul
aarch64-sve_fmuls_d_EXTRICATE_ARGS := float64_mul
aarch64-sve_fsubrs_h_EXTRICATE_ARGS := float16_sub
aarch64-sve_fsubrs_s_EXTRICATE_ARGS := float32_sub
aarch64-sve_fsubrs_d_EXTRICATE_ARGS := float64_sub
aarch64-sve_fmaxnms_h_EXTRICATE_ARGS := float16_maxnum
aarch64-sve_fmaxnms_s_EXTRICATE_ARGS := float32_maxnum
aarch64-sve_fmaxnms_d_EXTRICATE_ARGS := float64_maxnum
aarch64-sve_fminnms_h_EXTRICATE_ARGS := float16_minnum
aarch64-sve_fminnms_s_EXTRICATE_ARGS := float32_minnum
aarch64-sve_fminnms_d_EXTRICATE_ARGS := float64_minnum
aarch64-sve_fmaxs_h_EXTRICATE_ARGS := float16_max
aarch64-sve_fmaxs_s_EXTRICATE_ARGS := float32_max
aarch64-sve_fmaxs_d_EXTRICATE_ARGS := float64_max
aarch64-sve_fmins_h_EXTRICATE_ARGS := float16_min
aarch64-sve_fmins_s_EXTRICATE_ARGS := float32_min
aarch64-sve_fmins_d_EXTRICATE_ARGS := float64_min
aarch64-sve_fcvt_sh_EXTRICATE_ARGS := float32_to_float16
aarch64-sve_fcvt_dh_EXTRICATE_ARGS := float64_to_float16
aarch64-sve_fcvt_hs_EXTRICATE_ARGS := float16_to_float32
aarch64-sve_fcvt_ds_EXTRICATE_ARGS := float64_to_float32
aarch64-sve_fcvt_hd_EXTRICATE_ARGS := float16_to_float64
aarch64-sve_fcvt_sd_EXTRICATE_ARGS := float32_to_float64
aarch64-sve_fcvtzs_hh_EXTRICATE_ARGS := float16_to_int16_round_to_zero float_raise
aarch64-sve_fcvtzs_hs_EXTRICATE_ARGS := helper_vfp_tosizh
aarch64-sve_fcvtzs_ss_EXTRICATE_ARGS := helper_vfp_tosizs
aarch64-sve_fcvtzs_ds_EXTRICATE_ARGS := helper_vfp_tosizd
aarch64-sve_fcvtzs_hd_EXTRICATE_ARGS := float16_to_int64_round_to_zero float_raise
aarch64-sve_fcvtzs_sd_EXTRICATE_ARGS := float32_to_int64_round_to_zero float_raise
aarch64-sve_fcvtzs_dd_EXTRICATE_ARGS := float64_to_int64_round_to_zero float_raise
aarch64-sve_fcvtzu_hh_EXTRICATE_ARGS := float16_to_uint16_round_to_zero float_raise
aarch64-sve_fcvtzu_hs_EXTRICATE_ARGS := helper_vfp_touizh
aarch64-sve_fcvtzu_ss_EXTRICATE_ARGS := helper_vfp_touizs
aarch64-sve_fcvtzu_ds_EXTRICATE_ARGS := helper_vfp_touizd
aarch64-sve_fcvtzu_hd_EXTRICATE_ARGS := float16_to_uint64_round_to_zero float_raise
aarch64-sve_fcvtzu_sd_EXTRICATE_ARGS := float32_to_uint64_round_to_zero float_raise
aarch64-sve_fcvtzu_dd_EXTRICATE_ARGS := float64_to_uint64_round_to_zero float_raise
aarch64-sve_frint_h_EXTRICATE_ARGS := helper_advsimd_rinth
aarch64-sve_frint_s_EXTRICATE_ARGS := helper_rints
aarch64-sve_frint_d_EXTRICATE_ARGS := helper_rintd
aarch64-sve_frintx_h_EXTRICATE_ARGS := float16_round_to_int
aarch64-sve_frintx_s_EXTRICATE_ARGS := float32_round_to_int
aarch64-sve_frintx_d_EXTRICATE_ARGS := float64_round_to_int
aarch64-sve_frecpx_h_EXTRICATE_ARGS := helper_frecpx_f16
aarch64-sve_frecpx_s_EXTRICATE_ARGS := helper_frecpx_f32
aarch64-sve_frecpx_d_EXTRICATE_ARGS := helper_frecpx_f64
aarch64-sve_fsqrt_h_EXTRICATE_ARGS := float16_sqrt
aarch64-sve_fsqrt_s_EXTRICATE_ARGS := float32_sqrt
aarch64-sve_fsqrt_d_EXTRICATE_ARGS := float64_sqrt
aarch64-sve_scvt_hh_EXTRICATE_ARGS := int16_to_float16
aarch64-sve_scvt_sh_EXTRICATE_ARGS := int32_to_float16
aarch64-sve_scvt_dh_EXTRICATE_ARGS := int64_to_float16
aarch64-sve_scvt_ss_EXTRICATE_ARGS := int32_to_float32
aarch64-sve_scvt_sd_EXTRICATE_ARGS := int32_to_float64
aarch64-sve_scvt_ds_EXTRICATE_ARGS := int64_to_float32
aarch64-sve_scvt_dd_EXTRICATE_ARGS := int64_to_float64
aarch64-sve_ucvt_hh_EXTRICATE_ARGS := uint16_to_float16
aarch64-sve_ucvt_sh_EXTRICATE_ARGS := uint32_to_float16
aarch64-sve_ucvt_dh_EXTRICATE_ARGS := uint64_to_float16
aarch64-sve_ucvt_ss_EXTRICATE_ARGS := uint32_to_float32
aarch64-sve_ucvt_sd_EXTRICATE_ARGS := uint32_to_float64
aarch64-sve_ucvt_ds_EXTRICATE_ARGS := uint64_to_float32
aarch64-sve_ucvt_dd_EXTRICATE_ARGS := uint64_to_float64
aarch64-sve_fcmge_h_EXTRICATE_ARGS := float64_compare float16_compare float32_compare
aarch64-sve_fcmge_s_EXTRICATE_ARGS := float64_compare float16_compare float32_compare
aarch64-sve_fcmge_d_EXTRICATE_ARGS := float64_compare float16_compare float32_compare
aarch64-sve_fcmgt_h_EXTRICATE_ARGS := float64_compare float16_compare float32_compare
aarch64-sve_fcmgt_s_EXTRICATE_ARGS := float64_compare float16_compare float32_compare
aarch64-sve_fcmgt_d_EXTRICATE_ARGS := float64_compare float16_compare float32_compare
aarch64-sve_fcmeq_h_EXTRICATE_ARGS := float64_compare_quiet float16_compare_quiet float32_compare_quiet
aarch64-sve_fcmeq_s_EXTRICATE_ARGS := float64_compare_quiet float16_compare_quiet float32_compare_quiet
aarch64-sve_fcmeq_d_EXTRICATE_ARGS := float64_compare_quiet float16_compare_quiet float32_compare_quiet
aarch64-sve_fcmne_h_EXTRICATE_ARGS := float64_compare_quiet float16_compare_quiet float32_compare_quiet
aarch64-sve_fcmne_s_EXTRICATE_ARGS := float64_compare_quiet float16_compare_quiet float32_compare_quiet
aarch64-sve_fcmne_d_EXTRICATE_ARGS := float64_compare_quiet float16_compare_quiet float32_compare_quiet
aarch64-sve_fcmuo_h_EXTRICATE_ARGS := float64_compare_quiet float16_compare_quiet float32_compare_quiet
aarch64-sve_fcmuo_s_EXTRICATE_ARGS := float64_compare_quiet float16_compare_quiet float32_compare_quiet
aarch64-sve_fcmuo_d_EXTRICATE_ARGS := float64_compare_quiet float16_compare_quiet float32_compare_quiet
aarch64-sve_facge_h_EXTRICATE_ARGS := float64_compare float16_compare float32_compare
aarch64-sve_facge_s_EXTRICATE_ARGS := float64_compare float16_compare float32_compare
aarch64-sve_facge_d_EXTRICATE_ARGS := float64_compare float16_compare float32_compare
aarch64-sve_facgt_h_EXTRICATE_ARGS := float64_compare float16_compare float32_compare
aarch64-sve_facgt_s_EXTRICATE_ARGS := float64_compare float16_compare float32_compare
aarch64-sve_facgt_d_EXTRICATE_ARGS := float64_compare float16_compare float32_compare
aarch64-sve_fcadd_h_EXTRICATE_ARGS := float16_add
aarch64-sve_fcadd_s_EXTRICATE_ARGS := float32_add
aarch64-sve_fcadd_d_EXTRICATE_ARGS := float64_add
aarch64-sve_fmla_zpzzz_h_EXTRICATE_ARGS := float16_muladd
aarch64-sve_fmla_zpzzz_s_EXTRICATE_ARGS := float32_muladd
aarch64-sve_fmla_zpzzz_d_EXTRICATE_ARGS := float64_muladd
aarch64-sve_fmls_zpzzz_h_EXTRICATE_ARGS := float16_muladd
aarch64-sve_fmls_zpzzz_s_EXTRICATE_ARGS := float32_muladd
aarch64-sve_fmls_zpzzz_d_EXTRICATE_ARGS := float64_muladd
aarch64-sve_fnmla_zpzzz_h_EXTRICATE_ARGS := float16_muladd
aarch64-sve_fnmla_zpzzz_s_EXTRICATE_ARGS := float32_muladd
aarch64-sve_fnmla_zpzzz_d_EXTRICATE_ARGS := float64_muladd
aarch64-sve_fnmls_zpzzz_h_EXTRICATE_ARGS := float16_muladd
aarch64-sve_fnmls_zpzzz_s_EXTRICATE_ARGS := float32_muladd
aarch64-sve_fnmls_zpzzz_d_EXTRICATE_ARGS := float64_muladd
aarch64-sve_fcmla_zpzzz_h_EXTRICATE_ARGS := float16_muladd
aarch64-sve_fcmla_zpzzz_s_EXTRICATE_ARGS := float32_muladd
aarch64-sve_fcmla_zpzzz_d_EXTRICATE_ARGS := float64_muladd
aarch64-sve_ftmad_h_EXTRICATE_ARGS := float16_muladd
aarch64-sve_ftmad_s_EXTRICATE_ARGS := float32_muladd
aarch64-sve_ftmad_d_EXTRICATE_ARGS := float64_muladd

x86_64-aaa_EXTRICATE_ARGS := cpu_cc_compute_all
x86_64-aas_EXTRICATE_ARGS := cpu_cc_compute_all
x86_64-daa_EXTRICATE_ARGS := cpu_cc_compute_all
x86_64-das_EXTRICATE_ARGS := cpu_cc_compute_all
x86_64-lsl_EXTRICATE_ARGS := cpu_cc_compute_all
x86_64-lar_EXTRICATE_ARGS := cpu_cc_compute_all
x86_64-verr_EXTRICATE_ARGS := cpu_cc_compute_all
x86_64-verw_EXTRICATE_ARGS := cpu_cc_compute_all
x86_64-load_seg_EXTRICATE_ARGS := cpu_sync_bndcs_hflags
x86_64-lret_protected_EXTRICATE_ARGS := cpu_sync_bndcs_hflags
x86_64-invlpg_EXTRICATE_ARGS := cpu_svm_check_intercept_param
x86_64-ljmp_protected_EXTRICATE_ARGS := cpu_cc_compute_all cpu_sync_bndcs_hflags
x86_64-sysenter_EXTRICATE_ARGS := cpu_sync_bndcs_hflags
x86_64-monitor_EXTRICATE_ARGS := cpu_svm_check_intercept_param
x86_64-sysexit_EXTRICATE_ARGS := cpu_sync_bndcs_hflags
x86_64-sysret_EXTRICATE_ARGS := cpu_sync_bndcs_hflags
x86_64-mwait_EXTRICATE_ARGS := cpu_svm_check_intercept_param
x86_64-pause_EXTRICATE_ARGS := cpu_svm_check_intercept_param
x86_64-into_EXTRICATE_ARGS := raise_interrupt cpu_cc_compute_all
x86_64-cmpxchg8b_unlocked_EXTRICATE_ARGS := cpu_cc_compute_all
x86_64-cmpxchg8b_EXTRICATE_ARGS := cpu_cc_compute_all
x86_64-cmpxchg16b_unlocked_EXTRICATE_ARGS := cpu_cc_compute_all
x86_64-cmpxchg16b_EXTRICATE_ARGS := helper_atomic_cmpxchgo_le_mmu cpu_cc_compute_all
x86_64-cpuid_EXTRICATE_ARGS := cpu_x86_cpuid cpu_svm_check_intercept_param
x86_64-rdtsc_EXTRICATE_ARGS := cpu_get_tsc cpu_svm_check_intercept_param
x86_64-rdtscp_EXTRICATE_ARGS := cpu_get_tsc cpu_svm_check_intercept_param
x86_64-rdpmc_EXTRICATE_ARGS := cpu_svm_check_intercept_param
x86_64-flds_FT0_EXTRICATE_ARGS := float32_to_floatx80
x86_64-fildl_FT0_EXTRICATE_ARGS := int32_to_floatx80
x86_64-flds_ST0_EXTRICATE_ARGS := float32_to_floatx80
x86_64-fldl_FT0_EXTRICATE_ARGS := float64_to_floatx80
x86_64-fldl_ST0_EXTRICATE_ARGS := float64_to_floatx80
x86_64-fildl_ST0_EXTRICATE_ARGS := int32_to_floatx80
x86_64-fildll_ST0_EXTRICATE_ARGS := int64_to_floatx80
x86_64-fsts_ST0_EXTRICATE_ARGS := floatx80_to_float32
x86_64-fstl_ST0_EXTRICATE_ARGS := floatx80_to_float64
x86_64-fist_ST0_EXTRICATE_ARGS := floatx80_to_int32
x86_64-fistl_ST0_EXTRICATE_ARGS := floatx80_to_int32
x86_64-fistll_ST0_EXTRICATE_ARGS := floatx80_to_int64
x86_64-fistt_ST0_EXTRICATE_ARGS := floatx80_to_int32_round_to_zero
x86_64-fisttl_ST0_EXTRICATE_ARGS := floatx80_to_int32_round_to_zero
x86_64-fisttll_ST0_EXTRICATE_ARGS := floatx80_to_int64_round_to_zero
x86_64-fcom_ST0_FT0_EXTRICATE_ARGS := floatx80_compare
x86_64-fucom_ST0_FT0_EXTRICATE_ARGS := floatx80_compare_quiet
x86_64-fcomi_ST0_FT0_EXTRICATE_ARGS := cpu_cc_compute_all floatx80_compare
x86_64-fucomi_ST0_FT0_EXTRICATE_ARGS := cpu_cc_compute_all floatx80_compare_quiet
x86_64-fadd_ST0_FT0_EXTRICATE_ARGS := floatx80_add
x86_64-fmul_ST0_FT0_EXTRICATE_ARGS := floatx80_mul
x86_64-fsub_ST0_FT0_EXTRICATE_ARGS := floatx80_sub
x86_64-fsubr_ST0_FT0_EXTRICATE_ARGS := floatx80_sub
x86_64-fdiv_ST0_FT0_EXTRICATE_ARGS := floatx80_div
x86_64-fdivr_ST0_FT0_EXTRICATE_ARGS := floatx80_div
x86_64-fadd_STN_ST0_EXTRICATE_ARGS := floatx80_add
x86_64-fmul_STN_ST0_EXTRICATE_ARGS := floatx80_mul
x86_64-fsub_STN_ST0_EXTRICATE_ARGS := floatx80_sub
x86_64-fsubr_STN_ST0_EXTRICATE_ARGS := floatx80_sub
x86_64-fdiv_STN_ST0_EXTRICATE_ARGS := floatx80_div
x86_64-fdivr_STN_ST0_EXTRICATE_ARGS := floatx80_div
x86_64-f2xm1_EXTRICATE_ARGS := float64_to_floatx80 pow floatx80_to_float64
x86_64-fptan_EXTRICATE_ARGS := float64_to_floatx80 tan floatx80_to_float64
x86_64-fbst_ST0_EXTRICATE_ARGS := floatx80_to_int64
x86_64-fyl2x_EXTRICATE_ARGS := float64_to_floatx80 log floatx80_to_float64
x86_64-fbld_ST0_EXTRICATE_ARGS := int64_to_floatx80
x86_64-fpatan_EXTRICATE_ARGS := float64_to_floatx80 atan2 floatx80_to_float64
x86_64-fxtract_EXTRICATE_ARGS := int32_to_floatx80 floatx80_div
x86_64-fyl2xp1_EXTRICATE_ARGS := float64_to_floatx80 log floatx80_to_float64
x86_64-fprem1_EXTRICATE_ARGS := float64_to_floatx80 floor rint pow fabs floatx80_to_float64
x86_64-fprem_EXTRICATE_ARGS := float64_to_floatx80 floatx80_to_float64 rint pow fabs floor ceil
x86_64-fsqrt_EXTRICATE_ARGS := floatx80_sqrt
x86_64-fsincos_EXTRICATE_ARGS := float64_to_floatx80 floatx80_to_float64 sin cos
x86_64-frndint_EXTRICATE_ARGS := floatx80_round_to_int
x86_64-fscale_EXTRICATE_ARGS := floatx80_scalbn floatx80_to_int32_round_to_zero
x86_64-fcos_EXTRICATE_ARGS := float64_to_floatx80 cos floatx80_to_float64
x86_64-fsin_EXTRICATE_ARGS := float64_to_floatx80 sin floatx80_to_float64
x86_64-xsetbv_EXTRICATE_ARGS := cpu_sync_bndcs_hflags cpu_x86_cpuid
x86_64-xrstor_EXTRICATE_ARGS := cpu_sync_bndcs_hflags
x86_64-pi2fw_EXTRICATE_ARGS := int32_to_float32
x86_64-pi2fd_EXTRICATE_ARGS := int32_to_float32
x86_64-pf2id_EXTRICATE_ARGS := float32_to_int32_round_to_zero
x86_64-pf2iw_EXTRICATE_ARGS := float32_to_int32_round_to_zero
x86_64-pfacc_EXTRICATE_ARGS := float32_add
x86_64-pfadd_EXTRICATE_ARGS := float32_add
x86_64-pfcmpeq_EXTRICATE_ARGS := float32_eq_quiet
x86_64-pfcmpge_EXTRICATE_ARGS := float32_le
x86_64-pfcmpgt_EXTRICATE_ARGS := float32_lt
x86_64-pfmax_EXTRICATE_ARGS := float32_lt
x86_64-pfmul_EXTRICATE_ARGS := float32_mul
x86_64-pfmin_EXTRICATE_ARGS := float32_lt
x86_64-pfnacc_EXTRICATE_ARGS := float32_sub
x86_64-pfpnacc_EXTRICATE_ARGS := float32_add float32_sub
x86_64-pfrcp_EXTRICATE_ARGS := float32_div
x86_64-pfrsqrt_EXTRICATE_ARGS := float32_sqrt float32_div
x86_64-pfsub_EXTRICATE_ARGS := float32_sub
x86_64-pfsubr_EXTRICATE_ARGS := float32_sub
x86_64-addps_EXTRICATE_ARGS := float64_add float32_add
x86_64-addss_EXTRICATE_ARGS := float64_add float32_add
x86_64-addsd_EXTRICATE_ARGS := float64_add float32_add
x86_64-subps_EXTRICATE_ARGS := float64_sub float32_sub
x86_64-addpd_EXTRICATE_ARGS := float64_add float32_add
x86_64-subss_EXTRICATE_ARGS := float64_sub float32_sub
x86_64-subpd_EXTRICATE_ARGS := float64_sub float32_sub
x86_64-subsd_EXTRICATE_ARGS := float64_sub float32_sub
x86_64-mulps_EXTRICATE_ARGS := float64_mul float32_mul
x86_64-mulss_EXTRICATE_ARGS := float64_mul float32_mul
x86_64-mulpd_EXTRICATE_ARGS := float64_mul float32_mul
x86_64-mulsd_EXTRICATE_ARGS := float64_mul float32_mul
x86_64-divps_EXTRICATE_ARGS := float64_div float32_div
x86_64-divpd_EXTRICATE_ARGS := float64_div float32_div
x86_64-divss_EXTRICATE_ARGS := float64_div float32_div
x86_64-divsd_EXTRICATE_ARGS := float64_div float32_div
x86_64-minps_EXTRICATE_ARGS := float64_lt float32_lt
x86_64-minss_EXTRICATE_ARGS := float64_lt float32_lt
x86_64-minpd_EXTRICATE_ARGS := float64_lt float32_lt
x86_64-minsd_EXTRICATE_ARGS := float64_lt float32_lt
x86_64-maxps_EXTRICATE_ARGS := float64_lt float32_lt
x86_64-maxss_EXTRICATE_ARGS := float64_lt float32_lt
x86_64-maxpd_EXTRICATE_ARGS := float64_lt float32_lt
x86_64-maxsd_EXTRICATE_ARGS := float64_lt float32_lt
x86_64-sqrtps_EXTRICATE_ARGS := float64_sqrt float32_sqrt
x86_64-sqrtss_EXTRICATE_ARGS := float64_sqrt float32_sqrt
x86_64-sqrtpd_EXTRICATE_ARGS := float64_sqrt float32_sqrt
x86_64-sqrtsd_EXTRICATE_ARGS := float64_sqrt float32_sqrt
x86_64-cvtps2pd_EXTRICATE_ARGS := float32_to_float64
x86_64-cvtpd2ps_EXTRICATE_ARGS := float64_to_float32
x86_64-cvtss2sd_EXTRICATE_ARGS := float32_to_float64
x86_64-cvtsd2ss_EXTRICATE_ARGS := float64_to_float32
x86_64-cvtdq2ps_EXTRICATE_ARGS := int32_to_float32
x86_64-cvtdq2pd_EXTRICATE_ARGS := int32_to_float64
x86_64-cvtpi2ps_EXTRICATE_ARGS := int32_to_float32
x86_64-cvtpi2pd_EXTRICATE_ARGS := int32_to_float64
x86_64-cvtsi2ss_EXTRICATE_ARGS := int32_to_float32
x86_64-cvtsi2sd_EXTRICATE_ARGS := int32_to_float64
x86_64-cvtsq2sd_EXTRICATE_ARGS := int64_to_float64
x86_64-cvtsq2ss_EXTRICATE_ARGS := int64_to_float32
x86_64-cvtps2dq_EXTRICATE_ARGS := float32_to_int32
x86_64-cvtpd2dq_EXTRICATE_ARGS := float64_to_int32
x86_64-cvtps2pi_EXTRICATE_ARGS := float32_to_int32
x86_64-cvtpd2pi_EXTRICATE_ARGS := float64_to_int32
x86_64-cvtss2si_EXTRICATE_ARGS := float32_to_int32
x86_64-cvtsd2si_EXTRICATE_ARGS := float64_to_int32
x86_64-cvtss2sq_EXTRICATE_ARGS := float32_to_int64
x86_64-cvtsd2sq_EXTRICATE_ARGS := float64_to_int64
x86_64-cvttps2dq_EXTRICATE_ARGS := float32_to_int32_round_to_zero
x86_64-cvttpd2dq_EXTRICATE_ARGS := float64_to_int32_round_to_zero
x86_64-cvttps2pi_EXTRICATE_ARGS := float32_to_int32_round_to_zero
x86_64-cvttpd2pi_EXTRICATE_ARGS := float64_to_int32_round_to_zero
x86_64-cvttss2si_EXTRICATE_ARGS := float32_to_int32_round_to_zero
x86_64-cvttsd2si_EXTRICATE_ARGS := float64_to_int32_round_to_zero
x86_64-cvttss2sq_EXTRICATE_ARGS := float32_to_int64_round_to_zero
x86_64-cvttsd2sq_EXTRICATE_ARGS := float64_to_int64_round_to_zero
x86_64-rsqrtps_EXTRICATE_ARGS := float32_sqrt float32_div
x86_64-rsqrtss_EXTRICATE_ARGS := float32_sqrt float32_div
x86_64-rcpps_EXTRICATE_ARGS := float32_div
x86_64-rcpss_EXTRICATE_ARGS := float32_div
x86_64-haddps_EXTRICATE_ARGS := float32_add
x86_64-haddpd_EXTRICATE_ARGS := float64_add
x86_64-hsubps_EXTRICATE_ARGS := float32_sub
x86_64-hsubpd_EXTRICATE_ARGS := float64_sub
x86_64-addsubps_EXTRICATE_ARGS := float32_add float32_sub
x86_64-addsubpd_EXTRICATE_ARGS := float64_add float64_sub
x86_64-cmpeqpd_EXTRICATE_ARGS := float64_eq_quiet float32_eq_quiet
x86_64-cmpeqps_EXTRICATE_ARGS := float64_eq_quiet float32_eq_quiet
x86_64-cmpeqss_EXTRICATE_ARGS := float64_eq_quiet float32_eq_quiet
x86_64-cmpeqsd_EXTRICATE_ARGS := float64_eq_quiet float32_eq_quiet
x86_64-cmpltps_EXTRICATE_ARGS := float64_lt float32_lt
x86_64-cmpltss_EXTRICATE_ARGS := float64_lt float32_lt
x86_64-cmpltpd_EXTRICATE_ARGS := float64_lt float32_lt
x86_64-cmpltsd_EXTRICATE_ARGS := float64_lt float32_lt
x86_64-cmpleps_EXTRICATE_ARGS := float64_le float32_le
x86_64-cmpless_EXTRICATE_ARGS := float64_le float32_le
x86_64-cmplepd_EXTRICATE_ARGS := float64_le float32_le
x86_64-cmplesd_EXTRICATE_ARGS := float64_le float32_le
x86_64-cmpunordps_EXTRICATE_ARGS := float64_unordered_quiet float32_unordered_quiet
x86_64-cmpunordss_EXTRICATE_ARGS := float64_unordered_quiet float32_unordered_quiet
x86_64-cmpunordpd_EXTRICATE_ARGS := float64_unordered_quiet float32_unordered_quiet
x86_64-cmpunordsd_EXTRICATE_ARGS := float64_unordered_quiet float32_unordered_quiet
x86_64-cmpneqps_EXTRICATE_ARGS := float64_eq_quiet float32_eq_quiet
x86_64-cmpneqss_EXTRICATE_ARGS := float64_eq_quiet float32_eq_quiet
x86_64-cmpneqpd_EXTRICATE_ARGS := float64_eq_quiet float32_eq_quiet
x86_64-cmpneqsd_EXTRICATE_ARGS := float64_eq_quiet float32_eq_quiet
x86_64-cmpnltps_EXTRICATE_ARGS := float64_lt float32_lt
x86_64-cmpnltss_EXTRICATE_ARGS := float64_lt float32_lt
x86_64-cmpnltsd_EXTRICATE_ARGS := float64_lt float32_lt
x86_64-cmpnltpd_EXTRICATE_ARGS := float64_lt float32_lt
x86_64-cmpnleps_EXTRICATE_ARGS := float64_le float32_le
x86_64-cmpnless_EXTRICATE_ARGS := float64_le float32_le
x86_64-cmpnlepd_EXTRICATE_ARGS := float64_le float32_le
x86_64-cmpnlesd_EXTRICATE_ARGS := float64_le float32_le
x86_64-cmpordps_EXTRICATE_ARGS := float64_unordered_quiet float32_unordered_quiet
x86_64-cmpordss_EXTRICATE_ARGS := float64_unordered_quiet float32_unordered_quiet
x86_64-cmpordpd_EXTRICATE_ARGS := float64_unordered_quiet float32_unordered_quiet
x86_64-cmpordsd_EXTRICATE_ARGS := float64_unordered_quiet float32_unordered_quiet
x86_64-ucomiss_EXTRICATE_ARGS := float32_compare_quiet
x86_64-comiss_EXTRICATE_ARGS := float32_compare
x86_64-ucomisd_EXTRICATE_ARGS := float64_compare_quiet
x86_64-comisd_EXTRICATE_ARGS := float64_compare
x86_64-roundps_xmm_EXTRICATE_ARGS := float32_round_to_int
x86_64-roundpd_xmm_EXTRICATE_ARGS := float64_round_to_int
x86_64-roundss_xmm_EXTRICATE_ARGS := float32_round_to_int
x86_64-roundsd_xmm_EXTRICATE_ARGS := float64_round_to_int
x86_64-dpps_xmm_EXTRICATE_ARGS := float32_mul float32_add
x86_64-dppd_xmm_EXTRICATE_ARGS := float64_mul float64_add
x86_64-rdrand_EXTRICATE_ARGS := error_get_pretty error_free qemu_guest_getrandom qemu_log
x86_64-aesdec_xmm_EXTRICATE_ARGS := AES_Td3 AES_Td2 AES_Td1 AES_ishifts AES_Td0
x86_64-aesdeclast_xmm_EXTRICATE_ARGS := AES_ishifts AES_isbox
x86_64-aesenc_xmm_EXTRICATE_ARGS := AES_Te3 AES_Te2 AES_Te1 AES_shifts AES_Te0
x86_64-aesenclast_xmm_EXTRICATE_ARGS := AES_shifts AES_sbox
x86_64-aesimc_xmm_EXTRICATE_ARGS := AES_imc
x86_64-aeskeygenassist_xmm_EXTRICATE_ARGS := AES_sbox

i386-aaa_EXTRICATE_ARGS := cpu_cc_compute_all
i386-aas_EXTRICATE_ARGS := cpu_cc_compute_all
i386-daa_EXTRICATE_ARGS := cpu_cc_compute_all
i386-das_EXTRICATE_ARGS := cpu_cc_compute_all
i386-lsl_EXTRICATE_ARGS := cpu_cc_compute_all
i386-lar_EXTRICATE_ARGS := cpu_cc_compute_all
i386-verr_EXTRICATE_ARGS := cpu_cc_compute_all
i386-verw_EXTRICATE_ARGS := cpu_cc_compute_all
i386-cmpxchg8b_unlocked_EXTRICATE_ARGS := cpu_cc_compute_all
i386-cmpxchg8b_EXTRICATE_ARGS := cpu_cc_compute_all
i386-flds_FT0_EXTRICATE_ARGS := float32_to_floatx80
i386-fldl_FT0_EXTRICATE_ARGS := float64_to_floatx80
i386-fildl_FT0_EXTRICATE_ARGS := int32_to_floatx80
i386-flds_ST0_EXTRICATE_ARGS := float32_to_floatx80
i386-fldl_ST0_EXTRICATE_ARGS := float64_to_floatx80
i386-fildl_ST0_EXTRICATE_ARGS := int32_to_floatx80
i386-fildll_ST0_EXTRICATE_ARGS := int64_to_floatx80
i386-fsts_ST0_EXTRICATE_ARGS := floatx80_to_float32
i386-fstl_ST0_EXTRICATE_ARGS := floatx80_to_float64
i386-fist_ST0_EXTRICATE_ARGS := floatx80_to_int32
i386-fistl_ST0_EXTRICATE_ARGS := floatx80_to_int32
i386-fistll_ST0_EXTRICATE_ARGS := floatx80_to_int64
i386-fistt_ST0_EXTRICATE_ARGS := floatx80_to_int32_round_to_zero
i386-fisttl_ST0_EXTRICATE_ARGS := floatx80_to_int32_round_to_zero
i386-fisttll_ST0_EXTRICATE_ARGS := floatx80_to_int64_round_to_zero
i386-fcom_ST0_FT0_EXTRICATE_ARGS := floatx80_compare
i386-fucom_ST0_FT0_EXTRICATE_ARGS := floatx80_compare_quiet
i386-fcomi_ST0_FT0_EXTRICATE_ARGS := cpu_cc_compute_all floatx80_compare
i386-fucomi_ST0_FT0_EXTRICATE_ARGS := cpu_cc_compute_all floatx80_compare_quiet
i386-fadd_ST0_FT0_EXTRICATE_ARGS := floatx80_add
i386-fmul_ST0_FT0_EXTRICATE_ARGS := floatx80_mul
i386-fsub_ST0_FT0_EXTRICATE_ARGS := floatx80_sub
i386-fsubr_ST0_FT0_EXTRICATE_ARGS := floatx80_sub
i386-fdiv_ST0_FT0_EXTRICATE_ARGS := floatx80_div
i386-fdivr_ST0_FT0_EXTRICATE_ARGS := floatx80_div
i386-fadd_STN_ST0_EXTRICATE_ARGS := floatx80_add
i386-fmul_STN_ST0_EXTRICATE_ARGS := floatx80_mul
i386-fsub_STN_ST0_EXTRICATE_ARGS := floatx80_sub
i386-fsubr_STN_ST0_EXTRICATE_ARGS := floatx80_sub
i386-fdiv_STN_ST0_EXTRICATE_ARGS := floatx80_div
i386-fdivr_STN_ST0_EXTRICATE_ARGS := floatx80_div
i386-fbld_ST0_EXTRICATE_ARGS := int64_to_floatx80
i386-fbst_ST0_EXTRICATE_ARGS := floatx80_to_int64
i386-f2xm1_EXTRICATE_ARGS := float64_to_floatx80 __pow_finite floatx80_to_float64
i386-fyl2x_EXTRICATE_ARGS := float64_to_floatx80 __log_finite floatx80_to_float64
i386-fptan_EXTRICATE_ARGS := float64_to_floatx80 tan floatx80_to_float64
i386-fpatan_EXTRICATE_ARGS := float64_to_floatx80 __atan2_finite floatx80_to_float64
i386-fxtract_EXTRICATE_ARGS := int32_to_floatx80 floatx80_div
i386-fprem1_EXTRICATE_ARGS := float64_to_floatx80 floatx80_to_float64 __pow_finite rint floor fabs
i386-fprem_EXTRICATE_ARGS := floatx80_to_float64 __pow_finite rint floor fabs float64_to_floatx80 ceil
i386-fyl2xp1_EXTRICATE_ARGS := float64_to_floatx80 __log_finite floatx80_to_float64
i386-fsqrt_EXTRICATE_ARGS := floatx80_sqrt
i386-fsincos_EXTRICATE_ARGS := float64_to_floatx80 floatx80_to_float64 sin cos
i386-frndint_EXTRICATE_ARGS := floatx80_round_to_int
i386-fscale_EXTRICATE_ARGS := floatx80_scalbn floatx80_to_int32_round_to_zero
i386-fsin_EXTRICATE_ARGS := float64_to_floatx80 sin floatx80_to_float64
i386-fcos_EXTRICATE_ARGS := float64_to_floatx80 cos floatx80_to_float64
i386-xrstor_EXTRICATE_ARGS := cpu_sync_bndcs_hflags
i386-xsetbv_EXTRICATE_ARGS := cpu_sync_bndcs_hflags cpu_x86_cpuid
i386-rdpkru_EXTRICATE_ARGS := cpu_x86_cpuid cpu_svm_check_intercept_param
i386-wrpkru_EXTRICATE_ARGS := cpu_x86_cpuid cpu_svm_check_intercept_param
i386-pi2fd_EXTRICATE_ARGS := int32_to_float32
i386-pi2fw_EXTRICATE_ARGS := int32_to_float32
i386-pf2id_EXTRICATE_ARGS := float32_to_int32_round_to_zero
i386-pf2iw_EXTRICATE_ARGS := float32_to_int32_round_to_zero
i386-pfacc_EXTRICATE_ARGS := float32_add
i386-pfadd_EXTRICATE_ARGS := float32_add
i386-pfcmpeq_EXTRICATE_ARGS := float32_eq_quiet
i386-pfcmpge_EXTRICATE_ARGS := float32_le
i386-pfcmpgt_EXTRICATE_ARGS := float32_lt
i386-pfmax_EXTRICATE_ARGS := float32_lt
i386-pfmin_EXTRICATE_ARGS := float32_lt
i386-pfmul_EXTRICATE_ARGS := float32_mul
i386-pfnacc_EXTRICATE_ARGS := float32_sub
i386-pfpnacc_EXTRICATE_ARGS := float32_add float32_sub
i386-pfrcp_EXTRICATE_ARGS := float32_div
i386-pfrsqrt_EXTRICATE_ARGS := float32_sqrt float32_div
i386-pfsub_EXTRICATE_ARGS := float32_sub
i386-pfsubr_EXTRICATE_ARGS := float32_sub
i386-addps_EXTRICATE_ARGS := float64_add float32_add
i386-subps_EXTRICATE_ARGS := float64_sub float32_sub
i386-mulps_EXTRICATE_ARGS := float64_mul float32_mul
i386-divps_EXTRICATE_ARGS := float64_div float32_div
i386-minps_EXTRICATE_ARGS := float64_lt float32_lt
i386-maxps_EXTRICATE_ARGS := float64_lt float32_lt
i386-sqrtps_EXTRICATE_ARGS := float64_sqrt float32_sqrt
i386-cvtps2pd_EXTRICATE_ARGS := float32_to_float64
i386-cvtpd2ps_EXTRICATE_ARGS := float64_to_float32
i386-cvtss2sd_EXTRICATE_ARGS := float32_to_float64
i386-cvtsd2ss_EXTRICATE_ARGS := float64_to_float32
i386-cvtdq2ps_EXTRICATE_ARGS := int32_to_float32
i386-cvtdq2pd_EXTRICATE_ARGS := int32_to_float64
i386-cvtpi2ps_EXTRICATE_ARGS := int32_to_float32
i386-cvtpi2pd_EXTRICATE_ARGS := int32_to_float64
i386-cvtsi2ss_EXTRICATE_ARGS := int32_to_float32
i386-cvtsi2sd_EXTRICATE_ARGS := int32_to_float64
i386-cvtps2dq_EXTRICATE_ARGS := float32_to_int32
i386-cvtpd2dq_EXTRICATE_ARGS := float64_to_int32
i386-cvtps2pi_EXTRICATE_ARGS := float32_to_int32
i386-cvtpd2pi_EXTRICATE_ARGS := float64_to_int32
i386-cvtss2si_EXTRICATE_ARGS := float32_to_int32
i386-cvtsd2si_EXTRICATE_ARGS := float64_to_int32
i386-cvttps2dq_EXTRICATE_ARGS := float32_to_int32_round_to_zero
i386-cvttpd2dq_EXTRICATE_ARGS := float64_to_int32_round_to_zero
i386-cvttps2pi_EXTRICATE_ARGS := float32_to_int32_round_to_zero
i386-cvttpd2pi_EXTRICATE_ARGS := float64_to_int32_round_to_zero
i386-cvttss2si_EXTRICATE_ARGS := float32_to_int32_round_to_zero
i386-cvttsd2si_EXTRICATE_ARGS := float64_to_int32_round_to_zero
i386-rsqrtps_EXTRICATE_ARGS := float32_sqrt float32_div
i386-rsqrtss_EXTRICATE_ARGS := float32_sqrt float32_div
i386-rcpps_EXTRICATE_ARGS := float32_div
i386-rcpss_EXTRICATE_ARGS := float32_div
i386-haddps_EXTRICATE_ARGS := float32_add
i386-haddpd_EXTRICATE_ARGS := float64_add
i386-hsubps_EXTRICATE_ARGS := float32_sub
i386-hsubpd_EXTRICATE_ARGS := float64_sub
i386-addsubps_EXTRICATE_ARGS := float32_add float32_sub
i386-addsubpd_EXTRICATE_ARGS := float64_add float64_sub
i386-cmpeqps_EXTRICATE_ARGS := float64_eq_quiet float32_eq_quiet
i386-cmpltps_EXTRICATE_ARGS := float64_lt float32_lt
i386-cmpleps_EXTRICATE_ARGS := float64_le float32_le
i386-cmpunordps_EXTRICATE_ARGS := float64_unordered_quiet float32_unordered_quiet
i386-cmpneqps_EXTRICATE_ARGS := float64_eq_quiet float32_eq_quiet
i386-cmpnltps_EXTRICATE_ARGS := float64_lt float32_lt
i386-cmpnleps_EXTRICATE_ARGS := float64_le float32_le
i386-cmpordps_EXTRICATE_ARGS := float64_unordered_quiet float32_unordered_quiet
i386-ucomiss_EXTRICATE_ARGS := float32_compare_quiet
i386-comiss_EXTRICATE_ARGS := float32_compare
i386-ucomisd_EXTRICATE_ARGS := float64_compare_quiet
i386-comisd_EXTRICATE_ARGS := float64_compare
i386-roundps_xmm_EXTRICATE_ARGS := float32_round_to_int
i386-roundpd_xmm_EXTRICATE_ARGS := float64_round_to_int
i386-roundss_xmm_EXTRICATE_ARGS := float32_round_to_int
i386-roundsd_xmm_EXTRICATE_ARGS := float64_round_to_int
i386-dpps_xmm_EXTRICATE_ARGS := float32_mul float32_add
i386-dppd_xmm_EXTRICATE_ARGS := float64_mul float64_add
i386-mulsh_i64_EXTRICATE_ARGS := muls64
i386-muluh_i64_EXTRICATE_ARGS := mulu64

i386-addss_EXTRICATE_ARGS := float64_add float32_add
i386-addpd_EXTRICATE_ARGS := float64_add float32_add
i386-addsd_EXTRICATE_ARGS := float64_add float32_add
i386-subss_EXTRICATE_ARGS := float64_sub float32_sub
i386-subpd_EXTRICATE_ARGS := float64_sub float32_sub
i386-subsd_EXTRICATE_ARGS := float64_sub float32_sub
i386-mulss_EXTRICATE_ARGS := float64_mul float32_mul
i386-mulpd_EXTRICATE_ARGS := float64_mul float32_mul
i386-mulsd_EXTRICATE_ARGS := float64_mul float32_mul
i386-divss_EXTRICATE_ARGS := float64_div float32_div
i386-divpd_EXTRICATE_ARGS := float64_div float32_div
i386-divsd_EXTRICATE_ARGS := float64_div float32_div
i386-minss_EXTRICATE_ARGS := float64_lt float32_lt
i386-minpd_EXTRICATE_ARGS := float64_lt float32_lt
i386-minsd_EXTRICATE_ARGS := float64_lt float32_lt
i386-maxss_EXTRICATE_ARGS := float64_lt float32_lt
i386-maxpd_EXTRICATE_ARGS := float64_lt float32_lt
i386-maxsd_EXTRICATE_ARGS := float64_lt float32_lt
i386-sqrtss_EXTRICATE_ARGS := float64_sqrt float32_sqrt
i386-sqrtpd_EXTRICATE_ARGS := float64_sqrt float32_sqrt
i386-sqrtsd_EXTRICATE_ARGS := float64_sqrt float32_sqrt
i386-cmpeqss_EXTRICATE_ARGS := float64_eq_quiet float32_eq_quiet
i386-cmpeqpd_EXTRICATE_ARGS := float64_eq_quiet float32_eq_quiet
i386-cmpeqsd_EXTRICATE_ARGS := float64_eq_quiet float32_eq_quiet
i386-cmpltss_EXTRICATE_ARGS := float64_lt float32_lt
i386-cmpltpd_EXTRICATE_ARGS := float64_lt float32_lt
i386-cmpltsd_EXTRICATE_ARGS := float64_lt float32_lt
i386-cmpless_EXTRICATE_ARGS := float64_le float32_le
i386-cmplepd_EXTRICATE_ARGS := float64_le float32_le
i386-cmplesd_EXTRICATE_ARGS := float64_le float32_le
i386-cmpunordss_EXTRICATE_ARGS := float64_unordered_quiet float32_unordered_quiet
i386-cmpunordpd_EXTRICATE_ARGS := float64_unordered_quiet float32_unordered_quiet
i386-cmpunordsd_EXTRICATE_ARGS := float64_unordered_quiet float32_unordered_quiet
i386-cmpneqss_EXTRICATE_ARGS := float64_eq_quiet float32_eq_quiet
i386-cmpneqpd_EXTRICATE_ARGS := float64_eq_quiet float32_eq_quiet
i386-cmpneqsd_EXTRICATE_ARGS := float64_eq_quiet float32_eq_quiet
i386-cmpnltss_EXTRICATE_ARGS := float64_lt float32_lt
i386-cmpnltpd_EXTRICATE_ARGS := float64_lt float32_lt
i386-cmpnltsd_EXTRICATE_ARGS := float64_lt float32_lt
i386-cmpnless_EXTRICATE_ARGS := float64_le float32_le
i386-cmpnlepd_EXTRICATE_ARGS := float64_le float32_le
i386-cmpnlesd_EXTRICATE_ARGS := float64_le float32_le
i386-cmpordss_EXTRICATE_ARGS := float64_unordered_quiet float32_unordered_quiet
i386-cmpordpd_EXTRICATE_ARGS := float64_unordered_quiet float32_unordered_quiet
i386-cmpordsd_EXTRICATE_ARGS := float64_unordered_quiet float32_unordered_quiet

i386-into_EXTRICATE_ARGS := cpu_cc_compute_all

#
# I'll just put this here.
#
# carbon-extract tcg/tcg-op.c:1243l tcg/optimize.c:599l tcg/tcg-common.c:33l accel/tcg/translate-all.c:1667l accel/tcg/translator.c:36l util/cutils.c:45l tcg/tcg.c:2634l tcg/tcg.c:2824l tcg/tcg.c:5714l gen_intermediate_code target/mips/translate.c:30971l > ../jove/lib/arch/mips64el/tcg.hpp

#
# TCG helpers
#
.PHONY: extract-helpers
extract-helpers: $(foreach helper,$($(ARCH)_HELPERS),extract-$(helper))

define extract_helper_template
.PHONY: extract-$(1)
extract-$(1):
	-$(CLANG_EXTRICATE)/extract/bin/carbon-extract --src $(QEMU_SRC_DIR) --bin $(QEMU_BUILD_DIR) helper_$(1) $($(ARCH)-$(1)_EXTRICATE_ARGS) > lib/arch/$(ARCH)/helpers/$(1).c
endef
$(foreach helper,$($(ARCH)_HELPERS),$(eval $(call extract_helper_template,$(helper))))

define build_helper_template
$(BINDIR)/$(1).ll: $(BINDIR)/$(1).bc
	@echo DIS $$<
	@$(_LLVM_DIS) -o $$@ $$<

$(BINDIR)/$(1).bc: lib/arch/$(ARCH)/helpers/$(1).c
	@echo BC $$<
	@$(_LLVM_CC) -o $$@ -c -I lib -I lib/arch/$(ARCH) -emit-llvm -fPIC -g -O3 -ffreestanding -fno-stack-protector -Wall -Wno-macro-redefined -Wno-initializer-overrides -fno-strict-aliasing -fno-common -fwrapv -DNEED_CPU_H -DNDEBUG $($(ARCH)_HELPER_CFLAGS) $$<
endef
$(foreach helper,$($(ARCH)_HELPERS),$(eval $(call build_helper_template,$(helper))))

define build_helper_dfsan_template
$(BINDIR)/$(1).dfsan.ll: $(BINDIR)/$(1).dfsan.bc
	@echo DIS $$<
	@$(_LLVM_DIS) -o $$@ $$<

$(BINDIR)/$(1).dfsan.bc: lib/arch/$(ARCH)/helpers/$(1).c
	@echo BC "(DFSAN)" $$<
	@$(_LLVM_CC) -o $$@ -c -I lib -I lib/arch/$(ARCH) -emit-llvm -fPIC -g -O3 -ffreestanding -fno-stack-protector -Wall -Wno-macro-redefined -Wno-initializer-overrides -fno-strict-aliasing -fno-common -fwrapv -DNEED_CPU_H -DNDEBUG -DJOVE_DFSAN $($(ARCH)_HELPER_CFLAGS) $$<
endef
$(foreach helper,$($(ARCH)_HELPERS),$(eval $(call build_helper_dfsan_template,$(helper))))

.PHONY: check-helpers
check-helpers: $(foreach helper,$($(ARCH)_HELPERS),check-$(helper))

define check_helper_template
.PHONY: check-$(1)
check-$(1): $(BINDIR)/$(1).bc $(BINDIR)/check-helper
	-@$(BINDIR)/check-helper $(1)
endef
$(foreach helper,$($(ARCH)_HELPERS),$(eval $(call check_helper_template,$(helper))))

#
# qemu configure command
#
#./configure --target-list=i386-linux-user --cc=clang --host-cc=clang --cxx=clang++ --objcc=clang --disable-tcg-interpreter --disable-sdl --disable-gtk --disable-xen --disable-bluez --disable-kvm --disable-guest-agent --disable-vnc --disable-jemalloc --disable-tcmalloc --disable-vhost-user --disable-opengl --disable-glusterfs --disable-gnutls --disable-nettle --disable-gcrypt --disable-curses --disable-libnfs --disable-libusb --disable-lzo --disable-bzip2 --disable-vhost-vsock --disable-smartcard --disable-usb-redir --disable-spice --disable-vhost-net --disable-snappy --disable-seccomp --disable-vhost-scsi --disable-virglrenderer --disable-vde --disable-rbd --disable-live-block-migration --disable-tools --disable-tpm --disable-numa --disable-cap-ng --disable-replication --disable-vte --disable-qom-cast-debug --disable-tpm --disable-xfsctl --disable-linux-aio --disable-attr --disable-coroutine-pool --disable-hax --enable-trace-backends=nop --disable-libxml2 --disable-vhost-crypto --disable-capstone --disable-werror --extra-cflags="-Xclang -load -Xclang $HOME/clang-extricate/collect/bin/carbon-collect.so -Xclang -add-plugin -Xclang carbon-collect -Xclang -plugin-arg-carbon-collect -Xclang $(pwd) -Xclang -plugin-arg-carbon-collect -Xclang $(pwd)"
