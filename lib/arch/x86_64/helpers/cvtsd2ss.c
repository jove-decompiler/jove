#define TARGET_X86_64 1

#include <stdbool.h>

#include <stdint.h>

#include <stdlib.h>

#define Q_TAILQ_ENTRY(type, qual)                                       \
struct {                                                                \
        qual type *tqe_next;            /* next element */              \
        qual type *qual *tqe_prev;      /* address of previous next element */\
}

#define QTAILQ_ENTRY(type)       Q_TAILQ_ENTRY(struct type,)

typedef uint8_t flag;

typedef uint32_t float32;

#define float64_val(x) (x)

#define make_float32(x) (x)

#define make_float64(x) (x)

#define const_float32(x) (x)

typedef uint64_t float64;

typedef struct {
    uint64_t low;
    uint16_t high;
} floatx80;

enum {
    float_tininess_after_rounding  = 0,
    float_tininess_before_rounding = 1
};

enum {
    float_round_nearest_even = 0,
    float_round_down         = 1,
    float_round_up           = 2,
    float_round_to_zero      = 3,
    float_round_ties_away    = 4,
    /* Not an IEEE rounding mode: round to the closest odd mantissa value */
    float_round_to_odd       = 5,
};

enum {
    float_flag_invalid   =  1,
    float_flag_divbyzero =  4,
    float_flag_overflow  =  8,
    float_flag_underflow = 16,
    float_flag_inexact   = 32,
    float_flag_input_denormal = 64,
    float_flag_output_denormal = 128
};

typedef struct float_status {
    signed char float_detect_tininess;
    signed char float_rounding_mode;
    uint8_t     float_exception_flags;
    signed char floatx80_rounding_precision;
    /* should denormalised results go to zero and set the inexact flag? */
    flag flush_to_zero;
    /* should denormalised inputs go to zero and set the input_denormal flag? */
    flag flush_inputs_to_zero;
    flag default_nan_mode;
    flag snan_bit_is_one;
} float_status;

typedef struct MemTxAttrs {
    /* Bus masters which don't specify any attributes will get this
     * (via the MEMTXATTRS_UNSPECIFIED constant), so that we can
     * distinguish "all attributes deliberately clear" from
     * "didn't specify" if necessary.
     */
    unsigned int unspecified:1;
    /* ARM/AMBA: TrustZone Secure access
     * x86: System Management Mode access
     */
    unsigned int secure:1;
    /* Memory access is usermode (unprivileged) */
    unsigned int user:1;
    /* Requester ID (for MSI for example) */
    unsigned int requester_id:16;
} MemTxAttrs;

typedef uint64_t vaddr;

typedef struct CPUBreakpoint {
    vaddr pc;
    int flags; /* BP_* */
    QTAILQ_ENTRY(CPUBreakpoint) entry;
} CPUBreakpoint;

struct CPUWatchpoint {
    vaddr _vaddr;
    vaddr len;
    vaddr hitaddr;
    MemTxAttrs hitattrs;
    int flags; /* BP_* */
    QTAILQ_ENTRY(CPUWatchpoint) entry;
};

#define HV_X64_MSR_CRASH_P0                     0x40000100

#define HV_X64_MSR_CRASH_P4                     0x40000104

#define HV_CRASH_PARAMS    (HV_X64_MSR_CRASH_P4 - HV_X64_MSR_CRASH_P0 + 1)

#define HV_SINT_COUNT                         16

#define HV_STIMER_COUNT                       4

#define CPU_COMMON_TLB

#define CPU_COMMON                                                      \
    /* soft mmu support */                                              \
    CPU_COMMON_TLB

typedef uint64_t target_ulong;

#define MCE_BANKS_DEF   10

#define MSR_MTRRcap_VCNT                8

#define MSR_P6_EVNTSEL0                 0x186

#define MSR_IA32_PERF_STATUS            0x198

#define MAX_RTIT_ADDRS                  8

typedef enum FeatureWord {
    FEAT_1_EDX,         /* CPUID[1].EDX */
    FEAT_1_ECX,         /* CPUID[1].ECX */
    FEAT_7_0_EBX,       /* CPUID[EAX=7,ECX=0].EBX */
    FEAT_7_0_ECX,       /* CPUID[EAX=7,ECX=0].ECX */
    FEAT_7_0_EDX,       /* CPUID[EAX=7,ECX=0].EDX */
    FEAT_8000_0001_EDX, /* CPUID[8000_0001].EDX */
    FEAT_8000_0001_ECX, /* CPUID[8000_0001].ECX */
    FEAT_8000_0007_EDX, /* CPUID[8000_0007].EDX */
    FEAT_8000_0008_EBX, /* CPUID[8000_0008].EBX */
    FEAT_C000_0001_EDX, /* CPUID[C000_0001].EDX */
    FEAT_KVM,           /* CPUID[4000_0001].EAX (KVM_CPUID_FEATURES) */
    FEAT_KVM_HINTS,     /* CPUID[4000_0001].EDX */
    FEAT_HYPERV_EAX,    /* CPUID[4000_0003].EAX */
    FEAT_HYPERV_EBX,    /* CPUID[4000_0003].EBX */
    FEAT_HYPERV_EDX,    /* CPUID[4000_0003].EDX */
    FEAT_SVM,           /* CPUID[8000_000A].EDX */
    FEAT_XSAVE,         /* CPUID[EAX=0xd,ECX=1].EAX */
    FEAT_6_EAX,         /* CPUID[6].EAX */
    FEAT_XSAVE_COMP_LO, /* CPUID[EAX=0xd,ECX=0].EAX */
    FEAT_XSAVE_COMP_HI, /* CPUID[EAX=0xd,ECX=0].EDX */
    FEATURE_WORDS,
} FeatureWord;

typedef uint32_t FeatureWordArray[FEATURE_WORDS];

#define MMREG_UNION(n, bits)        \
    union n {                       \
        uint8_t  _b_##n[(bits)/8];  \
        uint16_t _w_##n[(bits)/16]; \
        uint32_t _l_##n[(bits)/32]; \
        uint64_t _q_##n[(bits)/64]; \
        float32  _s_##n[(bits)/32]; \
        float64  _d_##n[(bits)/64]; \
    }

typedef struct SegmentCache {
    uint32_t selector;
    target_ulong base;
    uint32_t limit;
    uint32_t flags;
} SegmentCache;

typedef union {
    uint8_t _b[16];
    uint16_t _w[8];
    uint32_t _l[4];
    uint64_t _q[2];
} XMMReg;

typedef union {
    uint8_t _b[32];
    uint16_t _w[16];
    uint32_t _l[8];
    uint64_t _q[4];
} YMMReg;

typedef MMREG_UNION(ZMMReg, 512) ZMMReg;

typedef MMREG_UNION(MMXReg, 64)  MMXReg;

typedef struct BNDReg {
    uint64_t lb;
    uint64_t ub;
} BNDReg;

#define ZMM_S(n) _s_ZMMReg[n]

#define ZMM_D(n) _d_ZMMReg[n]

typedef struct BNDCSReg {
    uint64_t cfgu;
    uint64_t sts;
} BNDCSReg;

typedef union {
    floatx80 d __attribute__((aligned(16)));
    MMXReg mmx;
} FPReg;

#define CPU_NB_REGS64 16

#define CPU_NB_REGS CPU_NB_REGS64

#define MAX_FIXED_COUNTERS 3

#define MAX_GP_COUNTERS    (MSR_IA32_PERF_STATUS - MSR_P6_EVNTSEL0)

#define NB_OPMASK_REGS 8

typedef struct {
    uint64_t base;
    uint64_t mask;
} MTRRVar;

typedef enum TPRAccess {
    TPR_ACCESS_READ,
    TPR_ACCESS_WRITE,
} TPRAccess;

typedef struct CPUX86State {
    /* standard registers */
    target_ulong regs[CPU_NB_REGS];
    target_ulong eip;
    target_ulong eflags; /* eflags register. During CPU emulation, CC
                        flags and DF are set to zero because they are
                        stored elsewhere */

    /* emulator internal eflags handling */
    target_ulong cc_dst;
    target_ulong cc_src;
    target_ulong cc_src2;
    uint32_t cc_op;
    int32_t df; /* D flag : 1 if D = 0, -1 if D = 1 */
    uint32_t hflags; /* TB flags, see HF_xxx constants. These flags
                        are known at translation time. */
    uint32_t hflags2; /* various other flags, see HF2_xxx constants. */

    /* segments */
    SegmentCache segs[6]; /* selector values */
    SegmentCache ldt;
    SegmentCache tr;
    SegmentCache gdt; /* only base and limit are used */
    SegmentCache idt; /* only base and limit are used */

    target_ulong cr[5]; /* NOTE: cr1 is unused */
    int32_t a20_mask;

    BNDReg bnd_regs[4];
    BNDCSReg bndcs_regs;
    uint64_t msr_bndcfgs;
    uint64_t efer;

    /* Beginning of state preserved by INIT (dummy marker).  */
    struct {} start_init_save;

    /* FPU state */
    unsigned int fpstt; /* top of stack index */
    uint16_t fpus;
    uint16_t fpuc;
    uint8_t fptags[8];   /* 0 = valid, 1 = empty */
    FPReg fpregs[8];
    /* KVM-only so far */
    uint16_t fpop;
    uint64_t fpip;
    uint64_t fpdp;

    /* emulator internal variables */
    float_status fp_status;
    floatx80 ft0;

    float_status mmx_status; /* for 3DNow! float ops */
    float_status sse_status;
    uint32_t mxcsr;
    ZMMReg xmm_regs[CPU_NB_REGS == 8 ? 8 : 32];
    ZMMReg xmm_t0;
    MMXReg mmx_t0;

    XMMReg ymmh_regs[CPU_NB_REGS];

    uint64_t opmask_regs[NB_OPMASK_REGS];
    YMMReg zmmh_regs[CPU_NB_REGS];
    ZMMReg hi16_zmm_regs[CPU_NB_REGS];

    /* sysenter registers */
    uint32_t sysenter_cs;
    target_ulong sysenter_esp;
    target_ulong sysenter_eip;
    uint64_t star;

    uint64_t vm_hsave;

#ifdef TARGET_X86_64
    target_ulong lstar;
    target_ulong cstar;
    target_ulong fmask;
    target_ulong kernelgsbase;
#endif

    uint64_t tsc;
    uint64_t tsc_adjust;
    uint64_t tsc_deadline;
    uint64_t tsc_aux;

    uint64_t xcr0;

    uint64_t mcg_status;
    uint64_t msr_ia32_misc_enable;
    uint64_t msr_ia32_feature_control;

    uint64_t msr_fixed_ctr_ctrl;
    uint64_t msr_global_ctrl;
    uint64_t msr_global_status;
    uint64_t msr_global_ovf_ctrl;
    uint64_t msr_fixed_counters[MAX_FIXED_COUNTERS];
    uint64_t msr_gp_counters[MAX_GP_COUNTERS];
    uint64_t msr_gp_evtsel[MAX_GP_COUNTERS];

    uint64_t pat;
    uint32_t smbase;
    uint64_t msr_smi_count;

    uint32_t pkru;

    uint64_t spec_ctrl;

    /* End of state preserved by INIT (dummy marker).  */
    struct {} end_init_save;

    uint64_t system_time_msr;
    uint64_t wall_clock_msr;
    uint64_t steal_time_msr;
    uint64_t async_pf_en_msr;
    uint64_t pv_eoi_en_msr;

    /* Partition-wide HV MSRs, will be updated only on the first vcpu */
    uint64_t msr_hv_hypercall;
    uint64_t msr_hv_guest_os_id;
    uint64_t msr_hv_tsc;

    /* Per-VCPU HV MSRs */
    uint64_t msr_hv_vapic;
    uint64_t msr_hv_crash_params[HV_CRASH_PARAMS];
    uint64_t msr_hv_runtime;
    uint64_t msr_hv_synic_control;
    uint64_t msr_hv_synic_evt_page;
    uint64_t msr_hv_synic_msg_page;
    uint64_t msr_hv_synic_sint[HV_SINT_COUNT];
    uint64_t msr_hv_stimer_config[HV_STIMER_COUNT];
    uint64_t msr_hv_stimer_count[HV_STIMER_COUNT];

    uint64_t msr_rtit_ctrl;
    uint64_t msr_rtit_status;
    uint64_t msr_rtit_output_base;
    uint64_t msr_rtit_output_mask;
    uint64_t msr_rtit_cr3_match;
    uint64_t msr_rtit_addrs[MAX_RTIT_ADDRS];

    /* exception/interrupt handling */
    int error_code;
    int exception_is_int;
    target_ulong exception_next_eip;
    target_ulong dr[8]; /* debug registers; note dr4 and dr5 are unused */
    union {
        struct CPUBreakpoint *cpu_breakpoint[4];
        struct CPUWatchpoint *cpu_watchpoint[4];
    }; /* break/watchpoints for dr[0..3] */
    int old_exception;  /* exception in flight */

    uint64_t vm_vmcb;
    uint64_t tsc_offset;
    uint64_t intercept;
    uint16_t intercept_cr_read;
    uint16_t intercept_cr_write;
    uint16_t intercept_dr_read;
    uint16_t intercept_dr_write;
    uint32_t intercept_exceptions;
    uint8_t v_tpr;

    /* KVM states, automatically cleared on reset */
    uint8_t nmi_injected;
    uint8_t nmi_pending;

    /* Fields up to this point are cleared by a CPU reset */
    struct {} end_reset_fields;

    CPU_COMMON

    /* Fields after CPU_COMMON are preserved across CPU reset. */

    /* processor features (e.g. for CPUID insn) */
    /* Minimum level/xlevel/xlevel2, based on CPU model + features */
    uint32_t cpuid_min_level, cpuid_min_xlevel, cpuid_min_xlevel2;
    /* Maximum level/xlevel/xlevel2 value for auto-assignment: */
    uint32_t cpuid_max_level, cpuid_max_xlevel, cpuid_max_xlevel2;
    /* Actual level/xlevel/xlevel2 value: */
    uint32_t cpuid_level, cpuid_xlevel, cpuid_xlevel2;
    uint32_t cpuid_vendor1;
    uint32_t cpuid_vendor2;
    uint32_t cpuid_vendor3;
    uint32_t cpuid_version;
    FeatureWordArray features;
    /* Features that were explicitly enabled/disabled */
    FeatureWordArray user_features;
    uint32_t cpuid_model[12];

    /* MTRRs */
    uint64_t mtrr_fixed[11];
    uint64_t mtrr_deftype;
    MTRRVar mtrr_var[MSR_MTRRcap_VCNT];

    /* For KVM */
    uint32_t mp_state;
    int32_t exception_injected;
    int32_t interrupt_injected;
    uint8_t soft_interrupt;
    uint8_t has_error_code;
    uint32_t ins_len;
    uint32_t sipi_vector;
    bool tsc_valid;
    int64_t tsc_khz;
    int64_t user_tsc_khz; /* for sanity check only */
    void *kvm_xsave_buf;
#if defined(CONFIG_HVF)
    HVFX86EmulatorState *hvf_emul;
#endif

    uint64_t mcg_cap;
    uint64_t mcg_ctl;
    uint64_t mcg_ext_ctl;
    uint64_t mce_banks[MCE_BANKS_DEF*4];
    uint64_t xstate_bv;

    /* vmstate */
    uint16_t fpus_vmstate;
    uint16_t fptag_vmstate;
    uint16_t fpregs_format_vmstate;

    uint64_t xss;

    TPRAccess tpr_access_type;
} CPUX86State;

#define LIT64( a ) a##LL

static inline float32 packFloat32(flag zSign, int zExp, uint32_t zSig)
{
    return make_float32(
          (((uint32_t)zSign) << 31) + (((uint32_t)zExp) << 23) + zSig);
}

float32 float64_to_float32(float64, float_status *status);

#define Reg ZMMReg

void helper_cvtsd2ss(CPUX86State *env, Reg *d, Reg *s)
{
    d->ZMM_S(0) = float64_to_float32(s->ZMM_D(0), &env->sse_status);
}

static inline void shift32RightJamming(uint32_t a, int count, uint32_t *zPtr)
{
    uint32_t z;

    if ( count == 0 ) {
        z = a;
    }
    else if ( count < 32 ) {
        z = ( a>>count ) | ( ( a<<( ( - count ) & 31 ) ) != 0 );
    }
    else {
        z = ( a != 0 );
    }
    *zPtr = z;

}

static inline void shift64RightJamming(uint64_t a, int count, uint64_t *zPtr)
{
    uint64_t z;

    if ( count == 0 ) {
        z = a;
    }
    else if ( count < 64 ) {
        z = ( a>>count ) | ( ( a<<( ( - count ) & 63 ) ) != 0 );
    }
    else {
        z = ( a != 0 );
    }
    *zPtr = z;

}

float32 float32_default_nan(float_status *status)
{
#if defined(TARGET_SPARC) || defined(TARGET_M68K)
    return const_float32(0x7FFFFFFF);
#elif defined(TARGET_PPC) || defined(TARGET_ARM) || defined(TARGET_ALPHA) || \
      defined(TARGET_XTENSA) || defined(TARGET_S390X) || \
      defined(TARGET_TRICORE) || defined(TARGET_RISCV)
    return const_float32(0x7FC00000);
#elif defined(TARGET_HPPA)
    return const_float32(0x7FA00000);
#else
    if (status->snan_bit_is_one) {
        return const_float32(0x7FBFFFFF);
    } else {
#if defined(TARGET_MIPS)
        return const_float32(0x7FC00000);
#else
        return const_float32(0xFFC00000);
#endif
    }
#endif
}

void float_raise(uint8_t flags, float_status *status)
{
    status->float_exception_flags |= flags;
}

typedef struct {
    flag sign;
    uint64_t high, low;
} commonNaNT;

static float32 commonNaNToFloat32(commonNaNT a, float_status *status)
{
    uint32_t mantissa = a.high >> 41;

    if (status->default_nan_mode) {
        return float32_default_nan(status);
    }

    if (mantissa) {
        return make_float32(
            (((uint32_t)a.sign) << 31) | 0x7F800000 | (a.high >> 41));
    } else {
        return float32_default_nan(status);
    }
}

int float64_is_signaling_nan(float64 a_, float_status *status)
{
    uint64_t a = float64_val(a_);
    if (status->snan_bit_is_one) {
        return ((a << 1) >= 0xFFF0000000000000ULL);
    } else {
        return (((a >> 51) & 0xFFF) == 0xFFE)
            && (a & LIT64(0x0007FFFFFFFFFFFF));
    }
}

static commonNaNT float64ToCommonNaN(float64 a, float_status *status)
{
    commonNaNT z;

    if (float64_is_signaling_nan(a, status)) {
        float_raise(float_flag_invalid, status);
    }
    z.sign = float64_val(a) >> 63;
    z.low = 0;
    z.high = float64_val(a) << 12;
    return z;
}

static inline uint64_t extractFloat64Frac(float64 a)
{
    return float64_val(a) & LIT64(0x000FFFFFFFFFFFFF);
}

static inline int extractFloat64Exp(float64 a)
{
    return (float64_val(a) >> 52) & 0x7FF;
}

static inline flag extractFloat64Sign(float64 a)
{
    return float64_val(a) >> 63;
}

static float32 roundAndPackFloat32(flag zSign, int zExp, uint32_t zSig,
                                   float_status *status)
{
    int8_t roundingMode;
    flag roundNearestEven;
    int8_t roundIncrement, roundBits;
    flag isTiny;

    roundingMode = status->float_rounding_mode;
    roundNearestEven = ( roundingMode == float_round_nearest_even );
    switch (roundingMode) {
    case float_round_nearest_even:
    case float_round_ties_away:
        roundIncrement = 0x40;
        break;
    case float_round_to_zero:
        roundIncrement = 0;
        break;
    case float_round_up:
        roundIncrement = zSign ? 0 : 0x7f;
        break;
    case float_round_down:
        roundIncrement = zSign ? 0x7f : 0;
        break;
    default:
        abort();
        break;
    }
    roundBits = zSig & 0x7F;
    if ( 0xFD <= (uint16_t) zExp ) {
        if (    ( 0xFD < zExp )
             || (    ( zExp == 0xFD )
                  && ( (int32_t) ( zSig + roundIncrement ) < 0 ) )
           ) {
            float_raise(float_flag_overflow | float_flag_inexact, status);
            return packFloat32( zSign, 0xFF, - ( roundIncrement == 0 ));
        }
        if ( zExp < 0 ) {
            if (status->flush_to_zero) {
                float_raise(float_flag_output_denormal, status);
                return packFloat32(zSign, 0, 0);
            }
            isTiny =
                (status->float_detect_tininess
                 == float_tininess_before_rounding)
                || ( zExp < -1 )
                || ( zSig + roundIncrement < 0x80000000 );
            shift32RightJamming( zSig, - zExp, &zSig );
            zExp = 0;
            roundBits = zSig & 0x7F;
            if (isTiny && roundBits) {
                float_raise(float_flag_underflow, status);
            }
        }
    }
    if (roundBits) {
        status->float_exception_flags |= float_flag_inexact;
    }
    zSig = ( zSig + roundIncrement )>>7;
    zSig &= ~ ( ( ( roundBits ^ 0x40 ) == 0 ) & roundNearestEven );
    if ( zSig == 0 ) zExp = 0;
    return packFloat32( zSign, zExp, zSig );

}

float64 float64_squash_input_denormal(float64 a, float_status *status)
{
    if (status->flush_inputs_to_zero) {
        if (extractFloat64Exp(a) == 0 && extractFloat64Frac(a) != 0) {
            float_raise(float_flag_input_denormal, status);
            return make_float64(float64_val(a) & (1ULL << 63));
        }
    }
    return a;
}

float32 float64_to_float32(float64 a, float_status *status)
{
    flag aSign;
    int aExp;
    uint64_t aSig;
    uint32_t zSig;
    a = float64_squash_input_denormal(a, status);

    aSig = extractFloat64Frac( a );
    aExp = extractFloat64Exp( a );
    aSign = extractFloat64Sign( a );
    if ( aExp == 0x7FF ) {
        if (aSig) {
            return commonNaNToFloat32(float64ToCommonNaN(a, status), status);
        }
        return packFloat32( aSign, 0xFF, 0 );
    }
    shift64RightJamming( aSig, 22, &aSig );
    zSig = aSig;
    if ( aExp || zSig ) {
        zSig |= 0x40000000;
        aExp -= 0x381;
    }
    return roundAndPackFloat32(aSign, aExp, zSig, status);

}

