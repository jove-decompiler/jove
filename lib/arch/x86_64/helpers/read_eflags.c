#define TARGET_X86_64 1

#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdbool.h>

#include <stdint.h>

#define QTAILQ_ENTRY(type)                                              \
union {                                                                 \
        struct type *tqe_next;        /* next element */                \
        QTailQLink tqe_circ;          /* link for circular backwards list */ \
}

typedef struct QTailQLink {
    void *tql_next;
    struct QTailQLink *tql_prev;
} QTailQLink;

typedef uint8_t flag;

typedef uint32_t float32;

typedef uint64_t float64;

typedef struct {
    uint64_t low;
    uint16_t high;
} floatx80;

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
    /* not always used -- see snan_bit_is_one() in softfloat-specialize.h */
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
    /* Invert endianness for this page */
    unsigned int byte_swap:1;
    /*
     * The following are target-specific page-table bits.  These are not
     * related to actual memory transactions at all.  However, this structure
     * is part of the tlb_fill interface, cached in the cputlb structure,
     * and has unused bits.  These fields will be read by target-specific
     * helpers using env->iotlb[mmu_idx][tlb_index()].attrs.target_tlb_bitN.
     */
    unsigned int target_tlb_bit0 : 1;
    unsigned int target_tlb_bit1 : 1;
    unsigned int target_tlb_bit2 : 1;
} MemTxAttrs;

typedef uint64_t vaddr;

typedef struct CPUBreakpoint {
    vaddr pc;
    int flags; /* BP_* */
    QTAILQ_ENTRY(CPUBreakpoint) entry;
} CPUBreakpoint;

struct CPUWatchpoint {
    vaddr vaddr;
    vaddr len;
    vaddr hitaddr;
    MemTxAttrs hitattrs;
    int flags; /* BP_* */
    QTAILQ_ENTRY(CPUWatchpoint) entry;
};

#define HV_SINT_COUNT                         16

#define HV_X64_MSR_CRASH_P0                     0x40000100

#define HV_X64_MSR_CRASH_P4                     0x40000104

#define HV_CRASH_PARAMS    (HV_X64_MSR_CRASH_P4 - HV_X64_MSR_CRASH_P0 + 1)

#define HV_STIMER_COUNT                       4

typedef int64_t target_long;

typedef uint64_t target_ulong;

#define CC_C    0x0001

#define CC_P    0x0004

#define CC_A    0x0010

#define CC_Z    0x0040

#define CC_S    0x0080

#define CC_O    0x0800

#define DF_MASK                 0x00000400

#define RF_MASK                 0x00010000

#define VM_MASK                 0x00020000

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
    FEAT_7_1_EAX,       /* CPUID[EAX=7,ECX=1].EAX */
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
    FEAT_HV_RECOMM_EAX, /* CPUID[4000_0004].EAX */
    FEAT_HV_NESTED_EAX, /* CPUID[4000_000A].EAX */
    FEAT_SVM,           /* CPUID[8000_000A].EDX */
    FEAT_XSAVE,         /* CPUID[EAX=0xd,ECX=1].EAX */
    FEAT_6_EAX,         /* CPUID[6].EAX */
    FEAT_XSAVE_COMP_LO, /* CPUID[EAX=0xd,ECX=0].EAX */
    FEAT_XSAVE_COMP_HI, /* CPUID[EAX=0xd,ECX=0].EDX */
    FEAT_ARCH_CAPABILITIES,
    FEAT_CORE_CAPABILITY,
    FEAT_VMX_PROCBASED_CTLS,
    FEAT_VMX_SECONDARY_CTLS,
    FEAT_VMX_PINBASED_CTLS,
    FEAT_VMX_EXIT_CTLS,
    FEAT_VMX_ENTRY_CTLS,
    FEAT_VMX_MISC,
    FEAT_VMX_EPT_VPID_CAPS,
    FEAT_VMX_BASIC,
    FEAT_VMX_VMFUNC,
    FEATURE_WORDS,
} FeatureWord;

typedef uint64_t FeatureWordArray[FEATURE_WORDS];

typedef enum {
    CC_OP_DYNAMIC, /* must use dynamic code to get cc_op */
    CC_OP_EFLAGS,  /* all cc are explicitly computed, CC_SRC = flags */

    CC_OP_MULB, /* modify all flags, C, O = (CC_SRC != 0) */
    CC_OP_MULW,
    CC_OP_MULL,
    CC_OP_MULQ,

    CC_OP_ADDB, /* modify all flags, CC_DST = res, CC_SRC = src1 */
    CC_OP_ADDW,
    CC_OP_ADDL,
    CC_OP_ADDQ,

    CC_OP_ADCB, /* modify all flags, CC_DST = res, CC_SRC = src1 */
    CC_OP_ADCW,
    CC_OP_ADCL,
    CC_OP_ADCQ,

    CC_OP_SUBB, /* modify all flags, CC_DST = res, CC_SRC = src1 */
    CC_OP_SUBW,
    CC_OP_SUBL,
    CC_OP_SUBQ,

    CC_OP_SBBB, /* modify all flags, CC_DST = res, CC_SRC = src1 */
    CC_OP_SBBW,
    CC_OP_SBBL,
    CC_OP_SBBQ,

    CC_OP_LOGICB, /* modify all flags, CC_DST = res */
    CC_OP_LOGICW,
    CC_OP_LOGICL,
    CC_OP_LOGICQ,

    CC_OP_INCB, /* modify all flags except, CC_DST = res, CC_SRC = C */
    CC_OP_INCW,
    CC_OP_INCL,
    CC_OP_INCQ,

    CC_OP_DECB, /* modify all flags except, CC_DST = res, CC_SRC = C  */
    CC_OP_DECW,
    CC_OP_DECL,
    CC_OP_DECQ,

    CC_OP_SHLB, /* modify all flags, CC_DST = res, CC_SRC.msb = C */
    CC_OP_SHLW,
    CC_OP_SHLL,
    CC_OP_SHLQ,

    CC_OP_SARB, /* modify all flags, CC_DST = res, CC_SRC.lsb = C */
    CC_OP_SARW,
    CC_OP_SARL,
    CC_OP_SARQ,

    CC_OP_BMILGB, /* Z,S via CC_DST, C = SRC==0; O=0; P,A undefined */
    CC_OP_BMILGW,
    CC_OP_BMILGL,
    CC_OP_BMILGQ,

    CC_OP_ADCX, /* CC_DST = C, CC_SRC = rest.  */
    CC_OP_ADOX, /* CC_DST = O, CC_SRC = rest.  */
    CC_OP_ADCOX, /* CC_DST = C, CC_SRC2 = O, CC_SRC = rest.  */

    CC_OP_CLR, /* Z set, all other flags clear.  */
    CC_OP_POPCNT, /* Z via CC_SRC, all other flags clear.  */

    CC_OP_NB,
} CCOp;

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

enum CacheType {
    DATA_CACHE,
    INSTRUCTION_CACHE,
    UNIFIED_CACHE
};

typedef struct CPUCacheInfo {
    enum CacheType type;
    uint8_t level;
    /* Size in bytes */
    uint32_t size;
    /* Line size, in bytes */
    uint16_t line_size;
    /*
     * Associativity.
     * Note: representation of fully-associative caches is not implemented
     */
    uint8_t associativity;
    /* Physical line partitions. CPUID[0x8000001D].EBX, CPUID[4].EBX */
    uint8_t partitions;
    /* Number of sets. CPUID[0x8000001D].ECX, CPUID[4].ECX */
    uint32_t sets;
    /*
     * Lines per tag.
     * AMD-specific: CPUID[0x80000005], CPUID[0x80000006].
     * (Is this synonym to @partitions?)
     */
    uint8_t lines_per_tag;

    /* Self-initializing cache */
    bool self_init;
    /*
     * WBINVD/INVD is not guaranteed to act upon lower level caches of
     * non-originating threads sharing this cache.
     * CPUID[4].EDX[bit 0], CPUID[0x8000001D].EDX[bit 0]
     */
    bool no_invd_sharing;
    /*
     * Cache is inclusive of lower cache levels.
     * CPUID[4].EDX[bit 1], CPUID[0x8000001D].EDX[bit 1].
     */
    bool inclusive;
    /*
     * A complex function is used to index the cache, potentially using all
     * address bits.  CPUID[4].EDX[bit 2].
     */
    bool complex_indexing;
} CPUCacheInfo;

typedef struct CPUCaches {
        CPUCacheInfo *l1d_cache;
        CPUCacheInfo *l1i_cache;
        CPUCacheInfo *l2_cache;
        CPUCacheInfo *l3_cache;
} CPUCaches;

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
    uint32_t tsx_ctrl;

    uint64_t spec_ctrl;
    uint64_t virt_ssbd;

    /* End of state preserved by INIT (dummy marker).  */
    struct {} end_init_save;

    uint64_t system_time_msr;
    uint64_t wall_clock_msr;
    uint64_t steal_time_msr;
    uint64_t async_pf_en_msr;
    uint64_t pv_eoi_en_msr;
    uint64_t poll_control_msr;

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
    uint64_t msr_hv_reenlightenment_control;
    uint64_t msr_hv_tsc_emulation_control;
    uint64_t msr_hv_tsc_emulation_status;

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
    uint64_t nested_cr3;
    uint32_t nested_pg_mode;
    uint8_t v_tpr;

    /* KVM states, automatically cleared on reset */
    uint8_t nmi_injected;
    uint8_t nmi_pending;

    uintptr_t retaddr;

    /* Fields up to this point are cleared by a CPU reset */
    struct {} end_reset_fields;

    /* Fields after this point are preserved across CPU reset. */

    /* processor features (e.g. for CPUID insn) */
    /* Minimum cpuid leaf 7 value */
    uint32_t cpuid_level_func7;
    /* Actual cpuid leaf 7 value */
    uint32_t cpuid_min_level_func7;
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
    /* Cache information for CPUID.  When legacy-cache=on, the cache data
     * on each CPUID leaf will be different, because we keep compatibility
     * with old QEMU versions.
     */
    CPUCaches cache_info_cpuid2, cache_info_cpuid4, cache_info_amd;

    /* MTRRs */
    uint64_t mtrr_fixed[11];
    uint64_t mtrr_deftype;
    MTRRVar mtrr_var[MSR_MTRRcap_VCNT];

    /* For KVM */
    uint32_t mp_state;
    int32_t exception_nr;
    int32_t interrupt_injected;
    uint8_t soft_interrupt;
    uint8_t exception_pending;
    uint8_t exception_injected;
    uint8_t has_error_code;
    uint8_t exception_has_payload;
    uint64_t exception_payload;
    uint32_t ins_len;
    uint32_t sipi_vector;
    bool tsc_valid;
    int64_t tsc_khz;
    int64_t user_tsc_khz; /* for sanity check only */
#if defined(CONFIG_KVM) || defined(CONFIG_HVF)
    void *xsave_buf;
#endif
#if defined(CONFIG_KVM)
    struct kvm_nested_state *nested_state;
#endif
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
    uint32_t umwait;

    TPRAccess tpr_access_type;

    unsigned nr_dies;
} CPUX86State;

#define CC_DST  (env->cc_dst)

#define CC_SRC  (env->cc_src)

#define CC_SRC2 (env->cc_src2)

#define CC_OP   (env->cc_op)

static inline target_long lshift(target_long x, int n)
{
    if (n >= 0) {
        return x << n;
    } else {
        return x >> (-n);
    }
}

#define SHIFT 0

#define DATA_BITS (1 << (3 + SHIFT))

#define SUFFIX b

#define DATA_TYPE uint8_t

#define SIGN_MASK (((DATA_TYPE)1) << (DATA_BITS - 1))

const uint8_t parity_table[256] = {
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
};

static int glue(compute_all_add, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src2 = dst - src1;

    cf = dst < src1;
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & CC_A;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = lshift((src1 ^ src2 ^ -1) & (src1 ^ dst), 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_adc, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1,
                                         DATA_TYPE src3)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src2 = dst - src1 - src3;

    cf = (src3 ? dst <= src1 : dst < src1);
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & 0x10;
    zf = (dst == 0) << 6;
    sf = lshift(dst, 8 - DATA_BITS) & 0x80;
    of = lshift((src1 ^ src2 ^ -1) & (src1 ^ dst), 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_sub, SUFFIX)(DATA_TYPE dst, DATA_TYPE src2)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src1 = dst + src2;

    cf = src1 < src2;
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & CC_A;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = lshift((src1 ^ src2) & (src1 ^ dst), 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_sbb, SUFFIX)(DATA_TYPE dst, DATA_TYPE src2,
                                         DATA_TYPE src3)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src1 = dst + src2 + src3;

    cf = (src3 ? src1 <= src2 : src1 < src2);
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & 0x10;
    zf = (dst == 0) << 6;
    sf = lshift(dst, 8 - DATA_BITS) & 0x80;
    of = lshift((src1 ^ src2) & (src1 ^ dst), 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_logic, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    cf = 0;
    pf = parity_table[(uint8_t)dst];
    af = 0;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = 0;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_inc, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src2;

    cf = src1;
    src1 = dst - 1;
    src2 = 1;
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & CC_A;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = (dst == SIGN_MASK) * CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_dec, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src2;

    cf = src1;
    src1 = dst + 1;
    src2 = 1;
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & CC_A;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = (dst == SIGN_MASK - 1) * CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_shl, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    cf = (src1 >> (DATA_BITS - 1)) & CC_C;
    pf = parity_table[(uint8_t)dst];
    af = 0; /* undefined */
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    /* of is defined iff shift count == 1 */
    of = lshift(src1 ^ dst, 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_sar, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    cf = src1 & 1;
    pf = parity_table[(uint8_t)dst];
    af = 0; /* undefined */
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    /* of is defined iff shift count == 1 */
    of = lshift(src1 ^ dst, 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_mul, SUFFIX)(DATA_TYPE dst, target_long src1)
{
    int cf, pf, af, zf, sf, of;

    cf = (src1 != 0);
    pf = parity_table[(uint8_t)dst];
    af = 0; /* undefined */
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = cf * CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_bmilg, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    cf = (src1 == 0);
    pf = 0; /* undefined */
    af = 0; /* undefined */
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = 0;
    return cf | pf | af | zf | sf | of;
}

#define SHIFT 1

#define DATA_BITS (1 << (3 + SHIFT))

#define SUFFIX w

#define DATA_TYPE uint16_t

#define SIGN_MASK (((DATA_TYPE)1) << (DATA_BITS - 1))

static int glue(compute_all_add, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src2 = dst - src1;

    cf = dst < src1;
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & CC_A;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = lshift((src1 ^ src2 ^ -1) & (src1 ^ dst), 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_adc, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1,
                                         DATA_TYPE src3)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src2 = dst - src1 - src3;

    cf = (src3 ? dst <= src1 : dst < src1);
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & 0x10;
    zf = (dst == 0) << 6;
    sf = lshift(dst, 8 - DATA_BITS) & 0x80;
    of = lshift((src1 ^ src2 ^ -1) & (src1 ^ dst), 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_sub, SUFFIX)(DATA_TYPE dst, DATA_TYPE src2)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src1 = dst + src2;

    cf = src1 < src2;
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & CC_A;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = lshift((src1 ^ src2) & (src1 ^ dst), 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_sbb, SUFFIX)(DATA_TYPE dst, DATA_TYPE src2,
                                         DATA_TYPE src3)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src1 = dst + src2 + src3;

    cf = (src3 ? src1 <= src2 : src1 < src2);
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & 0x10;
    zf = (dst == 0) << 6;
    sf = lshift(dst, 8 - DATA_BITS) & 0x80;
    of = lshift((src1 ^ src2) & (src1 ^ dst), 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_logic, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    cf = 0;
    pf = parity_table[(uint8_t)dst];
    af = 0;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = 0;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_inc, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src2;

    cf = src1;
    src1 = dst - 1;
    src2 = 1;
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & CC_A;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = (dst == SIGN_MASK) * CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_dec, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src2;

    cf = src1;
    src1 = dst + 1;
    src2 = 1;
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & CC_A;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = (dst == SIGN_MASK - 1) * CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_shl, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    cf = (src1 >> (DATA_BITS - 1)) & CC_C;
    pf = parity_table[(uint8_t)dst];
    af = 0; /* undefined */
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    /* of is defined iff shift count == 1 */
    of = lshift(src1 ^ dst, 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_sar, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    cf = src1 & 1;
    pf = parity_table[(uint8_t)dst];
    af = 0; /* undefined */
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    /* of is defined iff shift count == 1 */
    of = lshift(src1 ^ dst, 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_mul, SUFFIX)(DATA_TYPE dst, target_long src1)
{
    int cf, pf, af, zf, sf, of;

    cf = (src1 != 0);
    pf = parity_table[(uint8_t)dst];
    af = 0; /* undefined */
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = cf * CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_bmilg, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    cf = (src1 == 0);
    pf = 0; /* undefined */
    af = 0; /* undefined */
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = 0;
    return cf | pf | af | zf | sf | of;
}

#define SHIFT 2

#define DATA_BITS (1 << (3 + SHIFT))

#define SUFFIX l

#define DATA_TYPE uint32_t

#define SIGN_MASK (((DATA_TYPE)1) << (DATA_BITS - 1))

static int glue(compute_all_add, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src2 = dst - src1;

    cf = dst < src1;
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & CC_A;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = lshift((src1 ^ src2 ^ -1) & (src1 ^ dst), 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_adc, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1,
                                         DATA_TYPE src3)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src2 = dst - src1 - src3;

    cf = (src3 ? dst <= src1 : dst < src1);
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & 0x10;
    zf = (dst == 0) << 6;
    sf = lshift(dst, 8 - DATA_BITS) & 0x80;
    of = lshift((src1 ^ src2 ^ -1) & (src1 ^ dst), 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_sub, SUFFIX)(DATA_TYPE dst, DATA_TYPE src2)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src1 = dst + src2;

    cf = src1 < src2;
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & CC_A;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = lshift((src1 ^ src2) & (src1 ^ dst), 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_sbb, SUFFIX)(DATA_TYPE dst, DATA_TYPE src2,
                                         DATA_TYPE src3)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src1 = dst + src2 + src3;

    cf = (src3 ? src1 <= src2 : src1 < src2);
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & 0x10;
    zf = (dst == 0) << 6;
    sf = lshift(dst, 8 - DATA_BITS) & 0x80;
    of = lshift((src1 ^ src2) & (src1 ^ dst), 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_logic, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    cf = 0;
    pf = parity_table[(uint8_t)dst];
    af = 0;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = 0;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_inc, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src2;

    cf = src1;
    src1 = dst - 1;
    src2 = 1;
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & CC_A;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = (dst == SIGN_MASK) * CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_dec, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src2;

    cf = src1;
    src1 = dst + 1;
    src2 = 1;
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & CC_A;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = (dst == SIGN_MASK - 1) * CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_shl, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    cf = (src1 >> (DATA_BITS - 1)) & CC_C;
    pf = parity_table[(uint8_t)dst];
    af = 0; /* undefined */
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    /* of is defined iff shift count == 1 */
    of = lshift(src1 ^ dst, 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_sar, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    cf = src1 & 1;
    pf = parity_table[(uint8_t)dst];
    af = 0; /* undefined */
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    /* of is defined iff shift count == 1 */
    of = lshift(src1 ^ dst, 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_mul, SUFFIX)(DATA_TYPE dst, target_long src1)
{
    int cf, pf, af, zf, sf, of;

    cf = (src1 != 0);
    pf = parity_table[(uint8_t)dst];
    af = 0; /* undefined */
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = cf * CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_bmilg, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    cf = (src1 == 0);
    pf = 0; /* undefined */
    af = 0; /* undefined */
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = 0;
    return cf | pf | af | zf | sf | of;
}

#define SHIFT 3

#define DATA_BITS (1 << (3 + SHIFT))

#define SUFFIX q

#define DATA_TYPE uint64_t

#define SIGN_MASK (((DATA_TYPE)1) << (DATA_BITS - 1))

static int glue(compute_all_add, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src2 = dst - src1;

    cf = dst < src1;
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & CC_A;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = lshift((src1 ^ src2 ^ -1) & (src1 ^ dst), 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_adc, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1,
                                         DATA_TYPE src3)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src2 = dst - src1 - src3;

    cf = (src3 ? dst <= src1 : dst < src1);
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & 0x10;
    zf = (dst == 0) << 6;
    sf = lshift(dst, 8 - DATA_BITS) & 0x80;
    of = lshift((src1 ^ src2 ^ -1) & (src1 ^ dst), 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_sub, SUFFIX)(DATA_TYPE dst, DATA_TYPE src2)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src1 = dst + src2;

    cf = src1 < src2;
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & CC_A;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = lshift((src1 ^ src2) & (src1 ^ dst), 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_sbb, SUFFIX)(DATA_TYPE dst, DATA_TYPE src2,
                                         DATA_TYPE src3)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src1 = dst + src2 + src3;

    cf = (src3 ? src1 <= src2 : src1 < src2);
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & 0x10;
    zf = (dst == 0) << 6;
    sf = lshift(dst, 8 - DATA_BITS) & 0x80;
    of = lshift((src1 ^ src2) & (src1 ^ dst), 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_logic, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    cf = 0;
    pf = parity_table[(uint8_t)dst];
    af = 0;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = 0;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_inc, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src2;

    cf = src1;
    src1 = dst - 1;
    src2 = 1;
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & CC_A;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = (dst == SIGN_MASK) * CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_dec, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src2;

    cf = src1;
    src1 = dst + 1;
    src2 = 1;
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & CC_A;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = (dst == SIGN_MASK - 1) * CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_shl, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    cf = (src1 >> (DATA_BITS - 1)) & CC_C;
    pf = parity_table[(uint8_t)dst];
    af = 0; /* undefined */
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    /* of is defined iff shift count == 1 */
    of = lshift(src1 ^ dst, 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_sar, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    cf = src1 & 1;
    pf = parity_table[(uint8_t)dst];
    af = 0; /* undefined */
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    /* of is defined iff shift count == 1 */
    of = lshift(src1 ^ dst, 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_mul, SUFFIX)(DATA_TYPE dst, target_long src1)
{
    int cf, pf, af, zf, sf, of;

    cf = (src1 != 0);
    pf = parity_table[(uint8_t)dst];
    af = 0; /* undefined */
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = cf * CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_bmilg, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    cf = (src1 == 0);
    pf = 0; /* undefined */
    af = 0; /* undefined */
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = 0;
    return cf | pf | af | zf | sf | of;
}

static target_ulong compute_all_adcx(target_ulong dst, target_ulong src1,
                                     target_ulong src2)
{
    return (src1 & ~CC_C) | (dst * CC_C);
}

static target_ulong compute_all_adox(target_ulong dst, target_ulong src1,
                                     target_ulong src2)
{
    return (src1 & ~CC_O) | (src2 * CC_O);
}

static target_ulong compute_all_adcox(target_ulong dst, target_ulong src1,
                                      target_ulong src2)
{
    return (src1 & ~(CC_C | CC_O)) | (dst * CC_C) | (src2 * CC_O);
}

target_ulong helper_cc_compute_all(target_ulong dst, target_ulong src1,
                                   target_ulong src2, int op)
{
    switch (op) {
    default: /* should never happen */
        return 0;

    case CC_OP_EFLAGS:
        return src1;
    case CC_OP_CLR:
        return CC_Z | CC_P;
    case CC_OP_POPCNT:
        return src1 ? 0 : CC_Z;

    case CC_OP_MULB:
        return compute_all_mulb(dst, src1);
    case CC_OP_MULW:
        return compute_all_mulw(dst, src1);
    case CC_OP_MULL:
        return compute_all_mull(dst, src1);

    case CC_OP_ADDB:
        return compute_all_addb(dst, src1);
    case CC_OP_ADDW:
        return compute_all_addw(dst, src1);
    case CC_OP_ADDL:
        return compute_all_addl(dst, src1);

    case CC_OP_ADCB:
        return compute_all_adcb(dst, src1, src2);
    case CC_OP_ADCW:
        return compute_all_adcw(dst, src1, src2);
    case CC_OP_ADCL:
        return compute_all_adcl(dst, src1, src2);

    case CC_OP_SUBB:
        return compute_all_subb(dst, src1);
    case CC_OP_SUBW:
        return compute_all_subw(dst, src1);
    case CC_OP_SUBL:
        return compute_all_subl(dst, src1);

    case CC_OP_SBBB:
        return compute_all_sbbb(dst, src1, src2);
    case CC_OP_SBBW:
        return compute_all_sbbw(dst, src1, src2);
    case CC_OP_SBBL:
        return compute_all_sbbl(dst, src1, src2);

    case CC_OP_LOGICB:
        return compute_all_logicb(dst, src1);
    case CC_OP_LOGICW:
        return compute_all_logicw(dst, src1);
    case CC_OP_LOGICL:
        return compute_all_logicl(dst, src1);

    case CC_OP_INCB:
        return compute_all_incb(dst, src1);
    case CC_OP_INCW:
        return compute_all_incw(dst, src1);
    case CC_OP_INCL:
        return compute_all_incl(dst, src1);

    case CC_OP_DECB:
        return compute_all_decb(dst, src1);
    case CC_OP_DECW:
        return compute_all_decw(dst, src1);
    case CC_OP_DECL:
        return compute_all_decl(dst, src1);

    case CC_OP_SHLB:
        return compute_all_shlb(dst, src1);
    case CC_OP_SHLW:
        return compute_all_shlw(dst, src1);
    case CC_OP_SHLL:
        return compute_all_shll(dst, src1);

    case CC_OP_SARB:
        return compute_all_sarb(dst, src1);
    case CC_OP_SARW:
        return compute_all_sarw(dst, src1);
    case CC_OP_SARL:
        return compute_all_sarl(dst, src1);

    case CC_OP_BMILGB:
        return compute_all_bmilgb(dst, src1);
    case CC_OP_BMILGW:
        return compute_all_bmilgw(dst, src1);
    case CC_OP_BMILGL:
        return compute_all_bmilgl(dst, src1);

    case CC_OP_ADCX:
        return compute_all_adcx(dst, src1, src2);
    case CC_OP_ADOX:
        return compute_all_adox(dst, src1, src2);
    case CC_OP_ADCOX:
        return compute_all_adcox(dst, src1, src2);

#ifdef TARGET_X86_64
    case CC_OP_MULQ:
        return compute_all_mulq(dst, src1);
    case CC_OP_ADDQ:
        return compute_all_addq(dst, src1);
    case CC_OP_ADCQ:
        return compute_all_adcq(dst, src1, src2);
    case CC_OP_SUBQ:
        return compute_all_subq(dst, src1);
    case CC_OP_SBBQ:
        return compute_all_sbbq(dst, src1, src2);
    case CC_OP_LOGICQ:
        return compute_all_logicq(dst, src1);
    case CC_OP_INCQ:
        return compute_all_incq(dst, src1);
    case CC_OP_DECQ:
        return compute_all_decq(dst, src1);
    case CC_OP_SHLQ:
        return compute_all_shlq(dst, src1);
    case CC_OP_SARQ:
        return compute_all_sarq(dst, src1);
    case CC_OP_BMILGQ:
        return compute_all_bmilgq(dst, src1);
#endif
    }
}

uint32_t cpu_cc_compute_all(CPUX86State *env, int op)
{
    return helper_cc_compute_all(CC_DST, CC_SRC, CC_SRC2, op);
}

target_ulong helper_read_eflags(CPUX86State *env)
{
    uint32_t eflags;

    eflags = cpu_cc_compute_all(env, CC_OP);
    eflags |= (env->df & DF_MASK);
    eflags |= env->eflags & ~(VM_MASK | RF_MASK);
    return eflags;
}

