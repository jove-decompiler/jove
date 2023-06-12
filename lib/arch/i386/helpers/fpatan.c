#define HOST_BIG_ENDIAN (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)

#define QEMU_ALIGNED(X) __attribute__((aligned(X)))

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

typedef struct Int128 Int128;

struct Int128 {
#if HOST_BIG_ENDIAN
    int64_t hi;
    uint64_t lo;
#else
    uint64_t lo;
    int64_t hi;
#endif
};

static inline int clz128(Int128 a)
{
    if (a.hi) {
        return __builtin_clzll(a.hi);
    } else {
        return (a.lo) ? __builtin_clzll(a.lo) + 64 : 128;
    }
}

void mulu64(uint64_t *plow, uint64_t *phigh, uint64_t a, uint64_t b);

static inline int clz8(uint8_t val)
{
    return val ? __builtin_clz(val) - 24 : 8;
}

static inline int clz32(uint32_t val)
{
    return val ? __builtin_clz(val) : 32;
}

static inline int clz64(uint64_t val)
{
    return val ? __builtin_clzll(val) : 64;
}

static inline uint64_t uadd64_carry(uint64_t x, uint64_t y, bool *pcarry)
{
#if __has_builtin(__builtin_addcll)
    unsigned long long c = *pcarry;
    x = __builtin_addcll(x, y, c, &c);
    *pcarry = c & 1;
    return x;
#else
    bool c = *pcarry;
    /* This is clang's internal expansion of __builtin_addc. */
    c = uadd64_overflow(x, c, &x);
    c |= uadd64_overflow(x, y, &x);
    *pcarry = c;
    return x;
#endif
}

static inline uint64_t usub64_borrow(uint64_t x, uint64_t y, bool *pborrow)
{
#if __has_builtin(__builtin_subcll)
    unsigned long long b = *pborrow;
    x = __builtin_subcll(x, y, b, &b);
    *pborrow = b & 1;
    return x;
#else
    bool b = *pborrow;
    b = usub64_overflow(x, b, &x);
    b |= usub64_overflow(x, y, &x);
    *pborrow = b;
    return x;
#endif
}

typedef uint64_t vaddr;

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
    /*
     * Bus interconnect and peripherals can access anything (memories,
     * devices) by default. By setting the 'memory' bit, bus transaction
     * are restricted to "normal" memories (per the AMBA documentation)
     * versus devices. Access to devices will be logged and rejected
     * (see MEMTX_ACCESS_ERROR).
     */
    unsigned int memory:1;
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

#define HV_SINT_COUNT                         16

#define HV_X64_MSR_CRASH_P0                     0x40000100

#define HV_X64_MSR_CRASH_P4                     0x40000104

#define HV_CRASH_PARAMS    (HV_X64_MSR_CRASH_P4 - HV_X64_MSR_CRASH_P0 + 1)

#define HV_STIMER_COUNT                       4

typedef uint32_t target_ulong;

typedef uint16_t float16;

typedef uint32_t float32;

typedef uint64_t float64;

#define make_floatx80(exp, mant) ((floatx80) { mant, exp })

#define make_floatx80_init(exp, mant) { .low = mant, .high = exp }

typedef struct {
    uint64_t low;
    uint16_t high;
} floatx80;

typedef enum __attribute__((__packed__)) {
    float_round_nearest_even = 0,
    float_round_down         = 1,
    float_round_up           = 2,
    float_round_to_zero      = 3,
    float_round_ties_away    = 4,
    /* Not an IEEE rounding mode: round to closest odd, overflow to max */
    float_round_to_odd       = 5,
    /* Not an IEEE rounding mode: round to closest odd, overflow to inf */
    float_round_to_odd_inf   = 6,
} FloatRoundMode;

enum {
    float_flag_invalid         = 0x0001,
    float_flag_divbyzero       = 0x0002,
    float_flag_overflow        = 0x0004,
    float_flag_underflow       = 0x0008,
    float_flag_inexact         = 0x0010,
    float_flag_input_denormal  = 0x0020,
    float_flag_output_denormal = 0x0040,
    float_flag_invalid_isi     = 0x0080,  /* inf - inf */
    float_flag_invalid_imz     = 0x0100,  /* inf * 0 */
    float_flag_invalid_idi     = 0x0200,  /* inf / inf */
    float_flag_invalid_zdz     = 0x0400,  /* 0 / 0 */
    float_flag_invalid_sqrt    = 0x0800,  /* sqrt(-x) */
    float_flag_invalid_cvti    = 0x1000,  /* non-nan to integer */
    float_flag_invalid_snan    = 0x2000,  /* any operand was snan */
};

typedef enum __attribute__((__packed__)) {
    floatx80_precision_x,
    floatx80_precision_d,
    floatx80_precision_s,
} FloatX80RoundPrec;

typedef struct float_status {
    uint16_t float_exception_flags;
    FloatRoundMode float_rounding_mode;
    FloatX80RoundPrec floatx80_rounding_precision;
    bool tininess_before_rounding;
    /* should denormalised results go to zero and set the inexact flag? */
    bool flush_to_zero;
    /* should denormalised inputs go to zero and set the input_denormal flag? */
    bool flush_inputs_to_zero;
    bool default_nan_mode;
    /*
     * The flags below are not used on all specializations and may
     * constant fold away (see snan_bit_is_one()/no_signalling_nans() in
     * softfloat-specialize.inc.c)
     */
    bool snan_bit_is_one;
    bool use_first_nan;
    bool no_signaling_nans;
    /* should overflowed results subtract re_bias to its exponent? */
    bool rebias_overflow;
    /* should underflowed results add re_bias to its exponent? */
    bool rebias_underflow;
} float_status;

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
    FEAT_8000_0021_EAX, /* CPUID[8000_0021].EAX */
    FEAT_C000_0001_EDX, /* CPUID[C000_0001].EDX */
    FEAT_KVM,           /* CPUID[4000_0001].EAX (KVM_CPUID_FEATURES) */
    FEAT_KVM_HINTS,     /* CPUID[4000_0001].EDX */
    FEAT_SVM,           /* CPUID[8000_000A].EDX */
    FEAT_XSAVE,         /* CPUID[EAX=0xd,ECX=1].EAX */
    FEAT_6_EAX,         /* CPUID[6].EAX */
    FEAT_XSAVE_XCR0_LO, /* CPUID[EAX=0xd,ECX=0].EAX */
    FEAT_XSAVE_XCR0_HI, /* CPUID[EAX=0xd,ECX=0].EDX */
    FEAT_ARCH_CAPABILITIES,
    FEAT_CORE_CAPABILITY,
    FEAT_PERF_CAPABILITIES,
    FEAT_VMX_PROCBASED_CTLS,
    FEAT_VMX_SECONDARY_CTLS,
    FEAT_VMX_PINBASED_CTLS,
    FEAT_VMX_EXIT_CTLS,
    FEAT_VMX_ENTRY_CTLS,
    FEAT_VMX_MISC,
    FEAT_VMX_EPT_VPID_CAPS,
    FEAT_VMX_BASIC,
    FEAT_VMX_VMFUNC,
    FEAT_14_0_ECX,
    FEAT_SGX_12_0_EAX,  /* CPUID[EAX=0x12,ECX=0].EAX (SGX) */
    FEAT_SGX_12_0_EBX,  /* CPUID[EAX=0x12,ECX=0].EBX (SGX MISCSELECT[31:0]) */
    FEAT_SGX_12_1_EAX,  /* CPUID[EAX=0x12,ECX=1].EAX (SGX ATTRIBUTES[31:0]) */
    FEAT_XSAVE_XSS_LO,     /* CPUID[EAX=0xd,ECX=1].ECX */
    FEAT_XSAVE_XSS_HI,     /* CPUID[EAX=0xd,ECX=1].EDX */
    FEAT_7_1_EDX,       /* CPUID[EAX=7,ECX=1].EDX */
    FEATURE_WORDS,
} FeatureWord;

typedef uint64_t FeatureWordArray[FEATURE_WORDS];

typedef struct SegmentCache {
    uint32_t selector;
    target_ulong base;
    uint32_t limit;
    uint32_t flags;
} SegmentCache;

typedef union MMXReg {
    uint8_t  _b_MMXReg[64 / 8];
    uint16_t _w_MMXReg[64 / 16];
    uint32_t _l_MMXReg[64 / 32];
    uint64_t _q_MMXReg[64 / 64];
    float32  _s_MMXReg[64 / 32];
    float64  _d_MMXReg[64 / 64];
} MMXReg;

typedef union XMMReg {
    uint64_t _q_XMMReg[128 / 64];
} XMMReg;

typedef union YMMReg {
    uint64_t _q_YMMReg[256 / 64];
    XMMReg   _x_YMMReg[256 / 128];
} YMMReg;

typedef union ZMMReg {
    uint8_t  _b_ZMMReg[512 / 8];
    uint16_t _w_ZMMReg[512 / 16];
    uint32_t _l_ZMMReg[512 / 32];
    uint64_t _q_ZMMReg[512 / 64];
    float16  _h_ZMMReg[512 / 16];
    float32  _s_ZMMReg[512 / 32];
    float64  _d_ZMMReg[512 / 64];
    XMMReg   _x_ZMMReg[512 / 128];
    YMMReg   _y_ZMMReg[512 / 256];
} ZMMReg;

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

#define CPU_NB_REGS32 8

#define CPU_NB_REGS CPU_NB_REGS32

#define MAX_FIXED_COUNTERS 3

#define MAX_GP_COUNTERS    (MSR_IA32_PERF_STATUS - MSR_P6_EVNTSEL0)

#define NB_OPMASK_REGS 8

typedef struct {
    uint64_t base;
    uint64_t mask;
} MTRRVar;

#define ARCH_LBR_NR_ENTRIES            32

typedef struct {
       uint64_t from;
       uint64_t to;
       uint64_t info;
} LBREntry;

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

typedef struct CPUArchState {
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

    bool pdptrs_valid;
    uint64_t pdptrs[4];
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
    uint16_t fpcs;
    uint16_t fpds;
    uint64_t fpip;
    uint64_t fpdp;

    /* emulator internal variables */
    float_status fp_status;
    floatx80 ft0;

    float_status mmx_status; /* for 3DNow! float ops */
    float_status sse_status;
    uint32_t mxcsr;
    ZMMReg xmm_regs[CPU_NB_REGS == 8 ? 8 : 32] QEMU_ALIGNED(16);
    ZMMReg xmm_t0 QEMU_ALIGNED(16);
    MMXReg mmx_t0;

    uint64_t opmask_regs[NB_OPMASK_REGS];
#ifdef TARGET_X86_64
    uint8_t xtilecfg[64];
    uint8_t xtiledata[8192];
#endif

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

    uint64_t tsc_adjust;
    uint64_t tsc_deadline;
    uint64_t tsc_aux;

    uint64_t xcr0;

    uint64_t mcg_status;
    uint64_t msr_ia32_misc_enable;
    uint64_t msr_ia32_feature_control;
    uint64_t msr_ia32_sgxlepubkeyhash[4];

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
    uint32_t pkrs;
    uint32_t tsx_ctrl;

    uint64_t spec_ctrl;
    uint64_t amd_tsc_scale_msr;
    uint64_t virt_ssbd;

    /* End of state preserved by INIT (dummy marker).  */
    struct {} end_init_save;

    uint64_t system_time_msr;
    uint64_t wall_clock_msr;
    uint64_t steal_time_msr;
    uint64_t async_pf_en_msr;
    uint64_t async_pf_int_msr;
    uint64_t pv_eoi_en_msr;
    uint64_t poll_control_msr;

    /* Partition-wide HV MSRs, will be updated only on the first vcpu */
    uint64_t msr_hv_hypercall;
    uint64_t msr_hv_guest_os_id;
    uint64_t msr_hv_tsc;
    uint64_t msr_hv_syndbg_control;
    uint64_t msr_hv_syndbg_status;
    uint64_t msr_hv_syndbg_send_page;
    uint64_t msr_hv_syndbg_recv_page;
    uint64_t msr_hv_syndbg_pending_page;
    uint64_t msr_hv_syndbg_options;

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

    /* Per-VCPU XFD MSRs */
    uint64_t msr_xfd;
    uint64_t msr_xfd_err;

    /* Per-VCPU Arch LBR MSRs */
    uint64_t msr_lbr_ctl;
    uint64_t msr_lbr_depth;
    LBREntry lbr_records[ARCH_LBR_NR_ENTRIES];

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
    uint32_t int_ctl;

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
    uint8_t triple_fault_pending;
    uint32_t ins_len;
    uint32_t sipi_vector;
    bool tsc_valid;
    int64_t tsc_khz;
    int64_t user_tsc_khz; /* for sanity check only */
    uint64_t apic_bus_freq;
    uint64_t tsc;
#if defined(CONFIG_KVM) || defined(CONFIG_HVF)
    void *xsave_buf;
    uint32_t xsave_buf_len;
#endif
#if defined(CONFIG_KVM)
    struct kvm_nested_state *nested_state;
    MemoryRegion *xen_vcpu_info_mr;
    void *xen_vcpu_info_hva;
    uint64_t xen_vcpu_info_gpa;
    uint64_t xen_vcpu_info_default_gpa;
    uint64_t xen_vcpu_time_info_gpa;
    uint64_t xen_vcpu_runstate_gpa;
    uint8_t xen_vcpu_callback_vector;
    bool xen_callback_asserted;
    uint16_t xen_virq[XEN_NR_VIRQS];
    uint64_t xen_singleshot_timer_ns;
    QEMUTimer *xen_singleshot_timer;
    uint64_t xen_periodic_timer_period;
    QEMUTimer *xen_periodic_timer;
    QemuMutex xen_timers_lock;
#endif
#if defined(CONFIG_HVF)
    HVFX86LazyFlags hvf_lflags;
    void *hvf_mmio_buf;
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

static inline void set_float_exception_flags(int val, float_status *status)
{
    status->float_exception_flags = val;
}

static inline int get_float_exception_flags(float_status *status)
{
    return status->float_exception_flags;
}

static inline void float_raise(uint16_t flags, float_status *status)
{
    status->float_exception_flags |= flags;
}

int32_t floatx80_to_int32(floatx80, float_status *status);

extern const floatx80 floatx80_infinity;

floatx80 floatx80_add(floatx80, floatx80, float_status *status);

floatx80 floatx80_mul(floatx80, floatx80, float_status *status);

floatx80 floatx80_div(floatx80, floatx80, float_status *status);

int floatx80_is_signaling_nan(floatx80, float_status *status);

floatx80 floatx80_silence_nan(floatx80, float_status *status);

static inline bool floatx80_is_infinity(floatx80 a)
{
#if defined(TARGET_M68K)
    return (a.high & 0x7fff) == floatx80_infinity.high && !(a.low << 1);
#else
    return (a.high & 0x7fff) == floatx80_infinity.high &&
                       a.low == floatx80_infinity.low;
#endif
}

static inline bool floatx80_is_zero(floatx80 a)
{
    return (a.high & 0x7fff) == 0 && a.low == 0;
}

static inline bool floatx80_is_any_nan(floatx80 a)
{
    return ((a.high & 0x7fff) == 0x7fff) && (a.low<<1);
}

#define floatx80_zero_init make_floatx80_init(0x0000, 0x0000000000000000LL)

static inline bool floatx80_invalid_encoding(floatx80 a)
{
#if defined(TARGET_M68K)
    /*-------------------------------------------------------------------------
    | With m68k, the explicit integer bit can be zero in the case of:
    | - zeros                (exp == 0, mantissa == 0)
    | - denormalized numbers (exp == 0, mantissa != 0)
    | - unnormalized numbers (exp != 0, exp < 0x7FFF)
    | - infinities           (exp == 0x7FFF, mantissa == 0)
    | - not-a-numbers        (exp == 0x7FFF, mantissa != 0)
    |
    | For infinities and NaNs, the explicit integer bit can be either one or
    | zero.
    |
    | The IEEE 754 standard does not define a zero integer bit. Such a number
    | is an unnormalized number. Hardware does not directly support
    | denormalized and unnormalized numbers, but implicitly supports them by
    | trapping them as unimplemented data types, allowing efficient conversion
    | in software.
    |
    | See "M68000 FAMILY PROGRAMMER’S REFERENCE MANUAL",
    |     "1.6 FLOATING-POINT DATA TYPES"
    *------------------------------------------------------------------------*/
    return false;
#else
    return (a.low & (1ULL << 63)) == 0 && (a.high & 0x7FFF) != 0;
#endif
}

static inline uint64_t extractFloatx80Frac(floatx80 a)
{
    return a.low;
}

static inline int32_t extractFloatx80Exp(floatx80 a)
{
    return a.high & 0x7FFF;
}

static inline bool extractFloatx80Sign(floatx80 a)
{
    return a.high >> 15;
}

void normalizeFloatx80Subnormal(uint64_t aSig, int32_t *zExpPtr,
                                uint64_t *zSigPtr);

floatx80 normalizeRoundAndPackFloatx80(FloatX80RoundPrec roundingPrecision,
                                       bool zSign, int32_t zExp,
                                       uint64_t zSig0, uint64_t zSig1,
                                       float_status *status);

floatx80 floatx80_default_nan(float_status *status);

static inline void
 shift128Right(
     uint64_t a0, uint64_t a1, int count, uint64_t *z0Ptr, uint64_t *z1Ptr)
{
    uint64_t z0, z1;
    int8_t negCount = ( - count ) & 63;

    if ( count == 0 ) {
        z1 = a1;
        z0 = a0;
    }
    else if ( count < 64 ) {
        z1 = ( a0<<negCount ) | ( a1>>count );
        z0 = a0>>count;
    }
    else {
        z1 = (count < 128) ? (a0 >> (count & 63)) : 0;
        z0 = 0;
    }
    *z1Ptr = z1;
    *z0Ptr = z0;

}

static inline void
 shift128RightJamming(
     uint64_t a0, uint64_t a1, int count, uint64_t *z0Ptr, uint64_t *z1Ptr)
{
    uint64_t z0, z1;
    int8_t negCount = ( - count ) & 63;

    if ( count == 0 ) {
        z1 = a1;
        z0 = a0;
    }
    else if ( count < 64 ) {
        z1 = ( a0<<negCount ) | ( a1>>count ) | ( ( a1<<negCount ) != 0 );
        z0 = a0>>count;
    }
    else {
        if ( count == 64 ) {
            z1 = a0 | ( a1 != 0 );
        }
        else if ( count < 128 ) {
            z1 = ( a0>>( count & 63 ) ) | ( ( ( a0<<negCount ) | a1 ) != 0 );
        }
        else {
            z1 = ( ( a0 | a1 ) != 0 );
        }
        z0 = 0;
    }
    *z1Ptr = z1;
    *z0Ptr = z0;

}

static inline void shift128Left(uint64_t a0, uint64_t a1, int count,
                                uint64_t *z0Ptr, uint64_t *z1Ptr)
{
    if (count < 64) {
        *z1Ptr = a1 << count;
        *z0Ptr = count == 0 ? a0 : (a0 << count) | (a1 >> (-count & 63));
    } else {
        *z1Ptr = 0;
        *z0Ptr = a1 << (count - 64);
    }
}

static inline void add128(uint64_t a0, uint64_t a1, uint64_t b0, uint64_t b1,
                          uint64_t *z0Ptr, uint64_t *z1Ptr)
{
    bool c = 0;
    *z1Ptr = uadd64_carry(a1, b1, &c);
    *z0Ptr = uadd64_carry(a0, b0, &c);
}

static inline void add192(uint64_t a0, uint64_t a1, uint64_t a2,
                          uint64_t b0, uint64_t b1, uint64_t b2,
                          uint64_t *z0Ptr, uint64_t *z1Ptr, uint64_t *z2Ptr)
{
    bool c = 0;
    *z2Ptr = uadd64_carry(a2, b2, &c);
    *z1Ptr = uadd64_carry(a1, b1, &c);
    *z0Ptr = uadd64_carry(a0, b0, &c);
}

static inline void sub128(uint64_t a0, uint64_t a1, uint64_t b0, uint64_t b1,
                          uint64_t *z0Ptr, uint64_t *z1Ptr)
{
    bool c = 0;
    *z1Ptr = usub64_borrow(a1, b1, &c);
    *z0Ptr = usub64_borrow(a0, b0, &c);
}

static inline void sub192(uint64_t a0, uint64_t a1, uint64_t a2,
                          uint64_t b0, uint64_t b1, uint64_t b2,
                          uint64_t *z0Ptr, uint64_t *z1Ptr, uint64_t *z2Ptr)
{
    bool c = 0;
    *z2Ptr = usub64_borrow(a2, b2, &c);
    *z1Ptr = usub64_borrow(a1, b1, &c);
    *z0Ptr = usub64_borrow(a0, b0, &c);
}

static inline void
mul64To128(uint64_t a, uint64_t b, uint64_t *z0Ptr, uint64_t *z1Ptr)
{
    mulu64(z1Ptr, z0Ptr, a, b);
}

static inline void
mul128By64To192(uint64_t a0, uint64_t a1, uint64_t b,
                uint64_t *z0Ptr, uint64_t *z1Ptr, uint64_t *z2Ptr)
{
    uint64_t z0, z1, m1;

    mul64To128(a1, b, &m1, z2Ptr);
    mul64To128(a0, b, &z0, &z1);
    add128(z0, z1, 0, m1, z0Ptr, z1Ptr);
}

static inline void mul128To256(uint64_t a0, uint64_t a1,
                               uint64_t b0, uint64_t b1,
                               uint64_t *z0Ptr, uint64_t *z1Ptr,
                               uint64_t *z2Ptr, uint64_t *z3Ptr)
{
    uint64_t z0, z1, z2;
    uint64_t m0, m1, m2, n1, n2;

    mul64To128(a1, b0, &m1, &m2);
    mul64To128(a0, b1, &n1, &n2);
    mul64To128(a1, b1, &z2, z3Ptr);
    mul64To128(a0, b0, &z0, &z1);

    add192( 0, m1, m2,  0, n1, n2, &m0, &m1, &m2);
    add192(m0, m1, m2, z0, z1, z2, z0Ptr, z1Ptr, z2Ptr);
}

static inline uint64_t estimateDiv128To64(uint64_t a0, uint64_t a1, uint64_t b)
{
    uint64_t b0, b1;
    uint64_t rem0, rem1, term0, term1;
    uint64_t z;

    if ( b <= a0 ) return UINT64_C(0xFFFFFFFFFFFFFFFF);
    b0 = b>>32;
    z = ( b0<<32 <= a0 ) ? UINT64_C(0xFFFFFFFF00000000) : ( a0 / b0 )<<32;
    mul64To128( b, z, &term0, &term1 );
    sub128( a0, a1, term0, term1, &rem0, &rem1 );
    while ( ( (int64_t) rem0 ) < 0 ) {
        z -= UINT64_C(0x100000000);
        b1 = b<<32;
        add128( rem0, rem1, b0, b1, &rem0, &rem1 );
    }
    rem0 = ( rem0<<32 ) | ( rem1>>32 );
    z |= ( b0<<32 <= rem0 ) ? 0xFFFFFFFF : rem0 / b0;
    return z;

}

#define ST0    (env->fpregs[env->fpstt].d)

#define ST(n)  (env->fpregs[(env->fpstt + (n)) & 7].d)

#define ST1    ST(1)

#define FPUS_IE (1 << 0)

#define FPUS_DE (1 << 1)

#define FPUS_ZE (1 << 2)

#define FPUS_OE (1 << 3)

#define FPUS_UE (1 << 4)

#define FPUS_PE (1 << 5)

#define FPUS_SE (1 << 7)

#define FPUS_B  (1 << 15)

#define FPUC_EM 0x3f

static inline void fpop(CPUX86State *env)
{
    env->fptags[env->fpstt] = 1; /* invalidate stack entry */
    env->fpstt = (env->fpstt + 1) & 7;
}

static void fpu_set_exception(CPUX86State *env, int mask)
{
    env->fpus |= mask;
    if (env->fpus & (~env->fpuc & FPUC_EM)) {
        env->fpus |= FPUS_SE | FPUS_B;
    }
}

static inline uint8_t save_exception_flags(CPUX86State *env)
{
    uint8_t old_flags = get_float_exception_flags(&env->fp_status);
    set_float_exception_flags(0, &env->fp_status);
    return old_flags;
}

static void merge_exception_flags(CPUX86State *env, uint8_t old_flags)
{
    uint8_t new_flags = get_float_exception_flags(&env->fp_status);
    float_raise(old_flags, &env->fp_status);
    fpu_set_exception(env,
                      ((new_flags & float_flag_invalid ? FPUS_IE : 0) |
                       (new_flags & float_flag_divbyzero ? FPUS_ZE : 0) |
                       (new_flags & float_flag_overflow ? FPUS_OE : 0) |
                       (new_flags & float_flag_underflow ? FPUS_UE : 0) |
                       (new_flags & float_flag_inexact ? FPUS_PE : 0) |
                       (new_flags & float_flag_input_denormal ? FPUS_DE : 0)));
}

#define pi_4_exp 0x3ffe

#define pi_4_sig_high 0xc90fdaa22168c234ULL

#define pi_4_sig_low 0xc4c6628b80dc1cd1ULL

#define pi_2_exp 0x3fff

#define pi_2_sig_high 0xc90fdaa22168c234ULL

#define pi_2_sig_low 0xc4c6628b80dc1cd1ULL

#define pi_34_exp 0x4000

#define pi_34_sig_high 0x96cbe3f9990e91a7ULL

#define pi_34_sig_low 0x9394c9e8a0a5159dULL

#define pi_exp 0x4000

#define pi_sig_high 0xc90fdaa22168c234ULL

#define pi_sig_low 0xc4c6628b80dc1cd1ULL

#define fpatan_coeff_0 make_floatx80(0x3fff, 0x8000000000000000ULL)

#define fpatan_coeff_1 make_floatx80(0xbffd, 0xaaaaaaaaaaaaaa43ULL)

#define fpatan_coeff_2 make_floatx80(0x3ffc, 0xccccccccccbfe4f8ULL)

#define fpatan_coeff_3 make_floatx80(0xbffc, 0x92492491fbab2e66ULL)

#define fpatan_coeff_4 make_floatx80(0x3ffb, 0xe38e372881ea1e0bULL)

#define fpatan_coeff_5 make_floatx80(0xbffb, 0xba2c0104bbdd0615ULL)

#define fpatan_coeff_6 make_floatx80(0x3ffb, 0x9baf7ebf898b42efULL)

struct fpatan_data {
    /* High and low parts of atan(x).  */
    floatx80 atan_high, atan_low;
};

static const struct fpatan_data fpatan_table[9] = {
    { floatx80_zero_init,
      floatx80_zero_init },
    { make_floatx80_init(0x3ffb, 0xfeadd4d5617b6e33ULL),
      make_floatx80_init(0xbfb9, 0xdda19d8305ddc420ULL) },
    { make_floatx80_init(0x3ffc, 0xfadbafc96406eb15ULL),
      make_floatx80_init(0x3fbb, 0xdb8f3debef442fccULL) },
    { make_floatx80_init(0x3ffd, 0xb7b0ca0f26f78474ULL),
      make_floatx80_init(0xbfbc, 0xeab9bdba460376faULL) },
    { make_floatx80_init(0x3ffd, 0xed63382b0dda7b45ULL),
      make_floatx80_init(0x3fbc, 0xdfc88bd978751a06ULL) },
    { make_floatx80_init(0x3ffe, 0x8f005d5ef7f59f9bULL),
      make_floatx80_init(0x3fbd, 0xb906bc2ccb886e90ULL) },
    { make_floatx80_init(0x3ffe, 0xa4bc7d1934f70924ULL),
      make_floatx80_init(0x3fbb, 0xcd43f9522bed64f8ULL) },
    { make_floatx80_init(0x3ffe, 0xb8053e2bc2319e74ULL),
      make_floatx80_init(0xbfbc, 0xd3496ab7bd6eef0cULL) },
    { make_floatx80_init(0x3ffe, 0xc90fdaa22168c235ULL),
      make_floatx80_init(0xbfbc, 0xece675d1fc8f8cbcULL) },
};

void helper_fpatan(CPUX86State *env)
{
    uint8_t old_flags = save_exception_flags(env);
    uint64_t arg0_sig = extractFloatx80Frac(ST0);
    int32_t arg0_exp = extractFloatx80Exp(ST0);
    bool arg0_sign = extractFloatx80Sign(ST0);
    uint64_t arg1_sig = extractFloatx80Frac(ST1);
    int32_t arg1_exp = extractFloatx80Exp(ST1);
    bool arg1_sign = extractFloatx80Sign(ST1);

    if (floatx80_is_signaling_nan(ST0, &env->fp_status)) {
        float_raise(float_flag_invalid, &env->fp_status);
        ST1 = floatx80_silence_nan(ST0, &env->fp_status);
    } else if (floatx80_is_signaling_nan(ST1, &env->fp_status)) {
        float_raise(float_flag_invalid, &env->fp_status);
        ST1 = floatx80_silence_nan(ST1, &env->fp_status);
    } else if (floatx80_invalid_encoding(ST0) ||
               floatx80_invalid_encoding(ST1)) {
        float_raise(float_flag_invalid, &env->fp_status);
        ST1 = floatx80_default_nan(&env->fp_status);
    } else if (floatx80_is_any_nan(ST0)) {
        ST1 = ST0;
    } else if (floatx80_is_any_nan(ST1)) {
        /* Pass this NaN through.  */
    } else if (floatx80_is_zero(ST1) && !arg0_sign) {
        /* Pass this zero through.  */
    } else if (((floatx80_is_infinity(ST0) && !floatx80_is_infinity(ST1)) ||
                 arg0_exp - arg1_exp >= 80) &&
               !arg0_sign) {
        /*
         * Dividing ST1 by ST0 gives the correct result up to
         * rounding, and avoids spurious underflow exceptions that
         * might result from passing some small values through the
         * polynomial approximation, but if a finite nonzero result of
         * division is exact, the result of fpatan is still inexact
         * (and underflowing where appropriate).
         */
        FloatX80RoundPrec save_prec =
            env->fp_status.floatx80_rounding_precision;
        env->fp_status.floatx80_rounding_precision = floatx80_precision_x;
        ST1 = floatx80_div(ST1, ST0, &env->fp_status);
        env->fp_status.floatx80_rounding_precision = save_prec;
        if (!floatx80_is_zero(ST1) &&
            !(get_float_exception_flags(&env->fp_status) &
              float_flag_inexact)) {
            /*
             * The mathematical result is very slightly closer to zero
             * than this exact result.  Round a value with the
             * significand adjusted accordingly to get the correct
             * exceptions, and possibly an adjusted result depending
             * on the rounding mode.
             */
            uint64_t sig = extractFloatx80Frac(ST1);
            int32_t exp = extractFloatx80Exp(ST1);
            bool sign = extractFloatx80Sign(ST1);
            if (exp == 0) {
                normalizeFloatx80Subnormal(sig, &exp, &sig);
            }
            ST1 = normalizeRoundAndPackFloatx80(floatx80_precision_x,
                                                sign, exp, sig - 1,
                                                -1, &env->fp_status);
        }
    } else {
        /* The result is inexact.  */
        bool rsign = arg1_sign;
        int32_t rexp;
        uint64_t rsig0, rsig1;
        if (floatx80_is_zero(ST1)) {
            /*
             * ST0 is negative.  The result is pi with the sign of
             * ST1.
             */
            rexp = pi_exp;
            rsig0 = pi_sig_high;
            rsig1 = pi_sig_low;
        } else if (floatx80_is_infinity(ST1)) {
            if (floatx80_is_infinity(ST0)) {
                if (arg0_sign) {
                    rexp = pi_34_exp;
                    rsig0 = pi_34_sig_high;
                    rsig1 = pi_34_sig_low;
                } else {
                    rexp = pi_4_exp;
                    rsig0 = pi_4_sig_high;
                    rsig1 = pi_4_sig_low;
                }
            } else {
                rexp = pi_2_exp;
                rsig0 = pi_2_sig_high;
                rsig1 = pi_2_sig_low;
            }
        } else if (floatx80_is_zero(ST0) || arg1_exp - arg0_exp >= 80) {
            rexp = pi_2_exp;
            rsig0 = pi_2_sig_high;
            rsig1 = pi_2_sig_low;
        } else if (floatx80_is_infinity(ST0) || arg0_exp - arg1_exp >= 80) {
            /* ST0 is negative.  */
            rexp = pi_exp;
            rsig0 = pi_sig_high;
            rsig1 = pi_sig_low;
        } else {
            /*
             * ST0 and ST1 are finite, nonzero and with exponents not
             * too far apart.
             */
            int32_t adj_exp, num_exp, den_exp, xexp, yexp, n, texp, zexp, aexp;
            int32_t azexp, axexp;
            bool adj_sub, ysign, zsign;
            uint64_t adj_sig0, adj_sig1, num_sig, den_sig, xsig0, xsig1;
            uint64_t msig0, msig1, msig2, remsig0, remsig1, remsig2;
            uint64_t ysig0, ysig1, tsig, zsig0, zsig1, asig0, asig1;
            uint64_t azsig0, azsig1;
            uint64_t azsig2, azsig3, axsig0, axsig1;
            floatx80 x8;
            FloatRoundMode save_mode = env->fp_status.float_rounding_mode;
            FloatX80RoundPrec save_prec =
                env->fp_status.floatx80_rounding_precision;
            env->fp_status.float_rounding_mode = float_round_nearest_even;
            env->fp_status.floatx80_rounding_precision = floatx80_precision_x;

            if (arg0_exp == 0) {
                normalizeFloatx80Subnormal(arg0_sig, &arg0_exp, &arg0_sig);
            }
            if (arg1_exp == 0) {
                normalizeFloatx80Subnormal(arg1_sig, &arg1_exp, &arg1_sig);
            }
            if (arg0_exp > arg1_exp ||
                (arg0_exp == arg1_exp && arg0_sig >= arg1_sig)) {
                /* Work with abs(ST1) / abs(ST0).  */
                num_exp = arg1_exp;
                num_sig = arg1_sig;
                den_exp = arg0_exp;
                den_sig = arg0_sig;
                if (arg0_sign) {
                    /* The result is subtracted from pi.  */
                    adj_exp = pi_exp;
                    adj_sig0 = pi_sig_high;
                    adj_sig1 = pi_sig_low;
                    adj_sub = true;
                } else {
                    /* The result is used as-is.  */
                    adj_exp = 0;
                    adj_sig0 = 0;
                    adj_sig1 = 0;
                    adj_sub = false;
                }
            } else {
                /* Work with abs(ST0) / abs(ST1).  */
                num_exp = arg0_exp;
                num_sig = arg0_sig;
                den_exp = arg1_exp;
                den_sig = arg1_sig;
                /* The result is added to or subtracted from pi/2.  */
                adj_exp = pi_2_exp;
                adj_sig0 = pi_2_sig_high;
                adj_sig1 = pi_2_sig_low;
                adj_sub = !arg0_sign;
            }

            /*
             * Compute x = num/den, where 0 < x <= 1 and x is not too
             * small.
             */
            xexp = num_exp - den_exp + 0x3ffe;
            remsig0 = num_sig;
            remsig1 = 0;
            if (den_sig <= remsig0) {
                shift128Right(remsig0, remsig1, 1, &remsig0, &remsig1);
                ++xexp;
            }
            xsig0 = estimateDiv128To64(remsig0, remsig1, den_sig);
            mul64To128(den_sig, xsig0, &msig0, &msig1);
            sub128(remsig0, remsig1, msig0, msig1, &remsig0, &remsig1);
            while ((int64_t) remsig0 < 0) {
                --xsig0;
                add128(remsig0, remsig1, 0, den_sig, &remsig0, &remsig1);
            }
            xsig1 = estimateDiv128To64(remsig1, 0, den_sig);
            /*
             * No need to correct any estimation error in xsig1; even
             * with such error, it is accurate enough.
             */

            /*
             * Split x as x = t + y, where t = n/8 is the nearest
             * multiple of 1/8 to x.
             */
            x8 = normalizeRoundAndPackFloatx80(floatx80_precision_x,
                                               false, xexp + 3, xsig0,
                                               xsig1, &env->fp_status);
            n = floatx80_to_int32(x8, &env->fp_status);
            if (n == 0) {
                ysign = false;
                yexp = xexp;
                ysig0 = xsig0;
                ysig1 = xsig1;
                texp = 0;
                tsig = 0;
            } else {
                int shift = clz32(n) + 32;
                texp = 0x403b - shift;
                tsig = n;
                tsig <<= shift;
                if (texp == xexp) {
                    sub128(xsig0, xsig1, tsig, 0, &ysig0, &ysig1);
                    if ((int64_t) ysig0 >= 0) {
                        ysign = false;
                        if (ysig0 == 0) {
                            if (ysig1 == 0) {
                                yexp = 0;
                            } else {
                                shift = clz64(ysig1) + 64;
                                yexp = xexp - shift;
                                shift128Left(ysig0, ysig1, shift,
                                             &ysig0, &ysig1);
                            }
                        } else {
                            shift = clz64(ysig0);
                            yexp = xexp - shift;
                            shift128Left(ysig0, ysig1, shift, &ysig0, &ysig1);
                        }
                    } else {
                        ysign = true;
                        sub128(0, 0, ysig0, ysig1, &ysig0, &ysig1);
                        if (ysig0 == 0) {
                            shift = clz64(ysig1) + 64;
                        } else {
                            shift = clz64(ysig0);
                        }
                        yexp = xexp - shift;
                        shift128Left(ysig0, ysig1, shift, &ysig0, &ysig1);
                    }
                } else {
                    /*
                     * t's exponent must be greater than x's because t
                     * is positive and the nearest multiple of 1/8 to
                     * x, and if x has a greater exponent, the power
                     * of 2 with that exponent is also a multiple of
                     * 1/8.
                     */
                    uint64_t usig0, usig1;
                    shift128RightJamming(xsig0, xsig1, texp - xexp,
                                         &usig0, &usig1);
                    ysign = true;
                    sub128(tsig, 0, usig0, usig1, &ysig0, &ysig1);
                    if (ysig0 == 0) {
                        shift = clz64(ysig1) + 64;
                    } else {
                        shift = clz64(ysig0);
                    }
                    yexp = texp - shift;
                    shift128Left(ysig0, ysig1, shift, &ysig0, &ysig1);
                }
            }

            /*
             * Compute z = y/(1+tx), so arctan(x) = arctan(t) +
             * arctan(z).
             */
            zsign = ysign;
            if (texp == 0 || yexp == 0) {
                zexp = yexp;
                zsig0 = ysig0;
                zsig1 = ysig1;
            } else {
                /*
                 * t <= 1, x <= 1 and if both are 1 then y is 0, so tx < 1.
                 */
                int32_t dexp = texp + xexp - 0x3ffe;
                uint64_t dsig0, dsig1, dsig2;
                mul128By64To192(xsig0, xsig1, tsig, &dsig0, &dsig1, &dsig2);
                /*
                 * dexp <= 0x3fff (and if equal, dsig0 has a leading 0
                 * bit).  Add 1 to produce the denominator 1+tx.
                 */
                shift128RightJamming(dsig0, dsig1, 0x3fff - dexp,
                                     &dsig0, &dsig1);
                dsig0 |= 0x8000000000000000ULL;
                zexp = yexp - 1;
                remsig0 = ysig0;
                remsig1 = ysig1;
                remsig2 = 0;
                if (dsig0 <= remsig0) {
                    shift128Right(remsig0, remsig1, 1, &remsig0, &remsig1);
                    ++zexp;
                }
                zsig0 = estimateDiv128To64(remsig0, remsig1, dsig0);
                mul128By64To192(dsig0, dsig1, zsig0, &msig0, &msig1, &msig2);
                sub192(remsig0, remsig1, remsig2, msig0, msig1, msig2,
                       &remsig0, &remsig1, &remsig2);
                while ((int64_t) remsig0 < 0) {
                    --zsig0;
                    add192(remsig0, remsig1, remsig2, 0, dsig0, dsig1,
                           &remsig0, &remsig1, &remsig2);
                }
                zsig1 = estimateDiv128To64(remsig1, remsig2, dsig0);
                /* No need to correct any estimation error in zsig1.  */
            }

            if (zexp == 0) {
                azexp = 0;
                azsig0 = 0;
                azsig1 = 0;
            } else {
                floatx80 z2, accum;
                uint64_t z2sig0, z2sig1, z2sig2, z2sig3;
                /* Compute z^2.  */
                mul128To256(zsig0, zsig1, zsig0, zsig1,
                            &z2sig0, &z2sig1, &z2sig2, &z2sig3);
                z2 = normalizeRoundAndPackFloatx80(floatx80_precision_x, false,
                                                   zexp + zexp - 0x3ffe,
                                                   z2sig0, z2sig1,
                                                   &env->fp_status);

                /* Compute the lower parts of the polynomial expansion.  */
                accum = floatx80_mul(fpatan_coeff_6, z2, &env->fp_status);
                accum = floatx80_add(fpatan_coeff_5, accum, &env->fp_status);
                accum = floatx80_mul(accum, z2, &env->fp_status);
                accum = floatx80_add(fpatan_coeff_4, accum, &env->fp_status);
                accum = floatx80_mul(accum, z2, &env->fp_status);
                accum = floatx80_add(fpatan_coeff_3, accum, &env->fp_status);
                accum = floatx80_mul(accum, z2, &env->fp_status);
                accum = floatx80_add(fpatan_coeff_2, accum, &env->fp_status);
                accum = floatx80_mul(accum, z2, &env->fp_status);
                accum = floatx80_add(fpatan_coeff_1, accum, &env->fp_status);
                accum = floatx80_mul(accum, z2, &env->fp_status);

                /*
                 * The full polynomial expansion is z*(fpatan_coeff_0 + accum).
                 * fpatan_coeff_0 is 1, and accum is negative and much smaller.
                 */
                aexp = extractFloatx80Exp(fpatan_coeff_0);
                shift128RightJamming(extractFloatx80Frac(accum), 0,
                                     aexp - extractFloatx80Exp(accum),
                                     &asig0, &asig1);
                sub128(extractFloatx80Frac(fpatan_coeff_0), 0, asig0, asig1,
                       &asig0, &asig1);
                /* Multiply by z to compute arctan(z).  */
                azexp = aexp + zexp - 0x3ffe;
                mul128To256(asig0, asig1, zsig0, zsig1, &azsig0, &azsig1,
                            &azsig2, &azsig3);
            }

            /* Add arctan(t) (positive or zero) and arctan(z) (sign zsign).  */
            if (texp == 0) {
                /* z is positive.  */
                axexp = azexp;
                axsig0 = azsig0;
                axsig1 = azsig1;
            } else {
                bool low_sign = extractFloatx80Sign(fpatan_table[n].atan_low);
                int32_t low_exp = extractFloatx80Exp(fpatan_table[n].atan_low);
                uint64_t low_sig0 =
                    extractFloatx80Frac(fpatan_table[n].atan_low);
                uint64_t low_sig1 = 0;
                axexp = extractFloatx80Exp(fpatan_table[n].atan_high);
                axsig0 = extractFloatx80Frac(fpatan_table[n].atan_high);
                axsig1 = 0;
                shift128RightJamming(low_sig0, low_sig1, axexp - low_exp,
                                     &low_sig0, &low_sig1);
                if (low_sign) {
                    sub128(axsig0, axsig1, low_sig0, low_sig1,
                           &axsig0, &axsig1);
                } else {
                    add128(axsig0, axsig1, low_sig0, low_sig1,
                           &axsig0, &axsig1);
                }
                if (azexp >= axexp) {
                    shift128RightJamming(axsig0, axsig1, azexp - axexp + 1,
                                         &axsig0, &axsig1);
                    axexp = azexp + 1;
                    shift128RightJamming(azsig0, azsig1, 1,
                                         &azsig0, &azsig1);
                } else {
                    shift128RightJamming(axsig0, axsig1, 1,
                                         &axsig0, &axsig1);
                    shift128RightJamming(azsig0, azsig1, axexp - azexp + 1,
                                         &azsig0, &azsig1);
                    ++axexp;
                }
                if (zsign) {
                    sub128(axsig0, axsig1, azsig0, azsig1,
                           &axsig0, &axsig1);
                } else {
                    add128(axsig0, axsig1, azsig0, azsig1,
                           &axsig0, &axsig1);
                }
            }

            if (adj_exp == 0) {
                rexp = axexp;
                rsig0 = axsig0;
                rsig1 = axsig1;
            } else {
                /*
                 * Add or subtract arctan(x) (exponent axexp,
                 * significand axsig0 and axsig1, positive, not
                 * necessarily normalized) to the number given by
                 * adj_exp, adj_sig0 and adj_sig1, according to
                 * adj_sub.
                 */
                if (adj_exp >= axexp) {
                    shift128RightJamming(axsig0, axsig1, adj_exp - axexp + 1,
                                         &axsig0, &axsig1);
                    rexp = adj_exp + 1;
                    shift128RightJamming(adj_sig0, adj_sig1, 1,
                                         &adj_sig0, &adj_sig1);
                } else {
                    shift128RightJamming(axsig0, axsig1, 1,
                                         &axsig0, &axsig1);
                    shift128RightJamming(adj_sig0, adj_sig1,
                                         axexp - adj_exp + 1,
                                         &adj_sig0, &adj_sig1);
                    rexp = axexp + 1;
                }
                if (adj_sub) {
                    sub128(adj_sig0, adj_sig1, axsig0, axsig1,
                           &rsig0, &rsig1);
                } else {
                    add128(adj_sig0, adj_sig1, axsig0, axsig1,
                           &rsig0, &rsig1);
                }
            }

            env->fp_status.float_rounding_mode = save_mode;
            env->fp_status.floatx80_rounding_precision = save_prec;
        }
        /* This result is inexact.  */
        rsig1 |= 1;
        ST1 = normalizeRoundAndPackFloatx80(floatx80_precision_x, rsign, rexp,
                                            rsig0, rsig1, &env->fp_status);
    }

    fpop(env);
    merge_exception_flags(env, old_flags);
}

