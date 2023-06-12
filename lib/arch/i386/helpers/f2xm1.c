#define HOST_BIG_ENDIAN (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)

#define QEMU_ALIGNED(X) __attribute__((aligned(X)))

#include <stdbool.h>

#include <stdint.h>

void mulu64(uint64_t *plow, uint64_t *phigh, uint64_t a, uint64_t b);

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

static inline void mul64(uint64_t *plow, uint64_t *phigh,
                         uint64_t a, uint64_t b)
{
    typedef union {
        uint64_t ll;
        struct {
#if HOST_BIG_ENDIAN
            uint32_t high, low;
#else
            uint32_t low, high;
#endif
        } l;
    } LL;
    LL rl, rm, rn, rh, a0, b0;
    uint64_t c;

    a0.ll = a;
    b0.ll = b;

    rl.ll = (uint64_t)a0.l.low * b0.l.low;
    rm.ll = (uint64_t)a0.l.low * b0.l.high;
    rn.ll = (uint64_t)a0.l.high * b0.l.low;
    rh.ll = (uint64_t)a0.l.high * b0.l.high;

    c = (uint64_t)rl.l.high + rm.l.low + rn.l.low;
    rl.l.high = c;
    c >>= 32;
    c = c + rm.l.high + rn.l.high + rh.l.low;
    rh.l.low = c;
    rh.l.high += (uint32_t)(c >> 32);

    *plow = rl.ll;
    *phigh = rh.ll;
}

void mulu64 (uint64_t *plow, uint64_t *phigh, uint64_t a, uint64_t b)
{
    mul64(plow, phigh, a, b);
}

#define QTAILQ_ENTRY(type)                                              \
union {                                                                 \
        struct type *tqe_next;        /* next element */                \
        QTailQLink tqe_circ;          /* link for circular backwards list */ \
}

typedef struct QTailQLink {
    void *tql_next;
    struct QTailQLink *tql_prev;
} QTailQLink;

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

floatx80 floatx80_add(floatx80, floatx80, float_status *status);

floatx80 floatx80_sub(floatx80, floatx80, float_status *status);

floatx80 floatx80_mul(floatx80, floatx80, float_status *status);

int floatx80_is_signaling_nan(floatx80, float_status *status);

floatx80 floatx80_silence_nan(floatx80, float_status *status);

floatx80 floatx80_scalbn(floatx80, int, float_status *status);

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

static inline void add128(uint64_t a0, uint64_t a1, uint64_t b0, uint64_t b1,
                          uint64_t *z0Ptr, uint64_t *z1Ptr)
{
    bool c = 0;
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

#define ST0    (env->fpregs[env->fpstt].d)

#define FPUS_IE (1 << 0)

#define FPUS_DE (1 << 1)

#define FPUS_ZE (1 << 2)

#define FPUS_OE (1 << 3)

#define FPUS_UE (1 << 4)

#define FPUS_PE (1 << 5)

#define FPUS_SE (1 << 7)

#define FPUS_B  (1 << 15)

#define FPUC_EM 0x3f

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

#define ln2_sig_high 0xb17217f7d1cf79abULL

#define ln2_sig_low 0xc9e3b39803f2f6afULL

#define f2xm1_coeff_0 make_floatx80(0x3ffe, 0xb17217f7d1cf79acULL)

#define f2xm1_coeff_0_low make_floatx80(0xbfbc, 0xd87edabf495b3762ULL)

#define f2xm1_coeff_1 make_floatx80(0x3ffc, 0xf5fdeffc162c7543ULL)

#define f2xm1_coeff_2 make_floatx80(0x3ffa, 0xe35846b82505fcc7ULL)

#define f2xm1_coeff_3 make_floatx80(0x3ff8, 0x9d955b7dd273b899ULL)

#define f2xm1_coeff_4 make_floatx80(0x3ff5, 0xaec3ff3c4ef4ac0cULL)

#define f2xm1_coeff_5 make_floatx80(0x3ff2, 0xa184897c3a7f0de9ULL)

#define f2xm1_coeff_6 make_floatx80(0x3fee, 0xffe634d0ec30d504ULL)

#define f2xm1_coeff_7 make_floatx80(0x3feb, 0xb160111d2db515e4ULL)

struct f2xm1_data {
    /*
     * A value very close to a multiple of 1/32, such that 2^t and 2^t - 1
     * are very close to exact floatx80 values.
     */
    floatx80 t;
    /* The value of 2^t.  */
    floatx80 exp2;
    /* The value of 2^t - 1.  */
    floatx80 exp2m1;
};

static const struct f2xm1_data f2xm1_table[65] = {
    { make_floatx80_init(0xbfff, 0x8000000000000000ULL),
      make_floatx80_init(0x3ffe, 0x8000000000000000ULL),
      make_floatx80_init(0xbffe, 0x8000000000000000ULL) },
    { make_floatx80_init(0xbffe, 0xf800000000002e7eULL),
      make_floatx80_init(0x3ffe, 0x82cd8698ac2b9160ULL),
      make_floatx80_init(0xbffd, 0xfa64f2cea7a8dd40ULL) },
    { make_floatx80_init(0xbffe, 0xefffffffffffe960ULL),
      make_floatx80_init(0x3ffe, 0x85aac367cc488345ULL),
      make_floatx80_init(0xbffd, 0xf4aa7930676ef976ULL) },
    { make_floatx80_init(0xbffe, 0xe800000000006f10ULL),
      make_floatx80_init(0x3ffe, 0x88980e8092da5c14ULL),
      make_floatx80_init(0xbffd, 0xeecfe2feda4b47d8ULL) },
    { make_floatx80_init(0xbffe, 0xe000000000008a45ULL),
      make_floatx80_init(0x3ffe, 0x8b95c1e3ea8ba2a5ULL),
      make_floatx80_init(0xbffd, 0xe8d47c382ae8bab6ULL) },
    { make_floatx80_init(0xbffe, 0xd7ffffffffff8a9eULL),
      make_floatx80_init(0x3ffe, 0x8ea4398b45cd8116ULL),
      make_floatx80_init(0xbffd, 0xe2b78ce97464fdd4ULL) },
    { make_floatx80_init(0xbffe, 0xd0000000000019a0ULL),
      make_floatx80_init(0x3ffe, 0x91c3d373ab11b919ULL),
      make_floatx80_init(0xbffd, 0xdc785918a9dc8dceULL) },
    { make_floatx80_init(0xbffe, 0xc7ffffffffff14dfULL),
      make_floatx80_init(0x3ffe, 0x94f4efa8fef76836ULL),
      make_floatx80_init(0xbffd, 0xd61620ae02112f94ULL) },
    { make_floatx80_init(0xbffe, 0xc000000000006530ULL),
      make_floatx80_init(0x3ffe, 0x9837f0518db87fbbULL),
      make_floatx80_init(0xbffd, 0xcf901f5ce48f008aULL) },
    { make_floatx80_init(0xbffe, 0xb7ffffffffff1723ULL),
      make_floatx80_init(0x3ffe, 0x9b8d39b9d54eb74cULL),
      make_floatx80_init(0xbffd, 0xc8e58c8c55629168ULL) },
    { make_floatx80_init(0xbffe, 0xb00000000000b5e1ULL),
      make_floatx80_init(0x3ffe, 0x9ef5326091a0c366ULL),
      make_floatx80_init(0xbffd, 0xc2159b3edcbe7934ULL) },
    { make_floatx80_init(0xbffe, 0xa800000000006f8aULL),
      make_floatx80_init(0x3ffe, 0xa27043030c49370aULL),
      make_floatx80_init(0xbffd, 0xbb1f79f9e76d91ecULL) },
    { make_floatx80_init(0xbffe, 0x9fffffffffff816aULL),
      make_floatx80_init(0x3ffe, 0xa5fed6a9b15171cfULL),
      make_floatx80_init(0xbffd, 0xb40252ac9d5d1c62ULL) },
    { make_floatx80_init(0xbffe, 0x97ffffffffffb621ULL),
      make_floatx80_init(0x3ffe, 0xa9a15ab4ea7c30e6ULL),
      make_floatx80_init(0xbffd, 0xacbd4a962b079e34ULL) },
    { make_floatx80_init(0xbffe, 0x8fffffffffff162bULL),
      make_floatx80_init(0x3ffe, 0xad583eea42a1b886ULL),
      make_floatx80_init(0xbffd, 0xa54f822b7abc8ef4ULL) },
    { make_floatx80_init(0xbffe, 0x87ffffffffff4d34ULL),
      make_floatx80_init(0x3ffe, 0xb123f581d2ac7b51ULL),
      make_floatx80_init(0xbffd, 0x9db814fc5aa7095eULL) },
    { make_floatx80_init(0xbffe, 0x800000000000227dULL),
      make_floatx80_init(0x3ffe, 0xb504f333f9de539dULL),
      make_floatx80_init(0xbffd, 0x95f619980c4358c6ULL) },
    { make_floatx80_init(0xbffd, 0xefffffffffff3978ULL),
      make_floatx80_init(0x3ffe, 0xb8fbaf4762fbd0a1ULL),
      make_floatx80_init(0xbffd, 0x8e08a1713a085ebeULL) },
    { make_floatx80_init(0xbffd, 0xe00000000000df81ULL),
      make_floatx80_init(0x3ffe, 0xbd08a39f580bfd8cULL),
      make_floatx80_init(0xbffd, 0x85eeb8c14fe804e8ULL) },
    { make_floatx80_init(0xbffd, 0xd00000000000bccfULL),
      make_floatx80_init(0x3ffe, 0xc12c4cca667062f6ULL),
      make_floatx80_init(0xbffc, 0xfb4eccd6663e7428ULL) },
    { make_floatx80_init(0xbffd, 0xc00000000000eff0ULL),
      make_floatx80_init(0x3ffe, 0xc5672a1155069abeULL),
      make_floatx80_init(0xbffc, 0xea6357baabe59508ULL) },
    { make_floatx80_init(0xbffd, 0xb000000000000fe6ULL),
      make_floatx80_init(0x3ffe, 0xc9b9bd866e2f234bULL),
      make_floatx80_init(0xbffc, 0xd91909e6474372d4ULL) },
    { make_floatx80_init(0xbffd, 0x9fffffffffff2172ULL),
      make_floatx80_init(0x3ffe, 0xce248c151f84bf00ULL),
      make_floatx80_init(0xbffc, 0xc76dcfab81ed0400ULL) },
    { make_floatx80_init(0xbffd, 0x8fffffffffffafffULL),
      make_floatx80_init(0x3ffe, 0xd2a81d91f12afb2bULL),
      make_floatx80_init(0xbffc, 0xb55f89b83b541354ULL) },
    { make_floatx80_init(0xbffc, 0xffffffffffff81a3ULL),
      make_floatx80_init(0x3ffe, 0xd744fccad69d7d5eULL),
      make_floatx80_init(0xbffc, 0xa2ec0cd4a58a0a88ULL) },
    { make_floatx80_init(0xbffc, 0xdfffffffffff1568ULL),
      make_floatx80_init(0x3ffe, 0xdbfbb797daf25a44ULL),
      make_floatx80_init(0xbffc, 0x901121a0943696f0ULL) },
    { make_floatx80_init(0xbffc, 0xbfffffffffff68daULL),
      make_floatx80_init(0x3ffe, 0xe0ccdeec2a94f811ULL),
      make_floatx80_init(0xbffb, 0xf999089eab583f78ULL) },
    { make_floatx80_init(0xbffc, 0x9fffffffffff4690ULL),
      make_floatx80_init(0x3ffe, 0xe5b906e77c83657eULL),
      make_floatx80_init(0xbffb, 0xd237c8c41be4d410ULL) },
    { make_floatx80_init(0xbffb, 0xffffffffffff8aeeULL),
      make_floatx80_init(0x3ffe, 0xeac0c6e7dd24427cULL),
      make_floatx80_init(0xbffb, 0xa9f9c8c116ddec20ULL) },
    { make_floatx80_init(0xbffb, 0xbfffffffffff2d18ULL),
      make_floatx80_init(0x3ffe, 0xefe4b99bdcdb06ebULL),
      make_floatx80_init(0xbffb, 0x80da33211927c8a8ULL) },
    { make_floatx80_init(0xbffa, 0xffffffffffff8ccbULL),
      make_floatx80_init(0x3ffe, 0xf5257d152486d0f4ULL),
      make_floatx80_init(0xbffa, 0xada82eadb792f0c0ULL) },
    { make_floatx80_init(0xbff9, 0xffffffffffff11feULL),
      make_floatx80_init(0x3ffe, 0xfa83b2db722a0846ULL),
      make_floatx80_init(0xbff9, 0xaf89a491babef740ULL) },
    { floatx80_zero_init,
      make_floatx80_init(0x3fff, 0x8000000000000000ULL),
      floatx80_zero_init },
    { make_floatx80_init(0x3ff9, 0xffffffffffff2680ULL),
      make_floatx80_init(0x3fff, 0x82cd8698ac2b9f6fULL),
      make_floatx80_init(0x3ff9, 0xb361a62b0ae7dbc0ULL) },
    { make_floatx80_init(0x3ffb, 0x800000000000b500ULL),
      make_floatx80_init(0x3fff, 0x85aac367cc488345ULL),
      make_floatx80_init(0x3ffa, 0xb5586cf9891068a0ULL) },
    { make_floatx80_init(0x3ffb, 0xbfffffffffff4b67ULL),
      make_floatx80_init(0x3fff, 0x88980e8092da7cceULL),
      make_floatx80_init(0x3ffb, 0x8980e8092da7cce0ULL) },
    { make_floatx80_init(0x3ffb, 0xffffffffffffff57ULL),
      make_floatx80_init(0x3fff, 0x8b95c1e3ea8bd6dfULL),
      make_floatx80_init(0x3ffb, 0xb95c1e3ea8bd6df0ULL) },
    { make_floatx80_init(0x3ffc, 0x9fffffffffff811fULL),
      make_floatx80_init(0x3fff, 0x8ea4398b45cd4780ULL),
      make_floatx80_init(0x3ffb, 0xea4398b45cd47800ULL) },
    { make_floatx80_init(0x3ffc, 0xbfffffffffff9980ULL),
      make_floatx80_init(0x3fff, 0x91c3d373ab11b919ULL),
      make_floatx80_init(0x3ffc, 0x8e1e9b9d588dc8c8ULL) },
    { make_floatx80_init(0x3ffc, 0xdffffffffffff631ULL),
      make_floatx80_init(0x3fff, 0x94f4efa8fef70864ULL),
      make_floatx80_init(0x3ffc, 0xa7a77d47f7b84320ULL) },
    { make_floatx80_init(0x3ffc, 0xffffffffffff2499ULL),
      make_floatx80_init(0x3fff, 0x9837f0518db892d4ULL),
      make_floatx80_init(0x3ffc, 0xc1bf828c6dc496a0ULL) },
    { make_floatx80_init(0x3ffd, 0x8fffffffffff80fbULL),
      make_floatx80_init(0x3fff, 0x9b8d39b9d54e3a79ULL),
      make_floatx80_init(0x3ffc, 0xdc69cdceaa71d3c8ULL) },
    { make_floatx80_init(0x3ffd, 0x9fffffffffffbc23ULL),
      make_floatx80_init(0x3fff, 0x9ef5326091a10313ULL),
      make_floatx80_init(0x3ffc, 0xf7a993048d081898ULL) },
    { make_floatx80_init(0x3ffd, 0xafffffffffff20ecULL),
      make_floatx80_init(0x3fff, 0xa27043030c49370aULL),
      make_floatx80_init(0x3ffd, 0x89c10c0c3124dc28ULL) },
    { make_floatx80_init(0x3ffd, 0xc00000000000fd2cULL),
      make_floatx80_init(0x3fff, 0xa5fed6a9b15171cfULL),
      make_floatx80_init(0x3ffd, 0x97fb5aa6c545c73cULL) },
    { make_floatx80_init(0x3ffd, 0xd0000000000093beULL),
      make_floatx80_init(0x3fff, 0xa9a15ab4ea7c30e6ULL),
      make_floatx80_init(0x3ffd, 0xa6856ad3a9f0c398ULL) },
    { make_floatx80_init(0x3ffd, 0xe00000000000c2aeULL),
      make_floatx80_init(0x3fff, 0xad583eea42a17876ULL),
      make_floatx80_init(0x3ffd, 0xb560fba90a85e1d8ULL) },
    { make_floatx80_init(0x3ffd, 0xefffffffffff1e3fULL),
      make_floatx80_init(0x3fff, 0xb123f581d2abef6cULL),
      make_floatx80_init(0x3ffd, 0xc48fd6074aafbdb0ULL) },
    { make_floatx80_init(0x3ffd, 0xffffffffffff1c23ULL),
      make_floatx80_init(0x3fff, 0xb504f333f9de2cadULL),
      make_floatx80_init(0x3ffd, 0xd413cccfe778b2b4ULL) },
    { make_floatx80_init(0x3ffe, 0x8800000000006344ULL),
      make_floatx80_init(0x3fff, 0xb8fbaf4762fbd0a1ULL),
      make_floatx80_init(0x3ffd, 0xe3eebd1d8bef4284ULL) },
    { make_floatx80_init(0x3ffe, 0x9000000000005d67ULL),
      make_floatx80_init(0x3fff, 0xbd08a39f580c668dULL),
      make_floatx80_init(0x3ffd, 0xf4228e7d60319a34ULL) },
    { make_floatx80_init(0x3ffe, 0x9800000000009127ULL),
      make_floatx80_init(0x3fff, 0xc12c4cca6670e042ULL),
      make_floatx80_init(0x3ffe, 0x82589994cce1c084ULL) },
    { make_floatx80_init(0x3ffe, 0x9fffffffffff06f9ULL),
      make_floatx80_init(0x3fff, 0xc5672a11550655c3ULL),
      make_floatx80_init(0x3ffe, 0x8ace5422aa0cab86ULL) },
    { make_floatx80_init(0x3ffe, 0xa7fffffffffff80dULL),
      make_floatx80_init(0x3fff, 0xc9b9bd866e2f234bULL),
      make_floatx80_init(0x3ffe, 0x93737b0cdc5e4696ULL) },
    { make_floatx80_init(0x3ffe, 0xafffffffffff1470ULL),
      make_floatx80_init(0x3fff, 0xce248c151f83fd69ULL),
      make_floatx80_init(0x3ffe, 0x9c49182a3f07fad2ULL) },
    { make_floatx80_init(0x3ffe, 0xb800000000000e0aULL),
      make_floatx80_init(0x3fff, 0xd2a81d91f12aec5cULL),
      make_floatx80_init(0x3ffe, 0xa5503b23e255d8b8ULL) },
    { make_floatx80_init(0x3ffe, 0xc00000000000b7faULL),
      make_floatx80_init(0x3fff, 0xd744fccad69dd630ULL),
      make_floatx80_init(0x3ffe, 0xae89f995ad3bac60ULL) },
    { make_floatx80_init(0x3ffe, 0xc800000000003aa6ULL),
      make_floatx80_init(0x3fff, 0xdbfbb797daf25a44ULL),
      make_floatx80_init(0x3ffe, 0xb7f76f2fb5e4b488ULL) },
    { make_floatx80_init(0x3ffe, 0xd00000000000a6aeULL),
      make_floatx80_init(0x3fff, 0xe0ccdeec2a954685ULL),
      make_floatx80_init(0x3ffe, 0xc199bdd8552a8d0aULL) },
    { make_floatx80_init(0x3ffe, 0xd800000000004165ULL),
      make_floatx80_init(0x3fff, 0xe5b906e77c837155ULL),
      make_floatx80_init(0x3ffe, 0xcb720dcef906e2aaULL) },
    { make_floatx80_init(0x3ffe, 0xe00000000000582cULL),
      make_floatx80_init(0x3fff, 0xeac0c6e7dd24713aULL),
      make_floatx80_init(0x3ffe, 0xd5818dcfba48e274ULL) },
    { make_floatx80_init(0x3ffe, 0xe800000000001a5dULL),
      make_floatx80_init(0x3fff, 0xefe4b99bdcdb06ebULL),
      make_floatx80_init(0x3ffe, 0xdfc97337b9b60dd6ULL) },
    { make_floatx80_init(0x3ffe, 0xefffffffffffc1efULL),
      make_floatx80_init(0x3fff, 0xf5257d152486a2faULL),
      make_floatx80_init(0x3ffe, 0xea4afa2a490d45f4ULL) },
    { make_floatx80_init(0x3ffe, 0xf800000000001069ULL),
      make_floatx80_init(0x3fff, 0xfa83b2db722a0e5cULL),
      make_floatx80_init(0x3ffe, 0xf50765b6e4541cb8ULL) },
    { make_floatx80_init(0x3fff, 0x8000000000000000ULL),
      make_floatx80_init(0x4000, 0x8000000000000000ULL),
      make_floatx80_init(0x3fff, 0x8000000000000000ULL) },
};

void helper_f2xm1(CPUX86State *env)
{
    uint8_t old_flags = save_exception_flags(env);
    uint64_t sig = extractFloatx80Frac(ST0);
    int32_t exp = extractFloatx80Exp(ST0);
    bool sign = extractFloatx80Sign(ST0);

    if (floatx80_invalid_encoding(ST0)) {
        float_raise(float_flag_invalid, &env->fp_status);
        ST0 = floatx80_default_nan(&env->fp_status);
    } else if (floatx80_is_any_nan(ST0)) {
        if (floatx80_is_signaling_nan(ST0, &env->fp_status)) {
            float_raise(float_flag_invalid, &env->fp_status);
            ST0 = floatx80_silence_nan(ST0, &env->fp_status);
        }
    } else if (exp > 0x3fff ||
               (exp == 0x3fff && sig != (0x8000000000000000ULL))) {
        /* Out of range for the instruction, treat as invalid.  */
        float_raise(float_flag_invalid, &env->fp_status);
        ST0 = floatx80_default_nan(&env->fp_status);
    } else if (exp == 0x3fff) {
        /* Argument 1 or -1, exact result 1 or -0.5.  */
        if (sign) {
            ST0 = make_floatx80(0xbffe, 0x8000000000000000ULL);
        }
    } else if (exp < 0x3fb0) {
        if (!floatx80_is_zero(ST0)) {
            /*
             * Multiplying the argument by an extra-precision version
             * of log(2) is sufficiently precise.  Zero arguments are
             * returned unchanged.
             */
            uint64_t sig0, sig1, sig2;
            if (exp == 0) {
                normalizeFloatx80Subnormal(sig, &exp, &sig);
            }
            mul128By64To192(ln2_sig_high, ln2_sig_low, sig, &sig0, &sig1,
                            &sig2);
            /* This result is inexact.  */
            sig1 |= 1;
            ST0 = normalizeRoundAndPackFloatx80(floatx80_precision_x,
                                                sign, exp, sig0, sig1,
                                                &env->fp_status);
        }
    } else {
        floatx80 tmp, y, accum;
        bool asign, bsign;
        int32_t n, aexp, bexp;
        uint64_t asig0, asig1, asig2, bsig0, bsig1;
        FloatRoundMode save_mode = env->fp_status.float_rounding_mode;
        FloatX80RoundPrec save_prec =
            env->fp_status.floatx80_rounding_precision;
        env->fp_status.float_rounding_mode = float_round_nearest_even;
        env->fp_status.floatx80_rounding_precision = floatx80_precision_x;

        /* Find the nearest multiple of 1/32 to the argument.  */
        tmp = floatx80_scalbn(ST0, 5, &env->fp_status);
        n = 32 + floatx80_to_int32(tmp, &env->fp_status);
        y = floatx80_sub(ST0, f2xm1_table[n].t, &env->fp_status);

        if (floatx80_is_zero(y)) {
            /*
             * Use the value of 2^t - 1 from the table, to avoid
             * needing to special-case zero as a result of
             * multiplication below.
             */
            ST0 = f2xm1_table[n].t;
            set_float_exception_flags(float_flag_inexact, &env->fp_status);
            env->fp_status.float_rounding_mode = save_mode;
        } else {
            /*
             * Compute the lower parts of a polynomial expansion for
             * (2^y - 1) / y.
             */
            accum = floatx80_mul(f2xm1_coeff_7, y, &env->fp_status);
            accum = floatx80_add(f2xm1_coeff_6, accum, &env->fp_status);
            accum = floatx80_mul(accum, y, &env->fp_status);
            accum = floatx80_add(f2xm1_coeff_5, accum, &env->fp_status);
            accum = floatx80_mul(accum, y, &env->fp_status);
            accum = floatx80_add(f2xm1_coeff_4, accum, &env->fp_status);
            accum = floatx80_mul(accum, y, &env->fp_status);
            accum = floatx80_add(f2xm1_coeff_3, accum, &env->fp_status);
            accum = floatx80_mul(accum, y, &env->fp_status);
            accum = floatx80_add(f2xm1_coeff_2, accum, &env->fp_status);
            accum = floatx80_mul(accum, y, &env->fp_status);
            accum = floatx80_add(f2xm1_coeff_1, accum, &env->fp_status);
            accum = floatx80_mul(accum, y, &env->fp_status);
            accum = floatx80_add(f2xm1_coeff_0_low, accum, &env->fp_status);

            /*
             * The full polynomial expansion is f2xm1_coeff_0 + accum
             * (where accum has much lower magnitude, and so, in
             * particular, carry out of the addition is not possible).
             * (This expansion is only accurate to about 70 bits, not
             * 128 bits.)
             */
            aexp = extractFloatx80Exp(f2xm1_coeff_0);
            asign = extractFloatx80Sign(f2xm1_coeff_0);
            shift128RightJamming(extractFloatx80Frac(accum), 0,
                                 aexp - extractFloatx80Exp(accum),
                                 &asig0, &asig1);
            bsig0 = extractFloatx80Frac(f2xm1_coeff_0);
            bsig1 = 0;
            if (asign == extractFloatx80Sign(accum)) {
                add128(bsig0, bsig1, asig0, asig1, &asig0, &asig1);
            } else {
                sub128(bsig0, bsig1, asig0, asig1, &asig0, &asig1);
            }
            /* And thus compute an approximation to 2^y - 1.  */
            mul128By64To192(asig0, asig1, extractFloatx80Frac(y),
                            &asig0, &asig1, &asig2);
            aexp += extractFloatx80Exp(y) - 0x3ffe;
            asign ^= extractFloatx80Sign(y);
            if (n != 32) {
                /*
                 * Multiply this by the precomputed value of 2^t and
                 * add that of 2^t - 1.
                 */
                mul128By64To192(asig0, asig1,
                                extractFloatx80Frac(f2xm1_table[n].exp2),
                                &asig0, &asig1, &asig2);
                aexp += extractFloatx80Exp(f2xm1_table[n].exp2) - 0x3ffe;
                bexp = extractFloatx80Exp(f2xm1_table[n].exp2m1);
                bsig0 = extractFloatx80Frac(f2xm1_table[n].exp2m1);
                bsig1 = 0;
                if (bexp < aexp) {
                    shift128RightJamming(bsig0, bsig1, aexp - bexp,
                                         &bsig0, &bsig1);
                } else if (aexp < bexp) {
                    shift128RightJamming(asig0, asig1, bexp - aexp,
                                         &asig0, &asig1);
                    aexp = bexp;
                }
                /* The sign of 2^t - 1 is always that of the result.  */
                bsign = extractFloatx80Sign(f2xm1_table[n].exp2m1);
                if (asign == bsign) {
                    /* Avoid possible carry out of the addition.  */
                    shift128RightJamming(asig0, asig1, 1,
                                         &asig0, &asig1);
                    shift128RightJamming(bsig0, bsig1, 1,
                                         &bsig0, &bsig1);
                    ++aexp;
                    add128(asig0, asig1, bsig0, bsig1, &asig0, &asig1);
                } else {
                    sub128(bsig0, bsig1, asig0, asig1, &asig0, &asig1);
                    asign = bsign;
                }
            }
            env->fp_status.float_rounding_mode = save_mode;
            /* This result is inexact.  */
            asig1 |= 1;
            ST0 = normalizeRoundAndPackFloatx80(floatx80_precision_x,
                                                asign, aexp, asig0, asig1,
                                                &env->fp_status);
        }

        env->fp_status.floatx80_rounding_precision = save_prec;
    }
    merge_exception_flags(env, old_flags);
}

