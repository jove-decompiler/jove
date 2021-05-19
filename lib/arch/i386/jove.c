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

typedef uint32_t target_ulong;

enum {
    R_EAX = 0,
    R_ECX = 1,
    R_EDX = 2,
    R_EBX = 3,
    R_ESP = 4,
    R_EBP = 5,
    R_ESI = 6,
    R_EDI = 7,
    R_R8 = 8,
    R_R9 = 9,
    R_R10 = 10,
    R_R11 = 11,
    R_R12 = 12,
    R_R13 = 13,
    R_R14 = 14,
    R_R15 = 15,

    R_AL = 0,
    R_CL = 1,
    R_DL = 2,
    R_BL = 3,
    R_AH = 4,
    R_CH = 5,
    R_DH = 6,
    R_BH = 7,
};

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

#define CPU_NB_REGS32 8

#define CPU_NB_REGS CPU_NB_REGS32

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

#include <stddef.h>

extern /* __thread */ struct CPUX86State __jove_env;

extern /* __thread */ uint64_t *__jove_trace;
extern /* __thread */ uint64_t *__jove_trace_begin;

extern /* __thread */ uint64_t *__jove_callstack;
extern /* __thread */ uint64_t *__jove_callstack_begin;

extern int    __jove_startup_info_argc;
extern char **__jove_startup_info_argv;
extern char **__jove_startup_info_environ;

#define _JOVE_MAX_BINARIES 512
extern uintptr_t *__jove_function_tables[_JOVE_MAX_BINARIES];

/* -> static */ uintptr_t *__jove_foreign_function_tables[_JOVE_MAX_BINARIES] = {
  [0 ... _JOVE_MAX_BINARIES - 1] = NULL
};

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <signal.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define _IOV_ENTRY(var) {.iov_base = &var, .iov_len = sizeof(var)}

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define _CTOR    __attribute__((constructor(0)))
#define _INL     __attribute__((always_inline))
#define _NAKED   __attribute__((naked))
#define _NOINL   __attribute__((noinline))
#define _NORET   __attribute__((noreturn))
#define _UNUSED  __attribute__((unused))
#define _HIDDEN  __attribute__((visibility("hidden")))
#define _REGPARM __attribute__((regparm(3)))

#define JOVE_SYS_ATTR _NOINL _HIDDEN
#include "jove_sys.h"

extern /* -> static */ uintptr_t _jove_sections_start_file_addr(void);
extern /* -> static */ uintptr_t _jove_sections_global_beg_addr(void);
extern /* -> static */ uintptr_t _jove_sections_global_end_addr(void);
extern /* -> static */ uint32_t _jove_binary_index(void);
extern /* -> static */ bool _jove_trace_enabled(void);
extern /* -> static */ bool _jove_dfsan_enabled(void);
extern /* -> static */ void _jove_call_entry(void);
extern /* -> static */ uintptr_t *_jove_get_function_table(void);
extern /* -> static */ uintptr_t *_jove_get_dynl_function_table(void);
extern /* -> static */ uintptr_t *_jove_get_vdso_function_table(void);
extern /* -> static */ void _jove_do_tpoff_hack(void);
extern /* -> static */ void _jove_do_emulate_copy_relocations(void);
extern /* -> static */ const char *_jove_dynl_path(void);

extern /* -> static */ uint32_t    _jove_foreign_lib_count(void);
extern /* -> static */ const char *_jove_foreign_lib_path(uint32_t Idx);
extern /* -> static */ uintptr_t  *_jove_foreign_lib_function_table(uint32_t Idx);

_CTOR static void _jove_tpoff_hack(void) {
  _jove_do_tpoff_hack();
}

static bool __jove_did_emu_copy_reloc = false;

_CTOR static void _jove_emulate_copy_relocations(void) {
  if (!__jove_did_emu_copy_reloc) {
    __jove_did_emu_copy_reloc = true;

    _jove_do_emulate_copy_relocations();
  }
}

_CTOR _HIDDEN void _jove_install_function_table(void) {
  __jove_function_tables[_jove_binary_index()] = _jove_get_function_table();
  _jove_do_tpoff_hack(); /* for good measure */

  if (!__jove_did_emu_copy_reloc) {
    __jove_did_emu_copy_reloc = true;

    _jove_do_emulate_copy_relocations();
  }
}

_CTOR static void _jove_install_foreign_function_tables(void);

_HIDDEN
_NAKED void _jove_start(void);
_HIDDEN void _jove_begin(target_ulong sp_addr);

_HIDDEN unsigned long _jove_thread_init(unsigned long clone_newsp);

_NAKED _NOINL target_ulong _jove_thunk(target_ulong dstpc,
                                       target_ulong *args,
                                       target_ulong *emuspp);

_NOINL _HIDDEN void _jove_recover_dyn_target(uint32_t CallerBBIdx,
                                             target_ulong CalleeAddr);

_NOINL _HIDDEN void _jove_recover_basic_block(uint32_t IndBrBBIdx,
                                              target_ulong BBAddr);

_NOINL _HIDDEN void _jove_recover_returned(uint32_t CallerBBIdx);

_NAKED _NOINL _NORET void _jove_fail1(target_ulong);
_NAKED _NOINL _NORET void _jove_fail2(target_ulong, target_ulong);

_NOINL void _jove_check_return_address(target_ulong RetAddr,
                                       target_ulong NativeRetAddr);

#define JOVE_PAGE_SIZE 4096
#define JOVE_STACK_SIZE (256 * JOVE_PAGE_SIZE)

_HIDDEN target_ulong _jove_alloc_stack(void);
_HIDDEN void _jove_free_stack(target_ulong);

_HIDDEN target_ulong _jove_alloc_callstack(void);
_HIDDEN void _jove_free_callstack(target_ulong);

#define JOVE_CALLSTACK_SIZE (32 * JOVE_PAGE_SIZE)

//
// utility functions
//
static _INL unsigned _read_pseudo_file(const char *path, char *out, size_t len);
static _INL uintptr_t _parse_stack_end_of_maps(char *maps, const unsigned n);
static _INL uintptr_t _parse_dynl_load_bias(char *maps, const unsigned n);
static _INL uintptr_t _parse_vdso_load_bias(char *maps, const unsigned n);
static _INL size_t _sum_iovec_lengths(const struct iovec *, unsigned n);
static _INL bool _isDigit(char);
static _INL int _atoi(const char *s);
static _INL size_t _strlen(const char *s);
static _INL unsigned _getDigit(char cdigit, uint8_t radix);
static _INL void *_memchr(const void *s, int c, size_t n);
static _INL void *_memcpy(void *dest, const void *src, size_t n);
static _INL void *_memset(void *dst, int c, size_t n);
static _INL char *_findenv(const char *name, int len, int *offset);
static _INL char *_getenv(const char *name);
static _INL uint64_t _u64ofhexstr(char *str_begin, char *str_end);
static _INL unsigned _getHexDigit(char cdigit);
static _INL uintptr_t _get_stack_end(void);

//
// definitions
//

void _jove_start(void) {
  asm volatile(/* Clear the frame pointer.  The ABI suggests this be done, to
                  mark the outermost frame obviously.  */
               "xorl %%ebp, %%ebp\n"

               /* save original sp */
               "movl %%esp, %%ecx\n"

               /* Align the stack to a 16 byte boundary to follow the ABI. */
               "andl $0xfffffff0, %%esp\n"

               /* pass original sp */
               "pushl %%ecx\n"
               "call _jove_begin\n"

               "hlt\n"

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

static void _jove_trace_init(void);
static void _jove_callstack_init(void);

unsigned long _jove_thread_init(unsigned long clone_newsp) {
  //
  // initialize CPUState
  //
  __jove_env.df = 1;

  //
  // setup the emulated stack
  //
  unsigned long env_stack_beg = _jove_alloc_stack();
  unsigned long env_stack_end = env_stack_beg + JOVE_STACK_SIZE;

  unsigned long env_sp = env_stack_end - JOVE_PAGE_SIZE - 16;

  _memcpy((void *)env_sp , (void *)clone_newsp, 16);

  return env_sp;
}

#define CPUID_XSAVE_XGETBV1    (1U << 2)

void _jove_begin(target_ulong sp_addr) {
  __jove_env.df = 1;
  __jove_env.features[FEAT_XSAVE] |= CPUID_XSAVE_XGETBV1;

  //
  // _jove_startup_info
  //
  {
    uintptr_t addr = sp_addr;

    __jove_startup_info_argc = *((long *)addr);

    addr += sizeof(long);

    __jove_startup_info_argv = (char **)addr;

    addr += __jove_startup_info_argc * sizeof(char *);
    addr += sizeof(char *);

    __jove_startup_info_environ = (char **)addr;
  }

  //
  // setup the stack
  //
  {
    unsigned len = _get_stack_end() - sp_addr;

    unsigned long env_stack_beg = _jove_alloc_stack();
    unsigned long env_stack_end = env_stack_beg + JOVE_STACK_SIZE;

    char *env_sp = (char *)(env_stack_end - JOVE_PAGE_SIZE - len);

    _memcpy(env_sp, (void *)sp_addr, len);

    __jove_env.regs[R_ESP] = (target_ulong)env_sp;
  }

  // trace init (if -trace was passed)
  if (_jove_trace_enabled())
    _jove_trace_init();

  // init callstack (if enabled)
  if (_jove_dfsan_enabled())
    _jove_callstack_init();

  _jove_install_function_table();
  _jove_install_foreign_function_tables();

  return _jove_call_entry();
}

char *_findenv(const char *name, int len, int *offset) {
  int i;
  const char *np;
  char **p, *cp;

  if (name == NULL || __jove_startup_info_environ == NULL)
    return (NULL);
  for (p = __jove_startup_info_environ + *offset; (cp = *p) != NULL; ++p) {
    for (np = name, i = len; i && *cp; i--)
      if (*cp++ != *np++)
        break;
    if (i == 0 && *cp++ == '=') {
      *offset = p - __jove_startup_info_environ;
      return (cp);
    }
  }
  return (NULL);
}

char *_getenv(const char *name) {
  int offset = 0;
  const char *np;

  for (np = name; *np && *np != '='; ++np)
    ;
  return (_findenv(name, (int)(np - name), &offset));
}

uintptr_t _get_stack_end(void) {
  char buff[4096 * 16];
  unsigned n = _read_pseudo_file("/proc/self/maps", buff, sizeof(buff));
  buff[n] = '\0';

  uintptr_t res = _parse_stack_end_of_maps(buff, n);
  return res;
}

void *_memchr(const void *s, int c, size_t n) {
  if (n != 0) {
    const unsigned char *p = s;

    do {
      if (*p++ == (unsigned char)c)
        return ((void *)(p - 1));
    } while (--n != 0);
  }
  return (NULL);
}

unsigned _getHexDigit(char cdigit) {
  unsigned radix = 0x10;

  unsigned r;

  if (radix == 16 || radix == 36) {
    r = cdigit - '0';
    if (r <= 9)
      return r;

    r = cdigit - 'A';
    if (r <= radix - 11U)
      return r + 10;

    r = cdigit - 'a';
    if (r <= radix - 11U)
      return r + 10;

    radix = 10;
  }

  r = cdigit - '0';
  if (r < radix)
    return r;

  return -1U;
}

uint64_t _u64ofhexstr(char *str_begin, char *str_end) {
  const unsigned radix = 0x10;

  uint64_t res = 0;

  char *p = str_begin;
  size_t slen = str_end - str_begin;

  // Figure out if we can shift instead of multiply
  unsigned shift = (radix == 16 ? 4 : radix == 8 ? 3 : radix == 2 ? 1 : 0);

  // Enter digit traversal loop
  for (char *e = str_end; p != e; ++p) {
    unsigned digit = _getHexDigit(*p);

    if (!(digit < radix))
      return 0;

    // Shift or multiply the value by the radix
    if (slen > 1) {
      if (shift)
        res <<= shift;
      else
        res *= radix;
    }

    // Add in the digit we just interpreted
    res += digit;
  }

  return res;
}

uintptr_t _parse_stack_end_of_maps(char *maps, const unsigned n) {
  char *const beg = &maps[0];
  char *const end = &maps[n];

  char *eol;
  for (char *line = beg; line != end; line = eol + 1) {
    unsigned left = n - (line - beg);

    //
    // find the end of the current line
    //
    eol = _memchr(line, '\n', left);

    //
    // second hex address
    //
    if (eol[-1] == ']' &&
        eol[-2] == 'k' &&
        eol[-3] == 'c' &&
        eol[-4] == 'a' &&
        eol[-5] == 't' &&
        eol[-6] == 's' &&
        eol[-7] == '[') {
      char *dash = _memchr(line, '-', left);

      char *space = _memchr(line, ' ', left);
      uint64_t max = _u64ofhexstr(dash + 1, space);
      return max;
    }
  }

  __builtin_trap();
  __builtin_unreachable();
}

unsigned _read_pseudo_file(const char *path, char *out, size_t len) {
  unsigned n;

  {
    int fd = _jove_sys_open(path, O_RDONLY, S_IRWXU);
    if (fd < 0) {
      __builtin_trap();
      __builtin_unreachable();
    }

    // let n denote the number of characters read
    n = 0;

    for (;;) {
      ssize_t ret = _jove_sys_read(fd, &out[n], len - n);

      if (ret == 0)
        break;

      if (ret < 0) {
        if (ret == -EINTR)
          continue;

        __builtin_trap();
        __builtin_unreachable();
      }

      n += ret;
    }

    if (_jove_sys_close(fd) < 0) {
      __builtin_trap();
      __builtin_unreachable();
    }
  }

  return n;
}

void *_memcpy(void *dest, const void *src, size_t n) {
  unsigned char *d = dest;
  const unsigned char *s = src;

  for (; n; n--)
    *d++ = *s++;

  return dest;
}

void *_memset(void *dst, int c, size_t n) {
  if (n != 0) {
    unsigned char *d = dst;

    do
      *d++ = (unsigned char)c;
    while (--n != 0);
  }
  return (dst);
}

static void _jove_sigsegv_handler(void);

void _jove_trace_init(void) {
  int fd =
      _jove_sys_open("trace.bin", O_RDWR | O_CREAT | O_TRUNC, 0666);
  if (fd < 0) {
    __builtin_trap();
    __builtin_unreachable();
  }

  off_t size = 1UL << 30; /* 1 GiB */
  if (_jove_sys_ftruncate(fd, size) < 0) {
    __builtin_trap();
    __builtin_unreachable();
  }

  {
    long ret = _jove_sys_mmap_pgoff(0x0, size, PROT_READ | PROT_WRITE,
                                    MAP_SHARED, fd, 0);

    if (ret < 0 && ret > -4096) {
      __builtin_trap();
      __builtin_unreachable();
    }

    void *ptr = (void *)ret;

    __jove_trace_begin = __jove_trace = ptr;
  }

  if (_jove_sys_close(fd) < 0) {
    __builtin_trap();
    __builtin_unreachable();
  }

#if 0
  //
  // install SIGSEGV handler
  //
  struct kernel_sigaction sa;
  _memset(&sa, 0, sizeof(sa));
  sa._sa_handler = (void *)_jove_sigsegv_handler;

  {
    long ret =
        _jove_sys_rt_sigaction(SIGSEGV, &sa, NULL, sizeof(kernel_sigset_t));
    if (ret < 0) {
      __builtin_trap();
      __builtin_unreachable();
    }
  }
#endif
}

static void _jove_flush_trace(void);

void _jove_sigsegv_handler(void) {
  _jove_flush_trace();

  _jove_sys_exit_group(22);
  __builtin_trap();
  __builtin_unreachable();
}

void _jove_flush_trace(void) {
  if (!__jove_trace || !__jove_trace_begin)
    return;

  size_t len = __jove_trace - __jove_trace_begin;
  len *= sizeof(uint64_t);

  long ret = _jove_sys_msync((unsigned long)__jove_trace_begin, len, MS_SYNC);
  if (ret < 0) {
    __builtin_trap();
    __builtin_unreachable();
  }
}

static char *ulongtostr(char *dst, unsigned long N) {
  char *Str = dst;

  const unsigned Radix = 10;

  // First, check for a zero value and just short circuit the logic below.
  if (N == 0) {
    *Str++ = '0';
    goto out;
  }

  static const char Digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";

  char Buffer[65];
  char *const BufEnd = &Buffer[sizeof(Buffer)];

  char *BufPtr = BufEnd;

  while (N) {
    *--BufPtr = Digits[N % Radix];
    N /= Radix;
  }

  for (char *Ptr = BufPtr; Ptr != BufEnd; ++Ptr)
    *Str++ = *Ptr;

out:
  *Str = '\0';
  return Str;
}

/// A utility function that converts a character to a digit.
unsigned _getDigit(char cdigit, uint8_t radix) {
  unsigned r;

  if (radix == 16 || radix == 36) {
    r = cdigit - '0';
    if (r <= 9)
      return r;

    r = cdigit - 'A';
    if (r <= radix - 11U)
      return r + 10;

    r = cdigit - 'a';
    if (r <= radix - 11U)
      return r + 10;

    radix = 10;
  }

  r = cdigit - '0';
  if (r < radix)
    return r;

  return -1U;
}

size_t _strlen(const char *str) {
  const char *s;

  for (s = str; *s; ++s)
    ;
  return (s - str);
}

int _atoi(const char *s) {
  unsigned res = 0;
  const uint8_t radix = 10;
  // Figure out if we can shift instead of multiply
  unsigned shift = (radix == 16 ? 4 : radix == 8 ? 3 : radix == 2 ? 1 : 0);
  size_t slen = _strlen(s);

  const char *p = s;
  for (const char *e = s + slen; p != e; ++p) {
    unsigned digit = _getDigit(*p, radix);

    // Shift or multiply the value by the radix
    if (slen > 1) {
      if (shift)
        res <<= shift;
      else
        res *= radix;
    }

    // Add in the digit we just interpreted
    res += digit;
  }

  return res;
}

size_t _sum_iovec_lengths(const struct iovec *iov, unsigned n) {
  size_t expected = 0;
  for (unsigned i = 0; i < n; ++i)
    expected += iov[i].iov_len;
  return expected;
}

void _jove_recover_dyn_target(uint32_t CallerBBIdx,
                              target_ulong CalleeAddr) {
#if 0
  char *recover_fifo_path = _getenv("JOVE_RECOVER_FIFO");
  if (!recover_fifo_path)
    return;
#else
  const char *recover_fifo_path = "/jove-recover.fifo";
#endif

  uint32_t CallerBIdx = _jove_binary_index();

  struct {
    uint32_t BIdx;
    uint32_t FIdx;
  } Callee;

  for (unsigned BIdx = 0; BIdx < _JOVE_MAX_BINARIES ; ++BIdx) {
    uintptr_t *fns = __jove_function_tables[BIdx];
    if (!fns) {
      if (BIdx == 1 || BIdx == 2) { /* XXX */
        fns = __jove_foreign_function_tables[BIdx];
        if (!fns)
          continue;
      } else {
        continue;
      }
    }

    if (BIdx == 1 || BIdx == 2) { /* XXX */
      for (unsigned FIdx = 0; fns[FIdx]; ++FIdx) {
        if (CalleeAddr == fns[FIdx]) {
          Callee.BIdx = BIdx;
          Callee.FIdx = FIdx;

          goto found;
        }
      }
    } else {
      for (unsigned FIdx = 0; fns[2 * FIdx]; ++FIdx) {
        if (CalleeAddr == fns[2 * FIdx + 0] ||
            CalleeAddr == fns[2 * FIdx + 1]) {
          Callee.BIdx = BIdx;
          Callee.FIdx = FIdx;

          goto found;
        }
      }
    }
  }

  unsigned N = _jove_foreign_lib_count();
  if (N > 0) {
    //
    // see if this is a function in a foreign DSO
    //
    char maps[4096 * 16];
    unsigned n = _read_pseudo_file("/proc/self/maps", maps, sizeof(maps));
    maps[n] = '\0';

    char *const beg = &maps[0];
    char *const end = &maps[n];

    char *eol;
    for (char *line = beg; line != end; line = eol + 1) {
      unsigned left = n - (line - beg);

      //
      // find the end of the current line
      //
      eol = _memchr(line, '\n', left);

      char *space = _memchr(line, ' ', left);

      char *rp = space + 1;
      char *wp = space + 2;
      char *xp = space + 3;
      char *pp = space + 4;

      if (*xp != 'x') /* is the mapping executable? */
        continue;

      char *dash = _memchr(line, '-', left);

      uint64_t min = _u64ofhexstr(line, dash);
      uint64_t max = _u64ofhexstr(dash + 1, space);

      if (!(CalleeAddr >= min && CalleeAddr < max))
        continue;

      //
      // found the mapping where the address is located
      //
      uint64_t off;
      {
        char *offset = pp + 2;
        char *offset_end = _memchr(offset, ' ', n - (offset - beg));

        off = _u64ofhexstr(offset, offset_end);
      }

      //
      // search the foreign libs
      //
      for (unsigned i = 0; i < N; ++i) {
        const char *foreign_dso_path_beg = _jove_foreign_lib_path(i);
        const unsigned foreign_dso_path_len = _strlen(foreign_dso_path_beg);
        const char *foreign_dso_path_end = &foreign_dso_path_beg[foreign_dso_path_len];

        bool match = true;
        {
          const char *s1 = foreign_dso_path_end - 1;
          const char *s2 = eol - 1;
          for (;;) {
            if (*s1 != *s2) {
              match = false;
              break;
            }

            if (s1 == foreign_dso_path_beg)
              break; /* we're done here */

            --s1;
            --s2;
          }
        }

        if (match) {
          uintptr_t *ForeignFnTbl = _jove_foreign_lib_function_table(i);

          for (unsigned FIdx = 0; ForeignFnTbl[FIdx]; ++FIdx) {
            if (CalleeAddr == ForeignFnTbl[FIdx]) {
              Callee.BIdx = i + 3;
              Callee.FIdx = FIdx;

              goto found;
            }
          }
        }
      }
    }
  }

  return; /* not found */

found:
  {
    int recover_fd = _jove_sys_open(recover_fifo_path, O_WRONLY, 0666);
    if (recover_fd < 0) {
      __builtin_trap();
      __builtin_unreachable();
    }

    {
      char ch = 'f';

      struct iovec iov_arr[] = {
          _IOV_ENTRY(ch),
          _IOV_ENTRY(CallerBIdx),
          _IOV_ENTRY(CallerBBIdx),
          _IOV_ENTRY(Callee.BIdx),
          _IOV_ENTRY(Callee.FIdx)
      };

      size_t expected = _sum_iovec_lengths(iov_arr, ARRAY_SIZE(iov_arr));
      if (_jove_sys_writev(recover_fd, iov_arr, ARRAY_SIZE(iov_arr)) != expected) {
        __builtin_trap();
        __builtin_unreachable();
      }

      _jove_sys_close(recover_fd);
      _jove_sys_exit_group(ch);
    }
  }
}

void _jove_recover_basic_block(uint32_t IndBrBBIdx,
                               target_ulong BBAddr) {
#if 0
  char *recover_fifo_path = _getenv("JOVE_RECOVER_FIFO");
  if (!recover_fifo_path)
    return;
#else
  const char *recover_fifo_path = "/jove-recover.fifo";
#endif

  struct {
    uint32_t BIdx;
    uint32_t BBIdx;
  } IndBr;

  struct {
    uintptr_t Beg;
    uintptr_t End;
  } SectionsGlobal;

  uintptr_t SectsStartFileAddr;

  IndBr.BIdx = _jove_binary_index();
  IndBr.BBIdx = IndBrBBIdx;

  SectionsGlobal.Beg = _jove_sections_global_beg_addr();
  SectionsGlobal.End = _jove_sections_global_end_addr();
  SectsStartFileAddr = _jove_sections_start_file_addr();

  if (!(BBAddr >= SectionsGlobal.Beg && BBAddr < SectionsGlobal.End))
    return; /* not found */

  uintptr_t FileAddr = (BBAddr - SectionsGlobal.Beg) + SectsStartFileAddr;

found:
  {
    int recover_fd = _jove_sys_open(recover_fifo_path, O_WRONLY, 0666);
    if (recover_fd < 0) {
      __builtin_trap();
      __builtin_unreachable();
    }

    {
      char ch = 'b';

      struct iovec iov_arr[] = {
          _IOV_ENTRY(ch),
          _IOV_ENTRY(IndBr.BIdx),
          _IOV_ENTRY(IndBr.BBIdx),
          _IOV_ENTRY(FileAddr)
      };

      size_t expected = _sum_iovec_lengths(iov_arr, ARRAY_SIZE(iov_arr));
      if (_jove_sys_writev(recover_fd, iov_arr, ARRAY_SIZE(iov_arr)) != expected) {
        __builtin_trap();
        __builtin_unreachable();
      }

      _jove_sys_close(recover_fd);
      _jove_sys_exit_group(ch);
    }
  }
}

void _jove_recover_returned(uint32_t CallerBBIdx) {
#if 0
  char *recover_fifo_path = _getenv("JOVE_RECOVER_FIFO");
  if (!recover_fifo_path)
    return;
#else
  const char *recover_fifo_path = "/jove-recover.fifo";
#endif

  struct {
    uint32_t BIdx;
    uint32_t BBIdx;
  } Call;

  Call.BIdx = _jove_binary_index();
  Call.BBIdx = CallerBBIdx;

found:
  {
    int recover_fd = _jove_sys_open(recover_fifo_path, O_WRONLY, 0666);
    if (recover_fd < 0) {
      __builtin_trap();
      __builtin_unreachable();
    }

    {
      char ch = 'r';

      struct iovec iov_arr[] = {
          _IOV_ENTRY(ch),
          _IOV_ENTRY(Call.BIdx),
          _IOV_ENTRY(Call.BBIdx)
      };

      size_t expected = _sum_iovec_lengths(iov_arr, ARRAY_SIZE(iov_arr));
      if (_jove_sys_writev(recover_fd, iov_arr, ARRAY_SIZE(iov_arr)) != expected) {
        __builtin_trap();
        __builtin_unreachable();
      }

      _jove_sys_close(recover_fd);
      _jove_sys_exit_group(ch);
    }
  }
}

void _jove_fail1(target_ulong x) {
  asm volatile("mov 0x4(%esp), %eax\n" /* x in eax */
               "hlt");
}

void _jove_fail2(target_ulong x,
                 target_ulong y) {
  asm volatile("hlt");
}

target_ulong _jove_thunk(target_ulong dstpc,
                         target_ulong *args,
                         target_ulong *emuspp) {
  asm volatile("push %%ebp\n" /* callee-saved registers */
               "push %%edi\n"
               "push %%esi\n"
               "push %%ebx\n"

               "movl 0x14(%%esp), %%ebx\n" /* dstpc in ebx */
               "movl 0x18(%%esp), %%esi\n" /* args in esi */
               "movl 0x1c(%%esp), %%edi\n" /* emuspp in edi */

               "call _jove_alloc_stack\n"
               "pushl %%eax\n"

               "movl %%esp, %%ebp\n" /* save sp in ebp */

               "addl $0x80000, %%eax\n"

               "movl (%%edi), %%esp\n" /* sp=*emusp */
               "movl %%eax, (%%edi)\n" /* *emusp=stack storage */

               /* -- unpack args -- */
               "movl 0x0(%%esi), %%eax\n"
               "movl 0x4(%%esi), %%edx\n"
               "movl 0x8(%%esi), %%ecx\n"

               "addl $4, %%esp\n" /* replace return address on the stack */
               "call *%%ebx\n"   /* call dstpc */

               "movl %%eax, %%esi\n" /* save return value in esi */
               "movl %%edx, %%ebx\n" /* save return value in ebx */

               "movl %%esp, (%%edi)\n" /* store modified emusp */
               "movl %%ebp, %%esp\n"   /* restore stack pointer */

               //
               // free stack
               //
               "call _jove_free_stack\n"
               "addl $4, %%esp\n"

               //
               // restore return values
               //
               "movl %%esi, %%eax\n"
               "movl %%ebx, %%edx\n"

               "popl %%ebx\n"
               "popl %%esi\n"
               "popl %%edi\n"
               "popl %%ebp\n" /* callee-saved registers */

               "ret\n"

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

bool _isDigit(char C) { return C >= '0' && C <= '9'; }

uintptr_t _parse_dynl_load_bias(char *maps, const unsigned n) {
  char *const beg = &maps[0];
  char *const end = &maps[n];

  const char *const dynl_path_beg = _jove_dynl_path();
  const unsigned    dynl_path_len = _strlen(dynl_path_beg);
  const char *const dynl_path_end = &dynl_path_beg[dynl_path_len];

  char *eol;
  for (char *line = beg; line != end; line = eol + 1) {
    unsigned left = n - (line - beg);

    //
    // find the end of the current line
    //
    eol = _memchr(line, '\n', left);

    //
    // second hex address
    //
    bool match = true;

    {
      const char *s1 = dynl_path_end - 1;
      const char *s2 = eol - 1;
      for (;;) {
        if (*s1 != *s2) {
          match = false;
          break;
        }

        if (s1 == dynl_path_beg)
          break; /* we're done here */

        --s1;
        --s2;
      }
    }

    if (match) {
      char *space = _memchr(line, ' ', left);

      char *rp = space + 1;
      char *wp = space + 2;
      char *xp = space + 3;
      char *pp = space + 4;

      bool x = *xp == 'x';
      if (!x)
        continue;

      char *dash = _memchr(line, '-', left);
      uint64_t res = _u64ofhexstr(line, dash);

      // offset may be nonzero for dynamic linker
      uint64_t off;
      {
        char *offset = pp + 2;
        unsigned _left = n - (offset - beg);
        char *offset_end = _memchr(offset, ' ', _left);

        off = _u64ofhexstr(offset, offset_end);
      }

      return res - off;
    }
  }

  __builtin_trap();
  __builtin_unreachable();
}

uintptr_t _parse_vdso_load_bias(char *maps, const unsigned n) {
  char *const beg = &maps[0];
  char *const end = &maps[n];

  char *eol;
  for (char *line = beg; line != end; line = eol + 1) {
    unsigned left = n - (line - beg);

    //
    // find the end of the current line
    //
    eol = _memchr(line, '\n', left);

    //
    // second hex address
    //
    if (eol[-1] == ']' &&
        eol[-2] == 'o' &&
        eol[-3] == 's' &&
        eol[-4] == 'd' &&
        eol[-5] == 'v' &&
        eol[-6] == '[') {
      char *dash = _memchr(line, '-', left);
      return _u64ofhexstr(line, dash);
    }
  }

  __builtin_trap();
  __builtin_unreachable();
}

static bool __jove_installed_foreign_function_tables = false;

void _jove_install_foreign_function_tables(void) {
  if (__jove_installed_foreign_function_tables)
    return;
  __jove_installed_foreign_function_tables = true;

  /* we need to get the load addresses for the dynamic linker and VDSO by
   * parsing /proc/self/maps */
  char maps[4096 * 16];
  unsigned n = _read_pseudo_file("/proc/self/maps", maps, sizeof(maps));
  maps[n] = '\0';

  uintptr_t dynl_load_bias = _parse_dynl_load_bias(maps, n);
  uintptr_t vdso_load_bias = _parse_vdso_load_bias(maps, n);

  uintptr_t *dynl_fn_tbl = _jove_get_dynl_function_table();
  uintptr_t *vdso_fn_tbl = _jove_get_vdso_function_table();

  for (uintptr_t *p = dynl_fn_tbl; *p; ++p)
    *p += dynl_load_bias;
  for (uintptr_t *p = vdso_fn_tbl; *p; ++p)
    *p += vdso_load_bias;

  __jove_foreign_function_tables[1] = dynl_fn_tbl;
  __jove_foreign_function_tables[2] = vdso_fn_tbl;

  unsigned N = _jove_foreign_lib_count();
  if (N > 0) {
    char *const beg = &maps[0];
    char *const end = &maps[n];

    char *eol;
    for (char *line = beg; line != end; line = eol + 1) {
      unsigned left = n - (line - beg);

      //
      // find the end of the current line
      //
      eol = _memchr(line, '\n', left);

      char *space = _memchr(line, ' ', left);

      char *rp = space + 1;
      char *wp = space + 2;
      char *xp = space + 3;
      char *pp = space + 4;

      if (*xp != 'x') /* is the mapping executable? */
        continue;

      char *dash = _memchr(line, '-', left);

      uint64_t min = _u64ofhexstr(line, dash);
      uint64_t max = _u64ofhexstr(dash + 1, space);

      //
      // found the mapping where the address is located
      //
      uint64_t off;
      {
        char *offset = pp + 2;
        char *offset_end = _memchr(offset, ' ', n - (offset - beg));

        off = _u64ofhexstr(offset, offset_end);
      }

      //
      // search the foreign libs
      //
      for (unsigned i = 0; i < N; ++i) {
        const char *foreign_dso_path_beg = _jove_foreign_lib_path(i);
        const unsigned foreign_dso_path_len = _strlen(foreign_dso_path_beg);
        const char *foreign_dso_path_end = &foreign_dso_path_beg[foreign_dso_path_len];

        bool match = true;
        {
          const char *s1 = foreign_dso_path_end - 1;
          const char *s2 = eol - 1;
          for (;;) {
            if (*s1 != *s2) {
              match = false;
              break;
            }

            if (s1 == foreign_dso_path_beg)
              break; /* we're done here */

            --s1;
            --s2;
          }
        }

        if (match) {
          uintptr_t *foreign_fn_tbl = _jove_foreign_lib_function_table(i);

          uintptr_t load_bias = min - off;
          for (unsigned FIdx = 0; foreign_fn_tbl[FIdx]; ++FIdx)
            foreign_fn_tbl[FIdx] += load_bias;

          __jove_foreign_function_tables[i + 3] = foreign_fn_tbl; /* install */
          break;
        }
      }
    }
  }
}

target_ulong _jove_alloc_stack(void) {
  long ret = _jove_sys_mmap_pgoff(0x0, JOVE_STACK_SIZE, PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1L, 0);
  if (ret < 0 && ret > -4096) {
    __builtin_trap();
    __builtin_unreachable();
  }

  unsigned long uret = (unsigned long)ret;

  //
  // create guard pages on both sides
  //
  unsigned long beg = uret;
  unsigned long end = beg + JOVE_STACK_SIZE;

  if (_jove_sys_mprotect(beg, JOVE_PAGE_SIZE, PROT_NONE) < 0) {
    __builtin_trap();
    __builtin_unreachable();
  }

  if (_jove_sys_mprotect(end - JOVE_PAGE_SIZE, JOVE_PAGE_SIZE, PROT_NONE) < 0) {
    __builtin_trap();
    __builtin_unreachable();
  }

  return beg;
}

void _jove_free_stack(target_ulong beg) {
  if (_jove_sys_munmap(beg, JOVE_STACK_SIZE) < 0) {
    __builtin_trap();
    __builtin_unreachable();
  }
}

target_ulong _jove_alloc_callstack(void) {
  long ret = _jove_sys_mmap_pgoff(0x0, JOVE_CALLSTACK_SIZE, PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1L, 0);
  if (ret < 0 && ret > -4096) {
    __builtin_trap();
    __builtin_unreachable();
  }

  unsigned long uret = (unsigned long)ret;

  //
  // create guard pages on both sides
  //
  unsigned long beg = uret;
  unsigned long end = beg + JOVE_CALLSTACK_SIZE;

  if (_jove_sys_mprotect(beg, JOVE_PAGE_SIZE, PROT_NONE) < 0) {
    __builtin_trap();
    __builtin_unreachable();
  }

  if (_jove_sys_mprotect(end - JOVE_PAGE_SIZE, JOVE_PAGE_SIZE, PROT_NONE) < 0) {
    __builtin_trap();
    __builtin_unreachable();
  }

  return beg;
}

void _jove_free_callstack(target_ulong start) {
  if (_jove_sys_munmap(start - JOVE_PAGE_SIZE /* XXX */, JOVE_CALLSTACK_SIZE) < 0) {
    __builtin_trap();
    __builtin_unreachable();
  }
}


static bool _jove_is_readable_mem(target_ulong Addr);
static bool _jove_is_foreign_code(target_ulong Addr);

void _jove_check_return_address(target_ulong RetAddr,
                                target_ulong NativeRetAddr) {
  static const target_ulong Cookie = 0xd27b9f5a;
  if (likely(RetAddr == Cookie))
    return;

  if (_jove_is_readable_mem(NativeRetAddr) &&
      _jove_is_foreign_code(NativeRetAddr))
    return; /* the return address is bogus because foreign code is calling into
               recompiled code */

  __builtin_trap();
  __builtin_unreachable();
}

bool _jove_is_readable_mem(target_ulong Addr) {
  pid_t pid;
  {
    long ret = _jove_sys_getpid();
    if (unlikely(ret < 0)) {
      __builtin_trap();
      __builtin_unreachable();
    }
    pid = ret;
  }

  struct iovec lvec[1];
  struct iovec rvec[1];

  uint8_t byte;

  lvec[0].iov_base = &byte;
  lvec[0].iov_len = sizeof(byte);

  rvec[0].iov_base = (void *)Addr;
  rvec[0].iov_len = sizeof(byte);

  long ret = _jove_sys_process_vm_readv(pid,
                                        lvec, ARRAY_SIZE(lvec),
                                        rvec, ARRAY_SIZE(rvec),
                                        0);

  return ret == sizeof(byte);
}

static bool _is_foreign_code_of_maps(char *maps, const unsigned n,
                                     target_ulong Addr);

bool _jove_is_foreign_code(target_ulong Addr) {
  char buff[4096 * 16];
  unsigned n = _read_pseudo_file("/proc/self/maps", buff, sizeof(buff));
  buff[n] = '\0';

  uintptr_t res = _is_foreign_code_of_maps(buff, n, Addr);
  return res;
}

// precondition: Addr must point to valid virtual memory area
bool _is_foreign_code_of_maps(char *maps, const unsigned n, target_ulong Addr) {
  char *const beg = &maps[0];
  char *const end = &maps[n];

  char *eol;
  for (char *line = beg; line != end; line = eol + 1) {
    {
      unsigned left = n - (line - beg);

      //
      // find the end of the current line
      //
      eol = _memchr(line, '\n', left);
    }

    struct {
      uint64_t min, max;
    } vm;

    {
      unsigned left = eol - line;

      char *dash = _memchr(line, '-', left);
      vm.min = _u64ofhexstr(line, dash);

      char *space = _memchr(line, ' ', left);
      vm.max = _u64ofhexstr(dash + 1, space);
    }

    if (Addr >= vm.min && Addr < vm.max) {
      return (eol[-1] == ']'
           && eol[-2] == 'o'
           && eol[-3] == 's'
           && eol[-4] == 'd'
           && eol[-5] == 'v'
           && eol[-6] == '[')
        ||
             (eol[-1]  == 'o'
           && eol[-2]  == 's'
           && eol[-3]  == '.'
           && _isDigit(eol[-4])
           && _isDigit(eol[-5])
           && eol[-6]  == '.'
           && _isDigit(eol[-7])
           && eol[-8]  == '-'
           && eol[-9]  == 'd'
           && eol[-10] == 'l'
           && eol[-11] == '/'
           && eol[-12] == 'b'
           && eol[-13] == 'i'
           && eol[-14] == 'l'
           && eol[-15] == '/'
           && eol[-16] == 'r'
           && eol[-17] == 's'
           && eol[-18] == 'u'
           && eol[-19] == '/');
    }
  }

  __builtin_trap();
  __builtin_unreachable();
}

void _jove_callstack_init(void) {
  uintptr_t ptr = _jove_alloc_callstack();

  __jove_callstack_begin = __jove_callstack = (void *)(ptr + JOVE_PAGE_SIZE);
}

typedef uint16_t dfsan_label;

static const uint64_t DF32_ADDR_SPACE_SIZE = 0xffffffffull + 1ull;
static const unsigned DF32_PAGE_SIZE = 4 * 1024; /* 4 KiB */
static const unsigned DF32_SHADOW_PAGE_SIZE = 16 * DF32_PAGE_SIZE; /* 64 KiB */
static const unsigned DF32_NUM_PAGES = DF32_ADDR_SPACE_SIZE / DF32_SHADOW_PAGE_SIZE;

extern dfsan_label *__df32_shadow_page_table[DF32_NUM_PAGES];

#ifdef JOVE_DFSAN
_HIDDEN
#else
static
#endif
dfsan_label *__df32_shadow_for(uint32_t A) {
  unsigned quot = A / DF32_SHADOW_PAGE_SIZE;
  unsigned rem  = A % DF32_SHADOW_PAGE_SIZE;

#define page_bits_ptr __df32_shadow_page_table[quot]

  if (unlikely(!page_bits_ptr)) {
    long ret = _jove_sys_mmap_pgoff(0x0,
                                    (sizeof(dfsan_label) * DF32_SHADOW_PAGE_SIZE)
                                    + 2 * DF32_PAGE_SIZE /* extra space */
                                    + 2 * DF32_PAGE_SIZE /* guard pages */,
                                    PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1L, 0);
    if (ret < 0 && ret > -4096) {
      __builtin_trap();
      __builtin_unreachable();
    }

    if (ret == 0) {
      __builtin_trap();
      __builtin_unreachable();
    }

    //
    // create guard pages on both sides
    //
    if (_jove_sys_mprotect(ret, DF32_PAGE_SIZE, PROT_NONE) < 0) {
      __builtin_trap();
      __builtin_unreachable();
    }

    if (_jove_sys_mprotect(
            ret + DF32_PAGE_SIZE + /* guard page */
                (sizeof(dfsan_label) * DF32_SHADOW_PAGE_SIZE) /* labels */ +
                2 * DF32_PAGE_SIZE /* extra space */,
            DF32_PAGE_SIZE, PROT_NONE) < 0) {
      __builtin_trap();
      __builtin_unreachable();
    }

    page_bits_ptr = (dfsan_label *)(ret + DF32_PAGE_SIZE);

    //internal_memset(&page_bits_ptr[0], 0, sizeof(dfsan_label) * _PAGE_SIZE);
  }

  return &page_bits_ptr[rem];
}
