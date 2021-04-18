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

/* __thread */ struct CPUX86State __jove_env;

/* __thread */ uint64_t *__jove_trace       = NULL;
/* __thread */ uint64_t *__jove_trace_begin = NULL;

/* __thread */ uint64_t *__jove_callstack       = NULL;
/* __thread */ uint64_t *__jove_callstack_begin = NULL;

#define _JOVE_MAX_BINARIES 512

uintptr_t *__jove_function_tables[_JOVE_MAX_BINARIES] = {
    [0 ... _JOVE_MAX_BINARIES - 1] = NULL
};

int    __jove_startup_info_argc = 0;
char **__jove_startup_info_argv = NULL;
char **__jove_startup_info_environ = NULL;

#  define __user

#define _NSIG		64

# define _NSIG_BPW	32

#define _NSIG_WORDS	(_NSIG / _NSIG_BPW)

typedef struct {
	unsigned long sig[_NSIG_WORDS];
} kernel_sigset_t;

typedef void __signalfn_t(int);

typedef __signalfn_t __user *__sighandler_t;

typedef void __restorefn_t(void);

typedef __restorefn_t __user *__sigrestore_t;

#define __ARCH_HAS_SA_RESTORER

struct kernel_sigaction {
#ifndef __ARCH_HAS_IRIX_SIGACTION
	__sighandler_t	sa_handler;
	unsigned long	sa_flags;
#else
	unsigned int	sa_flags;
	__sighandler_t	sa_handler;
#endif
#ifdef __ARCH_HAS_SA_RESTORER
	__sigrestore_t sa_restorer;
#endif
	kernel_sigset_t	sa_mask;	/* mask last for extensibility */
};

#define _GNU_SOURCE /* for REG_EIP */
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
#include <ucontext.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define _CTOR   __attribute__((constructor(0)))
#define _INL    __attribute__((always_inline))
#define _UNUSED __attribute__((unused))
#define _NAKED  __attribute__((naked))
#define _NOINL  __attribute__((noinline))
#define _NORET  __attribute__((noreturn))
#define _HIDDEN __attribute__((visibility("hidden")))
#define _REGPARM __attribute__((regparm(3)))

#define JOVE_SYS_ATTR _HIDDEN _UNUSED
#include "jove_sys.h"

static void _jove_rt_signal_handler(int, siginfo_t *, ucontext_t *);
_NAKED static void _jove_do_rt_sigreturn(void);
_NAKED static void _jove_inverse_thunk(void);
static void _jove_callstack_init(void);
static void _jove_trace_init(void);
static void _jove_init_cpu_state(void);

#define JOVE_PAGE_SIZE 4096
#define JOVE_STACK_SIZE (256 * JOVE_PAGE_SIZE)

static target_ulong _jove_alloc_callstack(void);
_REGPARM _HIDDEN void _jove_free_callstack(target_ulong);

static target_ulong _jove_alloc_stack(void);
_REGPARM _HIDDEN void _jove_free_stack(target_ulong);

_HIDDEN uintptr_t _jove_emusp_location(void);
_HIDDEN uintptr_t _jove_callstack_location(void);
_HIDDEN uintptr_t _jove_callstack_begin_location(void);
_REGPARM _HIDDEN void _jove_free_stack_later(target_ulong);

#define JOVE_CALLSTACK_SIZE (32 * JOVE_PAGE_SIZE)

//
// utility functions
//
static _INL void *_memset(void *dst, int c, size_t n);
static _INL void *_memcpy(void *dest, const void *src, size_t n);
static _INL size_t _strlen(const char *s);
static _INL void _addrtostr(uintptr_t addr, char *dst, size_t n);

//
// definitions
//

void _jove_do_rt_sigreturn(void) {
  asm volatile("movl   $0xad,%eax\n"
               "int    $0x80\n");
}

void _jove_inverse_thunk(void) {
  asm volatile("pushl $0xdead\n"
               "pushl %%eax\n" /* preserve return registers */
               "pushl %%edx\n"

               //
               // restore emulated stack pointer
               //
               "call _jove_emusp_location\n" // eax = emuspp

               "movl (%%eax), %%edx\n"   // edx = emusp
               "movl %%edx, 8(%%esp)\n" // replace 0xdead with emusp

               "movl 20(%%esp), %%edx\n" // edx = saved_emusp
               "movl %%edx, (%%eax)\n"   // restore emusp

               //
               // free the callstack we allocated in sighandler
               //
               "call _jove_callstack_begin_location\n"
               "movl (%%eax), %%eax\n"
               "call _jove_free_callstack\n"

               //
               // restore __jove_callstack
               //
               "call _jove_callstack_location\n" // eax = &__jove_callstack

               "movl 24(%%esp), %%edx\n" // edx = saved_callstack
               "movl %%edx, (%%eax)\n"   // restore callstack

               //
               // restore __jove_callstack_begin
               //
               "call _jove_callstack_begin_location\n" // eax = &__jove_callstack_begin

               "movl 28(%%esp), %%edx\n" // edx = saved_callstack_begin
               "movl %%edx, (%%eax)\n"   // restore callstack_begin

               //
               // mark newstack as to be freed
               //
               "movl 32(%%esp), %%eax\n" // eax = newstack
               "call _jove_free_stack_later\n"

               //
               // ecx is the *only* register we can clobber
               //
               "movl 12(%%esp), %%ecx\n" // ecx = saved_retaddr

               "popl %%edx\n"
               "popl %%eax\n"
               "popl %%esp\n"

               "jmp *%%ecx\n"

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

static _CTOR void _jove_rt_init(void) {
  struct kernel_sigaction sa;
  _memset(&sa, 0, sizeof(sa));

#undef sa_handler
#undef sa_restorer
#undef sa_flags

  sa.sa_handler = _jove_rt_signal_handler;
  sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
  sa.sa_restorer = _jove_do_rt_sigreturn;

  {
    long ret =
        _jove_sys_rt_sigaction(SIGSEGV, &sa, NULL, sizeof(kernel_sigset_t));
    if (ret < 0) {
      __builtin_trap();
      __builtin_unreachable();
    }
  }

  target_ulong newstack = _jove_alloc_stack();

  stack_t uss = {.ss_sp = newstack + JOVE_PAGE_SIZE,
                 .ss_flags = 0,
                 .ss_size = JOVE_STACK_SIZE - 2 * JOVE_PAGE_SIZE};
  {
    long ret = _jove_sys_sigaltstack(&uss, NULL);
    if (ret < 0) {
      __builtin_trap();
      __builtin_unreachable();
    }
  }

  _jove_callstack_init();
  _jove_trace_init();
  _jove_init_cpu_state();
}

static target_ulong to_free[16];

void _jove_rt_signal_handler(int sig, siginfo_t *si, ucontext_t *uctx) {
#define pc    uctx->uc_mcontext.gregs[REG_EIP]
#define sp    uctx->uc_mcontext.gregs[REG_ESP]
#define emusp           __jove_env.regs[R_ESP]

  //
  // no time like the present
  //
  for (unsigned i = 0; i < ARRAY_SIZE(to_free); ++i) {
    if (to_free[i] == 0)
      continue;

    _jove_free_stack(to_free[i]);
    to_free[i] = 0;
  }

  uintptr_t saved_pc = pc;

  for (unsigned BIdx = 0; BIdx < _JOVE_MAX_BINARIES; ++BIdx) {
    if (BIdx == 1 ||
        BIdx == 2)
      continue; /* rtld or vdso */

    uintptr_t *fns = __jove_function_tables[BIdx];

    if (!fns)
      continue;

    for (unsigned FIdx = 0; fns[2 * FIdx]; ++FIdx) {
      if (saved_pc != fns[2 * FIdx + 0])
        continue;

      uintptr_t saved_sp = sp;
      uintptr_t saved_emusp = emusp;
      uintptr_t saved_retaddr = *((uintptr_t *)saved_sp);
      uintptr_t saved_callstack       = (uintptr_t)__jove_callstack;
      uintptr_t saved_callstack_begin = (uintptr_t)__jove_callstack_begin;

      //
      // real stack becomes emulated stack
      //
      emusp = saved_sp;

      {
        const uintptr_t newstack = _jove_alloc_stack();

        uintptr_t newsp =
            newstack + JOVE_STACK_SIZE - JOVE_PAGE_SIZE - 7 * sizeof(uintptr_t);

        newsp &= 0xfffffff0; // align the stack

        ((uintptr_t *)newsp)[0] = _jove_inverse_thunk;
        ((uintptr_t *)newsp)[1] = saved_retaddr;
        ((uintptr_t *)newsp)[2] = saved_sp;
        ((uintptr_t *)newsp)[3] = saved_emusp;
        ((uintptr_t *)newsp)[4] = saved_callstack;
        ((uintptr_t *)newsp)[5] = saved_callstack_begin;
        ((uintptr_t *)newsp)[6] = newstack;

        sp = newsp;
      }

      {
        const uintptr_t new_callsp = _jove_alloc_callstack();

        __jove_callstack_begin = __jove_callstack = new_callsp + JOVE_PAGE_SIZE;
      }

      pc = fns[2 * FIdx + 1];

      return;
    }
  }

#undef emusp
#undef sp
#undef pc

  //
  // if we get here, this is most likely a real crash.
  //
  __builtin_trap();
  __builtin_unreachable();
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

void _jove_free_stack_later(target_ulong stack) {
  for (unsigned i = 0; i < ARRAY_SIZE(to_free); ++i) {
    if (to_free[i] != 0)
      continue;

    to_free[i] = stack;
    return;
  }

  __builtin_trap();
  __builtin_unreachable();
}

void _addrtostr(uintptr_t addr, char *Str, size_t n) {
  const unsigned Radix = 16;
  const bool formatAsCLiteral = true;
  const bool Signed = false;

#if 0
  assert((Radix == 10 || Radix == 8 || Radix == 16 || Radix == 2 ||
          Radix == 36) &&
         "Radix should be 2, 8, 10, 16, or 36!");
#endif

  const char *Prefix = "";
  if (formatAsCLiteral) {
    switch (Radix) {
      case 2:
        // Binary literals are a non-standard extension added in gcc 4.3:
        // http://gcc.gnu.org/onlinedocs/gcc-4.3.0/gcc/Binary-constants.html
        Prefix = "0b";
        break;
      case 8:
        Prefix = "0";
        break;
      case 10:
        break; // No prefix
      case 16:
        Prefix = "0x";
        break;
      default: /* invalid radix */
        __builtin_trap();
        __builtin_unreachable();
    }
  }

  // First, check for a zero value and just short circuit the logic below.
  if (addr == 0) {
    while (*Prefix)
      *Str++ = *Prefix++;

    *Str++ = '0';
    *Str++ = '\0'; /* null-terminate */
    return;
  }

  static const char Digits[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

  char Buffer[65];
  char *BufPtr = &Buffer[sizeof(Buffer)];

  uint64_t N = addr;

  while (*Prefix)
    *Str++ = *Prefix++;

  while (N) {
    *--BufPtr = Digits[N % Radix];
    N /= Radix;
  }

  for (char *Ptr = BufPtr; Ptr != &Buffer[sizeof(Buffer)]; ++Ptr)
    *Str++ = *Ptr;

  *Str = '\0';
}

size_t _strlen(const char *str) {
  const char *s;

  for (s = str; *s; ++s)
    ;
  return (s - str);
}

void _jove_callstack_init(void) {
  target_ulong ptr = _jove_alloc_callstack();

  __jove_callstack_begin = __jove_callstack = ptr + JOVE_PAGE_SIZE;
}

void _jove_trace_init(void) {
  static uint64_t zeros[4 * 4096] = {0};

  __jove_trace = &zeros[0];
}

void _jove_init_cpu_state(void) {
  __jove_env.df = 1;
}

uintptr_t _jove_emusp_location(void) {
  return &__jove_env.regs[R_ESP];
}

uintptr_t _jove_callstack_location(void) {
  return &__jove_callstack;
}

uintptr_t _jove_callstack_begin_location(void) {
  return &__jove_callstack_begin;
}
