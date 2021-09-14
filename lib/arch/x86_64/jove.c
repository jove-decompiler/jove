#define TARGET_X86_64 1

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

typedef uint64_t target_ulong;

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

#include <stddef.h>

extern /* __thread */ struct CPUX86State __jove_env;

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

#include "jove.constants.h"
#include "jove.macros.h"

#define JOVE_SYS_ATTR _INL _UNUSED
#include "jove_sys.h"

_HIDDEN uintptr_t _jove_alloc_stack(void);
_HIDDEN void _jove_free_stack(uintptr_t);

#include "jove.llvm.c"
#include "jove.util.c"
#include "jove.arch.c"
#include "jove.common.c"
#include "jove.recover.c"

_HIDDEN
_NAKED void _jove_start(void);
static void _jove_begin(uint64_t rdi,
                        uint64_t rsi,
                        uint64_t rdx,
                        uint64_t rcx,
                        uint64_t r8,
                        uint64_t sp_addr /* formerly r9 */);

_HIDDEN unsigned long _jove_thread_init(unsigned long clone_newsp);

_NAKED __int128 _jove_thunk0(uint64_t dstpc,
                             uint64_t *emuspp);

_NAKED __int128 _jove_thunk1(uint64_t rdi,
                             uint64_t dstpc,
                             uint64_t *emuspp);

_NAKED __int128 _jove_thunk2(uint64_t rdi,
                             uint64_t rsi,
                             uint64_t dstpc,
                             uint64_t *emuspp);

_NAKED __int128 _jove_thunk3(uint64_t rdi,
                             uint64_t rsi,
                             uint64_t rdx,
                             uint64_t dstpc,
                             uint64_t *emuspp);

_NAKED __int128 _jove_thunk4(uint64_t rdi,
                             uint64_t rsi,
                             uint64_t rdx,
                             uint64_t rcx,
                             uint64_t dstpc,
                             uint64_t *emuspp);

_NAKED __int128 _jove_thunk5(uint64_t rdi,
                             uint64_t rsi,
                             uint64_t rdx,
                             uint64_t rcx,
                             uint64_t r8,
                             uint64_t dstpc,
                             uint64_t *emuspp);

_NAKED __int128 _jove_thunk6(uint64_t rdi,
                             uint64_t rsi,
                             uint64_t rdx,
                             uint64_t rcx,
                             uint64_t r8,
                             uint64_t r9,
                             uint64_t dstpc,
                             uint64_t *emuspp);

void _jove_start(void) {
  asm volatile(/* Clearing frame pointer is insufficient, use CFI.  */
               ".cfi_undefined %%rip\n"

                /* Clear the frame pointer.  The ABI suggests this be done, to
                  mark the outermost frame obviously.  */
               "xorq %%rbp, %%rbp\n"

               "movq %%rsp, %%r9\n"

		/* Align the stack to a 16 byte boundary to follow the ABI.  */
               "and  $~15, %%rsp\n"
               "call %P0\n"
               "hlt\n" /* Crash if somehow `_jove_begin' does return. */

               : /* OutputOperands */
               : /* InputOperands */
               "i"(_jove_begin)
               : /* Clobbers */);
}

//_HIDDEN uintptr_t _jove_alloc_callstack(void);
//_HIDDEN void _jove_free_callstack(uintptr_t);

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

static void _jove_trace_init(void);
static void _jove_callstack_init(void);

void _jove_begin(uint64_t rdi,
                 uint64_t rsi,
                 uint64_t rdx,
                 uint64_t rcx,
                 uint64_t r8,
                 uint64_t sp_addr /* formerly r9 */) {
  __jove_env.regs[R_EDI] = rdi;
  __jove_env.regs[R_ESI] = rsi;
  __jove_env.regs[R_EDX] = rdx;
  __jove_env.regs[R_ECX] = rcx;
  __jove_env.regs[R_R8] = r8;
  __jove_env.df = 1;

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

  // init trace (if enabled)
  if (_jove_trace_enabled())
    _jove_trace_init();

  // init callstack (if enabled)
  if (_jove_dfsan_enabled())
    _jove_callstack_init();

  _jove_init();

  return _jove_call_entry();
}

void _jove_trace_init(void) {
  if (__jove_trace)
    return;

  int fd =
      _jove_sys_open("trace.bin", O_RDWR | O_CREAT | O_TRUNC, 0666);
  if (fd < 0)
    _UNREACHABLE();

  off_t size = 1UL << 31; /* 2 GiB */
  if (_jove_sys_ftruncate(fd, size) < 0)
    _UNREACHABLE();

  {
    long ret =
        _jove_sys_mmap(0x0, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (ret < 0 && ret > -4096)
      _UNREACHABLE();

    void *ptr = (void *)ret;

    __jove_trace_begin = __jove_trace = ptr;
  }

  if (_jove_sys_close(fd) < 0)
    _UNREACHABLE();
}

void _jove_callstack_init(void) {
  long ret = _jove_sys_mmap(0x0, JOVE_CALLSTACK_SIZE, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1L, 0);
  if (ret < 0 && ret > -4096)
    _UNREACHABLE();

  void *ptr = (void *)ret;

  //
  // create guard pages on both sides
  //
  unsigned long beg = (unsigned long)ret;
  unsigned long end = beg + JOVE_CALLSTACK_SIZE;

  if (_jove_sys_mprotect(beg, JOVE_PAGE_SIZE, PROT_NONE) < 0)
    _UNREACHABLE();

  if (_jove_sys_mprotect(end - JOVE_PAGE_SIZE, JOVE_PAGE_SIZE, PROT_NONE) < 0)
    _UNREACHABLE();

  __jove_callstack_begin = __jove_callstack = ptr + JOVE_PAGE_SIZE;
}

#define JOVE_THUNK_PROLOGUE                                                    \
  "pushq %%r15\n"                                                              \
  "pushq %%r14\n"                                                              \
  "pushq %%r13\n"                                                              \
  "pushq %%r12\n"                                                              \
                                                                               \
  "movq %%rsp, %%r15\n" /* save sp in r15 */

#define JOVE_THUNK_EPILOGUE                                                    \
  "movq %%rsp, (%%r14)\n" /* store modified emusp */                           \
  "movq %%r15, %%rsp\n" /* restore stack pointer */                            \
                                                                               \
  "popq %%r12\n"                                                               \
  "popq %%r13\n"                                                               \
  "popq %%r14\n"                                                               \
  "popq %%r15\n"                                                               \
  "retq\n"

__int128 _jove_thunk0(uint64_t dstpc   /* rdi */,
                      uint64_t *emuspp /* rsi */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "movq %%rsi, %%r14\n" /* emuspp in r14 */

               "movq (%%rsi), %%rsp\n" /* sp=emusp */
               "xorq %%rax, %%rax\n"
               "movq %%rax, (%%rsi)\n" /* emusp=0x0 */

               /* args: nothing to do */

               "addq $8, %%rsp\n" /* replace return address on the stack */
               "callq *%%rdi\n"   /* call dstpc */

               JOVE_THUNK_EPILOGUE

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

__int128 _jove_thunk1(uint64_t rdi,
                      uint64_t dstpc   /* rsi */,
                      uint64_t *emuspp /* rdx */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "movq %%rdx, %%r14\n" /* emuspp in r14 */

               "movq (%%rdx), %%rsp\n" /* sp=emusp */
               "xorq %%rax, %%rax\n"
               "movq %%rax, (%%rdx)\n" /* emusp=0x0 */

               /* args: nothing to do */

               "addq $8, %%rsp\n" /* replace return address on the stack */
               "callq *%%rsi\n"   /* call dstpc */

               JOVE_THUNK_EPILOGUE

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

__int128 _jove_thunk2(uint64_t rdi,
                      uint64_t rsi,
                      uint64_t dstpc   /* rdx */,
                      uint64_t *emuspp /* rcx */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "movq %%rcx, %%r14\n" /* emuspp in r14 */

               "movq (%%rcx), %%rsp\n" /* sp=emusp */
               "xorq %%rax, %%rax\n"
               "movq %%rax, (%%rcx)\n" /* emusp=0x0 */

               /* args: nothing to do */

               "addq $8, %%rsp\n" /* replace return address on the stack */
               "callq *%%rdx\n"   /* call dstpc */

               JOVE_THUNK_EPILOGUE

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

__int128 _jove_thunk3(uint64_t rdi,
                      uint64_t rsi,
                      uint64_t rdx,
                      uint64_t dstpc   /* rcx */,
                      uint64_t *emuspp /* r8 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "movq %%r8, %%r14\n" /* emuspp in r14 */

               "movq (%%r8), %%rsp\n" /* sp=emusp */
               "xorq %%rax, %%rax\n"
               "movq %%rax, (%%r8)\n" /* emusp=0x0 */

               /* args: nothing to do */

               "addq $8, %%rsp\n" /* replace return address on the stack */
               "callq *%%rcx\n"   /* call dstpc */

               JOVE_THUNK_EPILOGUE

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

__int128 _jove_thunk4(uint64_t rdi,
                      uint64_t rsi,
                      uint64_t rdx,
                      uint64_t rcx,
                      uint64_t dstpc   /* r8 */,
                      uint64_t *emuspp /* r9 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "movq %%r9, %%r14\n" /* emuspp in r14 */

               "movq (%%r9), %%rsp\n" /* sp=emusp */
               "xorq %%rax, %%rax\n"
               "movq %%rax, (%%r9)\n" /* emusp=0x0 */

               /* args: nothing to do */

               "addq $8, %%rsp\n" /* replace return address on the stack */
               "callq *%%r8\n"   /* call dstpc */

               JOVE_THUNK_EPILOGUE

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

__int128 _jove_thunk5(uint64_t rdi,
                      uint64_t rsi,
                      uint64_t rdx,
                      uint64_t rcx,
                      uint64_t r8,
                      uint64_t dstpc   /* r9 */,
                      uint64_t *emuspp) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "movq 40(%%rsp), %%r14\n" /* emuspp in r14 */

               "movq (%%r14), %%rsp\n" /* sp=emusp */
               "xorq %%rax, %%rax\n"
               "movq %%rax, (%%r14)\n" /* emusp=0x0 */

               /* args: nothing to do */

               "addq $8, %%rsp\n" /* replace return address on the stack */
               "callq *%%r9\n"   /* call dstpc */

               JOVE_THUNK_EPILOGUE

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

__int128 _jove_thunk6(uint64_t rdi,
                      uint64_t rsi,
                      uint64_t rdx,
                      uint64_t rcx,
                      uint64_t r8,
                      uint64_t r9,
                      uint64_t dstpc,
                      uint64_t *emuspp) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "movq 40(%%rsp), %%r12\n" /* dstpc in r12 */
               "movq 48(%%rsp), %%r14\n" /* emuspp in r14 */

               "movq (%%r14), %%rsp\n" /* sp=emusp */
               "xorq %%rax, %%rax\n"
               "movq %%rax, (%%r14)\n" /* emusp=0x0 */

               /* args: nothing to do */

               "addq $8, %%rsp\n" /* replace return address on the stack */
               "callq *%%r12\n"   /* call dstpc */

               JOVE_THUNK_EPILOGUE

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

#undef JOVE_THUNK_PROLOGUE
#undef JOVE_THUNK_EPILOGUE
