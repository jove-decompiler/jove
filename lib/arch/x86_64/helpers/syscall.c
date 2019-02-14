#define TARGET_X86_64 1

#define QEMU_NORETURN __attribute__ ((__noreturn__))

#define container_of(ptr, type, member) ({                      \
        const typeof(((type *) 0)->member) *__mptr = (ptr);     \
        (type *) ((char *) __mptr - offsetof(type, member));})

#include <stddef.h>

#include <stdbool.h>

#include <stdint.h>

#include <sys/types.h>

#include <limits.h>

#include <setjmp.h>

typedef void* gpointer;

typedef struct _GHashTable  GHashTable;

typedef struct _GSList GSList;

struct _GSList
{
  gpointer data;
  GSList *next;
};

typedef struct AddressSpace AddressSpace;

typedef struct BusState BusState;

typedef struct CPUAddressSpace CPUAddressSpace;

typedef struct CPUState CPUState;

typedef struct DeviceState DeviceState;

typedef struct MemoryRegion MemoryRegion;

typedef struct QemuMutex QemuMutex;

typedef struct QemuOpts QemuOpts;

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

#define QLIST_HEAD(name, type)                                          \
struct name {                                                           \
        struct type *lh_first;  /* first element */                     \
}

#define QLIST_ENTRY(type)                                               \
struct {                                                                \
        struct type *le_next;   /* next element */                      \
        struct type **le_prev;  /* address of previous next element */  \
}

#define Q_TAILQ_HEAD(name, type, qual)                                  \
struct name {                                                           \
        qual type *tqh_first;           /* first element */             \
        qual type *qual *tqh_last;      /* addr of last next element */ \
}

#define QTAILQ_HEAD(name, type)  Q_TAILQ_HEAD(name, struct type,)

#define Q_TAILQ_ENTRY(type, qual)                                       \
struct {                                                                \
        qual type *tqe_next;            /* next element */              \
        qual type *qual *tqe_prev;      /* address of previous next element */\
}

#define QTAILQ_ENTRY(type)       Q_TAILQ_ENTRY(struct type,)

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
    flag snan_bit_is_one;
} float_status;

#define BITS_PER_BYTE           CHAR_BIT

#define BITS_TO_LONGS(nr)       DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))

#define DECLARE_BITMAP(name,bits)                  \
        unsigned long name[BITS_TO_LONGS(bits)]

struct TypeImpl;

typedef struct TypeImpl *Type;

typedef struct ObjectClass ObjectClass;

typedef struct Object Object;

typedef void (ObjectUnparent)(Object *obj);

#define OBJECT_CLASS_CAST_CACHE 4

typedef void (ObjectFree)(void *obj);

struct ObjectClass
{
    /*< private >*/
    Type type;
    GSList *interfaces;

    const char *object_cast_cache[OBJECT_CLASS_CAST_CACHE];
    const char *class_cast_cache[OBJECT_CLASS_CAST_CACHE];

    ObjectUnparent *unparent;

    GHashTable *properties;
};

struct Object
{
    /*< private >*/
    ObjectClass *klass;
    ObjectFree *free;
    GHashTable *properties;
    uint32_t ref;
    Object *parent;
};

typedef struct IRQState *qemu_irq;

struct NamedGPIOList {
    char *name;
    qemu_irq *in;
    int num_in;
    int num_out;
    QLIST_ENTRY(NamedGPIOList) node;
};

struct DeviceState {
    /*< private >*/
    Object parent_obj;
    /*< public >*/

    const char *id;
    char *canonical_path;
    bool realized;
    bool pending_deleted_event;
    QemuOpts *opts;
    int hotplugged;
    BusState *parent_bus;
    QLIST_HEAD(, NamedGPIOList) gpios;
    QLIST_HEAD(, BusState) child_bus;
    int num_child_bus;
    int instance_id_alias;
    int alias_required_for_version;
};

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

struct QemuMutex {
    pthread_mutex_t lock;
    bool initialized;
};

struct QemuCond {
    pthread_cond_t cond;
    bool initialized;
};

struct QemuThread {
    pthread_t thread;
};

struct Notifier;

#define CPU(obj) ((CPUState *)(obj))

typedef uint64_t vaddr;

typedef struct CPUWatchpoint CPUWatchpoint;

struct TranslationBlock;

typedef struct icount_decr_u16 {
    uint16_t low;
    uint16_t high;
} icount_decr_u16;

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

struct KVMState;

struct kvm_run;

#define TB_JMP_CACHE_BITS 12

#define TB_JMP_CACHE_SIZE (1 << TB_JMP_CACHE_BITS)

struct hax_vcpu_state;

#define CPU_TRACE_DSTATE_MAX_EVENTS 32

struct qemu_work_item;

struct CPUState {
    /*< private >*/
    DeviceState parent_obj;
    /*< public >*/

    int nr_cores;
    int nr_threads;

    struct QemuThread *thread;
#ifdef _WIN32
    HANDLE hThread;
#endif
    int thread_id;
    bool running, has_waiter;
    struct QemuCond *halt_cond;
    bool thread_kicked;
    bool created;
    bool stop;
    bool stopped;
    bool unplug;
    bool crash_occurred;
    bool exit_request;
    uint32_t cflags_next_tb;
    /* updates protected by BQL */
    uint32_t interrupt_request;
    int singlestep_enabled;
    int64_t icount_budget;
    int64_t icount_extra;
    sigjmp_buf jmp_env;

    QemuMutex work_mutex;
    struct qemu_work_item *queued_work_first, *queued_work_last;

    CPUAddressSpace *cpu_ases;
    int num_ases;
    AddressSpace *as;
    MemoryRegion *memory;

    void *env_ptr; /* CPUArchState */

    /* Accessed in parallel; all accesses must be atomic */
    struct TranslationBlock *tb_jmp_cache[TB_JMP_CACHE_SIZE];

    struct GDBRegisterState *gdb_regs;
    int gdb_num_regs;
    int gdb_num_g_regs;
    QTAILQ_ENTRY(CPUState) node;

    /* ice debug support */
    QTAILQ_HEAD(breakpoints_head, CPUBreakpoint) breakpoints;

    QTAILQ_HEAD(watchpoints_head, CPUWatchpoint) watchpoints;
    CPUWatchpoint *watchpoint_hit;

    void *opaque;

    /* In order to avoid passing too many arguments to the MMIO helpers,
     * we store some rarely used information in the CPU context.
     */
    uintptr_t mem_io_pc;
    vaddr mem_io_vaddr;

    int kvm_fd;
    struct KVMState *kvm_state;
    struct kvm_run *kvm_run;

    /* Used for events with 'vcpu' and *without* the 'disabled' properties */
    DECLARE_BITMAP(trace_dstate_delayed, CPU_TRACE_DSTATE_MAX_EVENTS);
    DECLARE_BITMAP(trace_dstate, CPU_TRACE_DSTATE_MAX_EVENTS);

    /* TODO Move common fields from CPUArchState here. */
    int cpu_index;
    uint32_t halted;
    uint32_t can_do_io;
    int32_t exception_index;

    /* shared by kvm, hax and hvf */
    bool vcpu_dirty;

    /* Used to keep track of an outstanding cpu throttle thread for migration
     * autoconverge
     */
    bool throttle_thread_scheduled;

    bool ignore_memory_transaction_failures;

    /* Note that this is accessed at the start of every TB via a negative
       offset from AREG0.  Leave this field at the end so as to make the
       (absolute value) offset as small as possible.  This reduces code
       size, especially for hosts without large memory offsets.  */
    union {
        uint32_t u32;
        icount_decr_u16 u16;
    } icount_decr;

    struct hax_vcpu_state *hax_vcpu;

    /* The pending_tlb_flush flag is set and cleared atomically to
     * avoid potential races. The aim of the flag is to avoid
     * unnecessary flushes.
     */
    uint16_t pending_tlb_flush;

    int hvf_fd;
};

typedef struct Notifier Notifier;

struct Notifier
{
    void (*notify)(Notifier *notifier, void *data);
    QLIST_ENTRY(Notifier) node;
};

#define HV_X64_MSR_CRASH_P0                     0x40000100

#define HV_X64_MSR_CRASH_P4                     0x40000104

#define HV_CRASH_PARAMS    (HV_X64_MSR_CRASH_P4 - HV_X64_MSR_CRASH_P0 + 1)

#define HV_SINT_COUNT                         16

#define HV_STIMER_COUNT                       4

typedef struct X86CPU X86CPU;

#define CPU_COMMON_TLB

#define CPU_COMMON                                                      \
    /* soft mmu support */                                              \
    CPU_COMMON_TLB

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

#define EXCP_SYSCALL    0x100

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

struct kvm_msrs;

struct X86CPU {
    /*< private >*/
    CPUState parent_obj;
    /*< public >*/

    CPUX86State env;

    bool hyperv_vapic;
    bool hyperv_relaxed_timing;
    int hyperv_spinlock_attempts;
    char *hyperv_vendor_id;
    bool hyperv_time;
    bool hyperv_crash;
    bool hyperv_reset;
    bool hyperv_vpindex;
    bool hyperv_runtime;
    bool hyperv_synic;
    bool hyperv_stimer;
    bool hyperv_frequencies;
    bool check_cpuid;
    bool enforce_cpuid;
    bool expose_kvm;
    bool expose_tcg;
    bool migratable;
    bool max_features; /* Enable all supported features automatically */
    uint32_t apic_id;

    /* Enables publishing of TSC increment and Local APIC bus frequencies to
     * the guest OS in CPUID page 0x40000010, the same way that VMWare does. */
    bool vmware_cpuid_freq;

    /* if true the CPUID code directly forward host cache leaves to the guest */
    bool cache_info_passthrough;

    /* Features that were filtered out because of missing host capabilities */
    uint32_t filtered_features[FEATURE_WORDS];

    /* Enable PMU CPUID bits. This can't be enabled by default yet because
     * it doesn't have ABI stability guarantees, as it passes all PMU CPUID
     * bits returned by GET_SUPPORTED_CPUID (that depend on host CPU and kernel
     * capabilities) directly to the guest.
     */
    bool enable_pmu;

    /* LMCE support can be enabled/disabled via cpu option 'lmce=on/off'. It is
     * disabled by default to avoid breaking migration between QEMU with
     * different LMCE configurations.
     */
    bool enable_lmce;

    /* Compatibility bits for old machine types.
     * If true present virtual l3 cache for VM, the vcpus in the same virtual
     * socket share an virtual l3 cache.
     */
    bool enable_l3_cache;

    /* Compatibility bits for old machine types: */
    bool enable_cpuid_0xb;

    /* Enable auto level-increase for all CPUID leaves */
    bool full_cpuid_auto_level;

    /* if true fill the top bits of the MTRR_PHYSMASKn variable range */
    bool fill_mtrr_mask;

    /* if true override the phys_bits value with a value read from the host */
    bool host_phys_bits;

    /* Stop SMI delivery for migration compatibility with old machines */
    bool kvm_no_smi_migration;

    /* Number of physical address bits supported */
    uint32_t phys_bits;

    /* in order to simplify APIC support, we leave this pointer to the
       user */
    struct DeviceState *apic_state;
    struct MemoryRegion *cpu_as_root, *cpu_as_mem, *smram;
    Notifier machine_done;

    struct kvm_msrs *kvm_msr_buf;

    int32_t node_id; /* NUMA node this CPU belongs to */
    int32_t socket_id;
    int32_t core_id;
    int32_t thread_id;

    int32_t hv_max_vps;
};

__attribute__((always_inline)) void helper_syscall(CPUX86State *, int);

static const unsigned sys_ni_syscall = 0;

static const unsigned __x64_sys_accept = 3;
static const unsigned __x64_sys_accept4 = 4;
static const unsigned __x64_sys_access = 2;
static const unsigned __x64_sys_acct = 1;
static const unsigned __x64_sys_add_key = 5;
static const unsigned __x64_sys_adjtimex = 1;
static const unsigned __x64_sys_alarm = 1;
static const unsigned __x64_sys_arch_prctl = 2;
static const unsigned __x64_sys_bind = 3;
static const unsigned __x64_sys_bpf = 3;
static const unsigned __x64_sys_brk = 1;
static const unsigned __x64_sys_capget = 2;
static const unsigned __x64_sys_capset = 2;
static const unsigned __x64_sys_chdir = 1;
static const unsigned __x64_sys_chmod = 2;
static const unsigned __x64_sys_chown = 3;
static const unsigned __x64_sys_chroot = 1;
static const unsigned __x64_sys_clock_adjtime = 2;
static const unsigned __x64_sys_clock_getres = 2;
static const unsigned __x64_sys_clock_gettime = 2;
static const unsigned __x64_sys_clock_nanosleep = 4;
static const unsigned __x64_sys_clock_settime = 2;
static const unsigned __x64_sys_clone = 5;
static const unsigned __x64_sys_close = 1;
static const unsigned __x64_sys_connect = 3;
static const unsigned __x64_sys_copy_file_range = 6;
static const unsigned __x64_sys_creat = 2;
static const unsigned __x64_sys_delete_module = 2;
static const unsigned __x64_sys_dup = 1;
static const unsigned __x64_sys_dup2 = 2;
static const unsigned __x64_sys_dup3 = 3;
static const unsigned __x64_sys_epoll_create = 1;
static const unsigned __x64_sys_epoll_create1 = 1;
static const unsigned __x64_sys_epoll_ctl = 4;
static const unsigned __x64_sys_epoll_pwait = 6;
static const unsigned __x64_sys_epoll_wait = 4;
static const unsigned __x64_sys_eventfd = 1;
static const unsigned __x64_sys_eventfd2 = 2;
static const unsigned __x64_sys_execve = 3;
static const unsigned __x64_sys_execveat = 5;
static const unsigned __x64_sys_exit = 1;
static const unsigned __x64_sys_exit_group = 1;
static const unsigned __x64_sys_faccessat = 3;
static const unsigned __x64_sys_fadvise64 = 4;
static const unsigned __x64_sys_fallocate = 4;
static const unsigned __x64_sys_fanotify_init = 2;
static const unsigned __x64_sys_fanotify_mark = 5;
static const unsigned __x64_sys_fchdir = 1;
static const unsigned __x64_sys_fchmod = 2;
static const unsigned __x64_sys_fchmodat = 3;
static const unsigned __x64_sys_fchown = 3;
static const unsigned __x64_sys_fchownat = 5;
static const unsigned __x64_sys_fcntl = 3;
static const unsigned __x64_sys_fdatasync = 1;
static const unsigned __x64_sys_fgetxattr = 4;
static const unsigned __x64_sys_finit_module = 3;
static const unsigned __x64_sys_flistxattr = 3;
static const unsigned __x64_sys_flock = 2;
static const unsigned __x64_sys_fork = 0;
static const unsigned __x64_sys_fremovexattr = 2;
static const unsigned __x64_sys_fsetxattr = 5;
static const unsigned __x64_sys_fstatfs = 2;
static const unsigned __x64_sys_fsync = 1;
static const unsigned __x64_sys_ftruncate = 2;
static const unsigned __x64_sys_futex = 6;
static const unsigned __x64_sys_futimesat = 3;
static const unsigned __x64_sys_get_mempolicy = 5;
static const unsigned __x64_sys_get_robust_list = 3;
static const unsigned __x64_sys_getcpu = 3;
static const unsigned __x64_sys_getcwd = 2;
static const unsigned __x64_sys_getdents = 3;
static const unsigned __x64_sys_getdents64 = 3;
static const unsigned __x64_sys_getegid = 0;
static const unsigned __x64_sys_geteuid = 0;
static const unsigned __x64_sys_getgid = 0;
static const unsigned __x64_sys_getgroups = 2;
static const unsigned __x64_sys_getitimer = 2;
static const unsigned __x64_sys_getpeername = 3;
static const unsigned __x64_sys_getpgid = 1;
static const unsigned __x64_sys_getpgrp = 0;
static const unsigned __x64_sys_getpid = 0;
static const unsigned __x64_sys_getppid = 0;
static const unsigned __x64_sys_getpriority = 2;
static const unsigned __x64_sys_getrandom = 3;
static const unsigned __x64_sys_getresgid = 3;
static const unsigned __x64_sys_getresuid = 3;
static const unsigned __x64_sys_getrlimit = 2;
static const unsigned __x64_sys_getrusage = 2;
static const unsigned __x64_sys_getsid = 1;
static const unsigned __x64_sys_getsockname = 3;
static const unsigned __x64_sys_getsockopt = 5;
static const unsigned __x64_sys_gettid = 0;
static const unsigned __x64_sys_gettimeofday = 2;
static const unsigned __x64_sys_getuid = 0;
static const unsigned __x64_sys_getxattr = 4;
static const unsigned __x64_sys_init_module = 3;
static const unsigned __x64_sys_inotify_add_watch = 3;
static const unsigned __x64_sys_inotify_init = 0;
static const unsigned __x64_sys_inotify_init1 = 1;
static const unsigned __x64_sys_inotify_rm_watch = 2;
static const unsigned __x64_sys_io_cancel = 3;
static const unsigned __x64_sys_io_destroy = 1;
static const unsigned __x64_sys_io_getevents = 5;
static const unsigned __x64_sys_io_pgetevents = 6;
static const unsigned __x64_sys_io_setup = 2;
static const unsigned __x64_sys_io_submit = 3;
static const unsigned __x64_sys_ioctl = 3;
static const unsigned __x64_sys_ioperm = 3;
static const unsigned __x64_sys_iopl = 1;
static const unsigned __x64_sys_ioprio_get = 2;
static const unsigned __x64_sys_ioprio_set = 3;
static const unsigned __x64_sys_kcmp = 5;
static const unsigned __x64_sys_kexec_file_load = 5;
static const unsigned __x64_sys_kexec_load = 4;
static const unsigned __x64_sys_keyctl = 5;
static const unsigned __x64_sys_kill = 2;
static const unsigned __x64_sys_lchown = 3;
static const unsigned __x64_sys_lgetxattr = 4;
static const unsigned __x64_sys_link = 2;
static const unsigned __x64_sys_linkat = 5;
static const unsigned __x64_sys_listen = 2;
static const unsigned __x64_sys_listxattr = 3;
static const unsigned __x64_sys_llistxattr = 3;
static const unsigned __x64_sys_lookup_dcookie = 3;
static const unsigned __x64_sys_lremovexattr = 2;
static const unsigned __x64_sys_lseek = 3;
static const unsigned __x64_sys_lsetxattr = 5;
static const unsigned __x64_sys_madvise = 3;
static const unsigned __x64_sys_mbind = 6;
static const unsigned __x64_sys_membarrier = 2;
static const unsigned __x64_sys_memfd_create = 2;
static const unsigned __x64_sys_migrate_pages = 4;
static const unsigned __x64_sys_mincore = 3;
static const unsigned __x64_sys_mkdir = 2;
static const unsigned __x64_sys_mkdirat = 3;
static const unsigned __x64_sys_mknod = 3;
static const unsigned __x64_sys_mknodat = 4;
static const unsigned __x64_sys_mlock = 2;
static const unsigned __x64_sys_mlock2 = 3;
static const unsigned __x64_sys_mlockall = 1;
static const unsigned __x64_sys_mmap = 6;
static const unsigned __x64_sys_modify_ldt = 3;
static const unsigned __x64_sys_mount = 5;
static const unsigned __x64_sys_move_pages = 6;
static const unsigned __x64_sys_mprotect = 3;
static const unsigned __x64_sys_mq_getsetattr = 3;
static const unsigned __x64_sys_mq_notify = 2;
static const unsigned __x64_sys_mq_open = 4;
static const unsigned __x64_sys_mq_timedreceive = 5;
static const unsigned __x64_sys_mq_timedsend = 5;
static const unsigned __x64_sys_mq_unlink = 1;
static const unsigned __x64_sys_mremap = 5;
static const unsigned __x64_sys_msgctl = 3;
static const unsigned __x64_sys_msgget = 2;
static const unsigned __x64_sys_msgrcv = 5;
static const unsigned __x64_sys_msgsnd = 4;
static const unsigned __x64_sys_msync = 3;
static const unsigned __x64_sys_munlock = 2;
static const unsigned __x64_sys_munlockall = 0;
static const unsigned __x64_sys_munmap = 2;
static const unsigned __x64_sys_name_to_handle_at = 5;
static const unsigned __x64_sys_nanosleep = 2;
static const unsigned __x64_sys_newfstat = 2;
static const unsigned __x64_sys_newfstatat = 4;
static const unsigned __x64_sys_newlstat = 2;
static const unsigned __x64_sys_newstat = 2;
static const unsigned __x64_sys_newuname = 1;
static const unsigned __x64_sys_open = 3;
static const unsigned __x64_sys_open_by_handle_at = 3;
static const unsigned __x64_sys_openat = 4;
static const unsigned __x64_sys_pause = 0;
static const unsigned __x64_sys_perf_event_open = 5;
static const unsigned __x64_sys_personality = 1;
static const unsigned __x64_sys_pipe = 1;
static const unsigned __x64_sys_pipe2 = 2;
static const unsigned __x64_sys_pivot_root = 2;
static const unsigned __x64_sys_pkey_alloc = 2;
static const unsigned __x64_sys_pkey_free = 1;
static const unsigned __x64_sys_pkey_mprotect = 4;
static const unsigned __x64_sys_poll = 3;
static const unsigned __x64_sys_ppoll = 5;
static const unsigned __x64_sys_prctl = 5;
static const unsigned __x64_sys_pread64 = 4;
static const unsigned __x64_sys_preadv = 5;
static const unsigned __x64_sys_preadv2 = 6;
static const unsigned __x64_sys_prlimit64 = 4;
static const unsigned __x64_sys_process_vm_readv = 6;
static const unsigned __x64_sys_process_vm_writev = 6;
static const unsigned __x64_sys_pselect6 = 6;
static const unsigned __x64_sys_ptrace = 4;
static const unsigned __x64_sys_pwrite64 = 4;
static const unsigned __x64_sys_pwritev = 5;
static const unsigned __x64_sys_pwritev2 = 6;
static const unsigned __x64_sys_quotactl = 4;
static const unsigned __x64_sys_read = 3;
static const unsigned __x64_sys_readahead = 3;
static const unsigned __x64_sys_readlink = 3;
static const unsigned __x64_sys_readlinkat = 4;
static const unsigned __x64_sys_readv = 3;
static const unsigned __x64_sys_reboot = 4;
static const unsigned __x64_sys_recvfrom = 6;
static const unsigned __x64_sys_recvmmsg = 5;
static const unsigned __x64_sys_recvmsg = 3;
static const unsigned __x64_sys_remap_file_pages = 5;
static const unsigned __x64_sys_removexattr = 2;
static const unsigned __x64_sys_rename = 2;
static const unsigned __x64_sys_renameat = 4;
static const unsigned __x64_sys_renameat2 = 5;
static const unsigned __x64_sys_request_key = 4;
static const unsigned __x64_sys_restart_syscall = 0;
static const unsigned __x64_sys_rmdir = 1;
static const unsigned __x64_sys_rseq = 4;
static const unsigned __x64_sys_rt_sigaction = 4;
static const unsigned __x64_sys_rt_sigpending = 2;
static const unsigned __x64_sys_rt_sigprocmask = 4;
static const unsigned __x64_sys_rt_sigqueueinfo = 3;
static const unsigned __x64_sys_rt_sigreturn = 0;
static const unsigned __x64_sys_rt_sigsuspend = 2;
static const unsigned __x64_sys_rt_sigtimedwait = 4;
static const unsigned __x64_sys_rt_tgsigqueueinfo = 4;
static const unsigned __x64_sys_sched_get_priority_max = 1;
static const unsigned __x64_sys_sched_get_priority_min = 1;
static const unsigned __x64_sys_sched_getaffinity = 3;
static const unsigned __x64_sys_sched_getattr = 4;
static const unsigned __x64_sys_sched_getparam = 2;
static const unsigned __x64_sys_sched_getscheduler = 1;
static const unsigned __x64_sys_sched_rr_get_interval = 2;
static const unsigned __x64_sys_sched_setaffinity = 3;
static const unsigned __x64_sys_sched_setattr = 3;
static const unsigned __x64_sys_sched_setparam = 2;
static const unsigned __x64_sys_sched_setscheduler = 3;
static const unsigned __x64_sys_sched_yield = 0;
static const unsigned __x64_sys_seccomp = 3;
static const unsigned __x64_sys_select = 5;
static const unsigned __x64_sys_semctl = 4;
static const unsigned __x64_sys_semget = 3;
static const unsigned __x64_sys_semop = 3;
static const unsigned __x64_sys_semtimedop = 4;
static const unsigned __x64_sys_sendfile64 = 4;
static const unsigned __x64_sys_sendmmsg = 4;
static const unsigned __x64_sys_sendmsg = 3;
static const unsigned __x64_sys_sendto = 6;
static const unsigned __x64_sys_set_mempolicy = 3;
static const unsigned __x64_sys_set_robust_list = 2;
static const unsigned __x64_sys_set_tid_address = 1;
static const unsigned __x64_sys_setdomainname = 2;
static const unsigned __x64_sys_setfsgid = 1;
static const unsigned __x64_sys_setfsuid = 1;
static const unsigned __x64_sys_setgid = 1;
static const unsigned __x64_sys_setgroups = 2;
static const unsigned __x64_sys_sethostname = 2;
static const unsigned __x64_sys_setitimer = 3;
static const unsigned __x64_sys_setns = 2;
static const unsigned __x64_sys_setpgid = 2;
static const unsigned __x64_sys_setpriority = 3;
static const unsigned __x64_sys_setregid = 2;
static const unsigned __x64_sys_setresgid = 3;
static const unsigned __x64_sys_setresuid = 3;
static const unsigned __x64_sys_setreuid = 2;
static const unsigned __x64_sys_setrlimit = 2;
static const unsigned __x64_sys_setsid = 0;
static const unsigned __x64_sys_setsockopt = 5;
static const unsigned __x64_sys_settimeofday = 2;
static const unsigned __x64_sys_setuid = 1;
static const unsigned __x64_sys_setxattr = 5;
static const unsigned __x64_sys_shmat = 3;
static const unsigned __x64_sys_shmctl = 3;
static const unsigned __x64_sys_shmdt = 1;
static const unsigned __x64_sys_shmget = 3;
static const unsigned __x64_sys_shutdown = 2;
static const unsigned __x64_sys_sigaltstack = 2;
static const unsigned __x64_sys_signalfd = 3;
static const unsigned __x64_sys_signalfd4 = 4;
static const unsigned __x64_sys_socket = 3;
static const unsigned __x64_sys_socketpair = 4;
static const unsigned __x64_sys_splice = 6;
static const unsigned __x64_sys_statfs = 2;
static const unsigned __x64_sys_statx = 5;
static const unsigned __x64_sys_swapoff = 1;
static const unsigned __x64_sys_swapon = 2;
static const unsigned __x64_sys_symlink = 2;
static const unsigned __x64_sys_symlinkat = 3;
static const unsigned __x64_sys_sync = 0;
static const unsigned __x64_sys_sync_file_range = 4;
static const unsigned __x64_sys_syncfs = 1;
static const unsigned __x64_sys_sysctl = 1;
static const unsigned __x64_sys_sysfs = 3;
static const unsigned __x64_sys_sysinfo = 1;
static const unsigned __x64_sys_syslog = 3;
static const unsigned __x64_sys_tee = 4;
static const unsigned __x64_sys_tgkill = 3;
static const unsigned __x64_sys_time = 1;
static const unsigned __x64_sys_timer_create = 3;
static const unsigned __x64_sys_timer_delete = 1;
static const unsigned __x64_sys_timer_getoverrun = 1;
static const unsigned __x64_sys_timer_gettime = 2;
static const unsigned __x64_sys_timer_settime = 4;
static const unsigned __x64_sys_timerfd_create = 2;
static const unsigned __x64_sys_timerfd_gettime = 2;
static const unsigned __x64_sys_timerfd_settime = 4;
static const unsigned __x64_sys_times = 1;
static const unsigned __x64_sys_tkill = 2;
static const unsigned __x64_sys_truncate = 2;
static const unsigned __x64_sys_umask = 1;
static const unsigned __x64_sys_umount = 2;
static const unsigned __x64_sys_unlink = 1;
static const unsigned __x64_sys_unlinkat = 3;
static const unsigned __x64_sys_unshare = 1;
static const unsigned __x64_sys_userfaultfd = 1;
static const unsigned __x64_sys_ustat = 2;
static const unsigned __x64_sys_utime = 2;
static const unsigned __x64_sys_utimensat = 4;
static const unsigned __x64_sys_utimes = 2;
static const unsigned __x64_sys_vfork = 0;
static const unsigned __x64_sys_vhangup = 0;
static const unsigned __x64_sys_vmsplice = 4;
static const unsigned __x64_sys_wait4 = 4;
static const unsigned __x64_sys_waitid = 5;
static const unsigned __x64_sys_write = 3;
static const unsigned __x64_sys_writev = 3;

static const unsigned sys_call_arg_cnt_table[334 +1] = {
 [0 ... 334] = sys_ni_syscall,

[0] = __x64_sys_read,
[1] = __x64_sys_write,
[2] = __x64_sys_open,
[3] = __x64_sys_close,
[4] = __x64_sys_newstat,
[5] = __x64_sys_newfstat,
[6] = __x64_sys_newlstat,
[7] = __x64_sys_poll,
[8] = __x64_sys_lseek,
[9] = __x64_sys_mmap,
[10] = __x64_sys_mprotect,
[11] = __x64_sys_munmap,
[12] = __x64_sys_brk,
[13] = __x64_sys_rt_sigaction,
[14] = __x64_sys_rt_sigprocmask,
[15] = __x64_sys_rt_sigreturn,
[16] = __x64_sys_ioctl,
[17] = __x64_sys_pread64,
[18] = __x64_sys_pwrite64,
[19] = __x64_sys_readv,
[20] = __x64_sys_writev,
[21] = __x64_sys_access,
[22] = __x64_sys_pipe,
[23] = __x64_sys_select,
[24] = __x64_sys_sched_yield,
[25] = __x64_sys_mremap,
[26] = __x64_sys_msync,
[27] = __x64_sys_mincore,
[28] = __x64_sys_madvise,
[29] = __x64_sys_shmget,
[30] = __x64_sys_shmat,
[31] = __x64_sys_shmctl,
[32] = __x64_sys_dup,
[33] = __x64_sys_dup2,
[34] = __x64_sys_pause,
[35] = __x64_sys_nanosleep,
[36] = __x64_sys_getitimer,
[37] = __x64_sys_alarm,
[38] = __x64_sys_setitimer,
[39] = __x64_sys_getpid,
[40] = __x64_sys_sendfile64,
[41] = __x64_sys_socket,
[42] = __x64_sys_connect,
[43] = __x64_sys_accept,
[44] = __x64_sys_sendto,
[45] = __x64_sys_recvfrom,
[46] = __x64_sys_sendmsg,
[47] = __x64_sys_recvmsg,
[48] = __x64_sys_shutdown,
[49] = __x64_sys_bind,
[50] = __x64_sys_listen,
[51] = __x64_sys_getsockname,
[52] = __x64_sys_getpeername,
[53] = __x64_sys_socketpair,
[54] = __x64_sys_setsockopt,
[55] = __x64_sys_getsockopt,
[56] = __x64_sys_clone,
[57] = __x64_sys_fork,
[58] = __x64_sys_vfork,
[59] = __x64_sys_execve,
[60] = __x64_sys_exit,
[61] = __x64_sys_wait4,
[62] = __x64_sys_kill,
[63] = __x64_sys_newuname,
[64] = __x64_sys_semget,
[65] = __x64_sys_semop,
[66] = __x64_sys_semctl,
[67] = __x64_sys_shmdt,
[68] = __x64_sys_msgget,
[69] = __x64_sys_msgsnd,
[70] = __x64_sys_msgrcv,
[71] = __x64_sys_msgctl,
[72] = __x64_sys_fcntl,
[73] = __x64_sys_flock,
[74] = __x64_sys_fsync,
[75] = __x64_sys_fdatasync,
[76] = __x64_sys_truncate,
[77] = __x64_sys_ftruncate,
[78] = __x64_sys_getdents,
[79] = __x64_sys_getcwd,
[80] = __x64_sys_chdir,
[81] = __x64_sys_fchdir,
[82] = __x64_sys_rename,
[83] = __x64_sys_mkdir,
[84] = __x64_sys_rmdir,
[85] = __x64_sys_creat,
[86] = __x64_sys_link,
[87] = __x64_sys_unlink,
[88] = __x64_sys_symlink,
[89] = __x64_sys_readlink,
[90] = __x64_sys_chmod,
[91] = __x64_sys_fchmod,
[92] = __x64_sys_chown,
[93] = __x64_sys_fchown,
[94] = __x64_sys_lchown,
[95] = __x64_sys_umask,
[96] = __x64_sys_gettimeofday,
[97] = __x64_sys_getrlimit,
[98] = __x64_sys_getrusage,
[99] = __x64_sys_sysinfo,
[100] = __x64_sys_times,
[101] = __x64_sys_ptrace,
[102] = __x64_sys_getuid,
[103] = __x64_sys_syslog,
[104] = __x64_sys_getgid,
[105] = __x64_sys_setuid,
[106] = __x64_sys_setgid,
[107] = __x64_sys_geteuid,
[108] = __x64_sys_getegid,
[109] = __x64_sys_setpgid,
[110] = __x64_sys_getppid,
[111] = __x64_sys_getpgrp,
[112] = __x64_sys_setsid,
[113] = __x64_sys_setreuid,
[114] = __x64_sys_setregid,
[115] = __x64_sys_getgroups,
[116] = __x64_sys_setgroups,
[117] = __x64_sys_setresuid,
[118] = __x64_sys_getresuid,
[119] = __x64_sys_setresgid,
[120] = __x64_sys_getresgid,
[121] = __x64_sys_getpgid,
[122] = __x64_sys_setfsuid,
[123] = __x64_sys_setfsgid,
[124] = __x64_sys_getsid,
[125] = __x64_sys_capget,
[126] = __x64_sys_capset,
[127] = __x64_sys_rt_sigpending,
[128] = __x64_sys_rt_sigtimedwait,
[129] = __x64_sys_rt_sigqueueinfo,
[130] = __x64_sys_rt_sigsuspend,
[131] = __x64_sys_sigaltstack,
[132] = __x64_sys_utime,
[133] = __x64_sys_mknod,
[135] = __x64_sys_personality,
[136] = __x64_sys_ustat,
[137] = __x64_sys_statfs,
[138] = __x64_sys_fstatfs,
[139] = __x64_sys_sysfs,
[140] = __x64_sys_getpriority,
[141] = __x64_sys_setpriority,
[142] = __x64_sys_sched_setparam,
[143] = __x64_sys_sched_getparam,
[144] = __x64_sys_sched_setscheduler,
[145] = __x64_sys_sched_getscheduler,
[146] = __x64_sys_sched_get_priority_max,
[147] = __x64_sys_sched_get_priority_min,
[148] = __x64_sys_sched_rr_get_interval,
[149] = __x64_sys_mlock,
[150] = __x64_sys_munlock,
[151] = __x64_sys_mlockall,
[152] = __x64_sys_munlockall,
[153] = __x64_sys_vhangup,
[154] = __x64_sys_modify_ldt,
[155] = __x64_sys_pivot_root,
[156] = __x64_sys_sysctl,
[157] = __x64_sys_prctl,
[158] = __x64_sys_arch_prctl,
[159] = __x64_sys_adjtimex,
[160] = __x64_sys_setrlimit,
[161] = __x64_sys_chroot,
[162] = __x64_sys_sync,
[163] = __x64_sys_acct,
[164] = __x64_sys_settimeofday,
[165] = __x64_sys_mount,
[166] = __x64_sys_umount,
[167] = __x64_sys_swapon,
[168] = __x64_sys_swapoff,
[169] = __x64_sys_reboot,
[170] = __x64_sys_sethostname,
[171] = __x64_sys_setdomainname,
[172] = __x64_sys_iopl,
[173] = __x64_sys_ioperm,
[175] = __x64_sys_init_module,
[176] = __x64_sys_delete_module,
[179] = __x64_sys_quotactl,
[186] = __x64_sys_gettid,
[187] = __x64_sys_readahead,
[188] = __x64_sys_setxattr,
[189] = __x64_sys_lsetxattr,
[190] = __x64_sys_fsetxattr,
[191] = __x64_sys_getxattr,
[192] = __x64_sys_lgetxattr,
[193] = __x64_sys_fgetxattr,
[194] = __x64_sys_listxattr,
[195] = __x64_sys_llistxattr,
[196] = __x64_sys_flistxattr,
[197] = __x64_sys_removexattr,
[198] = __x64_sys_lremovexattr,
[199] = __x64_sys_fremovexattr,
[200] = __x64_sys_tkill,
[201] = __x64_sys_time,
[202] = __x64_sys_futex,
[203] = __x64_sys_sched_setaffinity,
[204] = __x64_sys_sched_getaffinity,
[206] = __x64_sys_io_setup,
[207] = __x64_sys_io_destroy,
[208] = __x64_sys_io_getevents,
[209] = __x64_sys_io_submit,
[210] = __x64_sys_io_cancel,
[212] = __x64_sys_lookup_dcookie,
[213] = __x64_sys_epoll_create,
[216] = __x64_sys_remap_file_pages,
[217] = __x64_sys_getdents64,
[218] = __x64_sys_set_tid_address,
[219] = __x64_sys_restart_syscall,
[220] = __x64_sys_semtimedop,
[221] = __x64_sys_fadvise64,
[222] = __x64_sys_timer_create,
[223] = __x64_sys_timer_settime,
[224] = __x64_sys_timer_gettime,
[225] = __x64_sys_timer_getoverrun,
[226] = __x64_sys_timer_delete,
[227] = __x64_sys_clock_settime,
[228] = __x64_sys_clock_gettime,
[229] = __x64_sys_clock_getres,
[230] = __x64_sys_clock_nanosleep,
[231] = __x64_sys_exit_group,
[232] = __x64_sys_epoll_wait,
[233] = __x64_sys_epoll_ctl,
[234] = __x64_sys_tgkill,
[235] = __x64_sys_utimes,
[237] = __x64_sys_mbind,
[238] = __x64_sys_set_mempolicy,
[239] = __x64_sys_get_mempolicy,
[240] = __x64_sys_mq_open,
[241] = __x64_sys_mq_unlink,
[242] = __x64_sys_mq_timedsend,
[243] = __x64_sys_mq_timedreceive,
[244] = __x64_sys_mq_notify,
[245] = __x64_sys_mq_getsetattr,
[246] = __x64_sys_kexec_load,
[247] = __x64_sys_waitid,
[248] = __x64_sys_add_key,
[249] = __x64_sys_request_key,
[250] = __x64_sys_keyctl,
[251] = __x64_sys_ioprio_set,
[252] = __x64_sys_ioprio_get,
[253] = __x64_sys_inotify_init,
[254] = __x64_sys_inotify_add_watch,
[255] = __x64_sys_inotify_rm_watch,
[256] = __x64_sys_migrate_pages,
[257] = __x64_sys_openat,
[258] = __x64_sys_mkdirat,
[259] = __x64_sys_mknodat,
[260] = __x64_sys_fchownat,
[261] = __x64_sys_futimesat,
[262] = __x64_sys_newfstatat,
[263] = __x64_sys_unlinkat,
[264] = __x64_sys_renameat,
[265] = __x64_sys_linkat,
[266] = __x64_sys_symlinkat,
[267] = __x64_sys_readlinkat,
[268] = __x64_sys_fchmodat,
[269] = __x64_sys_faccessat,
[270] = __x64_sys_pselect6,
[271] = __x64_sys_ppoll,
[272] = __x64_sys_unshare,
[273] = __x64_sys_set_robust_list,
[274] = __x64_sys_get_robust_list,
[275] = __x64_sys_splice,
[276] = __x64_sys_tee,
[277] = __x64_sys_sync_file_range,
[278] = __x64_sys_vmsplice,
[279] = __x64_sys_move_pages,
[280] = __x64_sys_utimensat,
[281] = __x64_sys_epoll_pwait,
[282] = __x64_sys_signalfd,
[283] = __x64_sys_timerfd_create,
[284] = __x64_sys_eventfd,
[285] = __x64_sys_fallocate,
[286] = __x64_sys_timerfd_settime,
[287] = __x64_sys_timerfd_gettime,
[288] = __x64_sys_accept4,
[289] = __x64_sys_signalfd4,
[290] = __x64_sys_eventfd2,
[291] = __x64_sys_epoll_create1,
[292] = __x64_sys_dup3,
[293] = __x64_sys_pipe2,
[294] = __x64_sys_inotify_init1,
[295] = __x64_sys_preadv,
[296] = __x64_sys_pwritev,
[297] = __x64_sys_rt_tgsigqueueinfo,
[298] = __x64_sys_perf_event_open,
[299] = __x64_sys_recvmmsg,
[300] = __x64_sys_fanotify_init,
[301] = __x64_sys_fanotify_mark,
[302] = __x64_sys_prlimit64,
[303] = __x64_sys_name_to_handle_at,
[304] = __x64_sys_open_by_handle_at,
[305] = __x64_sys_clock_adjtime,
[306] = __x64_sys_syncfs,
[307] = __x64_sys_sendmmsg,
[308] = __x64_sys_setns,
[309] = __x64_sys_getcpu,
[310] = __x64_sys_process_vm_readv,
[311] = __x64_sys_process_vm_writev,
[312] = __x64_sys_kcmp,
[313] = __x64_sys_finit_module,
[314] = __x64_sys_sched_setattr,
[315] = __x64_sys_sched_getattr,
[316] = __x64_sys_renameat2,
[317] = __x64_sys_seccomp,
[318] = __x64_sys_getrandom,
[319] = __x64_sys_memfd_create,
[320] = __x64_sys_kexec_file_load,
[321] = __x64_sys_bpf,
[322] = __x64_sys_execveat,
[323] = __x64_sys_userfaultfd,
[324] = __x64_sys_membarrier,
[325] = __x64_sys_mlock2,
[326] = __x64_sys_copy_file_range,
[327] = __x64_sys_preadv2,
[328] = __x64_sys_pwritev2,
[329] = __x64_sys_pkey_mprotect,
[330] = __x64_sys_pkey_alloc,
[331] = __x64_sys_pkey_free,
[332] = __x64_sys_statx,
[333] = __x64_sys_io_pgetevents,
[334] = __x64_sys_rseq,
};

static long dosys0(long no);
static long dosys1(long no, long a1);
static long dosys2(long no, long a1, long a2);
static long dosys3(long no, long a1, long a2, long a3);
static long dosys4(long no, long a1, long a2, long a3, long a4);
static long dosys5(long no, long a1, long a2, long a3, long a4, long a5);
static long dosys6(long no, long a1, long a2, long a3, long a4, long a5, long a6);

void helper_syscall(CPUX86State *env, int next_eip_addend)
{
  long sysnum = env->regs[R_EAX];
  unsigned N = sys_call_arg_cnt_table[sysnum];


  long sysret;
  switch (N) {
  case 0: {
    sysret = dosys0(sysnum);
    break;
  }

  case 1: {
    long a1 = env->regs[R_EDI];
    sysret = dosys1(sysnum, a1);
    break;
  }

  case 2: {
    long a1 = env->regs[R_EDI];
    long a2 = env->regs[R_ESI];
    sysret = dosys2(sysnum, a1, a2);
    break;
  }

  case 3: {
    long a1 = env->regs[R_EDI];
    long a2 = env->regs[R_ESI];
    long a3 = env->regs[R_EDX];
    sysret = dosys3(sysnum, a1, a2, a3);
    break;
  }

  case 4: {
    long a1 = env->regs[R_EDI];
    long a2 = env->regs[R_ESI];
    long a3 = env->regs[R_EDX];
    long a4 = env->regs[R_R10];
    sysret = dosys4(sysnum, a1, a2, a3, a4);
    break;
  }

  case 5: {
    long a1 = env->regs[R_EDI];
    long a2 = env->regs[R_ESI];
    long a3 = env->regs[R_EDX];
    long a4 = env->regs[R_R10];
    long a5 = env->regs[R_R8];
    sysret = dosys5(sysnum, a1, a2, a3, a4, a5);
    break;
  }

  case 6: {
    long a1 = env->regs[R_EDI];
    long a2 = env->regs[R_ESI];
    long a3 = env->regs[R_EDX];
    long a4 = env->regs[R_R10];
    long a5 = env->regs[R_R8];
    long a6 = env->regs[R_R9];
    sysret = dosys6(sysnum, a1, a2, a3, a4, a5, a6);
    break;
  }

  default:
    __builtin_unreachable();
  }

  env->regs[R_EAX] = sysret;
}

long dosys0(long no) {
  long resultvar;

  register long _no asm("rax") = no;

  asm volatile("syscall\n\t"
               : "=a"(resultvar)
               : "r"(_no)
               : "memory", "cc", "r11", "cx");
  
  return resultvar;
}

long dosys1(long no, long a1) {
  long resultvar;

  register long _no asm("rax") = no;

  register long _a1 asm("rdi") = a1;

  asm volatile("syscall\n\t"
               : "=a"(resultvar)
               : "r"(_no), "r"(_a1)
               : "memory", "cc", "r11", "cx");
  
  return resultvar;
}

long dosys2(long no, long a1, long a2) {
  long resultvar;

  register long _no asm("rax") = no;

  register long _a1 asm("rdi") = a1;
  register long _a2 asm("rsi") = a2;

  asm volatile("syscall\n\t"
               : "=a"(resultvar)
               : "r"(_no), "r"(_a1), "r"(_a2)
               : "memory", "cc", "r11", "cx");
  
  return resultvar;
}

long dosys3(long no, long a1, long a2, long a3) {
  long resultvar;

  register long _no asm("rax") = no;

  register long _a1 asm("rdi") = a1;
  register long _a2 asm("rsi") = a2;
  register long _a3 asm("rdx") = a3;

  asm volatile("syscall\n\t"
               : "=a"(resultvar)
               : "r"(_no), "r"(_a1), "r"(_a2), "r"(_a3)
               : "memory", "cc", "r11", "cx");
  
  return resultvar;
}

long dosys4(long no, long a1, long a2, long a3, long a4) {
  long resultvar;

  register long _no asm("rax") = no;

  register long _a1 asm("rdi") = a1;
  register long _a2 asm("rsi") = a2;
  register long _a3 asm("rdx") = a3;
  register long _a4 asm("r10") = a4;

  asm volatile("syscall\n\t"
               : "=a"(resultvar)
               : "r"(_no), "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4)
               : "memory", "cc", "r11", "cx");
  
  return resultvar;
}

long dosys5(long no, long a1, long a2, long a3, long a4, long a5) {
  long resultvar;

  register long _no asm("rax") = no;

  register long _a1 asm("rdi") = a1;
  register long _a2 asm("rsi") = a2;
  register long _a3 asm("rdx") = a3;
  register long _a4 asm("r10") = a4;
  register long _a5 asm("r8")  = a5;

  asm volatile("syscall\n\t"
               : "=a"(resultvar)
               : "r"(_no), "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5)
               : "memory", "cc", "r11", "cx");
  
  return resultvar;
}

long dosys6(long no, long a1, long a2, long a3, long a4, long a5, long a6) {
  long resultvar;

  register long _no asm("rax") = no;

  register long _a1 asm("rdi") = a1;
  register long _a2 asm("rsi") = a2;
  register long _a3 asm("rdx") = a3;
  register long _a4 asm("r10") = a4;
  register long _a5 asm("r8")  = a5;
  register long _a6 asm("r9")  = a6;

  asm volatile("syscall\n\t"
               : "=a"(resultvar)
               : "r"(_no), "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5),
                 "r"(_a6)
               : "memory", "cc", "r11", "cx");
  
  return resultvar;
}
