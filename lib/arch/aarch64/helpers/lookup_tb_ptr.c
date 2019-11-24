#define TARGET_AARCH64 1

#define CONFIG_USER_ONLY 1

#define QEMU_ALIGNED(X) __attribute__((aligned(X)))

#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#define likely(x)   __builtin_expect(!!(x), 1)

#define unlikely(x)   __builtin_expect(!!(x), 0)

#define container_of(ptr, type, member) ({                      \
        const typeof(((type *) 0)->member) *__mptr = (ptr);     \
        (type *) ((char *) __mptr - offsetof(type, member));})

#define QEMU_BUILD_BUG_MSG(x, msg) _Static_assert(!(x), msg)

#define QEMU_BUILD_BUG_ON(x) QEMU_BUILD_BUG_MSG(x, "not expecting: " #x)

#  define GCC_FMT_ATTR(n, m) __attribute__((format(printf, n, m)))

#include <stddef.h>

#include <stdbool.h>

#include <stdint.h>

#include <sys/types.h>

#include <stdio.h>

#include <inttypes.h>

#include <limits.h>

#include <setjmp.h>

typedef char   gchar;

typedef unsigned int    guint;

typedef void* gpointer;

typedef struct _GArray		GArray;

struct _GArray
{
  gchar *data;
  guint len;
};

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

typedef struct ObjectClass ObjectClass;

typedef struct QemuMutex QemuMutex;

typedef struct QemuOpts QemuOpts;

typedef struct QemuSpin QemuSpin;

typedef struct QEMUTimer QEMUTimer;

typedef struct IRQState *qemu_irq;

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

typedef uint8_t flag;

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

#define barrier()   ({ asm volatile("" ::: "memory"); (void)0; })

#define typeof_strip_qual(expr)                                                    \
  typeof(                                                                          \
    __builtin_choose_expr(                                                         \
      __builtin_types_compatible_p(typeof(expr), bool) ||                          \
        __builtin_types_compatible_p(typeof(expr), const bool) ||                  \
        __builtin_types_compatible_p(typeof(expr), volatile bool) ||               \
        __builtin_types_compatible_p(typeof(expr), const volatile bool),           \
        (bool)1,                                                                   \
    __builtin_choose_expr(                                                         \
      __builtin_types_compatible_p(typeof(expr), signed char) ||                   \
        __builtin_types_compatible_p(typeof(expr), const signed char) ||           \
        __builtin_types_compatible_p(typeof(expr), volatile signed char) ||        \
        __builtin_types_compatible_p(typeof(expr), const volatile signed char),    \
        (signed char)1,                                                            \
    __builtin_choose_expr(                                                         \
      __builtin_types_compatible_p(typeof(expr), unsigned char) ||                 \
        __builtin_types_compatible_p(typeof(expr), const unsigned char) ||         \
        __builtin_types_compatible_p(typeof(expr), volatile unsigned char) ||      \
        __builtin_types_compatible_p(typeof(expr), const volatile unsigned char),  \
        (unsigned char)1,                                                          \
    __builtin_choose_expr(                                                         \
      __builtin_types_compatible_p(typeof(expr), signed short) ||                  \
        __builtin_types_compatible_p(typeof(expr), const signed short) ||          \
        __builtin_types_compatible_p(typeof(expr), volatile signed short) ||       \
        __builtin_types_compatible_p(typeof(expr), const volatile signed short),   \
        (signed short)1,                                                           \
    __builtin_choose_expr(                                                         \
      __builtin_types_compatible_p(typeof(expr), unsigned short) ||                \
        __builtin_types_compatible_p(typeof(expr), const unsigned short) ||        \
        __builtin_types_compatible_p(typeof(expr), volatile unsigned short) ||     \
        __builtin_types_compatible_p(typeof(expr), const volatile unsigned short), \
        (unsigned short)1,                                                         \
      (expr)+0))))))

#define smp_read_barrier_depends()   barrier()

# define ATOMIC_REG_SIZE  sizeof(void *)

#define atomic_read__nocheck(ptr) \
    __atomic_load_n(ptr, __ATOMIC_RELAXED)

#define atomic_read(ptr)                              \
    ({                                                \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > ATOMIC_REG_SIZE); \
    atomic_read__nocheck(ptr);                        \
    })

#define atomic_set__nocheck(ptr, i) \
    __atomic_store_n(ptr, i, __ATOMIC_RELAXED)

#define atomic_set(ptr, i)  do {                      \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > ATOMIC_REG_SIZE); \
    atomic_set__nocheck(ptr, i);                      \
} while(0)

#define atomic_rcu_read__nocheck(ptr, valptr)           \
    __atomic_load(ptr, valptr, __ATOMIC_RELAXED);       \
    smp_read_barrier_depends();

#define atomic_rcu_read(ptr)                          \
    ({                                                \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > ATOMIC_REG_SIZE); \
    typeof_strip_qual(*ptr) _val;                     \
    atomic_rcu_read__nocheck(ptr, &_val);             \
    _val;                                             \
    })

#define BITS_PER_BYTE           CHAR_BIT

#define BITS_TO_LONGS(nr)       DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))

#define QLIST_HEAD(name, type)                                          \
struct name {                                                           \
        struct type *lh_first;  /* first element */                     \
}

#define QLIST_ENTRY(type)                                               \
struct {                                                                \
        struct type *le_next;   /* next element */                      \
        struct type **le_prev;  /* address of previous next element */  \
}

#define QSIMPLEQ_HEAD(name, type)                                       \
struct name {                                                           \
    struct type *sqh_first;    /* first element */                      \
    struct type **sqh_last;    /* addr of last next element */          \
}

#define QSIMPLEQ_ENTRY(type)                                            \
struct {                                                                \
    struct type *sqe_next;    /* next element */                        \
}

#define QTAILQ_HEAD(name, type)                                         \
union name {                                                            \
        struct type *tqh_first;       /* first element */               \
        QTailQLink tqh_circ;          /* link for circular backwards list */ \
}

#define QTAILQ_ENTRY(type)                                              \
union {                                                                 \
        struct type *tqe_next;        /* next element */                \
        QTailQLink tqe_circ;          /* link for circular backwards list */ \
}

#define DECLARE_BITMAP(name,bits)                  \
        unsigned long name[BITS_TO_LONGS(bits)]

typedef struct QTailQLink {
    void *tql_next;
    struct QTailQLink *tql_prev;
} QTailQLink;

struct TypeImpl;

typedef struct TypeImpl *Type;

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
    bool allow_unplug_during_migration;
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

struct QemuMutex {
    pthread_mutex_t lock;
#ifdef CONFIG_DEBUG_MUTEX
    const char *file;
    int line;
#endif
    bool initialized;
};

struct QemuCond {
    pthread_cond_t cond;
    bool initialized;
};

struct QemuThread {
    pthread_t thread;
};

struct QemuSpin {
    int value;
};

enum qemu_plugin_event {
    QEMU_PLUGIN_EV_VCPU_INIT,
    QEMU_PLUGIN_EV_VCPU_EXIT,
    QEMU_PLUGIN_EV_VCPU_TB_TRANS,
    QEMU_PLUGIN_EV_VCPU_IDLE,
    QEMU_PLUGIN_EV_VCPU_RESUME,
    QEMU_PLUGIN_EV_VCPU_SYSCALL,
    QEMU_PLUGIN_EV_VCPU_SYSCALL_RET,
    QEMU_PLUGIN_EV_FLUSH,
    QEMU_PLUGIN_EV_ATEXIT,
    QEMU_PLUGIN_EV_MAX, /* total number of plugin events we support */
};

typedef uint64_t vaddr;

typedef struct CPUWatchpoint CPUWatchpoint;

struct TranslationBlock;

typedef union IcountDecr {
    uint32_t u32;
    struct {
#ifdef HOST_WORDS_BIGENDIAN
        uint16_t high;
        uint16_t low;
#else
        uint16_t low;
        uint16_t high;
#endif
    } u16;
} IcountDecr;

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
    bool in_exclusive_context;
    uint32_t cflags_next_tb;
    /* updates protected by BQL */
    uint32_t interrupt_request;
    int singlestep_enabled;
    int64_t icount_budget;
    int64_t icount_extra;
    uint64_t random_seed;
    sigjmp_buf jmp_env;

    QemuMutex work_mutex;
    struct qemu_work_item *queued_work_first, *queued_work_last;

    CPUAddressSpace *cpu_ases;
    int num_ases;
    AddressSpace *as;
    MemoryRegion *memory;

    void *env_ptr; /* CPUArchState */
    IcountDecr *icount_decr_ptr;

    /* Accessed in parallel; all accesses must be atomic */
    struct TranslationBlock *tb_jmp_cache[TB_JMP_CACHE_SIZE];

    struct GDBRegisterState *gdb_regs;
    int gdb_num_regs;
    int gdb_num_g_regs;
    QTAILQ_ENTRY(CPUState) node;

    /* ice debug support */
    QTAILQ_HEAD(, CPUBreakpoint) breakpoints;

    QTAILQ_HEAD(, CPUWatchpoint) watchpoints;
    CPUWatchpoint *watchpoint_hit;

    void *opaque;

    /* In order to avoid passing too many arguments to the MMIO helpers,
     * we store some rarely used information in the CPU context.
     */
    uintptr_t mem_io_pc;

    int kvm_fd;
    struct KVMState *kvm_state;
    struct kvm_run *kvm_run;

    /* Used for events with 'vcpu' and *without* the 'disabled' properties */
    DECLARE_BITMAP(trace_dstate_delayed, CPU_TRACE_DSTATE_MAX_EVENTS);
    DECLARE_BITMAP(trace_dstate, CPU_TRACE_DSTATE_MAX_EVENTS);

    DECLARE_BITMAP(plugin_mask, QEMU_PLUGIN_EV_MAX);

    GArray *plugin_mem_cbs;

    /* TODO Move common fields from CPUArchState here. */
    int cpu_index;
    int cluster_index;
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

    struct hax_vcpu_state *hax_vcpu;

    int hvf_fd;

    /* track IOMMUs whose translations we've cached in the TCG TLB */
    GArray *iommu_notifiers;
};

struct arm_boot_info;

typedef struct ARMCPU ARMCPU;

#define TCG_TARGET_NB_REGS 64

typedef enum {
    TCG_REG_X0, TCG_REG_X1, TCG_REG_X2, TCG_REG_X3,
    TCG_REG_X4, TCG_REG_X5, TCG_REG_X6, TCG_REG_X7,
    TCG_REG_X8, TCG_REG_X9, TCG_REG_X10, TCG_REG_X11,
    TCG_REG_X12, TCG_REG_X13, TCG_REG_X14, TCG_REG_X15,
    TCG_REG_X16, TCG_REG_X17, TCG_REG_X18, TCG_REG_X19,
    TCG_REG_X20, TCG_REG_X21, TCG_REG_X22, TCG_REG_X23,
    TCG_REG_X24, TCG_REG_X25, TCG_REG_X26, TCG_REG_X27,
    TCG_REG_X28, TCG_REG_X29, TCG_REG_X30,

    /* X31 is either the stack pointer or zero, depending on context.  */
    TCG_REG_SP = 31,
    TCG_REG_XZR = 31,

    TCG_REG_V0 = 32, TCG_REG_V1, TCG_REG_V2, TCG_REG_V3,
    TCG_REG_V4, TCG_REG_V5, TCG_REG_V6, TCG_REG_V7,
    TCG_REG_V8, TCG_REG_V9, TCG_REG_V10, TCG_REG_V11,
    TCG_REG_V12, TCG_REG_V13, TCG_REG_V14, TCG_REG_V15,
    TCG_REG_V16, TCG_REG_V17, TCG_REG_V18, TCG_REG_V19,
    TCG_REG_V20, TCG_REG_V21, TCG_REG_V22, TCG_REG_V23,
    TCG_REG_V24, TCG_REG_V25, TCG_REG_V26, TCG_REG_V27,
    TCG_REG_V28, TCG_REG_V29, TCG_REG_V30, TCG_REG_V31,

    /* Aliases.  */
    TCG_REG_FP = TCG_REG_X29,
    TCG_REG_LR = TCG_REG_X30,
    TCG_AREG0  = TCG_REG_X19,
} TCGReg;

#define TCG_TARGET_NEED_POOL_LABELS

# define TARGET_LONG_BITS             64

#define TARGET_FMT_lx "%016" PRIx64

typedef uint64_t target_ulong;

typedef struct CPUTLB { } CPUTLB;

typedef struct CPUNegativeOffsetState {
    CPUTLB tlb;
    IcountDecr icount_decr;
} CPUNegativeOffsetState;

#define TARGET_INSN_START_EXTRA_WORDS 2

enum {
    M_REG_NS = 0,
    M_REG_S = 1,
    M_REG_NUM_BANKS = 2,
};

typedef struct DynamicGDBXMLInfo {
    char *desc;
    int num_cpregs;
    uint32_t *cpregs_keys;
} DynamicGDBXMLInfo;

#define NUM_GTIMERS 4

typedef struct ARMGenericTimer {
    uint64_t cval; /* Timer CompareValue register */
    uint64_t ctl; /* Timer Control register */
} ARMGenericTimer;

# define ARM_MAX_VQ    16

typedef struct {
    uint64_t raw_tcr;
    uint32_t mask;
    uint32_t base_mask;
} TCR;

typedef struct ARMVectorReg {
    uint64_t d[2 * ARM_MAX_VQ] QEMU_ALIGNED(16);
} ARMVectorReg;

typedef struct ARMPredicateReg {
    uint64_t p[DIV_ROUND_UP(2 * ARM_MAX_VQ, 8)] QEMU_ALIGNED(16);
} ARMPredicateReg;

typedef struct ARMPACKey {
    uint64_t lo, hi;
} ARMPACKey;

typedef struct CPUARMState {
    /* Regs for current mode.  */
    uint32_t regs[16];

    /* 32/64 switch only happens when taking and returning from
     * exceptions so the overlap semantics are taken care of then
     * instead of having a complicated union.
     */
    /* Regs for A64 mode.  */
    uint64_t xregs[32];
    uint64_t pc;
    /* PSTATE isn't an architectural register for ARMv8. However, it is
     * convenient for us to assemble the underlying state into a 32 bit format
     * identical to the architectural format used for the SPSR. (This is also
     * what the Linux kernel's 'pstate' field in signal handlers and KVM's
     * 'pstate' register are.) Of the PSTATE bits:
     *  NZCV are kept in the split out env->CF/VF/NF/ZF, (which have the same
     *    semantics as for AArch32, as described in the comments on each field)
     *  nRW (also known as M[4]) is kept, inverted, in env->aarch64
     *  DAIF (exception masks) are kept in env->daif
     *  BTYPE is kept in env->btype
     *  all other bits are stored in their correct places in env->pstate
     */
    uint32_t pstate;
    uint32_t aarch64; /* 1 if CPU is in aarch64 state; inverse of PSTATE.nRW */

    /* Cached TBFLAGS state.  See below for which bits are included.  */
    uint32_t hflags;

    /* Frequently accessed CPSR bits are stored separately for efficiency.
       This contains all the other bits.  Use cpsr_{read,write} to access
       the whole CPSR.  */
    uint32_t uncached_cpsr;
    uint32_t spsr;

    /* Banked registers.  */
    uint64_t banked_spsr[8];
    uint32_t banked_r13[8];
    uint32_t banked_r14[8];

    /* These hold r8-r12.  */
    uint32_t usr_regs[5];
    uint32_t fiq_regs[5];

    /* cpsr flag cache for faster execution */
    uint32_t CF; /* 0 or 1 */
    uint32_t VF; /* V is the bit 31. All other bits are undefined */
    uint32_t NF; /* N is bit 31. All other bits are undefined.  */
    uint32_t ZF; /* Z set if zero.  */
    uint32_t QF; /* 0 or 1 */
    uint32_t GE; /* cpsr[19:16] */
    uint32_t thumb; /* cpsr[5]. 0 = arm mode, 1 = thumb mode. */
    uint32_t condexec_bits; /* IT bits.  cpsr[15:10,26:25].  */
    uint32_t btype;  /* BTI branch type.  spsr[11:10].  */
    uint64_t daif; /* exception masks, in the bits they are in PSTATE */

    uint64_t elr_el[4]; /* AArch64 exception link regs  */
    uint64_t sp_el[4]; /* AArch64 banked stack pointers */

    /* System control coprocessor (cp15) */
    struct {
        uint32_t c0_cpuid;
        union { /* Cache size selection */
            struct {
                uint64_t _unused_csselr0;
                uint64_t csselr_ns;
                uint64_t _unused_csselr1;
                uint64_t csselr_s;
            };
            uint64_t csselr_el[4];
        };
        union { /* System control register. */
            struct {
                uint64_t _unused_sctlr;
                uint64_t sctlr_ns;
                uint64_t hsctlr;
                uint64_t sctlr_s;
            };
            uint64_t sctlr_el[4];
        };
        uint64_t cpacr_el1; /* Architectural feature access control register */
        uint64_t cptr_el[4];  /* ARMv8 feature trap registers */
        uint32_t c1_xscaleauxcr; /* XScale auxiliary control register.  */
        uint64_t sder; /* Secure debug enable register. */
        uint32_t nsacr; /* Non-secure access control register. */
        union { /* MMU translation table base 0. */
            struct {
                uint64_t _unused_ttbr0_0;
                uint64_t ttbr0_ns;
                uint64_t _unused_ttbr0_1;
                uint64_t ttbr0_s;
            };
            uint64_t ttbr0_el[4];
        };
        union { /* MMU translation table base 1. */
            struct {
                uint64_t _unused_ttbr1_0;
                uint64_t ttbr1_ns;
                uint64_t _unused_ttbr1_1;
                uint64_t ttbr1_s;
            };
            uint64_t ttbr1_el[4];
        };
        uint64_t vttbr_el2; /* Virtualization Translation Table Base.  */
        /* MMU translation table base control. */
        TCR tcr_el[4];
        TCR vtcr_el2; /* Virtualization Translation Control.  */
        uint32_t c2_data; /* MPU data cacheable bits.  */
        uint32_t c2_insn; /* MPU instruction cacheable bits.  */
        union { /* MMU domain access control register
                 * MPU write buffer control.
                 */
            struct {
                uint64_t dacr_ns;
                uint64_t dacr_s;
            };
            struct {
                uint64_t dacr32_el2;
            };
        };
        uint32_t pmsav5_data_ap; /* PMSAv5 MPU data access permissions */
        uint32_t pmsav5_insn_ap; /* PMSAv5 MPU insn access permissions */
        uint64_t hcr_el2; /* Hypervisor configuration register */
        uint64_t scr_el3; /* Secure configuration register.  */
        union { /* Fault status registers.  */
            struct {
                uint64_t ifsr_ns;
                uint64_t ifsr_s;
            };
            struct {
                uint64_t ifsr32_el2;
            };
        };
        union {
            struct {
                uint64_t _unused_dfsr;
                uint64_t dfsr_ns;
                uint64_t hsr;
                uint64_t dfsr_s;
            };
            uint64_t esr_el[4];
        };
        uint32_t c6_region[8]; /* MPU base/size registers.  */
        union { /* Fault address registers. */
            struct {
                uint64_t _unused_far0;
#ifdef HOST_WORDS_BIGENDIAN
                uint32_t ifar_ns;
                uint32_t dfar_ns;
                uint32_t ifar_s;
                uint32_t dfar_s;
#else
                uint32_t dfar_ns;
                uint32_t ifar_ns;
                uint32_t dfar_s;
                uint32_t ifar_s;
#endif
                uint64_t _unused_far3;
            };
            uint64_t far_el[4];
        };
        uint64_t hpfar_el2;
        uint64_t hstr_el2;
        union { /* Translation result. */
            struct {
                uint64_t _unused_par_0;
                uint64_t par_ns;
                uint64_t _unused_par_1;
                uint64_t par_s;
            };
            uint64_t par_el[4];
        };

        uint32_t c9_insn; /* Cache lockdown registers.  */
        uint32_t c9_data;
        uint64_t c9_pmcr; /* performance monitor control register */
        uint64_t c9_pmcnten; /* perf monitor counter enables */
        uint64_t c9_pmovsr; /* perf monitor overflow status */
        uint64_t c9_pmuserenr; /* perf monitor user enable */
        uint64_t c9_pmselr; /* perf monitor counter selection register */
        uint64_t c9_pminten; /* perf monitor interrupt enables */
        union { /* Memory attribute redirection */
            struct {
#ifdef HOST_WORDS_BIGENDIAN
                uint64_t _unused_mair_0;
                uint32_t mair1_ns;
                uint32_t mair0_ns;
                uint64_t _unused_mair_1;
                uint32_t mair1_s;
                uint32_t mair0_s;
#else
                uint64_t _unused_mair_0;
                uint32_t mair0_ns;
                uint32_t mair1_ns;
                uint64_t _unused_mair_1;
                uint32_t mair0_s;
                uint32_t mair1_s;
#endif
            };
            uint64_t mair_el[4];
        };
        union { /* vector base address register */
            struct {
                uint64_t _unused_vbar;
                uint64_t vbar_ns;
                uint64_t hvbar;
                uint64_t vbar_s;
            };
            uint64_t vbar_el[4];
        };
        uint32_t mvbar; /* (monitor) vector base address register */
        struct { /* FCSE PID. */
            uint32_t fcseidr_ns;
            uint32_t fcseidr_s;
        };
        union { /* Context ID. */
            struct {
                uint64_t _unused_contextidr_0;
                uint64_t contextidr_ns;
                uint64_t _unused_contextidr_1;
                uint64_t contextidr_s;
            };
            uint64_t contextidr_el[4];
        };
        union { /* User RW Thread register. */
            struct {
                uint64_t tpidrurw_ns;
                uint64_t tpidrprw_ns;
                uint64_t htpidr;
                uint64_t _tpidr_el3;
            };
            uint64_t tpidr_el[4];
        };
        /* The secure banks of these registers don't map anywhere */
        uint64_t tpidrurw_s;
        uint64_t tpidrprw_s;
        uint64_t tpidruro_s;

        union { /* User RO Thread register. */
            uint64_t tpidruro_ns;
            uint64_t tpidrro_el[1];
        };
        uint64_t c14_cntfrq; /* Counter Frequency register */
        uint64_t c14_cntkctl; /* Timer Control register */
        uint32_t cnthctl_el2; /* Counter/Timer Hyp Control register */
        uint64_t cntvoff_el2; /* Counter Virtual Offset register */
        ARMGenericTimer c14_timer[NUM_GTIMERS];
        uint32_t c15_cpar; /* XScale Coprocessor Access Register */
        uint32_t c15_ticonfig; /* TI925T configuration byte.  */
        uint32_t c15_i_max; /* Maximum D-cache dirty line index.  */
        uint32_t c15_i_min; /* Minimum D-cache dirty line index.  */
        uint32_t c15_threadid; /* TI debugger thread-ID.  */
        uint32_t c15_config_base_address; /* SCU base address.  */
        uint32_t c15_diagnostic; /* diagnostic register */
        uint32_t c15_power_diagnostic;
        uint32_t c15_power_control; /* power control */
        uint64_t dbgbvr[16]; /* breakpoint value registers */
        uint64_t dbgbcr[16]; /* breakpoint control registers */
        uint64_t dbgwvr[16]; /* watchpoint value registers */
        uint64_t dbgwcr[16]; /* watchpoint control registers */
        uint64_t mdscr_el1;
        uint64_t oslsr_el1; /* OS Lock Status */
        uint64_t mdcr_el2;
        uint64_t mdcr_el3;
        /* Stores the architectural value of the counter *the last time it was
         * updated* by pmccntr_op_start. Accesses should always be surrounded
         * by pmccntr_op_start/pmccntr_op_finish to guarantee the latest
         * architecturally-correct value is being read/set.
         */
        uint64_t c15_ccnt;
        /* Stores the delta between the architectural value and the underlying
         * cycle count during normal operation. It is used to update c15_ccnt
         * to be the correct architectural value before accesses. During
         * accesses, c15_ccnt_delta contains the underlying count being used
         * for the access, after which it reverts to the delta value in
         * pmccntr_op_finish.
         */
        uint64_t c15_ccnt_delta;
        uint64_t c14_pmevcntr[31];
        uint64_t c14_pmevcntr_delta[31];
        uint64_t c14_pmevtyper[31];
        uint64_t pmccfiltr_el0; /* Performance Monitor Filter Register */
        uint64_t vpidr_el2; /* Virtualization Processor ID Register */
        uint64_t vmpidr_el2; /* Virtualization Multiprocessor ID Register */
    } cp15;

    struct {
        /* M profile has up to 4 stack pointers:
         * a Main Stack Pointer and a Process Stack Pointer for each
         * of the Secure and Non-Secure states. (If the CPU doesn't support
         * the security extension then it has only two SPs.)
         * In QEMU we always store the currently active SP in regs[13],
         * and the non-active SP for the current security state in
         * v7m.other_sp. The stack pointers for the inactive security state
         * are stored in other_ss_msp and other_ss_psp.
         * switch_v7m_security_state() is responsible for rearranging them
         * when we change security state.
         */
        uint32_t other_sp;
        uint32_t other_ss_msp;
        uint32_t other_ss_psp;
        uint32_t vecbase[M_REG_NUM_BANKS];
        uint32_t basepri[M_REG_NUM_BANKS];
        uint32_t control[M_REG_NUM_BANKS];
        uint32_t ccr[M_REG_NUM_BANKS]; /* Configuration and Control */
        uint32_t cfsr[M_REG_NUM_BANKS]; /* Configurable Fault Status */
        uint32_t hfsr; /* HardFault Status */
        uint32_t dfsr; /* Debug Fault Status Register */
        uint32_t sfsr; /* Secure Fault Status Register */
        uint32_t mmfar[M_REG_NUM_BANKS]; /* MemManage Fault Address */
        uint32_t bfar; /* BusFault Address */
        uint32_t sfar; /* Secure Fault Address Register */
        unsigned mpu_ctrl[M_REG_NUM_BANKS]; /* MPU_CTRL */
        int exception;
        uint32_t primask[M_REG_NUM_BANKS];
        uint32_t faultmask[M_REG_NUM_BANKS];
        uint32_t aircr; /* only holds r/w state if security extn implemented */
        uint32_t secure; /* Is CPU in Secure state? (not guest visible) */
        uint32_t csselr[M_REG_NUM_BANKS];
        uint32_t scr[M_REG_NUM_BANKS];
        uint32_t msplim[M_REG_NUM_BANKS];
        uint32_t psplim[M_REG_NUM_BANKS];
        uint32_t fpcar[M_REG_NUM_BANKS];
        uint32_t fpccr[M_REG_NUM_BANKS];
        uint32_t fpdscr[M_REG_NUM_BANKS];
        uint32_t cpacr[M_REG_NUM_BANKS];
        uint32_t nsacr;
    } v7m;

    /* Information associated with an exception about to be taken:
     * code which raises an exception must set cs->exception_index and
     * the relevant parts of this structure; the cpu_do_interrupt function
     * will then set the guest-visible registers as part of the exception
     * entry process.
     */
    struct {
        uint32_t syndrome; /* AArch64 format syndrome register */
        uint32_t fsr; /* AArch32 format fault status register info */
        uint64_t vaddress; /* virtual addr associated with exception, if any */
        uint32_t target_el; /* EL the exception should be targeted for */
        /* If we implement EL2 we will also need to store information
         * about the intermediate physical address for stage 2 faults.
         */
    } exception;

    /* Information associated with an SError */
    struct {
        uint8_t pending;
        uint8_t has_esr;
        uint64_t esr;
    } serror;

    /* State of our input IRQ/FIQ/VIRQ/VFIQ lines */
    uint32_t irq_line_state;

    /* Thumb-2 EE state.  */
    uint32_t teecr;
    uint32_t teehbr;

    /* VFP coprocessor state.  */
    struct {
        ARMVectorReg zregs[32];

#ifdef TARGET_AARCH64
        /* Store FFR as pregs[16] to make it easier to treat as any other.  */
#define FFR_PRED_NUM 16
        ARMPredicateReg pregs[17];
        /* Scratch space for aa64 sve predicate temporary.  */
        ARMPredicateReg preg_tmp;
#endif

        /* We store these fpcsr fields separately for convenience.  */
        uint32_t qc[4] QEMU_ALIGNED(16);
        int vec_len;
        int vec_stride;

        uint32_t xregs[16];

        /* Scratch space for aa32 neon expansion.  */
        uint32_t scratch[8];

        /* There are a number of distinct float control structures:
         *
         *  fp_status: is the "normal" fp status.
         *  fp_status_fp16: used for half-precision calculations
         *  standard_fp_status : the ARM "Standard FPSCR Value"
         *
         * Half-precision operations are governed by a separate
         * flush-to-zero control bit in FPSCR:FZ16. We pass a separate
         * status structure to control this.
         *
         * The "Standard FPSCR", ie default-NaN, flush-to-zero,
         * round-to-nearest and is used by any operations (generally
         * Neon) which the architecture defines as controlled by the
         * standard FPSCR value rather than the FPSCR.
         *
         * To avoid having to transfer exception bits around, we simply
         * say that the FPSCR cumulative exception flags are the logical
         * OR of the flags in the three fp statuses. This relies on the
         * only thing which needs to read the exception flags being
         * an explicit FPSCR read.
         */
        float_status fp_status;
        float_status fp_status_f16;
        float_status standard_fp_status;

        /* ZCR_EL[1-3] */
        uint64_t zcr_el[4];
    } vfp;
    uint64_t exclusive_addr;
    uint64_t exclusive_val;
    uint64_t exclusive_high;

    /* iwMMXt coprocessor state.  */
    struct {
        uint64_t regs[16];
        uint64_t val;

        uint32_t cregs[16];
    } iwmmxt;

#ifdef TARGET_AARCH64
    struct {
        ARMPACKey apia;
        ARMPACKey apib;
        ARMPACKey apda;
        ARMPACKey apdb;
        ARMPACKey apga;
    } keys;
#endif

#if defined(CONFIG_USER_ONLY)
    /* For usermode syscall translation.  */
    int eabi;
#endif

    struct CPUBreakpoint *cpu_breakpoint[16];
    struct CPUWatchpoint *cpu_watchpoint[16];

    /* Fields up to this point are cleared by a CPU reset */
    struct {} end_reset_fields;

    /* Fields after this point are preserved across CPU reset. */

    /* Internal CPU feature flags.  */
    uint64_t features;

    /* PMSAv7 MPU */
    struct {
        uint32_t *drbar;
        uint32_t *drsr;
        uint32_t *dracr;
        uint32_t rnr[M_REG_NUM_BANKS];
    } pmsav7;

    /* PMSAv8 MPU */
    struct {
        /* The PMSAv8 implementation also shares some PMSAv7 config
         * and state:
         *  pmsav7.rnr (region number register)
         *  pmsav7_dregion (number of configured regions)
         */
        uint32_t *rbar[M_REG_NUM_BANKS];
        uint32_t *rlar[M_REG_NUM_BANKS];
        uint32_t mair0[M_REG_NUM_BANKS];
        uint32_t mair1[M_REG_NUM_BANKS];
    } pmsav8;

    /* v8M SAU */
    struct {
        uint32_t *rbar;
        uint32_t *rlar;
        uint32_t rnr;
        uint32_t ctrl;
    } sau;

    void *nvic;
    const struct arm_boot_info *boot_info;
    /* Store GICv3CPUState to access from this struct */
    void *gicv3state;
} CPUARMState;

typedef void ARMELChangeHookFn(ARMCPU *cpu, void *opaque);

struct ARMELChangeHook {
    ARMELChangeHookFn *hook;
    void *opaque;
    QLIST_ENTRY(ARMELChangeHook) node;
};

typedef enum ARMPSCIState {
    PSCI_ON = 0,
    PSCI_OFF = 1,
    PSCI_ON_PENDING = 2
} ARMPSCIState;

struct ARMISARegisters {
    uint32_t id_isar0;
    uint32_t id_isar1;
    uint32_t id_isar2;
    uint32_t id_isar3;
    uint32_t id_isar4;
    uint32_t id_isar5;
    uint32_t id_isar6;
    uint32_t mvfr0;
    uint32_t mvfr1;
    uint32_t mvfr2;
    uint64_t id_aa64isar0;
    uint64_t id_aa64isar1;
    uint64_t id_aa64pfr0;
    uint64_t id_aa64pfr1;
    uint64_t id_aa64mmfr0;
    uint64_t id_aa64mmfr1;
};

struct ARMCPU {
    /*< private >*/
    CPUState parent_obj;
    /*< public >*/

    CPUNegativeOffsetState neg;
    CPUARMState env;

    /* Coprocessor information */
    GHashTable *cp_regs;
    /* For marshalling (mostly coprocessor) register state between the
     * kernel and QEMU (for KVM) and between two QEMUs (for migration),
     * we use these arrays.
     */
    /* List of register indexes managed via these arrays; (full KVM style
     * 64 bit indexes, not CPRegInfo 32 bit indexes)
     */
    uint64_t *cpreg_indexes;
    /* Values of the registers (cpreg_indexes[i]'s value is cpreg_values[i]) */
    uint64_t *cpreg_values;
    /* Length of the indexes, values, reset_values arrays */
    int32_t cpreg_array_len;
    /* These are used only for migration: incoming data arrives in
     * these fields and is sanity checked in post_load before copying
     * to the working data structures above.
     */
    uint64_t *cpreg_vmstate_indexes;
    uint64_t *cpreg_vmstate_values;
    int32_t cpreg_vmstate_array_len;

    DynamicGDBXMLInfo dyn_xml;

    /* Timers used by the generic (architected) timer */
    QEMUTimer *gt_timer[NUM_GTIMERS];
    /*
     * Timer used by the PMU. Its state is restored after migration by
     * pmu_op_finish() - it does not need other handling during migration
     */
    QEMUTimer *pmu_timer;
    /* GPIO outputs for generic timer */
    qemu_irq gt_timer_outputs[NUM_GTIMERS];
    /* GPIO output for GICv3 maintenance interrupt signal */
    qemu_irq gicv3_maintenance_interrupt;
    /* GPIO output for the PMU interrupt */
    qemu_irq pmu_interrupt;

    /* MemoryRegion to use for secure physical accesses */
    MemoryRegion *secure_memory;

    /* For v8M, pointer to the IDAU interface provided by board/SoC */
    Object *idau;

    /* 'compatible' string for this CPU for Linux device trees */
    const char *dtb_compatible;

    /* PSCI version for this CPU
     * Bits[31:16] = Major Version
     * Bits[15:0] = Minor Version
     */
    uint32_t psci_version;

    /* Should CPU start in PSCI powered-off state? */
    bool start_powered_off;

    /* Current power state, access guarded by BQL */
    ARMPSCIState power_state;

    /* CPU has virtualization extension */
    bool has_el2;
    /* CPU has security extension */
    bool has_el3;
    /* CPU has PMU (Performance Monitor Unit) */
    bool has_pmu;
    /* CPU has VFP */
    bool has_vfp;
    /* CPU has Neon */
    bool has_neon;
    /* CPU has M-profile DSP extension */
    bool has_dsp;

    /* CPU has memory protection unit */
    bool has_mpu;
    /* PMSAv7 MPU number of supported regions */
    uint32_t pmsav7_dregion;
    /* v8M SAU number of supported regions */
    uint32_t sau_sregion;

    /* PSCI conduit used to invoke PSCI methods
     * 0 - disabled, 1 - smc, 2 - hvc
     */
    uint32_t psci_conduit;

    /* For v8M, initial value of the Secure VTOR */
    uint32_t init_svtor;

    /* [QEMU_]KVM_ARM_TARGET_* constant for this CPU, or
     * QEMU_KVM_ARM_TARGET_NONE if the kernel doesn't support this CPU type.
     */
    uint32_t kvm_target;

    /* KVM init features for this CPU */
    uint32_t kvm_init_features[7];

    /* Uniprocessor system with MP extensions */
    bool mp_is_up;

    /* True if we tried kvm_arm_host_cpu_features() during CPU instance_init
     * and the probe failed (so we need to report the error in realize)
     */
    bool host_cpu_probe_failed;

    /* Specify the number of cores in this CPU cluster. Used for the L2CTLR
     * register.
     */
    int32_t core_count;

    /* The instance init functions for implementation-specific subclasses
     * set these fields to specify the implementation-dependent values of
     * various constant registers and reset values of non-constant
     * registers.
     * Some of these might become QOM properties eventually.
     * Field names match the official register names as defined in the
     * ARMv7AR ARM Architecture Reference Manual. A reset_ prefix
     * is used for reset values of non-constant registers; no reset_
     * prefix means a constant register.
     * Some of these registers are split out into a substructure that
     * is shared with the translators to control the ISA.
     */
    struct ARMISARegisters isar;
    uint32_t midr;
    uint32_t revidr;
    uint32_t reset_fpsid;
    uint32_t ctr;
    uint32_t reset_sctlr;
    uint32_t id_pfr0;
    uint32_t id_pfr1;
    uint32_t id_dfr0;
    uint64_t pmceid0;
    uint64_t pmceid1;
    uint32_t id_afr0;
    uint32_t id_mmfr0;
    uint32_t id_mmfr1;
    uint32_t id_mmfr2;
    uint32_t id_mmfr3;
    uint32_t id_mmfr4;
    uint64_t id_aa64dfr0;
    uint64_t id_aa64dfr1;
    uint64_t id_aa64afr0;
    uint64_t id_aa64afr1;
    uint32_t dbgdidr;
    uint32_t clidr;
    uint64_t mp_affinity; /* MP ID without feature bits */
    /* The elements of this array are the CCSIDR values for each cache,
     * in the order L1DCache, L1ICache, L2DCache, L2ICache, etc.
     */
    uint32_t ccsidr[16];
    uint64_t reset_cbar;
    uint32_t reset_auxcr;
    bool reset_hivecs;
    /* DCZ blocksize, in log_2(words), ie low 4 bits of DCZID_EL0 */
    uint32_t dcz_blocksize;
    uint64_t rvbar;

    /* Configurable aspects of GIC cpu interface (which is part of the CPU) */
    int gic_num_lrs; /* number of list registers */
    int gic_vpribits; /* number of virtual priority bits */
    int gic_vprebits; /* number of virtual preemption bits */

    /* Whether the cfgend input is high (i.e. this CPU should reset into
     * big-endian mode).  This setting isn't used directly: instead it modifies
     * the reset_sctlr value to have SCTLR_B or SCTLR_EE set, depending on the
     * architecture version.
     */
    bool cfgend;

    QLIST_HEAD(, ARMELChangeHook) pre_el_change_hooks;
    QLIST_HEAD(, ARMELChangeHook) el_change_hooks;

    int32_t node_id; /* NUMA node this CPU belongs to */

    /* Used to synchronize KVM and QEMU in-kernel device levels */
    uint8_t device_irq_level;

    /* Used to set the maximum vector length the cpu will support.  */
    uint32_t sve_max_vq;

    /*
     * In sve_vq_map each set bit is a supported vector length of
     * (bit-number + 1) * 16 bytes, i.e. each bit number + 1 is the vector
     * length in quadwords.
     *
     * While processing properties during initialization, corresponding
     * sve_vq_init bits are set for bits in sve_vq_map that have been
     * set by properties.
     */
    DECLARE_BITMAP(sve_vq_map, ARM_MAX_VQ);
    DECLARE_BITMAP(sve_vq_init, ARM_MAX_VQ);
};

typedef CPUARMState CPUArchState;

typedef ARMCPU ArchCPU;

#define TARGET_ABI_BITS TARGET_LONG_BITS

#define ABI_LONG_ALIGNMENT (TARGET_ABI_BITS / 8)

typedef target_ulong abi_ulong __attribute__((aligned(ABI_LONG_ALIGNMENT)));

static inline ArchCPU *env_archcpu(CPUArchState *env)
{
    return container_of(env, ArchCPU, env);
}

static inline CPUState *env_cpu(CPUArchState *env)
{
    return &env_archcpu(env)->parent_obj;
}

void cpu_get_tb_cpu_state(CPUARMState *env, target_ulong *pc,
                          target_ulong *cs_base, uint32_t *flags);

#define HELPER(name) glue(helper_, name)

typedef struct TranslationBlock TranslationBlock;

#define MAX_OPC_PARAM_PER_ARG 1

#define MAX_OPC_PARAM_IARGS 6

#define MAX_OPC_PARAM_OARGS 1

#define MAX_OPC_PARAM_ARGS (MAX_OPC_PARAM_IARGS + MAX_OPC_PARAM_OARGS)

#define MAX_OPC_PARAM (4 + (MAX_OPC_PARAM_PER_ARG * MAX_OPC_PARAM_ARGS))

#  define TCG_TARGET_REG_BITS 64

typedef int64_t tcg_target_long;

typedef uint64_t tcg_target_ulong;

#define TCG_TARGET_MAYBE_vec            1

# define TARGET_INSN_START_WORDS (1 + TARGET_INSN_START_EXTRA_WORDS)

typedef uint64_t TCGRegSet;

typedef enum TCGOpcode {
#define DEF(name, oargs, iargs, cargs, flags) INDEX_op_ ## name,
/*
 * Tiny Code Generator for QEMU
 *
 * Copyright (c) 2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/*
 * DEF(name, oargs, iargs, cargs, flags)
 */

/* predefined ops */
DEF(discard, 1, 0, 0, TCG_OPF_NOT_PRESENT)
DEF(set_label, 0, 0, 1, TCG_OPF_BB_END | TCG_OPF_NOT_PRESENT)

/* variable number of parameters */
DEF(call, 0, 0, 3, TCG_OPF_CALL_CLOBBER | TCG_OPF_NOT_PRESENT)

DEF(br, 0, 0, 1, TCG_OPF_BB_END)

#define IMPL(X) (__builtin_constant_p(X) && (X) <= 0 ? TCG_OPF_NOT_PRESENT : 0)
#if TCG_TARGET_REG_BITS == 32
# define IMPL64  TCG_OPF_64BIT | TCG_OPF_NOT_PRESENT
#else
# define IMPL64  TCG_OPF_64BIT
#endif

DEF(mb, 0, 0, 1, 0)

DEF(mov_i32, 1, 1, 0, TCG_OPF_NOT_PRESENT)
DEF(movi_i32, 1, 0, 1, TCG_OPF_NOT_PRESENT)
DEF(setcond_i32, 1, 2, 1, 0)
DEF(movcond_i32, 1, 4, 1, IMPL(TCG_TARGET_HAS_movcond_i32))
/* load/store */
DEF(ld8u_i32, 1, 1, 1, 0)
DEF(ld8s_i32, 1, 1, 1, 0)
DEF(ld16u_i32, 1, 1, 1, 0)
DEF(ld16s_i32, 1, 1, 1, 0)
DEF(ld_i32, 1, 1, 1, 0)
DEF(st8_i32, 0, 2, 1, 0)
DEF(st16_i32, 0, 2, 1, 0)
DEF(st_i32, 0, 2, 1, 0)
/* arith */
DEF(add_i32, 1, 2, 0, 0)
DEF(sub_i32, 1, 2, 0, 0)
DEF(mul_i32, 1, 2, 0, 0)
DEF(div_i32, 1, 2, 0, IMPL(TCG_TARGET_HAS_div_i32))
DEF(divu_i32, 1, 2, 0, IMPL(TCG_TARGET_HAS_div_i32))
DEF(rem_i32, 1, 2, 0, IMPL(TCG_TARGET_HAS_rem_i32))
DEF(remu_i32, 1, 2, 0, IMPL(TCG_TARGET_HAS_rem_i32))
DEF(div2_i32, 2, 3, 0, IMPL(TCG_TARGET_HAS_div2_i32))
DEF(divu2_i32, 2, 3, 0, IMPL(TCG_TARGET_HAS_div2_i32))
DEF(and_i32, 1, 2, 0, 0)
DEF(or_i32, 1, 2, 0, 0)
DEF(xor_i32, 1, 2, 0, 0)
/* shifts/rotates */
DEF(shl_i32, 1, 2, 0, 0)
DEF(shr_i32, 1, 2, 0, 0)
DEF(sar_i32, 1, 2, 0, 0)
DEF(rotl_i32, 1, 2, 0, IMPL(TCG_TARGET_HAS_rot_i32))
DEF(rotr_i32, 1, 2, 0, IMPL(TCG_TARGET_HAS_rot_i32))
DEF(deposit_i32, 1, 2, 2, IMPL(TCG_TARGET_HAS_deposit_i32))
DEF(extract_i32, 1, 1, 2, IMPL(TCG_TARGET_HAS_extract_i32))
DEF(sextract_i32, 1, 1, 2, IMPL(TCG_TARGET_HAS_sextract_i32))
DEF(extract2_i32, 1, 2, 1, IMPL(TCG_TARGET_HAS_extract2_i32))

DEF(brcond_i32, 0, 2, 2, TCG_OPF_BB_END)

DEF(add2_i32, 2, 4, 0, IMPL(TCG_TARGET_HAS_add2_i32))
DEF(sub2_i32, 2, 4, 0, IMPL(TCG_TARGET_HAS_sub2_i32))
DEF(mulu2_i32, 2, 2, 0, IMPL(TCG_TARGET_HAS_mulu2_i32))
DEF(muls2_i32, 2, 2, 0, IMPL(TCG_TARGET_HAS_muls2_i32))
DEF(muluh_i32, 1, 2, 0, IMPL(TCG_TARGET_HAS_muluh_i32))
DEF(mulsh_i32, 1, 2, 0, IMPL(TCG_TARGET_HAS_mulsh_i32))
DEF(brcond2_i32, 0, 4, 2, TCG_OPF_BB_END | IMPL(TCG_TARGET_REG_BITS == 32))
DEF(setcond2_i32, 1, 4, 1, IMPL(TCG_TARGET_REG_BITS == 32))

DEF(ext8s_i32, 1, 1, 0, IMPL(TCG_TARGET_HAS_ext8s_i32))
DEF(ext16s_i32, 1, 1, 0, IMPL(TCG_TARGET_HAS_ext16s_i32))
DEF(ext8u_i32, 1, 1, 0, IMPL(TCG_TARGET_HAS_ext8u_i32))
DEF(ext16u_i32, 1, 1, 0, IMPL(TCG_TARGET_HAS_ext16u_i32))
DEF(bswap16_i32, 1, 1, 0, IMPL(TCG_TARGET_HAS_bswap16_i32))
DEF(bswap32_i32, 1, 1, 0, IMPL(TCG_TARGET_HAS_bswap32_i32))
DEF(not_i32, 1, 1, 0, IMPL(TCG_TARGET_HAS_not_i32))
DEF(neg_i32, 1, 1, 0, IMPL(TCG_TARGET_HAS_neg_i32))
DEF(andc_i32, 1, 2, 0, IMPL(TCG_TARGET_HAS_andc_i32))
DEF(orc_i32, 1, 2, 0, IMPL(TCG_TARGET_HAS_orc_i32))
DEF(eqv_i32, 1, 2, 0, IMPL(TCG_TARGET_HAS_eqv_i32))
DEF(nand_i32, 1, 2, 0, IMPL(TCG_TARGET_HAS_nand_i32))
DEF(nor_i32, 1, 2, 0, IMPL(TCG_TARGET_HAS_nor_i32))
DEF(clz_i32, 1, 2, 0, IMPL(TCG_TARGET_HAS_clz_i32))
DEF(ctz_i32, 1, 2, 0, IMPL(TCG_TARGET_HAS_ctz_i32))
DEF(ctpop_i32, 1, 1, 0, IMPL(TCG_TARGET_HAS_ctpop_i32))

DEF(mov_i64, 1, 1, 0, TCG_OPF_64BIT | TCG_OPF_NOT_PRESENT)
DEF(movi_i64, 1, 0, 1, TCG_OPF_64BIT | TCG_OPF_NOT_PRESENT)
DEF(setcond_i64, 1, 2, 1, IMPL64)
DEF(movcond_i64, 1, 4, 1, IMPL64 | IMPL(TCG_TARGET_HAS_movcond_i64))
/* load/store */
DEF(ld8u_i64, 1, 1, 1, IMPL64)
DEF(ld8s_i64, 1, 1, 1, IMPL64)
DEF(ld16u_i64, 1, 1, 1, IMPL64)
DEF(ld16s_i64, 1, 1, 1, IMPL64)
DEF(ld32u_i64, 1, 1, 1, IMPL64)
DEF(ld32s_i64, 1, 1, 1, IMPL64)
DEF(ld_i64, 1, 1, 1, IMPL64)
DEF(st8_i64, 0, 2, 1, IMPL64)
DEF(st16_i64, 0, 2, 1, IMPL64)
DEF(st32_i64, 0, 2, 1, IMPL64)
DEF(st_i64, 0, 2, 1, IMPL64)
/* arith */
DEF(add_i64, 1, 2, 0, IMPL64)
DEF(sub_i64, 1, 2, 0, IMPL64)
DEF(mul_i64, 1, 2, 0, IMPL64)
DEF(div_i64, 1, 2, 0, IMPL64 | IMPL(TCG_TARGET_HAS_div_i64))
DEF(divu_i64, 1, 2, 0, IMPL64 | IMPL(TCG_TARGET_HAS_div_i64))
DEF(rem_i64, 1, 2, 0, IMPL64 | IMPL(TCG_TARGET_HAS_rem_i64))
DEF(remu_i64, 1, 2, 0, IMPL64 | IMPL(TCG_TARGET_HAS_rem_i64))
DEF(div2_i64, 2, 3, 0, IMPL64 | IMPL(TCG_TARGET_HAS_div2_i64))
DEF(divu2_i64, 2, 3, 0, IMPL64 | IMPL(TCG_TARGET_HAS_div2_i64))
DEF(and_i64, 1, 2, 0, IMPL64)
DEF(or_i64, 1, 2, 0, IMPL64)
DEF(xor_i64, 1, 2, 0, IMPL64)
/* shifts/rotates */
DEF(shl_i64, 1, 2, 0, IMPL64)
DEF(shr_i64, 1, 2, 0, IMPL64)
DEF(sar_i64, 1, 2, 0, IMPL64)
DEF(rotl_i64, 1, 2, 0, IMPL64 | IMPL(TCG_TARGET_HAS_rot_i64))
DEF(rotr_i64, 1, 2, 0, IMPL64 | IMPL(TCG_TARGET_HAS_rot_i64))
DEF(deposit_i64, 1, 2, 2, IMPL64 | IMPL(TCG_TARGET_HAS_deposit_i64))
DEF(extract_i64, 1, 1, 2, IMPL64 | IMPL(TCG_TARGET_HAS_extract_i64))
DEF(sextract_i64, 1, 1, 2, IMPL64 | IMPL(TCG_TARGET_HAS_sextract_i64))
DEF(extract2_i64, 1, 2, 1, IMPL64 | IMPL(TCG_TARGET_HAS_extract2_i64))

/* size changing ops */
DEF(ext_i32_i64, 1, 1, 0, IMPL64)
DEF(extu_i32_i64, 1, 1, 0, IMPL64)
DEF(extrl_i64_i32, 1, 1, 0,
    IMPL(TCG_TARGET_HAS_extrl_i64_i32)
    | (TCG_TARGET_REG_BITS == 32 ? TCG_OPF_NOT_PRESENT : 0))
DEF(extrh_i64_i32, 1, 1, 0,
    IMPL(TCG_TARGET_HAS_extrh_i64_i32)
    | (TCG_TARGET_REG_BITS == 32 ? TCG_OPF_NOT_PRESENT : 0))

DEF(brcond_i64, 0, 2, 2, TCG_OPF_BB_END | IMPL64)
DEF(ext8s_i64, 1, 1, 0, IMPL64 | IMPL(TCG_TARGET_HAS_ext8s_i64))
DEF(ext16s_i64, 1, 1, 0, IMPL64 | IMPL(TCG_TARGET_HAS_ext16s_i64))
DEF(ext32s_i64, 1, 1, 0, IMPL64 | IMPL(TCG_TARGET_HAS_ext32s_i64))
DEF(ext8u_i64, 1, 1, 0, IMPL64 | IMPL(TCG_TARGET_HAS_ext8u_i64))
DEF(ext16u_i64, 1, 1, 0, IMPL64 | IMPL(TCG_TARGET_HAS_ext16u_i64))
DEF(ext32u_i64, 1, 1, 0, IMPL64 | IMPL(TCG_TARGET_HAS_ext32u_i64))
DEF(bswap16_i64, 1, 1, 0, IMPL64 | IMPL(TCG_TARGET_HAS_bswap16_i64))
DEF(bswap32_i64, 1, 1, 0, IMPL64 | IMPL(TCG_TARGET_HAS_bswap32_i64))
DEF(bswap64_i64, 1, 1, 0, IMPL64 | IMPL(TCG_TARGET_HAS_bswap64_i64))
DEF(not_i64, 1, 1, 0, IMPL64 | IMPL(TCG_TARGET_HAS_not_i64))
DEF(neg_i64, 1, 1, 0, IMPL64 | IMPL(TCG_TARGET_HAS_neg_i64))
DEF(andc_i64, 1, 2, 0, IMPL64 | IMPL(TCG_TARGET_HAS_andc_i64))
DEF(orc_i64, 1, 2, 0, IMPL64 | IMPL(TCG_TARGET_HAS_orc_i64))
DEF(eqv_i64, 1, 2, 0, IMPL64 | IMPL(TCG_TARGET_HAS_eqv_i64))
DEF(nand_i64, 1, 2, 0, IMPL64 | IMPL(TCG_TARGET_HAS_nand_i64))
DEF(nor_i64, 1, 2, 0, IMPL64 | IMPL(TCG_TARGET_HAS_nor_i64))
DEF(clz_i64, 1, 2, 0, IMPL64 | IMPL(TCG_TARGET_HAS_clz_i64))
DEF(ctz_i64, 1, 2, 0, IMPL64 | IMPL(TCG_TARGET_HAS_ctz_i64))
DEF(ctpop_i64, 1, 1, 0, IMPL64 | IMPL(TCG_TARGET_HAS_ctpop_i64))

DEF(add2_i64, 2, 4, 0, IMPL64 | IMPL(TCG_TARGET_HAS_add2_i64))
DEF(sub2_i64, 2, 4, 0, IMPL64 | IMPL(TCG_TARGET_HAS_sub2_i64))
DEF(mulu2_i64, 2, 2, 0, IMPL64 | IMPL(TCG_TARGET_HAS_mulu2_i64))
DEF(muls2_i64, 2, 2, 0, IMPL64 | IMPL(TCG_TARGET_HAS_muls2_i64))
DEF(muluh_i64, 1, 2, 0, IMPL64 | IMPL(TCG_TARGET_HAS_muluh_i64))
DEF(mulsh_i64, 1, 2, 0, IMPL64 | IMPL(TCG_TARGET_HAS_mulsh_i64))

#define TLADDR_ARGS  (TARGET_LONG_BITS <= TCG_TARGET_REG_BITS ? 1 : 2)
#define DATA64_ARGS  (TCG_TARGET_REG_BITS == 64 ? 1 : 2)

/* QEMU specific */
DEF(insn_start, 0, 0, TLADDR_ARGS * TARGET_INSN_START_WORDS,
    TCG_OPF_NOT_PRESENT)
DEF(exit_tb, 0, 0, 1, TCG_OPF_BB_EXIT | TCG_OPF_BB_END)
DEF(goto_tb, 0, 0, 1, TCG_OPF_BB_EXIT | TCG_OPF_BB_END)
DEF(goto_ptr, 0, 1, 0,
    TCG_OPF_BB_EXIT | TCG_OPF_BB_END | IMPL(TCG_TARGET_HAS_goto_ptr))

DEF(plugin_cb_start, 0, 0, 3, TCG_OPF_NOT_PRESENT)
DEF(plugin_cb_end, 0, 0, 0, TCG_OPF_NOT_PRESENT)

DEF(qemu_ld_i32, 1, TLADDR_ARGS, 1,
    TCG_OPF_CALL_CLOBBER | TCG_OPF_SIDE_EFFECTS)
DEF(qemu_st_i32, 0, TLADDR_ARGS + 1, 1,
    TCG_OPF_CALL_CLOBBER | TCG_OPF_SIDE_EFFECTS)
DEF(qemu_ld_i64, DATA64_ARGS, TLADDR_ARGS, 1,
    TCG_OPF_CALL_CLOBBER | TCG_OPF_SIDE_EFFECTS | TCG_OPF_64BIT)
DEF(qemu_st_i64, 0, TLADDR_ARGS + DATA64_ARGS, 1,
    TCG_OPF_CALL_CLOBBER | TCG_OPF_SIDE_EFFECTS | TCG_OPF_64BIT)

/* Host vector support.  */

#define IMPLVEC  TCG_OPF_VECTOR | IMPL(TCG_TARGET_MAYBE_vec)

DEF(mov_vec, 1, 1, 0, TCG_OPF_VECTOR | TCG_OPF_NOT_PRESENT)
DEF(dupi_vec, 1, 0, 1, TCG_OPF_VECTOR | TCG_OPF_NOT_PRESENT)

DEF(dup_vec, 1, 1, 0, IMPLVEC)
DEF(dup2_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_REG_BITS == 32))

DEF(ld_vec, 1, 1, 1, IMPLVEC)
DEF(st_vec, 0, 2, 1, IMPLVEC)
DEF(dupm_vec, 1, 1, 1, IMPLVEC)

DEF(add_vec, 1, 2, 0, IMPLVEC)
DEF(sub_vec, 1, 2, 0, IMPLVEC)
DEF(mul_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_mul_vec))
DEF(neg_vec, 1, 1, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_neg_vec))
DEF(abs_vec, 1, 1, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_abs_vec))
DEF(ssadd_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_sat_vec))
DEF(usadd_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_sat_vec))
DEF(sssub_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_sat_vec))
DEF(ussub_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_sat_vec))
DEF(smin_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_minmax_vec))
DEF(umin_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_minmax_vec))
DEF(smax_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_minmax_vec))
DEF(umax_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_minmax_vec))

DEF(and_vec, 1, 2, 0, IMPLVEC)
DEF(or_vec, 1, 2, 0, IMPLVEC)
DEF(xor_vec, 1, 2, 0, IMPLVEC)
DEF(andc_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_andc_vec))
DEF(orc_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_orc_vec))
DEF(not_vec, 1, 1, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_not_vec))

DEF(shli_vec, 1, 1, 1, IMPLVEC | IMPL(TCG_TARGET_HAS_shi_vec))
DEF(shri_vec, 1, 1, 1, IMPLVEC | IMPL(TCG_TARGET_HAS_shi_vec))
DEF(sari_vec, 1, 1, 1, IMPLVEC | IMPL(TCG_TARGET_HAS_shi_vec))

DEF(shls_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_shs_vec))
DEF(shrs_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_shs_vec))
DEF(sars_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_shs_vec))

DEF(shlv_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_shv_vec))
DEF(shrv_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_shv_vec))
DEF(sarv_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_shv_vec))

DEF(cmp_vec, 1, 2, 1, IMPLVEC)

DEF(bitsel_vec, 1, 3, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_bitsel_vec))
DEF(cmpsel_vec, 1, 4, 1, IMPLVEC | IMPL(TCG_TARGET_HAS_cmpsel_vec))

DEF(last_generic, 0, 0, 0, TCG_OPF_NOT_PRESENT)

#if TCG_TARGET_MAYBE_vec
/*
 * Copyright (c) 2019 Linaro
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * (at your option) any later version.
 *
 * See the COPYING file in the top-level directory for details.
 *
 * Target-specific opcodes for host vector expansion.  These will be
 * emitted by tcg_expand_vec_op.  For those familiar with GCC internals,
 * consider these to be UNSPEC with names.
 */

DEF(aa64_sshl_vec, 1, 2, 0, IMPLVEC)
#endif

#undef TLADDR_ARGS
#undef DATA64_ARGS
#undef IMPL
#undef IMPL64
#undef IMPLVEC
#undef DEF
#undef DEF
    NB_OPS,
} TCGOpcode;

typedef uint32_t tcg_insn_unit;

struct TCGRelocation {
    QSIMPLEQ_ENTRY(TCGRelocation) next;
    tcg_insn_unit *ptr;
    intptr_t addend;
    int type;
};

typedef struct TCGLabel TCGLabel;

struct TCGLabel {
    unsigned present : 1;
    unsigned has_value : 1;
    unsigned id : 14;
    unsigned refs : 16;
    union {
        uintptr_t value;
        tcg_insn_unit *value_ptr;
    } u;
    QSIMPLEQ_HEAD(, TCGRelocation) relocs;
    QSIMPLEQ_ENTRY(TCGLabel) next;
};

#define TCG_MAX_TEMPS 512

#define TCG_MAX_INSNS 512

typedef struct TCGPool {
    struct TCGPool *next;
    int size;
    uint8_t data[0] __attribute__ ((aligned));
} TCGPool;

typedef enum TCGType {
    TCG_TYPE_I32,
    TCG_TYPE_I64,

    TCG_TYPE_V64,
    TCG_TYPE_V128,
    TCG_TYPE_V256,

    TCG_TYPE_COUNT, /* number of different types */

    /* An alias for the size of the host register.  */
#if TCG_TARGET_REG_BITS == 32
    TCG_TYPE_REG = TCG_TYPE_I32,
#else
    TCG_TYPE_REG = TCG_TYPE_I64,
#endif

    /* An alias for the size of the native pointer.  */
#if UINTPTR_MAX == UINT32_MAX
    TCG_TYPE_PTR = TCG_TYPE_I32,
#else
    TCG_TYPE_PTR = TCG_TYPE_I64,
#endif

    /* An alias for the size of the target "long", aka register.  */
#if TARGET_LONG_BITS == 64
    TCG_TYPE_TL = TCG_TYPE_I64,
#else
    TCG_TYPE_TL = TCG_TYPE_I32,
#endif
} TCGType;

typedef tcg_target_ulong TCGArg;

typedef enum TCGTempVal {
    TEMP_VAL_DEAD,
    TEMP_VAL_REG,
    TEMP_VAL_MEM,
    TEMP_VAL_CONST,
} TCGTempVal;

typedef struct TCGTemp {
    TCGReg reg:8;
    TCGTempVal val_type:8;
    TCGType base_type:8;
    TCGType type:8;
    unsigned int fixed_reg:1;
    unsigned int indirect_reg:1;
    unsigned int indirect_base:1;
    unsigned int mem_coherent:1;
    unsigned int mem_allocated:1;
    /* If true, the temp is saved across both basic blocks and
       translation blocks.  */
    unsigned int temp_global:1;
    /* If true, the temp is saved across basic blocks but dead
       at the end of translation blocks.  If false, the temp is
       dead at the end of basic blocks.  */
    unsigned int temp_local:1;
    unsigned int temp_allocated:1;

    tcg_target_long val;
    struct TCGTemp *mem_base;
    intptr_t mem_offset;
    const char *name;

    /* Pass-specific information that can be stored for a temporary.
       One word worth of integer data, and one pointer to data
       allocated separately.  */
    uintptr_t state;
    void *state_ptr;
} TCGTemp;

typedef struct TCGContext TCGContext;

typedef struct TCGTempSet {
    unsigned long l[BITS_TO_LONGS(TCG_MAX_TEMPS)];
} TCGTempSet;

typedef struct TCGOp {
    TCGOpcode opc   : 8;        /*  8 */

    /* Parameters for this opcode.  See below.  */
    unsigned param1 : 4;        /* 12 */
    unsigned param2 : 4;        /* 16 */

    /* Lifetime data of the operands.  */
    unsigned life   : 16;       /* 32 */

    /* Next and previous opcodes.  */
    QTAILQ_ENTRY(TCGOp) link;
#ifdef CONFIG_PLUGIN
    QSIMPLEQ_ENTRY(TCGOp) plugin_link;
#endif

    /* Arguments for the opcode.  */
    TCGArg args[MAX_OPC_PARAM];

    /* Register preferences for the output(s).  */
    TCGRegSet output_pref[2];
} TCGOp;

struct TCGContext {
    uint8_t *pool_cur, *pool_end;
    TCGPool *pool_first, *pool_current, *pool_first_large;
    int nb_labels;
    int nb_globals;
    int nb_temps;
    int nb_indirects;
    int nb_ops;

    /* goto_tb support */
    tcg_insn_unit *code_buf;
    uint16_t *tb_jmp_reset_offset; /* tb->jmp_reset_offset */
    uintptr_t *tb_jmp_insn_offset; /* tb->jmp_target_arg if direct_jump */
    uintptr_t *tb_jmp_target_addr; /* tb->jmp_target_arg if !direct_jump */

    TCGRegSet reserved_regs;
    uint32_t tb_cflags; /* cflags of the current TB */
    intptr_t current_frame_offset;
    intptr_t frame_start;
    intptr_t frame_end;
    TCGTemp *frame_temp;

    tcg_insn_unit *code_ptr;

#ifdef CONFIG_PROFILER
    TCGProfile prof;
#endif

#ifdef CONFIG_DEBUG_TCG
    int temps_in_use;
    int goto_tb_issue_mask;
    const TCGOpcode *vecop_list;
#endif

    /* Code generation.  Note that we specifically do not use tcg_insn_unit
       here, because there's too much arithmetic throughout that relies
       on addition and subtraction working on bytes.  Rely on the GCC
       extension that allows arithmetic on void*.  */
    void *code_gen_prologue;
    void *code_gen_epilogue;
    void *code_gen_buffer;
    size_t code_gen_buffer_size;
    void *code_gen_ptr;
    void *data_gen_ptr;

    /* Threshold to flush the translated code buffer.  */
    void *code_gen_highwater;

    size_t tb_phys_invalidate_count;

    /* Track which vCPU triggers events */
    CPUState *cpu;                      /* *_trans */

    /* These structures are private to tcg-target.inc.c.  */
#ifdef TCG_TARGET_NEED_LDST_LABELS
    QSIMPLEQ_HEAD(, TCGLabelQemuLdst) ldst_labels;
#endif
#ifdef TCG_TARGET_NEED_POOL_LABELS
    struct TCGLabelPoolData *pool_labels;
#endif

    TCGLabel *exitreq_label;

#ifdef CONFIG_PLUGIN
    /*
     * We keep one plugin_tb struct per TCGContext. Note that on every TB
     * translation we clear but do not free its contents; this way we
     * avoid a lot of malloc/free churn, since after a few TB's it's
     * unlikely that we'll need to allocate either more instructions or more
     * space for instructions (for variable-instruction-length ISAs).
     */
    struct qemu_plugin_tb *plugin_tb;

    /* descriptor of the instruction being translated */
    struct qemu_plugin_insn *plugin_insn;

    /* list to quickly access the injected ops */
    QSIMPLEQ_HEAD(, TCGOp) plugin_ops;
#endif

    TCGTempSet free_temps[TCG_TYPE_COUNT * 2];
    TCGTemp temps[TCG_MAX_TEMPS]; /* globals first, temps after */

    QTAILQ_HEAD(, TCGOp) ops, free_ops;
    QSIMPLEQ_HEAD(, TCGLabel) labels;

    /* Tells which temporary holds a given register.
       It does not take into account fixed registers */
    TCGTemp *reg_to_temp[TCG_TARGET_NB_REGS];

    uint16_t gen_insn_end_off[TCG_MAX_INSNS];
    target_ulong gen_insn_data[TCG_MAX_INSNS][TARGET_INSN_START_WORDS];
};

extern __thread TCGContext *tcg_ctx;

extern int use_icount;

typedef abi_ulong tb_page_addr_t;

extern int qemu_loglevel;

static inline bool qemu_loglevel_mask(int mask)
{
    return (qemu_loglevel & mask) != 0;
}

int GCC_FMT_ATTR(1, 2) qemu_log(const char *fmt, ...);

#define CPU_LOG_EXEC       (1 << 5)

#define qemu_log_mask_and_addr(MASK, ADDR, FMT, ...)    \
    do {                                                \
        if (unlikely(qemu_loglevel_mask(MASK)) &&       \
                     qemu_log_in_addr_range(ADDR)) {    \
            qemu_log(FMT, ## __VA_ARGS__);              \
        }                                               \
    } while (0)

bool qemu_log_in_addr_range(uint64_t addr);

struct tb_tc {
    void *ptr;    /* pointer to the translated code */
    size_t size;
};

struct TranslationBlock {
    target_ulong pc;   /* simulated PC corresponding to this block (EIP + CS base) */
    target_ulong cs_base; /* CS base for this block */
    uint32_t flags; /* flags defining in which context the code was generated */
    uint16_t size;      /* size of target code for this block (1 <=
                           size <= TARGET_PAGE_SIZE) */
    uint16_t icount;
    uint32_t cflags;    /* compile flags */
#define CF_COUNT_MASK  0x00007fff
#define CF_LAST_IO     0x00008000 /* Last insn may be an IO access.  */
#define CF_NOCACHE     0x00010000 /* To be freed after execution */
#define CF_USE_ICOUNT  0x00020000
#define CF_INVALID     0x00040000 /* TB is stale. Set with @jmp_lock held */
#define CF_PARALLEL    0x00080000 /* Generate code for a parallel context */
#define CF_CLUSTER_MASK 0xff000000 /* Top 8 bits are cluster ID */
#define CF_CLUSTER_SHIFT 24
/* cflags' mask for hashing/comparison */
#define CF_HASH_MASK   \
    (CF_COUNT_MASK | CF_LAST_IO | CF_USE_ICOUNT | CF_PARALLEL | CF_CLUSTER_MASK)

    /* Per-vCPU dynamic tracing state used to generate this TB */
    uint32_t trace_vcpu_dstate;

    struct tb_tc tc;

    /* original tb when cflags has CF_NOCACHE */
    struct TranslationBlock *orig_tb;
    /* first and second physical page containing code. The lower bit
       of the pointer tells the index in page_next[].
       The list is protected by the TB's page('s) lock(s) */
    uintptr_t page_next[2];
    tb_page_addr_t page_addr[2];

    /* jmp_lock placed here to fill a 4-byte hole. Its documentation is below */
    QemuSpin jmp_lock;

    /* The following data are used to directly call another TB from
     * the code of this one. This can be done either by emitting direct or
     * indirect native jump instructions. These jumps are reset so that the TB
     * just continues its execution. The TB can be linked to another one by
     * setting one of the jump targets (or patching the jump instruction). Only
     * two of such jumps are supported.
     */
    uint16_t jmp_reset_offset[2]; /* offset of original jump target */
#define TB_JMP_RESET_OFFSET_INVALID 0xffff /* indicates no jump generated */
    uintptr_t jmp_target_arg[2];  /* target address or offset */

    /*
     * Each TB has a NULL-terminated list (jmp_list_head) of incoming jumps.
     * Each TB can have two outgoing jumps, and therefore can participate
     * in two lists. The list entries are kept in jmp_list_next[2]. The least
     * significant bit (LSB) of the pointers in these lists is used to encode
     * which of the two list entries is to be used in the pointed TB.
     *
     * List traversals are protected by jmp_lock. The destination TB of each
     * outgoing jump is kept in jmp_dest[] so that the appropriate jmp_lock
     * can be acquired from any origin TB.
     *
     * jmp_dest[] are tagged pointers as well. The LSB is set when the TB is
     * being invalidated, so that no further outgoing jumps from it can be set.
     *
     * jmp_lock also protects the CF_INVALID cflag; a jump must not be chained
     * to a destination TB that has CF_INVALID set.
     */
    uintptr_t jmp_list_head;
    uintptr_t jmp_list_next[2];
    uintptr_t jmp_dest[2];
};

extern bool parallel_cpus;

static inline uint32_t tb_cflags(const TranslationBlock *tb)
{
    return atomic_read(&tb->cflags);
}

static inline uint32_t curr_cflags(void)
{
    return (parallel_cpus ? CF_PARALLEL : 0)
         | (use_icount ? CF_USE_ICOUNT : 0);
}

TranslationBlock *tb_htable_lookup(CPUState *cpu, target_ulong pc,
                                   target_ulong cs_base, uint32_t flags,
                                   uint32_t cf_mask);

static inline unsigned int tb_jmp_cache_hash_func(target_ulong pc)
{
    return (pc ^ (pc >> TB_JMP_CACHE_BITS)) & (TB_JMP_CACHE_SIZE - 1);
}

static inline TranslationBlock *
tb_lookup__cpu_state(CPUState *cpu, target_ulong *pc, target_ulong *cs_base,
                     uint32_t *flags, uint32_t cf_mask)
{
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
    TranslationBlock *tb;
    uint32_t hash;

    cpu_get_tb_cpu_state(env, pc, cs_base, flags);
    hash = tb_jmp_cache_hash_func(*pc);
    tb = atomic_rcu_read(&cpu->tb_jmp_cache[hash]);

    cf_mask &= ~CF_CLUSTER_MASK;
    cf_mask |= cpu->cluster_index << CF_CLUSTER_SHIFT;

    if (likely(tb &&
               tb->pc == *pc &&
               tb->cs_base == *cs_base &&
               tb->flags == *flags &&
               tb->trace_vcpu_dstate == *cpu->trace_dstate &&
               (tb_cflags(tb) & (CF_HASH_MASK | CF_INVALID)) == cf_mask)) {
        return tb;
    }
    tb = tb_htable_lookup(cpu, *pc, *cs_base, *flags, cf_mask);
    if (tb == NULL) {
        return NULL;
    }
    atomic_set(&cpu->tb_jmp_cache[hash], tb);
    return tb;
}

const char *lookup_symbol(target_ulong orig_addr);

void *HELPER(lookup_tb_ptr)(CPUArchState *env)
{
#if 0
    CPUState *cpu = env_cpu(env);
    TranslationBlock *tb;
    target_ulong cs_base, pc;
    uint32_t flags;

    tb = tb_lookup__cpu_state(cpu, &pc, &cs_base, &flags, curr_cflags());
    if (tb == NULL) {
        return tcg_ctx->code_gen_epilogue;
    }
    qemu_log_mask_and_addr(CPU_LOG_EXEC, pc,
                           "Chain %d: %p ["
                           TARGET_FMT_lx "/" TARGET_FMT_lx "/%#x] %s\n",
                           cpu->cpu_index, tb->tc.ptr, cs_base, pc, flags,
                           lookup_symbol(pc));
    return tb->tc.ptr;
#else
    __builtin_trap();
    __builtin_unreachable();
#endif
}

