#define CONFIG_USER_ONLY 1

#define QEMU_NORETURN __attribute__ ((__noreturn__))

#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#define unlikely(x)   __builtin_expect(!!(x), 0)

#define container_of(ptr, type, member) ({                      \
        const typeof(((type *) 0)->member) *__mptr = (ptr);     \
        (type *) ((char *) __mptr - offsetof(type, member));})

#include <stddef.h>

#include <stdbool.h>

#include <stdint.h>

#include <sys/types.h>

#include <stdio.h>

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

typedef struct IRQState *qemu_irq;

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

static bool tcg_allowed = true;

#define tcg_enabled() (tcg_allowed)

#define QLIST_HEAD(name, type)                                          \
struct name {                                                           \
        struct type *lh_first;  /* first element */                     \
}

#define QLIST_ENTRY(type)                                               \
struct {                                                                \
        struct type *le_next;   /* next element */                      \
        struct type **le_prev;  /* address of previous next element */  \
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

#define le_bswap(v, size) (v)

static inline int ldub_p(const void *ptr)
{
    return *(uint8_t *)ptr;
}

static inline void stb_p(void *ptr, uint8_t v)
{
    *(uint8_t *)ptr = v;
}

static inline int lduw_he_p(const void *ptr)
{
    uint16_t r;
    __builtin_memcpy(&r, ptr, sizeof(r));
    return r;
}

static inline void stw_he_p(void *ptr, uint16_t v)
{
    __builtin_memcpy(ptr, &v, sizeof(v));
}

static inline int ldl_he_p(const void *ptr)
{
    int32_t r;
    __builtin_memcpy(&r, ptr, sizeof(r));
    return r;
}

static inline void stl_he_p(void *ptr, uint32_t v)
{
    __builtin_memcpy(ptr, &v, sizeof(v));
}

static inline int lduw_le_p(const void *ptr)
{
    return (uint16_t)le_bswap(lduw_he_p(ptr), 16);
}

static inline int ldl_le_p(const void *ptr)
{
    return le_bswap(ldl_he_p(ptr), 32);
}

static inline void stw_le_p(void *ptr, uint16_t v)
{
    stw_he_p(ptr, le_bswap(v, 16));
}

static inline void stl_le_p(void *ptr, uint32_t v)
{
    stl_he_p(ptr, le_bswap(v, 32));
}

#define signal_barrier() do {} while (0)

#define BITS_PER_BYTE           CHAR_BIT

#define BITS_PER_LONG           (sizeof (unsigned long) * BITS_PER_BYTE)

#define BIT_WORD(nr)            ((nr) / BITS_PER_LONG)

#define BITS_TO_LONGS(nr)       DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))

static inline int test_bit(long nr, const unsigned long *addr)
{
    return 1UL & (addr[BIT_WORD(nr)] >> (nr & (BITS_PER_LONG-1)));
}

#define DECLARE_BITMAP(name,bits)                  \
        unsigned long name[BITS_TO_LONGS(bits)]

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
    ObjectClass *class;
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

struct Notifier;

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

static inline void qemu_plugin_vcpu_mem_cb(CPUState *cpu, uint64_t vaddr,
                                           uint32_t meminfo)
{ }

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

typedef struct Notifier Notifier;

struct Notifier
{
    void (*notify)(Notifier *notifier, void *data);
    QLIST_ENTRY(Notifier) node;
};

#define HV_SINT_COUNT                         16

typedef struct X86CPU X86CPU;

#define HV_X64_MSR_CRASH_P0                     0x40000100

#define HV_X64_MSR_CRASH_P4                     0x40000104

#define HV_CRASH_PARAMS    (HV_X64_MSR_CRASH_P4 - HV_X64_MSR_CRASH_P0 + 1)

#define HV_STIMER_COUNT                       4

typedef uint32_t target_ulong;

typedef struct CPUTLB { } CPUTLB;

typedef struct CPUNegativeOffsetState {
    CPUTLB tlb;
    IcountDecr icount_decr;
} CPUNegativeOffsetState;

typedef enum OnOffAuto {
    ON_OFF_AUTO_AUTO,
    ON_OFF_AUTO_ON,
    ON_OFF_AUTO_OFF,
    ON_OFF_AUTO__MAX,
} OnOffAuto;

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

#define DESC_G_SHIFT    23

#define DESC_G_MASK     (1 << DESC_G_SHIFT)

#define DESC_B_SHIFT    22

#define DESC_B_MASK     (1 << DESC_B_SHIFT)

#define DESC_L_SHIFT    21

#define DESC_L_MASK     (1 << DESC_L_SHIFT)

#define DESC_P_SHIFT    15

#define DESC_P_MASK     (1 << DESC_P_SHIFT)

#define DESC_DPL_SHIFT  13

#define DESC_S_SHIFT    12

#define DESC_S_MASK     (1 << DESC_S_SHIFT)

#define DESC_TYPE_SHIFT 8

#define DESC_A_MASK     (1 << 8)

#define DESC_CS_MASK    (1 << 11)

#define DESC_C_MASK     (1 << 10)

#define DESC_R_MASK     (1 << 9)

#define DESC_W_MASK     (1 << 9)

#define DESC_TSS_BUSY_MASK (1 << 9)

#define CC_C    0x0001

#define CC_P    0x0004

#define CC_A    0x0010

#define CC_Z    0x0040

#define CC_S    0x0080

#define CC_O    0x0800

#define TF_MASK                 0x00000100

#define IF_MASK                 0x00000200

#define DF_MASK                 0x00000400

#define IOPL_MASK               0x00003000

#define NT_MASK                 0x00004000

#define RF_MASK                 0x00010000

#define VM_MASK                 0x00020000

#define AC_MASK                 0x00040000

#define ID_MASK                 0x00200000

#define HF_CPL_SHIFT         0

#define HF_CS32_SHIFT        4

#define HF_SS32_SHIFT        5

#define HF_ADDSEG_SHIFT      6

#define HF_TS_SHIFT         11

#define HF_LMA_SHIFT        14

#define HF_CS64_SHIFT       15

#define HF_CPL_MASK          (3 << HF_CPL_SHIFT)

#define HF_CS32_MASK         (1 << HF_CS32_SHIFT)

#define HF_SS32_MASK         (1 << HF_SS32_SHIFT)

#define HF_ADDSEG_MASK       (1 << HF_ADDSEG_SHIFT)

#define HF_TS_MASK           (1 << HF_TS_SHIFT)

#define HF_LMA_MASK          (1 << HF_LMA_SHIFT)

#define HF_CS64_MASK         (1 << HF_CS64_SHIFT)

#define CR0_PE_MASK  (1U << 0)

#define CR0_TS_MASK  (1U << 3)

#define CR0_PG_MASK  (1U << 31)

#define MCE_BANKS_DEF   10

#define MSR_MTRRcap_VCNT                8

#define MSR_P6_EVNTSEL0                 0x186

#define MSR_IA32_PERF_STATUS            0x198

#define MAX_RTIT_ADDRS                  8

typedef enum X86Seg {
    R_ES = 0,
    R_CS = 1,
    R_SS = 2,
    R_DS = 3,
    R_FS = 4,
    R_GS = 5,
    R_LDTR = 6,
    R_TR = 7,
} X86Seg;

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

#define EXCP0A_TSS	10

#define EXCP0B_NOSEG	11

#define EXCP0D_GPF	13

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

struct kvm_msrs;

struct X86CPU {
    /*< private >*/
    CPUState parent_obj;
    /*< public >*/

    CPUNegativeOffsetState neg;
    CPUX86State env;

    uint32_t hyperv_spinlock_attempts;
    char *hyperv_vendor_id;
    bool hyperv_synic_kvm_only;
    uint64_t hyperv_features;
    bool hyperv_passthrough;
    OnOffAuto hyperv_no_nonarch_cs;

    bool check_cpuid;
    bool enforce_cpuid;
    /*
     * Force features to be enabled even if the host doesn't support them.
     * This is dangerous and should be done only for testing CPUID
     * compatibility.
     */
    bool force_features;
    bool expose_kvm;
    bool expose_tcg;
    bool migratable;
    bool migrate_smi_count;
    bool max_features; /* Enable all supported features automatically */
    uint32_t apic_id;

    /* Enables publishing of TSC increment and Local APIC bus frequencies to
     * the guest OS in CPUID page 0x40000010, the same way that VMWare does. */
    bool vmware_cpuid_freq;

    /* if true the CPUID code directly forward host cache leaves to the guest */
    bool cache_info_passthrough;

    /* if true the CPUID code directly forwards
     * host monitor/mwait leaves to the guest */
    struct {
        uint32_t eax;
        uint32_t ebx;
        uint32_t ecx;
        uint32_t edx;
    } mwait;

    /* Features that were filtered out because of missing host capabilities */
    FeatureWordArray filtered_features;

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

    /* Compatibility bits for old machine types.
     * If true present the old cache topology information
     */
    bool legacy_cache;

    /* Compatibility bits for old machine types: */
    bool enable_cpuid_0xb;

    /* Enable auto level-increase for all CPUID leaves */
    bool full_cpuid_auto_level;

    /* Enable auto level-increase for Intel Processor Trace leave */
    bool intel_pt_auto_level;

    /* if true fill the top bits of the MTRR_PHYSMASKn variable range */
    bool fill_mtrr_mask;

    /* if true override the phys_bits value with a value read from the host */
    bool host_phys_bits;

    /* if set, limit maximum value for phys_bits when host_phys_bits is true */
    uint8_t host_phys_bits_limit;

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
    int32_t die_id;
    int32_t core_id;
    int32_t thread_id;

    int32_t hv_max_vps;
};

void cpu_sync_bndcs_hflags(CPUX86State *env);

static inline void cpu_x86_load_seg_cache(CPUX86State *env,
                                          int seg_reg, unsigned int selector,
                                          target_ulong base,
                                          unsigned int limit,
                                          unsigned int flags)
{
    SegmentCache *sc;
    unsigned int new_hflags;

    sc = &env->segs[seg_reg];
    sc->selector = selector;
    sc->base = base;
    sc->limit = limit;
    sc->flags = flags;

    /* update the hidden flags */
    {
        if (seg_reg == R_CS) {
#ifdef TARGET_X86_64
            if ((env->hflags & HF_LMA_MASK) && (flags & DESC_L_MASK)) {
                /* long mode */
                env->hflags |= HF_CS32_MASK | HF_SS32_MASK | HF_CS64_MASK;
                env->hflags &= ~(HF_ADDSEG_MASK);
            } else
#endif
            {
                /* legacy / compatibility case */
                new_hflags = (env->segs[R_CS].flags & DESC_B_MASK)
                    >> (DESC_B_SHIFT - HF_CS32_SHIFT);
                env->hflags = (env->hflags & ~(HF_CS32_MASK | HF_CS64_MASK)) |
                    new_hflags;
            }
        }
        if (seg_reg == R_SS) {
            int cpl = (flags >> DESC_DPL_SHIFT) & 3;
#if HF_CPL_MASK != 3
#error HF_CPL_MASK is hardcoded
#endif
            env->hflags = (env->hflags & ~HF_CPL_MASK) | cpl;
            /* Possibly switch between BNDCFGS and BNDCFGU */
            cpu_sync_bndcs_hflags(env);
        }
        new_hflags = (env->segs[R_SS].flags & DESC_B_MASK)
            >> (DESC_B_SHIFT - HF_SS32_SHIFT);
        if (env->hflags & HF_CS64_MASK) {
            /* zero base assumed for DS, ES and SS in long mode */
        } else if (!(env->cr[0] & CR0_PE_MASK) ||
                   (env->eflags & VM_MASK) ||
                   !(env->hflags & HF_CS32_MASK)) {
            /* XXX: try to avoid this test. The problem comes from the
               fact that is real mode or vm86 mode we only modify the
               'base' and 'selector' fields of the segment cache to go
               faster. A solution may be to force addseg to one in
               translate-i386.c. */
            new_hflags |= HF_ADDSEG_MASK;
        } else {
            new_hflags |= ((env->segs[R_DS].base |
                            env->segs[R_ES].base |
                            env->segs[R_SS].base) != 0) <<
                HF_ADDSEG_SHIFT;
        }
        env->hflags = (env->hflags &
                       ~(HF_SS32_MASK | HF_ADDSEG_MASK)) | new_hflags;
    }
}

void cpu_x86_update_cr3(CPUX86State *env, target_ulong new_cr3);

#define MMU_USER_IDX    1

#define CC_SRC  (env->cc_src)

#define CC_OP   (env->cc_op)

typedef CPUX86State CPUArchState;

typedef X86CPU ArchCPU;

#define lduw_p(p) lduw_le_p(p)

#define ldl_p(p) ldl_le_p(p)

#define stw_p(p, v) stw_le_p(p, v)

#define stl_p(p, v) stl_le_p(p, v)

extern unsigned long guest_base;

static inline ArchCPU *env_archcpu(CPUArchState *env)
{
    return container_of(env, ArchCPU, env);
}

static inline CPUState *env_cpu(CPUArchState *env)
{
    return &env_archcpu(env)->parent_obj;
}

void QEMU_NORETURN raise_exception_err_ra(CPUX86State *env, int exception_index,
                                          int error_code, uintptr_t retaddr);

uint32_t cpu_cc_compute_all(CPUX86State *env1, int op);

static inline uint32_t cpu_compute_eflags(CPUX86State *env)
{
    uint32_t eflags = env->eflags;
    if (tcg_enabled()) {
        eflags |= cpu_cc_compute_all(env, CC_OP) | (env->df & DF_MASK);
    }
    return eflags;
}

static inline void cpu_load_eflags(CPUX86State *env, int eflags,
                                   int update_mask)
{
    CC_SRC = eflags & (CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C);
    CC_OP = CC_OP_EFLAGS;
    env->df = 1 - (2 * ((eflags >> 10) & 1));
    env->eflags = (env->eflags & ~update_mask) |
        (eflags & update_mask) | 0x2;
}

#define g2h(x) ((void *)((unsigned long)(x)))

typedef uint32_t abi_ptr;

static uintptr_t helper_retaddr;

static inline void set_helper_retaddr(uintptr_t ra)
{
    helper_retaddr = ra;
    /*
     * Ensure that this write is visible to the SIGSEGV handler that
     * may be invoked due to a subsequent invalid memory operation.
     */
    signal_barrier();
}

static inline void clear_helper_retaddr(void)
{
    /*
     * Ensure that previous memory operations have succeeded before
     * removing the data visible to the signal handler.
     */
    signal_barrier();
    helper_retaddr = 0;
}

typedef struct TraceEvent {
    uint32_t id;
    uint32_t vcpu_id;
    const char * name;
    const bool sstate;
    uint16_t *dstate;
} TraceEvent;

extern int trace_events_enabled_count;

#define trace_event_get_vcpu_state(vcpu, id)                            \
    ((id ##_ENABLED) &&                                                 \
     trace_event_get_vcpu_state_dynamic_by_vcpu_id(                     \
         vcpu, _ ## id ## _EVENT.vcpu_id))

static inline bool
trace_event_get_vcpu_state_dynamic_by_vcpu_id(CPUState *vcpu,
                                              uint32_t vcpu_id)
{
    /* it's on fast path, avoid consistency checks (asserts) */
    if (unlikely(trace_events_enabled_count)) {
        return test_bit(vcpu_id, vcpu->trace_dstate);
    } else {
        return false;
    }
}

extern TraceEvent _TRACE_GUEST_MEM_BEFORE_EXEC_EVENT;

#define TRACE_GUEST_MEM_BEFORE_EXEC_ENABLED 1

static inline void _nocheck__trace_guest_mem_before_exec(CPUState * __cpu, uint64_t vaddr, uint16_t info)
{
}

static inline void trace_guest_mem_before_exec(CPUState * __cpu, uint64_t vaddr, uint16_t info)
{
    if (trace_event_get_vcpu_state(__cpu, TRACE_GUEST_MEM_BEFORE_EXEC)) {
        _nocheck__trace_guest_mem_before_exec(__cpu, vaddr, info);
    }
}

typedef enum MemOp {
    MO_8     = 0,
    MO_16    = 1,
    MO_32    = 2,
    MO_64    = 3,
    MO_SIZE  = 3,   /* Mask for the above.  */

    MO_SIGN  = 4,   /* Sign-extended, otherwise zero-extended.  */

    MO_BSWAP = 8,   /* Host reverse endian.  */
#ifdef HOST_WORDS_BIGENDIAN
    MO_LE    = MO_BSWAP,
    MO_BE    = 0,
#else
    MO_LE    = 0,
    MO_BE    = MO_BSWAP,
#endif
#ifdef NEED_CPU_H
#ifdef TARGET_WORDS_BIGENDIAN
    MO_TE    = MO_BE,
#else
    MO_TE    = MO_LE,
#endif
#endif

    /*
     * MO_UNALN accesses are never checked for alignment.
     * MO_ALIGN accesses will result in a call to the CPU's
     * do_unaligned_access hook if the guest address is not aligned.
     * The default depends on whether the target CPU defines
     * TARGET_ALIGNED_ONLY.
     *
     * Some architectures (e.g. ARMv8) need the address which is aligned
     * to a size more than the size of the memory access.
     * Some architectures (e.g. SPARCv9) need an address which is aligned,
     * but less strictly than the natural alignment.
     *
     * MO_ALIGN supposes the alignment size is the size of a memory access.
     *
     * There are three options:
     * - unaligned access permitted (MO_UNALN).
     * - an alignment to the size of an access (MO_ALIGN);
     * - an alignment to a specified size, which may be more or less than
     *   the access size (MO_ALIGN_x where 'x' is a size in bytes);
     */
    MO_ASHIFT = 4,
    MO_AMASK = 7 << MO_ASHIFT,
#ifdef NEED_CPU_H
#ifdef TARGET_ALIGNED_ONLY
    MO_ALIGN = 0,
    MO_UNALN = MO_AMASK,
#else
    MO_ALIGN = MO_AMASK,
    MO_UNALN = 0,
#endif
#endif
    MO_ALIGN_2  = 1 << MO_ASHIFT,
    MO_ALIGN_4  = 2 << MO_ASHIFT,
    MO_ALIGN_8  = 3 << MO_ASHIFT,
    MO_ALIGN_16 = 4 << MO_ASHIFT,
    MO_ALIGN_32 = 5 << MO_ASHIFT,
    MO_ALIGN_64 = 6 << MO_ASHIFT,

    /* Combinations of the above, for ease of use.  */
    MO_UB    = MO_8,
    MO_UW    = MO_16,
    MO_UL    = MO_32,
    MO_SB    = MO_SIGN | MO_8,
    MO_SW    = MO_SIGN | MO_16,
    MO_SL    = MO_SIGN | MO_32,
    MO_Q     = MO_64,

    MO_LEUW  = MO_LE | MO_UW,
    MO_LEUL  = MO_LE | MO_UL,
    MO_LESW  = MO_LE | MO_SW,
    MO_LESL  = MO_LE | MO_SL,
    MO_LEQ   = MO_LE | MO_Q,

    MO_BEUW  = MO_BE | MO_UW,
    MO_BEUL  = MO_BE | MO_UL,
    MO_BESW  = MO_BE | MO_SW,
    MO_BESL  = MO_BE | MO_SL,
    MO_BEQ   = MO_BE | MO_Q,

#ifdef NEED_CPU_H
    MO_TEUW  = MO_TE | MO_UW,
    MO_TEUL  = MO_TE | MO_UL,
    MO_TESW  = MO_TE | MO_SW,
    MO_TESL  = MO_TE | MO_SL,
    MO_TEQ   = MO_TE | MO_Q,
#endif

    MO_SSIZE = MO_SIZE | MO_SIGN,
} MemOp;

#define TRACE_MEM_SZ_SHIFT_MASK 0xf

#define TRACE_MEM_SE (1ULL << 4)

#define TRACE_MEM_BE (1ULL << 5)

#define TRACE_MEM_ST (1ULL << 6)

static inline uint16_t trace_mem_build_info(
    int size_shift, bool sign_extend, MemOp endianness,
    bool store, unsigned int mmu_idx)
{
    uint16_t res;

    res = size_shift & TRACE_MEM_SZ_SHIFT_MASK;
    if (sign_extend) {
        res |= TRACE_MEM_SE;
    }
    if (endianness == MO_BE) {
        res |= TRACE_MEM_BE;
    }
    if (store) {
        res |= TRACE_MEM_ST;
    }
#ifdef CONFIG_SOFTMMU
    res |= mmu_idx << TRACE_MEM_MMU_SHIFT;
#endif
    return res;
}

# define GETPC() tci_tb_ptr

extern uintptr_t tci_tb_ptr;

# define LOG_PCALL(...) do { } while (0)

#define MEMSUFFIX _kernel

#define SUFFIX b

#define USUFFIX ub

#define SHIFT 0

#define RES_TYPE uint32_t

static inline RES_TYPE
glue(glue(cpu_ld, USUFFIX), MEMSUFFIX)(CPUArchState *env, abi_ptr ptr)
{
    RES_TYPE ret;
#ifdef CODE_ACCESS
    set_helper_retaddr(1);
    ret = glue(glue(ld, USUFFIX), _p)(g2h(ptr));
    clear_helper_retaddr();
#else
    uint16_t meminfo = trace_mem_build_info(SHIFT, false, MO_TE, false,
                                            MMU_USER_IDX);
    trace_guest_mem_before_exec(env_cpu(env), ptr, meminfo);
    ret = glue(glue(ld, USUFFIX), _p)(g2h(ptr));
#endif
    return ret;
}

static inline RES_TYPE
glue(glue(glue(cpu_ld, USUFFIX), MEMSUFFIX), _ra)(CPUArchState *env,
                                                  abi_ptr ptr,
                                                  uintptr_t retaddr)
{
    RES_TYPE ret;
    set_helper_retaddr(retaddr);
    ret = glue(glue(cpu_ld, USUFFIX), MEMSUFFIX)(env, ptr);
    clear_helper_retaddr();
    return ret;
}

static inline void
glue(glue(cpu_st, SUFFIX), MEMSUFFIX)(CPUArchState *env, abi_ptr ptr,
                                      RES_TYPE v)
{
    uint16_t meminfo = trace_mem_build_info(SHIFT, false, MO_TE, true,
                                            MMU_USER_IDX);
    trace_guest_mem_before_exec(env_cpu(env), ptr, meminfo);
    glue(glue(st, SUFFIX), _p)(g2h(ptr), v);
    qemu_plugin_vcpu_mem_cb(env_cpu(env), ptr, meminfo);
}

static inline void
glue(glue(glue(cpu_st, SUFFIX), MEMSUFFIX), _ra)(CPUArchState *env,
                                                  abi_ptr ptr,
                                                  RES_TYPE v,
                                                  uintptr_t retaddr)
{
    set_helper_retaddr(retaddr);
    glue(glue(cpu_st, SUFFIX), MEMSUFFIX)(env, ptr, v);
    clear_helper_retaddr();
}

#define SUFFIX w

#define USUFFIX uw

#define SHIFT 1

#define RES_TYPE uint32_t

static inline RES_TYPE
glue(glue(cpu_ld, USUFFIX), MEMSUFFIX)(CPUArchState *env, abi_ptr ptr)
{
    RES_TYPE ret;
#ifdef CODE_ACCESS
    set_helper_retaddr(1);
    ret = glue(glue(ld, USUFFIX), _p)(g2h(ptr));
    clear_helper_retaddr();
#else
    uint16_t meminfo = trace_mem_build_info(SHIFT, false, MO_TE, false,
                                            MMU_USER_IDX);
    trace_guest_mem_before_exec(env_cpu(env), ptr, meminfo);
    ret = glue(glue(ld, USUFFIX), _p)(g2h(ptr));
#endif
    return ret;
}

static inline RES_TYPE
glue(glue(glue(cpu_ld, USUFFIX), MEMSUFFIX), _ra)(CPUArchState *env,
                                                  abi_ptr ptr,
                                                  uintptr_t retaddr)
{
    RES_TYPE ret;
    set_helper_retaddr(retaddr);
    ret = glue(glue(cpu_ld, USUFFIX), MEMSUFFIX)(env, ptr);
    clear_helper_retaddr();
    return ret;
}

static inline void
glue(glue(cpu_st, SUFFIX), MEMSUFFIX)(CPUArchState *env, abi_ptr ptr,
                                      RES_TYPE v)
{
    uint16_t meminfo = trace_mem_build_info(SHIFT, false, MO_TE, true,
                                            MMU_USER_IDX);
    trace_guest_mem_before_exec(env_cpu(env), ptr, meminfo);
    glue(glue(st, SUFFIX), _p)(g2h(ptr), v);
    qemu_plugin_vcpu_mem_cb(env_cpu(env), ptr, meminfo);
}

static inline void
glue(glue(glue(cpu_st, SUFFIX), MEMSUFFIX), _ra)(CPUArchState *env,
                                                  abi_ptr ptr,
                                                  RES_TYPE v,
                                                  uintptr_t retaddr)
{
    set_helper_retaddr(retaddr);
    glue(glue(cpu_st, SUFFIX), MEMSUFFIX)(env, ptr, v);
    clear_helper_retaddr();
}

#define SUFFIX l

#define USUFFIX l

#define SHIFT 2

#define RES_TYPE uint32_t

static inline RES_TYPE
glue(glue(cpu_ld, USUFFIX), MEMSUFFIX)(CPUArchState *env, abi_ptr ptr)
{
    RES_TYPE ret;
#ifdef CODE_ACCESS
    set_helper_retaddr(1);
    ret = glue(glue(ld, USUFFIX), _p)(g2h(ptr));
    clear_helper_retaddr();
#else
    uint16_t meminfo = trace_mem_build_info(SHIFT, false, MO_TE, false,
                                            MMU_USER_IDX);
    trace_guest_mem_before_exec(env_cpu(env), ptr, meminfo);
    ret = glue(glue(ld, USUFFIX), _p)(g2h(ptr));
#endif
    return ret;
}

static inline RES_TYPE
glue(glue(glue(cpu_ld, USUFFIX), MEMSUFFIX), _ra)(CPUArchState *env,
                                                  abi_ptr ptr,
                                                  uintptr_t retaddr)
{
    RES_TYPE ret;
    set_helper_retaddr(retaddr);
    ret = glue(glue(cpu_ld, USUFFIX), MEMSUFFIX)(env, ptr);
    clear_helper_retaddr();
    return ret;
}

static inline void
glue(glue(cpu_st, SUFFIX), MEMSUFFIX)(CPUArchState *env, abi_ptr ptr,
                                      RES_TYPE v)
{
    uint16_t meminfo = trace_mem_build_info(SHIFT, false, MO_TE, true,
                                            MMU_USER_IDX);
    trace_guest_mem_before_exec(env_cpu(env), ptr, meminfo);
    glue(glue(st, SUFFIX), _p)(g2h(ptr), v);
    qemu_plugin_vcpu_mem_cb(env_cpu(env), ptr, meminfo);
}

static inline void
glue(glue(glue(cpu_st, SUFFIX), MEMSUFFIX), _ra)(CPUArchState *env,
                                                  abi_ptr ptr,
                                                  RES_TYPE v,
                                                  uintptr_t retaddr)
{
    set_helper_retaddr(retaddr);
    glue(glue(cpu_st, SUFFIX), MEMSUFFIX)(env, ptr, v);
    clear_helper_retaddr();
}

static inline int load_segment_ra(CPUX86State *env, uint32_t *e1_ptr,
                               uint32_t *e2_ptr, int selector,
                               uintptr_t retaddr)
{
    SegmentCache *dt;
    int index;
    target_ulong ptr;

    if (selector & 0x4) {
        dt = &env->ldt;
    } else {
        dt = &env->gdt;
    }
    index = selector & ~7;
    if ((index + 7) > dt->limit) {
        return -1;
    }
    ptr = dt->base + index;
    *e1_ptr = cpu_ldl_kernel_ra(env, ptr, retaddr);
    *e2_ptr = cpu_ldl_kernel_ra(env, ptr + 4, retaddr);
    return 0;
}

static inline unsigned int get_seg_limit(uint32_t e1, uint32_t e2)
{
    unsigned int limit;

    limit = (e1 & 0xffff) | (e2 & 0x000f0000);
    if (e2 & DESC_G_MASK) {
        limit = (limit << 12) | 0xfff;
    }
    return limit;
}

static inline uint32_t get_seg_base(uint32_t e1, uint32_t e2)
{
    return (e1 >> 16) | ((e2 & 0xff) << 16) | (e2 & 0xff000000);
}

static inline void load_seg_cache_raw_dt(SegmentCache *sc, uint32_t e1,
                                         uint32_t e2)
{
    sc->base = get_seg_base(e1, e2);
    sc->limit = get_seg_limit(e1, e2);
    sc->flags = e2;
}

static inline void load_seg_vm(CPUX86State *env, int seg, int selector)
{
    selector &= 0xffff;

    cpu_x86_load_seg_cache(env, seg, selector, (selector << 4), 0xffff,
                           DESC_P_MASK | DESC_S_MASK | DESC_W_MASK |
                           DESC_A_MASK | (3 << DESC_DPL_SHIFT));
}

#define SWITCH_TSS_JMP  0

#define SWITCH_TSS_IRET 1

#define SWITCH_TSS_CALL 2

static void tss_load_seg(CPUX86State *env, int seg_reg, int selector, int cpl,
                         uintptr_t retaddr)
{
    uint32_t e1, e2;
    int rpl, dpl;

    if ((selector & 0xfffc) != 0) {
        if (load_segment_ra(env, &e1, &e2, selector, retaddr) != 0) {
            raise_exception_err_ra(env, EXCP0A_TSS, selector & 0xfffc, retaddr);
        }
        if (!(e2 & DESC_S_MASK)) {
            raise_exception_err_ra(env, EXCP0A_TSS, selector & 0xfffc, retaddr);
        }
        rpl = selector & 3;
        dpl = (e2 >> DESC_DPL_SHIFT) & 3;
        if (seg_reg == R_CS) {
            if (!(e2 & DESC_CS_MASK)) {
                raise_exception_err_ra(env, EXCP0A_TSS, selector & 0xfffc, retaddr);
            }
            if (dpl != rpl) {
                raise_exception_err_ra(env, EXCP0A_TSS, selector & 0xfffc, retaddr);
            }
        } else if (seg_reg == R_SS) {
            /* SS must be writable data */
            if ((e2 & DESC_CS_MASK) || !(e2 & DESC_W_MASK)) {
                raise_exception_err_ra(env, EXCP0A_TSS, selector & 0xfffc, retaddr);
            }
            if (dpl != cpl || dpl != rpl) {
                raise_exception_err_ra(env, EXCP0A_TSS, selector & 0xfffc, retaddr);
            }
        } else {
            /* not readable code */
            if ((e2 & DESC_CS_MASK) && !(e2 & DESC_R_MASK)) {
                raise_exception_err_ra(env, EXCP0A_TSS, selector & 0xfffc, retaddr);
            }
            /* if data or non conforming code, checks the rights */
            if (((e2 >> DESC_TYPE_SHIFT) & 0xf) < 12) {
                if (dpl < cpl || dpl < rpl) {
                    raise_exception_err_ra(env, EXCP0A_TSS, selector & 0xfffc, retaddr);
                }
            }
        }
        if (!(e2 & DESC_P_MASK)) {
            raise_exception_err_ra(env, EXCP0B_NOSEG, selector & 0xfffc, retaddr);
        }
        cpu_x86_load_seg_cache(env, seg_reg, selector,
                               get_seg_base(e1, e2),
                               get_seg_limit(e1, e2),
                               e2);
    } else {
        if (seg_reg == R_SS || seg_reg == R_CS) {
            raise_exception_err_ra(env, EXCP0A_TSS, selector & 0xfffc, retaddr);
        }
    }
}

static void switch_tss_ra(CPUX86State *env, int tss_selector,
                          uint32_t e1, uint32_t e2, int source,
                          uint32_t next_eip, uintptr_t retaddr)
{
    int tss_limit, tss_limit_max, type, old_tss_limit_max, old_type, v1, v2, i;
    target_ulong tss_base;
    uint32_t new_regs[8], new_segs[6];
    uint32_t new_eflags, new_eip, new_cr3, new_ldt, new_trap;
    uint32_t old_eflags, eflags_mask;
    SegmentCache *dt;
    int index;
    target_ulong ptr;

    type = (e2 >> DESC_TYPE_SHIFT) & 0xf;
    LOG_PCALL("switch_tss: sel=0x%04x type=%d src=%d\n", tss_selector, type,
              source);

    /* if task gate, we read the TSS segment and we load it */
    if (type == 5) {
        if (!(e2 & DESC_P_MASK)) {
            raise_exception_err_ra(env, EXCP0B_NOSEG, tss_selector & 0xfffc, retaddr);
        }
        tss_selector = e1 >> 16;
        if (tss_selector & 4) {
            raise_exception_err_ra(env, EXCP0A_TSS, tss_selector & 0xfffc, retaddr);
        }
        if (load_segment_ra(env, &e1, &e2, tss_selector, retaddr) != 0) {
            raise_exception_err_ra(env, EXCP0D_GPF, tss_selector & 0xfffc, retaddr);
        }
        if (e2 & DESC_S_MASK) {
            raise_exception_err_ra(env, EXCP0D_GPF, tss_selector & 0xfffc, retaddr);
        }
        type = (e2 >> DESC_TYPE_SHIFT) & 0xf;
        if ((type & 7) != 1) {
            raise_exception_err_ra(env, EXCP0D_GPF, tss_selector & 0xfffc, retaddr);
        }
    }

    if (!(e2 & DESC_P_MASK)) {
        raise_exception_err_ra(env, EXCP0B_NOSEG, tss_selector & 0xfffc, retaddr);
    }

    if (type & 8) {
        tss_limit_max = 103;
    } else {
        tss_limit_max = 43;
    }
    tss_limit = get_seg_limit(e1, e2);
    tss_base = get_seg_base(e1, e2);
    if ((tss_selector & 4) != 0 ||
        tss_limit < tss_limit_max) {
        raise_exception_err_ra(env, EXCP0A_TSS, tss_selector & 0xfffc, retaddr);
    }
    old_type = (env->tr.flags >> DESC_TYPE_SHIFT) & 0xf;
    if (old_type & 8) {
        old_tss_limit_max = 103;
    } else {
        old_tss_limit_max = 43;
    }

    /* read all the registers from the new TSS */
    if (type & 8) {
        /* 32 bit */
        new_cr3 = cpu_ldl_kernel_ra(env, tss_base + 0x1c, retaddr);
        new_eip = cpu_ldl_kernel_ra(env, tss_base + 0x20, retaddr);
        new_eflags = cpu_ldl_kernel_ra(env, tss_base + 0x24, retaddr);
        for (i = 0; i < 8; i++) {
            new_regs[i] = cpu_ldl_kernel_ra(env, tss_base + (0x28 + i * 4),
                                            retaddr);
        }
        for (i = 0; i < 6; i++) {
            new_segs[i] = cpu_lduw_kernel_ra(env, tss_base + (0x48 + i * 4),
                                             retaddr);
        }
        new_ldt = cpu_lduw_kernel_ra(env, tss_base + 0x60, retaddr);
        new_trap = cpu_ldl_kernel_ra(env, tss_base + 0x64, retaddr);
    } else {
        /* 16 bit */
        new_cr3 = 0;
        new_eip = cpu_lduw_kernel_ra(env, tss_base + 0x0e, retaddr);
        new_eflags = cpu_lduw_kernel_ra(env, tss_base + 0x10, retaddr);
        for (i = 0; i < 8; i++) {
            new_regs[i] = cpu_lduw_kernel_ra(env, tss_base + (0x12 + i * 2),
                                             retaddr) | 0xffff0000;
        }
        for (i = 0; i < 4; i++) {
            new_segs[i] = cpu_lduw_kernel_ra(env, tss_base + (0x22 + i * 4),
                                             retaddr);
        }
        new_ldt = cpu_lduw_kernel_ra(env, tss_base + 0x2a, retaddr);
        new_segs[R_FS] = 0;
        new_segs[R_GS] = 0;
        new_trap = 0;
    }
    /* XXX: avoid a compiler warning, see
     http://support.amd.com/us/Processor_TechDocs/24593.pdf
     chapters 12.2.5 and 13.2.4 on how to implement TSS Trap bit */
    (void)new_trap;

    /* NOTE: we must avoid memory exceptions during the task switch,
       so we make dummy accesses before */
    /* XXX: it can still fail in some cases, so a bigger hack is
       necessary to valid the TLB after having done the accesses */

    v1 = cpu_ldub_kernel_ra(env, env->tr.base, retaddr);
    v2 = cpu_ldub_kernel_ra(env, env->tr.base + old_tss_limit_max, retaddr);
    cpu_stb_kernel_ra(env, env->tr.base, v1, retaddr);
    cpu_stb_kernel_ra(env, env->tr.base + old_tss_limit_max, v2, retaddr);

    /* clear busy bit (it is restartable) */
    if (source == SWITCH_TSS_JMP || source == SWITCH_TSS_IRET) {
        target_ulong ptr;
        uint32_t e2;

        ptr = env->gdt.base + (env->tr.selector & ~7);
        e2 = cpu_ldl_kernel_ra(env, ptr + 4, retaddr);
        e2 &= ~DESC_TSS_BUSY_MASK;
        cpu_stl_kernel_ra(env, ptr + 4, e2, retaddr);
    }
    old_eflags = cpu_compute_eflags(env);
    if (source == SWITCH_TSS_IRET) {
        old_eflags &= ~NT_MASK;
    }

    /* save the current state in the old TSS */
    if (type & 8) {
        /* 32 bit */
        cpu_stl_kernel_ra(env, env->tr.base + 0x20, next_eip, retaddr);
        cpu_stl_kernel_ra(env, env->tr.base + 0x24, old_eflags, retaddr);
        cpu_stl_kernel_ra(env, env->tr.base + (0x28 + 0 * 4), env->regs[R_EAX], retaddr);
        cpu_stl_kernel_ra(env, env->tr.base + (0x28 + 1 * 4), env->regs[R_ECX], retaddr);
        cpu_stl_kernel_ra(env, env->tr.base + (0x28 + 2 * 4), env->regs[R_EDX], retaddr);
        cpu_stl_kernel_ra(env, env->tr.base + (0x28 + 3 * 4), env->regs[R_EBX], retaddr);
        cpu_stl_kernel_ra(env, env->tr.base + (0x28 + 4 * 4), env->regs[R_ESP], retaddr);
        cpu_stl_kernel_ra(env, env->tr.base + (0x28 + 5 * 4), env->regs[R_EBP], retaddr);
        cpu_stl_kernel_ra(env, env->tr.base + (0x28 + 6 * 4), env->regs[R_ESI], retaddr);
        cpu_stl_kernel_ra(env, env->tr.base + (0x28 + 7 * 4), env->regs[R_EDI], retaddr);
        for (i = 0; i < 6; i++) {
            cpu_stw_kernel_ra(env, env->tr.base + (0x48 + i * 4),
                              env->segs[i].selector, retaddr);
        }
    } else {
        /* 16 bit */
        cpu_stw_kernel_ra(env, env->tr.base + 0x0e, next_eip, retaddr);
        cpu_stw_kernel_ra(env, env->tr.base + 0x10, old_eflags, retaddr);
        cpu_stw_kernel_ra(env, env->tr.base + (0x12 + 0 * 2), env->regs[R_EAX], retaddr);
        cpu_stw_kernel_ra(env, env->tr.base + (0x12 + 1 * 2), env->regs[R_ECX], retaddr);
        cpu_stw_kernel_ra(env, env->tr.base + (0x12 + 2 * 2), env->regs[R_EDX], retaddr);
        cpu_stw_kernel_ra(env, env->tr.base + (0x12 + 3 * 2), env->regs[R_EBX], retaddr);
        cpu_stw_kernel_ra(env, env->tr.base + (0x12 + 4 * 2), env->regs[R_ESP], retaddr);
        cpu_stw_kernel_ra(env, env->tr.base + (0x12 + 5 * 2), env->regs[R_EBP], retaddr);
        cpu_stw_kernel_ra(env, env->tr.base + (0x12 + 6 * 2), env->regs[R_ESI], retaddr);
        cpu_stw_kernel_ra(env, env->tr.base + (0x12 + 7 * 2), env->regs[R_EDI], retaddr);
        for (i = 0; i < 4; i++) {
            cpu_stw_kernel_ra(env, env->tr.base + (0x22 + i * 4),
                              env->segs[i].selector, retaddr);
        }
    }

    /* now if an exception occurs, it will occurs in the next task
       context */

    if (source == SWITCH_TSS_CALL) {
        cpu_stw_kernel_ra(env, tss_base, env->tr.selector, retaddr);
        new_eflags |= NT_MASK;
    }

    /* set busy bit */
    if (source == SWITCH_TSS_JMP || source == SWITCH_TSS_CALL) {
        target_ulong ptr;
        uint32_t e2;

        ptr = env->gdt.base + (tss_selector & ~7);
        e2 = cpu_ldl_kernel_ra(env, ptr + 4, retaddr);
        e2 |= DESC_TSS_BUSY_MASK;
        cpu_stl_kernel_ra(env, ptr + 4, e2, retaddr);
    }

    /* set the new CPU state */
    /* from this point, any exception which occurs can give problems */
    env->cr[0] |= CR0_TS_MASK;
    env->hflags |= HF_TS_MASK;
    env->tr.selector = tss_selector;
    env->tr.base = tss_base;
    env->tr.limit = tss_limit;
    env->tr.flags = e2 & ~DESC_TSS_BUSY_MASK;

    if ((type & 8) && (env->cr[0] & CR0_PG_MASK)) {
        cpu_x86_update_cr3(env, new_cr3);
    }

    /* load all registers without an exception, then reload them with
       possible exception */
    env->eip = new_eip;
    eflags_mask = TF_MASK | AC_MASK | ID_MASK |
        IF_MASK | IOPL_MASK | VM_MASK | RF_MASK | NT_MASK;
    if (!(type & 8)) {
        eflags_mask &= 0xffff;
    }
    cpu_load_eflags(env, new_eflags, eflags_mask);
    /* XXX: what to do in 16 bit case? */
    env->regs[R_EAX] = new_regs[0];
    env->regs[R_ECX] = new_regs[1];
    env->regs[R_EDX] = new_regs[2];
    env->regs[R_EBX] = new_regs[3];
    env->regs[R_ESP] = new_regs[4];
    env->regs[R_EBP] = new_regs[5];
    env->regs[R_ESI] = new_regs[6];
    env->regs[R_EDI] = new_regs[7];
    if (new_eflags & VM_MASK) {
        for (i = 0; i < 6; i++) {
            load_seg_vm(env, i, new_segs[i]);
        }
    } else {
        /* first just selectors as the rest may trigger exceptions */
        for (i = 0; i < 6; i++) {
            cpu_x86_load_seg_cache(env, i, new_segs[i], 0, 0, 0);
        }
    }

    env->ldt.selector = new_ldt & ~4;
    env->ldt.base = 0;
    env->ldt.limit = 0;
    env->ldt.flags = 0;

    /* load the LDT */
    if (new_ldt & 4) {
        raise_exception_err_ra(env, EXCP0A_TSS, new_ldt & 0xfffc, retaddr);
    }

    if ((new_ldt & 0xfffc) != 0) {
        dt = &env->gdt;
        index = new_ldt & ~7;
        if ((index + 7) > dt->limit) {
            raise_exception_err_ra(env, EXCP0A_TSS, new_ldt & 0xfffc, retaddr);
        }
        ptr = dt->base + index;
        e1 = cpu_ldl_kernel_ra(env, ptr, retaddr);
        e2 = cpu_ldl_kernel_ra(env, ptr + 4, retaddr);
        if ((e2 & DESC_S_MASK) || ((e2 >> DESC_TYPE_SHIFT) & 0xf) != 2) {
            raise_exception_err_ra(env, EXCP0A_TSS, new_ldt & 0xfffc, retaddr);
        }
        if (!(e2 & DESC_P_MASK)) {
            raise_exception_err_ra(env, EXCP0A_TSS, new_ldt & 0xfffc, retaddr);
        }
        load_seg_cache_raw_dt(&env->ldt, e1, e2);
    }

    /* load the segments */
    if (!(new_eflags & VM_MASK)) {
        int cpl = new_segs[R_CS] & 3;
        tss_load_seg(env, R_CS, new_segs[R_CS], cpl, retaddr);
        tss_load_seg(env, R_SS, new_segs[R_SS], cpl, retaddr);
        tss_load_seg(env, R_ES, new_segs[R_ES], cpl, retaddr);
        tss_load_seg(env, R_DS, new_segs[R_DS], cpl, retaddr);
        tss_load_seg(env, R_FS, new_segs[R_FS], cpl, retaddr);
        tss_load_seg(env, R_GS, new_segs[R_GS], cpl, retaddr);
    }

    /* check that env->eip is in the CS segment limits */
    if (new_eip > env->segs[R_CS].limit) {
        /* XXX: different exception if CALL? */
        raise_exception_err_ra(env, EXCP0D_GPF, 0, retaddr);
    }

#ifndef CONFIG_USER_ONLY
    /* reset local breakpoints */
    if (env->dr[7] & DR7_LOCAL_BP_MASK) {
        cpu_x86_update_dr7(env, env->dr[7] & ~DR7_LOCAL_BP_MASK);
    }
#endif
}

void helper_ljmp_protected(CPUX86State *env, int new_cs, target_ulong new_eip,
                           target_ulong next_eip)
{
    int gate_cs, type;
    uint32_t e1, e2, cpl, dpl, rpl, limit;

    if ((new_cs & 0xfffc) == 0) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
    }
    if (load_segment_ra(env, &e1, &e2, new_cs, GETPC()) != 0) {
        raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, GETPC());
    }
    cpl = env->hflags & HF_CPL_MASK;
    if (e2 & DESC_S_MASK) {
        if (!(e2 & DESC_CS_MASK)) {
            raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, GETPC());
        }
        dpl = (e2 >> DESC_DPL_SHIFT) & 3;
        if (e2 & DESC_C_MASK) {
            /* conforming code segment */
            if (dpl > cpl) {
                raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, GETPC());
            }
        } else {
            /* non conforming code segment */
            rpl = new_cs & 3;
            if (rpl > cpl) {
                raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, GETPC());
            }
            if (dpl != cpl) {
                raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, GETPC());
            }
        }
        if (!(e2 & DESC_P_MASK)) {
            raise_exception_err_ra(env, EXCP0B_NOSEG, new_cs & 0xfffc, GETPC());
        }
        limit = get_seg_limit(e1, e2);
        if (new_eip > limit &&
            (!(env->hflags & HF_LMA_MASK) || !(e2 & DESC_L_MASK))) {
            raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
        }
        cpu_x86_load_seg_cache(env, R_CS, (new_cs & 0xfffc) | cpl,
                       get_seg_base(e1, e2), limit, e2);
        env->eip = new_eip;
    } else {
        /* jump to call or task gate */
        dpl = (e2 >> DESC_DPL_SHIFT) & 3;
        rpl = new_cs & 3;
        cpl = env->hflags & HF_CPL_MASK;
        type = (e2 >> DESC_TYPE_SHIFT) & 0xf;

#ifdef TARGET_X86_64
        if (env->efer & MSR_EFER_LMA) {
            if (type != 12) {
                raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, GETPC());
            }
        }
#endif
        switch (type) {
        case 1: /* 286 TSS */
        case 9: /* 386 TSS */
        case 5: /* task gate */
            if (dpl < cpl || dpl < rpl) {
                raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, GETPC());
            }
            switch_tss_ra(env, new_cs, e1, e2, SWITCH_TSS_JMP, next_eip, GETPC());
            break;
        case 4: /* 286 call gate */
        case 12: /* 386 call gate */
            if ((dpl < cpl) || (dpl < rpl)) {
                raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, GETPC());
            }
            if (!(e2 & DESC_P_MASK)) {
                raise_exception_err_ra(env, EXCP0B_NOSEG, new_cs & 0xfffc, GETPC());
            }
            gate_cs = e1 >> 16;
            new_eip = (e1 & 0xffff);
            if (type == 12) {
                new_eip |= (e2 & 0xffff0000);
            }

#ifdef TARGET_X86_64
            if (env->efer & MSR_EFER_LMA) {
                /* load the upper 8 bytes of the 64-bit call gate */
                if (load_segment_ra(env, &e1, &e2, new_cs + 8, GETPC())) {
                    raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc,
                                           GETPC());
                }
                type = (e2 >> DESC_TYPE_SHIFT) & 0x1f;
                if (type != 0) {
                    raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc,
                                           GETPC());
                }
                new_eip |= ((target_ulong)e1) << 32;
            }
#endif

            if (load_segment_ra(env, &e1, &e2, gate_cs, GETPC()) != 0) {
                raise_exception_err_ra(env, EXCP0D_GPF, gate_cs & 0xfffc, GETPC());
            }
            dpl = (e2 >> DESC_DPL_SHIFT) & 3;
            /* must be code segment */
            if (((e2 & (DESC_S_MASK | DESC_CS_MASK)) !=
                 (DESC_S_MASK | DESC_CS_MASK))) {
                raise_exception_err_ra(env, EXCP0D_GPF, gate_cs & 0xfffc, GETPC());
            }
            if (((e2 & DESC_C_MASK) && (dpl > cpl)) ||
                (!(e2 & DESC_C_MASK) && (dpl != cpl))) {
                raise_exception_err_ra(env, EXCP0D_GPF, gate_cs & 0xfffc, GETPC());
            }
#ifdef TARGET_X86_64
            if (env->efer & MSR_EFER_LMA) {
                if (!(e2 & DESC_L_MASK)) {
                    raise_exception_err_ra(env, EXCP0D_GPF, gate_cs & 0xfffc, GETPC());
                }
                if (e2 & DESC_B_MASK) {
                    raise_exception_err_ra(env, EXCP0D_GPF, gate_cs & 0xfffc, GETPC());
                }
            }
#endif
            if (!(e2 & DESC_P_MASK)) {
                raise_exception_err_ra(env, EXCP0D_GPF, gate_cs & 0xfffc, GETPC());
            }
            limit = get_seg_limit(e1, e2);
            if (new_eip > limit &&
                (!(env->hflags & HF_LMA_MASK) || !(e2 & DESC_L_MASK))) {
                raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
            }
            cpu_x86_load_seg_cache(env, R_CS, (gate_cs & 0xfffc) | cpl,
                                   get_seg_base(e1, e2), limit, e2);
            env->eip = new_eip;
            break;
        default:
            raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, GETPC());
            break;
        }
    }
}

