#define CONFIG_CPUID_H 1

#define TARGET_X86_64 1

#define CONFIG_USER_ONLY 1

#define QEMU_NORETURN __attribute__ ((__noreturn__))

#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#define likely(x)   __builtin_expect(!!(x), 1)

#define unlikely(x)   __builtin_expect(!!(x), 0)

#define container_of(ptr, type, member) ({                      \
        const typeof(((type *) 0)->member) *__mptr = (ptr);     \
        (type *) ((char *) __mptr - offsetof(type, member));})

#define QEMU_BUILD_BUG_ON(x) _Static_assert(!(x), "not expecting: " #x)

#  define GCC_FMT_ATTR(n, m) __attribute__((format(printf, n, m)))

#include <stddef.h>

#include <stdbool.h>

#include <stdint.h>

#include <sys/types.h>

#include <stdlib.h>

#include <stdio.h>

#include <string.h>

#include <inttypes.h>

#include <limits.h>

#include <assert.h>

#include <setjmp.h>

static inline void qemu_flockfile(FILE *f)
{
    flockfile(f);
}

#define G_GNUC_MALLOC __attribute__((__malloc__))

#define G_GNUC_ALLOC_SIZE(x) __attribute__((__alloc_size__(x)))

#define _GLIB_EXTERN extern "C"

static inline void qemu_funlockfile(FILE *f)
{
    funlockfile(f);
}

typedef unsigned long gsize;

#define GLIB_AVAILABLE_IN_ALL                   _GLIB_EXTERN

typedef int    gint;

typedef gint   gboolean;

typedef unsigned int    guint;

typedef void* gpointer;

typedef const void *gconstpointer;

typedef gboolean        (*GEqualFunc)           (gconstpointer  a,
                                                 gconstpointer  b);

typedef guint           (*GHashFunc)            (gconstpointer  key);

GLIB_AVAILABLE_IN_ALL
void	 g_free	          (gpointer	 mem);

GLIB_AVAILABLE_IN_ALL
gpointer g_malloc         (gsize	 n_bytes) G_GNUC_MALLOC G_GNUC_ALLOC_SIZE(1);

typedef struct _GHashTable  GHashTable;

GLIB_AVAILABLE_IN_ALL
GHashTable* g_hash_table_new               (GHashFunc       hash_func,
                                            GEqualFunc      key_equal_func);

GLIB_AVAILABLE_IN_ALL
gboolean    g_hash_table_insert            (GHashTable     *hash_table,
                                            gpointer        key,
                                            gpointer        value);

GLIB_AVAILABLE_IN_ALL
gpointer    g_hash_table_lookup            (GHashTable     *hash_table,
                                            gconstpointer   key);

typedef struct _GSList GSList;

struct _GSList
{
  gpointer data;
  GSList *next;
};

#include <pthread.h>

typedef struct AddressSpace AddressSpace;

typedef struct BusState BusState;

typedef struct CPUAddressSpace CPUAddressSpace;

typedef struct CPUState CPUState;

typedef struct DeviceState DeviceState;

typedef struct MemoryRegion MemoryRegion;

typedef struct QemuOpts QemuOpts;

#define QEMU_ALIGN_DOWN(n, m) ((n) / (m) * (m))

#define QEMU_ALIGN_UP(n, m) QEMU_ALIGN_DOWN((n) + (m) - 1, (m))

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

#define QEMU_IS_ARRAY(x) (!__builtin_types_compatible_p(typeof(x), \
                                                        typeof(&(x)[0])))

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

# define ATOMIC_REG_SIZE  8

#define atomic_read__nocheck(ptr) \
    __atomic_load_n(ptr, __ATOMIC_RELAXED)

#define atomic_read(ptr)                              \
    ({                                                \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > ATOMIC_REG_SIZE); \
    atomic_read__nocheck(ptr);                        \
    })

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

#define le_bswap(v, size) (v)

static inline int ldub_p(const void *ptr)
{
    return *(uint8_t *)ptr;
}

static inline int lduw_he_p(const void *ptr)
{
    uint16_t r;
    memcpy(&r, ptr, sizeof(r));
    return r;
}

static inline int ldl_he_p(const void *ptr)
{
    int32_t r;
    memcpy(&r, ptr, sizeof(r));
    return r;
}

static inline uint64_t ldq_he_p(const void *ptr)
{
    uint64_t r;
    memcpy(&r, ptr, sizeof(r));
    return r;
}

static inline int lduw_le_p(const void *ptr)
{
    return (uint16_t)le_bswap(lduw_he_p(ptr), 16);
}

static inline int ldsw_le_p(const void *ptr)
{
    return (int16_t)le_bswap(lduw_he_p(ptr), 16);
}

static inline int ldl_le_p(const void *ptr)
{
    return le_bswap(ldl_he_p(ptr), 32);
}

static inline uint64_t ldq_le_p(const void *ptr)
{
    return le_bswap(ldq_he_p(ptr), 64);
}

static inline int ctz32(uint32_t val)
{
    return val ? __builtin_ctz(val) : 32;
}

static inline int ctz64(uint64_t val)
{
    return val ? __builtin_ctzll(val) : 64;
}

# define ctzl   ctz64

#define BITS_PER_BYTE           CHAR_BIT

#define BITS_PER_LONG           (sizeof (unsigned long) * BITS_PER_BYTE)

#define BIT_MASK(nr)            (1UL << ((nr) % BITS_PER_LONG))

#define BIT_WORD(nr)            ((nr) / BITS_PER_LONG)

#define BITS_TO_LONGS(nr)       DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))

static inline void set_bit(long nr, unsigned long *addr)
{
    unsigned long mask = BIT_MASK(nr);
    unsigned long *p = addr + BIT_WORD(nr);

    *p  |= mask;
}

static inline void clear_bit(long nr, unsigned long *addr)
{
    unsigned long mask = BIT_MASK(nr);
    unsigned long *p = addr + BIT_WORD(nr);

    *p &= ~mask;
}

static inline int test_bit(long nr, const unsigned long *addr)
{
    return 1UL & (addr[BIT_WORD(nr)] >> (nr & (BITS_PER_LONG-1)));
}

static inline unsigned long find_first_bit(const unsigned long *addr,
                                           unsigned long size)
{
    unsigned long result, tmp;

    for (result = 0; result < size; result += BITS_PER_LONG) {
        tmp = *addr++;
        if (tmp) {
            result += ctzl(tmp);
            return result < size ? result : size;
        }
    }
    /* Not found */
    return size;
}

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

typedef struct QemuMutex QemuMutex;

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

typedef struct Notifier Notifier;

struct Notifier
{
    void (*notify)(Notifier *notifier, void *data);
    QLIST_ENTRY(Notifier) node;
};

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
    ::vaddr vaddr;
    ::vaddr len;
    ::vaddr hitaddr;
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
};

#define BP_GDB                0x10

#define BP_CPU                0x20

#define BP_ANY                (BP_GDB | BP_CPU)

#define HV_X64_MSR_CRASH_P0                     0x40000100

#define HV_X64_MSR_CRASH_P4                     0x40000104

#define HV_CRASH_PARAMS    (HV_X64_MSR_CRASH_P4 - HV_X64_MSR_CRASH_P0 + 1)

#define HV_SINT_COUNT                         16

#define HV_STIMER_COUNT                       4

typedef struct X86CPU X86CPU;

#define TARGET_LONG_BITS 64

#define TCG_GUEST_DEFAULT_MO      (TCG_MO_ALL & ~TCG_MO_ST_LD)

#define TARGET_MAX_INSN_SIZE 16

#define CPUArchState struct CPUX86State

# define TCG_TARGET_REG_BITS  64

# define TCG_TARGET_NB_REGS   16

#define TCG_REG_CALL_STACK TCG_REG_ESP

typedef enum {
    TCG_REG_EAX = 0,
    TCG_REG_ECX,
    TCG_REG_EDX,
    TCG_REG_EBX,
    TCG_REG_ESP,
    TCG_REG_EBP,
    TCG_REG_ESI,
    TCG_REG_EDI,

    /* 64-bit registers; always define the symbols to avoid
       too much if-deffing.  */
    TCG_REG_R8,
    TCG_REG_R9,
    TCG_REG_R10,
    TCG_REG_R11,
    TCG_REG_R12,
    TCG_REG_R13,
    TCG_REG_R14,
    TCG_REG_R15,
    TCG_REG_RAX = TCG_REG_EAX,
    TCG_REG_RCX = TCG_REG_ECX,
    TCG_REG_RDX = TCG_REG_EDX,
    TCG_REG_RBX = TCG_REG_EBX,
    TCG_REG_RSP = TCG_REG_ESP,
    TCG_REG_RBP = TCG_REG_EBP,
    TCG_REG_RSI = TCG_REG_ESI,
    TCG_REG_RDI = TCG_REG_EDI,
} TCGReg;

extern bool have_bmi1;

#define TCG_TARGET_HAS_div_i32          1
#define TCG_TARGET_HAS_rem_i32          1
#define TCG_TARGET_HAS_div2_i32         0
#define TCG_TARGET_HAS_add2_i32         0
#define TCG_TARGET_HAS_sub2_i32         0
#define TCG_TARGET_HAS_bswap16_i32      1
#define TCG_TARGET_HAS_orc_i32          0
#define TCG_TARGET_HAS_orc_i64          0
#define TCG_TARGET_HAS_eqv_i32          0
#define TCG_TARGET_HAS_nand_i32         0
#define TCG_TARGET_HAS_nor_i32          0
#define TCG_TARGET_HAS_div_i64          0
#define TCG_TARGET_HAS_rem_i64          0
#define TCG_TARGET_HAS_div2_i64         0
#define TCG_TARGET_HAS_bswap16_i64      1
#define TCG_TARGET_HAS_eqv_i64          0
#define TCG_TARGET_HAS_nand_i64         0
#define TCG_TARGET_HAS_nor_i64          0
#define TCG_TARGET_HAS_sub2_i64         0
#define TCG_TARGET_HAS_rot_i32          1
#define TCG_TARGET_HAS_ext8s_i32        1
#define TCG_TARGET_HAS_ext16s_i32       1
#define TCG_TARGET_HAS_ext8u_i32        1
#define TCG_TARGET_HAS_ext16u_i32       1
#define TCG_TARGET_HAS_bswap32_i32      1
#define TCG_TARGET_HAS_neg_i32          1
#define TCG_TARGET_HAS_not_i32          1
#define TCG_TARGET_HAS_andc_i32         have_bmi1
#define TCG_TARGET_HAS_clz_i32          1
#define TCG_TARGET_HAS_ctz_i32          1
#define TCG_TARGET_HAS_ctpop_i32        have_popcnt
#define TCG_TARGET_HAS_deposit_i32      1
#define TCG_TARGET_HAS_extract_i32      1
#define TCG_TARGET_HAS_sextract_i32     1
#define TCG_TARGET_HAS_movcond_i32      1
#define TCG_TARGET_HAS_mulu2_i32        1
#define TCG_TARGET_HAS_muls2_i32        1
#define TCG_TARGET_HAS_muluh_i32        0
#define TCG_TARGET_HAS_mulsh_i32        0
#define TCG_TARGET_HAS_goto_ptr         1
#define TCG_TARGET_HAS_extrl_i64_i32    0
#define TCG_TARGET_HAS_extrh_i64_i32    0
#define TCG_TARGET_HAS_rot_i64          1
#define TCG_TARGET_HAS_ext8s_i64        1
#define TCG_TARGET_HAS_ext16s_i64       1
#define TCG_TARGET_HAS_ext32s_i64       1
#define TCG_TARGET_HAS_ext8u_i64        1
#define TCG_TARGET_HAS_ext16u_i64       1
#define TCG_TARGET_HAS_ext32u_i64       1
#define TCG_TARGET_HAS_bswap32_i64      1
#define TCG_TARGET_HAS_bswap64_i64      1
#define TCG_TARGET_HAS_neg_i64          1
#define TCG_TARGET_HAS_not_i64          1
#define TCG_TARGET_HAS_andc_i64         have_bmi1
#define TCG_TARGET_HAS_clz_i64          1
#define TCG_TARGET_HAS_ctz_i64          1
#define TCG_TARGET_HAS_ctpop_i64        have_popcnt
#define TCG_TARGET_HAS_deposit_i64      1
#define TCG_TARGET_HAS_extract_i64      1
#define TCG_TARGET_HAS_sextract_i64     0
#define TCG_TARGET_HAS_movcond_i64      1
#define TCG_TARGET_HAS_add2_i64         1
#define TCG_TARGET_HAS_mulu2_i64        1
#define TCG_TARGET_HAS_muls2_i64        1
#define TCG_TARGET_HAS_muluh_i64        0
#define TCG_TARGET_HAS_mulsh_i64        0

#define TCG_TARGET_deposit_i32_valid(ofs, len) \
    (((ofs) == 0 && (len) == 8) || ((ofs) == 8 && (len) == 8) || \
     ((ofs) == 0 && (len) == 16))

#define TCG_TARGET_deposit_i64_valid    TCG_TARGET_deposit_i32_valid

#define TCG_TARGET_extract_i32_valid(ofs, len) ((ofs) == 8 && (len) == 8)

#define TCG_TARGET_extract_i64_valid(ofs, len) \
    (((ofs) == 8 && (len) == 8) || ((ofs) + (len)) == 32)

# define TCG_AREG0 TCG_REG_R14

extern bool have_popcnt;

#define TCG_TARGET_DEFAULT_MO (TCG_MO_ALL & ~TCG_MO_ST_LD)

#define TCG_TARGET_NEED_POOL_LABELS

typedef enum {
    /* Used to indicate the type of accesses on which ordering
       is to be ensured.  Modeled after SPARC barriers.

       This is of the form TCG_MO_A_B where A is before B in program order.
    */
    TCG_MO_LD_LD  = 0x01,
    TCG_MO_ST_LD  = 0x02,
    TCG_MO_LD_ST  = 0x04,
    TCG_MO_ST_ST  = 0x08,
    TCG_MO_ALL    = 0x0F,  /* OR of the above */

    /* Used to indicate the kind of ordering which is to be ensured by the
       instruction.  These types are derived from x86/aarch64 instructions.
       It should be noted that these are different from C11 semantics.  */
    TCG_BAR_LDAQ  = 0x10,  /* Following ops will not come forward */
    TCG_BAR_STRL  = 0x20,  /* Previous ops will not be delayed */
    TCG_BAR_SC    = 0x30,  /* No ops cross barrier; OR of the above */
} TCGBar;

typedef int64_t target_long;

#define TARGET_FMT_lx "%016" PRIx64

#define CPU_COMMON_TLB

#define CPU_COMMON                                                      \
    /* soft mmu support */                                              \
    CPU_COMMON_TLB

#define R_EAX 0

#define R_ECX 1

#define R_EDX 2

#define R_EBX 3

#define R_ESP 4

#define R_EBP 5

#define R_ESI 6

#define R_EDI 7

#define R_AH 4

#define R_ES 0

#define R_CS 1

#define R_SS 2

#define R_DS 3

#define R_FS 4

#define R_GS 5

#define CC_C    0x0001

#define CC_P    0x0004

#define CC_A    0x0010

#define CC_Z    0x0040

#define CC_S    0x0080

#define CC_O    0x0800

#define TF_SHIFT   8

#define IOPL_SHIFT 12

#define VM_SHIFT   17

#define TF_MASK                 0x00000100

#define IF_MASK                 0x00000200

#define IOPL_MASK               0x00003000

#define NT_MASK                 0x00004000

#define AC_MASK                 0x00040000

#define ID_MASK                 0x00200000

#define HF_CPL_SHIFT         0

#define HF_INHIBIT_IRQ_SHIFT 3

#define HF_CS32_SHIFT        4

#define HF_SS32_SHIFT        5

#define HF_ADDSEG_SHIFT      6

#define HF_PE_SHIFT          7

#define HF_MP_SHIFT          9

#define HF_EM_SHIFT         10

#define HF_TS_SHIFT         11

#define HF_LMA_SHIFT        14

#define HF_CS64_SHIFT       15

#define HF_RF_SHIFT         16

#define HF_SMM_SHIFT        19

#define HF_SVME_SHIFT       20

#define HF_SVMI_SHIFT       21

#define HF_OSFXSR_SHIFT     22

#define HF_IOBPT_SHIFT      24

#define HF_MPX_EN_SHIFT     25

#define HF_MPX_IU_SHIFT     26

#define HF_INHIBIT_IRQ_MASK  (1 << HF_INHIBIT_IRQ_SHIFT)

#define HF_MP_MASK           (1 << HF_MP_SHIFT)

#define HF_EM_MASK           (1 << HF_EM_SHIFT)

#define HF_TS_MASK           (1 << HF_TS_SHIFT)

#define HF_RF_MASK           (1 << HF_RF_SHIFT)

#define HF_SMM_MASK          (1 << HF_SMM_SHIFT)

#define HF_SVME_MASK         (1 << HF_SVME_SHIFT)

#define HF_SVMI_MASK         (1 << HF_SVMI_SHIFT)

#define HF_OSFXSR_MASK       (1 << HF_OSFXSR_SHIFT)

#define HF_IOBPT_MASK        (1 << HF_IOBPT_SHIFT)

#define HF_MPX_EN_MASK       (1 << HF_MPX_EN_SHIFT)

#define HF_MPX_IU_MASK       (1 << HF_MPX_IU_SHIFT)

#define CR4_FSGSBASE_MASK (1U << 16)

#define MCE_BANKS_DEF   10

#define MSR_MTRRcap_VCNT                8

#define MSR_P6_EVNTSEL0                 0x186

#define MSR_IA32_PERF_STATUS            0x198

typedef uint64_t target_ulong;

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

#define CPUID_CX8  (1U << 8)

#define CPUID_CMOV (1U << 15)

#define CPUID_CLFLUSH (1U << 19)

#define CPUID_FXSR (1U << 24)

#define CPUID_SSE  (1U << 25)

#define CPUID_SSE2 (1U << 26)

#define CPUID_EXT_PCLMULQDQ (1U << 1)

#define CPUID_EXT_MONITOR  (1U << 3)

#define CPUID_EXT_SSSE3    (1U << 9)

#define CPUID_EXT_CX16     (1U << 13)

#define CPUID_EXT_SSE41    (1U << 19)

#define CPUID_EXT_SSE42    (1U << 20)

#define CPUID_EXT_MOVBE    (1U << 22)

#define CPUID_EXT_POPCNT   (1U << 23)

#define CPUID_EXT_AES      (1U << 25)

#define CPUID_EXT_XSAVE    (1U << 26)

#define CPUID_EXT2_RDTSCP  (1U << 27)

#define CPUID_EXT2_3DNOW   (1U << 31)

#define CPUID_EXT3_LAHF_LM (1U << 0)

#define CPUID_EXT3_CR8LEG  (1U << 4)

#define CPUID_EXT3_ABM     (1U << 5)

#define CPUID_EXT3_SKINIT  (1U << 12)

#define CPUID_7_0_EBX_FSGSBASE (1U << 0)

#define CPUID_7_0_EBX_BMI1     (1U << 3)

#define CPUID_7_0_EBX_BMI2     (1U << 8)

#define CPUID_7_0_EBX_ADX      (1U << 19)

#define CPUID_7_0_EBX_SMAP     (1U << 20)

#define CPUID_7_0_EBX_PCOMMIT  (1U << 22)

#define CPUID_7_0_EBX_CLFLUSHOPT (1U << 23)

#define CPUID_7_0_EBX_CLWB     (1U << 24)

#define CPUID_XSAVE_XSAVEOPT   (1U << 0)

#define CPUID_VENDOR_INTEL_1 0x756e6547

#define EXCP00_DIVZ	0

#define EXCP03_INT3	3

#define EXCP06_ILLOP	6

#define EXCP07_PREX	7

#define EXCP0D_GPF	13

typedef uint32_t FeatureWordArray[FEATURE_WORDS];

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

typedef MMREG_UNION(ZMMReg, 512) ZMMReg;

typedef MMREG_UNION(MMXReg, 64)  MMXReg;

typedef struct BNDReg {
    uint64_t lb;
    uint64_t ub;
} BNDReg;

#define ZMM_B(n) _b_ZMMReg[n]

#define ZMM_W(n) _w_ZMMReg[n]

#define ZMM_L(n) _l_ZMMReg[n]

#define ZMM_Q(n) _q_ZMMReg[n]

#define ZMM_D(n) _d_ZMMReg[n]

#define MMX_W(n) _w_MMXReg[n]

#define MMX_L(n) _l_MMXReg[n]

#define MMX_Q(n) _q_MMXReg[n]

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

#define TARGET_INSN_START_EXTRA_WORDS 1

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

    uint64_t opmask_regs[NB_OPMASK_REGS];

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

    uint32_t pkru;

    uint64_t spec_ctrl;

    /* End of state preserved by INIT (dummy marker).  */
    struct {} end_init_save;

    uint64_t system_time_msr;
    uint64_t wall_clock_msr;
    uint64_t steal_time_msr;
    uint64_t async_pf_en_msr;
    uint64_t pv_eoi_en_msr;

    uint64_t msr_hv_hypercall;
    uint64_t msr_hv_guest_os_id;
    uint64_t msr_hv_vapic;
    uint64_t msr_hv_tsc;
    uint64_t msr_hv_crash_params[HV_CRASH_PARAMS];
    uint64_t msr_hv_runtime;
    uint64_t msr_hv_synic_control;
    uint64_t msr_hv_synic_version;
    uint64_t msr_hv_synic_evt_page;
    uint64_t msr_hv_synic_msg_page;
    uint64_t msr_hv_synic_sint[HV_SINT_COUNT];
    uint64_t msr_hv_stimer_config[HV_STIMER_COUNT];
    uint64_t msr_hv_stimer_count[HV_STIMER_COUNT];

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
    uint32_t sipi_vector;
    bool tsc_valid;
    int64_t tsc_khz;
    int64_t user_tsc_khz; /* for sanity check only */
    void *kvm_xsave_buf;

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

#define ENV_OFFSET offsetof(X86CPU, env)

#define TARGET_PAGE_BITS 12

#define lduw_p(p) lduw_le_p(p)

#define ldsw_p(p) ldsw_le_p(p)

#define ldl_p(p) ldl_le_p(p)

#define ldq_p(p) ldq_le_p(p)

#define TARGET_ABI_BITS TARGET_LONG_BITS

#define ABI_LONG_ALIGNMENT (TARGET_ABI_BITS / 8)

typedef target_ulong abi_ulong __attribute__((aligned(ABI_LONG_ALIGNMENT)));

extern unsigned long guest_base;

#define TARGET_PAGE_SIZE (1 << TARGET_PAGE_BITS)

#define TARGET_PAGE_MASK ~(TARGET_PAGE_SIZE - 1)

#define SVM_IOIO_TYPE_MASK 1

#define	SVM_EXIT_READ_CR0 	0x000

#define	SVM_EXIT_WRITE_CR0 	0x010

#define	SVM_EXIT_READ_DR0 	0x020

#define	SVM_EXIT_WRITE_DR0 	0x030

#define SVM_EXIT_IDTR_READ	0x066

#define SVM_EXIT_GDTR_READ	0x067

#define SVM_EXIT_LDTR_READ	0x068

#define SVM_EXIT_TR_READ	0x069

#define SVM_EXIT_IDTR_WRITE	0x06a

#define SVM_EXIT_GDTR_WRITE	0x06b

#define SVM_EXIT_LDTR_WRITE	0x06c

#define SVM_EXIT_TR_WRITE	0x06d

#define SVM_EXIT_PUSHF		0x070

#define SVM_EXIT_POPF		0x071

#define SVM_EXIT_RSM		0x073

#define SVM_EXIT_IRET		0x074

#define SVM_EXIT_INVD		0x076

#define SVM_EXIT_WBINVD		0x089

typedef struct TranslationBlock TranslationBlock;

typedef abi_ulong tb_page_addr_t;

extern FILE *qemu_logfile;

extern int qemu_loglevel;

#define LOG_UNIMP          (1 << 10)

#define CPU_LOG_TB_NOCHAIN (1 << 13)

static inline bool qemu_loglevel_mask(int mask)
{
    return (qemu_loglevel & mask) != 0;
}

static inline void qemu_log_lock(void)
{
    qemu_flockfile(qemu_logfile);
}

static inline void qemu_log_unlock(void)
{
    qemu_funlockfile(qemu_logfile);
}

int GCC_FMT_ATTR(1, 2) qemu_log(const char *fmt, ...);

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
#define CF_INVALID     0x00040000 /* TB is stale. Setters need tb_lock */
#define CF_PARALLEL    0x00080000 /* Generate code for a parallel context */
/* cflags' mask for hashing/comparison */
#define CF_HASH_MASK   \
    (CF_COUNT_MASK | CF_LAST_IO | CF_USE_ICOUNT | CF_PARALLEL)

    /* Per-vCPU dynamic tracing state used to generate this TB */
    uint32_t trace_vcpu_dstate;

    struct tb_tc tc;

    /* original tb when cflags has CF_NOCACHE */
    struct TranslationBlock *orig_tb;
    /* first and second physical page containing code. The lower bit
       of the pointer tells the index in page_next[] */
    struct TranslationBlock *page_next[2];
    tb_page_addr_t page_addr[2];

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

    /* Each TB has an associated circular list of TBs jumping to this one.
     * jmp_list_first points to the first TB jumping to this one.
     * jmp_list_next is used to point to the next TB in a list.
     * Since each TB can have two jumps, it can participate in two lists.
     * jmp_list_first and jmp_list_next are 4-byte aligned pointers to a
     * TranslationBlock structure, but the two least significant bits of
     * them are used to encode which data field of the pointed TB should
     * be used to traverse the list further from that TB:
     * 0 => jmp_list_next[0], 1 => jmp_list_next[1], 2 => jmp_list_first.
     * In other words, 0/1 tells which jump is used in the pointed TB,
     * and 2 means that this is a pointer back to the target TB of this list.
     */
    uintptr_t jmp_list_next[2];
    uintptr_t jmp_list_first;
};

static inline uint32_t tb_cflags(const TranslationBlock *tb)
{
    return atomic_read(&tb->cflags);
}

#define MAX_OPC_PARAM_PER_ARG 1

#define MAX_OPC_PARAM_IARGS 5

#define MAX_OPC_PARAM_OARGS 1

#define MAX_OPC_PARAM_ARGS (MAX_OPC_PARAM_IARGS + MAX_OPC_PARAM_OARGS)

#define MAX_OPC_PARAM (4 + (MAX_OPC_PARAM_PER_ARG * MAX_OPC_PARAM_ARGS))

#define OPC_BUF_SIZE 640

typedef int64_t tcg_target_long;

typedef uint64_t tcg_target_ulong;

# define TARGET_INSN_START_WORDS (1 + TARGET_INSN_START_EXTRA_WORDS)

typedef uint32_t TCGRegSet;

typedef enum TCGOpcode {
#define DEF(name, oargs, iargs, cargs, flags) INDEX_op_ ## name,
#include "tcg-opc.h"
#undef DEF
    NB_OPS,
} TCGOpcode;

#define tcg_regset_set_reg(d, r)   ((d) |= (TCGRegSet)1 << (r))

#define tcg_regset_reset_reg(d, r) ((d) &= ~((TCGRegSet)1 << (r)))

#define tcg_regset_test_reg(d, r)  (((d) >> (r)) & 1)

# define tcg_debug_assert(X) do { (void)(X); } while (0)

typedef uint8_t tcg_insn_unit;

typedef struct TCGRelocation {
    struct TCGRelocation *next;
    int type;
    tcg_insn_unit *ptr;
    intptr_t addend;
} TCGRelocation;

typedef struct TCGLabel {
    unsigned has_value : 1;
    unsigned id : 31;
    union {
        uintptr_t value;
        tcg_insn_unit *value_ptr;
        TCGRelocation *first_reloc;
    } u;
} TCGLabel;

#define TCG_POOL_CHUNK_SIZE 32768

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

typedef enum TCGMemOp {
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
#ifdef TARGET_WORDS_BIGENDIAN
    MO_TE    = MO_BE,
#else
    MO_TE    = MO_LE,
#endif

    /* MO_UNALN accesses are never checked for alignment.
     * MO_ALIGN accesses will result in a call to the CPU's
     * do_unaligned_access hook if the guest address is not aligned.
     * The default depends on whether the target CPU defines ALIGNED_ONLY.
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
#ifdef ALIGNED_ONLY
    MO_ALIGN = 0,
    MO_UNALN = MO_AMASK,
#else
    MO_ALIGN = MO_AMASK,
    MO_UNALN = 0,
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

    MO_TEUW  = MO_TE | MO_UW,
    MO_TEUL  = MO_TE | MO_UL,
    MO_TESW  = MO_TE | MO_SW,
    MO_TESL  = MO_TE | MO_SL,
    MO_TEQ   = MO_TE | MO_Q,

    MO_SSIZE = MO_SIZE | MO_SIGN,
} TCGMemOp;

static inline unsigned get_alignment_bits(TCGMemOp memop)
{
    unsigned a = memop & MO_AMASK;

    if (a == MO_UNALN) {
        /* No alignment required.  */
        a = 0;
    } else if (a == MO_ALIGN) {
        /* A natural alignment requirement.  */
        a = memop & MO_SIZE;
    } else {
        /* A specific alignment requirement.  */
        a = a >> MO_ASHIFT;
    }
#if defined(CONFIG_SOFTMMU)
    /* The requested alignment cannot overlap the TLB flags.  */
    tcg_debug_assert((TLB_FLAGS_MASK & ((1 << a) - 1)) == 0);
#endif
    return a;
}

typedef tcg_target_ulong TCGArg;

typedef struct TCGv_i32_d *TCGv_i32;

typedef struct TCGv_i64_d *TCGv_i64;

typedef struct TCGv_ptr_d *TCGv_ptr;

#define TCGv TCGv_i64

#define TCGV_UNUSED_I32(x) (x = (TCGv_i32)NULL)
#define TCGV_UNUSED_I64(x) (x = (TCGv_i64)NULL)
#define TCGV_UNUSED_PTR(x) (x = (TCGv_ptr)NULL)

#define TCGV_IS_UNUSED_I32(x) ((x) == (TCGv_i32)NULL)
#define TCGV_IS_UNUSED_I64(x) ((x) == (TCGv_i64)NULL)
#define TCGV_IS_UNUSED_PTR(x) ((x) == (TCGv_ptr)NULL)

/* call flags */
/* Helper does not read globals (either directly or through an exception). It
   implies TCG_CALL_NO_WRITE_GLOBALS. */
#define TCG_CALL_NO_READ_GLOBALS    0x0010
/* Helper does not write globals */
#define TCG_CALL_NO_WRITE_GLOBALS   0x0020
/* Helper can be safely suppressed if the return value is not used. */
#define TCG_CALL_NO_SIDE_EFFECTS    0x0040

/* convenience version of most used call flags */
#define TCG_CALL_NO_RWG         TCG_CALL_NO_READ_GLOBALS
#define TCG_CALL_NO_WG          TCG_CALL_NO_WRITE_GLOBALS
#define TCG_CALL_NO_SE          TCG_CALL_NO_SIDE_EFFECTS
#define TCG_CALL_NO_RWG_SE      (TCG_CALL_NO_RWG | TCG_CALL_NO_SE)
#define TCG_CALL_NO_WG_SE       (TCG_CALL_NO_WG | TCG_CALL_NO_SE)

/* Used to align parameters.  See the comment before tcgv_i32_temp.  */
#define TCG_CALL_DUMMY_ARG      ((TCGArg)0)

typedef TCGv_ptr TCGv_env;

typedef enum {
    /* non-signed */
    TCG_COND_NEVER  = 0 | 0 | 0 | 0,
    TCG_COND_ALWAYS = 0 | 0 | 0 | 1,
    TCG_COND_EQ     = 8 | 0 | 0 | 0,
    TCG_COND_NE     = 8 | 0 | 0 | 1,
    /* signed */
    TCG_COND_LT     = 0 | 0 | 2 | 0,
    TCG_COND_GE     = 0 | 0 | 2 | 1,
    TCG_COND_LE     = 8 | 0 | 2 | 0,
    TCG_COND_GT     = 8 | 0 | 2 | 1,
    /* unsigned */
    TCG_COND_LTU    = 0 | 4 | 0 | 0,
    TCG_COND_GEU    = 0 | 4 | 0 | 1,
    TCG_COND_LEU    = 8 | 4 | 0 | 0,
    TCG_COND_GTU    = 8 | 4 | 0 | 1,
} TCGCond;

static inline TCGCond tcg_invert_cond(TCGCond c)
{
    return (TCGCond)(c ^ 1);
}

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

    /* The number of out and in parameter for a call.  */
    unsigned calli  : 4;        /* 12 */
    unsigned callo  : 2;        /* 14 */
    unsigned        : 2;        /* 16 */

    /* Index of the prev/next op, or 0 for the end of the list.  */
    unsigned prev   : 16;       /* 32 */
    unsigned next   : 16;       /* 48 */

    /* Lifetime data of the operands.  */
    unsigned life   : 16;       /* 64 */

    /* Arguments for the opcode.  */
    TCGArg args[MAX_OPC_PARAM];
} TCGOp;

struct TCGContext {
    uint8_t *pool_cur, *pool_end;
    TCGPool *pool_first, *pool_current, *pool_first_large;
    int nb_labels;
    int nb_globals;
    int nb_temps;
    int nb_indirects;

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
#endif

    int gen_next_op_idx;

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

    /* Track which vCPU triggers events */
    CPUState *cpu;                      /* *_trans */

    /* These structures are private to tcg-target.inc.c.  */
#ifdef TCG_TARGET_NEED_LDST_LABELS
    struct TCGLabelQemuLdst *ldst_labels;
#endif
#ifdef TCG_TARGET_NEED_POOL_LABELS
    struct TCGLabelPoolData *pool_labels;
#endif

    TCGLabel *exitreq_label;

    TCGTempSet free_temps[TCG_TYPE_COUNT * 2];
    TCGTemp temps[TCG_MAX_TEMPS]; /* globals first, temps after */

    /* Tells which temporary holds a given register.
       It does not take into account fixed registers */
    TCGTemp *reg_to_temp[TCG_TARGET_NB_REGS];

    TCGOp gen_op_buf[OPC_BUF_SIZE];

    uint16_t gen_insn_end_off[TCG_MAX_INSNS];
    target_ulong gen_insn_data[TCG_MAX_INSNS][TARGET_INSN_START_WORDS];
};

extern __thread TCGContext *tcg_ctx;

extern TCGv_env cpu_env;

static inline size_t temp_idx(TCGTemp *ts)
{
    ptrdiff_t n = ts - tcg_ctx->temps;
    tcg_debug_assert(n >= 0 && n < tcg_ctx->nb_temps);
    return n;
}

static inline TCGArg temp_arg(TCGTemp *ts)
{
    return (uintptr_t)ts;
}

static inline TCGTemp *tcgv_i32_temp(TCGv_i32 v)
{
    uintptr_t o = (uintptr_t)v;
    TCGTemp *t = (TCGTemp *)((char *)tcg_ctx + o);
    tcg_debug_assert(offsetof(TCGContext, temps[temp_idx(t)]) == o);
    return t;
}

static inline TCGTemp *tcgv_i64_temp(TCGv_i64 v)
{
    return tcgv_i32_temp((TCGv_i32)v);
}

static inline TCGTemp *tcgv_ptr_temp(TCGv_ptr v)
{
    return tcgv_i32_temp((TCGv_i32)v);
}

static inline TCGArg tcgv_i32_arg(TCGv_i32 v)
{
    return temp_arg(tcgv_i32_temp(v));
}

static inline TCGArg tcgv_i64_arg(TCGv_i64 v)
{
    return temp_arg(tcgv_i64_temp(v));
}

static inline TCGArg tcgv_ptr_arg(TCGv_ptr v)
{
    return temp_arg(tcgv_ptr_temp(v));
}

static inline TCGv_i32 temp_tcgv_i32(TCGTemp *t)
{
    (void)temp_idx(t); /* trigger embedded assert */
    return (TCGv_i32)((char *)t - (char *)tcg_ctx);
}

static inline TCGv_i64 temp_tcgv_i64(TCGTemp *t)
{
    return (TCGv_i64)temp_tcgv_i32(t);
}

static inline TCGv_ptr temp_tcgv_ptr(TCGTemp *t)
{
    return (TCGv_ptr)temp_tcgv_i32(t);
}

void *tcg_malloc_internal(TCGContext *s, int size);

static inline void *tcg_malloc(int size)
{
    TCGContext *s = tcg_ctx;
    uint8_t *ptr, *ptr_end;

    /* ??? This is a weak placeholder for minimum malloc alignment.  */
    size = QEMU_ALIGN_UP(size, 8);

    ptr = s->pool_cur;
    ptr_end = ptr + size;
    if (unlikely(ptr_end > s->pool_end)) {
        return tcg_malloc_internal(tcg_ctx, size);
    } else {
        s->pool_cur = ptr_end;
        return ptr;
    }
}

TCGv_i32 tcg_temp_new_internal_i32(int temp_local);

TCGv_i64 tcg_temp_new_internal_i64(int temp_local);

void tcg_temp_free_i32(TCGv_i32 arg);

void tcg_temp_free_i64(TCGv_i64 arg);

static inline TCGv_i32 tcg_temp_new_i32(void)
{
    return tcg_temp_new_internal_i32(0);
}

static inline TCGv_i64 tcg_temp_new_i64(void)
{
    return tcg_temp_new_internal_i64(0);
}

static inline TCGv_i64 tcg_temp_local_new_i64(void)
{
    return tcg_temp_new_internal_i64(1);
}

#define TCG_CT_ALIAS  0x80

#define TCG_CT_IALIAS 0x40

#define TCG_CT_NEWREG 0x20

#define TCG_CT_REG    0x01

#define TCG_CT_CONST  0x02

#define TCG_MAX_OP_ARGS 16

typedef struct TCGArgConstraint {
    uint16_t ct;
    uint8_t alias_index;
    union {
        TCGRegSet regs;
    } u;
} TCGArgConstraint;

enum {
    /* Instruction defines the end of a basic block.  */
    TCG_OPF_BB_END       = 0x01,
    /* Instruction clobbers call registers and potentially update globals.  */
    TCG_OPF_CALL_CLOBBER = 0x02,
    /* Instruction has side effects: it cannot be removed if its outputs
       are not used, and might trigger exceptions.  */
    TCG_OPF_SIDE_EFFECTS = 0x04,
    /* Instruction operands are 64-bits (otherwise 32-bits).  */
    TCG_OPF_64BIT        = 0x08,
    /* Instruction is optional and not implemented by the host, or insn
       is generic and should not be implemened by the host.  */
    TCG_OPF_NOT_PRESENT  = 0x10,
};

typedef struct TCGOpDef {
    const char *name;
    uint8_t nb_oargs, nb_iargs, nb_cargs, nb_args;
    uint8_t flags;
    TCGArgConstraint *args_ct;
    int *sorted_args;
#if defined(CONFIG_DEBUG_TCG)
    int used;
#endif
} TCGOpDef;

TCGOpDef tcg_op_defs[] = {
#define DEF(s, oargs, iargs, cargs, flags) \
           { #s, oargs, iargs, cargs, iargs + oargs + cargs, flags },
#include "tcg-opc.h"
#undef DEF
};
const size_t tcg_op_defs_max = ARRAY_SIZE(tcg_op_defs);

#define tcg_abort() \
do {\
    fprintf(stderr, "%s:%d: tcg fatal error\n", __FILE__, __LINE__);\
    abort();\
} while (0)

typedef struct TCGTargetOpDef {
    TCGOpcode op;
    const char *args_ct_str[TCG_MAX_OP_ARGS];
} TCGTargetOpDef;

static inline TCGv_ptr TCGV_NAT_TO_PTR(TCGv_i64 n) { return (TCGv_ptr)n; }

#define tcg_temp_new_ptr() TCGV_NAT_TO_PTR(tcg_temp_new_i64())

#define tcg_temp_free_ptr(T) tcg_temp_free_i64(TCGV_PTR_TO_NAT(T))

static inline TCGv_i64 TCGV_PTR_TO_NAT(TCGv_ptr n) { return (TCGv_i64)n; }

void tcg_gen_callN(void *func, TCGTemp *ret, int nargs, TCGTemp **args);

TCGv_i32 tcg_const_i32(int32_t val);

TCGv_i64 tcg_const_i64(int64_t val);

TCGLabel *gen_new_label(void);

static inline TCGArg label_arg(TCGLabel *l)
{
    return (uintptr_t)l;
}

typedef uint32_t TCGMemOpIdx;

static inline TCGMemOpIdx make_memop_idx(TCGMemOp op, unsigned idx)
{
    tcg_debug_assert(idx <= 15);
    return (op << 4) | idx;
}

#define HELPER(name) glue(helper_, name)

#define dh_alias_i32 i32

#define dh_alias_s32 i32

#define dh_alias_int i32

#define dh_alias_i64 i64

#define dh_alias_s64 i64

#define dh_alias_ptr ptr

#define dh_alias_void void

#define dh_alias_noreturn noreturn

#define dh_alias(t) glue(dh_alias_, t)

#define dh_ctype_i32 uint32_t

#define dh_ctype_s32 int32_t

#define dh_ctype_int int

#define dh_ctype_i64 uint64_t

#define dh_ctype_s64 int64_t

#define dh_ctype_ptr void *

#define dh_ctype_void void

#define dh_ctype_noreturn void QEMU_NORETURN

#define dh_ctype(t) dh_ctype_##t

#   define dh_alias_tl i64

# define dh_alias_env ptr

# define dh_ctype_tl target_ulong

# define dh_ctype_env CPUArchState *

#define dh_retvar_decl_void

#define dh_retvar_decl_noreturn

#define dh_retvar_decl_i32 TCGv_i32 retval,

#define dh_retvar_decl_i64 TCGv_i64 retval,

#define dh_retvar_decl_ptr TCGv_ptr retval,

#define dh_retvar_decl(t) glue(dh_retvar_decl_, dh_alias(t))

#define dh_retvar_void NULL

#define dh_retvar_noreturn NULL

#define dh_retvar_i32 tcgv_i32_temp(retval)

#define dh_retvar_i64 tcgv_i64_temp(retval)

#define dh_retvar_ptr tcgv_ptr_temp(retval)

#define dh_retvar(t) glue(dh_retvar_, dh_alias(t))

#define dh_arg(t, n) \
  glue(glue(tcgv_, dh_alias(t)), _temp)(glue(arg, n))

#define dh_arg_decl(t, n) glue(TCGv_, dh_alias(t)) glue(arg, n)

#define DEF_HELPER_1(name, ret, t1) \
    DEF_HELPER_FLAGS_1(name, 0, ret, t1)

#define DEF_HELPER_2(name, ret, t1, t2) \
    DEF_HELPER_FLAGS_2(name, 0, ret, t1, t2)

#define DEF_HELPER_3(name, ret, t1, t2, t3) \
    DEF_HELPER_FLAGS_3(name, 0, ret, t1, t2, t3)

#define DEF_HELPER_4(name, ret, t1, t2, t3, t4) \
    DEF_HELPER_FLAGS_4(name, 0, ret, t1, t2, t3, t4)

#define DEF_HELPER_5(name, ret, t1, t2, t3, t4, t5) \
    DEF_HELPER_FLAGS_5(name, 0, ret, t1, t2, t3, t4, t5)

#define DEF_HELPER_FLAGS_1(name, flags, ret, t1) \
dh_ctype(ret) HELPER(name) (dh_ctype(t1));

#define DEF_HELPER_FLAGS_2(name, flags, ret, t1, t2) \
dh_ctype(ret) HELPER(name) (dh_ctype(t1), dh_ctype(t2));

#define DEF_HELPER_FLAGS_3(name, flags, ret, t1, t2, t3) \
dh_ctype(ret) HELPER(name) (dh_ctype(t1), dh_ctype(t2), dh_ctype(t3));

#define DEF_HELPER_FLAGS_4(name, flags, ret, t1, t2, t3, t4) \
dh_ctype(ret) HELPER(name) (dh_ctype(t1), dh_ctype(t2), dh_ctype(t3), \
                                   dh_ctype(t4));

#define DEF_HELPER_FLAGS_5(name, flags, ret, t1, t2, t3, t4, t5) \
dh_ctype(ret) HELPER(name) (dh_ctype(t1), dh_ctype(t2), dh_ctype(t3), \
                            dh_ctype(t4), dh_ctype(t5));

DEF_HELPER_FLAGS_4(cc_compute_all, TCG_CALL_NO_RWG_SE, tl, tl, tl, tl, int)

DEF_HELPER_FLAGS_4(cc_compute_c, TCG_CALL_NO_RWG_SE, tl, tl, tl, tl, int)

DEF_HELPER_3(write_eflags, void, env, tl, i32)

DEF_HELPER_1(read_eflags, tl, env)

DEF_HELPER_2(divb_AL, void, env, tl)

DEF_HELPER_2(idivb_AL, void, env, tl)

DEF_HELPER_2(divw_AX, void, env, tl)

DEF_HELPER_2(idivw_AX, void, env, tl)

DEF_HELPER_2(divl_EAX, void, env, tl)

DEF_HELPER_2(idivl_EAX, void, env, tl)

DEF_HELPER_2(divq_EAX, void, env, tl)

DEF_HELPER_2(idivq_EAX, void, env, tl)

DEF_HELPER_FLAGS_2(cr4_testbit, TCG_CALL_NO_WG, void, env, i32)

DEF_HELPER_FLAGS_2(bndck, TCG_CALL_NO_WG, void, env, i32)

DEF_HELPER_FLAGS_3(bndldx32, TCG_CALL_NO_WG, i64, env, tl, tl)

DEF_HELPER_FLAGS_3(bndldx64, TCG_CALL_NO_WG, i64, env, tl, tl)

DEF_HELPER_FLAGS_5(bndstx32, TCG_CALL_NO_WG, void, env, tl, tl, i64, i64)

DEF_HELPER_FLAGS_5(bndstx64, TCG_CALL_NO_WG, void, env, tl, tl, i64, i64)

DEF_HELPER_1(bnd_jmp, void, env)

DEF_HELPER_2(aam, void, env, int)

DEF_HELPER_2(aad, void, env, int)

DEF_HELPER_1(aaa, void, env)

DEF_HELPER_1(aas, void, env)

DEF_HELPER_1(daa, void, env)

DEF_HELPER_1(das, void, env)

DEF_HELPER_2(lsl, tl, env, tl)

DEF_HELPER_2(lar, tl, env, tl)

DEF_HELPER_2(verr, void, env, tl)

DEF_HELPER_2(verw, void, env, tl)

DEF_HELPER_2(lldt, void, env, int)

DEF_HELPER_2(ltr, void, env, int)

DEF_HELPER_3(load_seg, void, env, int, int)

DEF_HELPER_4(ljmp_protected, void, env, int, tl, tl)

DEF_HELPER_5(lcall_real, void, env, int, tl, int, int)

DEF_HELPER_5(lcall_protected, void, env, int, tl, int, tl)

DEF_HELPER_2(iret_real, void, env, int)

DEF_HELPER_3(iret_protected, void, env, int, int)

DEF_HELPER_3(lret_protected, void, env, int, int)

DEF_HELPER_2(read_crN, tl, env, int)

DEF_HELPER_3(write_crN, void, env, int, tl)

DEF_HELPER_2(lmsw, void, env, tl)

DEF_HELPER_1(clts, void, env)

DEF_HELPER_FLAGS_3(set_dr, TCG_CALL_NO_WG, void, env, int, tl)

DEF_HELPER_FLAGS_2(get_dr, TCG_CALL_NO_WG, tl, env, int)

DEF_HELPER_2(invlpg, void, env, tl)

DEF_HELPER_1(sysenter, void, env)

DEF_HELPER_2(sysexit, void, env, int)

DEF_HELPER_2(syscall, void, env, int)

DEF_HELPER_2(sysret, void, env, int)

DEF_HELPER_2(hlt, void, env, int)

DEF_HELPER_2(monitor, void, env, tl)

DEF_HELPER_2(mwait, void, env, int)

DEF_HELPER_2(pause, void, env, int)

DEF_HELPER_1(debug, void, env)

DEF_HELPER_1(reset_rf, void, env)

DEF_HELPER_3(raise_interrupt, void, env, int, int)

DEF_HELPER_2(raise_exception, void, env, int)

DEF_HELPER_1(cli, void, env)

DEF_HELPER_1(sti, void, env)

DEF_HELPER_1(clac, void, env)

DEF_HELPER_1(stac, void, env)

DEF_HELPER_3(boundw, void, env, tl, int)

DEF_HELPER_3(boundl, void, env, tl, int)

DEF_HELPER_1(rsm, void, env)

DEF_HELPER_2(into, void, env, int)

DEF_HELPER_2(cmpxchg8b_unlocked, void, env, tl)

DEF_HELPER_2(cmpxchg8b, void, env, tl)

DEF_HELPER_2(cmpxchg16b_unlocked, void, env, tl)

DEF_HELPER_2(cmpxchg16b, void, env, tl)

DEF_HELPER_1(single_step, void, env)

DEF_HELPER_1(rechecking_single_step, void, env)

DEF_HELPER_1(cpuid, void, env)

DEF_HELPER_1(rdtsc, void, env)

DEF_HELPER_1(rdtscp, void, env)

DEF_HELPER_1(rdpmc, void, env)

DEF_HELPER_1(rdmsr, void, env)

DEF_HELPER_1(wrmsr, void, env)

DEF_HELPER_2(check_iob, void, env, i32)

DEF_HELPER_2(check_iow, void, env, i32)

DEF_HELPER_2(check_iol, void, env, i32)

DEF_HELPER_3(outb, void, env, i32, i32)

DEF_HELPER_2(inb, tl, env, i32)

DEF_HELPER_3(outw, void, env, i32, i32)

DEF_HELPER_2(inw, tl, env, i32)

DEF_HELPER_3(outl, void, env, i32, i32)

DEF_HELPER_2(inl, tl, env, i32)

DEF_HELPER_FLAGS_4(bpt_io, TCG_CALL_NO_WG, void, env, i32, i32, tl)

DEF_HELPER_3(svm_check_intercept_param, void, env, i32, i64)

DEF_HELPER_4(svm_check_io, void, env, i32, i32, i32)

DEF_HELPER_3(vmrun, void, env, int, int)

DEF_HELPER_1(vmmcall, void, env)

DEF_HELPER_2(vmload, void, env, int)

DEF_HELPER_2(vmsave, void, env, int)

DEF_HELPER_1(stgi, void, env)

DEF_HELPER_1(clgi, void, env)

DEF_HELPER_1(skinit, void, env)

DEF_HELPER_2(invlpga, void, env, int)

DEF_HELPER_2(flds_FT0, void, env, i32)

DEF_HELPER_2(fldl_FT0, void, env, i64)

DEF_HELPER_2(fildl_FT0, void, env, s32)

DEF_HELPER_2(flds_ST0, void, env, i32)

DEF_HELPER_2(fldl_ST0, void, env, i64)

DEF_HELPER_2(fildl_ST0, void, env, s32)

DEF_HELPER_2(fildll_ST0, void, env, s64)

DEF_HELPER_1(fsts_ST0, i32, env)

DEF_HELPER_1(fstl_ST0, i64, env)

DEF_HELPER_1(fist_ST0, s32, env)

DEF_HELPER_1(fistl_ST0, s32, env)

DEF_HELPER_1(fistll_ST0, s64, env)

DEF_HELPER_1(fistt_ST0, s32, env)

DEF_HELPER_1(fisttl_ST0, s32, env)

DEF_HELPER_1(fisttll_ST0, s64, env)

DEF_HELPER_2(fldt_ST0, void, env, tl)

DEF_HELPER_2(fstt_ST0, void, env, tl)

DEF_HELPER_1(fpush, void, env)

DEF_HELPER_1(fpop, void, env)

DEF_HELPER_1(fdecstp, void, env)

DEF_HELPER_1(fincstp, void, env)

DEF_HELPER_2(ffree_STN, void, env, int)

DEF_HELPER_2(fmov_FT0_STN, void, env, int)

DEF_HELPER_2(fmov_ST0_STN, void, env, int)

DEF_HELPER_2(fmov_STN_ST0, void, env, int)

DEF_HELPER_2(fxchg_ST0_STN, void, env, int)

DEF_HELPER_1(fcom_ST0_FT0, void, env)

DEF_HELPER_1(fucom_ST0_FT0, void, env)

DEF_HELPER_1(fcomi_ST0_FT0, void, env)

DEF_HELPER_1(fucomi_ST0_FT0, void, env)

DEF_HELPER_1(fadd_ST0_FT0, void, env)

DEF_HELPER_1(fmul_ST0_FT0, void, env)

DEF_HELPER_1(fsub_ST0_FT0, void, env)

DEF_HELPER_1(fsubr_ST0_FT0, void, env)

DEF_HELPER_1(fdiv_ST0_FT0, void, env)

DEF_HELPER_1(fdivr_ST0_FT0, void, env)

DEF_HELPER_2(fadd_STN_ST0, void, env, int)

DEF_HELPER_2(fmul_STN_ST0, void, env, int)

DEF_HELPER_2(fsub_STN_ST0, void, env, int)

DEF_HELPER_2(fsubr_STN_ST0, void, env, int)

DEF_HELPER_2(fdiv_STN_ST0, void, env, int)

DEF_HELPER_2(fdivr_STN_ST0, void, env, int)

DEF_HELPER_1(fchs_ST0, void, env)

DEF_HELPER_1(fabs_ST0, void, env)

DEF_HELPER_1(fxam_ST0, void, env)

DEF_HELPER_1(fld1_ST0, void, env)

DEF_HELPER_1(fldl2t_ST0, void, env)

DEF_HELPER_1(fldl2e_ST0, void, env)

DEF_HELPER_1(fldpi_ST0, void, env)

DEF_HELPER_1(fldlg2_ST0, void, env)

DEF_HELPER_1(fldln2_ST0, void, env)

DEF_HELPER_1(fldz_ST0, void, env)

DEF_HELPER_1(fldz_FT0, void, env)

DEF_HELPER_1(fnstsw, i32, env)

DEF_HELPER_1(fnstcw, i32, env)

DEF_HELPER_2(fldcw, void, env, i32)

DEF_HELPER_1(fclex, void, env)

DEF_HELPER_1(fwait, void, env)

DEF_HELPER_1(fninit, void, env)

DEF_HELPER_2(fbld_ST0, void, env, tl)

DEF_HELPER_2(fbst_ST0, void, env, tl)

DEF_HELPER_1(f2xm1, void, env)

DEF_HELPER_1(fyl2x, void, env)

DEF_HELPER_1(fptan, void, env)

DEF_HELPER_1(fpatan, void, env)

DEF_HELPER_1(fxtract, void, env)

DEF_HELPER_1(fprem1, void, env)

DEF_HELPER_1(fprem, void, env)

DEF_HELPER_1(fyl2xp1, void, env)

DEF_HELPER_1(fsqrt, void, env)

DEF_HELPER_1(fsincos, void, env)

DEF_HELPER_1(frndint, void, env)

DEF_HELPER_1(fscale, void, env)

DEF_HELPER_1(fsin, void, env)

DEF_HELPER_1(fcos, void, env)

DEF_HELPER_3(fstenv, void, env, tl, int)

DEF_HELPER_3(fldenv, void, env, tl, int)

DEF_HELPER_3(fsave, void, env, tl, int)

DEF_HELPER_3(frstor, void, env, tl, int)

DEF_HELPER_FLAGS_2(fxsave, TCG_CALL_NO_WG, void, env, tl)

DEF_HELPER_FLAGS_2(fxrstor, TCG_CALL_NO_WG, void, env, tl)

DEF_HELPER_FLAGS_3(xsave, TCG_CALL_NO_WG, void, env, tl, i64)

DEF_HELPER_FLAGS_3(xsaveopt, TCG_CALL_NO_WG, void, env, tl, i64)

DEF_HELPER_FLAGS_3(xrstor, TCG_CALL_NO_WG, void, env, tl, i64)

DEF_HELPER_FLAGS_2(xgetbv, TCG_CALL_NO_WG, i64, env, i32)

DEF_HELPER_FLAGS_3(xsetbv, TCG_CALL_NO_WG, void, env, i32, i64)

DEF_HELPER_FLAGS_2(rdpkru, TCG_CALL_NO_WG, i64, env, i32)

DEF_HELPER_FLAGS_3(wrpkru, TCG_CALL_NO_WG, void, env, i32, i64)

DEF_HELPER_FLAGS_2(pdep, TCG_CALL_NO_RWG_SE, tl, tl, tl)

DEF_HELPER_FLAGS_2(pext, TCG_CALL_NO_RWG_SE, tl, tl, tl)

DEF_HELPER_2(ldmxcsr, void, env, i32)

DEF_HELPER_1(enter_mmx, void, env)

DEF_HELPER_1(emms, void, env)

DEF_HELPER_3(movq, void, env, ptr, ptr)

#define Reg MMXReg

#define SUFFIX _mmx

#define dh_ctype_MMXReg MMXReg *

DEF_HELPER_3(glue(psrlw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psraw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psllw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psrld, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psrad, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pslld, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psrlq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psllq, SUFFIX), void, env, Reg, Reg)

#define SSE_HELPER_B(name, F)\
    DEF_HELPER_3(glue(name, SUFFIX), void, env, Reg, Reg)

#define SSE_HELPER_W(name, F)\
    DEF_HELPER_3(glue(name, SUFFIX), void, env, Reg, Reg)

#define SSE_HELPER_L(name, F)\
    DEF_HELPER_3(glue(name, SUFFIX), void, env, Reg, Reg)

#define SSE_HELPER_Q(name, F)\
    DEF_HELPER_3(glue(name, SUFFIX), void, env, Reg, Reg)

SSE_HELPER_B(paddb, FADD)

SSE_HELPER_W(paddw, FADD)

SSE_HELPER_L(paddl, FADD)

SSE_HELPER_Q(paddq, FADD)

SSE_HELPER_B(psubb, FSUB)

SSE_HELPER_W(psubw, FSUB)

SSE_HELPER_L(psubl, FSUB)

SSE_HELPER_Q(psubq, FSUB)

SSE_HELPER_B(paddusb, FADDUB)

SSE_HELPER_B(paddsb, FADDSB)

SSE_HELPER_B(psubusb, FSUBUB)

SSE_HELPER_B(psubsb, FSUBSB)

SSE_HELPER_W(paddusw, FADDUW)

SSE_HELPER_W(paddsw, FADDSW)

SSE_HELPER_W(psubusw, FSUBUW)

SSE_HELPER_W(psubsw, FSUBSW)

SSE_HELPER_B(pminub, FMINUB)

SSE_HELPER_B(pmaxub, FMAXUB)

SSE_HELPER_W(pminsw, FMINSW)

SSE_HELPER_W(pmaxsw, FMAXSW)

SSE_HELPER_Q(pand, FAND)

SSE_HELPER_Q(pandn, FANDN)

SSE_HELPER_Q(por, FOR)

SSE_HELPER_Q(pxor, FXOR)

SSE_HELPER_B(pcmpgtb, FCMPGTB)

SSE_HELPER_W(pcmpgtw, FCMPGTW)

SSE_HELPER_L(pcmpgtl, FCMPGTL)

SSE_HELPER_B(pcmpeqb, FCMPEQ)

SSE_HELPER_W(pcmpeqw, FCMPEQ)

SSE_HELPER_L(pcmpeql, FCMPEQ)

SSE_HELPER_W(pmullw, FMULLW)

SSE_HELPER_W(pmulhrw, FMULHRW)

SSE_HELPER_W(pmulhuw, FMULHUW)

SSE_HELPER_W(pmulhw, FMULHW)

SSE_HELPER_B(pavgb, FAVG)

SSE_HELPER_W(pavgw, FAVG)

DEF_HELPER_3(glue(pmuludq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmaddwd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psadbw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_4(glue(maskmov, SUFFIX), void, env, Reg, Reg, tl)

DEF_HELPER_2(glue(movl_mm_T0, SUFFIX), void, Reg, i32)

DEF_HELPER_3(glue(pshufw, SUFFIX), void, Reg, Reg, int)

DEF_HELPER_2(glue(pmovmskb, SUFFIX), i32, env, Reg)

DEF_HELPER_3(glue(packsswb, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(packuswb, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(packssdw, SUFFIX), void, env, Reg, Reg)

#define UNPCK_OP(base_name, base)                                       \
    DEF_HELPER_3(glue(punpck ## base_name ## bw, SUFFIX), void, env, Reg, Reg) \
    DEF_HELPER_3(glue(punpck ## base_name ## wd, SUFFIX), void, env, Reg, Reg) \
    DEF_HELPER_3(glue(punpck ## base_name ## dq, SUFFIX), void, env, Reg, Reg)

UNPCK_OP(l, 0)

UNPCK_OP(h, 1)

DEF_HELPER_3(pi2fd, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pi2fw, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pf2id, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pf2iw, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pfacc, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pfadd, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pfcmpeq, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pfcmpge, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pfcmpgt, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pfmax, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pfmin, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pfmul, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pfnacc, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pfpnacc, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pfrcp, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pfrsqrt, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pfsub, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pfsubr, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pswapd, void, env, MMXReg, MMXReg)

DEF_HELPER_3(glue(phaddw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(phaddd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(phaddsw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(phsubw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(phsubd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(phsubsw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pabsb, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pabsw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pabsd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmaddubsw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmulhrsw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pshufb, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psignb, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psignw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psignd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_4(glue(palignr, SUFFIX), void, env, Reg, Reg, s32)

#define Reg ZMMReg

#define SUFFIX _xmm

#define dh_ctype_ZMMReg ZMMReg *

#define dh_ctype_MMXReg MMXReg *

DEF_HELPER_3(glue(psrlw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psraw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psllw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psrld, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psrad, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pslld, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psrlq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psllq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psrldq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pslldq, SUFFIX), void, env, Reg, Reg)

#define SSE_HELPER_B(name, F)\
    DEF_HELPER_3(glue(name, SUFFIX), void, env, Reg, Reg)

#define SSE_HELPER_W(name, F)\
    DEF_HELPER_3(glue(name, SUFFIX), void, env, Reg, Reg)

#define SSE_HELPER_L(name, F)\
    DEF_HELPER_3(glue(name, SUFFIX), void, env, Reg, Reg)

#define SSE_HELPER_Q(name, F)\
    DEF_HELPER_3(glue(name, SUFFIX), void, env, Reg, Reg)

SSE_HELPER_B(paddb, FADD)

SSE_HELPER_W(paddw, FADD)

SSE_HELPER_L(paddl, FADD)

SSE_HELPER_Q(paddq, FADD)

SSE_HELPER_B(psubb, FSUB)

SSE_HELPER_W(psubw, FSUB)

SSE_HELPER_L(psubl, FSUB)

SSE_HELPER_Q(psubq, FSUB)

SSE_HELPER_B(paddusb, FADDUB)

SSE_HELPER_B(paddsb, FADDSB)

SSE_HELPER_B(psubusb, FSUBUB)

SSE_HELPER_B(psubsb, FSUBSB)

SSE_HELPER_W(paddusw, FADDUW)

SSE_HELPER_W(paddsw, FADDSW)

SSE_HELPER_W(psubusw, FSUBUW)

SSE_HELPER_W(psubsw, FSUBSW)

SSE_HELPER_B(pminub, FMINUB)

SSE_HELPER_B(pmaxub, FMAXUB)

SSE_HELPER_W(pminsw, FMINSW)

SSE_HELPER_W(pmaxsw, FMAXSW)

SSE_HELPER_Q(pand, FAND)

SSE_HELPER_Q(pandn, FANDN)

SSE_HELPER_Q(por, FOR)

SSE_HELPER_Q(pxor, FXOR)

SSE_HELPER_B(pcmpgtb, FCMPGTB)

SSE_HELPER_W(pcmpgtw, FCMPGTW)

SSE_HELPER_L(pcmpgtl, FCMPGTL)

SSE_HELPER_B(pcmpeqb, FCMPEQ)

SSE_HELPER_W(pcmpeqw, FCMPEQ)

SSE_HELPER_L(pcmpeql, FCMPEQ)

SSE_HELPER_W(pmullw, FMULLW)

SSE_HELPER_W(pmulhuw, FMULHUW)

SSE_HELPER_W(pmulhw, FMULHW)

SSE_HELPER_B(pavgb, FAVG)

SSE_HELPER_W(pavgw, FAVG)

DEF_HELPER_3(glue(pmuludq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmaddwd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psadbw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_4(glue(maskmov, SUFFIX), void, env, Reg, Reg, tl)

DEF_HELPER_2(glue(movl_mm_T0, SUFFIX), void, Reg, i32)

DEF_HELPER_2(glue(movq_mm_T0, SUFFIX), void, Reg, i64)

DEF_HELPER_3(shufps, void, Reg, Reg, int)

DEF_HELPER_3(shufpd, void, Reg, Reg, int)

DEF_HELPER_3(glue(pshufd, SUFFIX), void, Reg, Reg, int)

DEF_HELPER_3(glue(pshuflw, SUFFIX), void, Reg, Reg, int)

DEF_HELPER_3(glue(pshufhw, SUFFIX), void, Reg, Reg, int)

#define SSE_HELPER_S(name, F)                            \
    DEF_HELPER_3(name ## ps, void, env, Reg, Reg)        \
    DEF_HELPER_3(name ## ss, void, env, Reg, Reg)        \
    DEF_HELPER_3(name ## pd, void, env, Reg, Reg)        \
    DEF_HELPER_3(name ## sd, void, env, Reg, Reg)

SSE_HELPER_S(add, FPU_ADD)

SSE_HELPER_S(sub, FPU_SUB)

SSE_HELPER_S(mul, FPU_MUL)

SSE_HELPER_S(div, FPU_DIV)

SSE_HELPER_S(min, FPU_MIN)

SSE_HELPER_S(max, FPU_MAX)

SSE_HELPER_S(sqrt, FPU_SQRT)

DEF_HELPER_3(cvtps2pd, void, env, Reg, Reg)

DEF_HELPER_3(cvtpd2ps, void, env, Reg, Reg)

DEF_HELPER_3(cvtss2sd, void, env, Reg, Reg)

DEF_HELPER_3(cvtsd2ss, void, env, Reg, Reg)

DEF_HELPER_3(cvtdq2ps, void, env, Reg, Reg)

DEF_HELPER_3(cvtdq2pd, void, env, Reg, Reg)

DEF_HELPER_3(cvtpi2ps, void, env, ZMMReg, MMXReg)

DEF_HELPER_3(cvtpi2pd, void, env, ZMMReg, MMXReg)

DEF_HELPER_3(cvtsi2ss, void, env, ZMMReg, i32)

DEF_HELPER_3(cvtsi2sd, void, env, ZMMReg, i32)

DEF_HELPER_3(cvtsq2ss, void, env, ZMMReg, i64)

DEF_HELPER_3(cvtsq2sd, void, env, ZMMReg, i64)

DEF_HELPER_3(cvtps2dq, void, env, ZMMReg, ZMMReg)

DEF_HELPER_3(cvtpd2dq, void, env, ZMMReg, ZMMReg)

DEF_HELPER_3(cvtps2pi, void, env, MMXReg, ZMMReg)

DEF_HELPER_3(cvtpd2pi, void, env, MMXReg, ZMMReg)

DEF_HELPER_2(cvtss2si, s32, env, ZMMReg)

DEF_HELPER_2(cvtsd2si, s32, env, ZMMReg)

DEF_HELPER_2(cvtss2sq, s64, env, ZMMReg)

DEF_HELPER_2(cvtsd2sq, s64, env, ZMMReg)

DEF_HELPER_3(cvttps2dq, void, env, ZMMReg, ZMMReg)

DEF_HELPER_3(cvttpd2dq, void, env, ZMMReg, ZMMReg)

DEF_HELPER_3(cvttps2pi, void, env, MMXReg, ZMMReg)

DEF_HELPER_3(cvttpd2pi, void, env, MMXReg, ZMMReg)

DEF_HELPER_2(cvttss2si, s32, env, ZMMReg)

DEF_HELPER_2(cvttsd2si, s32, env, ZMMReg)

DEF_HELPER_2(cvttss2sq, s64, env, ZMMReg)

DEF_HELPER_2(cvttsd2sq, s64, env, ZMMReg)

DEF_HELPER_3(rsqrtps, void, env, ZMMReg, ZMMReg)

DEF_HELPER_3(rsqrtss, void, env, ZMMReg, ZMMReg)

DEF_HELPER_3(rcpps, void, env, ZMMReg, ZMMReg)

DEF_HELPER_3(rcpss, void, env, ZMMReg, ZMMReg)

DEF_HELPER_3(extrq_r, void, env, ZMMReg, ZMMReg)

DEF_HELPER_4(extrq_i, void, env, ZMMReg, int, int)

DEF_HELPER_3(insertq_r, void, env, ZMMReg, ZMMReg)

DEF_HELPER_4(insertq_i, void, env, ZMMReg, int, int)

DEF_HELPER_3(haddps, void, env, ZMMReg, ZMMReg)

DEF_HELPER_3(haddpd, void, env, ZMMReg, ZMMReg)

DEF_HELPER_3(hsubps, void, env, ZMMReg, ZMMReg)

DEF_HELPER_3(hsubpd, void, env, ZMMReg, ZMMReg)

DEF_HELPER_3(addsubps, void, env, ZMMReg, ZMMReg)

DEF_HELPER_3(addsubpd, void, env, ZMMReg, ZMMReg)

#define SSE_HELPER_CMP(name, F)                           \
    DEF_HELPER_3(name ## ps, void, env, Reg, Reg)         \
    DEF_HELPER_3(name ## ss, void, env, Reg, Reg)         \
    DEF_HELPER_3(name ## pd, void, env, Reg, Reg)         \
    DEF_HELPER_3(name ## sd, void, env, Reg, Reg)

SSE_HELPER_CMP(cmpeq, FPU_CMPEQ)

SSE_HELPER_CMP(cmplt, FPU_CMPLT)

SSE_HELPER_CMP(cmple, FPU_CMPLE)

SSE_HELPER_CMP(cmpunord, FPU_CMPUNORD)

SSE_HELPER_CMP(cmpneq, FPU_CMPNEQ)

SSE_HELPER_CMP(cmpnlt, FPU_CMPNLT)

SSE_HELPER_CMP(cmpnle, FPU_CMPNLE)

SSE_HELPER_CMP(cmpord, FPU_CMPORD)

DEF_HELPER_3(ucomiss, void, env, Reg, Reg)

DEF_HELPER_3(comiss, void, env, Reg, Reg)

DEF_HELPER_3(ucomisd, void, env, Reg, Reg)

DEF_HELPER_3(comisd, void, env, Reg, Reg)

DEF_HELPER_2(movmskps, i32, env, Reg)

DEF_HELPER_2(movmskpd, i32, env, Reg)

DEF_HELPER_2(glue(pmovmskb, SUFFIX), i32, env, Reg)

DEF_HELPER_3(glue(packsswb, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(packuswb, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(packssdw, SUFFIX), void, env, Reg, Reg)

#define UNPCK_OP(base_name, base)                                       \
    DEF_HELPER_3(glue(punpck ## base_name ## bw, SUFFIX), void, env, Reg, Reg) \
    DEF_HELPER_3(glue(punpck ## base_name ## wd, SUFFIX), void, env, Reg, Reg) \
    DEF_HELPER_3(glue(punpck ## base_name ## dq, SUFFIX), void, env, Reg, Reg)

UNPCK_OP(l, 0)

UNPCK_OP(h, 1)

DEF_HELPER_3(glue(punpcklqdq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(punpckhqdq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(phaddw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(phaddd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(phaddsw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(phsubw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(phsubd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(phsubsw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pabsb, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pabsw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pabsd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmaddubsw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmulhrsw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pshufb, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psignb, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psignw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psignd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_4(glue(palignr, SUFFIX), void, env, Reg, Reg, s32)

DEF_HELPER_3(glue(pblendvb, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(blendvps, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(blendvpd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(ptest, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmovsxbw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmovsxbd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmovsxbq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmovsxwd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmovsxwq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmovsxdq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmovzxbw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmovzxbd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmovzxbq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmovzxwd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmovzxwq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmovzxdq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmuldq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pcmpeqq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(packusdw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pminsb, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pminsd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pminuw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pminud, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmaxsb, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmaxsd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmaxuw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmaxud, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmulld, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(phminposuw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_4(glue(roundps, SUFFIX), void, env, Reg, Reg, i32)

DEF_HELPER_4(glue(roundpd, SUFFIX), void, env, Reg, Reg, i32)

DEF_HELPER_4(glue(roundss, SUFFIX), void, env, Reg, Reg, i32)

DEF_HELPER_4(glue(roundsd, SUFFIX), void, env, Reg, Reg, i32)

DEF_HELPER_4(glue(blendps, SUFFIX), void, env, Reg, Reg, i32)

DEF_HELPER_4(glue(blendpd, SUFFIX), void, env, Reg, Reg, i32)

DEF_HELPER_4(glue(pblendw, SUFFIX), void, env, Reg, Reg, i32)

DEF_HELPER_4(glue(dpps, SUFFIX), void, env, Reg, Reg, i32)

DEF_HELPER_4(glue(dppd, SUFFIX), void, env, Reg, Reg, i32)

DEF_HELPER_4(glue(mpsadbw, SUFFIX), void, env, Reg, Reg, i32)

DEF_HELPER_3(glue(pcmpgtq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_4(glue(pcmpestri, SUFFIX), void, env, Reg, Reg, i32)

DEF_HELPER_4(glue(pcmpestrm, SUFFIX), void, env, Reg, Reg, i32)

DEF_HELPER_4(glue(pcmpistri, SUFFIX), void, env, Reg, Reg, i32)

DEF_HELPER_4(glue(pcmpistrm, SUFFIX), void, env, Reg, Reg, i32)

DEF_HELPER_3(crc32, tl, i32, tl, i32)

DEF_HELPER_3(glue(aesdec, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(aesdeclast, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(aesenc, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(aesenclast, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(aesimc, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_4(glue(aeskeygenassist, SUFFIX), void, env, Reg, Reg, i32)

DEF_HELPER_4(glue(pclmulqdq, SUFFIX), void, env, Reg, Reg, i32)

DEF_HELPER_3(rclb, tl, env, tl, tl)

DEF_HELPER_3(rclw, tl, env, tl, tl)

DEF_HELPER_3(rcll, tl, env, tl, tl)

DEF_HELPER_3(rcrb, tl, env, tl, tl)

DEF_HELPER_3(rcrw, tl, env, tl, tl)

DEF_HELPER_3(rcrl, tl, env, tl, tl)

DEF_HELPER_3(rclq, tl, env, tl, tl)

DEF_HELPER_3(rcrq, tl, env, tl, tl)

DEF_HELPER_FLAGS_3(trace_guest_mem_before_exec_proxy, TCG_CALL_NO_RWG, void, env, tl, i32)

DEF_HELPER_FLAGS_2(mulsh_i64, TCG_CALL_NO_RWG_SE, s64, s64, s64)

DEF_HELPER_FLAGS_2(muluh_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64)

DEF_HELPER_FLAGS_2(clz_i32, TCG_CALL_NO_RWG_SE, i32, i32, i32)

DEF_HELPER_FLAGS_2(ctz_i32, TCG_CALL_NO_RWG_SE, i32, i32, i32)

DEF_HELPER_FLAGS_2(clz_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64)

DEF_HELPER_FLAGS_2(ctz_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64)

DEF_HELPER_FLAGS_1(ctpop_i32, TCG_CALL_NO_RWG_SE, i32, i32)

DEF_HELPER_FLAGS_1(ctpop_i64, TCG_CALL_NO_RWG_SE, i64, i64)

DEF_HELPER_FLAGS_1(lookup_tb_ptr, TCG_CALL_NO_WG_SE, ptr, env)

DEF_HELPER_FLAGS_1(exit_atomic, TCG_CALL_NO_WG, noreturn, env)

DEF_HELPER_FLAGS_4(atomic_cmpxchgb, TCG_CALL_NO_WG, i32, env, tl, i32, i32)

DEF_HELPER_FLAGS_4(atomic_cmpxchgw_be, TCG_CALL_NO_WG, i32, env, tl, i32, i32)

DEF_HELPER_FLAGS_4(atomic_cmpxchgw_le, TCG_CALL_NO_WG, i32, env, tl, i32, i32)

DEF_HELPER_FLAGS_4(atomic_cmpxchgl_be, TCG_CALL_NO_WG, i32, env, tl, i32, i32)

DEF_HELPER_FLAGS_4(atomic_cmpxchgl_le, TCG_CALL_NO_WG, i32, env, tl, i32, i32)

#define GEN_ATOMIC_HELPERS(NAME)                             \
    DEF_HELPER_FLAGS_3(glue(glue(atomic_, NAME), b),         \
                       TCG_CALL_NO_WG, i32, env, tl, i32)    \
    DEF_HELPER_FLAGS_3(glue(glue(atomic_, NAME), w_le),      \
                       TCG_CALL_NO_WG, i32, env, tl, i32)    \
    DEF_HELPER_FLAGS_3(glue(glue(atomic_, NAME), w_be),      \
                       TCG_CALL_NO_WG, i32, env, tl, i32)    \
    DEF_HELPER_FLAGS_3(glue(glue(atomic_, NAME), l_le),      \
                       TCG_CALL_NO_WG, i32, env, tl, i32)    \
    DEF_HELPER_FLAGS_3(glue(glue(atomic_, NAME), l_be),      \
                       TCG_CALL_NO_WG, i32, env, tl, i32)

GEN_ATOMIC_HELPERS(fetch_add)

GEN_ATOMIC_HELPERS(fetch_and)

GEN_ATOMIC_HELPERS(fetch_or)

GEN_ATOMIC_HELPERS(fetch_xor)

GEN_ATOMIC_HELPERS(add_fetch)

GEN_ATOMIC_HELPERS(and_fetch)

GEN_ATOMIC_HELPERS(or_fetch)

GEN_ATOMIC_HELPERS(xor_fetch)

GEN_ATOMIC_HELPERS(xchg)

#define DEF_HELPER_FLAGS_1(name, flags, ret, t1)                        \
static inline void glue(gen_helper_, name)(dh_retvar_decl(ret)          \
    dh_arg_decl(t1, 1))                                                 \
{                                                                       \
  TCGTemp *args[1] = { dh_arg(t1, 1) };                                 \
  tcg_gen_callN((void*)HELPER(name), dh_retvar(ret), 1, args);          \
}

#define DEF_HELPER_FLAGS_2(name, flags, ret, t1, t2)                    \
static inline void glue(gen_helper_, name)(dh_retvar_decl(ret)          \
    dh_arg_decl(t1, 1), dh_arg_decl(t2, 2))                             \
{                                                                       \
  TCGTemp *args[2] = { dh_arg(t1, 1), dh_arg(t2, 2) };                  \
  tcg_gen_callN((void*)HELPER(name), dh_retvar(ret), 2, args);          \
}

#define DEF_HELPER_FLAGS_3(name, flags, ret, t1, t2, t3)                \
static inline void glue(gen_helper_, name)(dh_retvar_decl(ret)          \
    dh_arg_decl(t1, 1), dh_arg_decl(t2, 2), dh_arg_decl(t3, 3))         \
{                                                                       \
  TCGTemp *args[3] = { dh_arg(t1, 1), dh_arg(t2, 2), dh_arg(t3, 3) };   \
  tcg_gen_callN((void*)HELPER(name), dh_retvar(ret), 3, args);          \
}

#define DEF_HELPER_FLAGS_4(name, flags, ret, t1, t2, t3, t4)            \
static inline void glue(gen_helper_, name)(dh_retvar_decl(ret)          \
    dh_arg_decl(t1, 1), dh_arg_decl(t2, 2),                             \
    dh_arg_decl(t3, 3), dh_arg_decl(t4, 4))                             \
{                                                                       \
  TCGTemp *args[4] = { dh_arg(t1, 1), dh_arg(t2, 2),                    \
                     dh_arg(t3, 3), dh_arg(t4, 4) };                    \
  tcg_gen_callN((void*)HELPER(name), dh_retvar(ret), 4, args);          \
}

#define DEF_HELPER_FLAGS_5(name, flags, ret, t1, t2, t3, t4, t5)        \
static inline void glue(gen_helper_, name)(dh_retvar_decl(ret)          \
    dh_arg_decl(t1, 1),  dh_arg_decl(t2, 2), dh_arg_decl(t3, 3),        \
    dh_arg_decl(t4, 4), dh_arg_decl(t5, 5))                             \
{                                                                       \
  TCGTemp *args[5] = { dh_arg(t1, 1), dh_arg(t2, 2), dh_arg(t3, 3),     \
                     dh_arg(t4, 4), dh_arg(t5, 5) };                    \
  tcg_gen_callN((void*)HELPER(name), dh_retvar(ret), 5, args);          \
}

DEF_HELPER_FLAGS_4(cc_compute_all, TCG_CALL_NO_RWG_SE, tl, tl, tl, tl, int)

DEF_HELPER_FLAGS_4(cc_compute_c, TCG_CALL_NO_RWG_SE, tl, tl, tl, tl, int)

DEF_HELPER_3(write_eflags, void, env, tl, i32)

DEF_HELPER_1(read_eflags, tl, env)

DEF_HELPER_2(divb_AL, void, env, tl)

DEF_HELPER_2(idivb_AL, void, env, tl)

DEF_HELPER_2(divw_AX, void, env, tl)

DEF_HELPER_2(idivw_AX, void, env, tl)

DEF_HELPER_2(divl_EAX, void, env, tl)

DEF_HELPER_2(idivl_EAX, void, env, tl)

DEF_HELPER_2(divq_EAX, void, env, tl)

DEF_HELPER_2(idivq_EAX, void, env, tl)

DEF_HELPER_FLAGS_2(cr4_testbit, TCG_CALL_NO_WG, void, env, i32)

DEF_HELPER_FLAGS_2(bndck, TCG_CALL_NO_WG, void, env, i32)

DEF_HELPER_FLAGS_3(bndldx32, TCG_CALL_NO_WG, i64, env, tl, tl)

DEF_HELPER_FLAGS_3(bndldx64, TCG_CALL_NO_WG, i64, env, tl, tl)

DEF_HELPER_FLAGS_5(bndstx32, TCG_CALL_NO_WG, void, env, tl, tl, i64, i64)

DEF_HELPER_FLAGS_5(bndstx64, TCG_CALL_NO_WG, void, env, tl, tl, i64, i64)

DEF_HELPER_1(bnd_jmp, void, env)

DEF_HELPER_2(aam, void, env, int)

DEF_HELPER_2(aad, void, env, int)

DEF_HELPER_1(aaa, void, env)

DEF_HELPER_1(aas, void, env)

DEF_HELPER_1(daa, void, env)

DEF_HELPER_1(das, void, env)

DEF_HELPER_2(lsl, tl, env, tl)

DEF_HELPER_2(lar, tl, env, tl)

DEF_HELPER_2(verr, void, env, tl)

DEF_HELPER_2(verw, void, env, tl)

DEF_HELPER_2(lldt, void, env, int)

DEF_HELPER_2(ltr, void, env, int)

DEF_HELPER_3(load_seg, void, env, int, int)

DEF_HELPER_4(ljmp_protected, void, env, int, tl, tl)

DEF_HELPER_5(lcall_real, void, env, int, tl, int, int)

DEF_HELPER_5(lcall_protected, void, env, int, tl, int, tl)

DEF_HELPER_2(iret_real, void, env, int)

DEF_HELPER_3(iret_protected, void, env, int, int)

DEF_HELPER_3(lret_protected, void, env, int, int)

DEF_HELPER_2(read_crN, tl, env, int)

DEF_HELPER_3(write_crN, void, env, int, tl)

DEF_HELPER_2(lmsw, void, env, tl)

DEF_HELPER_1(clts, void, env)

DEF_HELPER_FLAGS_3(set_dr, TCG_CALL_NO_WG, void, env, int, tl)

DEF_HELPER_FLAGS_2(get_dr, TCG_CALL_NO_WG, tl, env, int)

DEF_HELPER_2(invlpg, void, env, tl)

DEF_HELPER_1(sysenter, void, env)

DEF_HELPER_2(sysexit, void, env, int)

DEF_HELPER_2(syscall, void, env, int)

DEF_HELPER_2(sysret, void, env, int)

DEF_HELPER_2(hlt, void, env, int)

DEF_HELPER_2(monitor, void, env, tl)

DEF_HELPER_2(mwait, void, env, int)

DEF_HELPER_2(pause, void, env, int)

DEF_HELPER_1(debug, void, env)

DEF_HELPER_1(reset_rf, void, env)

DEF_HELPER_3(raise_interrupt, void, env, int, int)

DEF_HELPER_2(raise_exception, void, env, int)

DEF_HELPER_1(cli, void, env)

DEF_HELPER_1(sti, void, env)

DEF_HELPER_1(clac, void, env)

DEF_HELPER_1(stac, void, env)

DEF_HELPER_3(boundw, void, env, tl, int)

DEF_HELPER_3(boundl, void, env, tl, int)

DEF_HELPER_1(rsm, void, env)

DEF_HELPER_2(into, void, env, int)

DEF_HELPER_2(cmpxchg8b_unlocked, void, env, tl)

DEF_HELPER_2(cmpxchg8b, void, env, tl)

DEF_HELPER_2(cmpxchg16b_unlocked, void, env, tl)

DEF_HELPER_2(cmpxchg16b, void, env, tl)

DEF_HELPER_1(single_step, void, env)

DEF_HELPER_1(rechecking_single_step, void, env)

DEF_HELPER_1(cpuid, void, env)

DEF_HELPER_1(rdtsc, void, env)

DEF_HELPER_1(rdtscp, void, env)

DEF_HELPER_1(rdpmc, void, env)

DEF_HELPER_1(rdmsr, void, env)

DEF_HELPER_1(wrmsr, void, env)

DEF_HELPER_2(check_iob, void, env, i32)

DEF_HELPER_2(check_iow, void, env, i32)

DEF_HELPER_2(check_iol, void, env, i32)

DEF_HELPER_3(outb, void, env, i32, i32)

DEF_HELPER_2(inb, tl, env, i32)

DEF_HELPER_3(outw, void, env, i32, i32)

DEF_HELPER_2(inw, tl, env, i32)

DEF_HELPER_3(outl, void, env, i32, i32)

DEF_HELPER_2(inl, tl, env, i32)

DEF_HELPER_FLAGS_4(bpt_io, TCG_CALL_NO_WG, void, env, i32, i32, tl)

DEF_HELPER_3(svm_check_intercept_param, void, env, i32, i64)

DEF_HELPER_4(svm_check_io, void, env, i32, i32, i32)

DEF_HELPER_3(vmrun, void, env, int, int)

DEF_HELPER_1(vmmcall, void, env)

DEF_HELPER_2(vmload, void, env, int)

DEF_HELPER_2(vmsave, void, env, int)

DEF_HELPER_1(stgi, void, env)

DEF_HELPER_1(clgi, void, env)

DEF_HELPER_1(skinit, void, env)

DEF_HELPER_2(invlpga, void, env, int)

DEF_HELPER_2(flds_FT0, void, env, i32)

DEF_HELPER_2(fldl_FT0, void, env, i64)

DEF_HELPER_2(fildl_FT0, void, env, s32)

DEF_HELPER_2(flds_ST0, void, env, i32)

DEF_HELPER_2(fldl_ST0, void, env, i64)

DEF_HELPER_2(fildl_ST0, void, env, s32)

DEF_HELPER_2(fildll_ST0, void, env, s64)

DEF_HELPER_1(fsts_ST0, i32, env)

DEF_HELPER_1(fstl_ST0, i64, env)

DEF_HELPER_1(fist_ST0, s32, env)

DEF_HELPER_1(fistl_ST0, s32, env)

DEF_HELPER_1(fistll_ST0, s64, env)

DEF_HELPER_1(fistt_ST0, s32, env)

DEF_HELPER_1(fisttl_ST0, s32, env)

DEF_HELPER_1(fisttll_ST0, s64, env)

DEF_HELPER_2(fldt_ST0, void, env, tl)

DEF_HELPER_2(fstt_ST0, void, env, tl)

DEF_HELPER_1(fpush, void, env)

DEF_HELPER_1(fpop, void, env)

DEF_HELPER_1(fdecstp, void, env)

DEF_HELPER_1(fincstp, void, env)

DEF_HELPER_2(ffree_STN, void, env, int)

DEF_HELPER_2(fmov_FT0_STN, void, env, int)

DEF_HELPER_2(fmov_ST0_STN, void, env, int)

DEF_HELPER_2(fmov_STN_ST0, void, env, int)

DEF_HELPER_2(fxchg_ST0_STN, void, env, int)

DEF_HELPER_1(fcom_ST0_FT0, void, env)

DEF_HELPER_1(fucom_ST0_FT0, void, env)

DEF_HELPER_1(fcomi_ST0_FT0, void, env)

DEF_HELPER_1(fucomi_ST0_FT0, void, env)

DEF_HELPER_1(fadd_ST0_FT0, void, env)

DEF_HELPER_1(fmul_ST0_FT0, void, env)

DEF_HELPER_1(fsub_ST0_FT0, void, env)

DEF_HELPER_1(fsubr_ST0_FT0, void, env)

DEF_HELPER_1(fdiv_ST0_FT0, void, env)

DEF_HELPER_1(fdivr_ST0_FT0, void, env)

DEF_HELPER_2(fadd_STN_ST0, void, env, int)

DEF_HELPER_2(fmul_STN_ST0, void, env, int)

DEF_HELPER_2(fsub_STN_ST0, void, env, int)

DEF_HELPER_2(fsubr_STN_ST0, void, env, int)

DEF_HELPER_2(fdiv_STN_ST0, void, env, int)

DEF_HELPER_2(fdivr_STN_ST0, void, env, int)

DEF_HELPER_1(fchs_ST0, void, env)

DEF_HELPER_1(fabs_ST0, void, env)

DEF_HELPER_1(fxam_ST0, void, env)

DEF_HELPER_1(fld1_ST0, void, env)

DEF_HELPER_1(fldl2t_ST0, void, env)

DEF_HELPER_1(fldl2e_ST0, void, env)

DEF_HELPER_1(fldpi_ST0, void, env)

DEF_HELPER_1(fldlg2_ST0, void, env)

DEF_HELPER_1(fldln2_ST0, void, env)

DEF_HELPER_1(fldz_ST0, void, env)

DEF_HELPER_1(fldz_FT0, void, env)

DEF_HELPER_1(fnstsw, i32, env)

DEF_HELPER_1(fnstcw, i32, env)

DEF_HELPER_2(fldcw, void, env, i32)

DEF_HELPER_1(fclex, void, env)

DEF_HELPER_1(fwait, void, env)

DEF_HELPER_1(fninit, void, env)

DEF_HELPER_2(fbld_ST0, void, env, tl)

DEF_HELPER_2(fbst_ST0, void, env, tl)

DEF_HELPER_1(f2xm1, void, env)

DEF_HELPER_1(fyl2x, void, env)

DEF_HELPER_1(fptan, void, env)

DEF_HELPER_1(fpatan, void, env)

DEF_HELPER_1(fxtract, void, env)

DEF_HELPER_1(fprem1, void, env)

DEF_HELPER_1(fprem, void, env)

DEF_HELPER_1(fyl2xp1, void, env)

DEF_HELPER_1(fsqrt, void, env)

DEF_HELPER_1(fsincos, void, env)

DEF_HELPER_1(frndint, void, env)

DEF_HELPER_1(fscale, void, env)

DEF_HELPER_1(fsin, void, env)

DEF_HELPER_1(fcos, void, env)

DEF_HELPER_3(fstenv, void, env, tl, int)

DEF_HELPER_3(fldenv, void, env, tl, int)

DEF_HELPER_3(fsave, void, env, tl, int)

DEF_HELPER_3(frstor, void, env, tl, int)

DEF_HELPER_FLAGS_2(fxsave, TCG_CALL_NO_WG, void, env, tl)

DEF_HELPER_FLAGS_2(fxrstor, TCG_CALL_NO_WG, void, env, tl)

DEF_HELPER_FLAGS_3(xsave, TCG_CALL_NO_WG, void, env, tl, i64)

DEF_HELPER_FLAGS_3(xsaveopt, TCG_CALL_NO_WG, void, env, tl, i64)

DEF_HELPER_FLAGS_3(xrstor, TCG_CALL_NO_WG, void, env, tl, i64)

DEF_HELPER_FLAGS_2(xgetbv, TCG_CALL_NO_WG, i64, env, i32)

DEF_HELPER_FLAGS_3(xsetbv, TCG_CALL_NO_WG, void, env, i32, i64)

DEF_HELPER_FLAGS_2(rdpkru, TCG_CALL_NO_WG, i64, env, i32)

DEF_HELPER_FLAGS_3(wrpkru, TCG_CALL_NO_WG, void, env, i32, i64)

DEF_HELPER_FLAGS_2(pdep, TCG_CALL_NO_RWG_SE, tl, tl, tl)

DEF_HELPER_FLAGS_2(pext, TCG_CALL_NO_RWG_SE, tl, tl, tl)

DEF_HELPER_2(ldmxcsr, void, env, i32)

DEF_HELPER_1(enter_mmx, void, env)

DEF_HELPER_1(emms, void, env)

DEF_HELPER_3(movq, void, env, ptr, ptr)

#define Reg MMXReg

#define SUFFIX _mmx

#define dh_alias_MMXReg ptr

DEF_HELPER_3(glue(psrlw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psraw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psllw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psrld, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psrad, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pslld, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psrlq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psllq, SUFFIX), void, env, Reg, Reg)

#define SSE_HELPER_B(name, F)\
    DEF_HELPER_3(glue(name, SUFFIX), void, env, Reg, Reg)

#define SSE_HELPER_W(name, F)\
    DEF_HELPER_3(glue(name, SUFFIX), void, env, Reg, Reg)

#define SSE_HELPER_L(name, F)\
    DEF_HELPER_3(glue(name, SUFFIX), void, env, Reg, Reg)

#define SSE_HELPER_Q(name, F)\
    DEF_HELPER_3(glue(name, SUFFIX), void, env, Reg, Reg)

SSE_HELPER_B(paddb, FADD)

SSE_HELPER_W(paddw, FADD)

SSE_HELPER_L(paddl, FADD)

SSE_HELPER_Q(paddq, FADD)

SSE_HELPER_B(psubb, FSUB)

SSE_HELPER_W(psubw, FSUB)

SSE_HELPER_L(psubl, FSUB)

SSE_HELPER_Q(psubq, FSUB)

SSE_HELPER_B(paddusb, FADDUB)

SSE_HELPER_B(paddsb, FADDSB)

SSE_HELPER_B(psubusb, FSUBUB)

SSE_HELPER_B(psubsb, FSUBSB)

SSE_HELPER_W(paddusw, FADDUW)

SSE_HELPER_W(paddsw, FADDSW)

SSE_HELPER_W(psubusw, FSUBUW)

SSE_HELPER_W(psubsw, FSUBSW)

SSE_HELPER_B(pminub, FMINUB)

SSE_HELPER_B(pmaxub, FMAXUB)

SSE_HELPER_W(pminsw, FMINSW)

SSE_HELPER_W(pmaxsw, FMAXSW)

SSE_HELPER_Q(pand, FAND)

SSE_HELPER_Q(pandn, FANDN)

SSE_HELPER_Q(por, FOR)

SSE_HELPER_Q(pxor, FXOR)

SSE_HELPER_B(pcmpgtb, FCMPGTB)

SSE_HELPER_W(pcmpgtw, FCMPGTW)

SSE_HELPER_L(pcmpgtl, FCMPGTL)

SSE_HELPER_B(pcmpeqb, FCMPEQ)

SSE_HELPER_W(pcmpeqw, FCMPEQ)

SSE_HELPER_L(pcmpeql, FCMPEQ)

SSE_HELPER_W(pmullw, FMULLW)

SSE_HELPER_W(pmulhrw, FMULHRW)

SSE_HELPER_W(pmulhuw, FMULHUW)

SSE_HELPER_W(pmulhw, FMULHW)

SSE_HELPER_B(pavgb, FAVG)

SSE_HELPER_W(pavgw, FAVG)

DEF_HELPER_3(glue(pmuludq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmaddwd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psadbw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_4(glue(maskmov, SUFFIX), void, env, Reg, Reg, tl)

DEF_HELPER_2(glue(movl_mm_T0, SUFFIX), void, Reg, i32)

DEF_HELPER_3(glue(pshufw, SUFFIX), void, Reg, Reg, int)

DEF_HELPER_2(glue(pmovmskb, SUFFIX), i32, env, Reg)

DEF_HELPER_3(glue(packsswb, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(packuswb, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(packssdw, SUFFIX), void, env, Reg, Reg)

#define UNPCK_OP(base_name, base)                                       \
    DEF_HELPER_3(glue(punpck ## base_name ## bw, SUFFIX), void, env, Reg, Reg) \
    DEF_HELPER_3(glue(punpck ## base_name ## wd, SUFFIX), void, env, Reg, Reg) \
    DEF_HELPER_3(glue(punpck ## base_name ## dq, SUFFIX), void, env, Reg, Reg)

UNPCK_OP(l, 0)

UNPCK_OP(h, 1)

DEF_HELPER_3(pi2fd, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pi2fw, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pf2id, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pf2iw, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pfacc, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pfadd, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pfcmpeq, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pfcmpge, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pfcmpgt, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pfmax, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pfmin, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pfmul, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pfnacc, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pfpnacc, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pfrcp, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pfrsqrt, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pfsub, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pfsubr, void, env, MMXReg, MMXReg)

DEF_HELPER_3(pswapd, void, env, MMXReg, MMXReg)

DEF_HELPER_3(glue(phaddw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(phaddd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(phaddsw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(phsubw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(phsubd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(phsubsw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pabsb, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pabsw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pabsd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmaddubsw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmulhrsw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pshufb, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psignb, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psignw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psignd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_4(glue(palignr, SUFFIX), void, env, Reg, Reg, s32)

#define Reg ZMMReg

#define SUFFIX _xmm

#define dh_alias_ZMMReg ptr

#define dh_alias_MMXReg ptr

DEF_HELPER_3(glue(psrlw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psraw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psllw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psrld, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psrad, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pslld, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psrlq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psllq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psrldq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pslldq, SUFFIX), void, env, Reg, Reg)

#define SSE_HELPER_B(name, F)\
    DEF_HELPER_3(glue(name, SUFFIX), void, env, Reg, Reg)

#define SSE_HELPER_W(name, F)\
    DEF_HELPER_3(glue(name, SUFFIX), void, env, Reg, Reg)

#define SSE_HELPER_L(name, F)\
    DEF_HELPER_3(glue(name, SUFFIX), void, env, Reg, Reg)

#define SSE_HELPER_Q(name, F)\
    DEF_HELPER_3(glue(name, SUFFIX), void, env, Reg, Reg)

SSE_HELPER_B(paddb, FADD)

SSE_HELPER_W(paddw, FADD)

SSE_HELPER_L(paddl, FADD)

SSE_HELPER_Q(paddq, FADD)

SSE_HELPER_B(psubb, FSUB)

SSE_HELPER_W(psubw, FSUB)

SSE_HELPER_L(psubl, FSUB)

SSE_HELPER_Q(psubq, FSUB)

SSE_HELPER_B(paddusb, FADDUB)

SSE_HELPER_B(paddsb, FADDSB)

SSE_HELPER_B(psubusb, FSUBUB)

SSE_HELPER_B(psubsb, FSUBSB)

SSE_HELPER_W(paddusw, FADDUW)

SSE_HELPER_W(paddsw, FADDSW)

SSE_HELPER_W(psubusw, FSUBUW)

SSE_HELPER_W(psubsw, FSUBSW)

SSE_HELPER_B(pminub, FMINUB)

SSE_HELPER_B(pmaxub, FMAXUB)

SSE_HELPER_W(pminsw, FMINSW)

SSE_HELPER_W(pmaxsw, FMAXSW)

SSE_HELPER_Q(pand, FAND)

SSE_HELPER_Q(pandn, FANDN)

SSE_HELPER_Q(por, FOR)

SSE_HELPER_Q(pxor, FXOR)

SSE_HELPER_B(pcmpgtb, FCMPGTB)

SSE_HELPER_W(pcmpgtw, FCMPGTW)

SSE_HELPER_L(pcmpgtl, FCMPGTL)

SSE_HELPER_B(pcmpeqb, FCMPEQ)

SSE_HELPER_W(pcmpeqw, FCMPEQ)

SSE_HELPER_L(pcmpeql, FCMPEQ)

SSE_HELPER_W(pmullw, FMULLW)

SSE_HELPER_W(pmulhuw, FMULHUW)

SSE_HELPER_W(pmulhw, FMULHW)

SSE_HELPER_B(pavgb, FAVG)

SSE_HELPER_W(pavgw, FAVG)

DEF_HELPER_3(glue(pmuludq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmaddwd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psadbw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_4(glue(maskmov, SUFFIX), void, env, Reg, Reg, tl)

DEF_HELPER_2(glue(movl_mm_T0, SUFFIX), void, Reg, i32)

DEF_HELPER_2(glue(movq_mm_T0, SUFFIX), void, Reg, i64)

DEF_HELPER_3(shufps, void, Reg, Reg, int)

DEF_HELPER_3(shufpd, void, Reg, Reg, int)

DEF_HELPER_3(glue(pshufd, SUFFIX), void, Reg, Reg, int)

DEF_HELPER_3(glue(pshuflw, SUFFIX), void, Reg, Reg, int)

DEF_HELPER_3(glue(pshufhw, SUFFIX), void, Reg, Reg, int)

#define SSE_HELPER_S(name, F)                            \
    DEF_HELPER_3(name ## ps, void, env, Reg, Reg)        \
    DEF_HELPER_3(name ## ss, void, env, Reg, Reg)        \
    DEF_HELPER_3(name ## pd, void, env, Reg, Reg)        \
    DEF_HELPER_3(name ## sd, void, env, Reg, Reg)

SSE_HELPER_S(add, FPU_ADD)

SSE_HELPER_S(sub, FPU_SUB)

SSE_HELPER_S(mul, FPU_MUL)

SSE_HELPER_S(div, FPU_DIV)

SSE_HELPER_S(min, FPU_MIN)

SSE_HELPER_S(max, FPU_MAX)

SSE_HELPER_S(sqrt, FPU_SQRT)

DEF_HELPER_3(cvtps2pd, void, env, Reg, Reg)

DEF_HELPER_3(cvtpd2ps, void, env, Reg, Reg)

DEF_HELPER_3(cvtss2sd, void, env, Reg, Reg)

DEF_HELPER_3(cvtsd2ss, void, env, Reg, Reg)

DEF_HELPER_3(cvtdq2ps, void, env, Reg, Reg)

DEF_HELPER_3(cvtdq2pd, void, env, Reg, Reg)

DEF_HELPER_3(cvtpi2ps, void, env, ZMMReg, MMXReg)

DEF_HELPER_3(cvtpi2pd, void, env, ZMMReg, MMXReg)

DEF_HELPER_3(cvtsi2ss, void, env, ZMMReg, i32)

DEF_HELPER_3(cvtsi2sd, void, env, ZMMReg, i32)

DEF_HELPER_3(cvtsq2ss, void, env, ZMMReg, i64)

DEF_HELPER_3(cvtsq2sd, void, env, ZMMReg, i64)

DEF_HELPER_3(cvtps2dq, void, env, ZMMReg, ZMMReg)

DEF_HELPER_3(cvtpd2dq, void, env, ZMMReg, ZMMReg)

DEF_HELPER_3(cvtps2pi, void, env, MMXReg, ZMMReg)

DEF_HELPER_3(cvtpd2pi, void, env, MMXReg, ZMMReg)

DEF_HELPER_2(cvtss2si, s32, env, ZMMReg)

DEF_HELPER_2(cvtsd2si, s32, env, ZMMReg)

DEF_HELPER_2(cvtss2sq, s64, env, ZMMReg)

DEF_HELPER_2(cvtsd2sq, s64, env, ZMMReg)

DEF_HELPER_3(cvttps2dq, void, env, ZMMReg, ZMMReg)

DEF_HELPER_3(cvttpd2dq, void, env, ZMMReg, ZMMReg)

DEF_HELPER_3(cvttps2pi, void, env, MMXReg, ZMMReg)

DEF_HELPER_3(cvttpd2pi, void, env, MMXReg, ZMMReg)

DEF_HELPER_2(cvttss2si, s32, env, ZMMReg)

DEF_HELPER_2(cvttsd2si, s32, env, ZMMReg)

DEF_HELPER_2(cvttss2sq, s64, env, ZMMReg)

DEF_HELPER_2(cvttsd2sq, s64, env, ZMMReg)

DEF_HELPER_3(rsqrtps, void, env, ZMMReg, ZMMReg)

DEF_HELPER_3(rsqrtss, void, env, ZMMReg, ZMMReg)

DEF_HELPER_3(rcpps, void, env, ZMMReg, ZMMReg)

DEF_HELPER_3(rcpss, void, env, ZMMReg, ZMMReg)

DEF_HELPER_3(extrq_r, void, env, ZMMReg, ZMMReg)

DEF_HELPER_4(extrq_i, void, env, ZMMReg, int, int)

DEF_HELPER_3(insertq_r, void, env, ZMMReg, ZMMReg)

DEF_HELPER_4(insertq_i, void, env, ZMMReg, int, int)

DEF_HELPER_3(haddps, void, env, ZMMReg, ZMMReg)

DEF_HELPER_3(haddpd, void, env, ZMMReg, ZMMReg)

DEF_HELPER_3(hsubps, void, env, ZMMReg, ZMMReg)

DEF_HELPER_3(hsubpd, void, env, ZMMReg, ZMMReg)

DEF_HELPER_3(addsubps, void, env, ZMMReg, ZMMReg)

DEF_HELPER_3(addsubpd, void, env, ZMMReg, ZMMReg)

#define SSE_HELPER_CMP(name, F)                           \
    DEF_HELPER_3(name ## ps, void, env, Reg, Reg)         \
    DEF_HELPER_3(name ## ss, void, env, Reg, Reg)         \
    DEF_HELPER_3(name ## pd, void, env, Reg, Reg)         \
    DEF_HELPER_3(name ## sd, void, env, Reg, Reg)

SSE_HELPER_CMP(cmpeq, FPU_CMPEQ)

SSE_HELPER_CMP(cmplt, FPU_CMPLT)

SSE_HELPER_CMP(cmple, FPU_CMPLE)

SSE_HELPER_CMP(cmpunord, FPU_CMPUNORD)

SSE_HELPER_CMP(cmpneq, FPU_CMPNEQ)

SSE_HELPER_CMP(cmpnlt, FPU_CMPNLT)

SSE_HELPER_CMP(cmpnle, FPU_CMPNLE)

SSE_HELPER_CMP(cmpord, FPU_CMPORD)

DEF_HELPER_3(ucomiss, void, env, Reg, Reg)

DEF_HELPER_3(comiss, void, env, Reg, Reg)

DEF_HELPER_3(ucomisd, void, env, Reg, Reg)

DEF_HELPER_3(comisd, void, env, Reg, Reg)

DEF_HELPER_2(movmskps, i32, env, Reg)

DEF_HELPER_2(movmskpd, i32, env, Reg)

DEF_HELPER_2(glue(pmovmskb, SUFFIX), i32, env, Reg)

DEF_HELPER_3(glue(packsswb, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(packuswb, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(packssdw, SUFFIX), void, env, Reg, Reg)

#define UNPCK_OP(base_name, base)                                       \
    DEF_HELPER_3(glue(punpck ## base_name ## bw, SUFFIX), void, env, Reg, Reg) \
    DEF_HELPER_3(glue(punpck ## base_name ## wd, SUFFIX), void, env, Reg, Reg) \
    DEF_HELPER_3(glue(punpck ## base_name ## dq, SUFFIX), void, env, Reg, Reg)

UNPCK_OP(l, 0)

UNPCK_OP(h, 1)

DEF_HELPER_3(glue(punpcklqdq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(punpckhqdq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(phaddw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(phaddd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(phaddsw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(phsubw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(phsubd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(phsubsw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pabsb, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pabsw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pabsd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmaddubsw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmulhrsw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pshufb, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psignb, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psignw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psignd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_4(glue(palignr, SUFFIX), void, env, Reg, Reg, s32)

DEF_HELPER_3(glue(pblendvb, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(blendvps, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(blendvpd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(ptest, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmovsxbw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmovsxbd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmovsxbq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmovsxwd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmovsxwq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmovsxdq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmovzxbw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmovzxbd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmovzxbq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmovzxwd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmovzxwq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmovzxdq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmuldq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pcmpeqq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(packusdw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pminsb, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pminsd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pminuw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pminud, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmaxsb, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmaxsd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmaxuw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmaxud, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(pmulld, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(phminposuw, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_4(glue(roundps, SUFFIX), void, env, Reg, Reg, i32)

DEF_HELPER_4(glue(roundpd, SUFFIX), void, env, Reg, Reg, i32)

DEF_HELPER_4(glue(roundss, SUFFIX), void, env, Reg, Reg, i32)

DEF_HELPER_4(glue(roundsd, SUFFIX), void, env, Reg, Reg, i32)

DEF_HELPER_4(glue(blendps, SUFFIX), void, env, Reg, Reg, i32)

DEF_HELPER_4(glue(blendpd, SUFFIX), void, env, Reg, Reg, i32)

DEF_HELPER_4(glue(pblendw, SUFFIX), void, env, Reg, Reg, i32)

DEF_HELPER_4(glue(dpps, SUFFIX), void, env, Reg, Reg, i32)

DEF_HELPER_4(glue(dppd, SUFFIX), void, env, Reg, Reg, i32)

DEF_HELPER_4(glue(mpsadbw, SUFFIX), void, env, Reg, Reg, i32)

DEF_HELPER_3(glue(pcmpgtq, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_4(glue(pcmpestri, SUFFIX), void, env, Reg, Reg, i32)

DEF_HELPER_4(glue(pcmpestrm, SUFFIX), void, env, Reg, Reg, i32)

DEF_HELPER_4(glue(pcmpistri, SUFFIX), void, env, Reg, Reg, i32)

DEF_HELPER_4(glue(pcmpistrm, SUFFIX), void, env, Reg, Reg, i32)

DEF_HELPER_3(crc32, tl, i32, tl, i32)

DEF_HELPER_3(glue(aesdec, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(aesdeclast, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(aesenc, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(aesenclast, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(aesimc, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_4(glue(aeskeygenassist, SUFFIX), void, env, Reg, Reg, i32)

DEF_HELPER_4(glue(pclmulqdq, SUFFIX), void, env, Reg, Reg, i32)

DEF_HELPER_3(rclb, tl, env, tl, tl)

DEF_HELPER_3(rclw, tl, env, tl, tl)

DEF_HELPER_3(rcll, tl, env, tl, tl)

DEF_HELPER_3(rcrb, tl, env, tl, tl)

DEF_HELPER_3(rcrw, tl, env, tl, tl)

DEF_HELPER_3(rcrl, tl, env, tl, tl)

DEF_HELPER_3(rclq, tl, env, tl, tl)

DEF_HELPER_3(rcrq, tl, env, tl, tl)

DEF_HELPER_FLAGS_3(trace_guest_mem_before_exec_proxy, TCG_CALL_NO_RWG, void, env, tl, i32)

#define tcg_temp_new_nop(v) (v)

#define tcg_temp_free_nop(v)

static inline void gen_helper_trace_guest_mem_before_exec(TCGv_env __tcg___cpu, TCGv vaddr, uint8_t info)
{
    TCGv_env ____tcg___cpu = tcg_temp_new_nop(__tcg___cpu);
    TCGv __vaddr = tcg_temp_new_nop(vaddr);
    TCGv_i32 __info = tcg_const_i32(info);
    gen_helper_trace_guest_mem_before_exec_proxy(____tcg___cpu, __vaddr, __info);
    tcg_temp_free_nop(____tcg___cpu);
    tcg_temp_free_nop(__vaddr);
    tcg_temp_free_i32(__info);
}

DEF_HELPER_FLAGS_2(mulsh_i64, TCG_CALL_NO_RWG_SE, s64, s64, s64)

DEF_HELPER_FLAGS_2(muluh_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64)

DEF_HELPER_FLAGS_2(clz_i32, TCG_CALL_NO_RWG_SE, i32, i32, i32)

DEF_HELPER_FLAGS_2(ctz_i32, TCG_CALL_NO_RWG_SE, i32, i32, i32)

DEF_HELPER_FLAGS_2(clz_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64)

DEF_HELPER_FLAGS_2(ctz_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64)

DEF_HELPER_FLAGS_1(ctpop_i32, TCG_CALL_NO_RWG_SE, i32, i32)

DEF_HELPER_FLAGS_1(ctpop_i64, TCG_CALL_NO_RWG_SE, i64, i64)

DEF_HELPER_FLAGS_1(lookup_tb_ptr, TCG_CALL_NO_WG_SE, ptr, env)

DEF_HELPER_FLAGS_1(exit_atomic, TCG_CALL_NO_WG, noreturn, env)

DEF_HELPER_FLAGS_4(atomic_cmpxchgb, TCG_CALL_NO_WG, i32, env, tl, i32, i32)

DEF_HELPER_FLAGS_4(atomic_cmpxchgw_be, TCG_CALL_NO_WG, i32, env, tl, i32, i32)

DEF_HELPER_FLAGS_4(atomic_cmpxchgw_le, TCG_CALL_NO_WG, i32, env, tl, i32, i32)

DEF_HELPER_FLAGS_4(atomic_cmpxchgl_be, TCG_CALL_NO_WG, i32, env, tl, i32, i32)

DEF_HELPER_FLAGS_4(atomic_cmpxchgl_le, TCG_CALL_NO_WG, i32, env, tl, i32, i32)

#define GEN_ATOMIC_HELPERS(NAME)                             \
    DEF_HELPER_FLAGS_3(glue(glue(atomic_, NAME), b),         \
                       TCG_CALL_NO_WG, i32, env, tl, i32)    \
    DEF_HELPER_FLAGS_3(glue(glue(atomic_, NAME), w_le),      \
                       TCG_CALL_NO_WG, i32, env, tl, i32)    \
    DEF_HELPER_FLAGS_3(glue(glue(atomic_, NAME), w_be),      \
                       TCG_CALL_NO_WG, i32, env, tl, i32)    \
    DEF_HELPER_FLAGS_3(glue(glue(atomic_, NAME), l_le),      \
                       TCG_CALL_NO_WG, i32, env, tl, i32)    \
    DEF_HELPER_FLAGS_3(glue(glue(atomic_, NAME), l_be),      \
                       TCG_CALL_NO_WG, i32, env, tl, i32)

GEN_ATOMIC_HELPERS(fetch_add)

GEN_ATOMIC_HELPERS(fetch_and)

GEN_ATOMIC_HELPERS(fetch_or)

GEN_ATOMIC_HELPERS(fetch_xor)

GEN_ATOMIC_HELPERS(add_fetch)

GEN_ATOMIC_HELPERS(and_fetch)

GEN_ATOMIC_HELPERS(or_fetch)

GEN_ATOMIC_HELPERS(xor_fetch)

GEN_ATOMIC_HELPERS(xchg)

void tcg_gen_op1(TCGOpcode, TCGArg);

void tcg_gen_op2(TCGOpcode, TCGArg, TCGArg);

void tcg_gen_op3(TCGOpcode, TCGArg, TCGArg, TCGArg);

void tcg_gen_op4(TCGOpcode, TCGArg, TCGArg, TCGArg, TCGArg);

void tcg_gen_op5(TCGOpcode, TCGArg, TCGArg, TCGArg, TCGArg, TCGArg);

void tcg_gen_op6(TCGOpcode, TCGArg, TCGArg, TCGArg, TCGArg, TCGArg, TCGArg);

static inline void tcg_gen_op1_i32(TCGOpcode opc, TCGv_i32 a1)
{
    tcg_gen_op1(opc, tcgv_i32_arg(a1));
}

static inline void tcg_gen_op1_i64(TCGOpcode opc, TCGv_i64 a1)
{
    tcg_gen_op1(opc, tcgv_i64_arg(a1));
}

static inline void tcg_gen_op1i(TCGOpcode opc, TCGArg a1)
{
    tcg_gen_op1(opc, a1);
}

static inline void tcg_gen_op2_i32(TCGOpcode opc, TCGv_i32 a1, TCGv_i32 a2)
{
    tcg_gen_op2(opc, tcgv_i32_arg(a1), tcgv_i32_arg(a2));
}

static inline void tcg_gen_op2_i64(TCGOpcode opc, TCGv_i64 a1, TCGv_i64 a2)
{
    tcg_gen_op2(opc, tcgv_i64_arg(a1), tcgv_i64_arg(a2));
}

static inline void tcg_gen_op2i_i32(TCGOpcode opc, TCGv_i32 a1, TCGArg a2)
{
    tcg_gen_op2(opc, tcgv_i32_arg(a1), a2);
}

static inline void tcg_gen_op2i_i64(TCGOpcode opc, TCGv_i64 a1, TCGArg a2)
{
    tcg_gen_op2(opc, tcgv_i64_arg(a1), a2);
}

static inline void tcg_gen_op3_i32(TCGOpcode opc, TCGv_i32 a1,
                                   TCGv_i32 a2, TCGv_i32 a3)
{
    tcg_gen_op3(opc, tcgv_i32_arg(a1), tcgv_i32_arg(a2), tcgv_i32_arg(a3));
}

static inline void tcg_gen_op3_i64(TCGOpcode opc, TCGv_i64 a1,
                                   TCGv_i64 a2, TCGv_i64 a3)
{
    tcg_gen_op3(opc, tcgv_i64_arg(a1), tcgv_i64_arg(a2), tcgv_i64_arg(a3));
}

static inline void tcg_gen_op3i_i64(TCGOpcode opc, TCGv_i64 a1,
                                    TCGv_i64 a2, TCGArg a3)
{
    tcg_gen_op3(opc, tcgv_i64_arg(a1), tcgv_i64_arg(a2), a3);
}

static inline void tcg_gen_ldst_op_i32(TCGOpcode opc, TCGv_i32 val,
                                       TCGv_ptr base, TCGArg offset)
{
    tcg_gen_op3(opc, tcgv_i32_arg(val), tcgv_ptr_arg(base), offset);
}

static inline void tcg_gen_ldst_op_i64(TCGOpcode opc, TCGv_i64 val,
                                       TCGv_ptr base, TCGArg offset)
{
    tcg_gen_op3(opc, tcgv_i64_arg(val), tcgv_ptr_arg(base), offset);
}

static inline void tcg_gen_op4_i32(TCGOpcode opc, TCGv_i32 a1, TCGv_i32 a2,
                                   TCGv_i32 a3, TCGv_i32 a4)
{
    tcg_gen_op4(opc, tcgv_i32_arg(a1), tcgv_i32_arg(a2),
                tcgv_i32_arg(a3), tcgv_i32_arg(a4));
}

static inline void tcg_gen_op4_i64(TCGOpcode opc, TCGv_i64 a1, TCGv_i64 a2,
                                   TCGv_i64 a3, TCGv_i64 a4)
{
    tcg_gen_op4(opc, tcgv_i64_arg(a1), tcgv_i64_arg(a2),
                tcgv_i64_arg(a3), tcgv_i64_arg(a4));
}

static inline void tcg_gen_op4i_i32(TCGOpcode opc, TCGv_i32 a1, TCGv_i32 a2,
                                    TCGv_i32 a3, TCGArg a4)
{
    tcg_gen_op4(opc, tcgv_i32_arg(a1), tcgv_i32_arg(a2),
                tcgv_i32_arg(a3), a4);
}

static inline void tcg_gen_op4i_i64(TCGOpcode opc, TCGv_i64 a1, TCGv_i64 a2,
                                    TCGv_i64 a3, TCGArg a4)
{
    tcg_gen_op4(opc, tcgv_i64_arg(a1), tcgv_i64_arg(a2),
                tcgv_i64_arg(a3), a4);
}

static inline void tcg_gen_op4ii_i32(TCGOpcode opc, TCGv_i32 a1, TCGv_i32 a2,
                                     TCGArg a3, TCGArg a4)
{
    tcg_gen_op4(opc, tcgv_i32_arg(a1), tcgv_i32_arg(a2), a3, a4);
}

static inline void tcg_gen_op4ii_i64(TCGOpcode opc, TCGv_i64 a1, TCGv_i64 a2,
                                     TCGArg a3, TCGArg a4)
{
    tcg_gen_op4(opc, tcgv_i64_arg(a1), tcgv_i64_arg(a2), a3, a4);
}

static inline void tcg_gen_op5i_i32(TCGOpcode opc, TCGv_i32 a1, TCGv_i32 a2,
                                    TCGv_i32 a3, TCGv_i32 a4, TCGArg a5)
{
    tcg_gen_op5(opc, tcgv_i32_arg(a1), tcgv_i32_arg(a2),
                tcgv_i32_arg(a3), tcgv_i32_arg(a4), a5);
}

static inline void tcg_gen_op5ii_i32(TCGOpcode opc, TCGv_i32 a1, TCGv_i32 a2,
                                     TCGv_i32 a3, TCGArg a4, TCGArg a5)
{
    tcg_gen_op5(opc, tcgv_i32_arg(a1), tcgv_i32_arg(a2),
                tcgv_i32_arg(a3), a4, a5);
}

static inline void tcg_gen_op5ii_i64(TCGOpcode opc, TCGv_i64 a1, TCGv_i64 a2,
                                     TCGv_i64 a3, TCGArg a4, TCGArg a5)
{
    tcg_gen_op5(opc, tcgv_i64_arg(a1), tcgv_i64_arg(a2),
                tcgv_i64_arg(a3), a4, a5);
}

static inline void tcg_gen_op6_i64(TCGOpcode opc, TCGv_i64 a1, TCGv_i64 a2,
                                   TCGv_i64 a3, TCGv_i64 a4,
                                   TCGv_i64 a5, TCGv_i64 a6)
{
    tcg_gen_op6(opc, tcgv_i64_arg(a1), tcgv_i64_arg(a2),
                tcgv_i64_arg(a3), tcgv_i64_arg(a4), tcgv_i64_arg(a5),
                tcgv_i64_arg(a6));
}

static inline void tcg_gen_op6i_i32(TCGOpcode opc, TCGv_i32 a1, TCGv_i32 a2,
                                    TCGv_i32 a3, TCGv_i32 a4,
                                    TCGv_i32 a5, TCGArg a6)
{
    tcg_gen_op6(opc, tcgv_i32_arg(a1), tcgv_i32_arg(a2),
                tcgv_i32_arg(a3), tcgv_i32_arg(a4), tcgv_i32_arg(a5), a6);
}

static inline void tcg_gen_op6i_i64(TCGOpcode opc, TCGv_i64 a1, TCGv_i64 a2,
                                    TCGv_i64 a3, TCGv_i64 a4,
                                    TCGv_i64 a5, TCGArg a6)
{
    tcg_gen_op6(opc, tcgv_i64_arg(a1), tcgv_i64_arg(a2),
                tcgv_i64_arg(a3), tcgv_i64_arg(a4), tcgv_i64_arg(a5), a6);
}

static inline void tcg_gen_op6ii_i32(TCGOpcode opc, TCGv_i32 a1, TCGv_i32 a2,
                                     TCGv_i32 a3, TCGv_i32 a4,
                                     TCGArg a5, TCGArg a6)
{
    tcg_gen_op6(opc, tcgv_i32_arg(a1), tcgv_i32_arg(a2),
                tcgv_i32_arg(a3), tcgv_i32_arg(a4), a5, a6);
}

static inline void gen_set_label(TCGLabel *l)
{
    tcg_gen_op1(INDEX_op_set_label, label_arg(l));
}

static inline void tcg_gen_br(TCGLabel *l)
{
    tcg_gen_op1(INDEX_op_br, label_arg(l));
}

void tcg_gen_mb(TCGBar);

void tcg_gen_subfi_i32(TCGv_i32 ret, int32_t arg1, TCGv_i32 arg2);

void tcg_gen_andi_i32(TCGv_i32 ret, TCGv_i32 arg1, uint32_t arg2);

void tcg_gen_ori_i32(TCGv_i32 ret, TCGv_i32 arg1, int32_t arg2);

void tcg_gen_xori_i32(TCGv_i32 ret, TCGv_i32 arg1, int32_t arg2);

void tcg_gen_sari_i32(TCGv_i32 ret, TCGv_i32 arg1, unsigned arg2);

void tcg_gen_ctpop_i32(TCGv_i32 a1, TCGv_i32 a2);

void tcg_gen_rotl_i32(TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2);

void tcg_gen_rotli_i32(TCGv_i32 ret, TCGv_i32 arg1, unsigned arg2);

void tcg_gen_rotr_i32(TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2);

void tcg_gen_rotri_i32(TCGv_i32 ret, TCGv_i32 arg1, unsigned arg2);

void tcg_gen_movcond_i32(TCGCond cond, TCGv_i32 ret, TCGv_i32 c1,
                         TCGv_i32 c2, TCGv_i32 v1, TCGv_i32 v2);

void tcg_gen_mulu2_i32(TCGv_i32 rl, TCGv_i32 rh, TCGv_i32 arg1, TCGv_i32 arg2);

void tcg_gen_muls2_i32(TCGv_i32 rl, TCGv_i32 rh, TCGv_i32 arg1, TCGv_i32 arg2);

void tcg_gen_ext8s_i32(TCGv_i32 ret, TCGv_i32 arg);

void tcg_gen_ext16s_i32(TCGv_i32 ret, TCGv_i32 arg);

void tcg_gen_ext8u_i32(TCGv_i32 ret, TCGv_i32 arg);

void tcg_gen_ext16u_i32(TCGv_i32 ret, TCGv_i32 arg);

static inline void tcg_gen_discard_i32(TCGv_i32 arg)
{
    tcg_gen_op1_i32(INDEX_op_discard, arg);
}

static inline void tcg_gen_mov_i32(TCGv_i32 ret, TCGv_i32 arg)
{
    if (ret != arg) {
        tcg_gen_op2_i32(INDEX_op_mov_i32, ret, arg);
    }
}

static inline void tcg_gen_movi_i32(TCGv_i32 ret, int32_t arg)
{
    tcg_gen_op2i_i32(INDEX_op_movi_i32, ret, arg);
}

static inline void tcg_gen_ld_i32(TCGv_i32 ret, TCGv_ptr arg2,
                                  tcg_target_long offset)
{
    tcg_gen_ldst_op_i32(INDEX_op_ld_i32, ret, arg2, offset);
}

static inline void tcg_gen_st_i32(TCGv_i32 arg1, TCGv_ptr arg2,
                                  tcg_target_long offset)
{
    tcg_gen_ldst_op_i32(INDEX_op_st_i32, arg1, arg2, offset);
}

static inline void tcg_gen_add_i32(TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    tcg_gen_op3_i32(INDEX_op_add_i32, ret, arg1, arg2);
}

static inline void tcg_gen_sub_i32(TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    tcg_gen_op3_i32(INDEX_op_sub_i32, ret, arg1, arg2);
}

static inline void tcg_gen_and_i32(TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    tcg_gen_op3_i32(INDEX_op_and_i32, ret, arg1, arg2);
}

static inline void tcg_gen_or_i32(TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    tcg_gen_op3_i32(INDEX_op_or_i32, ret, arg1, arg2);
}

static inline void tcg_gen_xor_i32(TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    tcg_gen_op3_i32(INDEX_op_xor_i32, ret, arg1, arg2);
}

static inline void tcg_gen_shl_i32(TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    tcg_gen_op3_i32(INDEX_op_shl_i32, ret, arg1, arg2);
}

static inline void tcg_gen_shr_i32(TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    tcg_gen_op3_i32(INDEX_op_shr_i32, ret, arg1, arg2);
}

static inline void tcg_gen_sar_i32(TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    tcg_gen_op3_i32(INDEX_op_sar_i32, ret, arg1, arg2);
}

static inline void tcg_gen_neg_i32(TCGv_i32 ret, TCGv_i32 arg)
{
    if (TCG_TARGET_HAS_neg_i32) {
        tcg_gen_op2_i32(INDEX_op_neg_i32, ret, arg);
    } else {
        tcg_gen_subfi_i32(ret, 0, arg);
    }
}

static inline void tcg_gen_not_i32(TCGv_i32 ret, TCGv_i32 arg)
{
    if (TCG_TARGET_HAS_not_i32) {
        tcg_gen_op2_i32(INDEX_op_not_i32, ret, arg);
    } else {
        tcg_gen_xori_i32(ret, arg, -1);
    }
}

void tcg_gen_addi_i64(TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2);

void tcg_gen_subfi_i64(TCGv_i64 ret, int64_t arg1, TCGv_i64 arg2);

void tcg_gen_subi_i64(TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2);

void tcg_gen_andi_i64(TCGv_i64 ret, TCGv_i64 arg1, uint64_t arg2);

void tcg_gen_ori_i64(TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2);

void tcg_gen_xori_i64(TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2);

void tcg_gen_shli_i64(TCGv_i64 ret, TCGv_i64 arg1, unsigned arg2);

void tcg_gen_shri_i64(TCGv_i64 ret, TCGv_i64 arg1, unsigned arg2);

void tcg_gen_sari_i64(TCGv_i64 ret, TCGv_i64 arg1, unsigned arg2);

void tcg_gen_muli_i64(TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2);

void tcg_gen_andc_i64(TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2);

void tcg_gen_clz_i64(TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2);

void tcg_gen_ctz_i64(TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2);

void tcg_gen_clzi_i64(TCGv_i64 ret, TCGv_i64 arg1, uint64_t arg2);

void tcg_gen_ctzi_i64(TCGv_i64 ret, TCGv_i64 arg1, uint64_t arg2);

void tcg_gen_ctpop_i64(TCGv_i64 a1, TCGv_i64 a2);

void tcg_gen_rotl_i64(TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2);

void tcg_gen_rotli_i64(TCGv_i64 ret, TCGv_i64 arg1, unsigned arg2);

void tcg_gen_rotr_i64(TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2);

void tcg_gen_rotri_i64(TCGv_i64 ret, TCGv_i64 arg1, unsigned arg2);

void tcg_gen_deposit_i64(TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2,
                         unsigned int ofs, unsigned int len);

void tcg_gen_extract_i64(TCGv_i64 ret, TCGv_i64 arg,
                         unsigned int ofs, unsigned int len);

void tcg_gen_sextract_i64(TCGv_i64 ret, TCGv_i64 arg,
                          unsigned int ofs, unsigned int len);

void tcg_gen_brcond_i64(TCGCond cond, TCGv_i64 arg1, TCGv_i64 arg2, TCGLabel *);

void tcg_gen_brcondi_i64(TCGCond cond, TCGv_i64 arg1, int64_t arg2, TCGLabel *);

void tcg_gen_setcond_i64(TCGCond cond, TCGv_i64 ret,
                         TCGv_i64 arg1, TCGv_i64 arg2);

void tcg_gen_setcondi_i64(TCGCond cond, TCGv_i64 ret,
                          TCGv_i64 arg1, int64_t arg2);

void tcg_gen_movcond_i64(TCGCond cond, TCGv_i64 ret, TCGv_i64 c1,
                         TCGv_i64 c2, TCGv_i64 v1, TCGv_i64 v2);

void tcg_gen_add2_i64(TCGv_i64 rl, TCGv_i64 rh, TCGv_i64 al,
                      TCGv_i64 ah, TCGv_i64 bl, TCGv_i64 bh);

void tcg_gen_mulu2_i64(TCGv_i64 rl, TCGv_i64 rh, TCGv_i64 arg1, TCGv_i64 arg2);

void tcg_gen_muls2_i64(TCGv_i64 rl, TCGv_i64 rh, TCGv_i64 arg1, TCGv_i64 arg2);

void tcg_gen_not_i64(TCGv_i64 ret, TCGv_i64 arg);

void tcg_gen_ext8s_i64(TCGv_i64 ret, TCGv_i64 arg);

void tcg_gen_ext16s_i64(TCGv_i64 ret, TCGv_i64 arg);

void tcg_gen_ext32s_i64(TCGv_i64 ret, TCGv_i64 arg);

void tcg_gen_ext8u_i64(TCGv_i64 ret, TCGv_i64 arg);

void tcg_gen_ext16u_i64(TCGv_i64 ret, TCGv_i64 arg);

void tcg_gen_ext32u_i64(TCGv_i64 ret, TCGv_i64 arg);

void tcg_gen_bswap32_i64(TCGv_i64 ret, TCGv_i64 arg);

void tcg_gen_bswap64_i64(TCGv_i64 ret, TCGv_i64 arg);

static inline void tcg_gen_discard_i64(TCGv_i64 arg)
{
    tcg_gen_op1_i64(INDEX_op_discard, arg);
}

static inline void tcg_gen_mov_i64(TCGv_i64 ret, TCGv_i64 arg)
{
    if (ret != arg) {
        tcg_gen_op2_i64(INDEX_op_mov_i64, ret, arg);
    }
}

static inline void tcg_gen_movi_i64(TCGv_i64 ret, int64_t arg)
{
    tcg_gen_op2i_i64(INDEX_op_movi_i64, ret, arg);
}

static inline void tcg_gen_ld8u_i64(TCGv_i64 ret, TCGv_ptr arg2,
                                    tcg_target_long offset)
{
    tcg_gen_ldst_op_i64(INDEX_op_ld8u_i64, ret, arg2, offset);
}

static inline void tcg_gen_ld16u_i64(TCGv_i64 ret, TCGv_ptr arg2,
                                     tcg_target_long offset)
{
    tcg_gen_ldst_op_i64(INDEX_op_ld16u_i64, ret, arg2, offset);
}

static inline void tcg_gen_ld32u_i64(TCGv_i64 ret, TCGv_ptr arg2,
                                     tcg_target_long offset)
{
    tcg_gen_ldst_op_i64(INDEX_op_ld32u_i64, ret, arg2, offset);
}

static inline void tcg_gen_ld32s_i64(TCGv_i64 ret, TCGv_ptr arg2,
                                     tcg_target_long offset)
{
    tcg_gen_ldst_op_i64(INDEX_op_ld32s_i64, ret, arg2, offset);
}

static inline void tcg_gen_ld_i64(TCGv_i64 ret, TCGv_ptr arg2,
                                  tcg_target_long offset)
{
    tcg_gen_ldst_op_i64(INDEX_op_ld_i64, ret, arg2, offset);
}

static inline void tcg_gen_st8_i64(TCGv_i64 arg1, TCGv_ptr arg2,
                                   tcg_target_long offset)
{
    tcg_gen_ldst_op_i64(INDEX_op_st8_i64, arg1, arg2, offset);
}

static inline void tcg_gen_st16_i64(TCGv_i64 arg1, TCGv_ptr arg2,
                                    tcg_target_long offset)
{
    tcg_gen_ldst_op_i64(INDEX_op_st16_i64, arg1, arg2, offset);
}

static inline void tcg_gen_st32_i64(TCGv_i64 arg1, TCGv_ptr arg2,
                                    tcg_target_long offset)
{
    tcg_gen_ldst_op_i64(INDEX_op_st32_i64, arg1, arg2, offset);
}

static inline void tcg_gen_st_i64(TCGv_i64 arg1, TCGv_ptr arg2,
                                  tcg_target_long offset)
{
    tcg_gen_ldst_op_i64(INDEX_op_st_i64, arg1, arg2, offset);
}

static inline void tcg_gen_add_i64(TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
    tcg_gen_op3_i64(INDEX_op_add_i64, ret, arg1, arg2);
}

static inline void tcg_gen_sub_i64(TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
    tcg_gen_op3_i64(INDEX_op_sub_i64, ret, arg1, arg2);
}

static inline void tcg_gen_and_i64(TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
    tcg_gen_op3_i64(INDEX_op_and_i64, ret, arg1, arg2);
}

static inline void tcg_gen_or_i64(TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
    tcg_gen_op3_i64(INDEX_op_or_i64, ret, arg1, arg2);
}

static inline void tcg_gen_xor_i64(TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
    tcg_gen_op3_i64(INDEX_op_xor_i64, ret, arg1, arg2);
}

static inline void tcg_gen_shl_i64(TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
    tcg_gen_op3_i64(INDEX_op_shl_i64, ret, arg1, arg2);
}

static inline void tcg_gen_shr_i64(TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
    tcg_gen_op3_i64(INDEX_op_shr_i64, ret, arg1, arg2);
}

static inline void tcg_gen_sar_i64(TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
    tcg_gen_op3_i64(INDEX_op_sar_i64, ret, arg1, arg2);
}

static inline void tcg_gen_mul_i64(TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
    tcg_gen_op3_i64(INDEX_op_mul_i64, ret, arg1, arg2);
}

static inline void tcg_gen_neg_i64(TCGv_i64 ret, TCGv_i64 arg)
{
    if (TCG_TARGET_HAS_neg_i64) {
        tcg_gen_op2_i64(INDEX_op_neg_i64, ret, arg);
    } else {
        tcg_gen_subfi_i64(ret, 0, arg);
    }
}

void tcg_gen_extu_i32_i64(TCGv_i64 ret, TCGv_i32 arg);

void tcg_gen_ext_i32_i64(TCGv_i64 ret, TCGv_i32 arg);

void tcg_gen_extrl_i64_i32(TCGv_i32 ret, TCGv_i64 arg);

void tcg_gen_extr_i64_i32(TCGv_i32 lo, TCGv_i32 hi, TCGv_i64 arg);

void tcg_gen_extr32_i64(TCGv_i64 lo, TCGv_i64 hi, TCGv_i64 arg);

static inline void tcg_gen_concat32_i64(TCGv_i64 ret, TCGv_i64 lo, TCGv_i64 hi)
{
    tcg_gen_deposit_i64(ret, lo, hi, 32, 32);
}

static inline void tcg_gen_insn_start(target_ulong pc, target_ulong a1)
{
    tcg_gen_op2(INDEX_op_insn_start, pc, a1);
}

static inline void tcg_gen_exit_tb(uintptr_t val)
{
    tcg_gen_op1i(INDEX_op_exit_tb, val);
}

void tcg_gen_goto_tb(unsigned idx);

#define tcg_temp_new() tcg_temp_new_i64()

#define tcg_temp_local_new() tcg_temp_local_new_i64()

#define tcg_temp_free tcg_temp_free_i64

#define TCGV_UNUSED(x) TCGV_UNUSED_I64(x)

#define TCGV_IS_UNUSED(x) TCGV_IS_UNUSED_I64(x)

#define tcg_gen_qemu_ld_tl tcg_gen_qemu_ld_i64

#define tcg_gen_qemu_st_tl tcg_gen_qemu_st_i64

void tcg_gen_lookup_and_goto_ptr(void);

void tcg_gen_qemu_ld_i32(TCGv_i32, TCGv, TCGArg, TCGMemOp);

void tcg_gen_qemu_st_i32(TCGv_i32, TCGv, TCGArg, TCGMemOp);

void tcg_gen_qemu_ld_i64(TCGv_i64, TCGv, TCGArg, TCGMemOp);

void tcg_gen_qemu_st_i64(TCGv_i64, TCGv, TCGArg, TCGMemOp);

void tcg_gen_atomic_cmpxchg_i64(TCGv_i64, TCGv, TCGv_i64, TCGv_i64,
                                TCGArg, TCGMemOp);

void tcg_gen_atomic_xchg_i64(TCGv_i64, TCGv, TCGv_i64, TCGArg, TCGMemOp);

void tcg_gen_atomic_fetch_add_i64(TCGv_i64, TCGv, TCGv_i64, TCGArg, TCGMemOp);

void tcg_gen_atomic_fetch_and_i64(TCGv_i64, TCGv, TCGv_i64, TCGArg, TCGMemOp);

void tcg_gen_atomic_fetch_or_i64(TCGv_i64, TCGv, TCGv_i64, TCGArg, TCGMemOp);

void tcg_gen_atomic_fetch_xor_i64(TCGv_i64, TCGv, TCGv_i64, TCGArg, TCGMemOp);

void tcg_gen_atomic_add_fetch_i64(TCGv_i64, TCGv, TCGv_i64, TCGArg, TCGMemOp);

void tcg_gen_atomic_and_fetch_i64(TCGv_i64, TCGv, TCGv_i64, TCGArg, TCGMemOp);

void tcg_gen_atomic_or_fetch_i64(TCGv_i64, TCGv, TCGv_i64, TCGArg, TCGMemOp);

#define tcg_gen_movi_tl tcg_gen_movi_i64

#define tcg_gen_mov_tl tcg_gen_mov_i64

#define tcg_gen_ld8u_tl tcg_gen_ld8u_i64

#define tcg_gen_ld16u_tl tcg_gen_ld16u_i64

#define tcg_gen_ld32u_tl tcg_gen_ld32u_i64

#define tcg_gen_ld32s_tl tcg_gen_ld32s_i64

#define tcg_gen_ld_tl tcg_gen_ld_i64

#define tcg_gen_st8_tl tcg_gen_st8_i64

#define tcg_gen_st16_tl tcg_gen_st16_i64

#define tcg_gen_st32_tl tcg_gen_st32_i64

#define tcg_gen_st_tl tcg_gen_st_i64

#define tcg_gen_add_tl tcg_gen_add_i64

#define tcg_gen_addi_tl tcg_gen_addi_i64

#define tcg_gen_sub_tl tcg_gen_sub_i64

#define tcg_gen_neg_tl tcg_gen_neg_i64

#define tcg_gen_subfi_tl tcg_gen_subfi_i64

#define tcg_gen_subi_tl tcg_gen_subi_i64

#define tcg_gen_and_tl tcg_gen_and_i64

#define tcg_gen_andi_tl tcg_gen_andi_i64

#define tcg_gen_or_tl tcg_gen_or_i64

#define tcg_gen_ori_tl tcg_gen_ori_i64

#define tcg_gen_xor_tl tcg_gen_xor_i64

#define tcg_gen_xori_tl tcg_gen_xori_i64

#define tcg_gen_not_tl tcg_gen_not_i64

#define tcg_gen_shl_tl tcg_gen_shl_i64

#define tcg_gen_shli_tl tcg_gen_shli_i64

#define tcg_gen_shr_tl tcg_gen_shr_i64

#define tcg_gen_shri_tl tcg_gen_shri_i64

#define tcg_gen_sar_tl tcg_gen_sar_i64

#define tcg_gen_sari_tl tcg_gen_sari_i64

#define tcg_gen_brcond_tl tcg_gen_brcond_i64

#define tcg_gen_brcondi_tl tcg_gen_brcondi_i64

#define tcg_gen_setcond_tl tcg_gen_setcond_i64

#define tcg_gen_setcondi_tl tcg_gen_setcondi_i64

#define tcg_gen_mul_tl tcg_gen_mul_i64

#define tcg_gen_muli_tl tcg_gen_muli_i64

#define tcg_gen_discard_tl tcg_gen_discard_i64

#define tcg_gen_trunc_tl_i32 tcg_gen_extrl_i64_i32

#define tcg_gen_extu_i32_tl tcg_gen_extu_i32_i64

#define tcg_gen_extu_tl_i64 tcg_gen_mov_i64

#define tcg_gen_ext8u_tl tcg_gen_ext8u_i64

#define tcg_gen_ext8s_tl tcg_gen_ext8s_i64

#define tcg_gen_ext16u_tl tcg_gen_ext16u_i64

#define tcg_gen_ext16s_tl tcg_gen_ext16s_i64

#define tcg_gen_ext32u_tl tcg_gen_ext32u_i64

#define tcg_gen_ext32s_tl tcg_gen_ext32s_i64

#define tcg_gen_bswap32_tl tcg_gen_bswap32_i64

#define tcg_gen_concat_tl_i64 tcg_gen_concat32_i64

#define tcg_gen_extr_i64_tl tcg_gen_extr32_i64

#define tcg_gen_andc_tl tcg_gen_andc_i64

#define tcg_gen_clz_tl tcg_gen_clz_i64

#define tcg_gen_ctz_tl tcg_gen_ctz_i64

#define tcg_gen_clzi_tl tcg_gen_clzi_i64

#define tcg_gen_ctzi_tl tcg_gen_ctzi_i64

#define tcg_gen_ctpop_tl tcg_gen_ctpop_i64

#define tcg_gen_rotl_tl tcg_gen_rotl_i64

#define tcg_gen_rotli_tl tcg_gen_rotli_i64

#define tcg_gen_rotr_tl tcg_gen_rotr_i64

#define tcg_gen_rotri_tl tcg_gen_rotri_i64

#define tcg_gen_deposit_tl tcg_gen_deposit_i64

#define tcg_gen_extract_tl tcg_gen_extract_i64

#define tcg_gen_sextract_tl tcg_gen_sextract_i64

#define tcg_const_tl tcg_const_i64

#define tcg_gen_movcond_tl tcg_gen_movcond_i64

#define tcg_gen_add2_tl tcg_gen_add2_i64

#define tcg_gen_atomic_cmpxchg_tl tcg_gen_atomic_cmpxchg_i64

#define tcg_gen_atomic_xchg_tl tcg_gen_atomic_xchg_i64

#define tcg_gen_atomic_fetch_add_tl tcg_gen_atomic_fetch_add_i64

#define tcg_gen_atomic_fetch_and_tl tcg_gen_atomic_fetch_and_i64

#define tcg_gen_atomic_fetch_or_tl tcg_gen_atomic_fetch_or_i64

#define tcg_gen_atomic_fetch_xor_tl tcg_gen_atomic_fetch_xor_i64

#define tcg_gen_atomic_add_fetch_tl tcg_gen_atomic_add_fetch_i64

#define tcg_gen_atomic_and_fetch_tl tcg_gen_atomic_and_fetch_i64

#define tcg_gen_atomic_or_fetch_tl tcg_gen_atomic_or_fetch_i64

#define tcg_gen_atomic_xor_fetch_tl tcg_gen_atomic_xor_fetch_i64

# define tcg_gen_addi_ptr(R, A, B) \
    tcg_gen_addi_i64(TCGV_PTR_TO_NAT(R), TCGV_PTR_TO_NAT(A), (B))

void tcg_gen_atomic_xor_fetch_i64(TCGv_i64, TCGv, TCGv_i64, TCGArg, TCGMemOp);

typedef struct TraceEvent {
    uint32_t id;
    uint32_t vcpu_id;
    const char * name;
    const bool sstate;
    uint16_t *dstate;
} TraceEvent;

#define trace_event_get_vcpu_state(vcpu, id)                            \
    ((id ##_ENABLED) &&                                                 \
     trace_event_get_vcpu_state_dynamic_by_vcpu_id(                     \
         vcpu, _ ## id ## _EVENT.vcpu_id))

extern int trace_events_enabled_count;

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

extern TraceEvent _TRACE_GUEST_MEM_BEFORE_TRANS_EVENT;

extern TraceEvent _TRACE_GUEST_MEM_BEFORE_EXEC_EVENT;

#define TRACE_GUEST_MEM_BEFORE_TRANS_ENABLED 1

#define TRACE_GUEST_MEM_BEFORE_EXEC_ENABLED 1

static inline void _nocheck__trace_guest_mem_before_trans(CPUState * __cpu, uint8_t info)
{
}

static inline void trace_guest_mem_before_trans(CPUState * __cpu, uint8_t info)
{
    if (trace_event_get_vcpu_state(__cpu, TRACE_GUEST_MEM_BEFORE_TRANS)) {
        _nocheck__trace_guest_mem_before_trans(__cpu, info);
    }
}

static inline void trace_guest_mem_before_tcg(CPUState * __cpu, TCGv_env __tcg___cpu, TCGv vaddr, uint8_t info)
{
    trace_guest_mem_before_trans(__cpu, info);
    if (trace_event_get_vcpu_state(__cpu, TRACE_GUEST_MEM_BEFORE_EXEC)) {
        gen_helper_trace_guest_mem_before_exec(__tcg___cpu, vaddr, info);
    }
}

static inline uint8_t trace_mem_get_info(TCGMemOp op, bool store)
{
    uint8_t res = op;
    bool be = (op & MO_BSWAP) == MO_BE;

    /* remove untraced fields */
    res &= (1ULL << 4) - 1;
    /* make endianness absolute */
    res &= ~MO_BSWAP;
    if (be) {
        res |= 1ULL << 3;
    }
    /* add fields */
    if (store) {
        res |= 1ULL << 4;
    }

    return res;
}

extern TCGv_i32 TCGV_LOW_link_error(TCGv_i64);

#define TCGV_LOW  TCGV_LOW_link_error

#define TCGV_HIGH TCGV_HIGH_link_error

extern TCGv_i32 TCGV_HIGH_link_error(TCGv_i64);

static inline TCGOp *tcg_emit_op(TCGOpcode opc)
{
    TCGContext *ctx = tcg_ctx;
    int oi = ctx->gen_next_op_idx;
    int ni = oi + 1;
    int pi = oi - 1;
    TCGOp *op = &ctx->gen_op_buf[oi];

    tcg_debug_assert(oi < OPC_BUF_SIZE);
    ctx->gen_op_buf[0].prev = oi;
    ctx->gen_next_op_idx = ni;

    memset(op, 0, offsetof(TCGOp, args));
    op->opc = opc;
    op->prev = pi;
    op->next = ni;

    return op;
}

void tcg_gen_op1(TCGOpcode opc, TCGArg a1)
{
    TCGOp *op = tcg_emit_op(opc);
    op->args[0] = a1;
}

void tcg_gen_op2(TCGOpcode opc, TCGArg a1, TCGArg a2)
{
    TCGOp *op = tcg_emit_op(opc);
    op->args[0] = a1;
    op->args[1] = a2;
}

void tcg_gen_op3(TCGOpcode opc, TCGArg a1, TCGArg a2, TCGArg a3)
{
    TCGOp *op = tcg_emit_op(opc);
    op->args[0] = a1;
    op->args[1] = a2;
    op->args[2] = a3;
}

void tcg_gen_op4(TCGOpcode opc, TCGArg a1, TCGArg a2, TCGArg a3, TCGArg a4)
{
    TCGOp *op = tcg_emit_op(opc);
    op->args[0] = a1;
    op->args[1] = a2;
    op->args[2] = a3;
    op->args[3] = a4;
}

void tcg_gen_op5(TCGOpcode opc, TCGArg a1, TCGArg a2, TCGArg a3,
                 TCGArg a4, TCGArg a5)
{
    TCGOp *op = tcg_emit_op(opc);
    op->args[0] = a1;
    op->args[1] = a2;
    op->args[2] = a3;
    op->args[3] = a4;
    op->args[4] = a5;
}

void tcg_gen_op6(TCGOpcode opc, TCGArg a1, TCGArg a2, TCGArg a3,
                 TCGArg a4, TCGArg a5, TCGArg a6)
{
    TCGOp *op = tcg_emit_op(opc);
    op->args[0] = a1;
    op->args[1] = a2;
    op->args[2] = a3;
    op->args[3] = a4;
    op->args[4] = a5;
    op->args[5] = a6;
}

void tcg_gen_mb(TCGBar mb_type)
{
    if (tcg_ctx->tb_cflags & CF_PARALLEL) {
        tcg_gen_op1(INDEX_op_mb, mb_type);
    }
}

void tcg_gen_addi_i32(TCGv_i32 ret, TCGv_i32 arg1, int32_t arg2)
{
    /* some cases can be optimized here */
    if (arg2 == 0) {
        tcg_gen_mov_i32(ret, arg1);
    } else {
        TCGv_i32 t0 = tcg_const_i32(arg2);
        tcg_gen_add_i32(ret, arg1, t0);
        tcg_temp_free_i32(t0);
    }
}

void tcg_gen_subfi_i32(TCGv_i32 ret, int32_t arg1, TCGv_i32 arg2)
{
    if (arg1 == 0 && TCG_TARGET_HAS_neg_i32) {
        /* Don't recurse with tcg_gen_neg_i32.  */
        tcg_gen_op2_i32(INDEX_op_neg_i32, ret, arg2);
    } else {
        TCGv_i32 t0 = tcg_const_i32(arg1);
        tcg_gen_sub_i32(ret, t0, arg2);
        tcg_temp_free_i32(t0);
    }
}

void tcg_gen_subi_i32(TCGv_i32 ret, TCGv_i32 arg1, int32_t arg2)
{
    /* some cases can be optimized here */
    if (arg2 == 0) {
        tcg_gen_mov_i32(ret, arg1);
    } else {
        TCGv_i32 t0 = tcg_const_i32(arg2);
        tcg_gen_sub_i32(ret, arg1, t0);
        tcg_temp_free_i32(t0);
    }
}

void tcg_gen_andi_i32(TCGv_i32 ret, TCGv_i32 arg1, uint32_t arg2)
{
    TCGv_i32 t0;
    /* Some cases can be optimized here.  */
    switch (arg2) {
    case 0:
        tcg_gen_movi_i32(ret, 0);
        return;
    case 0xffffffffu:
        tcg_gen_mov_i32(ret, arg1);
        return;
    case 0xffu:
        /* Don't recurse with tcg_gen_ext8u_i32.  */
        if (TCG_TARGET_HAS_ext8u_i32) {
            tcg_gen_op2_i32(INDEX_op_ext8u_i32, ret, arg1);
            return;
        }
        break;
    case 0xffffu:
        if (TCG_TARGET_HAS_ext16u_i32) {
            tcg_gen_op2_i32(INDEX_op_ext16u_i32, ret, arg1);
            return;
        }
        break;
    }
    t0 = tcg_const_i32(arg2);
    tcg_gen_and_i32(ret, arg1, t0);
    tcg_temp_free_i32(t0);
}

void tcg_gen_ori_i32(TCGv_i32 ret, TCGv_i32 arg1, int32_t arg2)
{
    /* Some cases can be optimized here.  */
    if (arg2 == -1) {
        tcg_gen_movi_i32(ret, -1);
    } else if (arg2 == 0) {
        tcg_gen_mov_i32(ret, arg1);
    } else {
        TCGv_i32 t0 = tcg_const_i32(arg2);
        tcg_gen_or_i32(ret, arg1, t0);
        tcg_temp_free_i32(t0);
    }
}

void tcg_gen_xori_i32(TCGv_i32 ret, TCGv_i32 arg1, int32_t arg2)
{
    /* Some cases can be optimized here.  */
    if (arg2 == 0) {
        tcg_gen_mov_i32(ret, arg1);
    } else if (arg2 == -1 && TCG_TARGET_HAS_not_i32) {
        /* Don't recurse with tcg_gen_not_i32.  */
        tcg_gen_op2_i32(INDEX_op_not_i32, ret, arg1);
    } else {
        TCGv_i32 t0 = tcg_const_i32(arg2);
        tcg_gen_xor_i32(ret, arg1, t0);
        tcg_temp_free_i32(t0);
    }
}

void tcg_gen_shli_i32(TCGv_i32 ret, TCGv_i32 arg1, unsigned arg2)
{
    tcg_debug_assert(arg2 < 32);
    if (arg2 == 0) {
        tcg_gen_mov_i32(ret, arg1);
    } else {
        TCGv_i32 t0 = tcg_const_i32(arg2);
        tcg_gen_shl_i32(ret, arg1, t0);
        tcg_temp_free_i32(t0);
    }
}

void tcg_gen_shri_i32(TCGv_i32 ret, TCGv_i32 arg1, unsigned arg2)
{
    tcg_debug_assert(arg2 < 32);
    if (arg2 == 0) {
        tcg_gen_mov_i32(ret, arg1);
    } else {
        TCGv_i32 t0 = tcg_const_i32(arg2);
        tcg_gen_shr_i32(ret, arg1, t0);
        tcg_temp_free_i32(t0);
    }
}

void tcg_gen_sari_i32(TCGv_i32 ret, TCGv_i32 arg1, unsigned arg2)
{
    tcg_debug_assert(arg2 < 32);
    if (arg2 == 0) {
        tcg_gen_mov_i32(ret, arg1);
    } else {
        TCGv_i32 t0 = tcg_const_i32(arg2);
        tcg_gen_sar_i32(ret, arg1, t0);
        tcg_temp_free_i32(t0);
    }
}

void tcg_gen_setcond_i32(TCGCond cond, TCGv_i32 ret,
                         TCGv_i32 arg1, TCGv_i32 arg2)
{
    if (cond == TCG_COND_ALWAYS) {
        tcg_gen_movi_i32(ret, 1);
    } else if (cond == TCG_COND_NEVER) {
        tcg_gen_movi_i32(ret, 0);
    } else {
        tcg_gen_op4i_i32(INDEX_op_setcond_i32, ret, arg1, arg2, cond);
    }
}

void tcg_gen_andc_i32(TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    if (TCG_TARGET_HAS_andc_i32) {
        tcg_gen_op3_i32(INDEX_op_andc_i32, ret, arg1, arg2);
    } else {
        TCGv_i32 t0 = tcg_temp_new_i32();
        tcg_gen_not_i32(t0, arg2);
        tcg_gen_and_i32(ret, arg1, t0);
        tcg_temp_free_i32(t0);
    }
}

void tcg_gen_clz_i32(TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    if (TCG_TARGET_HAS_clz_i32) {
        tcg_gen_op3_i32(INDEX_op_clz_i32, ret, arg1, arg2);
    } else if (TCG_TARGET_HAS_clz_i64) {
        TCGv_i64 t1 = tcg_temp_new_i64();
        TCGv_i64 t2 = tcg_temp_new_i64();
        tcg_gen_extu_i32_i64(t1, arg1);
        tcg_gen_extu_i32_i64(t2, arg2);
        tcg_gen_addi_i64(t2, t2, 32);
        tcg_gen_clz_i64(t1, t1, t2);
        tcg_gen_extrl_i64_i32(ret, t1);
        tcg_temp_free_i64(t1);
        tcg_temp_free_i64(t2);
        tcg_gen_subi_i32(ret, ret, 32);
    } else {
        gen_helper_clz_i32(ret, arg1, arg2);
    }
}

void tcg_gen_clzi_i32(TCGv_i32 ret, TCGv_i32 arg1, uint32_t arg2)
{
    TCGv_i32 t = tcg_const_i32(arg2);
    tcg_gen_clz_i32(ret, arg1, t);
    tcg_temp_free_i32(t);
}

void tcg_gen_ctz_i32(TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    if (TCG_TARGET_HAS_ctz_i32) {
        tcg_gen_op3_i32(INDEX_op_ctz_i32, ret, arg1, arg2);
    } else if (TCG_TARGET_HAS_ctz_i64) {
        TCGv_i64 t1 = tcg_temp_new_i64();
        TCGv_i64 t2 = tcg_temp_new_i64();
        tcg_gen_extu_i32_i64(t1, arg1);
        tcg_gen_extu_i32_i64(t2, arg2);
        tcg_gen_ctz_i64(t1, t1, t2);
        tcg_gen_extrl_i64_i32(ret, t1);
        tcg_temp_free_i64(t1);
        tcg_temp_free_i64(t2);
    } else if (TCG_TARGET_HAS_ctpop_i32
               || TCG_TARGET_HAS_ctpop_i64
               || TCG_TARGET_HAS_clz_i32
               || TCG_TARGET_HAS_clz_i64) {
        TCGv_i32 z, t = tcg_temp_new_i32();

        if (TCG_TARGET_HAS_ctpop_i32 || TCG_TARGET_HAS_ctpop_i64) {
            tcg_gen_subi_i32(t, arg1, 1);
            tcg_gen_andc_i32(t, t, arg1);
            tcg_gen_ctpop_i32(t, t);
        } else {
            /* Since all non-x86 hosts have clz(0) == 32, don't fight it.  */
            tcg_gen_neg_i32(t, arg1);
            tcg_gen_and_i32(t, t, arg1);
            tcg_gen_clzi_i32(t, t, 32);
            tcg_gen_xori_i32(t, t, 31);
        }
        z = tcg_const_i32(0);
        tcg_gen_movcond_i32(TCG_COND_EQ, ret, arg1, z, arg2, t);
        tcg_temp_free_i32(t);
        tcg_temp_free_i32(z);
    } else {
        gen_helper_ctz_i32(ret, arg1, arg2);
    }
}

void tcg_gen_ctpop_i32(TCGv_i32 ret, TCGv_i32 arg1)
{
    if (TCG_TARGET_HAS_ctpop_i32) {
        tcg_gen_op2_i32(INDEX_op_ctpop_i32, ret, arg1);
    } else if (TCG_TARGET_HAS_ctpop_i64) {
        TCGv_i64 t = tcg_temp_new_i64();
        tcg_gen_extu_i32_i64(t, arg1);
        tcg_gen_ctpop_i64(t, t);
        tcg_gen_extrl_i64_i32(ret, t);
        tcg_temp_free_i64(t);
    } else {
        gen_helper_ctpop_i32(ret, arg1);
    }
}

void tcg_gen_rotl_i32(TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    if (TCG_TARGET_HAS_rot_i32) {
        tcg_gen_op3_i32(INDEX_op_rotl_i32, ret, arg1, arg2);
    } else {
        TCGv_i32 t0, t1;

        t0 = tcg_temp_new_i32();
        t1 = tcg_temp_new_i32();
        tcg_gen_shl_i32(t0, arg1, arg2);
        tcg_gen_subfi_i32(t1, 32, arg2);
        tcg_gen_shr_i32(t1, arg1, t1);
        tcg_gen_or_i32(ret, t0, t1);
        tcg_temp_free_i32(t0);
        tcg_temp_free_i32(t1);
    }
}

void tcg_gen_rotli_i32(TCGv_i32 ret, TCGv_i32 arg1, unsigned arg2)
{
    tcg_debug_assert(arg2 < 32);
    /* some cases can be optimized here */
    if (arg2 == 0) {
        tcg_gen_mov_i32(ret, arg1);
    } else if (TCG_TARGET_HAS_rot_i32) {
        TCGv_i32 t0 = tcg_const_i32(arg2);
        tcg_gen_rotl_i32(ret, arg1, t0);
        tcg_temp_free_i32(t0);
    } else {
        TCGv_i32 t0, t1;
        t0 = tcg_temp_new_i32();
        t1 = tcg_temp_new_i32();
        tcg_gen_shli_i32(t0, arg1, arg2);
        tcg_gen_shri_i32(t1, arg1, 32 - arg2);
        tcg_gen_or_i32(ret, t0, t1);
        tcg_temp_free_i32(t0);
        tcg_temp_free_i32(t1);
    }
}

void tcg_gen_rotr_i32(TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    if (TCG_TARGET_HAS_rot_i32) {
        tcg_gen_op3_i32(INDEX_op_rotr_i32, ret, arg1, arg2);
    } else {
        TCGv_i32 t0, t1;

        t0 = tcg_temp_new_i32();
        t1 = tcg_temp_new_i32();
        tcg_gen_shr_i32(t0, arg1, arg2);
        tcg_gen_subfi_i32(t1, 32, arg2);
        tcg_gen_shl_i32(t1, arg1, t1);
        tcg_gen_or_i32(ret, t0, t1);
        tcg_temp_free_i32(t0);
        tcg_temp_free_i32(t1);
    }
}

void tcg_gen_rotri_i32(TCGv_i32 ret, TCGv_i32 arg1, unsigned arg2)
{
    tcg_debug_assert(arg2 < 32);
    /* some cases can be optimized here */
    if (arg2 == 0) {
        tcg_gen_mov_i32(ret, arg1);
    } else {
        tcg_gen_rotli_i32(ret, arg1, 32 - arg2);
    }
}

void tcg_gen_deposit_i32(TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2,
                         unsigned int ofs, unsigned int len)
{
    uint32_t mask;
    TCGv_i32 t1;

    tcg_debug_assert(ofs < 32);
    tcg_debug_assert(len > 0);
    tcg_debug_assert(len <= 32);
    tcg_debug_assert(ofs + len <= 32);

    if (len == 32) {
        tcg_gen_mov_i32(ret, arg2);
        return;
    }
    if (TCG_TARGET_HAS_deposit_i32 && TCG_TARGET_deposit_i32_valid(ofs, len)) {
        tcg_gen_op5ii_i32(INDEX_op_deposit_i32, ret, arg1, arg2, ofs, len);
        return;
    }

    mask = (1u << len) - 1;
    t1 = tcg_temp_new_i32();

    if (ofs + len < 32) {
        tcg_gen_andi_i32(t1, arg2, mask);
        tcg_gen_shli_i32(t1, t1, ofs);
    } else {
        tcg_gen_shli_i32(t1, arg2, ofs);
    }
    tcg_gen_andi_i32(ret, arg1, ~(mask << ofs));
    tcg_gen_or_i32(ret, ret, t1);

    tcg_temp_free_i32(t1);
}

void tcg_gen_extract_i32(TCGv_i32 ret, TCGv_i32 arg,
                         unsigned int ofs, unsigned int len)
{
    tcg_debug_assert(ofs < 32);
    tcg_debug_assert(len > 0);
    tcg_debug_assert(len <= 32);
    tcg_debug_assert(ofs + len <= 32);

    /* Canonicalize certain special cases, even if extract is supported.  */
    if (ofs + len == 32) {
        tcg_gen_shri_i32(ret, arg, 32 - len);
        return;
    }
    if (ofs == 0) {
        tcg_gen_andi_i32(ret, arg, (1u << len) - 1);
        return;
    }

    if (TCG_TARGET_HAS_extract_i32
        && TCG_TARGET_extract_i32_valid(ofs, len)) {
        tcg_gen_op4ii_i32(INDEX_op_extract_i32, ret, arg, ofs, len);
        return;
    }

    /* Assume that zero-extension, if available, is cheaper than a shift.  */
    switch (ofs + len) {
    case 16:
        if (TCG_TARGET_HAS_ext16u_i32) {
            tcg_gen_ext16u_i32(ret, arg);
            tcg_gen_shri_i32(ret, ret, ofs);
            return;
        }
        break;
    case 8:
        if (TCG_TARGET_HAS_ext8u_i32) {
            tcg_gen_ext8u_i32(ret, arg);
            tcg_gen_shri_i32(ret, ret, ofs);
            return;
        }
        break;
    }

    /* ??? Ideally we'd know what values are available for immediate AND.
       Assume that 8 bits are available, plus the special case of 16,
       so that we get ext8u, ext16u.  */
    switch (len) {
    case 1 ... 8: case 16:
        tcg_gen_shri_i32(ret, arg, ofs);
        tcg_gen_andi_i32(ret, ret, (1u << len) - 1);
        break;
    default:
        tcg_gen_shli_i32(ret, arg, 32 - len - ofs);
        tcg_gen_shri_i32(ret, ret, 32 - len);
        break;
    }
}

void tcg_gen_sextract_i32(TCGv_i32 ret, TCGv_i32 arg,
                          unsigned int ofs, unsigned int len)
{
    tcg_debug_assert(ofs < 32);
    tcg_debug_assert(len > 0);
    tcg_debug_assert(len <= 32);
    tcg_debug_assert(ofs + len <= 32);

    /* Canonicalize certain special cases, even if extract is supported.  */
    if (ofs + len == 32) {
        tcg_gen_sari_i32(ret, arg, 32 - len);
        return;
    }
    if (ofs == 0) {
        switch (len) {
        case 16:
            tcg_gen_ext16s_i32(ret, arg);
            return;
        case 8:
            tcg_gen_ext8s_i32(ret, arg);
            return;
        }
    }

    if (TCG_TARGET_HAS_sextract_i32
        && TCG_TARGET_extract_i32_valid(ofs, len)) {
        tcg_gen_op4ii_i32(INDEX_op_sextract_i32, ret, arg, ofs, len);
        return;
    }

    /* Assume that sign-extension, if available, is cheaper than a shift.  */
    switch (ofs + len) {
    case 16:
        if (TCG_TARGET_HAS_ext16s_i32) {
            tcg_gen_ext16s_i32(ret, arg);
            tcg_gen_sari_i32(ret, ret, ofs);
            return;
        }
        break;
    case 8:
        if (TCG_TARGET_HAS_ext8s_i32) {
            tcg_gen_ext8s_i32(ret, arg);
            tcg_gen_sari_i32(ret, ret, ofs);
            return;
        }
        break;
    }
    switch (len) {
    case 16:
        if (TCG_TARGET_HAS_ext16s_i32) {
            tcg_gen_shri_i32(ret, arg, ofs);
            tcg_gen_ext16s_i32(ret, ret);
            return;
        }
        break;
    case 8:
        if (TCG_TARGET_HAS_ext8s_i32) {
            tcg_gen_shri_i32(ret, arg, ofs);
            tcg_gen_ext8s_i32(ret, ret);
            return;
        }
        break;
    }

    tcg_gen_shli_i32(ret, arg, 32 - len - ofs);
    tcg_gen_sari_i32(ret, ret, 32 - len);
}

void tcg_gen_movcond_i32(TCGCond cond, TCGv_i32 ret, TCGv_i32 c1,
                         TCGv_i32 c2, TCGv_i32 v1, TCGv_i32 v2)
{
    if (cond == TCG_COND_ALWAYS) {
        tcg_gen_mov_i32(ret, v1);
    } else if (cond == TCG_COND_NEVER) {
        tcg_gen_mov_i32(ret, v2);
    } else if (TCG_TARGET_HAS_movcond_i32) {
        tcg_gen_op6i_i32(INDEX_op_movcond_i32, ret, c1, c2, v1, v2, cond);
    } else {
        TCGv_i32 t0 = tcg_temp_new_i32();
        TCGv_i32 t1 = tcg_temp_new_i32();
        tcg_gen_setcond_i32(cond, t0, c1, c2);
        tcg_gen_neg_i32(t0, t0);
        tcg_gen_and_i32(t1, v1, t0);
        tcg_gen_andc_i32(ret, v2, t0);
        tcg_gen_or_i32(ret, ret, t1);
        tcg_temp_free_i32(t0);
        tcg_temp_free_i32(t1);
    }
}

void tcg_gen_mulu2_i32(TCGv_i32 rl, TCGv_i32 rh, TCGv_i32 arg1, TCGv_i32 arg2)
{
    if (TCG_TARGET_HAS_mulu2_i32) {
        tcg_gen_op4_i32(INDEX_op_mulu2_i32, rl, rh, arg1, arg2);
    } else if (TCG_TARGET_HAS_muluh_i32) {
        TCGv_i32 t = tcg_temp_new_i32();
        tcg_gen_op3_i32(INDEX_op_mul_i32, t, arg1, arg2);
        tcg_gen_op3_i32(INDEX_op_muluh_i32, rh, arg1, arg2);
        tcg_gen_mov_i32(rl, t);
        tcg_temp_free_i32(t);
    } else {
        TCGv_i64 t0 = tcg_temp_new_i64();
        TCGv_i64 t1 = tcg_temp_new_i64();
        tcg_gen_extu_i32_i64(t0, arg1);
        tcg_gen_extu_i32_i64(t1, arg2);
        tcg_gen_mul_i64(t0, t0, t1);
        tcg_gen_extr_i64_i32(rl, rh, t0);
        tcg_temp_free_i64(t0);
        tcg_temp_free_i64(t1);
    }
}

void tcg_gen_muls2_i32(TCGv_i32 rl, TCGv_i32 rh, TCGv_i32 arg1, TCGv_i32 arg2)
{
    if (TCG_TARGET_HAS_muls2_i32) {
        tcg_gen_op4_i32(INDEX_op_muls2_i32, rl, rh, arg1, arg2);
    } else if (TCG_TARGET_HAS_mulsh_i32) {
        TCGv_i32 t = tcg_temp_new_i32();
        tcg_gen_op3_i32(INDEX_op_mul_i32, t, arg1, arg2);
        tcg_gen_op3_i32(INDEX_op_mulsh_i32, rh, arg1, arg2);
        tcg_gen_mov_i32(rl, t);
        tcg_temp_free_i32(t);
    } else if (TCG_TARGET_REG_BITS == 32) {
        TCGv_i32 t0 = tcg_temp_new_i32();
        TCGv_i32 t1 = tcg_temp_new_i32();
        TCGv_i32 t2 = tcg_temp_new_i32();
        TCGv_i32 t3 = tcg_temp_new_i32();
        tcg_gen_mulu2_i32(t0, t1, arg1, arg2);
        /* Adjust for negative inputs.  */
        tcg_gen_sari_i32(t2, arg1, 31);
        tcg_gen_sari_i32(t3, arg2, 31);
        tcg_gen_and_i32(t2, t2, arg2);
        tcg_gen_and_i32(t3, t3, arg1);
        tcg_gen_sub_i32(rh, t1, t2);
        tcg_gen_sub_i32(rh, rh, t3);
        tcg_gen_mov_i32(rl, t0);
        tcg_temp_free_i32(t0);
        tcg_temp_free_i32(t1);
        tcg_temp_free_i32(t2);
        tcg_temp_free_i32(t3);
    } else {
        TCGv_i64 t0 = tcg_temp_new_i64();
        TCGv_i64 t1 = tcg_temp_new_i64();
        tcg_gen_ext_i32_i64(t0, arg1);
        tcg_gen_ext_i32_i64(t1, arg2);
        tcg_gen_mul_i64(t0, t0, t1);
        tcg_gen_extr_i64_i32(rl, rh, t0);
        tcg_temp_free_i64(t0);
        tcg_temp_free_i64(t1);
    }
}

void tcg_gen_ext8s_i32(TCGv_i32 ret, TCGv_i32 arg)
{
    if (TCG_TARGET_HAS_ext8s_i32) {
        tcg_gen_op2_i32(INDEX_op_ext8s_i32, ret, arg);
    } else {
        tcg_gen_shli_i32(ret, arg, 24);
        tcg_gen_sari_i32(ret, ret, 24);
    }
}

void tcg_gen_ext16s_i32(TCGv_i32 ret, TCGv_i32 arg)
{
    if (TCG_TARGET_HAS_ext16s_i32) {
        tcg_gen_op2_i32(INDEX_op_ext16s_i32, ret, arg);
    } else {
        tcg_gen_shli_i32(ret, arg, 16);
        tcg_gen_sari_i32(ret, ret, 16);
    }
}

void tcg_gen_ext8u_i32(TCGv_i32 ret, TCGv_i32 arg)
{
    if (TCG_TARGET_HAS_ext8u_i32) {
        tcg_gen_op2_i32(INDEX_op_ext8u_i32, ret, arg);
    } else {
        tcg_gen_andi_i32(ret, arg, 0xffu);
    }
}

void tcg_gen_ext16u_i32(TCGv_i32 ret, TCGv_i32 arg)
{
    if (TCG_TARGET_HAS_ext16u_i32) {
        tcg_gen_op2_i32(INDEX_op_ext16u_i32, ret, arg);
    } else {
        tcg_gen_andi_i32(ret, arg, 0xffffu);
    }
}

void tcg_gen_bswap32_i32(TCGv_i32 ret, TCGv_i32 arg)
{
    if (TCG_TARGET_HAS_bswap32_i32) {
        tcg_gen_op2_i32(INDEX_op_bswap32_i32, ret, arg);
    } else {
        TCGv_i32 t0, t1;
        t0 = tcg_temp_new_i32();
        t1 = tcg_temp_new_i32();

        tcg_gen_shli_i32(t0, arg, 24);

        tcg_gen_andi_i32(t1, arg, 0x0000ff00);
        tcg_gen_shli_i32(t1, t1, 8);
        tcg_gen_or_i32(t0, t0, t1);

        tcg_gen_shri_i32(t1, arg, 8);
        tcg_gen_andi_i32(t1, t1, 0x0000ff00);
        tcg_gen_or_i32(t0, t0, t1);

        tcg_gen_shri_i32(t1, arg, 24);
        tcg_gen_or_i32(ret, t0, t1);
        tcg_temp_free_i32(t0);
        tcg_temp_free_i32(t1);
    }
}

void tcg_gen_addi_i64(TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2)
{
    /* some cases can be optimized here */
    if (arg2 == 0) {
        tcg_gen_mov_i64(ret, arg1);
    } else {
        TCGv_i64 t0 = tcg_const_i64(arg2);
        tcg_gen_add_i64(ret, arg1, t0);
        tcg_temp_free_i64(t0);
    }
}

void tcg_gen_subfi_i64(TCGv_i64 ret, int64_t arg1, TCGv_i64 arg2)
{
    if (arg1 == 0 && TCG_TARGET_HAS_neg_i64) {
        /* Don't recurse with tcg_gen_neg_i64.  */
        tcg_gen_op2_i64(INDEX_op_neg_i64, ret, arg2);
    } else {
        TCGv_i64 t0 = tcg_const_i64(arg1);
        tcg_gen_sub_i64(ret, t0, arg2);
        tcg_temp_free_i64(t0);
    }
}

void tcg_gen_subi_i64(TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2)
{
    /* some cases can be optimized here */
    if (arg2 == 0) {
        tcg_gen_mov_i64(ret, arg1);
    } else {
        TCGv_i64 t0 = tcg_const_i64(arg2);
        tcg_gen_sub_i64(ret, arg1, t0);
        tcg_temp_free_i64(t0);
    }
}

void tcg_gen_andi_i64(TCGv_i64 ret, TCGv_i64 arg1, uint64_t arg2)
{
    TCGv_i64 t0;

    if (TCG_TARGET_REG_BITS == 32) {
        tcg_gen_andi_i32(TCGV_LOW(ret), TCGV_LOW(arg1), arg2);
        tcg_gen_andi_i32(TCGV_HIGH(ret), TCGV_HIGH(arg1), arg2 >> 32);
        return;
    }

    /* Some cases can be optimized here.  */
    switch (arg2) {
    case 0:
        tcg_gen_movi_i64(ret, 0);
        return;
    case 0xffffffffffffffffull:
        tcg_gen_mov_i64(ret, arg1);
        return;
    case 0xffull:
        /* Don't recurse with tcg_gen_ext8u_i64.  */
        if (TCG_TARGET_HAS_ext8u_i64) {
            tcg_gen_op2_i64(INDEX_op_ext8u_i64, ret, arg1);
            return;
        }
        break;
    case 0xffffu:
        if (TCG_TARGET_HAS_ext16u_i64) {
            tcg_gen_op2_i64(INDEX_op_ext16u_i64, ret, arg1);
            return;
        }
        break;
    case 0xffffffffull:
        if (TCG_TARGET_HAS_ext32u_i64) {
            tcg_gen_op2_i64(INDEX_op_ext32u_i64, ret, arg1);
            return;
        }
        break;
    }
    t0 = tcg_const_i64(arg2);
    tcg_gen_and_i64(ret, arg1, t0);
    tcg_temp_free_i64(t0);
}

void tcg_gen_ori_i64(TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2)
{
    if (TCG_TARGET_REG_BITS == 32) {
        tcg_gen_ori_i32(TCGV_LOW(ret), TCGV_LOW(arg1), arg2);
        tcg_gen_ori_i32(TCGV_HIGH(ret), TCGV_HIGH(arg1), arg2 >> 32);
        return;
    }
    /* Some cases can be optimized here.  */
    if (arg2 == -1) {
        tcg_gen_movi_i64(ret, -1);
    } else if (arg2 == 0) {
        tcg_gen_mov_i64(ret, arg1);
    } else {
        TCGv_i64 t0 = tcg_const_i64(arg2);
        tcg_gen_or_i64(ret, arg1, t0);
        tcg_temp_free_i64(t0);
    }
}

void tcg_gen_xori_i64(TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2)
{
    if (TCG_TARGET_REG_BITS == 32) {
        tcg_gen_xori_i32(TCGV_LOW(ret), TCGV_LOW(arg1), arg2);
        tcg_gen_xori_i32(TCGV_HIGH(ret), TCGV_HIGH(arg1), arg2 >> 32);
        return;
    }
    /* Some cases can be optimized here.  */
    if (arg2 == 0) {
        tcg_gen_mov_i64(ret, arg1);
    } else if (arg2 == -1 && TCG_TARGET_HAS_not_i64) {
        /* Don't recurse with tcg_gen_not_i64.  */
        tcg_gen_op2_i64(INDEX_op_not_i64, ret, arg1);
    } else {
        TCGv_i64 t0 = tcg_const_i64(arg2);
        tcg_gen_xor_i64(ret, arg1, t0);
        tcg_temp_free_i64(t0);
    }
}

static inline void tcg_gen_shifti_i64(TCGv_i64 ret, TCGv_i64 arg1,
                                      unsigned c, bool right, bool arith)
{
    tcg_debug_assert(c < 64);
    if (c == 0) {
        tcg_gen_mov_i32(TCGV_LOW(ret), TCGV_LOW(arg1));
        tcg_gen_mov_i32(TCGV_HIGH(ret), TCGV_HIGH(arg1));
    } else if (c >= 32) {
        c -= 32;
        if (right) {
            if (arith) {
                tcg_gen_sari_i32(TCGV_LOW(ret), TCGV_HIGH(arg1), c);
                tcg_gen_sari_i32(TCGV_HIGH(ret), TCGV_HIGH(arg1), 31);
            } else {
                tcg_gen_shri_i32(TCGV_LOW(ret), TCGV_HIGH(arg1), c);
                tcg_gen_movi_i32(TCGV_HIGH(ret), 0);
            }
        } else {
            tcg_gen_shli_i32(TCGV_HIGH(ret), TCGV_LOW(arg1), c);
            tcg_gen_movi_i32(TCGV_LOW(ret), 0);
        }
    } else {
        TCGv_i32 t0, t1;

        t0 = tcg_temp_new_i32();
        t1 = tcg_temp_new_i32();
        if (right) {
            tcg_gen_shli_i32(t0, TCGV_HIGH(arg1), 32 - c);
            if (arith) {
                tcg_gen_sari_i32(t1, TCGV_HIGH(arg1), c);
            } else {
                tcg_gen_shri_i32(t1, TCGV_HIGH(arg1), c);
            }
            tcg_gen_shri_i32(TCGV_LOW(ret), TCGV_LOW(arg1), c);
            tcg_gen_or_i32(TCGV_LOW(ret), TCGV_LOW(ret), t0);
            tcg_gen_mov_i32(TCGV_HIGH(ret), t1);
        } else {
            tcg_gen_shri_i32(t0, TCGV_LOW(arg1), 32 - c);
            /* Note: ret can be the same as arg1, so we use t1 */
            tcg_gen_shli_i32(t1, TCGV_LOW(arg1), c);
            tcg_gen_shli_i32(TCGV_HIGH(ret), TCGV_HIGH(arg1), c);
            tcg_gen_or_i32(TCGV_HIGH(ret), TCGV_HIGH(ret), t0);
            tcg_gen_mov_i32(TCGV_LOW(ret), t1);
        }
        tcg_temp_free_i32(t0);
        tcg_temp_free_i32(t1);
    }
}

void tcg_gen_shli_i64(TCGv_i64 ret, TCGv_i64 arg1, unsigned arg2)
{
    tcg_debug_assert(arg2 < 64);
    if (TCG_TARGET_REG_BITS == 32) {
        tcg_gen_shifti_i64(ret, arg1, arg2, 0, 0);
    } else if (arg2 == 0) {
        tcg_gen_mov_i64(ret, arg1);
    } else {
        TCGv_i64 t0 = tcg_const_i64(arg2);
        tcg_gen_shl_i64(ret, arg1, t0);
        tcg_temp_free_i64(t0);
    }
}

void tcg_gen_shri_i64(TCGv_i64 ret, TCGv_i64 arg1, unsigned arg2)
{
    tcg_debug_assert(arg2 < 64);
    if (TCG_TARGET_REG_BITS == 32) {
        tcg_gen_shifti_i64(ret, arg1, arg2, 1, 0);
    } else if (arg2 == 0) {
        tcg_gen_mov_i64(ret, arg1);
    } else {
        TCGv_i64 t0 = tcg_const_i64(arg2);
        tcg_gen_shr_i64(ret, arg1, t0);
        tcg_temp_free_i64(t0);
    }
}

void tcg_gen_sari_i64(TCGv_i64 ret, TCGv_i64 arg1, unsigned arg2)
{
    tcg_debug_assert(arg2 < 64);
    if (TCG_TARGET_REG_BITS == 32) {
        tcg_gen_shifti_i64(ret, arg1, arg2, 1, 1);
    } else if (arg2 == 0) {
        tcg_gen_mov_i64(ret, arg1);
    } else {
        TCGv_i64 t0 = tcg_const_i64(arg2);
        tcg_gen_sar_i64(ret, arg1, t0);
        tcg_temp_free_i64(t0);
    }
}

void tcg_gen_brcond_i64(TCGCond cond, TCGv_i64 arg1, TCGv_i64 arg2, TCGLabel *l)
{
    if (cond == TCG_COND_ALWAYS) {
        tcg_gen_br(l);
    } else if (cond != TCG_COND_NEVER) {
        if (TCG_TARGET_REG_BITS == 32) {
            tcg_gen_op6ii_i32(INDEX_op_brcond2_i32, TCGV_LOW(arg1),
                              TCGV_HIGH(arg1), TCGV_LOW(arg2),
                              TCGV_HIGH(arg2), cond, label_arg(l));
        } else {
            tcg_gen_op4ii_i64(INDEX_op_brcond_i64, arg1, arg2, cond,
                              label_arg(l));
        }
    }
}

void tcg_gen_brcondi_i64(TCGCond cond, TCGv_i64 arg1, int64_t arg2, TCGLabel *l)
{
    if (cond == TCG_COND_ALWAYS) {
        tcg_gen_br(l);
    } else if (cond != TCG_COND_NEVER) {
        TCGv_i64 t0 = tcg_const_i64(arg2);
        tcg_gen_brcond_i64(cond, arg1, t0, l);
        tcg_temp_free_i64(t0);
    }
}

void tcg_gen_setcond_i64(TCGCond cond, TCGv_i64 ret,
                         TCGv_i64 arg1, TCGv_i64 arg2)
{
    if (cond == TCG_COND_ALWAYS) {
        tcg_gen_movi_i64(ret, 1);
    } else if (cond == TCG_COND_NEVER) {
        tcg_gen_movi_i64(ret, 0);
    } else {
        if (TCG_TARGET_REG_BITS == 32) {
            tcg_gen_op6i_i32(INDEX_op_setcond2_i32, TCGV_LOW(ret),
                             TCGV_LOW(arg1), TCGV_HIGH(arg1),
                             TCGV_LOW(arg2), TCGV_HIGH(arg2), cond);
            tcg_gen_movi_i32(TCGV_HIGH(ret), 0);
        } else {
            tcg_gen_op4i_i64(INDEX_op_setcond_i64, ret, arg1, arg2, cond);
        }
    }
}

void tcg_gen_setcondi_i64(TCGCond cond, TCGv_i64 ret,
                          TCGv_i64 arg1, int64_t arg2)
{
    TCGv_i64 t0 = tcg_const_i64(arg2);
    tcg_gen_setcond_i64(cond, ret, arg1, t0);
    tcg_temp_free_i64(t0);
}

void tcg_gen_muli_i64(TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2)
{
    TCGv_i64 t0 = tcg_const_i64(arg2);
    tcg_gen_mul_i64(ret, arg1, t0);
    tcg_temp_free_i64(t0);
}

void tcg_gen_ext8s_i64(TCGv_i64 ret, TCGv_i64 arg)
{
    if (TCG_TARGET_REG_BITS == 32) {
        tcg_gen_ext8s_i32(TCGV_LOW(ret), TCGV_LOW(arg));
        tcg_gen_sari_i32(TCGV_HIGH(ret), TCGV_LOW(ret), 31);
    } else if (TCG_TARGET_HAS_ext8s_i64) {
        tcg_gen_op2_i64(INDEX_op_ext8s_i64, ret, arg);
    } else {
        tcg_gen_shli_i64(ret, arg, 56);
        tcg_gen_sari_i64(ret, ret, 56);
    }
}

void tcg_gen_ext16s_i64(TCGv_i64 ret, TCGv_i64 arg)
{
    if (TCG_TARGET_REG_BITS == 32) {
        tcg_gen_ext16s_i32(TCGV_LOW(ret), TCGV_LOW(arg));
        tcg_gen_sari_i32(TCGV_HIGH(ret), TCGV_LOW(ret), 31);
    } else if (TCG_TARGET_HAS_ext16s_i64) {
        tcg_gen_op2_i64(INDEX_op_ext16s_i64, ret, arg);
    } else {
        tcg_gen_shli_i64(ret, arg, 48);
        tcg_gen_sari_i64(ret, ret, 48);
    }
}

void tcg_gen_ext32s_i64(TCGv_i64 ret, TCGv_i64 arg)
{
    if (TCG_TARGET_REG_BITS == 32) {
        tcg_gen_mov_i32(TCGV_LOW(ret), TCGV_LOW(arg));
        tcg_gen_sari_i32(TCGV_HIGH(ret), TCGV_LOW(ret), 31);
    } else if (TCG_TARGET_HAS_ext32s_i64) {
        tcg_gen_op2_i64(INDEX_op_ext32s_i64, ret, arg);
    } else {
        tcg_gen_shli_i64(ret, arg, 32);
        tcg_gen_sari_i64(ret, ret, 32);
    }
}

void tcg_gen_ext8u_i64(TCGv_i64 ret, TCGv_i64 arg)
{
    if (TCG_TARGET_REG_BITS == 32) {
        tcg_gen_ext8u_i32(TCGV_LOW(ret), TCGV_LOW(arg));
        tcg_gen_movi_i32(TCGV_HIGH(ret), 0);
    } else if (TCG_TARGET_HAS_ext8u_i64) {
        tcg_gen_op2_i64(INDEX_op_ext8u_i64, ret, arg);
    } else {
        tcg_gen_andi_i64(ret, arg, 0xffu);
    }
}

void tcg_gen_ext16u_i64(TCGv_i64 ret, TCGv_i64 arg)
{
    if (TCG_TARGET_REG_BITS == 32) {
        tcg_gen_ext16u_i32(TCGV_LOW(ret), TCGV_LOW(arg));
        tcg_gen_movi_i32(TCGV_HIGH(ret), 0);
    } else if (TCG_TARGET_HAS_ext16u_i64) {
        tcg_gen_op2_i64(INDEX_op_ext16u_i64, ret, arg);
    } else {
        tcg_gen_andi_i64(ret, arg, 0xffffu);
    }
}

void tcg_gen_ext32u_i64(TCGv_i64 ret, TCGv_i64 arg)
{
    if (TCG_TARGET_REG_BITS == 32) {
        tcg_gen_mov_i32(TCGV_LOW(ret), TCGV_LOW(arg));
        tcg_gen_movi_i32(TCGV_HIGH(ret), 0);
    } else if (TCG_TARGET_HAS_ext32u_i64) {
        tcg_gen_op2_i64(INDEX_op_ext32u_i64, ret, arg);
    } else {
        tcg_gen_andi_i64(ret, arg, 0xffffffffu);
    }
}

void tcg_gen_bswap32_i64(TCGv_i64 ret, TCGv_i64 arg)
{
    if (TCG_TARGET_REG_BITS == 32) {
        tcg_gen_bswap32_i32(TCGV_LOW(ret), TCGV_LOW(arg));
        tcg_gen_movi_i32(TCGV_HIGH(ret), 0);
    } else if (TCG_TARGET_HAS_bswap32_i64) {
        tcg_gen_op2_i64(INDEX_op_bswap32_i64, ret, arg);
    } else {
        TCGv_i64 t0, t1;
        t0 = tcg_temp_new_i64();
        t1 = tcg_temp_new_i64();

        tcg_gen_shli_i64(t0, arg, 24);
        tcg_gen_ext32u_i64(t0, t0);

        tcg_gen_andi_i64(t1, arg, 0x0000ff00);
        tcg_gen_shli_i64(t1, t1, 8);
        tcg_gen_or_i64(t0, t0, t1);

        tcg_gen_shri_i64(t1, arg, 8);
        tcg_gen_andi_i64(t1, t1, 0x0000ff00);
        tcg_gen_or_i64(t0, t0, t1);

        tcg_gen_shri_i64(t1, arg, 24);
        tcg_gen_or_i64(ret, t0, t1);
        tcg_temp_free_i64(t0);
        tcg_temp_free_i64(t1);
    }
}

void tcg_gen_bswap64_i64(TCGv_i64 ret, TCGv_i64 arg)
{
    if (TCG_TARGET_REG_BITS == 32) {
        TCGv_i32 t0, t1;
        t0 = tcg_temp_new_i32();
        t1 = tcg_temp_new_i32();

        tcg_gen_bswap32_i32(t0, TCGV_LOW(arg));
        tcg_gen_bswap32_i32(t1, TCGV_HIGH(arg));
        tcg_gen_mov_i32(TCGV_LOW(ret), t1);
        tcg_gen_mov_i32(TCGV_HIGH(ret), t0);
        tcg_temp_free_i32(t0);
        tcg_temp_free_i32(t1);
    } else if (TCG_TARGET_HAS_bswap64_i64) {
        tcg_gen_op2_i64(INDEX_op_bswap64_i64, ret, arg);
    } else {
        TCGv_i64 t0 = tcg_temp_new_i64();
        TCGv_i64 t1 = tcg_temp_new_i64();

        tcg_gen_shli_i64(t0, arg, 56);

        tcg_gen_andi_i64(t1, arg, 0x0000ff00);
        tcg_gen_shli_i64(t1, t1, 40);
        tcg_gen_or_i64(t0, t0, t1);

        tcg_gen_andi_i64(t1, arg, 0x00ff0000);
        tcg_gen_shli_i64(t1, t1, 24);
        tcg_gen_or_i64(t0, t0, t1);

        tcg_gen_andi_i64(t1, arg, 0xff000000);
        tcg_gen_shli_i64(t1, t1, 8);
        tcg_gen_or_i64(t0, t0, t1);

        tcg_gen_shri_i64(t1, arg, 8);
        tcg_gen_andi_i64(t1, t1, 0xff000000);
        tcg_gen_or_i64(t0, t0, t1);

        tcg_gen_shri_i64(t1, arg, 24);
        tcg_gen_andi_i64(t1, t1, 0x00ff0000);
        tcg_gen_or_i64(t0, t0, t1);

        tcg_gen_shri_i64(t1, arg, 40);
        tcg_gen_andi_i64(t1, t1, 0x0000ff00);
        tcg_gen_or_i64(t0, t0, t1);

        tcg_gen_shri_i64(t1, arg, 56);
        tcg_gen_or_i64(ret, t0, t1);
        tcg_temp_free_i64(t0);
        tcg_temp_free_i64(t1);
    }
}

void tcg_gen_not_i64(TCGv_i64 ret, TCGv_i64 arg)
{
    if (TCG_TARGET_REG_BITS == 32) {
        tcg_gen_not_i32(TCGV_LOW(ret), TCGV_LOW(arg));
        tcg_gen_not_i32(TCGV_HIGH(ret), TCGV_HIGH(arg));
    } else if (TCG_TARGET_HAS_not_i64) {
        tcg_gen_op2_i64(INDEX_op_not_i64, ret, arg);
    } else {
        tcg_gen_xori_i64(ret, arg, -1);
    }
}

void tcg_gen_andc_i64(TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
    if (TCG_TARGET_REG_BITS == 32) {
        tcg_gen_andc_i32(TCGV_LOW(ret), TCGV_LOW(arg1), TCGV_LOW(arg2));
        tcg_gen_andc_i32(TCGV_HIGH(ret), TCGV_HIGH(arg1), TCGV_HIGH(arg2));
    } else if (TCG_TARGET_HAS_andc_i64) {
        tcg_gen_op3_i64(INDEX_op_andc_i64, ret, arg1, arg2);
    } else {
        TCGv_i64 t0 = tcg_temp_new_i64();
        tcg_gen_not_i64(t0, arg2);
        tcg_gen_and_i64(ret, arg1, t0);
        tcg_temp_free_i64(t0);
    }
}

void tcg_gen_clz_i64(TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
    if (TCG_TARGET_HAS_clz_i64) {
        tcg_gen_op3_i64(INDEX_op_clz_i64, ret, arg1, arg2);
    } else {
        gen_helper_clz_i64(ret, arg1, arg2);
    }
}

void tcg_gen_clzi_i64(TCGv_i64 ret, TCGv_i64 arg1, uint64_t arg2)
{
    if (TCG_TARGET_REG_BITS == 32
        && TCG_TARGET_HAS_clz_i32
        && arg2 <= 0xffffffffu) {
        TCGv_i32 t = tcg_const_i32((uint32_t)arg2 - 32);
        tcg_gen_clz_i32(t, TCGV_LOW(arg1), t);
        tcg_gen_addi_i32(t, t, 32);
        tcg_gen_clz_i32(TCGV_LOW(ret), TCGV_HIGH(arg1), t);
        tcg_gen_movi_i32(TCGV_HIGH(ret), 0);
        tcg_temp_free_i32(t);
    } else {
        TCGv_i64 t = tcg_const_i64(arg2);
        tcg_gen_clz_i64(ret, arg1, t);
        tcg_temp_free_i64(t);
    }
}

void tcg_gen_ctz_i64(TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
    if (TCG_TARGET_HAS_ctz_i64) {
        tcg_gen_op3_i64(INDEX_op_ctz_i64, ret, arg1, arg2);
    } else if (TCG_TARGET_HAS_ctpop_i64 || TCG_TARGET_HAS_clz_i64) {
        TCGv_i64 z, t = tcg_temp_new_i64();

        if (TCG_TARGET_HAS_ctpop_i64) {
            tcg_gen_subi_i64(t, arg1, 1);
            tcg_gen_andc_i64(t, t, arg1);
            tcg_gen_ctpop_i64(t, t);
        } else {
            /* Since all non-x86 hosts have clz(0) == 64, don't fight it.  */
            tcg_gen_neg_i64(t, arg1);
            tcg_gen_and_i64(t, t, arg1);
            tcg_gen_clzi_i64(t, t, 64);
            tcg_gen_xori_i64(t, t, 63);
        }
        z = tcg_const_i64(0);
        tcg_gen_movcond_i64(TCG_COND_EQ, ret, arg1, z, arg2, t);
        tcg_temp_free_i64(t);
        tcg_temp_free_i64(z);
    } else {
        gen_helper_ctz_i64(ret, arg1, arg2);
    }
}

void tcg_gen_ctzi_i64(TCGv_i64 ret, TCGv_i64 arg1, uint64_t arg2)
{
    if (TCG_TARGET_REG_BITS == 32
        && TCG_TARGET_HAS_ctz_i32
        && arg2 <= 0xffffffffu) {
        TCGv_i32 t32 = tcg_const_i32((uint32_t)arg2 - 32);
        tcg_gen_ctz_i32(t32, TCGV_HIGH(arg1), t32);
        tcg_gen_addi_i32(t32, t32, 32);
        tcg_gen_ctz_i32(TCGV_LOW(ret), TCGV_LOW(arg1), t32);
        tcg_gen_movi_i32(TCGV_HIGH(ret), 0);
        tcg_temp_free_i32(t32);
    } else if (!TCG_TARGET_HAS_ctz_i64
               && TCG_TARGET_HAS_ctpop_i64
               && arg2 == 64) {
        /* This equivalence has the advantage of not requiring a fixup.  */
        TCGv_i64 t = tcg_temp_new_i64();
        tcg_gen_subi_i64(t, arg1, 1);
        tcg_gen_andc_i64(t, t, arg1);
        tcg_gen_ctpop_i64(ret, t);
        tcg_temp_free_i64(t);
    } else {
        TCGv_i64 t64 = tcg_const_i64(arg2);
        tcg_gen_ctz_i64(ret, arg1, t64);
        tcg_temp_free_i64(t64);
    }
}

void tcg_gen_ctpop_i64(TCGv_i64 ret, TCGv_i64 arg1)
{
    if (TCG_TARGET_HAS_ctpop_i64) {
        tcg_gen_op2_i64(INDEX_op_ctpop_i64, ret, arg1);
    } else if (TCG_TARGET_REG_BITS == 32 && TCG_TARGET_HAS_ctpop_i32) {
        tcg_gen_ctpop_i32(TCGV_HIGH(ret), TCGV_HIGH(arg1));
        tcg_gen_ctpop_i32(TCGV_LOW(ret), TCGV_LOW(arg1));
        tcg_gen_add_i32(TCGV_LOW(ret), TCGV_LOW(ret), TCGV_HIGH(ret));
        tcg_gen_movi_i32(TCGV_HIGH(ret), 0);
    } else {
        gen_helper_ctpop_i64(ret, arg1);
    }
}

void tcg_gen_rotl_i64(TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
    if (TCG_TARGET_HAS_rot_i64) {
        tcg_gen_op3_i64(INDEX_op_rotl_i64, ret, arg1, arg2);
    } else {
        TCGv_i64 t0, t1;
        t0 = tcg_temp_new_i64();
        t1 = tcg_temp_new_i64();
        tcg_gen_shl_i64(t0, arg1, arg2);
        tcg_gen_subfi_i64(t1, 64, arg2);
        tcg_gen_shr_i64(t1, arg1, t1);
        tcg_gen_or_i64(ret, t0, t1);
        tcg_temp_free_i64(t0);
        tcg_temp_free_i64(t1);
    }
}

void tcg_gen_rotli_i64(TCGv_i64 ret, TCGv_i64 arg1, unsigned arg2)
{
    tcg_debug_assert(arg2 < 64);
    /* some cases can be optimized here */
    if (arg2 == 0) {
        tcg_gen_mov_i64(ret, arg1);
    } else if (TCG_TARGET_HAS_rot_i64) {
        TCGv_i64 t0 = tcg_const_i64(arg2);
        tcg_gen_rotl_i64(ret, arg1, t0);
        tcg_temp_free_i64(t0);
    } else {
        TCGv_i64 t0, t1;
        t0 = tcg_temp_new_i64();
        t1 = tcg_temp_new_i64();
        tcg_gen_shli_i64(t0, arg1, arg2);
        tcg_gen_shri_i64(t1, arg1, 64 - arg2);
        tcg_gen_or_i64(ret, t0, t1);
        tcg_temp_free_i64(t0);
        tcg_temp_free_i64(t1);
    }
}

void tcg_gen_rotr_i64(TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
    if (TCG_TARGET_HAS_rot_i64) {
        tcg_gen_op3_i64(INDEX_op_rotr_i64, ret, arg1, arg2);
    } else {
        TCGv_i64 t0, t1;
        t0 = tcg_temp_new_i64();
        t1 = tcg_temp_new_i64();
        tcg_gen_shr_i64(t0, arg1, arg2);
        tcg_gen_subfi_i64(t1, 64, arg2);
        tcg_gen_shl_i64(t1, arg1, t1);
        tcg_gen_or_i64(ret, t0, t1);
        tcg_temp_free_i64(t0);
        tcg_temp_free_i64(t1);
    }
}

void tcg_gen_rotri_i64(TCGv_i64 ret, TCGv_i64 arg1, unsigned arg2)
{
    tcg_debug_assert(arg2 < 64);
    /* some cases can be optimized here */
    if (arg2 == 0) {
        tcg_gen_mov_i64(ret, arg1);
    } else {
        tcg_gen_rotli_i64(ret, arg1, 64 - arg2);
    }
}

void tcg_gen_deposit_i64(TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2,
                         unsigned int ofs, unsigned int len)
{
    uint64_t mask;
    TCGv_i64 t1;

    tcg_debug_assert(ofs < 64);
    tcg_debug_assert(len > 0);
    tcg_debug_assert(len <= 64);
    tcg_debug_assert(ofs + len <= 64);

    if (len == 64) {
        tcg_gen_mov_i64(ret, arg2);
        return;
    }
    if (TCG_TARGET_HAS_deposit_i64 && TCG_TARGET_deposit_i64_valid(ofs, len)) {
        tcg_gen_op5ii_i64(INDEX_op_deposit_i64, ret, arg1, arg2, ofs, len);
        return;
    }

    if (TCG_TARGET_REG_BITS == 32) {
        if (ofs >= 32) {
            tcg_gen_deposit_i32(TCGV_HIGH(ret), TCGV_HIGH(arg1),
                                TCGV_LOW(arg2), ofs - 32, len);
            tcg_gen_mov_i32(TCGV_LOW(ret), TCGV_LOW(arg1));
            return;
        }
        if (ofs + len <= 32) {
            tcg_gen_deposit_i32(TCGV_LOW(ret), TCGV_LOW(arg1),
                                TCGV_LOW(arg2), ofs, len);
            tcg_gen_mov_i32(TCGV_HIGH(ret), TCGV_HIGH(arg1));
            return;
        }
    }

    mask = (1ull << len) - 1;
    t1 = tcg_temp_new_i64();

    if (ofs + len < 64) {
        tcg_gen_andi_i64(t1, arg2, mask);
        tcg_gen_shli_i64(t1, t1, ofs);
    } else {
        tcg_gen_shli_i64(t1, arg2, ofs);
    }
    tcg_gen_andi_i64(ret, arg1, ~(mask << ofs));
    tcg_gen_or_i64(ret, ret, t1);

    tcg_temp_free_i64(t1);
}

void tcg_gen_extract_i64(TCGv_i64 ret, TCGv_i64 arg,
                         unsigned int ofs, unsigned int len)
{
    tcg_debug_assert(ofs < 64);
    tcg_debug_assert(len > 0);
    tcg_debug_assert(len <= 64);
    tcg_debug_assert(ofs + len <= 64);

    /* Canonicalize certain special cases, even if extract is supported.  */
    if (ofs + len == 64) {
        tcg_gen_shri_i64(ret, arg, 64 - len);
        return;
    }
    if (ofs == 0) {
        tcg_gen_andi_i64(ret, arg, (1ull << len) - 1);
        return;
    }

    if (TCG_TARGET_REG_BITS == 32) {
        /* Look for a 32-bit extract within one of the two words.  */
        if (ofs >= 32) {
            tcg_gen_extract_i32(TCGV_LOW(ret), TCGV_HIGH(arg), ofs - 32, len);
            tcg_gen_movi_i32(TCGV_HIGH(ret), 0);
            return;
        }
        if (ofs + len <= 32) {
            tcg_gen_extract_i32(TCGV_LOW(ret), TCGV_LOW(arg), ofs, len);
            tcg_gen_movi_i32(TCGV_HIGH(ret), 0);
            return;
        }
        /* The field is split across two words.  One double-word
           shift is better than two double-word shifts.  */
        goto do_shift_and;
    }

    if (TCG_TARGET_HAS_extract_i64
        && TCG_TARGET_extract_i64_valid(ofs, len)) {
        tcg_gen_op4ii_i64(INDEX_op_extract_i64, ret, arg, ofs, len);
        return;
    }

    /* Assume that zero-extension, if available, is cheaper than a shift.  */
    switch (ofs + len) {
    case 32:
        if (TCG_TARGET_HAS_ext32u_i64) {
            tcg_gen_ext32u_i64(ret, arg);
            tcg_gen_shri_i64(ret, ret, ofs);
            return;
        }
        break;
    case 16:
        if (TCG_TARGET_HAS_ext16u_i64) {
            tcg_gen_ext16u_i64(ret, arg);
            tcg_gen_shri_i64(ret, ret, ofs);
            return;
        }
        break;
    case 8:
        if (TCG_TARGET_HAS_ext8u_i64) {
            tcg_gen_ext8u_i64(ret, arg);
            tcg_gen_shri_i64(ret, ret, ofs);
            return;
        }
        break;
    }

    /* ??? Ideally we'd know what values are available for immediate AND.
       Assume that 8 bits are available, plus the special cases of 16 and 32,
       so that we get ext8u, ext16u, and ext32u.  */
    switch (len) {
    case 1 ... 8: case 16: case 32:
    do_shift_and:
        tcg_gen_shri_i64(ret, arg, ofs);
        tcg_gen_andi_i64(ret, ret, (1ull << len) - 1);
        break;
    default:
        tcg_gen_shli_i64(ret, arg, 64 - len - ofs);
        tcg_gen_shri_i64(ret, ret, 64 - len);
        break;
    }
}

void tcg_gen_sextract_i64(TCGv_i64 ret, TCGv_i64 arg,
                          unsigned int ofs, unsigned int len)
{
    tcg_debug_assert(ofs < 64);
    tcg_debug_assert(len > 0);
    tcg_debug_assert(len <= 64);
    tcg_debug_assert(ofs + len <= 64);

    /* Canonicalize certain special cases, even if sextract is supported.  */
    if (ofs + len == 64) {
        tcg_gen_sari_i64(ret, arg, 64 - len);
        return;
    }
    if (ofs == 0) {
        switch (len) {
        case 32:
            tcg_gen_ext32s_i64(ret, arg);
            return;
        case 16:
            tcg_gen_ext16s_i64(ret, arg);
            return;
        case 8:
            tcg_gen_ext8s_i64(ret, arg);
            return;
        }
    }

    if (TCG_TARGET_REG_BITS == 32) {
        /* Look for a 32-bit extract within one of the two words.  */
        if (ofs >= 32) {
            tcg_gen_sextract_i32(TCGV_LOW(ret), TCGV_HIGH(arg), ofs - 32, len);
        } else if (ofs + len <= 32) {
            tcg_gen_sextract_i32(TCGV_LOW(ret), TCGV_LOW(arg), ofs, len);
        } else if (ofs == 0) {
            tcg_gen_mov_i32(TCGV_LOW(ret), TCGV_LOW(arg));
            tcg_gen_sextract_i32(TCGV_HIGH(ret), TCGV_HIGH(arg), 0, len - 32);
            return;
        } else if (len > 32) {
            TCGv_i32 t = tcg_temp_new_i32();
            /* Extract the bits for the high word normally.  */
            tcg_gen_sextract_i32(t, TCGV_HIGH(arg), ofs + 32, len - 32);
            /* Shift the field down for the low part.  */
            tcg_gen_shri_i64(ret, arg, ofs);
            /* Overwrite the shift into the high part.  */
            tcg_gen_mov_i32(TCGV_HIGH(ret), t);
            tcg_temp_free_i32(t);
            return;
        } else {
            /* Shift the field down for the low part, such that the
               field sits at the MSB.  */
            tcg_gen_shri_i64(ret, arg, ofs + len - 32);
            /* Shift the field down from the MSB, sign extending.  */
            tcg_gen_sari_i32(TCGV_LOW(ret), TCGV_LOW(ret), 32 - len);
        }
        /* Sign-extend the field from 32 bits.  */
        tcg_gen_sari_i32(TCGV_HIGH(ret), TCGV_LOW(ret), 31);
        return;
    }

    if (TCG_TARGET_HAS_sextract_i64
        && TCG_TARGET_extract_i64_valid(ofs, len)) {
        tcg_gen_op4ii_i64(INDEX_op_sextract_i64, ret, arg, ofs, len);
        return;
    }

    /* Assume that sign-extension, if available, is cheaper than a shift.  */
    switch (ofs + len) {
    case 32:
        if (TCG_TARGET_HAS_ext32s_i64) {
            tcg_gen_ext32s_i64(ret, arg);
            tcg_gen_sari_i64(ret, ret, ofs);
            return;
        }
        break;
    case 16:
        if (TCG_TARGET_HAS_ext16s_i64) {
            tcg_gen_ext16s_i64(ret, arg);
            tcg_gen_sari_i64(ret, ret, ofs);
            return;
        }
        break;
    case 8:
        if (TCG_TARGET_HAS_ext8s_i64) {
            tcg_gen_ext8s_i64(ret, arg);
            tcg_gen_sari_i64(ret, ret, ofs);
            return;
        }
        break;
    }
    switch (len) {
    case 32:
        if (TCG_TARGET_HAS_ext32s_i64) {
            tcg_gen_shri_i64(ret, arg, ofs);
            tcg_gen_ext32s_i64(ret, ret);
            return;
        }
        break;
    case 16:
        if (TCG_TARGET_HAS_ext16s_i64) {
            tcg_gen_shri_i64(ret, arg, ofs);
            tcg_gen_ext16s_i64(ret, ret);
            return;
        }
        break;
    case 8:
        if (TCG_TARGET_HAS_ext8s_i64) {
            tcg_gen_shri_i64(ret, arg, ofs);
            tcg_gen_ext8s_i64(ret, ret);
            return;
        }
        break;
    }
    tcg_gen_shli_i64(ret, arg, 64 - len - ofs);
    tcg_gen_sari_i64(ret, ret, 64 - len);
}

void tcg_gen_movcond_i64(TCGCond cond, TCGv_i64 ret, TCGv_i64 c1,
                         TCGv_i64 c2, TCGv_i64 v1, TCGv_i64 v2)
{
    if (cond == TCG_COND_ALWAYS) {
        tcg_gen_mov_i64(ret, v1);
    } else if (cond == TCG_COND_NEVER) {
        tcg_gen_mov_i64(ret, v2);
    } else if (TCG_TARGET_REG_BITS == 32) {
        TCGv_i32 t0 = tcg_temp_new_i32();
        TCGv_i32 t1 = tcg_temp_new_i32();
        tcg_gen_op6i_i32(INDEX_op_setcond2_i32, t0,
                         TCGV_LOW(c1), TCGV_HIGH(c1),
                         TCGV_LOW(c2), TCGV_HIGH(c2), cond);

        if (TCG_TARGET_HAS_movcond_i32) {
            tcg_gen_movi_i32(t1, 0);
            tcg_gen_movcond_i32(TCG_COND_NE, TCGV_LOW(ret), t0, t1,
                                TCGV_LOW(v1), TCGV_LOW(v2));
            tcg_gen_movcond_i32(TCG_COND_NE, TCGV_HIGH(ret), t0, t1,
                                TCGV_HIGH(v1), TCGV_HIGH(v2));
        } else {
            tcg_gen_neg_i32(t0, t0);

            tcg_gen_and_i32(t1, TCGV_LOW(v1), t0);
            tcg_gen_andc_i32(TCGV_LOW(ret), TCGV_LOW(v2), t0);
            tcg_gen_or_i32(TCGV_LOW(ret), TCGV_LOW(ret), t1);

            tcg_gen_and_i32(t1, TCGV_HIGH(v1), t0);
            tcg_gen_andc_i32(TCGV_HIGH(ret), TCGV_HIGH(v2), t0);
            tcg_gen_or_i32(TCGV_HIGH(ret), TCGV_HIGH(ret), t1);
        }
        tcg_temp_free_i32(t0);
        tcg_temp_free_i32(t1);
    } else if (TCG_TARGET_HAS_movcond_i64) {
        tcg_gen_op6i_i64(INDEX_op_movcond_i64, ret, c1, c2, v1, v2, cond);
    } else {
        TCGv_i64 t0 = tcg_temp_new_i64();
        TCGv_i64 t1 = tcg_temp_new_i64();
        tcg_gen_setcond_i64(cond, t0, c1, c2);
        tcg_gen_neg_i64(t0, t0);
        tcg_gen_and_i64(t1, v1, t0);
        tcg_gen_andc_i64(ret, v2, t0);
        tcg_gen_or_i64(ret, ret, t1);
        tcg_temp_free_i64(t0);
        tcg_temp_free_i64(t1);
    }
}

void tcg_gen_add2_i64(TCGv_i64 rl, TCGv_i64 rh, TCGv_i64 al,
                      TCGv_i64 ah, TCGv_i64 bl, TCGv_i64 bh)
{
    if (TCG_TARGET_HAS_add2_i64) {
        tcg_gen_op6_i64(INDEX_op_add2_i64, rl, rh, al, ah, bl, bh);
    } else {
        TCGv_i64 t0 = tcg_temp_new_i64();
        TCGv_i64 t1 = tcg_temp_new_i64();
        tcg_gen_add_i64(t0, al, bl);
        tcg_gen_setcond_i64(TCG_COND_LTU, t1, t0, al);
        tcg_gen_add_i64(rh, ah, bh);
        tcg_gen_add_i64(rh, rh, t1);
        tcg_gen_mov_i64(rl, t0);
        tcg_temp_free_i64(t0);
        tcg_temp_free_i64(t1);
    }
}

void tcg_gen_mulu2_i64(TCGv_i64 rl, TCGv_i64 rh, TCGv_i64 arg1, TCGv_i64 arg2)
{
    if (TCG_TARGET_HAS_mulu2_i64) {
        tcg_gen_op4_i64(INDEX_op_mulu2_i64, rl, rh, arg1, arg2);
    } else if (TCG_TARGET_HAS_muluh_i64) {
        TCGv_i64 t = tcg_temp_new_i64();
        tcg_gen_op3_i64(INDEX_op_mul_i64, t, arg1, arg2);
        tcg_gen_op3_i64(INDEX_op_muluh_i64, rh, arg1, arg2);
        tcg_gen_mov_i64(rl, t);
        tcg_temp_free_i64(t);
    } else {
        TCGv_i64 t0 = tcg_temp_new_i64();
        tcg_gen_mul_i64(t0, arg1, arg2);
        gen_helper_muluh_i64(rh, arg1, arg2);
        tcg_gen_mov_i64(rl, t0);
        tcg_temp_free_i64(t0);
    }
}

void tcg_gen_muls2_i64(TCGv_i64 rl, TCGv_i64 rh, TCGv_i64 arg1, TCGv_i64 arg2)
{
    if (TCG_TARGET_HAS_muls2_i64) {
        tcg_gen_op4_i64(INDEX_op_muls2_i64, rl, rh, arg1, arg2);
    } else if (TCG_TARGET_HAS_mulsh_i64) {
        TCGv_i64 t = tcg_temp_new_i64();
        tcg_gen_op3_i64(INDEX_op_mul_i64, t, arg1, arg2);
        tcg_gen_op3_i64(INDEX_op_mulsh_i64, rh, arg1, arg2);
        tcg_gen_mov_i64(rl, t);
        tcg_temp_free_i64(t);
    } else if (TCG_TARGET_HAS_mulu2_i64 || TCG_TARGET_HAS_muluh_i64) {
        TCGv_i64 t0 = tcg_temp_new_i64();
        TCGv_i64 t1 = tcg_temp_new_i64();
        TCGv_i64 t2 = tcg_temp_new_i64();
        TCGv_i64 t3 = tcg_temp_new_i64();
        tcg_gen_mulu2_i64(t0, t1, arg1, arg2);
        /* Adjust for negative inputs.  */
        tcg_gen_sari_i64(t2, arg1, 63);
        tcg_gen_sari_i64(t3, arg2, 63);
        tcg_gen_and_i64(t2, t2, arg2);
        tcg_gen_and_i64(t3, t3, arg1);
        tcg_gen_sub_i64(rh, t1, t2);
        tcg_gen_sub_i64(rh, rh, t3);
        tcg_gen_mov_i64(rl, t0);
        tcg_temp_free_i64(t0);
        tcg_temp_free_i64(t1);
        tcg_temp_free_i64(t2);
        tcg_temp_free_i64(t3);
    } else {
        TCGv_i64 t0 = tcg_temp_new_i64();
        tcg_gen_mul_i64(t0, arg1, arg2);
        gen_helper_mulsh_i64(rh, arg1, arg2);
        tcg_gen_mov_i64(rl, t0);
        tcg_temp_free_i64(t0);
    }
}

void tcg_gen_extrl_i64_i32(TCGv_i32 ret, TCGv_i64 arg)
{
    if (TCG_TARGET_REG_BITS == 32) {
        tcg_gen_mov_i32(ret, TCGV_LOW(arg));
    } else if (TCG_TARGET_HAS_extrl_i64_i32) {
        tcg_gen_op2(INDEX_op_extrl_i64_i32,
                    tcgv_i32_arg(ret), tcgv_i64_arg(arg));
    } else {
        tcg_gen_mov_i32(ret, (TCGv_i32)arg);
    }
}

void tcg_gen_extrh_i64_i32(TCGv_i32 ret, TCGv_i64 arg)
{
    if (TCG_TARGET_REG_BITS == 32) {
        tcg_gen_mov_i32(ret, TCGV_HIGH(arg));
    } else if (TCG_TARGET_HAS_extrh_i64_i32) {
        tcg_gen_op2(INDEX_op_extrh_i64_i32,
                    tcgv_i32_arg(ret), tcgv_i64_arg(arg));
    } else {
        TCGv_i64 t = tcg_temp_new_i64();
        tcg_gen_shri_i64(t, arg, 32);
        tcg_gen_mov_i32(ret, (TCGv_i32)t);
        tcg_temp_free_i64(t);
    }
}

void tcg_gen_extu_i32_i64(TCGv_i64 ret, TCGv_i32 arg)
{
    if (TCG_TARGET_REG_BITS == 32) {
        tcg_gen_mov_i32(TCGV_LOW(ret), arg);
        tcg_gen_movi_i32(TCGV_HIGH(ret), 0);
    } else {
        tcg_gen_op2(INDEX_op_extu_i32_i64,
                    tcgv_i64_arg(ret), tcgv_i32_arg(arg));
    }
}

void tcg_gen_ext_i32_i64(TCGv_i64 ret, TCGv_i32 arg)
{
    if (TCG_TARGET_REG_BITS == 32) {
        tcg_gen_mov_i32(TCGV_LOW(ret), arg);
        tcg_gen_sari_i32(TCGV_HIGH(ret), TCGV_LOW(ret), 31);
    } else {
        tcg_gen_op2(INDEX_op_ext_i32_i64,
                    tcgv_i64_arg(ret), tcgv_i32_arg(arg));
    }
}

void tcg_gen_extr_i64_i32(TCGv_i32 lo, TCGv_i32 hi, TCGv_i64 arg)
{
    if (TCG_TARGET_REG_BITS == 32) {
        tcg_gen_mov_i32(lo, TCGV_LOW(arg));
        tcg_gen_mov_i32(hi, TCGV_HIGH(arg));
    } else {
        tcg_gen_extrl_i64_i32(lo, arg);
        tcg_gen_extrh_i64_i32(hi, arg);
    }
}

void tcg_gen_extr32_i64(TCGv_i64 lo, TCGv_i64 hi, TCGv_i64 arg)
{
    tcg_gen_ext32u_i64(lo, arg);
    tcg_gen_shri_i64(hi, arg, 32);
}

void tcg_gen_goto_tb(unsigned idx)
{
    /* We only support two chained exits.  */
    tcg_debug_assert(idx <= 1);
#ifdef CONFIG_DEBUG_TCG
    /* Verify that we havn't seen this numbered exit before.  */
    tcg_debug_assert((tcg_ctx->goto_tb_issue_mask & (1 << idx)) == 0);
    tcg_ctx->goto_tb_issue_mask |= 1 << idx;
#endif
    tcg_gen_op1i(INDEX_op_goto_tb, idx);
}

void tcg_gen_lookup_and_goto_ptr(void)
{
    if (TCG_TARGET_HAS_goto_ptr && !qemu_loglevel_mask(CPU_LOG_TB_NOCHAIN)) {
        TCGv_ptr ptr = tcg_temp_new_ptr();
        gen_helper_lookup_tb_ptr(ptr, cpu_env);
        tcg_gen_op1i(INDEX_op_goto_ptr, tcgv_ptr_arg(ptr));
        tcg_temp_free_ptr(ptr);
    } else {
        tcg_gen_exit_tb(0);
    }
}

static inline TCGMemOp tcg_canonicalize_memop(TCGMemOp op, bool is64, bool st)
{
    /* Trigger the asserts within as early as possible.  */
    (void)get_alignment_bits(op);

    switch (op & MO_SIZE) {
    case MO_8:
        op = (TCGMemOp)(op & ~MO_BSWAP);
        break;
    case MO_16:
        break;
    case MO_32:
        if (!is64) {
            op = (TCGMemOp)(op & ~MO_SIGN);
        }
        break;
    case MO_64:
        if (!is64) {
            tcg_abort();
        }
        break;
    }
    if (st) {
        op = (TCGMemOp)(op & ~MO_SIGN);
    }
    return op;
}

static void gen_ldst_i32(TCGOpcode opc, TCGv_i32 val, TCGv addr,
                         TCGMemOp memop, TCGArg idx)
{
    TCGMemOpIdx oi = make_memop_idx(memop, idx);
#if TARGET_LONG_BITS == 32
    tcg_gen_op3i_i32(opc, val, addr, oi);
#else
    if (TCG_TARGET_REG_BITS == 32) {
        tcg_gen_op4i_i32(opc, val, TCGV_LOW(addr), TCGV_HIGH(addr), oi);
    } else {
        tcg_gen_op3(opc, tcgv_i32_arg(val), tcgv_i64_arg(addr), oi);
    }
#endif
}

static void gen_ldst_i64(TCGOpcode opc, TCGv_i64 val, TCGv addr,
                         TCGMemOp memop, TCGArg idx)
{
    TCGMemOpIdx oi = make_memop_idx(memop, idx);
#if TARGET_LONG_BITS == 32
    if (TCG_TARGET_REG_BITS == 32) {
        tcg_gen_op4i_i32(opc, TCGV_LOW(val), TCGV_HIGH(val), addr, oi);
    } else {
        tcg_gen_op3(opc, tcgv_i64_arg(val), tcgv_i32_arg(addr), oi);
    }
#else
    if (TCG_TARGET_REG_BITS == 32) {
        tcg_gen_op5i_i32(opc, TCGV_LOW(val), TCGV_HIGH(val),
                         TCGV_LOW(addr), TCGV_HIGH(addr), oi);
    } else {
        tcg_gen_op3i_i64(opc, val, addr, oi);
    }
#endif
}

static void tcg_gen_req_mo(TCGBar type)
{
#ifdef TCG_GUEST_DEFAULT_MO
    type = (TCGBar)(type & TCG_GUEST_DEFAULT_MO);
#endif
    type = (TCGBar)(type & ~TCG_TARGET_DEFAULT_MO);
    if (type) {
        tcg_gen_mb((TCGBar)(type | TCG_BAR_SC));
    }
}

void tcg_gen_qemu_ld_i32(TCGv_i32 val, TCGv addr, TCGArg idx, TCGMemOp memop)
{
    tcg_gen_req_mo((TCGBar)(TCG_MO_LD_LD | TCG_MO_ST_LD));
    memop = tcg_canonicalize_memop(memop, 0, 0);
    trace_guest_mem_before_tcg(tcg_ctx->cpu, cpu_env,
                               addr, trace_mem_get_info(memop, 0));
    gen_ldst_i32(INDEX_op_qemu_ld_i32, val, addr, memop, idx);
}

void tcg_gen_qemu_st_i32(TCGv_i32 val, TCGv addr, TCGArg idx, TCGMemOp memop)
{
    tcg_gen_req_mo((TCGBar)(TCG_MO_LD_ST | TCG_MO_ST_ST));
    memop = tcg_canonicalize_memop(memop, 0, 1);
    trace_guest_mem_before_tcg(tcg_ctx->cpu, cpu_env,
                               addr, trace_mem_get_info(memop, 1));
    gen_ldst_i32(INDEX_op_qemu_st_i32, val, addr, memop, idx);
}

void tcg_gen_qemu_ld_i64(TCGv_i64 val, TCGv addr, TCGArg idx, TCGMemOp memop)
{
    tcg_gen_req_mo((TCGBar)(TCG_MO_LD_LD | TCG_MO_ST_LD));
    if (TCG_TARGET_REG_BITS == 32 && (memop & MO_SIZE) < MO_64) {
        tcg_gen_qemu_ld_i32(TCGV_LOW(val), addr, idx, memop);
        if (memop & MO_SIGN) {
            tcg_gen_sari_i32(TCGV_HIGH(val), TCGV_LOW(val), 31);
        } else {
            tcg_gen_movi_i32(TCGV_HIGH(val), 0);
        }
        return;
    }

    memop = tcg_canonicalize_memop(memop, 1, 0);
    trace_guest_mem_before_tcg(tcg_ctx->cpu, cpu_env,
                               addr, trace_mem_get_info(memop, 0));
    gen_ldst_i64(INDEX_op_qemu_ld_i64, val, addr, memop, idx);
}

void tcg_gen_qemu_st_i64(TCGv_i64 val, TCGv addr, TCGArg idx, TCGMemOp memop)
{
    tcg_gen_req_mo((TCGBar)(TCG_MO_LD_ST | TCG_MO_ST_ST));
    if (TCG_TARGET_REG_BITS == 32 && (memop & MO_SIZE) < MO_64) {
        tcg_gen_qemu_st_i32(TCGV_LOW(val), addr, idx, memop);
        return;
    }

    memop = tcg_canonicalize_memop(memop, 1, 1);
    trace_guest_mem_before_tcg(tcg_ctx->cpu, cpu_env,
                               addr, trace_mem_get_info(memop, 1));
    gen_ldst_i64(INDEX_op_qemu_st_i64, val, addr, memop, idx);
}

static void tcg_gen_ext_i32(TCGv_i32 ret, TCGv_i32 val, TCGMemOp opc)
{
    switch (opc & MO_SSIZE) {
    case MO_SB:
        tcg_gen_ext8s_i32(ret, val);
        break;
    case MO_UB:
        tcg_gen_ext8u_i32(ret, val);
        break;
    case MO_SW:
        tcg_gen_ext16s_i32(ret, val);
        break;
    case MO_UW:
        tcg_gen_ext16u_i32(ret, val);
        break;
    default:
        tcg_gen_mov_i32(ret, val);
        break;
    }
}

static void tcg_gen_ext_i64(TCGv_i64 ret, TCGv_i64 val, TCGMemOp opc)
{
    switch (opc & MO_SSIZE) {
    case MO_SB:
        tcg_gen_ext8s_i64(ret, val);
        break;
    case MO_UB:
        tcg_gen_ext8u_i64(ret, val);
        break;
    case MO_SW:
        tcg_gen_ext16s_i64(ret, val);
        break;
    case MO_UW:
        tcg_gen_ext16u_i64(ret, val);
        break;
    case MO_SL:
        tcg_gen_ext32s_i64(ret, val);
        break;
    case MO_UL:
        tcg_gen_ext32u_i64(ret, val);
        break;
    default:
        tcg_gen_mov_i64(ret, val);
        break;
    }
}

typedef void (*gen_atomic_cx_i32)(TCGv_i32, TCGv_env, TCGv, TCGv_i32, TCGv_i32);

typedef void (*gen_atomic_op_i32)(TCGv_i32, TCGv_env, TCGv, TCGv_i32);

# define WITH_ATOMIC64(X)

static void * const table_cmpxchg[16] = {
    [MO_8] = (void *)gen_helper_atomic_cmpxchgb,
    [MO_16 | MO_LE] = (void *)gen_helper_atomic_cmpxchgw_le,
    [MO_16 | MO_BE] = (void *)gen_helper_atomic_cmpxchgw_be,
    [MO_32 | MO_LE] = (void *)gen_helper_atomic_cmpxchgl_le,
    [MO_32 | MO_BE] = (void *)gen_helper_atomic_cmpxchgl_be,
    WITH_ATOMIC64([MO_64 | MO_LE] = (void *)gen_helper_atomic_cmpxchgq_le)
    WITH_ATOMIC64([MO_64 | MO_BE] = (void *)gen_helper_atomic_cmpxchgq_be)
};

void tcg_gen_atomic_cmpxchg_i32(TCGv_i32 retv, TCGv addr, TCGv_i32 cmpv,
                                TCGv_i32 newv, TCGArg idx, TCGMemOp memop)
{
    memop = tcg_canonicalize_memop(memop, 0, 0);

    if (!(tcg_ctx->tb_cflags & CF_PARALLEL)) {
        TCGv_i32 t1 = tcg_temp_new_i32();
        TCGv_i32 t2 = tcg_temp_new_i32();

        tcg_gen_ext_i32(t2, cmpv, (TCGMemOp)(memop & MO_SIZE));

        tcg_gen_qemu_ld_i32(t1, addr, idx, (TCGMemOp)(memop & ~MO_SIGN));
        tcg_gen_movcond_i32(TCG_COND_EQ, t2, t1, t2, newv, t1);
        tcg_gen_qemu_st_i32(t2, addr, idx, memop);
        tcg_temp_free_i32(t2);

        if (memop & MO_SIGN) {
            tcg_gen_ext_i32(retv, t1, memop);
        } else {
            tcg_gen_mov_i32(retv, t1);
        }
        tcg_temp_free_i32(t1);
    } else {
        gen_atomic_cx_i32 gen;

        gen = (gen_atomic_cx_i32)table_cmpxchg[memop & (MO_SIZE | MO_BSWAP)];
        tcg_debug_assert(gen != NULL);

#ifdef CONFIG_SOFTMMU
        {
            TCGv_i32 oi = tcg_const_i32(make_memop_idx(memop & ~MO_SIGN, idx));
            gen(retv, cpu_env, addr, cmpv, newv, oi);
            tcg_temp_free_i32(oi);
        }
#else
        gen(retv, cpu_env, addr, cmpv, newv);
#endif

        if (memop & MO_SIGN) {
            tcg_gen_ext_i32(retv, retv, memop);
        }
    }
}

void tcg_gen_atomic_cmpxchg_i64(TCGv_i64 retv, TCGv addr, TCGv_i64 cmpv,
                                TCGv_i64 newv, TCGArg idx, TCGMemOp memop)
{
    memop = tcg_canonicalize_memop(memop, 1, 0);

    if (!(tcg_ctx->tb_cflags & CF_PARALLEL)) {
        TCGv_i64 t1 = tcg_temp_new_i64();
        TCGv_i64 t2 = tcg_temp_new_i64();

        tcg_gen_ext_i64(t2, cmpv, (TCGMemOp)(memop & MO_SIZE));

        tcg_gen_qemu_ld_i64(t1, addr, idx, (TCGMemOp)(memop & ~MO_SIGN));
        tcg_gen_movcond_i64(TCG_COND_EQ, t2, t1, t2, newv, t1);
        tcg_gen_qemu_st_i64(t2, addr, idx, memop);
        tcg_temp_free_i64(t2);

        if (memop & MO_SIGN) {
            tcg_gen_ext_i64(retv, t1, memop);
        } else {
            tcg_gen_mov_i64(retv, t1);
        }
        tcg_temp_free_i64(t1);
    } else if ((memop & MO_SIZE) == MO_64) {
#ifdef CONFIG_ATOMIC64
        gen_atomic_cx_i64 gen;

        gen = table_cmpxchg[memop & (MO_SIZE | MO_BSWAP)];
        tcg_debug_assert(gen != NULL);

#ifdef CONFIG_SOFTMMU
        {
            TCGv_i32 oi = tcg_const_i32(make_memop_idx(memop, idx));
            gen(retv, cpu_env, addr, cmpv, newv, oi);
            tcg_temp_free_i32(oi);
        }
#else
        gen(retv, cpu_env, addr, cmpv, newv);
#endif
#else
        gen_helper_exit_atomic(cpu_env);
        /* Produce a result, so that we have a well-formed opcode stream
           with respect to uses of the result in the (dead) code following.  */
        tcg_gen_movi_i64(retv, 0);
#endif /* CONFIG_ATOMIC64 */
    } else {
        TCGv_i32 c32 = tcg_temp_new_i32();
        TCGv_i32 n32 = tcg_temp_new_i32();
        TCGv_i32 r32 = tcg_temp_new_i32();

        tcg_gen_extrl_i64_i32(c32, cmpv);
        tcg_gen_extrl_i64_i32(n32, newv);
        tcg_gen_atomic_cmpxchg_i32(r32, addr, c32, n32, idx, (TCGMemOp)(memop & ~MO_SIGN));
        tcg_temp_free_i32(c32);
        tcg_temp_free_i32(n32);

        tcg_gen_extu_i32_i64(retv, r32);
        tcg_temp_free_i32(r32);

        if (memop & MO_SIGN) {
            tcg_gen_ext_i64(retv, retv, memop);
        }
    }
}

static void do_nonatomic_op_i32(TCGv_i32 ret, TCGv addr, TCGv_i32 val,
                                TCGArg idx, TCGMemOp memop, bool new_val,
                                void (*gen)(TCGv_i32, TCGv_i32, TCGv_i32))
{
    TCGv_i32 t1 = tcg_temp_new_i32();
    TCGv_i32 t2 = tcg_temp_new_i32();

    memop = tcg_canonicalize_memop(memop, 0, 0);

    tcg_gen_qemu_ld_i32(t1, addr, idx, (TCGMemOp)(memop & ~MO_SIGN));
    gen(t2, t1, val);
    tcg_gen_qemu_st_i32(t2, addr, idx, memop);

    tcg_gen_ext_i32(ret, (new_val ? t2 : t1), memop);
    tcg_temp_free_i32(t1);
    tcg_temp_free_i32(t2);
}

static void do_atomic_op_i32(TCGv_i32 ret, TCGv addr, TCGv_i32 val,
                             TCGArg idx, TCGMemOp memop, void * const table[])
{
    gen_atomic_op_i32 gen;

    memop = tcg_canonicalize_memop(memop, 0, 0);

    gen = (gen_atomic_op_i32)table[memop & (MO_SIZE | MO_BSWAP)];
    tcg_debug_assert(gen != NULL);

#ifdef CONFIG_SOFTMMU
    {
        TCGv_i32 oi = tcg_const_i32(make_memop_idx(memop & ~MO_SIGN, idx));
        gen(ret, cpu_env, addr, val, oi);
        tcg_temp_free_i32(oi);
    }
#else
    gen(ret, cpu_env, addr, val);
#endif

    if (memop & MO_SIGN) {
        tcg_gen_ext_i32(ret, ret, memop);
    }
}

static void do_nonatomic_op_i64(TCGv_i64 ret, TCGv addr, TCGv_i64 val,
                                TCGArg idx, TCGMemOp memop, bool new_val,
                                void (*gen)(TCGv_i64, TCGv_i64, TCGv_i64))
{
    TCGv_i64 t1 = tcg_temp_new_i64();
    TCGv_i64 t2 = tcg_temp_new_i64();

    memop = tcg_canonicalize_memop(memop, 1, 0);

    tcg_gen_qemu_ld_i64(t1, addr, idx, (TCGMemOp)(memop & ~MO_SIGN));
    gen(t2, t1, val);
    tcg_gen_qemu_st_i64(t2, addr, idx, memop);

    tcg_gen_ext_i64(ret, (new_val ? t2 : t1), memop);
    tcg_temp_free_i64(t1);
    tcg_temp_free_i64(t2);
}

#define GEN_ATOMIC_HELPER(NAME, OP, NEW)                                       \
static void * const table_##NAME[16] = {                                       \
    [MO_8] = (void *)gen_helper_atomic_##NAME##b,                              \
    [MO_16 | MO_LE] = (void *)gen_helper_atomic_##NAME##w_le,                  \
    [MO_16 | MO_BE] = (void *)gen_helper_atomic_##NAME##w_be,                  \
    [MO_32 | MO_LE] = (void *)gen_helper_atomic_##NAME##l_le,                  \
    [MO_32 | MO_BE] = (void *)gen_helper_atomic_##NAME##l_be,                  \
    WITH_ATOMIC64([MO_64 | MO_LE] = (void *)gen_helper_atomic_##NAME##q_le)    \
    WITH_ATOMIC64([MO_64 | MO_BE] = (void *)gen_helper_atomic_##NAME##q_be)    \
};                                                                      \
void tcg_gen_atomic_##NAME##_i32                                        \
    (TCGv_i32 ret, TCGv addr, TCGv_i32 val, TCGArg idx, TCGMemOp memop) \
{                                                                       \
    if (tcg_ctx->tb_cflags & CF_PARALLEL) {                             \
        do_atomic_op_i32(ret, addr, val, idx, memop, table_##NAME);     \
    } else {                                                            \
        do_nonatomic_op_i32(ret, addr, val, idx, memop, NEW,            \
                            tcg_gen_##OP##_i32);                        \
    }                                                                   \
}                                                                       \
void tcg_gen_atomic_##NAME##_i64                                        \
    (TCGv_i64 ret, TCGv addr, TCGv_i64 val, TCGArg idx, TCGMemOp memop) \
{                                                                       \
    if (tcg_ctx->tb_cflags & CF_PARALLEL) {                             \
        do_atomic_op_i64(ret, addr, val, idx, memop, table_##NAME);     \
    } else {                                                            \
        do_nonatomic_op_i64(ret, addr, val, idx, memop, NEW,            \
                            tcg_gen_##OP##_i64);                        \
    }                                                                   \
}

static void do_atomic_op_i64(TCGv_i64 ret, TCGv addr, TCGv_i64 val,
                             TCGArg idx, TCGMemOp memop, void * const table[])
{
    memop = tcg_canonicalize_memop(memop, 1, 0);

    if ((memop & MO_SIZE) == MO_64) {
#ifdef CONFIG_ATOMIC64
        gen_atomic_op_i64 gen;

        gen = table[memop & (MO_SIZE | MO_BSWAP)];
        tcg_debug_assert(gen != NULL);

#ifdef CONFIG_SOFTMMU
        {
            TCGv_i32 oi = tcg_const_i32(make_memop_idx(memop & ~MO_SIGN, idx));
            gen(ret, cpu_env, addr, val, oi);
            tcg_temp_free_i32(oi);
        }
#else
        gen(ret, cpu_env, addr, val);
#endif
#else
        gen_helper_exit_atomic(cpu_env);
        /* Produce a result, so that we have a well-formed opcode stream
           with respect to uses of the result in the (dead) code following.  */
        tcg_gen_movi_i64(ret, 0);
#endif /* CONFIG_ATOMIC64 */
    } else {
        TCGv_i32 v32 = tcg_temp_new_i32();
        TCGv_i32 r32 = tcg_temp_new_i32();

        tcg_gen_extrl_i64_i32(v32, val);
        do_atomic_op_i32(r32, addr, v32, idx, (TCGMemOp)(memop & ~MO_SIGN), table);
        tcg_temp_free_i32(v32);

        tcg_gen_extu_i32_i64(ret, r32);
        tcg_temp_free_i32(r32);

        if (memop & MO_SIGN) {
            tcg_gen_ext_i64(ret, ret, memop);
        }
    }
}

GEN_ATOMIC_HELPER(fetch_add, add, 0)

GEN_ATOMIC_HELPER(fetch_and, and, 0)

GEN_ATOMIC_HELPER(fetch_or, or, 0)

GEN_ATOMIC_HELPER(fetch_xor, xor, 0)

GEN_ATOMIC_HELPER(add_fetch, add, 1)

GEN_ATOMIC_HELPER(and_fetch, and, 1)

GEN_ATOMIC_HELPER(or_fetch, or, 1)

GEN_ATOMIC_HELPER(xor_fetch, xor, 1)

static void tcg_gen_mov2_i32(TCGv_i32 r, TCGv_i32 a, TCGv_i32 b)
{
    tcg_gen_mov_i32(r, b);
}

static void tcg_gen_mov2_i64(TCGv_i64 r, TCGv_i64 a, TCGv_i64 b)
{
    tcg_gen_mov_i64(r, b);
}

GEN_ATOMIC_HELPER(xchg, mov2, 0)

void target_disas(FILE *out, CPUState *cpu, target_ulong code,
                  target_ulong size);

const char *lookup_symbol(target_ulong orig_addr);

#define g2h(x) ((void *)((unsigned long)(target_ulong)(x) + guest_base))

#define MEMSUFFIX _code

#define CODE_ACCESS

#define USUFFIX ub

#define RES_TYPE uint32_t

static inline RES_TYPE
glue(glue(cpu_ld, USUFFIX), MEMSUFFIX)(CPUArchState *env, target_ulong ptr)
{
#if !defined(CODE_ACCESS)
    trace_guest_mem_before_exec(
        ENV_GET_CPU(env), ptr,
        trace_mem_build_info(DATA_SIZE, false, MO_TE, false));
#endif
    return glue(glue(ld, USUFFIX), _p)(g2h(ptr));
}

#define SUFFIX w

#define USUFFIX uw

#define RES_TYPE uint32_t

static inline RES_TYPE
glue(glue(cpu_ld, USUFFIX), MEMSUFFIX)(CPUArchState *env, target_ulong ptr)
{
#if !defined(CODE_ACCESS)
    trace_guest_mem_before_exec(
        ENV_GET_CPU(env), ptr,
        trace_mem_build_info(DATA_SIZE, false, MO_TE, false));
#endif
    return glue(glue(ld, USUFFIX), _p)(g2h(ptr));
}

static inline int
glue(glue(cpu_lds, SUFFIX), MEMSUFFIX)(CPUArchState *env, target_ulong ptr)
{
#if !defined(CODE_ACCESS)
    trace_guest_mem_before_exec(
        ENV_GET_CPU(env), ptr,
        trace_mem_build_info(DATA_SIZE, true, MO_TE, false));
#endif
    return glue(glue(lds, SUFFIX), _p)(g2h(ptr));
}

#define USUFFIX l

#define RES_TYPE uint32_t

static inline RES_TYPE
glue(glue(cpu_ld, USUFFIX), MEMSUFFIX)(CPUArchState *env, target_ulong ptr)
{
#if !defined(CODE_ACCESS)
    trace_guest_mem_before_exec(
        ENV_GET_CPU(env), ptr,
        trace_mem_build_info(DATA_SIZE, false, MO_TE, false));
#endif
    return glue(glue(ld, USUFFIX), _p)(g2h(ptr));
}

#define USUFFIX q

#define RES_TYPE uint64_t

static inline RES_TYPE
glue(glue(cpu_ld, USUFFIX), MEMSUFFIX)(CPUArchState *env, target_ulong ptr)
{
#if !defined(CODE_ACCESS)
    trace_guest_mem_before_exec(
        ENV_GET_CPU(env), ptr,
        trace_mem_build_info(DATA_SIZE, false, MO_TE, false));
#endif
    return glue(glue(ld, USUFFIX), _p)(g2h(ptr));
}

typedef enum DisasJumpType {
    DISAS_NEXT,
    DISAS_TOO_MANY,
    DISAS_NORETURN,
    DISAS_TARGET_0,
    DISAS_TARGET_1,
    DISAS_TARGET_2,
    DISAS_TARGET_3,
    DISAS_TARGET_4,
    DISAS_TARGET_5,
    DISAS_TARGET_6,
    DISAS_TARGET_7,
    DISAS_TARGET_8,
    DISAS_TARGET_9,
    DISAS_TARGET_10,
    DISAS_TARGET_11,
} DisasJumpType;

typedef struct DisasContextBase {
    TranslationBlock *tb;
    target_ulong pc_first;
    target_ulong pc_next;
    DisasJumpType is_jmp;
    unsigned int num_insns;
    bool singlestep_enabled;
} DisasContextBase;

typedef struct TranslatorOps {
    int (*init_disas_context)(DisasContextBase *db, CPUState *cpu,
                              int max_insns);
    void (*tb_start)(DisasContextBase *db, CPUState *cpu);
    void (*insn_start)(DisasContextBase *db, CPUState *cpu);
    bool (*breakpoint_check)(DisasContextBase *db, CPUState *cpu,
                             const CPUBreakpoint *bp);
    void (*translate_insn)(DisasContextBase *db, CPUState *cpu);
    void (*tb_stop)(DisasContextBase *db, CPUState *cpu);
    void (*disas_log)(const DisasContextBase *db, CPUState *cpu);
} TranslatorOps;

void translator_loop(const TranslatorOps *ops, DisasContextBase *db,
                     CPUState *cpu, TranslationBlock *tb);

static inline void log_target_disas(CPUState *cpu, target_ulong start,
                                    target_ulong len)
{
    target_disas(qemu_logfile, cpu, start, len);
}

#define PREFIX_REPZ   0x01

#define PREFIX_REPNZ  0x02

#define PREFIX_LOCK   0x04

#define PREFIX_DATA   0x08

#define PREFIX_ADR    0x10

#define PREFIX_VEX    0x20

#define CODE64(s) ((s)->code64)

#define REX_X(s) ((s)->rex_x)

#define REX_B(s) ((s)->rex_b)

# define ctztl  ctz64

#define CASE_MODRM_MEM_OP(OP) \
    case (0 << 6) | (OP << 3) | 0 ... (0 << 6) | (OP << 3) | 7: \
    case (1 << 6) | (OP << 3) | 0 ... (1 << 6) | (OP << 3) | 7: \
    case (2 << 6) | (OP << 3) | 0 ... (2 << 6) | (OP << 3) | 7

#define CASE_MODRM_OP(OP) \
    case (0 << 6) | (OP << 3) | 0 ... (0 << 6) | (OP << 3) | 7: \
    case (1 << 6) | (OP << 3) | 0 ... (1 << 6) | (OP << 3) | 7: \
    case (2 << 6) | (OP << 3) | 0 ... (2 << 6) | (OP << 3) | 7: \
    case (3 << 6) | (OP << 3) | 0 ... (3 << 6) | (OP << 3) | 7

static TCGv cpu_A0;

static TCGv cpu_cc_dst, cpu_cc_src, cpu_cc_src2, cpu_cc_srcT;

static TCGv_i32 cpu_cc_op;

static TCGv cpu_regs[CPU_NB_REGS];

static TCGv cpu_seg_base[6];

static TCGv_i64 cpu_bndl[4];

static TCGv_i64 cpu_bndu[4];

static TCGv cpu_T0, cpu_T1;

static TCGv cpu_tmp0, cpu_tmp4;

static TCGv_ptr cpu_ptr0, cpu_ptr1;

static TCGv_i32 cpu_tmp2_i32, cpu_tmp3_i32;

static TCGv_i64 cpu_tmp1_i64;

static inline void gen_io_start(void)
{
    TCGv_i32 tmp = tcg_const_i32(1);
    tcg_gen_st_i32(tmp, cpu_env, -ENV_OFFSET + offsetof(CPUState, can_do_io));
    tcg_temp_free_i32(tmp);
}

static inline void gen_io_end(void)
{
    TCGv_i32 tmp = tcg_const_i32(0);
    tcg_gen_st_i32(tmp, cpu_env, -ENV_OFFSET + offsetof(CPUState, can_do_io));
    tcg_temp_free_i32(tmp);
}

static int x86_64_hregs;

typedef struct DisasContext {
    DisasContextBase base;

    /* current insn context */
    int override; /* -1 if no override */
    int prefix;
    TCGMemOp aflag;
    TCGMemOp dflag;
    target_ulong pc_start;
    target_ulong pc; /* pc = eip + cs_base */
    /* current block context */
    target_ulong cs_base; /* base of CS segment */
    int pe;     /* protected mode */
    int code32; /* 32 bit code segment */
#ifdef TARGET_X86_64
    int lma;    /* long mode active */
    int code64; /* 64 bit code segment */
    int rex_x, rex_b;
#endif
    int vex_l;  /* vex vector length */
    int vex_v;  /* vex vvvv register, without 1's compliment.  */
    int ss32;   /* 32 bit stack segment */
    CCOp cc_op;  /* current CC operation */
    bool cc_op_dirty;
    int addseg; /* non zero if either DS/ES/SS have a non zero base */
    int f_st;   /* currently unused */
    int vm86;   /* vm86 mode */
    int cpl;
    int iopl;
    int tf;     /* TF cpu flag */
    int jmp_opt; /* use direct block chaining for direct jumps */
    int repz_opt; /* optimize jumps within repz instructions */
    int mem_index; /* select memory access functions */
    uint64_t flags; /* all execution flags */
    int popl_esp_hack; /* for correct popl with esp base handling */
    int rip_offset; /* only used in x86_64, but left for simplicity */
    int cpuid_features;
    int cpuid_ext_features;
    int cpuid_ext2_features;
    int cpuid_ext3_features;
    int cpuid_7_0_ebx_features;
    int cpuid_xsave_features;
    sigjmp_buf jmpbuf;
} DisasContext;

static void gen_eob(DisasContext *s);

static void gen_jr(DisasContext *s, TCGv dest);

static void gen_jmp(DisasContext *s, target_ulong eip);

static void gen_jmp_tb(DisasContext *s, target_ulong eip, int tb_num);

static void gen_op(DisasContext *s1, int op, TCGMemOp ot, int d);

enum {
    OP_ADDL,
    OP_ORL,
    OP_ADCL,
    OP_SBBL,
    OP_ANDL,
    OP_SUBL,
    OP_XORL,
    OP_CMPL,
};

enum {
    OP_ROL,
    OP_ROR,
    OP_RCL,
    OP_RCR,
    OP_SHL,
    OP_SHR,
    OP_SHL1, /* undocumented */
    OP_SAR = 7,
};

enum {
    JCC_O,
    JCC_B,
    JCC_Z,
    JCC_BE,
    JCC_S,
    JCC_P,
    JCC_L,
    JCC_LE,
};

enum {
    /* I386 int registers */
    OR_EAX,   /* MUST be even numbered */
    OR_ECX,
    OR_EDX,
    OR_EBX,
    OR_ESP,
    OR_EBP,
    OR_ESI,
    OR_EDI,

    OR_TMP0 = 16,    /* temporary operand register */
    OR_TMP1,
    OR_A0, /* temporary register used when doing address evaluation */
};

enum {
    USES_CC_DST  = 1,
    USES_CC_SRC  = 2,
    USES_CC_SRC2 = 4,
    USES_CC_SRCT = 8,
};

static const uint8_t cc_op_live[CC_OP_NB] = {
    [CC_OP_DYNAMIC] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_EFLAGS] = USES_CC_SRC,
    [CC_OP_MULB ... CC_OP_MULQ] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_ADDB ... CC_OP_ADDQ] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_ADCB ... CC_OP_ADCQ] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_SUBB ... CC_OP_SUBQ] = USES_CC_DST | USES_CC_SRC | USES_CC_SRCT,
    [CC_OP_SBBB ... CC_OP_SBBQ] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_LOGICB ... CC_OP_LOGICQ] = USES_CC_DST,
    [CC_OP_INCB ... CC_OP_INCQ] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_DECB ... CC_OP_DECQ] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_SHLB ... CC_OP_SHLQ] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_SARB ... CC_OP_SARQ] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_BMILGB ... CC_OP_BMILGQ] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_ADCX] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_ADOX] = USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_ADCOX] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_CLR] = 0,
    [CC_OP_POPCNT] = USES_CC_SRC,
};

static void set_cc_op(DisasContext *s, CCOp op)
{
    int dead;

    if (s->cc_op == op) {
        return;
    }

    /* Discard CC computation that will no longer be used.  */
    dead = cc_op_live[s->cc_op] & ~cc_op_live[op];
    if (dead & USES_CC_DST) {
        tcg_gen_discard_tl(cpu_cc_dst);
    }
    if (dead & USES_CC_SRC) {
        tcg_gen_discard_tl(cpu_cc_src);
    }
    if (dead & USES_CC_SRC2) {
        tcg_gen_discard_tl(cpu_cc_src2);
    }
    if (dead & USES_CC_SRCT) {
        tcg_gen_discard_tl(cpu_cc_srcT);
    }

    if (op == CC_OP_DYNAMIC) {
        /* The DYNAMIC setting is translator only, and should never be
           stored.  Thus we always consider it clean.  */
        s->cc_op_dirty = false;
    } else {
        /* Discard any computed CC_OP value (see shifts).  */
        if (s->cc_op == CC_OP_DYNAMIC) {
            tcg_gen_discard_i32(cpu_cc_op);
        }
        s->cc_op_dirty = true;
    }
    s->cc_op = op;
}

static void gen_update_cc_op(DisasContext *s)
{
    if (s->cc_op_dirty) {
        tcg_gen_movi_i32(cpu_cc_op, s->cc_op);
        s->cc_op_dirty = false;
    }
}

static inline bool byte_reg_is_xH(int reg)
{
    if (reg < 4) {
        return false;
    }
#ifdef TARGET_X86_64
    if (reg >= 8 || x86_64_hregs) {
        return false;
    }
#endif
    return true;
}

static inline TCGMemOp mo_pushpop(DisasContext *s, TCGMemOp ot)
{
    if (CODE64(s)) {
        return ot == MO_16 ? MO_16 : MO_64;
    } else {
        return ot;
    }
}

static inline TCGMemOp mo_stacksize(DisasContext *s)
{
    return CODE64(s) ? MO_64 : s->ss32 ? MO_32 : MO_16;
}

static inline TCGMemOp mo_64_32(TCGMemOp ot)
{
#ifdef TARGET_X86_64
    return ot == MO_64 ? MO_64 : MO_32;
#else
    return MO_32;
#endif
}

static inline TCGMemOp mo_b_d(int b, TCGMemOp ot)
{
    return b & 1 ? ot : MO_8;
}

static inline TCGMemOp mo_b_d32(int b, TCGMemOp ot)
{
    return b & 1 ? (ot == MO_16 ? MO_16 : MO_32) : MO_8;
}

static void gen_op_mov_reg_v(TCGMemOp ot, int reg, TCGv t0)
{
    switch(ot) {
    case MO_8:
        if (!byte_reg_is_xH(reg)) {
            tcg_gen_deposit_tl(cpu_regs[reg], cpu_regs[reg], t0, 0, 8);
        } else {
            tcg_gen_deposit_tl(cpu_regs[reg - 4], cpu_regs[reg - 4], t0, 8, 8);
        }
        break;
    case MO_16:
        tcg_gen_deposit_tl(cpu_regs[reg], cpu_regs[reg], t0, 0, 16);
        break;
    case MO_32:
        /* For x86_64, this sets the higher half of register to zero.
           For i386, this is equivalent to a mov. */
        tcg_gen_ext32u_tl(cpu_regs[reg], t0);
        break;
#ifdef TARGET_X86_64
    case MO_64:
        tcg_gen_mov_tl(cpu_regs[reg], t0);
        break;
#endif
    default:
        tcg_abort();
    }
}

static inline void gen_op_mov_v_reg(TCGMemOp ot, TCGv t0, int reg)
{
    if (ot == MO_8 && byte_reg_is_xH(reg)) {
        tcg_gen_extract_tl(t0, cpu_regs[reg - 4], 8, 8);
    } else {
        tcg_gen_mov_tl(t0, cpu_regs[reg]);
    }
}

static void gen_add_A0_im(DisasContext *s, int val)
{
    tcg_gen_addi_tl(cpu_A0, cpu_A0, val);
    if (!CODE64(s)) {
        tcg_gen_ext32u_tl(cpu_A0, cpu_A0);
    }
}

static inline void gen_op_jmp_v(TCGv dest)
{
    tcg_gen_st_tl(dest, cpu_env, offsetof(CPUX86State, eip));
}

static inline void gen_op_add_reg_im(TCGMemOp size, int reg, int32_t val)
{
    tcg_gen_addi_tl(cpu_tmp0, cpu_regs[reg], val);
    gen_op_mov_reg_v(size, reg, cpu_tmp0);
}

static inline void gen_op_add_reg_T0(TCGMemOp size, int reg)
{
    tcg_gen_add_tl(cpu_tmp0, cpu_regs[reg], cpu_T0);
    gen_op_mov_reg_v(size, reg, cpu_tmp0);
}

static inline void gen_op_ld_v(DisasContext *s, int idx, TCGv t0, TCGv a0)
{
    tcg_gen_qemu_ld_tl(t0, a0, s->mem_index, (TCGMemOp)(idx | MO_LE));
}

static inline void gen_op_st_v(DisasContext *s, int idx, TCGv t0, TCGv a0)
{
    tcg_gen_qemu_st_tl(t0, a0, s->mem_index, (TCGMemOp)(idx | MO_LE));
}

static inline void gen_op_st_rm_T0_A0(DisasContext *s, int idx, int d)
{
    if (d == OR_TMP0) {
        gen_op_st_v(s, idx, cpu_T0, cpu_A0);
    } else {
        gen_op_mov_reg_v((TCGMemOp)idx, d, cpu_T0);
    }
}

static inline void gen_jmp_im(target_ulong pc)
{
    tcg_gen_movi_tl(cpu_tmp0, pc);
    gen_op_jmp_v(cpu_tmp0);
}

static void gen_lea_v_seg(DisasContext *s, TCGMemOp aflag, TCGv a0,
                          int def_seg, int ovr_seg)
{
    switch (aflag) {
#ifdef TARGET_X86_64
    case MO_64:
        if (ovr_seg < 0) {
            tcg_gen_mov_tl(cpu_A0, a0);
            return;
        }
        break;
#endif
    case MO_32:
        /* 32 bit address */
        if (ovr_seg < 0 && s->addseg) {
            ovr_seg = def_seg;
        }
        if (ovr_seg < 0) {
            tcg_gen_ext32u_tl(cpu_A0, a0);
            return;
        }
        break;
    case MO_16:
        /* 16 bit address */
        tcg_gen_ext16u_tl(cpu_A0, a0);
        a0 = cpu_A0;
        if (ovr_seg < 0) {
            if (s->addseg) {
                ovr_seg = def_seg;
            } else {
                return;
            }
        }
        break;
    default:
        tcg_abort();
    }

    if (ovr_seg >= 0) {
        TCGv seg = cpu_seg_base[ovr_seg];

        if (aflag == MO_64) {
            tcg_gen_add_tl(cpu_A0, a0, seg);
        } else if (CODE64(s)) {
            tcg_gen_ext32u_tl(cpu_A0, a0);
            tcg_gen_add_tl(cpu_A0, cpu_A0, seg);
        } else {
            tcg_gen_add_tl(cpu_A0, a0, seg);
            tcg_gen_ext32u_tl(cpu_A0, cpu_A0);
        }
    }
}

static inline void gen_string_movl_A0_ESI(DisasContext *s)
{
    gen_lea_v_seg(s, s->aflag, cpu_regs[R_ESI], R_DS, s->override);
}

static inline void gen_string_movl_A0_EDI(DisasContext *s)
{
    gen_lea_v_seg(s, s->aflag, cpu_regs[R_EDI], R_ES, -1);
}

static inline void gen_op_movl_T0_Dshift(TCGMemOp ot)
{
    tcg_gen_ld32s_tl(cpu_T0, cpu_env, offsetof(CPUX86State, df));
    tcg_gen_shli_tl(cpu_T0, cpu_T0, ot);
}

static TCGv gen_ext_tl(TCGv dst, TCGv src, TCGMemOp size, bool sign)
{
    switch (size) {
    case MO_8:
        if (sign) {
            tcg_gen_ext8s_tl(dst, src);
        } else {
            tcg_gen_ext8u_tl(dst, src);
        }
        return dst;
    case MO_16:
        if (sign) {
            tcg_gen_ext16s_tl(dst, src);
        } else {
            tcg_gen_ext16u_tl(dst, src);
        }
        return dst;
#ifdef TARGET_X86_64
    case MO_32:
        if (sign) {
            tcg_gen_ext32s_tl(dst, src);
        } else {
            tcg_gen_ext32u_tl(dst, src);
        }
        return dst;
#endif
    default:
        return src;
    }
}

static void gen_extu(TCGMemOp ot, TCGv reg)
{
    gen_ext_tl(reg, reg, ot, false);
}

static void gen_exts(TCGMemOp ot, TCGv reg)
{
    gen_ext_tl(reg, reg, ot, true);
}

static inline void gen_op_jnz_ecx(TCGMemOp size, TCGLabel *label1)
{
    tcg_gen_mov_tl(cpu_tmp0, cpu_regs[R_ECX]);
    gen_extu(size, cpu_tmp0);
    tcg_gen_brcondi_tl(TCG_COND_NE, cpu_tmp0, 0, label1);
}

static inline void gen_op_jz_ecx(TCGMemOp size, TCGLabel *label1)
{
    tcg_gen_mov_tl(cpu_tmp0, cpu_regs[R_ECX]);
    gen_extu(size, cpu_tmp0);
    tcg_gen_brcondi_tl(TCG_COND_EQ, cpu_tmp0, 0, label1);
}

static void gen_helper_in_func(TCGMemOp ot, TCGv v, TCGv_i32 n)
{
    switch (ot) {
    case MO_8:
        gen_helper_inb(v, cpu_env, n);
        break;
    case MO_16:
        gen_helper_inw(v, cpu_env, n);
        break;
    case MO_32:
        gen_helper_inl(v, cpu_env, n);
        break;
    default:
        tcg_abort();
    }
}

static void gen_helper_out_func(TCGMemOp ot, TCGv_i32 v, TCGv_i32 n)
{
    switch (ot) {
    case MO_8:
        gen_helper_outb(cpu_env, v, n);
        break;
    case MO_16:
        gen_helper_outw(cpu_env, v, n);
        break;
    case MO_32:
        gen_helper_outl(cpu_env, v, n);
        break;
    default:
        tcg_abort();
    }
}

static void gen_check_io(DisasContext *s, TCGMemOp ot, target_ulong cur_eip,
                         uint32_t svm_flags)
{
    target_ulong next_eip;

    if (s->pe && (s->cpl > s->iopl || s->vm86)) {
        tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_T0);
        switch (ot) {
        case MO_8:
            gen_helper_check_iob(cpu_env, cpu_tmp2_i32);
            break;
        case MO_16:
            gen_helper_check_iow(cpu_env, cpu_tmp2_i32);
            break;
        case MO_32:
            gen_helper_check_iol(cpu_env, cpu_tmp2_i32);
            break;
        default:
            tcg_abort();
        }
    }
    if(s->flags & HF_SVMI_MASK) {
        gen_update_cc_op(s);
        gen_jmp_im(cur_eip);
        svm_flags |= (1 << (4 + ot));
        next_eip = s->pc - s->cs_base;
        tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_T0);
        gen_helper_svm_check_io(cpu_env, cpu_tmp2_i32,
                                tcg_const_i32(svm_flags),
                                tcg_const_i32(next_eip - cur_eip));
    }
}

static inline void gen_movs(DisasContext *s, TCGMemOp ot)
{
    gen_string_movl_A0_ESI(s);
    gen_op_ld_v(s, ot, cpu_T0, cpu_A0);
    gen_string_movl_A0_EDI(s);
    gen_op_st_v(s, ot, cpu_T0, cpu_A0);
    gen_op_movl_T0_Dshift(ot);
    gen_op_add_reg_T0(s->aflag, R_ESI);
    gen_op_add_reg_T0(s->aflag, R_EDI);
}

static void gen_op_update1_cc(void)
{
    tcg_gen_mov_tl(cpu_cc_dst, cpu_T0);
}

static void gen_op_update2_cc(void)
{
    tcg_gen_mov_tl(cpu_cc_src, cpu_T1);
    tcg_gen_mov_tl(cpu_cc_dst, cpu_T0);
}

static void gen_op_update3_cc(TCGv reg)
{
    tcg_gen_mov_tl(cpu_cc_src2, reg);
    tcg_gen_mov_tl(cpu_cc_src, cpu_T1);
    tcg_gen_mov_tl(cpu_cc_dst, cpu_T0);
}

static inline void gen_op_testl_T0_T1_cc(void)
{
    tcg_gen_and_tl(cpu_cc_dst, cpu_T0, cpu_T1);
}

static void gen_op_update_neg_cc(void)
{
    tcg_gen_mov_tl(cpu_cc_dst, cpu_T0);
    tcg_gen_neg_tl(cpu_cc_src, cpu_T0);
    tcg_gen_movi_tl(cpu_cc_srcT, 0);
}

static void gen_compute_eflags(DisasContext *s)
{
    TCGv zero, dst, src1, src2;
    int live, dead;

    if (s->cc_op == CC_OP_EFLAGS) {
        return;
    }
    if (s->cc_op == CC_OP_CLR) {
        tcg_gen_movi_tl(cpu_cc_src, CC_Z | CC_P);
        set_cc_op(s, CC_OP_EFLAGS);
        return;
    }

    TCGV_UNUSED(zero);
    dst = cpu_cc_dst;
    src1 = cpu_cc_src;
    src2 = cpu_cc_src2;

    /* Take care to not read values that are not live.  */
    live = cc_op_live[s->cc_op] & ~USES_CC_SRCT;
    dead = live ^ (USES_CC_DST | USES_CC_SRC | USES_CC_SRC2);
    if (dead) {
        zero = tcg_const_tl(0);
        if (dead & USES_CC_DST) {
            dst = zero;
        }
        if (dead & USES_CC_SRC) {
            src1 = zero;
        }
        if (dead & USES_CC_SRC2) {
            src2 = zero;
        }
    }

    gen_update_cc_op(s);
    gen_helper_cc_compute_all(cpu_cc_src, dst, src1, src2, cpu_cc_op);
    set_cc_op(s, CC_OP_EFLAGS);

    if (dead) {
        tcg_temp_free(zero);
    }
}

typedef struct CCPrepare {
    TCGCond cond;
    TCGv reg;
    TCGv reg2;
    target_ulong imm;
    target_ulong mask;
    bool use_reg2;
    bool no_setcond;
} CCPrepare;

static CCPrepare gen_prepare_eflags_c(DisasContext *s, TCGv reg)
{
    TCGv t0, t1;
    int size, shift;

    switch (s->cc_op) {
    case CC_OP_SUBB ... CC_OP_SUBQ:
        /* (DATA_TYPE)CC_SRCT < (DATA_TYPE)CC_SRC */
        size = s->cc_op - CC_OP_SUBB;
        t1 = gen_ext_tl(cpu_tmp0, cpu_cc_src, (TCGMemOp)size, false);
        /* If no temporary was used, be careful not to alias t1 and t0.  */
        t0 = t1 == cpu_cc_src ? cpu_tmp0 : reg;
        tcg_gen_mov_tl(t0, cpu_cc_srcT);
        gen_extu((TCGMemOp)size, t0);
        goto add_sub;

    case CC_OP_ADDB ... CC_OP_ADDQ:
        /* (DATA_TYPE)CC_DST < (DATA_TYPE)CC_SRC */
        size = s->cc_op - CC_OP_ADDB;
        t1 = gen_ext_tl(cpu_tmp0, cpu_cc_src, (TCGMemOp)size, false);
        t0 = gen_ext_tl(reg, cpu_cc_dst, (TCGMemOp)size, false);
    add_sub:
        return (CCPrepare) { .cond = TCG_COND_LTU, .reg = t0,
                             .reg2 = t1, .mask = (target_ulong)-1, .use_reg2 = true };

    case CC_OP_LOGICB ... CC_OP_LOGICQ:
    case CC_OP_CLR:
    case CC_OP_POPCNT:
        return (CCPrepare) { .cond = TCG_COND_NEVER, .mask = (target_ulong)-1 };

    case CC_OP_INCB ... CC_OP_INCQ:
    case CC_OP_DECB ... CC_OP_DECQ:
        return (CCPrepare) { .cond = TCG_COND_NE, .reg = cpu_cc_src,
                             .mask = (target_ulong)-1, .no_setcond = true };

    case CC_OP_SHLB ... CC_OP_SHLQ:
        /* (CC_SRC >> (DATA_BITS - 1)) & 1 */
        size = s->cc_op - CC_OP_SHLB;
        shift = (8 << size) - 1;
        return (CCPrepare) { .cond = TCG_COND_NE, .reg = cpu_cc_src,
                             .mask = (target_ulong)1 << shift };

    case CC_OP_MULB ... CC_OP_MULQ:
        return (CCPrepare) { .cond = TCG_COND_NE,
                             .reg = cpu_cc_src, .mask = (target_ulong)-1 };

    case CC_OP_BMILGB ... CC_OP_BMILGQ:
        size = s->cc_op - CC_OP_BMILGB;
        t0 = gen_ext_tl(reg, cpu_cc_src, (TCGMemOp)size, false);
        return (CCPrepare) { .cond = TCG_COND_EQ, .reg = t0, .mask = (target_ulong)-1 };

    case CC_OP_ADCX:
    case CC_OP_ADCOX:
        return (CCPrepare) { .cond = TCG_COND_NE, .reg = cpu_cc_dst,
                             .mask = (target_ulong)-1, .no_setcond = true };

    case CC_OP_EFLAGS:
    case CC_OP_SARB ... CC_OP_SARQ:
        /* CC_SRC & 1 */
        return (CCPrepare) { .cond = TCG_COND_NE,
                             .reg = cpu_cc_src, .mask = CC_C };

    default:
       /* The need to compute only C from CC_OP_DYNAMIC is important
          in efficiently implementing e.g. INC at the start of a TB.  */
       gen_update_cc_op(s);
       gen_helper_cc_compute_c(reg, cpu_cc_dst, cpu_cc_src,
                               cpu_cc_src2, cpu_cc_op);
       return (CCPrepare) { .cond = TCG_COND_NE, .reg = reg,
                            .mask = (target_ulong)-1, .no_setcond = true };
    }
}

static CCPrepare gen_prepare_eflags_p(DisasContext *s, TCGv reg)
{
    gen_compute_eflags(s);
    return (CCPrepare) { .cond = TCG_COND_NE, .reg = cpu_cc_src,
                         .mask = CC_P };
}

static CCPrepare gen_prepare_eflags_s(DisasContext *s, TCGv reg)
{
    switch (s->cc_op) {
    case CC_OP_DYNAMIC:
        gen_compute_eflags(s);
        /* FALLTHRU */
    case CC_OP_EFLAGS:
    case CC_OP_ADCX:
    case CC_OP_ADOX:
    case CC_OP_ADCOX:
        return (CCPrepare) { .cond = TCG_COND_NE, .reg = cpu_cc_src,
                             .mask = CC_S };
    case CC_OP_CLR:
    case CC_OP_POPCNT:
        return (CCPrepare) { .cond = TCG_COND_NEVER, .mask = (target_ulong)-1 };
    default:
        {
            TCGMemOp size = (TCGMemOp)((s->cc_op - CC_OP_ADDB) & 3);
            TCGv t0 = gen_ext_tl(reg, cpu_cc_dst, size, true);
            return (CCPrepare) { .cond = TCG_COND_LT, .reg = t0, .mask = (target_ulong)-1 };
        }
    }
}

static CCPrepare gen_prepare_eflags_o(DisasContext *s, TCGv reg)
{
    switch (s->cc_op) {
    case CC_OP_ADOX:
    case CC_OP_ADCOX:
        return (CCPrepare) { .cond = TCG_COND_NE, .reg = cpu_cc_src2,
                             .mask = (target_ulong)-1, .no_setcond = true };
    case CC_OP_CLR:
    case CC_OP_POPCNT:
        return (CCPrepare) { .cond = TCG_COND_NEVER, .mask = (target_ulong)-1 };
    default:
        gen_compute_eflags(s);
        return (CCPrepare) { .cond = TCG_COND_NE, .reg = cpu_cc_src,
                             .mask = CC_O };
    }
}

static CCPrepare gen_prepare_eflags_z(DisasContext *s, TCGv reg)
{
    switch (s->cc_op) {
    case CC_OP_DYNAMIC:
        gen_compute_eflags(s);
        /* FALLTHRU */
    case CC_OP_EFLAGS:
    case CC_OP_ADCX:
    case CC_OP_ADOX:
    case CC_OP_ADCOX:
        return (CCPrepare) { .cond = TCG_COND_NE, .reg = cpu_cc_src,
                             .mask = CC_Z };
    case CC_OP_CLR:
        return (CCPrepare) { .cond = TCG_COND_ALWAYS, .mask = (target_ulong)-1 };
    case CC_OP_POPCNT:
        return (CCPrepare) { .cond = TCG_COND_EQ, .reg = cpu_cc_src,
                             .mask = (target_ulong)-1 };
    default:
        {
            TCGMemOp size = (TCGMemOp)((s->cc_op - CC_OP_ADDB) & 3);
            TCGv t0 = gen_ext_tl(reg, cpu_cc_dst, size, false);
            return (CCPrepare) { .cond = TCG_COND_EQ, .reg = t0, .mask = (target_ulong)-1 };
        }
    }
}

static CCPrepare gen_prepare_cc(DisasContext *s, int b, TCGv reg)
{
    int inv, jcc_op, cond;
    TCGMemOp size;
    CCPrepare cc;
    TCGv t0;

    inv = b & 1;
    jcc_op = (b >> 1) & 7;

    switch (s->cc_op) {
    case CC_OP_SUBB ... CC_OP_SUBQ:
        /* We optimize relational operators for the cmp/jcc case.  */
        size = (TCGMemOp)(s->cc_op - CC_OP_SUBB);
        switch (jcc_op) {
        case JCC_BE:
            tcg_gen_mov_tl(cpu_tmp4, cpu_cc_srcT);
            gen_extu(size, cpu_tmp4);
            t0 = gen_ext_tl(cpu_tmp0, cpu_cc_src, size, false);
            cc = (CCPrepare) { .cond = TCG_COND_LEU, .reg = cpu_tmp4,
                               .reg2 = t0, .mask = (target_ulong)-1, .use_reg2 = true };
            break;

        case JCC_L:
            cond = TCG_COND_LT;
            goto fast_jcc_l;
        case JCC_LE:
            cond = TCG_COND_LE;
        fast_jcc_l:
            tcg_gen_mov_tl(cpu_tmp4, cpu_cc_srcT);
            gen_exts(size, cpu_tmp4);
            t0 = gen_ext_tl(cpu_tmp0, cpu_cc_src, size, true);
            cc = (CCPrepare) { .cond = (TCGCond)cond, .reg = cpu_tmp4,
                               .reg2 = t0, .mask = (target_ulong)-1, .use_reg2 = true };
            break;

        default:
            goto slow_jcc;
        }
        break;

    default:
    slow_jcc:
        /* This actually generates good code for JC, JZ and JS.  */
        switch (jcc_op) {
        case JCC_O:
            cc = gen_prepare_eflags_o(s, reg);
            break;
        case JCC_B:
            cc = gen_prepare_eflags_c(s, reg);
            break;
        case JCC_Z:
            cc = gen_prepare_eflags_z(s, reg);
            break;
        case JCC_BE:
            gen_compute_eflags(s);
            cc = (CCPrepare) { .cond = TCG_COND_NE, .reg = cpu_cc_src,
                               .mask = CC_Z | CC_C };
            break;
        case JCC_S:
            cc = gen_prepare_eflags_s(s, reg);
            break;
        case JCC_P:
            cc = gen_prepare_eflags_p(s, reg);
            break;
        case JCC_L:
            gen_compute_eflags(s);
            if (reg == cpu_cc_src) {
                reg = cpu_tmp0;
            }
            tcg_gen_shri_tl(reg, cpu_cc_src, 4); /* CC_O -> CC_S */
            tcg_gen_xor_tl(reg, reg, cpu_cc_src);
            cc = (CCPrepare) { .cond = TCG_COND_NE, .reg = reg,
                               .mask = CC_S };
            break;
        default:
        case JCC_LE:
            gen_compute_eflags(s);
            if (reg == cpu_cc_src) {
                reg = cpu_tmp0;
            }
            tcg_gen_shri_tl(reg, cpu_cc_src, 4); /* CC_O -> CC_S */
            tcg_gen_xor_tl(reg, reg, cpu_cc_src);
            cc = (CCPrepare) { .cond = TCG_COND_NE, .reg = reg,
                               .mask = CC_S | CC_Z };
            break;
        }
        break;
    }

    if (inv) {
        cc.cond = tcg_invert_cond(cc.cond);
    }
    return cc;
}

static void gen_setcc1(DisasContext *s, int b, TCGv reg)
{
    CCPrepare cc = gen_prepare_cc(s, b, reg);

    if (cc.no_setcond) {
        if (cc.cond == TCG_COND_EQ) {
            tcg_gen_xori_tl(reg, cc.reg, 1);
        } else {
            tcg_gen_mov_tl(reg, cc.reg);
        }
        return;
    }

    if (cc.cond == TCG_COND_NE && !cc.use_reg2 && cc.imm == 0 &&
        cc.mask != 0 && (cc.mask & (cc.mask - 1)) == 0) {
        tcg_gen_shri_tl(reg, cc.reg, ctztl(cc.mask));
        tcg_gen_andi_tl(reg, reg, 1);
        return;
    }
    if (cc.mask != -1) {
        tcg_gen_andi_tl(reg, cc.reg, cc.mask);
        cc.reg = reg;
    }
    if (cc.use_reg2) {
        tcg_gen_setcond_tl(cc.cond, reg, cc.reg, cc.reg2);
    } else {
        tcg_gen_setcondi_tl(cc.cond, reg, cc.reg, cc.imm);
    }
}

static inline void gen_compute_eflags_c(DisasContext *s, TCGv reg)
{
    gen_setcc1(s, JCC_B << 1, reg);
}

static inline void gen_jcc1_noeob(DisasContext *s, int b, TCGLabel *l1)
{
    CCPrepare cc = gen_prepare_cc(s, b, cpu_T0);

    if (cc.mask != -1) {
        tcg_gen_andi_tl(cpu_T0, cc.reg, cc.mask);
        cc.reg = cpu_T0;
    }
    if (cc.use_reg2) {
        tcg_gen_brcond_tl(cc.cond, cc.reg, cc.reg2, l1);
    } else {
        tcg_gen_brcondi_tl(cc.cond, cc.reg, cc.imm, l1);
    }
}

static inline void gen_jcc1(DisasContext *s, int b, TCGLabel *l1)
{
    CCPrepare cc = gen_prepare_cc(s, b, cpu_T0);

    gen_update_cc_op(s);
    if (cc.mask != -1) {
        tcg_gen_andi_tl(cpu_T0, cc.reg, cc.mask);
        cc.reg = cpu_T0;
    }
    set_cc_op(s, CC_OP_DYNAMIC);
    if (cc.use_reg2) {
        tcg_gen_brcond_tl(cc.cond, cc.reg, cc.reg2, l1);
    } else {
        tcg_gen_brcondi_tl(cc.cond, cc.reg, cc.imm, l1);
    }
}

static TCGLabel *gen_jz_ecx_string(DisasContext *s, target_ulong next_eip)
{
    TCGLabel *l1 = gen_new_label();
    TCGLabel *l2 = gen_new_label();
    gen_op_jnz_ecx(s->aflag, l1);
    gen_set_label(l2);
    gen_jmp_tb(s, next_eip, 1);
    gen_set_label(l1);
    return l2;
}

static inline void gen_stos(DisasContext *s, TCGMemOp ot)
{
    gen_op_mov_v_reg(MO_32, cpu_T0, R_EAX);
    gen_string_movl_A0_EDI(s);
    gen_op_st_v(s, ot, cpu_T0, cpu_A0);
    gen_op_movl_T0_Dshift(ot);
    gen_op_add_reg_T0(s->aflag, R_EDI);
}

static inline void gen_lods(DisasContext *s, TCGMemOp ot)
{
    gen_string_movl_A0_ESI(s);
    gen_op_ld_v(s, ot, cpu_T0, cpu_A0);
    gen_op_mov_reg_v(ot, R_EAX, cpu_T0);
    gen_op_movl_T0_Dshift(ot);
    gen_op_add_reg_T0(s->aflag, R_ESI);
}

static inline void gen_scas(DisasContext *s, TCGMemOp ot)
{
    gen_string_movl_A0_EDI(s);
    gen_op_ld_v(s, ot, cpu_T1, cpu_A0);
    gen_op(s, OP_CMPL, ot, R_EAX);
    gen_op_movl_T0_Dshift(ot);
    gen_op_add_reg_T0(s->aflag, R_EDI);
}

static inline void gen_cmps(DisasContext *s, TCGMemOp ot)
{
    gen_string_movl_A0_EDI(s);
    gen_op_ld_v(s, ot, cpu_T1, cpu_A0);
    gen_string_movl_A0_ESI(s);
    gen_op(s, OP_CMPL, ot, OR_TMP0);
    gen_op_movl_T0_Dshift(ot);
    gen_op_add_reg_T0(s->aflag, R_ESI);
    gen_op_add_reg_T0(s->aflag, R_EDI);
}

static void gen_bpt_io(DisasContext *s, TCGv_i32 t_port, int ot)
{
    if (s->flags & HF_IOBPT_MASK) {
        TCGv_i32 t_size = tcg_const_i32(1 << ot);
        TCGv t_next = tcg_const_tl(s->pc - s->cs_base);

        gen_helper_bpt_io(cpu_env, t_port, t_size, t_next);
        tcg_temp_free_i32(t_size);
        tcg_temp_free(t_next);
    }
}

static inline void gen_ins(DisasContext *s, TCGMemOp ot)
{
    if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
        gen_io_start();
    }
    gen_string_movl_A0_EDI(s);
    /* Note: we must do this dummy write first to be restartable in
       case of page fault. */
    tcg_gen_movi_tl(cpu_T0, 0);
    gen_op_st_v(s, ot, cpu_T0, cpu_A0);
    tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_regs[R_EDX]);
    tcg_gen_andi_i32(cpu_tmp2_i32, cpu_tmp2_i32, 0xffff);
    gen_helper_in_func(ot, cpu_T0, cpu_tmp2_i32);
    gen_op_st_v(s, ot, cpu_T0, cpu_A0);
    gen_op_movl_T0_Dshift(ot);
    gen_op_add_reg_T0(s->aflag, R_EDI);
    gen_bpt_io(s, cpu_tmp2_i32, ot);
    if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
        gen_io_end();
    }
}

#define GEN_REPZ(op)                                                          \
static inline void gen_repz_ ## op(DisasContext *s, TCGMemOp ot,              \
                                 target_ulong cur_eip, target_ulong next_eip) \
{                                                                             \
    TCGLabel *l2;                                                             \
    gen_update_cc_op(s);                                                      \
    l2 = gen_jz_ecx_string(s, next_eip);                                      \
    gen_ ## op(s, ot);                                                        \
    gen_op_add_reg_im(s->aflag, R_ECX, -1);                                   \
    /* a loop would cause two single step exceptions if ECX = 1               \
       before rep string_insn */                                              \
    if (s->repz_opt)                                                          \
        gen_op_jz_ecx(s->aflag, l2);                                          \
    gen_jmp(s, cur_eip);                                                      \
}

#define GEN_REPZ2(op)                                                         \
static inline void gen_repz_ ## op(DisasContext *s, TCGMemOp ot,              \
                                   target_ulong cur_eip,                      \
                                   target_ulong next_eip,                     \
                                   int nz)                                    \
{                                                                             \
    TCGLabel *l2;                                                             \
    gen_update_cc_op(s);                                                      \
    l2 = gen_jz_ecx_string(s, next_eip);                                      \
    gen_ ## op(s, ot);                                                        \
    gen_op_add_reg_im(s->aflag, R_ECX, -1);                                   \
    gen_update_cc_op(s);                                                      \
    gen_jcc1(s, (JCC_Z << 1) | (nz ^ 1), l2);                                 \
    if (s->repz_opt)                                                          \
        gen_op_jz_ecx(s->aflag, l2);                                          \
    gen_jmp(s, cur_eip);                                                      \
}

GEN_REPZ(movs)

static inline void gen_outs(DisasContext *s, TCGMemOp ot)
{
    if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
        gen_io_start();
    }
    gen_string_movl_A0_ESI(s);
    gen_op_ld_v(s, ot, cpu_T0, cpu_A0);

    tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_regs[R_EDX]);
    tcg_gen_andi_i32(cpu_tmp2_i32, cpu_tmp2_i32, 0xffff);
    tcg_gen_trunc_tl_i32(cpu_tmp3_i32, cpu_T0);
    gen_helper_out_func(ot, cpu_tmp2_i32, cpu_tmp3_i32);
    gen_op_movl_T0_Dshift(ot);
    gen_op_add_reg_T0(s->aflag, R_ESI);
    gen_bpt_io(s, cpu_tmp2_i32, ot);
    if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
        gen_io_end();
    }
}

GEN_REPZ(stos)

GEN_REPZ(lods)

GEN_REPZ(ins)

GEN_REPZ(outs)

GEN_REPZ2(scas)

GEN_REPZ2(cmps)

static void gen_helper_fp_arith_ST0_FT0(int op)
{
    switch (op) {
    case 0:
        gen_helper_fadd_ST0_FT0(cpu_env);
        break;
    case 1:
        gen_helper_fmul_ST0_FT0(cpu_env);
        break;
    case 2:
        gen_helper_fcom_ST0_FT0(cpu_env);
        break;
    case 3:
        gen_helper_fcom_ST0_FT0(cpu_env);
        break;
    case 4:
        gen_helper_fsub_ST0_FT0(cpu_env);
        break;
    case 5:
        gen_helper_fsubr_ST0_FT0(cpu_env);
        break;
    case 6:
        gen_helper_fdiv_ST0_FT0(cpu_env);
        break;
    case 7:
        gen_helper_fdivr_ST0_FT0(cpu_env);
        break;
    }
}

static void gen_helper_fp_arith_STN_ST0(int op, int opreg)
{
    TCGv_i32 tmp = tcg_const_i32(opreg);
    switch (op) {
    case 0:
        gen_helper_fadd_STN_ST0(cpu_env, tmp);
        break;
    case 1:
        gen_helper_fmul_STN_ST0(cpu_env, tmp);
        break;
    case 4:
        gen_helper_fsubr_STN_ST0(cpu_env, tmp);
        break;
    case 5:
        gen_helper_fsub_STN_ST0(cpu_env, tmp);
        break;
    case 6:
        gen_helper_fdivr_STN_ST0(cpu_env, tmp);
        break;
    case 7:
        gen_helper_fdiv_STN_ST0(cpu_env, tmp);
        break;
    }
}

static void gen_op(DisasContext *s1, int op, TCGMemOp ot, int d)
{
    if (d != OR_TMP0) {
        gen_op_mov_v_reg(ot, cpu_T0, d);
    } else if (!(s1->prefix & PREFIX_LOCK)) {
        gen_op_ld_v(s1, ot, cpu_T0, cpu_A0);
    }
    switch(op) {
    case OP_ADCL:
        gen_compute_eflags_c(s1, cpu_tmp4);
        if (s1->prefix & PREFIX_LOCK) {
            tcg_gen_add_tl(cpu_T0, cpu_tmp4, cpu_T1);
            tcg_gen_atomic_add_fetch_tl(cpu_T0, cpu_A0, cpu_T0,
                                        s1->mem_index, (TCGMemOp)(ot | MO_LE));
        } else {
            tcg_gen_add_tl(cpu_T0, cpu_T0, cpu_T1);
            tcg_gen_add_tl(cpu_T0, cpu_T0, cpu_tmp4);
            gen_op_st_rm_T0_A0(s1, ot, d);
        }
        gen_op_update3_cc(cpu_tmp4);
        set_cc_op(s1, (CCOp)(CC_OP_ADCB + ot));
        break;
    case OP_SBBL:
        gen_compute_eflags_c(s1, cpu_tmp4);
        if (s1->prefix & PREFIX_LOCK) {
            tcg_gen_add_tl(cpu_T0, cpu_T1, cpu_tmp4);
            tcg_gen_neg_tl(cpu_T0, cpu_T0);
            tcg_gen_atomic_add_fetch_tl(cpu_T0, cpu_A0, cpu_T0,
                                        s1->mem_index, (TCGMemOp)(ot | MO_LE));
        } else {
            tcg_gen_sub_tl(cpu_T0, cpu_T0, cpu_T1);
            tcg_gen_sub_tl(cpu_T0, cpu_T0, cpu_tmp4);
            gen_op_st_rm_T0_A0(s1, ot, d);
        }
        gen_op_update3_cc(cpu_tmp4);
        set_cc_op(s1, (CCOp)(CC_OP_SBBB + ot));
        break;
    case OP_ADDL:
        if (s1->prefix & PREFIX_LOCK) {
            tcg_gen_atomic_add_fetch_tl(cpu_T0, cpu_A0, cpu_T1,
                                        s1->mem_index, (TCGMemOp)(ot | MO_LE));
        } else {
            tcg_gen_add_tl(cpu_T0, cpu_T0, cpu_T1);
            gen_op_st_rm_T0_A0(s1, ot, d);
        }
        gen_op_update2_cc();
        set_cc_op(s1, (CCOp)(CC_OP_ADDB + ot));
        break;
    case OP_SUBL:
        if (s1->prefix & PREFIX_LOCK) {
            tcg_gen_neg_tl(cpu_T0, cpu_T1);
            tcg_gen_atomic_fetch_add_tl(cpu_cc_srcT, cpu_A0, cpu_T0,
                                        s1->mem_index, (TCGMemOp)(ot | MO_LE));
            tcg_gen_sub_tl(cpu_T0, cpu_cc_srcT, cpu_T1);
        } else {
            tcg_gen_mov_tl(cpu_cc_srcT, cpu_T0);
            tcg_gen_sub_tl(cpu_T0, cpu_T0, cpu_T1);
            gen_op_st_rm_T0_A0(s1, ot, d);
        }
        gen_op_update2_cc();
        set_cc_op(s1, (CCOp)(CC_OP_SUBB + ot));
        break;
    default:
    case OP_ANDL:
        if (s1->prefix & PREFIX_LOCK) {
            tcg_gen_atomic_and_fetch_tl(cpu_T0, cpu_A0, cpu_T1,
                                        s1->mem_index, (TCGMemOp)(ot | MO_LE));
        } else {
            tcg_gen_and_tl(cpu_T0, cpu_T0, cpu_T1);
            gen_op_st_rm_T0_A0(s1, ot, d);
        }
        gen_op_update1_cc();
        set_cc_op(s1, (CCOp)(CC_OP_LOGICB + ot));
        break;
    case OP_ORL:
        if (s1->prefix & PREFIX_LOCK) {
            tcg_gen_atomic_or_fetch_tl(cpu_T0, cpu_A0, cpu_T1,
                                       s1->mem_index, (TCGMemOp)(ot | MO_LE));
        } else {
            tcg_gen_or_tl(cpu_T0, cpu_T0, cpu_T1);
            gen_op_st_rm_T0_A0(s1, ot, d);
        }
        gen_op_update1_cc();
        set_cc_op(s1, (CCOp)(CC_OP_LOGICB + ot));
        break;
    case OP_XORL:
        if (s1->prefix & PREFIX_LOCK) {
            tcg_gen_atomic_xor_fetch_tl(cpu_T0, cpu_A0, cpu_T1,
                                        s1->mem_index, (TCGMemOp)(ot | MO_LE));
        } else {
            tcg_gen_xor_tl(cpu_T0, cpu_T0, cpu_T1);
            gen_op_st_rm_T0_A0(s1, ot, d);
        }
        gen_op_update1_cc();
        set_cc_op(s1, (CCOp)(CC_OP_LOGICB + ot));
        break;
    case OP_CMPL:
        tcg_gen_mov_tl(cpu_cc_src, cpu_T1);
        tcg_gen_mov_tl(cpu_cc_srcT, cpu_T0);
        tcg_gen_sub_tl(cpu_cc_dst, cpu_T0, cpu_T1);
        set_cc_op(s1, (CCOp)(CC_OP_SUBB + ot));
        break;
    }
}

static void gen_inc(DisasContext *s1, TCGMemOp ot, int d, int c)
{
    if (s1->prefix & PREFIX_LOCK) {
        tcg_gen_movi_tl(cpu_T0, c > 0 ? 1 : -1);
        tcg_gen_atomic_add_fetch_tl(cpu_T0, cpu_A0, cpu_T0,
                                    s1->mem_index, (TCGMemOp)(ot | MO_LE));
    } else {
        if (d != OR_TMP0) {
            gen_op_mov_v_reg(ot, cpu_T0, d);
        } else {
            gen_op_ld_v(s1, ot, cpu_T0, cpu_A0);
        }
        tcg_gen_addi_tl(cpu_T0, cpu_T0, (c > 0 ? 1 : -1));
        gen_op_st_rm_T0_A0(s1, ot, d);
    }

    gen_compute_eflags_c(s1, cpu_cc_src);
    tcg_gen_mov_tl(cpu_cc_dst, cpu_T0);
    set_cc_op(s1, (CCOp)((c > 0 ? CC_OP_INCB : CC_OP_DECB) + ot));
}

static void gen_shift_flags(DisasContext *s, TCGMemOp ot, TCGv result,
                            TCGv shm1, TCGv count, bool is_right)
{
    TCGv_i32 z32, s32, oldop;
    TCGv z_tl;

    /* Store the results into the CC variables.  If we know that the
       variable must be dead, store unconditionally.  Otherwise we'll
       need to not disrupt the current contents.  */
    z_tl = tcg_const_tl(0);
    if (cc_op_live[s->cc_op] & USES_CC_DST) {
        tcg_gen_movcond_tl(TCG_COND_NE, cpu_cc_dst, count, z_tl,
                           result, cpu_cc_dst);
    } else {
        tcg_gen_mov_tl(cpu_cc_dst, result);
    }
    if (cc_op_live[s->cc_op] & USES_CC_SRC) {
        tcg_gen_movcond_tl(TCG_COND_NE, cpu_cc_src, count, z_tl,
                           shm1, cpu_cc_src);
    } else {
        tcg_gen_mov_tl(cpu_cc_src, shm1);
    }
    tcg_temp_free(z_tl);

    /* Get the two potential CC_OP values into temporaries.  */
    tcg_gen_movi_i32(cpu_tmp2_i32, (is_right ? CC_OP_SARB : CC_OP_SHLB) + ot);
    if (s->cc_op == CC_OP_DYNAMIC) {
        oldop = cpu_cc_op;
    } else {
        tcg_gen_movi_i32(cpu_tmp3_i32, s->cc_op);
        oldop = cpu_tmp3_i32;
    }

    /* Conditionally store the CC_OP value.  */
    z32 = tcg_const_i32(0);
    s32 = tcg_temp_new_i32();
    tcg_gen_trunc_tl_i32(s32, count);
    tcg_gen_movcond_i32(TCG_COND_NE, cpu_cc_op, s32, z32, cpu_tmp2_i32, oldop);
    tcg_temp_free_i32(z32);
    tcg_temp_free_i32(s32);

    /* The CC_OP value is no longer predictable.  */
    set_cc_op(s, CC_OP_DYNAMIC);
}

static void gen_shift_rm_T1(DisasContext *s, TCGMemOp ot, int op1,
                            int is_right, int is_arith)
{
    target_ulong mask = (ot == MO_64 ? 0x3f : 0x1f);

    /* load */
    if (op1 == OR_TMP0) {
        gen_op_ld_v(s, ot, cpu_T0, cpu_A0);
    } else {
        gen_op_mov_v_reg(ot, cpu_T0, op1);
    }

    tcg_gen_andi_tl(cpu_T1, cpu_T1, mask);
    tcg_gen_subi_tl(cpu_tmp0, cpu_T1, 1);

    if (is_right) {
        if (is_arith) {
            gen_exts(ot, cpu_T0);
            tcg_gen_sar_tl(cpu_tmp0, cpu_T0, cpu_tmp0);
            tcg_gen_sar_tl(cpu_T0, cpu_T0, cpu_T1);
        } else {
            gen_extu(ot, cpu_T0);
            tcg_gen_shr_tl(cpu_tmp0, cpu_T0, cpu_tmp0);
            tcg_gen_shr_tl(cpu_T0, cpu_T0, cpu_T1);
        }
    } else {
        tcg_gen_shl_tl(cpu_tmp0, cpu_T0, cpu_tmp0);
        tcg_gen_shl_tl(cpu_T0, cpu_T0, cpu_T1);
    }

    /* store */
    gen_op_st_rm_T0_A0(s, ot, op1);

    gen_shift_flags(s, ot, cpu_T0, cpu_tmp0, cpu_T1, is_right);
}

static void gen_shift_rm_im(DisasContext *s, TCGMemOp ot, int op1, int op2,
                            int is_right, int is_arith)
{
    int mask = (ot == MO_64 ? 0x3f : 0x1f);

    /* load */
    if (op1 == OR_TMP0)
        gen_op_ld_v(s, ot, cpu_T0, cpu_A0);
    else
        gen_op_mov_v_reg(ot, cpu_T0, op1);

    op2 &= mask;
    if (op2 != 0) {
        if (is_right) {
            if (is_arith) {
                gen_exts(ot, cpu_T0);
                tcg_gen_sari_tl(cpu_tmp4, cpu_T0, op2 - 1);
                tcg_gen_sari_tl(cpu_T0, cpu_T0, op2);
            } else {
                gen_extu(ot, cpu_T0);
                tcg_gen_shri_tl(cpu_tmp4, cpu_T0, op2 - 1);
                tcg_gen_shri_tl(cpu_T0, cpu_T0, op2);
            }
        } else {
            tcg_gen_shli_tl(cpu_tmp4, cpu_T0, op2 - 1);
            tcg_gen_shli_tl(cpu_T0, cpu_T0, op2);
        }
    }

    /* store */
    gen_op_st_rm_T0_A0(s, ot, op1);

    /* update eflags if non zero shift */
    if (op2 != 0) {
        tcg_gen_mov_tl(cpu_cc_src, cpu_tmp4);
        tcg_gen_mov_tl(cpu_cc_dst, cpu_T0);
        set_cc_op(s, (CCOp)((is_right ? CC_OP_SARB : CC_OP_SHLB) + ot));
    }
}

static void gen_rot_rm_T1(DisasContext *s, TCGMemOp ot, int op1, int is_right)
{
    target_ulong mask = (ot == MO_64 ? 0x3f : 0x1f);
    TCGv_i32 t0, t1;

    /* load */
    if (op1 == OR_TMP0) {
        gen_op_ld_v(s, ot, cpu_T0, cpu_A0);
    } else {
        gen_op_mov_v_reg(ot, cpu_T0, op1);
    }

    tcg_gen_andi_tl(cpu_T1, cpu_T1, mask);

    switch (ot) {
    case MO_8:
        /* Replicate the 8-bit input so that a 32-bit rotate works.  */
        tcg_gen_ext8u_tl(cpu_T0, cpu_T0);
        tcg_gen_muli_tl(cpu_T0, cpu_T0, 0x01010101);
        goto do_long;
    case MO_16:
        /* Replicate the 16-bit input so that a 32-bit rotate works.  */
        tcg_gen_deposit_tl(cpu_T0, cpu_T0, cpu_T0, 16, 16);
        goto do_long;
    do_long:
#ifdef TARGET_X86_64
    case MO_32:
        tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_T0);
        tcg_gen_trunc_tl_i32(cpu_tmp3_i32, cpu_T1);
        if (is_right) {
            tcg_gen_rotr_i32(cpu_tmp2_i32, cpu_tmp2_i32, cpu_tmp3_i32);
        } else {
            tcg_gen_rotl_i32(cpu_tmp2_i32, cpu_tmp2_i32, cpu_tmp3_i32);
        }
        tcg_gen_extu_i32_tl(cpu_T0, cpu_tmp2_i32);
        break;
#endif
    default:
        if (is_right) {
            tcg_gen_rotr_tl(cpu_T0, cpu_T0, cpu_T1);
        } else {
            tcg_gen_rotl_tl(cpu_T0, cpu_T0, cpu_T1);
        }
        break;
    }

    /* store */
    gen_op_st_rm_T0_A0(s, ot, op1);

    /* We'll need the flags computed into CC_SRC.  */
    gen_compute_eflags(s);

    /* The value that was "rotated out" is now present at the other end
       of the word.  Compute C into CC_DST and O into CC_SRC2.  Note that
       since we've computed the flags into CC_SRC, these variables are
       currently dead.  */
    if (is_right) {
        tcg_gen_shri_tl(cpu_cc_src2, cpu_T0, mask - 1);
        tcg_gen_shri_tl(cpu_cc_dst, cpu_T0, mask);
        tcg_gen_andi_tl(cpu_cc_dst, cpu_cc_dst, 1);
    } else {
        tcg_gen_shri_tl(cpu_cc_src2, cpu_T0, mask);
        tcg_gen_andi_tl(cpu_cc_dst, cpu_T0, 1);
    }
    tcg_gen_andi_tl(cpu_cc_src2, cpu_cc_src2, 1);
    tcg_gen_xor_tl(cpu_cc_src2, cpu_cc_src2, cpu_cc_dst);

    /* Now conditionally store the new CC_OP value.  If the shift count
       is 0 we keep the CC_OP_EFLAGS setting so that only CC_SRC is live.
       Otherwise reuse CC_OP_ADCOX which have the C and O flags split out
       exactly as we computed above.  */
    t0 = tcg_const_i32(0);
    t1 = tcg_temp_new_i32();
    tcg_gen_trunc_tl_i32(t1, cpu_T1);
    tcg_gen_movi_i32(cpu_tmp2_i32, CC_OP_ADCOX); 
    tcg_gen_movi_i32(cpu_tmp3_i32, CC_OP_EFLAGS);
    tcg_gen_movcond_i32(TCG_COND_NE, cpu_cc_op, t1, t0,
                        cpu_tmp2_i32, cpu_tmp3_i32);
    tcg_temp_free_i32(t0);
    tcg_temp_free_i32(t1);

    /* The CC_OP value is no longer predictable.  */ 
    set_cc_op(s, CC_OP_DYNAMIC);
}

static void gen_rot_rm_im(DisasContext *s, TCGMemOp ot, int op1, int op2,
                          int is_right)
{
    int mask = (ot == MO_64 ? 0x3f : 0x1f);
    int shift;

    /* load */
    if (op1 == OR_TMP0) {
        gen_op_ld_v(s, ot, cpu_T0, cpu_A0);
    } else {
        gen_op_mov_v_reg(ot, cpu_T0, op1);
    }

    op2 &= mask;
    if (op2 != 0) {
        switch (ot) {
#ifdef TARGET_X86_64
        case MO_32:
            tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_T0);
            if (is_right) {
                tcg_gen_rotri_i32(cpu_tmp2_i32, cpu_tmp2_i32, op2);
            } else {
                tcg_gen_rotli_i32(cpu_tmp2_i32, cpu_tmp2_i32, op2);
            }
            tcg_gen_extu_i32_tl(cpu_T0, cpu_tmp2_i32);
            break;
#endif
        default:
            if (is_right) {
                tcg_gen_rotri_tl(cpu_T0, cpu_T0, op2);
            } else {
                tcg_gen_rotli_tl(cpu_T0, cpu_T0, op2);
            }
            break;
        case MO_8:
            mask = 7;
            goto do_shifts;
        case MO_16:
            mask = 15;
        do_shifts:
            shift = op2 & mask;
            if (is_right) {
                shift = mask + 1 - shift;
            }
            gen_extu(ot, cpu_T0);
            tcg_gen_shli_tl(cpu_tmp0, cpu_T0, shift);
            tcg_gen_shri_tl(cpu_T0, cpu_T0, mask + 1 - shift);
            tcg_gen_or_tl(cpu_T0, cpu_T0, cpu_tmp0);
            break;
        }
    }

    /* store */
    gen_op_st_rm_T0_A0(s, ot, op1);

    if (op2 != 0) {
        /* Compute the flags into CC_SRC.  */
        gen_compute_eflags(s);

        /* The value that was "rotated out" is now present at the other end
           of the word.  Compute C into CC_DST and O into CC_SRC2.  Note that
           since we've computed the flags into CC_SRC, these variables are
           currently dead.  */
        if (is_right) {
            tcg_gen_shri_tl(cpu_cc_src2, cpu_T0, mask - 1);
            tcg_gen_shri_tl(cpu_cc_dst, cpu_T0, mask);
            tcg_gen_andi_tl(cpu_cc_dst, cpu_cc_dst, 1);
        } else {
            tcg_gen_shri_tl(cpu_cc_src2, cpu_T0, mask);
            tcg_gen_andi_tl(cpu_cc_dst, cpu_T0, 1);
        }
        tcg_gen_andi_tl(cpu_cc_src2, cpu_cc_src2, 1);
        tcg_gen_xor_tl(cpu_cc_src2, cpu_cc_src2, cpu_cc_dst);
        set_cc_op(s, CC_OP_ADCOX);
    }
}

static void gen_rotc_rm_T1(DisasContext *s, TCGMemOp ot, int op1,
                           int is_right)
{
    gen_compute_eflags(s);
    assert(s->cc_op == CC_OP_EFLAGS);

    /* load */
    if (op1 == OR_TMP0)
        gen_op_ld_v(s, ot, cpu_T0, cpu_A0);
    else
        gen_op_mov_v_reg(ot, cpu_T0, op1);
    
    if (is_right) {
        switch (ot) {
        case MO_8:
            gen_helper_rcrb(cpu_T0, cpu_env, cpu_T0, cpu_T1);
            break;
        case MO_16:
            gen_helper_rcrw(cpu_T0, cpu_env, cpu_T0, cpu_T1);
            break;
        case MO_32:
            gen_helper_rcrl(cpu_T0, cpu_env, cpu_T0, cpu_T1);
            break;
#ifdef TARGET_X86_64
        case MO_64:
            gen_helper_rcrq(cpu_T0, cpu_env, cpu_T0, cpu_T1);
            break;
#endif
        default:
            tcg_abort();
        }
    } else {
        switch (ot) {
        case MO_8:
            gen_helper_rclb(cpu_T0, cpu_env, cpu_T0, cpu_T1);
            break;
        case MO_16:
            gen_helper_rclw(cpu_T0, cpu_env, cpu_T0, cpu_T1);
            break;
        case MO_32:
            gen_helper_rcll(cpu_T0, cpu_env, cpu_T0, cpu_T1);
            break;
#ifdef TARGET_X86_64
        case MO_64:
            gen_helper_rclq(cpu_T0, cpu_env, cpu_T0, cpu_T1);
            break;
#endif
        default:
            tcg_abort();
        }
    }
    /* store */
    gen_op_st_rm_T0_A0(s, ot, op1);
}

static void gen_shiftd_rm_T1(DisasContext *s, TCGMemOp ot, int op1,
                             bool is_right, TCGv count_in)
{
    target_ulong mask = (ot == MO_64 ? 63 : 31);
    TCGv count;

    /* load */
    if (op1 == OR_TMP0) {
        gen_op_ld_v(s, ot, cpu_T0, cpu_A0);
    } else {
        gen_op_mov_v_reg(ot, cpu_T0, op1);
    }

    count = tcg_temp_new();
    tcg_gen_andi_tl(count, count_in, mask);

    switch (ot) {
    case MO_16:
        /* Note: we implement the Intel behaviour for shift count > 16.
           This means "shrdw C, B, A" shifts A:B:A >> C.  Build the B:A
           portion by constructing it as a 32-bit value.  */
        if (is_right) {
            tcg_gen_deposit_tl(cpu_tmp0, cpu_T0, cpu_T1, 16, 16);
            tcg_gen_mov_tl(cpu_T1, cpu_T0);
            tcg_gen_mov_tl(cpu_T0, cpu_tmp0);
        } else {
            tcg_gen_deposit_tl(cpu_T1, cpu_T0, cpu_T1, 16, 16);
        }
        /* FALLTHRU */
#ifdef TARGET_X86_64
    case MO_32:
        /* Concatenate the two 32-bit values and use a 64-bit shift.  */
        tcg_gen_subi_tl(cpu_tmp0, count, 1);
        if (is_right) {
            tcg_gen_concat_tl_i64(cpu_T0, cpu_T0, cpu_T1);
            tcg_gen_shr_i64(cpu_tmp0, cpu_T0, cpu_tmp0);
            tcg_gen_shr_i64(cpu_T0, cpu_T0, count);
        } else {
            tcg_gen_concat_tl_i64(cpu_T0, cpu_T1, cpu_T0);
            tcg_gen_shl_i64(cpu_tmp0, cpu_T0, cpu_tmp0);
            tcg_gen_shl_i64(cpu_T0, cpu_T0, count);
            tcg_gen_shri_i64(cpu_tmp0, cpu_tmp0, 32);
            tcg_gen_shri_i64(cpu_T0, cpu_T0, 32);
        }
        break;
#endif
    default:
        tcg_gen_subi_tl(cpu_tmp0, count, 1);
        if (is_right) {
            tcg_gen_shr_tl(cpu_tmp0, cpu_T0, cpu_tmp0);

            tcg_gen_subfi_tl(cpu_tmp4, mask + 1, count);
            tcg_gen_shr_tl(cpu_T0, cpu_T0, count);
            tcg_gen_shl_tl(cpu_T1, cpu_T1, cpu_tmp4);
        } else {
            tcg_gen_shl_tl(cpu_tmp0, cpu_T0, cpu_tmp0);
            if (ot == MO_16) {
                /* Only needed if count > 16, for Intel behaviour.  */
                tcg_gen_subfi_tl(cpu_tmp4, 33, count);
                tcg_gen_shr_tl(cpu_tmp4, cpu_T1, cpu_tmp4);
                tcg_gen_or_tl(cpu_tmp0, cpu_tmp0, cpu_tmp4);
            }

            tcg_gen_subfi_tl(cpu_tmp4, mask + 1, count);
            tcg_gen_shl_tl(cpu_T0, cpu_T0, count);
            tcg_gen_shr_tl(cpu_T1, cpu_T1, cpu_tmp4);
        }
        tcg_gen_movi_tl(cpu_tmp4, 0);
        tcg_gen_movcond_tl(TCG_COND_EQ, cpu_T1, count, cpu_tmp4,
                           cpu_tmp4, cpu_T1);
        tcg_gen_or_tl(cpu_T0, cpu_T0, cpu_T1);
        break;
    }

    /* store */
    gen_op_st_rm_T0_A0(s, ot, op1);

    gen_shift_flags(s, ot, cpu_T0, cpu_tmp0, count, is_right);
    tcg_temp_free(count);
}

static void gen_shift(DisasContext *s1, int op, TCGMemOp ot, int d, int s)
{
    if (s != OR_TMP1)
        gen_op_mov_v_reg(ot, cpu_T1, s);
    switch(op) {
    case OP_ROL:
        gen_rot_rm_T1(s1, ot, d, 0);
        break;
    case OP_ROR:
        gen_rot_rm_T1(s1, ot, d, 1);
        break;
    case OP_SHL:
    case OP_SHL1:
        gen_shift_rm_T1(s1, ot, d, 0, 0);
        break;
    case OP_SHR:
        gen_shift_rm_T1(s1, ot, d, 1, 0);
        break;
    case OP_SAR:
        gen_shift_rm_T1(s1, ot, d, 1, 1);
        break;
    case OP_RCL:
        gen_rotc_rm_T1(s1, ot, d, 0);
        break;
    case OP_RCR:
        gen_rotc_rm_T1(s1, ot, d, 1);
        break;
    }
}

#define X86_MAX_INSN_LENGTH 15

static void gen_shifti(DisasContext *s1, int op, TCGMemOp ot, int d, int c)
{
    switch(op) {
    case OP_ROL:
        gen_rot_rm_im(s1, ot, d, c, 0);
        break;
    case OP_ROR:
        gen_rot_rm_im(s1, ot, d, c, 1);
        break;
    case OP_SHL:
    case OP_SHL1:
        gen_shift_rm_im(s1, ot, d, c, 0, 0);
        break;
    case OP_SHR:
        gen_shift_rm_im(s1, ot, d, c, 1, 0);
        break;
    case OP_SAR:
        gen_shift_rm_im(s1, ot, d, c, 1, 1);
        break;
    default:
        /* currently not optimized */
        tcg_gen_movi_tl(cpu_T1, c);
        gen_shift(s1, op, ot, d, OR_TMP1);
        break;
    }
}

static uint64_t advance_pc(CPUX86State *env, DisasContext *s, int num_bytes)
{
    uint64_t pc = s->pc;

    s->pc += num_bytes;
    if (unlikely(s->pc - s->pc_start > X86_MAX_INSN_LENGTH)) {
        /* If the instruction's 16th byte is on a different page than the 1st, a
         * page fault on the second page wins over the general protection fault
         * caused by the instruction being too long.
         * This can happen even if the operand is only one byte long!
         */
        if (((s->pc - 1) ^ (pc - 1)) & TARGET_PAGE_MASK) {
            volatile uint8_t unused =
                cpu_ldub_code(env, (s->pc - 1) & TARGET_PAGE_MASK);
            (void) unused;
        }
        siglongjmp(s->jmpbuf, 1);
    }

    return pc;
}

static inline uint8_t x86_ldub_code(CPUX86State *env, DisasContext *s)
{
    return cpu_ldub_code(env, advance_pc(env, s, 1));
}

static inline int16_t x86_ldsw_code(CPUX86State *env, DisasContext *s)
{
    return cpu_ldsw_code(env, advance_pc(env, s, 2));
}

static inline uint16_t x86_lduw_code(CPUX86State *env, DisasContext *s)
{
    return cpu_lduw_code(env, advance_pc(env, s, 2));
}

static inline uint32_t x86_ldl_code(CPUX86State *env, DisasContext *s)
{
    return cpu_ldl_code(env, advance_pc(env, s, 4));
}

static inline uint64_t x86_ldq_code(CPUX86State *env, DisasContext *s)
{
    return cpu_ldq_code(env, advance_pc(env, s, 8));
}

typedef struct AddressParts {
    int def_seg;
    int base;
    int index;
    int scale;
    target_long disp;
} AddressParts;

static AddressParts gen_lea_modrm_0(CPUX86State *env, DisasContext *s,
                                    int modrm)
{
    int def_seg, base, index, scale, mod, rm;
    target_long disp;
    bool havesib;

    def_seg = R_DS;
    index = -1;
    scale = 0;
    disp = 0;

    mod = (modrm >> 6) & 3;
    rm = modrm & 7;
    base = rm | REX_B(s);

    if (mod == 3) {
        /* Normally filtered out earlier, but including this path
           simplifies multi-byte nop, as well as bndcl, bndcu, bndcn.  */
        goto done;
    }

    switch (s->aflag) {
    case MO_64:
    case MO_32:
        havesib = 0;
        if (rm == 4) {
            int code = x86_ldub_code(env, s);
            scale = (code >> 6) & 3;
            index = ((code >> 3) & 7) | REX_X(s);
            if (index == 4) {
                index = -1;  /* no index */
            }
            base = (code & 7) | REX_B(s);
            havesib = 1;
        }

        switch (mod) {
        case 0:
            if ((base & 7) == 5) {
                base = -1;
                disp = (int32_t)x86_ldl_code(env, s);
                if (CODE64(s) && !havesib) {
                    base = -2;
                    disp += s->pc + s->rip_offset;
                }
            }
            break;
        case 1:
            disp = (int8_t)x86_ldub_code(env, s);
            break;
        default:
        case 2:
            disp = (int32_t)x86_ldl_code(env, s);
            break;
        }

        /* For correct popl handling with esp.  */
        if (base == R_ESP && s->popl_esp_hack) {
            disp += s->popl_esp_hack;
        }
        if (base == R_EBP || base == R_ESP) {
            def_seg = R_SS;
        }
        break;

    case MO_16:
        if (mod == 0) {
            if (rm == 6) {
                base = -1;
                disp = x86_lduw_code(env, s);
                break;
            }
        } else if (mod == 1) {
            disp = (int8_t)x86_ldub_code(env, s);
        } else {
            disp = (int16_t)x86_lduw_code(env, s);
        }

        switch (rm) {
        case 0:
            base = R_EBX;
            index = R_ESI;
            break;
        case 1:
            base = R_EBX;
            index = R_EDI;
            break;
        case 2:
            base = R_EBP;
            index = R_ESI;
            def_seg = R_SS;
            break;
        case 3:
            base = R_EBP;
            index = R_EDI;
            def_seg = R_SS;
            break;
        case 4:
            base = R_ESI;
            break;
        case 5:
            base = R_EDI;
            break;
        case 6:
            base = R_EBP;
            def_seg = R_SS;
            break;
        default:
        case 7:
            base = R_EBX;
            break;
        }
        break;

    default:
        tcg_abort();
    }

 done:
    return (AddressParts){ def_seg, base, index, scale, disp };
}

static TCGv gen_lea_modrm_1(AddressParts a)
{
    TCGv ea;

    TCGV_UNUSED(ea);
    if (a.index >= 0) {
        if (a.scale == 0) {
            ea = cpu_regs[a.index];
        } else {
            tcg_gen_shli_tl(cpu_A0, cpu_regs[a.index], a.scale);
            ea = cpu_A0;
        }
        if (a.base >= 0) {
            tcg_gen_add_tl(cpu_A0, ea, cpu_regs[a.base]);
            ea = cpu_A0;
        }
    } else if (a.base >= 0) {
        ea = cpu_regs[a.base];
    }
    if (TCGV_IS_UNUSED(ea)) {
        tcg_gen_movi_tl(cpu_A0, a.disp);
        ea = cpu_A0;
    } else if (a.disp != 0) {
        tcg_gen_addi_tl(cpu_A0, ea, a.disp);
        ea = cpu_A0;
    }

    return ea;
}

static void gen_lea_modrm(CPUX86State *env, DisasContext *s, int modrm)
{
    AddressParts a = gen_lea_modrm_0(env, s, modrm);
    TCGv ea = gen_lea_modrm_1(a);
    gen_lea_v_seg(s, s->aflag, ea, a.def_seg, s->override);
}

static void gen_nop_modrm(CPUX86State *env, DisasContext *s, int modrm)
{
    (void)gen_lea_modrm_0(env, s, modrm);
}

static void gen_bndck(CPUX86State *env, DisasContext *s, int modrm,
                      TCGCond cond, TCGv_i64 bndv)
{
    TCGv ea = gen_lea_modrm_1(gen_lea_modrm_0(env, s, modrm));

    tcg_gen_extu_tl_i64(cpu_tmp1_i64, ea);
    if (!CODE64(s)) {
        tcg_gen_ext32u_i64(cpu_tmp1_i64, cpu_tmp1_i64);
    }
    tcg_gen_setcond_i64(cond, cpu_tmp1_i64, cpu_tmp1_i64, bndv);
    tcg_gen_extrl_i64_i32(cpu_tmp2_i32, cpu_tmp1_i64);
    gen_helper_bndck(cpu_env, cpu_tmp2_i32);
}

static void gen_add_A0_ds_seg(DisasContext *s)
{
    gen_lea_v_seg(s, s->aflag, cpu_A0, R_DS, s->override);
}

static void gen_ldst_modrm(CPUX86State *env, DisasContext *s, int modrm,
                           TCGMemOp ot, int reg, int is_store)
{
    int mod, rm;

    mod = (modrm >> 6) & 3;
    rm = (modrm & 7) | REX_B(s);
    if (mod == 3) {
        if (is_store) {
            if (reg != OR_TMP0)
                gen_op_mov_v_reg(ot, cpu_T0, reg);
            gen_op_mov_reg_v(ot, rm, cpu_T0);
        } else {
            gen_op_mov_v_reg(ot, cpu_T0, rm);
            if (reg != OR_TMP0)
                gen_op_mov_reg_v(ot, reg, cpu_T0);
        }
    } else {
        gen_lea_modrm(env, s, modrm);
        if (is_store) {
            if (reg != OR_TMP0)
                gen_op_mov_v_reg(ot, cpu_T0, reg);
            gen_op_st_v(s, ot, cpu_T0, cpu_A0);
        } else {
            gen_op_ld_v(s, ot, cpu_T0, cpu_A0);
            if (reg != OR_TMP0)
                gen_op_mov_reg_v(ot, reg, cpu_T0);
        }
    }
}

static inline uint32_t insn_get(CPUX86State *env, DisasContext *s, TCGMemOp ot)
{
    uint32_t ret;

    switch (ot) {
    case MO_8:
        ret = x86_ldub_code(env, s);
        break;
    case MO_16:
        ret = x86_lduw_code(env, s);
        break;
    case MO_32:
#ifdef TARGET_X86_64
    case MO_64:
#endif
        ret = x86_ldl_code(env, s);
        break;
    default:
        tcg_abort();
    }
    return ret;
}

static inline int insn_const_size(TCGMemOp ot)
{
    if (ot <= MO_32) {
        return 1 << ot;
    } else {
        return 4;
    }
}

static inline bool use_goto_tb(DisasContext *s, target_ulong pc)
{
#ifndef CONFIG_USER_ONLY
    return (pc & TARGET_PAGE_MASK) == (s->base.tb->pc & TARGET_PAGE_MASK) ||
           (pc & TARGET_PAGE_MASK) == (s->pc_start & TARGET_PAGE_MASK);
#else
    return true;
#endif
}

static inline void gen_goto_tb(DisasContext *s, int tb_num, target_ulong eip)
{
    target_ulong pc = s->cs_base + eip;

    if (use_goto_tb(s, pc))  {
        /* jump to same page: we can use a direct jump */
        tcg_gen_goto_tb(tb_num);
        gen_jmp_im(eip);
        tcg_gen_exit_tb((uintptr_t)s->base.tb + tb_num);
        s->base.is_jmp = DISAS_NORETURN;
    } else {
        /* jump to another page */
        gen_jmp_im(eip);
        gen_jr(s, cpu_tmp0);
    }
}

static inline void gen_jcc(DisasContext *s, int b,
                           target_ulong val, target_ulong next_eip)
{
    TCGLabel *l1, *l2;

    if (s->jmp_opt) {
        l1 = gen_new_label();
        gen_jcc1(s, b, l1);

        gen_goto_tb(s, 0, next_eip);

        gen_set_label(l1);
        gen_goto_tb(s, 1, val);
    } else {
        l1 = gen_new_label();
        l2 = gen_new_label();
        gen_jcc1(s, b, l1);

        gen_jmp_im(next_eip);
        tcg_gen_br(l2);

        gen_set_label(l1);
        gen_jmp_im(val);
        gen_set_label(l2);
        gen_eob(s);
    }
}

static void gen_cmovcc1(CPUX86State *env, DisasContext *s, TCGMemOp ot, int b,
                        int modrm, int reg)
{
    CCPrepare cc;

    gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);

    cc = gen_prepare_cc(s, b, cpu_T1);
    if (cc.mask != -1) {
        TCGv t0 = tcg_temp_new();
        tcg_gen_andi_tl(t0, cc.reg, cc.mask);
        cc.reg = t0;
    }
    if (!cc.use_reg2) {
        cc.reg2 = tcg_const_tl(cc.imm);
    }

    tcg_gen_movcond_tl(cc.cond, cpu_T0, cc.reg, cc.reg2,
                       cpu_T0, cpu_regs[reg]);
    gen_op_mov_reg_v(ot, reg, cpu_T0);

    if (cc.mask != -1) {
        tcg_temp_free(cc.reg);
    }
    if (!cc.use_reg2) {
        tcg_temp_free(cc.reg2);
    }
}

static inline void gen_op_movl_T0_seg(int seg_reg)
{
    tcg_gen_ld32u_tl(cpu_T0, cpu_env,
                     offsetof(CPUX86State,segs[seg_reg].selector));
}

static inline void gen_op_movl_seg_T0_vm(int seg_reg)
{
    tcg_gen_ext16u_tl(cpu_T0, cpu_T0);
    tcg_gen_st32_tl(cpu_T0, cpu_env,
                    offsetof(CPUX86State,segs[seg_reg].selector));
    tcg_gen_shli_tl(cpu_seg_base[seg_reg], cpu_T0, 4);
}

static void gen_movl_seg_T0(DisasContext *s, int seg_reg)
{
    if (s->pe && !s->vm86) {
        tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_T0);
        gen_helper_load_seg(cpu_env, tcg_const_i32(seg_reg), cpu_tmp2_i32);
        /* abort translation because the addseg value may change or
           because ss32 may change. For R_SS, translation must always
           stop as a special handling must be done to disable hardware
           interrupts for the next instruction */
        if (seg_reg == R_SS || (s->code32 && seg_reg < R_FS)) {
            s->base.is_jmp = DISAS_TOO_MANY;
        }
    } else {
        gen_op_movl_seg_T0_vm(seg_reg);
        if (seg_reg == R_SS) {
            s->base.is_jmp = DISAS_TOO_MANY;
        }
    }
}

static inline int svm_is_rep(int prefixes)
{
    return ((prefixes & (PREFIX_REPZ | PREFIX_REPNZ)) ? 8 : 0);
}

static inline void
gen_svm_check_intercept_param(DisasContext *s, target_ulong pc_start,
                              uint32_t type, uint64_t param)
{
    /* no SVM activated; fast case */
    if (likely(!(s->flags & HF_SVMI_MASK)))
        return;
    gen_update_cc_op(s);
    gen_jmp_im(pc_start - s->cs_base);
    gen_helper_svm_check_intercept_param(cpu_env, tcg_const_i32(type),
                                         tcg_const_i64(param));
}

static inline void
gen_svm_check_intercept(DisasContext *s, target_ulong pc_start, uint64_t type)
{
    gen_svm_check_intercept_param(s, pc_start, type, 0);
}

static inline void gen_stack_update(DisasContext *s, int addend)
{
    gen_op_add_reg_im(mo_stacksize(s), R_ESP, addend);
}

static void gen_push_v(DisasContext *s, TCGv val)
{
    TCGMemOp d_ot = mo_pushpop(s, s->dflag);
    TCGMemOp a_ot = mo_stacksize(s);
    int size = 1 << d_ot;
    TCGv new_esp = cpu_A0;

    tcg_gen_subi_tl(cpu_A0, cpu_regs[R_ESP], size);

    if (!CODE64(s)) {
        if (s->addseg) {
            new_esp = cpu_tmp4;
            tcg_gen_mov_tl(new_esp, cpu_A0);
        }
        gen_lea_v_seg(s, a_ot, cpu_A0, R_SS, -1);
    }

    gen_op_st_v(s, d_ot, val, cpu_A0);
    gen_op_mov_reg_v(a_ot, R_ESP, new_esp);
}

static TCGMemOp gen_pop_T0(DisasContext *s)
{
    TCGMemOp d_ot = mo_pushpop(s, s->dflag);

    gen_lea_v_seg(s, mo_stacksize(s), cpu_regs[R_ESP], R_SS, -1);
    gen_op_ld_v(s, d_ot, cpu_T0, cpu_A0);

    return d_ot;
}

static inline void gen_pop_update(DisasContext *s, TCGMemOp ot)
{
    gen_stack_update(s, 1 << ot);
}

static inline void gen_stack_A0(DisasContext *s)
{
    gen_lea_v_seg(s, s->ss32 ? MO_32 : MO_16, cpu_regs[R_ESP], R_SS, -1);
}

static void gen_pusha(DisasContext *s)
{
    TCGMemOp s_ot = s->ss32 ? MO_32 : MO_16;
    TCGMemOp d_ot = s->dflag;
    int size = 1 << d_ot;
    int i;

    for (i = 0; i < 8; i++) {
        tcg_gen_addi_tl(cpu_A0, cpu_regs[R_ESP], (i - 8) * size);
        gen_lea_v_seg(s, s_ot, cpu_A0, R_SS, -1);
        gen_op_st_v(s, d_ot, cpu_regs[7 - i], cpu_A0);
    }

    gen_stack_update(s, -8 * size);
}

static void gen_popa(DisasContext *s)
{
    TCGMemOp s_ot = s->ss32 ? MO_32 : MO_16;
    TCGMemOp d_ot = s->dflag;
    int size = 1 << d_ot;
    int i;

    for (i = 0; i < 8; i++) {
        /* ESP is not reloaded */
        if (7 - i == R_ESP) {
            continue;
        }
        tcg_gen_addi_tl(cpu_A0, cpu_regs[R_ESP], i * size);
        gen_lea_v_seg(s, s_ot, cpu_A0, R_SS, -1);
        gen_op_ld_v(s, d_ot, cpu_T0, cpu_A0);
        gen_op_mov_reg_v(d_ot, 7 - i, cpu_T0);
    }

    gen_stack_update(s, 8 * size);
}

static void gen_enter(DisasContext *s, int esp_addend, int level)
{
    TCGMemOp d_ot = mo_pushpop(s, s->dflag);
    TCGMemOp a_ot = CODE64(s) ? MO_64 : s->ss32 ? MO_32 : MO_16;
    int size = 1 << d_ot;

    /* Push BP; compute FrameTemp into T1.  */
    tcg_gen_subi_tl(cpu_T1, cpu_regs[R_ESP], size);
    gen_lea_v_seg(s, a_ot, cpu_T1, R_SS, -1);
    gen_op_st_v(s, d_ot, cpu_regs[R_EBP], cpu_A0);

    level &= 31;
    if (level != 0) {
        int i;

        /* Copy level-1 pointers from the previous frame.  */
        for (i = 1; i < level; ++i) {
            tcg_gen_subi_tl(cpu_A0, cpu_regs[R_EBP], size * i);
            gen_lea_v_seg(s, a_ot, cpu_A0, R_SS, -1);
            gen_op_ld_v(s, d_ot, cpu_tmp0, cpu_A0);

            tcg_gen_subi_tl(cpu_A0, cpu_T1, size * i);
            gen_lea_v_seg(s, a_ot, cpu_A0, R_SS, -1);
            gen_op_st_v(s, d_ot, cpu_tmp0, cpu_A0);
        }

        /* Push the current FrameTemp as the last level.  */
        tcg_gen_subi_tl(cpu_A0, cpu_T1, size * level);
        gen_lea_v_seg(s, a_ot, cpu_A0, R_SS, -1);
        gen_op_st_v(s, d_ot, cpu_T1, cpu_A0);
    }

    /* Copy the FrameTemp value to EBP.  */
    gen_op_mov_reg_v(a_ot, R_EBP, cpu_T1);

    /* Compute the final value of ESP.  */
    tcg_gen_subi_tl(cpu_T1, cpu_T1, esp_addend + size * level);
    gen_op_mov_reg_v(a_ot, R_ESP, cpu_T1);
}

static void gen_leave(DisasContext *s)
{
    TCGMemOp d_ot = mo_pushpop(s, s->dflag);
    TCGMemOp a_ot = mo_stacksize(s);

    gen_lea_v_seg(s, a_ot, cpu_regs[R_EBP], R_SS, -1);
    gen_op_ld_v(s, d_ot, cpu_T0, cpu_A0);

    tcg_gen_addi_tl(cpu_T1, cpu_regs[R_EBP], 1 << d_ot);

    gen_op_mov_reg_v(d_ot, R_EBP, cpu_T0);
    gen_op_mov_reg_v(a_ot, R_ESP, cpu_T1);
}

static void gen_exception(DisasContext *s, int trapno, target_ulong cur_eip)
{
    gen_update_cc_op(s);
    gen_jmp_im(cur_eip);
    gen_helper_raise_exception(cpu_env, tcg_const_i32(trapno));
    s->base.is_jmp = DISAS_NORETURN;
}

static void gen_illegal_opcode(DisasContext *s)
{
    gen_exception(s, EXCP06_ILLOP, s->pc_start - s->cs_base);
}

static void gen_unknown_opcode(CPUX86State *env, DisasContext *s)
{
    gen_illegal_opcode(s);

    if (qemu_loglevel_mask(LOG_UNIMP)) {
        target_ulong pc = s->pc_start, end = s->pc;
        qemu_log_lock();
        qemu_log("ILLOPC: " TARGET_FMT_lx ":", pc);
        for (; pc < end; ++pc) {
            qemu_log(" %02x", cpu_ldub_code(env, pc));
        }
        qemu_log("\n");
        qemu_log_unlock();
    }
}

static void gen_interrupt(DisasContext *s, int intno,
                          target_ulong cur_eip, target_ulong next_eip)
{
    gen_update_cc_op(s);
    gen_jmp_im(cur_eip);
    gen_helper_raise_interrupt(cpu_env, tcg_const_i32(intno),
                               tcg_const_i32(next_eip - cur_eip));
    s->base.is_jmp = DISAS_NORETURN;
}

static void gen_debug(DisasContext *s, target_ulong cur_eip)
{
    gen_update_cc_op(s);
    gen_jmp_im(cur_eip);
    gen_helper_debug(cpu_env);
    s->base.is_jmp = DISAS_NORETURN;
}

static void gen_set_hflag(DisasContext *s, uint32_t mask)
{
    if ((s->flags & mask) == 0) {
        TCGv_i32 t = tcg_temp_new_i32();
        tcg_gen_ld_i32(t, cpu_env, offsetof(CPUX86State, hflags));
        tcg_gen_ori_i32(t, t, mask);
        tcg_gen_st_i32(t, cpu_env, offsetof(CPUX86State, hflags));
        tcg_temp_free_i32(t);
        s->flags |= mask;
    }
}

static void gen_reset_hflag(DisasContext *s, uint32_t mask)
{
    if (s->flags & mask) {
        TCGv_i32 t = tcg_temp_new_i32();
        tcg_gen_ld_i32(t, cpu_env, offsetof(CPUX86State, hflags));
        tcg_gen_andi_i32(t, t, ~mask);
        tcg_gen_st_i32(t, cpu_env, offsetof(CPUX86State, hflags));
        tcg_temp_free_i32(t);
        s->flags &= ~mask;
    }
}

static void gen_bnd_jmp(DisasContext *s)
{
    /* Clear the registers only if BND prefix is missing, MPX is enabled,
       and if the BNDREGs are known to be in use (non-zero) already.
       The helper itself will check BNDPRESERVE at runtime.  */
    if ((s->prefix & PREFIX_REPNZ) == 0
        && (s->flags & HF_MPX_EN_MASK) != 0
        && (s->flags & HF_MPX_IU_MASK) != 0) {
        gen_helper_bnd_jmp(cpu_env);
    }
}

static void
do_gen_eob_worker(DisasContext *s, bool inhibit, bool recheck_tf, bool jr)
{
    gen_update_cc_op(s);

    /* If several instructions disable interrupts, only the first does it.  */
    if (inhibit && !(s->flags & HF_INHIBIT_IRQ_MASK)) {
        gen_set_hflag(s, HF_INHIBIT_IRQ_MASK);
    } else {
        gen_reset_hflag(s, HF_INHIBIT_IRQ_MASK);
    }

    if (s->base.tb->flags & HF_RF_MASK) {
        gen_helper_reset_rf(cpu_env);
    }
    if (s->base.singlestep_enabled) {
        gen_helper_debug(cpu_env);
    } else if (recheck_tf) {
        gen_helper_rechecking_single_step(cpu_env);
        tcg_gen_exit_tb(0);
    } else if (s->tf) {
        gen_helper_single_step(cpu_env);
    } else if (jr) {
        tcg_gen_lookup_and_goto_ptr();
    } else {
        tcg_gen_exit_tb(0);
    }
    s->base.is_jmp = DISAS_NORETURN;
}

static inline void
gen_eob_worker(DisasContext *s, bool inhibit, bool recheck_tf)
{
    do_gen_eob_worker(s, inhibit, recheck_tf, false);
}

static void gen_eob_inhibit_irq(DisasContext *s, bool inhibit)
{
    gen_eob_worker(s, inhibit, false);
}

static void gen_eob(DisasContext *s)
{
    gen_eob_worker(s, false, false);
}

static void gen_jr(DisasContext *s, TCGv dest)
{
    do_gen_eob_worker(s, false, false, true);
}

static void gen_jmp_tb(DisasContext *s, target_ulong eip, int tb_num)
{
    gen_update_cc_op(s);
    set_cc_op(s, CC_OP_DYNAMIC);
    if (s->jmp_opt) {
        gen_goto_tb(s, tb_num, eip);
    } else {
        gen_jmp_im(eip);
        gen_eob(s);
    }
}

static void gen_jmp(DisasContext *s, target_ulong eip)
{
    gen_jmp_tb(s, eip, 0);
}

static inline void gen_ldq_env_A0(DisasContext *s, int offset)
{
    tcg_gen_qemu_ld_i64(cpu_tmp1_i64, cpu_A0, s->mem_index, MO_LEQ);
    tcg_gen_st_i64(cpu_tmp1_i64, cpu_env, offset);
}

static inline void gen_stq_env_A0(DisasContext *s, int offset)
{
    tcg_gen_ld_i64(cpu_tmp1_i64, cpu_env, offset);
    tcg_gen_qemu_st_i64(cpu_tmp1_i64, cpu_A0, s->mem_index, MO_LEQ);
}

static inline void gen_ldo_env_A0(DisasContext *s, int offset)
{
    int mem_index = s->mem_index;
    tcg_gen_qemu_ld_i64(cpu_tmp1_i64, cpu_A0, mem_index, MO_LEQ);
    tcg_gen_st_i64(cpu_tmp1_i64, cpu_env, offset + offsetof(ZMMReg, ZMM_Q(0)));
    tcg_gen_addi_tl(cpu_tmp0, cpu_A0, 8);
    tcg_gen_qemu_ld_i64(cpu_tmp1_i64, cpu_tmp0, mem_index, MO_LEQ);
    tcg_gen_st_i64(cpu_tmp1_i64, cpu_env, offset + offsetof(ZMMReg, ZMM_Q(1)));
}

static inline void gen_sto_env_A0(DisasContext *s, int offset)
{
    int mem_index = s->mem_index;
    tcg_gen_ld_i64(cpu_tmp1_i64, cpu_env, offset + offsetof(ZMMReg, ZMM_Q(0)));
    tcg_gen_qemu_st_i64(cpu_tmp1_i64, cpu_A0, mem_index, MO_LEQ);
    tcg_gen_addi_tl(cpu_tmp0, cpu_A0, 8);
    tcg_gen_ld_i64(cpu_tmp1_i64, cpu_env, offset + offsetof(ZMMReg, ZMM_Q(1)));
    tcg_gen_qemu_st_i64(cpu_tmp1_i64, cpu_tmp0, mem_index, MO_LEQ);
}

static inline void gen_op_movo(int d_offset, int s_offset)
{
    tcg_gen_ld_i64(cpu_tmp1_i64, cpu_env, s_offset + offsetof(ZMMReg, ZMM_Q(0)));
    tcg_gen_st_i64(cpu_tmp1_i64, cpu_env, d_offset + offsetof(ZMMReg, ZMM_Q(0)));
    tcg_gen_ld_i64(cpu_tmp1_i64, cpu_env, s_offset + offsetof(ZMMReg, ZMM_Q(1)));
    tcg_gen_st_i64(cpu_tmp1_i64, cpu_env, d_offset + offsetof(ZMMReg, ZMM_Q(1)));
}

static inline void gen_op_movq(int d_offset, int s_offset)
{
    tcg_gen_ld_i64(cpu_tmp1_i64, cpu_env, s_offset);
    tcg_gen_st_i64(cpu_tmp1_i64, cpu_env, d_offset);
}

static inline void gen_op_movl(int d_offset, int s_offset)
{
    tcg_gen_ld_i32(cpu_tmp2_i32, cpu_env, s_offset);
    tcg_gen_st_i32(cpu_tmp2_i32, cpu_env, d_offset);
}

static inline void gen_op_movq_env_0(int d_offset)
{
    tcg_gen_movi_i64(cpu_tmp1_i64, 0);
    tcg_gen_st_i64(cpu_tmp1_i64, cpu_env, d_offset);
}

typedef void (*SSEFunc_i_ep)(TCGv_i32 val, TCGv_ptr env, TCGv_ptr reg);

typedef void (*SSEFunc_l_ep)(TCGv_i64 val, TCGv_ptr env, TCGv_ptr reg);

typedef void (*SSEFunc_0_epi)(TCGv_ptr env, TCGv_ptr reg, TCGv_i32 val);

typedef void (*SSEFunc_0_epl)(TCGv_ptr env, TCGv_ptr reg, TCGv_i64 val);

typedef void (*SSEFunc_0_epp)(TCGv_ptr env, TCGv_ptr reg_a, TCGv_ptr reg_b);

typedef void (*SSEFunc_0_eppi)(TCGv_ptr env, TCGv_ptr reg_a, TCGv_ptr reg_b,
                               TCGv_i32 val);

typedef void (*SSEFunc_0_ppi)(TCGv_ptr reg_a, TCGv_ptr reg_b, TCGv_i32 val);

#define SSE_SPECIAL ((void *)1)

#define SSE_DUMMY ((void *)2)

#define MMX_OP2(x) { gen_helper_ ## x ## _mmx, gen_helper_ ## x ## _xmm }

#define SSE_FOP(x) { gen_helper_ ## x ## ps, gen_helper_ ## x ## pd, \
                     gen_helper_ ## x ## ss, gen_helper_ ## x ## sd, }

typedef void (*SSEFunc_0_eppt)(TCGv_ptr env, TCGv_ptr reg_a, TCGv_ptr reg_b,
                               TCGv val);

static const SSEFunc_0_epp sse_op_table1[256][4] = {
    /* 3DNow! extensions */
    [0x0e] = { (SSEFunc_0_epp)SSE_DUMMY }, /* femms */
    [0x0f] = { (SSEFunc_0_epp)SSE_DUMMY }, /* pf... */
    /* pure SSE operations */
    [0x10] = { (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL }, /* movups, movupd, movss, movsd */
    [0x11] = { (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL }, /* movups, movupd, movss, movsd */
    [0x12] = { (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL }, /* movlps, movlpd, movsldup, movddup */
    [0x13] = { (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL },  /* movlps, movlpd */
    [0x14] = { gen_helper_punpckldq_xmm, gen_helper_punpcklqdq_xmm },
    [0x15] = { gen_helper_punpckhdq_xmm, gen_helper_punpckhqdq_xmm },
    [0x16] = { (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL },  /* movhps, movhpd, movshdup */
    [0x17] = { (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL },  /* movhps, movhpd */

    [0x28] = { (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL },  /* movaps, movapd */
    [0x29] = { (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL },  /* movaps, movapd */
    [0x2a] = { (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL }, /* cvtpi2ps, cvtpi2pd, cvtsi2ss, cvtsi2sd */
    [0x2b] = { (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL }, /* movntps, movntpd, movntss, movntsd */
    [0x2c] = { (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL }, /* cvttps2pi, cvttpd2pi, cvttsd2si, cvttss2si */
    [0x2d] = { (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL }, /* cvtps2pi, cvtpd2pi, cvtsd2si, cvtss2si */
    [0x2e] = { gen_helper_ucomiss, gen_helper_ucomisd },
    [0x2f] = { gen_helper_comiss, gen_helper_comisd },
    [0x50] = { (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL }, /* movmskps, movmskpd */
    [0x51] = SSE_FOP(sqrt),
    [0x52] = { gen_helper_rsqrtps, NULL, gen_helper_rsqrtss, NULL },
    [0x53] = { gen_helper_rcpps, NULL, gen_helper_rcpss, NULL },
    [0x54] = { gen_helper_pand_xmm, gen_helper_pand_xmm }, /* andps, andpd */
    [0x55] = { gen_helper_pandn_xmm, gen_helper_pandn_xmm }, /* andnps, andnpd */
    [0x56] = { gen_helper_por_xmm, gen_helper_por_xmm }, /* orps, orpd */
    [0x57] = { gen_helper_pxor_xmm, gen_helper_pxor_xmm }, /* xorps, xorpd */
    [0x58] = SSE_FOP(add),
    [0x59] = SSE_FOP(mul),
    [0x5a] = { gen_helper_cvtps2pd, gen_helper_cvtpd2ps,
               gen_helper_cvtss2sd, gen_helper_cvtsd2ss },
    [0x5b] = { gen_helper_cvtdq2ps, gen_helper_cvtps2dq, gen_helper_cvttps2dq },
    [0x5c] = SSE_FOP(sub),
    [0x5d] = SSE_FOP(min),
    [0x5e] = SSE_FOP(div),
    [0x5f] = SSE_FOP(max),

    [0xc2] = SSE_FOP(cmpeq),
    [0xc6] = { (SSEFunc_0_epp)gen_helper_shufps,
               (SSEFunc_0_epp)gen_helper_shufpd }, /* XXX: casts */

    /* SSSE3, SSE4, MOVBE, CRC32, BMI1, BMI2, ADX.  */
    [0x38] = { (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL },
    [0x3a] = { (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL },

    /* MMX ops and their SSE extensions */
    [0x60] = MMX_OP2(punpcklbw),
    [0x61] = MMX_OP2(punpcklwd),
    [0x62] = MMX_OP2(punpckldq),
    [0x63] = MMX_OP2(packsswb),
    [0x64] = MMX_OP2(pcmpgtb),
    [0x65] = MMX_OP2(pcmpgtw),
    [0x66] = MMX_OP2(pcmpgtl),
    [0x67] = MMX_OP2(packuswb),
    [0x68] = MMX_OP2(punpckhbw),
    [0x69] = MMX_OP2(punpckhwd),
    [0x6a] = MMX_OP2(punpckhdq),
    [0x6b] = MMX_OP2(packssdw),
    [0x6c] = { NULL, gen_helper_punpcklqdq_xmm },
    [0x6d] = { NULL, gen_helper_punpckhqdq_xmm },
    [0x6e] = { (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL }, /* movd mm, ea */
    [0x6f] = { (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL }, /* movq, movdqa, , movqdu */
    [0x70] = { (SSEFunc_0_epp)gen_helper_pshufw_mmx,
               (SSEFunc_0_epp)gen_helper_pshufd_xmm,
               (SSEFunc_0_epp)gen_helper_pshufhw_xmm,
               (SSEFunc_0_epp)gen_helper_pshuflw_xmm }, /* XXX: casts */
    [0x71] = { (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL }, /* shiftw */
    [0x72] = { (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL }, /* shiftd */
    [0x73] = { (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL }, /* shiftq */
    [0x74] = MMX_OP2(pcmpeqb),
    [0x75] = MMX_OP2(pcmpeqw),
    [0x76] = MMX_OP2(pcmpeql),
    [0x77] = { (SSEFunc_0_epp)SSE_DUMMY }, /* emms */
    [0x78] = { NULL, (SSEFunc_0_epp)SSE_SPECIAL, NULL, (SSEFunc_0_epp)SSE_SPECIAL }, /* extrq_i, insertq_i */
    [0x79] = { NULL, gen_helper_extrq_r, NULL, gen_helper_insertq_r },
    [0x7c] = { NULL, gen_helper_haddpd, NULL, gen_helper_haddps },
    [0x7d] = { NULL, gen_helper_hsubpd, NULL, gen_helper_hsubps },
    [0x7e] = { (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL }, /* movd, movd, , movq */
    [0x7f] = { (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL }, /* movq, movdqa, movdqu */
    [0xc4] = { (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL }, /* pinsrw */
    [0xc5] = { (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL }, /* pextrw */
    [0xd0] = { NULL, gen_helper_addsubpd, NULL, gen_helper_addsubps },
    [0xd1] = MMX_OP2(psrlw),
    [0xd2] = MMX_OP2(psrld),
    [0xd3] = MMX_OP2(psrlq),
    [0xd4] = MMX_OP2(paddq),
    [0xd5] = MMX_OP2(pmullw),
    [0xd6] = { NULL, (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL },
    [0xd7] = { (SSEFunc_0_epp)SSE_SPECIAL, (SSEFunc_0_epp)SSE_SPECIAL }, /* pmovmskb */
    [0xd8] = MMX_OP2(psubusb),
    [0xd9] = MMX_OP2(psubusw),
    [0xda] = MMX_OP2(pminub),
    [0xdb] = MMX_OP2(pand),
    [0xdc] = MMX_OP2(paddusb),
    [0xdd] = MMX_OP2(paddusw),
    [0xde] = MMX_OP2(pmaxub),
    [0xdf] = MMX_OP2(pandn),
    [0xe0] = MMX_OP2(pavgb),
    [0xe1] = MMX_OP2(psraw),
    [0xe2] = MMX_OP2(psrad),
    [0xe3] = MMX_OP2(pavgw),
    [0xe4] = MMX_OP2(pmulhuw),
    [0xe5] = MMX_OP2(pmulhw),
    [0xe6] = { NULL, gen_helper_cvttpd2dq, gen_helper_cvtdq2pd, gen_helper_cvtpd2dq },
    [0xe7] = { (SSEFunc_0_epp)SSE_SPECIAL , (SSEFunc_0_epp)SSE_SPECIAL },  /* movntq, movntq */
    [0xe8] = MMX_OP2(psubsb),
    [0xe9] = MMX_OP2(psubsw),
    [0xea] = MMX_OP2(pminsw),
    [0xeb] = MMX_OP2(por),
    [0xec] = MMX_OP2(paddsb),
    [0xed] = MMX_OP2(paddsw),
    [0xee] = MMX_OP2(pmaxsw),
    [0xef] = MMX_OP2(pxor),
    [0xf0] = { NULL, NULL, NULL, (SSEFunc_0_epp)SSE_SPECIAL }, /* lddqu */
    [0xf1] = MMX_OP2(psllw),
    [0xf2] = MMX_OP2(pslld),
    [0xf3] = MMX_OP2(psllq),
    [0xf4] = MMX_OP2(pmuludq),
    [0xf5] = MMX_OP2(pmaddwd),
    [0xf6] = MMX_OP2(psadbw),
    [0xf7] = { (SSEFunc_0_epp)gen_helper_maskmov_mmx,
               (SSEFunc_0_epp)gen_helper_maskmov_xmm }, /* XXX: casts */
    [0xf8] = MMX_OP2(psubb),
    [0xf9] = MMX_OP2(psubw),
    [0xfa] = MMX_OP2(psubl),
    [0xfb] = MMX_OP2(psubq),
    [0xfc] = MMX_OP2(paddb),
    [0xfd] = MMX_OP2(paddw),
    [0xfe] = MMX_OP2(paddl),
};

static const SSEFunc_0_epp sse_op_table2[3 * 8][2] = {
    [0 + 2] = MMX_OP2(psrlw),
    [0 + 4] = MMX_OP2(psraw),
    [0 + 6] = MMX_OP2(psllw),
    [8 + 2] = MMX_OP2(psrld),
    [8 + 4] = MMX_OP2(psrad),
    [8 + 6] = MMX_OP2(pslld),
    [16 + 2] = MMX_OP2(psrlq),
    [16 + 3] = { NULL, gen_helper_psrldq_xmm },
    [16 + 6] = MMX_OP2(psllq),
    [16 + 7] = { NULL, gen_helper_pslldq_xmm },
};

static const SSEFunc_0_epi sse_op_table3ai[] = {
    gen_helper_cvtsi2ss,
    gen_helper_cvtsi2sd
};

static const SSEFunc_0_epl sse_op_table3aq[] = {
    gen_helper_cvtsq2ss,
    gen_helper_cvtsq2sd
};

static const SSEFunc_i_ep sse_op_table3bi[] = {
    gen_helper_cvttss2si,
    gen_helper_cvtss2si,
    gen_helper_cvttsd2si,
    gen_helper_cvtsd2si
};

static const SSEFunc_l_ep sse_op_table3bq[] = {
    gen_helper_cvttss2sq,
    gen_helper_cvtss2sq,
    gen_helper_cvttsd2sq,
    gen_helper_cvtsd2sq
};

static const SSEFunc_0_epp sse_op_table4[8][4] = {
    SSE_FOP(cmpeq),
    SSE_FOP(cmplt),
    SSE_FOP(cmple),
    SSE_FOP(cmpunord),
    SSE_FOP(cmpneq),
    SSE_FOP(cmpnlt),
    SSE_FOP(cmpnle),
    SSE_FOP(cmpord),
};

static const SSEFunc_0_epp sse_op_table5[256] = {
    [0x0c] = gen_helper_pi2fw,
    [0x0d] = gen_helper_pi2fd,
    [0x1c] = gen_helper_pf2iw,
    [0x1d] = gen_helper_pf2id,
    [0x8a] = gen_helper_pfnacc,
    [0x8e] = gen_helper_pfpnacc,
    [0x90] = gen_helper_pfcmpge,
    [0x94] = gen_helper_pfmin,
    [0x96] = gen_helper_pfrcp,
    [0x97] = gen_helper_pfrsqrt,
    [0x9a] = gen_helper_pfsub,
    [0x9e] = gen_helper_pfadd,
    [0xa0] = gen_helper_pfcmpgt,
    [0xa4] = gen_helper_pfmax,
    [0xa6] = gen_helper_movq, /* pfrcpit1; no need to actually increase precision */
    [0xa7] = gen_helper_movq, /* pfrsqit1 */
    [0xaa] = gen_helper_pfsubr,
    [0xae] = gen_helper_pfacc,
    [0xb0] = gen_helper_pfcmpeq,
    [0xb4] = gen_helper_pfmul,
    [0xb6] = gen_helper_movq, /* pfrcpit2 */
    [0xb7] = gen_helper_pmulhrw_mmx,
    [0xbb] = gen_helper_pswapd,
    [0xbf] = gen_helper_pavgb_mmx /* pavgusb */
};

struct SSEOpHelper_epp {
    SSEFunc_0_epp op[2];
    uint32_t ext_mask;
};

#define SSSE3_OP(x) { MMX_OP2(x), CPUID_EXT_SSSE3 }

#define SSE41_OP(x) { { NULL, gen_helper_ ## x ## _xmm }, CPUID_EXT_SSE41 }

#define SSE42_OP(x) { { NULL, gen_helper_ ## x ## _xmm }, CPUID_EXT_SSE42 }

#define SSE41_SPECIAL { { (SSEFunc_0_epp)NULL, (SSEFunc_0_epp)SSE_SPECIAL }, CPUID_EXT_SSE41 }

#define PCLMULQDQ_OP(x) { { NULL, gen_helper_ ## x ## _xmm }, \
        CPUID_EXT_PCLMULQDQ }

#define AESNI_OP(x) { { NULL, gen_helper_ ## x ## _xmm }, CPUID_EXT_AES }

struct SSEOpHelper_eppi {
    SSEFunc_0_eppi op[2];
    uint32_t ext_mask;
};

static const struct SSEOpHelper_epp sse_op_table6[256] = {
    [0x00] = SSSE3_OP(pshufb),
    [0x01] = SSSE3_OP(phaddw),
    [0x02] = SSSE3_OP(phaddd),
    [0x03] = SSSE3_OP(phaddsw),
    [0x04] = SSSE3_OP(pmaddubsw),
    [0x05] = SSSE3_OP(phsubw),
    [0x06] = SSSE3_OP(phsubd),
    [0x07] = SSSE3_OP(phsubsw),
    [0x08] = SSSE3_OP(psignb),
    [0x09] = SSSE3_OP(psignw),
    [0x0a] = SSSE3_OP(psignd),
    [0x0b] = SSSE3_OP(pmulhrsw),
    [0x10] = SSE41_OP(pblendvb),
    [0x14] = SSE41_OP(blendvps),
    [0x15] = SSE41_OP(blendvpd),
    [0x17] = SSE41_OP(ptest),
    [0x1c] = SSSE3_OP(pabsb),
    [0x1d] = SSSE3_OP(pabsw),
    [0x1e] = SSSE3_OP(pabsd),
    [0x20] = SSE41_OP(pmovsxbw),
    [0x21] = SSE41_OP(pmovsxbd),
    [0x22] = SSE41_OP(pmovsxbq),
    [0x23] = SSE41_OP(pmovsxwd),
    [0x24] = SSE41_OP(pmovsxwq),
    [0x25] = SSE41_OP(pmovsxdq),
    [0x28] = SSE41_OP(pmuldq),
    [0x29] = SSE41_OP(pcmpeqq),
    [0x2a] = SSE41_SPECIAL, /* movntqda */
    [0x2b] = SSE41_OP(packusdw),
    [0x30] = SSE41_OP(pmovzxbw),
    [0x31] = SSE41_OP(pmovzxbd),
    [0x32] = SSE41_OP(pmovzxbq),
    [0x33] = SSE41_OP(pmovzxwd),
    [0x34] = SSE41_OP(pmovzxwq),
    [0x35] = SSE41_OP(pmovzxdq),
    [0x37] = SSE42_OP(pcmpgtq),
    [0x38] = SSE41_OP(pminsb),
    [0x39] = SSE41_OP(pminsd),
    [0x3a] = SSE41_OP(pminuw),
    [0x3b] = SSE41_OP(pminud),
    [0x3c] = SSE41_OP(pmaxsb),
    [0x3d] = SSE41_OP(pmaxsd),
    [0x3e] = SSE41_OP(pmaxuw),
    [0x3f] = SSE41_OP(pmaxud),
    [0x40] = SSE41_OP(pmulld),
    [0x41] = SSE41_OP(phminposuw),
    [0xdb] = AESNI_OP(aesimc),
    [0xdc] = AESNI_OP(aesenc),
    [0xdd] = AESNI_OP(aesenclast),
    [0xde] = AESNI_OP(aesdec),
    [0xdf] = AESNI_OP(aesdeclast),
};

#define SSE41_SPECIAL { { (SSEFunc_0_eppi)NULL, (SSEFunc_0_eppi)SSE_SPECIAL }, CPUID_EXT_SSE41 }

static const struct SSEOpHelper_eppi sse_op_table7[256] = {
    [0x08] = SSE41_OP(roundps),
    [0x09] = SSE41_OP(roundpd),
    [0x0a] = SSE41_OP(roundss),
    [0x0b] = SSE41_OP(roundsd),
    [0x0c] = SSE41_OP(blendps),
    [0x0d] = SSE41_OP(blendpd),
    [0x0e] = SSE41_OP(pblendw),
    [0x0f] = SSSE3_OP(palignr),
    [0x14] = SSE41_SPECIAL, /* pextrb */
    [0x15] = SSE41_SPECIAL, /* pextrw */
    [0x16] = SSE41_SPECIAL, /* pextrd/pextrq */
    [0x17] = SSE41_SPECIAL, /* extractps */
    [0x20] = SSE41_SPECIAL, /* pinsrb */
    [0x21] = SSE41_SPECIAL, /* insertps */
    [0x22] = SSE41_SPECIAL, /* pinsrd/pinsrq */
    [0x40] = SSE41_OP(dpps),
    [0x41] = SSE41_OP(dppd),
    [0x42] = SSE41_OP(mpsadbw),
    [0x44] = PCLMULQDQ_OP(pclmulqdq),
    [0x60] = SSE42_OP(pcmpestrm),
    [0x61] = SSE42_OP(pcmpestri),
    [0x62] = SSE42_OP(pcmpistrm),
    [0x63] = SSE42_OP(pcmpistri),
    [0xdf] = AESNI_OP(aeskeygenassist),
};

static void gen_sse(CPUX86State *env, DisasContext *s, int b,
                    target_ulong pc_start, int rex_r)
{
    int b1, op1_offset, op2_offset, is_xmm, val;
    int modrm, mod, rm, reg;
    SSEFunc_0_epp sse_fn_epp;
    SSEFunc_0_eppi sse_fn_eppi;
    SSEFunc_0_ppi sse_fn_ppi;
    SSEFunc_0_eppt sse_fn_eppt;
    TCGMemOp ot;

    b &= 0xff;
    if (s->prefix & PREFIX_DATA)
        b1 = 1;
    else if (s->prefix & PREFIX_REPZ)
        b1 = 2;
    else if (s->prefix & PREFIX_REPNZ)
        b1 = 3;
    else
        b1 = 0;
    sse_fn_epp = sse_op_table1[b][b1];
    if (!sse_fn_epp) {
        goto unknown_op;
    }
    if ((b <= 0x5f && b >= 0x10) || b == 0xc6 || b == 0xc2) {
        is_xmm = 1;
    } else {
        if (b1 == 0) {
            /* MMX case */
            is_xmm = 0;
        } else {
            is_xmm = 1;
        }
    }
    /* simple MMX/SSE operation */
    if (s->flags & HF_TS_MASK) {
        gen_exception(s, EXCP07_PREX, pc_start - s->cs_base);
        return;
    }
    if (s->flags & HF_EM_MASK) {
    illegal_op:
        gen_illegal_opcode(s);
        return;
    }
    if (is_xmm
        && !(s->flags & HF_OSFXSR_MASK)
        && ((b != 0x38 && b != 0x3a) || (s->prefix & PREFIX_DATA))) {
        goto unknown_op;
    }
    if (b == 0x0e) {
        if (!(s->cpuid_ext2_features & CPUID_EXT2_3DNOW)) {
            /* If we were fully decoding this we might use illegal_op.  */
            goto unknown_op;
        }
        /* femms */
        gen_helper_emms(cpu_env);
        return;
    }
    if (b == 0x77) {
        /* emms */
        gen_helper_emms(cpu_env);
        return;
    }
    /* prepare MMX state (XXX: optimize by storing fptt and fptags in
       the static cpu state) */
    if (!is_xmm) {
        gen_helper_enter_mmx(cpu_env);
    }

    modrm = x86_ldub_code(env, s);
    reg = ((modrm >> 3) & 7);
    if (is_xmm)
        reg |= rex_r;
    mod = (modrm >> 6) & 3;
    if (sse_fn_epp == SSE_SPECIAL) {
        b |= (b1 << 8);
        switch(b) {
        case 0x0e7: /* movntq */
            if (mod == 3) {
                goto illegal_op;
            }
            gen_lea_modrm(env, s, modrm);
            gen_stq_env_A0(s, offsetof(CPUX86State, fpregs[reg].mmx));
            break;
        case 0x1e7: /* movntdq */
        case 0x02b: /* movntps */
        case 0x12b: /* movntps */
            if (mod == 3)
                goto illegal_op;
            gen_lea_modrm(env, s, modrm);
            gen_sto_env_A0(s, offsetof(CPUX86State, xmm_regs[reg]));
            break;
        case 0x3f0: /* lddqu */
            if (mod == 3)
                goto illegal_op;
            gen_lea_modrm(env, s, modrm);
            gen_ldo_env_A0(s, offsetof(CPUX86State, xmm_regs[reg]));
            break;
        case 0x22b: /* movntss */
        case 0x32b: /* movntsd */
            if (mod == 3)
                goto illegal_op;
            gen_lea_modrm(env, s, modrm);
            if (b1 & 1) {
                gen_stq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].ZMM_Q(0)));
            } else {
                tcg_gen_ld32u_tl(cpu_T0, cpu_env, offsetof(CPUX86State,
                    xmm_regs[reg].ZMM_L(0)));
                gen_op_st_v(s, MO_32, cpu_T0, cpu_A0);
            }
            break;
        case 0x6e: /* movd mm, ea */
#ifdef TARGET_X86_64
            if (s->dflag == MO_64) {
                gen_ldst_modrm(env, s, modrm, MO_64, OR_TMP0, 0);
                tcg_gen_st_tl(cpu_T0, cpu_env, offsetof(CPUX86State,fpregs[reg].mmx));
            } else
#endif
            {
                gen_ldst_modrm(env, s, modrm, MO_32, OR_TMP0, 0);
                tcg_gen_addi_ptr(cpu_ptr0, cpu_env, 
                                 offsetof(CPUX86State,fpregs[reg].mmx));
                tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_T0);
                gen_helper_movl_mm_T0_mmx(cpu_ptr0, cpu_tmp2_i32);
            }
            break;
        case 0x16e: /* movd xmm, ea */
#ifdef TARGET_X86_64
            if (s->dflag == MO_64) {
                gen_ldst_modrm(env, s, modrm, MO_64, OR_TMP0, 0);
                tcg_gen_addi_ptr(cpu_ptr0, cpu_env, 
                                 offsetof(CPUX86State,xmm_regs[reg]));
                gen_helper_movq_mm_T0_xmm(cpu_ptr0, cpu_T0);
            } else
#endif
            {
                gen_ldst_modrm(env, s, modrm, MO_32, OR_TMP0, 0);
                tcg_gen_addi_ptr(cpu_ptr0, cpu_env, 
                                 offsetof(CPUX86State,xmm_regs[reg]));
                tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_T0);
                gen_helper_movl_mm_T0_xmm(cpu_ptr0, cpu_tmp2_i32);
            }
            break;
        case 0x6f: /* movq mm, ea */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldq_env_A0(s, offsetof(CPUX86State, fpregs[reg].mmx));
            } else {
                rm = (modrm & 7);
                tcg_gen_ld_i64(cpu_tmp1_i64, cpu_env,
                               offsetof(CPUX86State,fpregs[rm].mmx));
                tcg_gen_st_i64(cpu_tmp1_i64, cpu_env,
                               offsetof(CPUX86State,fpregs[reg].mmx));
            }
            break;
        case 0x010: /* movups */
        case 0x110: /* movupd */
        case 0x028: /* movaps */
        case 0x128: /* movapd */
        case 0x16f: /* movdqa xmm, ea */
        case 0x26f: /* movdqu xmm, ea */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldo_env_A0(s, offsetof(CPUX86State, xmm_regs[reg]));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movo(offsetof(CPUX86State,xmm_regs[reg]),
                            offsetof(CPUX86State,xmm_regs[rm]));
            }
            break;
        case 0x210: /* movss xmm, ea */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_op_ld_v(s, MO_32, cpu_T0, cpu_A0);
                tcg_gen_st32_tl(cpu_T0, cpu_env, offsetof(CPUX86State,xmm_regs[reg].ZMM_L(0)));
                tcg_gen_movi_tl(cpu_T0, 0);
                tcg_gen_st32_tl(cpu_T0, cpu_env, offsetof(CPUX86State,xmm_regs[reg].ZMM_L(1)));
                tcg_gen_st32_tl(cpu_T0, cpu_env, offsetof(CPUX86State,xmm_regs[reg].ZMM_L(2)));
                tcg_gen_st32_tl(cpu_T0, cpu_env, offsetof(CPUX86State,xmm_regs[reg].ZMM_L(3)));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movl(offsetof(CPUX86State,xmm_regs[reg].ZMM_L(0)),
                            offsetof(CPUX86State,xmm_regs[rm].ZMM_L(0)));
            }
            break;
        case 0x310: /* movsd xmm, ea */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].ZMM_Q(0)));
                tcg_gen_movi_tl(cpu_T0, 0);
                tcg_gen_st32_tl(cpu_T0, cpu_env, offsetof(CPUX86State,xmm_regs[reg].ZMM_L(2)));
                tcg_gen_st32_tl(cpu_T0, cpu_env, offsetof(CPUX86State,xmm_regs[reg].ZMM_L(3)));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movq(offsetof(CPUX86State,xmm_regs[reg].ZMM_Q(0)),
                            offsetof(CPUX86State,xmm_regs[rm].ZMM_Q(0)));
            }
            break;
        case 0x012: /* movlps */
        case 0x112: /* movlpd */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].ZMM_Q(0)));
            } else {
                /* movhlps */
                rm = (modrm & 7) | REX_B(s);
                gen_op_movq(offsetof(CPUX86State,xmm_regs[reg].ZMM_Q(0)),
                            offsetof(CPUX86State,xmm_regs[rm].ZMM_Q(1)));
            }
            break;
        case 0x212: /* movsldup */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldo_env_A0(s, offsetof(CPUX86State, xmm_regs[reg]));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movl(offsetof(CPUX86State,xmm_regs[reg].ZMM_L(0)),
                            offsetof(CPUX86State,xmm_regs[rm].ZMM_L(0)));
                gen_op_movl(offsetof(CPUX86State,xmm_regs[reg].ZMM_L(2)),
                            offsetof(CPUX86State,xmm_regs[rm].ZMM_L(2)));
            }
            gen_op_movl(offsetof(CPUX86State,xmm_regs[reg].ZMM_L(1)),
                        offsetof(CPUX86State,xmm_regs[reg].ZMM_L(0)));
            gen_op_movl(offsetof(CPUX86State,xmm_regs[reg].ZMM_L(3)),
                        offsetof(CPUX86State,xmm_regs[reg].ZMM_L(2)));
            break;
        case 0x312: /* movddup */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].ZMM_Q(0)));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movq(offsetof(CPUX86State,xmm_regs[reg].ZMM_Q(0)),
                            offsetof(CPUX86State,xmm_regs[rm].ZMM_Q(0)));
            }
            gen_op_movq(offsetof(CPUX86State,xmm_regs[reg].ZMM_Q(1)),
                        offsetof(CPUX86State,xmm_regs[reg].ZMM_Q(0)));
            break;
        case 0x016: /* movhps */
        case 0x116: /* movhpd */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].ZMM_Q(1)));
            } else {
                /* movlhps */
                rm = (modrm & 7) | REX_B(s);
                gen_op_movq(offsetof(CPUX86State,xmm_regs[reg].ZMM_Q(1)),
                            offsetof(CPUX86State,xmm_regs[rm].ZMM_Q(0)));
            }
            break;
        case 0x216: /* movshdup */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldo_env_A0(s, offsetof(CPUX86State, xmm_regs[reg]));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movl(offsetof(CPUX86State,xmm_regs[reg].ZMM_L(1)),
                            offsetof(CPUX86State,xmm_regs[rm].ZMM_L(1)));
                gen_op_movl(offsetof(CPUX86State,xmm_regs[reg].ZMM_L(3)),
                            offsetof(CPUX86State,xmm_regs[rm].ZMM_L(3)));
            }
            gen_op_movl(offsetof(CPUX86State,xmm_regs[reg].ZMM_L(0)),
                        offsetof(CPUX86State,xmm_regs[reg].ZMM_L(1)));
            gen_op_movl(offsetof(CPUX86State,xmm_regs[reg].ZMM_L(2)),
                        offsetof(CPUX86State,xmm_regs[reg].ZMM_L(3)));
            break;
        case 0x178:
        case 0x378:
            {
                int bit_index, field_length;

                if (b1 == 1 && reg != 0)
                    goto illegal_op;
                field_length = x86_ldub_code(env, s) & 0x3F;
                bit_index = x86_ldub_code(env, s) & 0x3F;
                tcg_gen_addi_ptr(cpu_ptr0, cpu_env,
                    offsetof(CPUX86State,xmm_regs[reg]));
                if (b1 == 1)
                    gen_helper_extrq_i(cpu_env, cpu_ptr0,
                                       tcg_const_i32(bit_index),
                                       tcg_const_i32(field_length));
                else
                    gen_helper_insertq_i(cpu_env, cpu_ptr0,
                                         tcg_const_i32(bit_index),
                                         tcg_const_i32(field_length));
            }
            break;
        case 0x7e: /* movd ea, mm */
#ifdef TARGET_X86_64
            if (s->dflag == MO_64) {
                tcg_gen_ld_i64(cpu_T0, cpu_env,
                               offsetof(CPUX86State,fpregs[reg].mmx));
                gen_ldst_modrm(env, s, modrm, MO_64, OR_TMP0, 1);
            } else
#endif
            {
                tcg_gen_ld32u_tl(cpu_T0, cpu_env,
                                 offsetof(CPUX86State,fpregs[reg].mmx.MMX_L(0)));
                gen_ldst_modrm(env, s, modrm, MO_32, OR_TMP0, 1);
            }
            break;
        case 0x17e: /* movd ea, xmm */
#ifdef TARGET_X86_64
            if (s->dflag == MO_64) {
                tcg_gen_ld_i64(cpu_T0, cpu_env,
                               offsetof(CPUX86State,xmm_regs[reg].ZMM_Q(0)));
                gen_ldst_modrm(env, s, modrm, MO_64, OR_TMP0, 1);
            } else
#endif
            {
                tcg_gen_ld32u_tl(cpu_T0, cpu_env,
                                 offsetof(CPUX86State,xmm_regs[reg].ZMM_L(0)));
                gen_ldst_modrm(env, s, modrm, MO_32, OR_TMP0, 1);
            }
            break;
        case 0x27e: /* movq xmm, ea */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].ZMM_Q(0)));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movq(offsetof(CPUX86State,xmm_regs[reg].ZMM_Q(0)),
                            offsetof(CPUX86State,xmm_regs[rm].ZMM_Q(0)));
            }
            gen_op_movq_env_0(offsetof(CPUX86State,xmm_regs[reg].ZMM_Q(1)));
            break;
        case 0x7f: /* movq ea, mm */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_stq_env_A0(s, offsetof(CPUX86State, fpregs[reg].mmx));
            } else {
                rm = (modrm & 7);
                gen_op_movq(offsetof(CPUX86State,fpregs[rm].mmx),
                            offsetof(CPUX86State,fpregs[reg].mmx));
            }
            break;
        case 0x011: /* movups */
        case 0x111: /* movupd */
        case 0x029: /* movaps */
        case 0x129: /* movapd */
        case 0x17f: /* movdqa ea, xmm */
        case 0x27f: /* movdqu ea, xmm */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_sto_env_A0(s, offsetof(CPUX86State, xmm_regs[reg]));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movo(offsetof(CPUX86State,xmm_regs[rm]),
                            offsetof(CPUX86State,xmm_regs[reg]));
            }
            break;
        case 0x211: /* movss ea, xmm */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                tcg_gen_ld32u_tl(cpu_T0, cpu_env, offsetof(CPUX86State,xmm_regs[reg].ZMM_L(0)));
                gen_op_st_v(s, MO_32, cpu_T0, cpu_A0);
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movl(offsetof(CPUX86State,xmm_regs[rm].ZMM_L(0)),
                            offsetof(CPUX86State,xmm_regs[reg].ZMM_L(0)));
            }
            break;
        case 0x311: /* movsd ea, xmm */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_stq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].ZMM_Q(0)));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movq(offsetof(CPUX86State,xmm_regs[rm].ZMM_Q(0)),
                            offsetof(CPUX86State,xmm_regs[reg].ZMM_Q(0)));
            }
            break;
        case 0x013: /* movlps */
        case 0x113: /* movlpd */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_stq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].ZMM_Q(0)));
            } else {
                goto illegal_op;
            }
            break;
        case 0x017: /* movhps */
        case 0x117: /* movhpd */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_stq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].ZMM_Q(1)));
            } else {
                goto illegal_op;
            }
            break;
        case 0x71: /* shift mm, im */
        case 0x72:
        case 0x73:
        case 0x171: /* shift xmm, im */
        case 0x172:
        case 0x173:
            if (b1 >= 2) {
	        goto unknown_op;
            }
            val = x86_ldub_code(env, s);
            if (is_xmm) {
                tcg_gen_movi_tl(cpu_T0, val);
                tcg_gen_st32_tl(cpu_T0, cpu_env, offsetof(CPUX86State,xmm_t0.ZMM_L(0)));
                tcg_gen_movi_tl(cpu_T0, 0);
                tcg_gen_st32_tl(cpu_T0, cpu_env, offsetof(CPUX86State,xmm_t0.ZMM_L(1)));
                op1_offset = offsetof(CPUX86State,xmm_t0);
            } else {
                tcg_gen_movi_tl(cpu_T0, val);
                tcg_gen_st32_tl(cpu_T0, cpu_env, offsetof(CPUX86State,mmx_t0.MMX_L(0)));
                tcg_gen_movi_tl(cpu_T0, 0);
                tcg_gen_st32_tl(cpu_T0, cpu_env, offsetof(CPUX86State,mmx_t0.MMX_L(1)));
                op1_offset = offsetof(CPUX86State,mmx_t0);
            }
            sse_fn_epp = sse_op_table2[((b - 1) & 3) * 8 +
                                       (((modrm >> 3)) & 7)][b1];
            if (!sse_fn_epp) {
                goto unknown_op;
            }
            if (is_xmm) {
                rm = (modrm & 7) | REX_B(s);
                op2_offset = offsetof(CPUX86State,xmm_regs[rm]);
            } else {
                rm = (modrm & 7);
                op2_offset = offsetof(CPUX86State,fpregs[rm].mmx);
            }
            tcg_gen_addi_ptr(cpu_ptr0, cpu_env, op2_offset);
            tcg_gen_addi_ptr(cpu_ptr1, cpu_env, op1_offset);
            sse_fn_epp(cpu_env, cpu_ptr0, cpu_ptr1);
            break;
        case 0x050: /* movmskps */
            rm = (modrm & 7) | REX_B(s);
            tcg_gen_addi_ptr(cpu_ptr0, cpu_env, 
                             offsetof(CPUX86State,xmm_regs[rm]));
            gen_helper_movmskps(cpu_tmp2_i32, cpu_env, cpu_ptr0);
            tcg_gen_extu_i32_tl(cpu_regs[reg], cpu_tmp2_i32);
            break;
        case 0x150: /* movmskpd */
            rm = (modrm & 7) | REX_B(s);
            tcg_gen_addi_ptr(cpu_ptr0, cpu_env, 
                             offsetof(CPUX86State,xmm_regs[rm]));
            gen_helper_movmskpd(cpu_tmp2_i32, cpu_env, cpu_ptr0);
            tcg_gen_extu_i32_tl(cpu_regs[reg], cpu_tmp2_i32);
            break;
        case 0x02a: /* cvtpi2ps */
        case 0x12a: /* cvtpi2pd */
            gen_helper_enter_mmx(cpu_env);
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                op2_offset = offsetof(CPUX86State,mmx_t0);
                gen_ldq_env_A0(s, op2_offset);
            } else {
                rm = (modrm & 7);
                op2_offset = offsetof(CPUX86State,fpregs[rm].mmx);
            }
            op1_offset = offsetof(CPUX86State,xmm_regs[reg]);
            tcg_gen_addi_ptr(cpu_ptr0, cpu_env, op1_offset);
            tcg_gen_addi_ptr(cpu_ptr1, cpu_env, op2_offset);
            switch(b >> 8) {
            case 0x0:
                gen_helper_cvtpi2ps(cpu_env, cpu_ptr0, cpu_ptr1);
                break;
            default:
            case 0x1:
                gen_helper_cvtpi2pd(cpu_env, cpu_ptr0, cpu_ptr1);
                break;
            }
            break;
        case 0x22a: /* cvtsi2ss */
        case 0x32a: /* cvtsi2sd */
            ot = mo_64_32(s->dflag);
            gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
            op1_offset = offsetof(CPUX86State,xmm_regs[reg]);
            tcg_gen_addi_ptr(cpu_ptr0, cpu_env, op1_offset);
            if (ot == MO_32) {
                SSEFunc_0_epi sse_fn_epi = sse_op_table3ai[(b >> 8) & 1];
                tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_T0);
                sse_fn_epi(cpu_env, cpu_ptr0, cpu_tmp2_i32);
            } else {
#ifdef TARGET_X86_64
                SSEFunc_0_epl sse_fn_epl = sse_op_table3aq[(b >> 8) & 1];
                sse_fn_epl(cpu_env, cpu_ptr0, cpu_T0);
#else
                goto illegal_op;
#endif
            }
            break;
        case 0x02c: /* cvttps2pi */
        case 0x12c: /* cvttpd2pi */
        case 0x02d: /* cvtps2pi */
        case 0x12d: /* cvtpd2pi */
            gen_helper_enter_mmx(cpu_env);
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                op2_offset = offsetof(CPUX86State,xmm_t0);
                gen_ldo_env_A0(s, op2_offset);
            } else {
                rm = (modrm & 7) | REX_B(s);
                op2_offset = offsetof(CPUX86State,xmm_regs[rm]);
            }
            op1_offset = offsetof(CPUX86State,fpregs[reg & 7].mmx);
            tcg_gen_addi_ptr(cpu_ptr0, cpu_env, op1_offset);
            tcg_gen_addi_ptr(cpu_ptr1, cpu_env, op2_offset);
            switch(b) {
            case 0x02c:
                gen_helper_cvttps2pi(cpu_env, cpu_ptr0, cpu_ptr1);
                break;
            case 0x12c:
                gen_helper_cvttpd2pi(cpu_env, cpu_ptr0, cpu_ptr1);
                break;
            case 0x02d:
                gen_helper_cvtps2pi(cpu_env, cpu_ptr0, cpu_ptr1);
                break;
            case 0x12d:
                gen_helper_cvtpd2pi(cpu_env, cpu_ptr0, cpu_ptr1);
                break;
            }
            break;
        case 0x22c: /* cvttss2si */
        case 0x32c: /* cvttsd2si */
        case 0x22d: /* cvtss2si */
        case 0x32d: /* cvtsd2si */
            ot = mo_64_32(s->dflag);
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                if ((b >> 8) & 1) {
                    gen_ldq_env_A0(s, offsetof(CPUX86State, xmm_t0.ZMM_Q(0)));
                } else {
                    gen_op_ld_v(s, MO_32, cpu_T0, cpu_A0);
                    tcg_gen_st32_tl(cpu_T0, cpu_env, offsetof(CPUX86State,xmm_t0.ZMM_L(0)));
                }
                op2_offset = offsetof(CPUX86State,xmm_t0);
            } else {
                rm = (modrm & 7) | REX_B(s);
                op2_offset = offsetof(CPUX86State,xmm_regs[rm]);
            }
            tcg_gen_addi_ptr(cpu_ptr0, cpu_env, op2_offset);
            if (ot == MO_32) {
                SSEFunc_i_ep sse_fn_i_ep =
                    sse_op_table3bi[((b >> 7) & 2) | (b & 1)];
                sse_fn_i_ep(cpu_tmp2_i32, cpu_env, cpu_ptr0);
                tcg_gen_extu_i32_tl(cpu_T0, cpu_tmp2_i32);
            } else {
#ifdef TARGET_X86_64
                SSEFunc_l_ep sse_fn_l_ep =
                    sse_op_table3bq[((b >> 7) & 2) | (b & 1)];
                sse_fn_l_ep(cpu_T0, cpu_env, cpu_ptr0);
#else
                goto illegal_op;
#endif
            }
            gen_op_mov_reg_v(ot, reg, cpu_T0);
            break;
        case 0xc4: /* pinsrw */
        case 0x1c4:
            s->rip_offset = 1;
            gen_ldst_modrm(env, s, modrm, MO_16, OR_TMP0, 0);
            val = x86_ldub_code(env, s);
            if (b1) {
                val &= 7;
                tcg_gen_st16_tl(cpu_T0, cpu_env,
                                offsetof(CPUX86State,xmm_regs[reg].ZMM_W(val)));
            } else {
                val &= 3;
                tcg_gen_st16_tl(cpu_T0, cpu_env,
                                offsetof(CPUX86State,fpregs[reg].mmx.MMX_W(val)));
            }
            break;
        case 0xc5: /* pextrw */
        case 0x1c5:
            if (mod != 3)
                goto illegal_op;
            ot = mo_64_32(s->dflag);
            val = x86_ldub_code(env, s);
            if (b1) {
                val &= 7;
                rm = (modrm & 7) | REX_B(s);
                tcg_gen_ld16u_tl(cpu_T0, cpu_env,
                                 offsetof(CPUX86State,xmm_regs[rm].ZMM_W(val)));
            } else {
                val &= 3;
                rm = (modrm & 7);
                tcg_gen_ld16u_tl(cpu_T0, cpu_env,
                                offsetof(CPUX86State,fpregs[rm].mmx.MMX_W(val)));
            }
            reg = ((modrm >> 3) & 7) | rex_r;
            gen_op_mov_reg_v(ot, reg, cpu_T0);
            break;
        case 0x1d6: /* movq ea, xmm */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_stq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].ZMM_Q(0)));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movq(offsetof(CPUX86State,xmm_regs[rm].ZMM_Q(0)),
                            offsetof(CPUX86State,xmm_regs[reg].ZMM_Q(0)));
                gen_op_movq_env_0(offsetof(CPUX86State,xmm_regs[rm].ZMM_Q(1)));
            }
            break;
        case 0x2d6: /* movq2dq */
            gen_helper_enter_mmx(cpu_env);
            rm = (modrm & 7);
            gen_op_movq(offsetof(CPUX86State,xmm_regs[reg].ZMM_Q(0)),
                        offsetof(CPUX86State,fpregs[rm].mmx));
            gen_op_movq_env_0(offsetof(CPUX86State,xmm_regs[reg].ZMM_Q(1)));
            break;
        case 0x3d6: /* movdq2q */
            gen_helper_enter_mmx(cpu_env);
            rm = (modrm & 7) | REX_B(s);
            gen_op_movq(offsetof(CPUX86State,fpregs[reg & 7].mmx),
                        offsetof(CPUX86State,xmm_regs[rm].ZMM_Q(0)));
            break;
        case 0xd7: /* pmovmskb */
        case 0x1d7:
            if (mod != 3)
                goto illegal_op;
            if (b1) {
                rm = (modrm & 7) | REX_B(s);
                tcg_gen_addi_ptr(cpu_ptr0, cpu_env, offsetof(CPUX86State,xmm_regs[rm]));
                gen_helper_pmovmskb_xmm(cpu_tmp2_i32, cpu_env, cpu_ptr0);
            } else {
                rm = (modrm & 7);
                tcg_gen_addi_ptr(cpu_ptr0, cpu_env, offsetof(CPUX86State,fpregs[rm].mmx));
                gen_helper_pmovmskb_mmx(cpu_tmp2_i32, cpu_env, cpu_ptr0);
            }
            reg = ((modrm >> 3) & 7) | rex_r;
            tcg_gen_extu_i32_tl(cpu_regs[reg], cpu_tmp2_i32);
            break;

        case 0x138:
        case 0x038:
            b = modrm;
            if ((b & 0xf0) == 0xf0) {
                goto do_0f_38_fx;
            }
            modrm = x86_ldub_code(env, s);
            rm = modrm & 7;
            reg = ((modrm >> 3) & 7) | rex_r;
            mod = (modrm >> 6) & 3;
            if (b1 >= 2) {
                goto unknown_op;
            }

            sse_fn_epp = sse_op_table6[b].op[b1];
            if (!sse_fn_epp) {
                goto unknown_op;
            }
            if (!(s->cpuid_ext_features & sse_op_table6[b].ext_mask))
                goto illegal_op;

            if (b1) {
                op1_offset = offsetof(CPUX86State,xmm_regs[reg]);
                if (mod == 3) {
                    op2_offset = offsetof(CPUX86State,xmm_regs[rm | REX_B(s)]);
                } else {
                    op2_offset = offsetof(CPUX86State,xmm_t0);
                    gen_lea_modrm(env, s, modrm);
                    switch (b) {
                    case 0x20: case 0x30: /* pmovsxbw, pmovzxbw */
                    case 0x23: case 0x33: /* pmovsxwd, pmovzxwd */
                    case 0x25: case 0x35: /* pmovsxdq, pmovzxdq */
                        gen_ldq_env_A0(s, op2_offset +
                                        offsetof(ZMMReg, ZMM_Q(0)));
                        break;
                    case 0x21: case 0x31: /* pmovsxbd, pmovzxbd */
                    case 0x24: case 0x34: /* pmovsxwq, pmovzxwq */
                        tcg_gen_qemu_ld_i32(cpu_tmp2_i32, cpu_A0,
                                            s->mem_index, MO_LEUL);
                        tcg_gen_st_i32(cpu_tmp2_i32, cpu_env, op2_offset +
                                        offsetof(ZMMReg, ZMM_L(0)));
                        break;
                    case 0x22: case 0x32: /* pmovsxbq, pmovzxbq */
                        tcg_gen_qemu_ld_tl(cpu_tmp0, cpu_A0,
                                           s->mem_index, MO_LEUW);
                        tcg_gen_st16_tl(cpu_tmp0, cpu_env, op2_offset +
                                        offsetof(ZMMReg, ZMM_W(0)));
                        break;
                    case 0x2a:            /* movntqda */
                        gen_ldo_env_A0(s, op1_offset);
                        return;
                    default:
                        gen_ldo_env_A0(s, op2_offset);
                    }
                }
            } else {
                op1_offset = offsetof(CPUX86State,fpregs[reg].mmx);
                if (mod == 3) {
                    op2_offset = offsetof(CPUX86State,fpregs[rm].mmx);
                } else {
                    op2_offset = offsetof(CPUX86State,mmx_t0);
                    gen_lea_modrm(env, s, modrm);
                    gen_ldq_env_A0(s, op2_offset);
                }
            }
            if (sse_fn_epp == SSE_SPECIAL) {
                goto unknown_op;
            }

            tcg_gen_addi_ptr(cpu_ptr0, cpu_env, op1_offset);
            tcg_gen_addi_ptr(cpu_ptr1, cpu_env, op2_offset);
            sse_fn_epp(cpu_env, cpu_ptr0, cpu_ptr1);

            if (b == 0x17) {
                set_cc_op(s, CC_OP_EFLAGS);
            }
            break;

        case 0x238:
        case 0x338:
        do_0f_38_fx:
            /* Various integer extensions at 0f 38 f[0-f].  */
            b = modrm | (b1 << 8);
            modrm = x86_ldub_code(env, s);
            reg = ((modrm >> 3) & 7) | rex_r;

            switch (b) {
            case 0x3f0: /* crc32 Gd,Eb */
            case 0x3f1: /* crc32 Gd,Ey */
            do_crc32:
                if (!(s->cpuid_ext_features & CPUID_EXT_SSE42)) {
                    goto illegal_op;
                }
                if ((b & 0xff) == 0xf0) {
                    ot = MO_8;
                } else if (s->dflag != MO_64) {
                    ot = (s->prefix & PREFIX_DATA ? MO_16 : MO_32);
                } else {
                    ot = MO_64;
                }

                tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_regs[reg]);
                gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
                gen_helper_crc32(cpu_T0, cpu_tmp2_i32,
                                 cpu_T0, tcg_const_i32(8 << ot));

                ot = mo_64_32(s->dflag);
                gen_op_mov_reg_v(ot, reg, cpu_T0);
                break;

            case 0x1f0: /* crc32 or movbe */
            case 0x1f1:
                /* For these insns, the f3 prefix is supposed to have priority
                   over the 66 prefix, but that's not what we implement above
                   setting b1.  */
                if (s->prefix & PREFIX_REPNZ) {
                    goto do_crc32;
                }
                /* FALLTHRU */
            case 0x0f0: /* movbe Gy,My */
            case 0x0f1: /* movbe My,Gy */
                if (!(s->cpuid_ext_features & CPUID_EXT_MOVBE)) {
                    goto illegal_op;
                }
                if (s->dflag != MO_64) {
                    ot = (s->prefix & PREFIX_DATA ? MO_16 : MO_32);
                } else {
                    ot = MO_64;
                }

                gen_lea_modrm(env, s, modrm);
                if ((b & 1) == 0) {
                    tcg_gen_qemu_ld_tl(cpu_T0, cpu_A0,
                                       s->mem_index, (TCGMemOp)(ot | MO_BE));
                    gen_op_mov_reg_v(ot, reg, cpu_T0);
                } else {
                    tcg_gen_qemu_st_tl(cpu_regs[reg], cpu_A0,
                                       s->mem_index, (TCGMemOp)(ot | MO_BE));
                }
                break;

            case 0x0f2: /* andn Gy, By, Ey */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_BMI1)
                    || !(s->prefix & PREFIX_VEX)
                    || s->vex_l != 0) {
                    goto illegal_op;
                }
                ot = mo_64_32(s->dflag);
                gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
                tcg_gen_andc_tl(cpu_T0, cpu_regs[s->vex_v], cpu_T0);
                gen_op_mov_reg_v(ot, reg, cpu_T0);
                gen_op_update1_cc();
                set_cc_op(s, (CCOp)(CC_OP_LOGICB + ot));
                break;

            case 0x0f7: /* bextr Gy, Ey, By */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_BMI1)
                    || !(s->prefix & PREFIX_VEX)
                    || s->vex_l != 0) {
                    goto illegal_op;
                }
                ot = mo_64_32(s->dflag);
                {
                    TCGv bound, zero;

                    gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
                    /* Extract START, and shift the operand.
                       Shifts larger than operand size get zeros.  */
                    tcg_gen_ext8u_tl(cpu_A0, cpu_regs[s->vex_v]);
                    tcg_gen_shr_tl(cpu_T0, cpu_T0, cpu_A0);

                    bound = tcg_const_tl(ot == MO_64 ? 63 : 31);
                    zero = tcg_const_tl(0);
                    tcg_gen_movcond_tl(TCG_COND_LEU, cpu_T0, cpu_A0, bound,
                                       cpu_T0, zero);
                    tcg_temp_free(zero);

                    /* Extract the LEN into a mask.  Lengths larger than
                       operand size get all ones.  */
                    tcg_gen_extract_tl(cpu_A0, cpu_regs[s->vex_v], 8, 8);
                    tcg_gen_movcond_tl(TCG_COND_LEU, cpu_A0, cpu_A0, bound,
                                       cpu_A0, bound);
                    tcg_temp_free(bound);
                    tcg_gen_movi_tl(cpu_T1, 1);
                    tcg_gen_shl_tl(cpu_T1, cpu_T1, cpu_A0);
                    tcg_gen_subi_tl(cpu_T1, cpu_T1, 1);
                    tcg_gen_and_tl(cpu_T0, cpu_T0, cpu_T1);

                    gen_op_mov_reg_v(ot, reg, cpu_T0);
                    gen_op_update1_cc();
                    set_cc_op(s, (CCOp)(CC_OP_LOGICB + ot));
                }
                break;

            case 0x0f5: /* bzhi Gy, Ey, By */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_BMI2)
                    || !(s->prefix & PREFIX_VEX)
                    || s->vex_l != 0) {
                    goto illegal_op;
                }
                ot = mo_64_32(s->dflag);
                gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
                tcg_gen_ext8u_tl(cpu_T1, cpu_regs[s->vex_v]);
                {
                    TCGv bound = tcg_const_tl(ot == MO_64 ? 63 : 31);
                    /* Note that since we're using BMILG (in order to get O
                       cleared) we need to store the inverse into C.  */
                    tcg_gen_setcond_tl(TCG_COND_LT, cpu_cc_src,
                                       cpu_T1, bound);
                    tcg_gen_movcond_tl(TCG_COND_GT, cpu_T1, cpu_T1,
                                       bound, bound, cpu_T1);
                    tcg_temp_free(bound);
                }
                tcg_gen_movi_tl(cpu_A0, -1);
                tcg_gen_shl_tl(cpu_A0, cpu_A0, cpu_T1);
                tcg_gen_andc_tl(cpu_T0, cpu_T0, cpu_A0);
                gen_op_mov_reg_v(ot, reg, cpu_T0);
                gen_op_update1_cc();
                set_cc_op(s, (CCOp)(CC_OP_BMILGB + ot));
                break;

            case 0x3f6: /* mulx By, Gy, rdx, Ey */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_BMI2)
                    || !(s->prefix & PREFIX_VEX)
                    || s->vex_l != 0) {
                    goto illegal_op;
                }
                ot = mo_64_32(s->dflag);
                gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
                switch (ot) {
                default:
                    tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_T0);
                    tcg_gen_trunc_tl_i32(cpu_tmp3_i32, cpu_regs[R_EDX]);
                    tcg_gen_mulu2_i32(cpu_tmp2_i32, cpu_tmp3_i32,
                                      cpu_tmp2_i32, cpu_tmp3_i32);
                    tcg_gen_extu_i32_tl(cpu_regs[s->vex_v], cpu_tmp2_i32);
                    tcg_gen_extu_i32_tl(cpu_regs[reg], cpu_tmp3_i32);
                    break;
#ifdef TARGET_X86_64
                case MO_64:
                    tcg_gen_mulu2_i64(cpu_T0, cpu_T1,
                                      cpu_T0, cpu_regs[R_EDX]);
                    tcg_gen_mov_i64(cpu_regs[s->vex_v], cpu_T0);
                    tcg_gen_mov_i64(cpu_regs[reg], cpu_T1);
                    break;
#endif
                }
                break;

            case 0x3f5: /* pdep Gy, By, Ey */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_BMI2)
                    || !(s->prefix & PREFIX_VEX)
                    || s->vex_l != 0) {
                    goto illegal_op;
                }
                ot = mo_64_32(s->dflag);
                gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
                /* Note that by zero-extending the mask operand, we
                   automatically handle zero-extending the result.  */
                if (ot == MO_64) {
                    tcg_gen_mov_tl(cpu_T1, cpu_regs[s->vex_v]);
                } else {
                    tcg_gen_ext32u_tl(cpu_T1, cpu_regs[s->vex_v]);
                }
                gen_helper_pdep(cpu_regs[reg], cpu_T0, cpu_T1);
                break;

            case 0x2f5: /* pext Gy, By, Ey */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_BMI2)
                    || !(s->prefix & PREFIX_VEX)
                    || s->vex_l != 0) {
                    goto illegal_op;
                }
                ot = mo_64_32(s->dflag);
                gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
                /* Note that by zero-extending the mask operand, we
                   automatically handle zero-extending the result.  */
                if (ot == MO_64) {
                    tcg_gen_mov_tl(cpu_T1, cpu_regs[s->vex_v]);
                } else {
                    tcg_gen_ext32u_tl(cpu_T1, cpu_regs[s->vex_v]);
                }
                gen_helper_pext(cpu_regs[reg], cpu_T0, cpu_T1);
                break;

            case 0x1f6: /* adcx Gy, Ey */
            case 0x2f6: /* adox Gy, Ey */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_ADX)) {
                    goto illegal_op;
                } else {
                    TCGv carry_in, carry_out, zero;
                    int end_op;

                    ot = mo_64_32(s->dflag);
                    gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);

                    /* Re-use the carry-out from a previous round.  */
                    TCGV_UNUSED(carry_in);
                    carry_out = (b == 0x1f6 ? cpu_cc_dst : cpu_cc_src2);
                    switch (s->cc_op) {
                    case CC_OP_ADCX:
                        if (b == 0x1f6) {
                            carry_in = cpu_cc_dst;
                            end_op = CC_OP_ADCX;
                        } else {
                            end_op = CC_OP_ADCOX;
                        }
                        break;
                    case CC_OP_ADOX:
                        if (b == 0x1f6) {
                            end_op = CC_OP_ADCOX;
                        } else {
                            carry_in = cpu_cc_src2;
                            end_op = CC_OP_ADOX;
                        }
                        break;
                    case CC_OP_ADCOX:
                        end_op = CC_OP_ADCOX;
                        carry_in = carry_out;
                        break;
                    default:
                        end_op = (b == 0x1f6 ? CC_OP_ADCX : CC_OP_ADOX);
                        break;
                    }
                    /* If we can't reuse carry-out, get it out of EFLAGS.  */
                    if (TCGV_IS_UNUSED(carry_in)) {
                        if (s->cc_op != CC_OP_ADCX && s->cc_op != CC_OP_ADOX) {
                            gen_compute_eflags(s);
                        }
                        carry_in = cpu_tmp0;
                        tcg_gen_extract_tl(carry_in, cpu_cc_src,
                                           ctz32(b == 0x1f6 ? CC_C : CC_O), 1);
                    }

                    switch (ot) {
#ifdef TARGET_X86_64
                    case MO_32:
                        /* If we know TL is 64-bit, and we want a 32-bit
                           result, just do everything in 64-bit arithmetic.  */
                        tcg_gen_ext32u_i64(cpu_regs[reg], cpu_regs[reg]);
                        tcg_gen_ext32u_i64(cpu_T0, cpu_T0);
                        tcg_gen_add_i64(cpu_T0, cpu_T0, cpu_regs[reg]);
                        tcg_gen_add_i64(cpu_T0, cpu_T0, carry_in);
                        tcg_gen_ext32u_i64(cpu_regs[reg], cpu_T0);
                        tcg_gen_shri_i64(carry_out, cpu_T0, 32);
                        break;
#endif
                    default:
                        /* Otherwise compute the carry-out in two steps.  */
                        zero = tcg_const_tl(0);
                        tcg_gen_add2_tl(cpu_T0, carry_out,
                                        cpu_T0, zero,
                                        carry_in, zero);
                        tcg_gen_add2_tl(cpu_regs[reg], carry_out,
                                        cpu_regs[reg], carry_out,
                                        cpu_T0, zero);
                        tcg_temp_free(zero);
                        break;
                    }
                    set_cc_op(s, (CCOp)end_op);
                }
                break;

            case 0x1f7: /* shlx Gy, Ey, By */
            case 0x2f7: /* sarx Gy, Ey, By */
            case 0x3f7: /* shrx Gy, Ey, By */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_BMI2)
                    || !(s->prefix & PREFIX_VEX)
                    || s->vex_l != 0) {
                    goto illegal_op;
                }
                ot = mo_64_32(s->dflag);
                gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
                if (ot == MO_64) {
                    tcg_gen_andi_tl(cpu_T1, cpu_regs[s->vex_v], 63);
                } else {
                    tcg_gen_andi_tl(cpu_T1, cpu_regs[s->vex_v], 31);
                }
                if (b == 0x1f7) {
                    tcg_gen_shl_tl(cpu_T0, cpu_T0, cpu_T1);
                } else if (b == 0x2f7) {
                    if (ot != MO_64) {
                        tcg_gen_ext32s_tl(cpu_T0, cpu_T0);
                    }
                    tcg_gen_sar_tl(cpu_T0, cpu_T0, cpu_T1);
                } else {
                    if (ot != MO_64) {
                        tcg_gen_ext32u_tl(cpu_T0, cpu_T0);
                    }
                    tcg_gen_shr_tl(cpu_T0, cpu_T0, cpu_T1);
                }
                gen_op_mov_reg_v(ot, reg, cpu_T0);
                break;

            case 0x0f3:
            case 0x1f3:
            case 0x2f3:
            case 0x3f3: /* Group 17 */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_BMI1)
                    || !(s->prefix & PREFIX_VEX)
                    || s->vex_l != 0) {
                    goto illegal_op;
                }
                ot = mo_64_32(s->dflag);
                gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);

                switch (reg & 7) {
                case 1: /* blsr By,Ey */
                    tcg_gen_neg_tl(cpu_T1, cpu_T0);
                    tcg_gen_and_tl(cpu_T0, cpu_T0, cpu_T1);
                    gen_op_mov_reg_v(ot, s->vex_v, cpu_T0);
                    gen_op_update2_cc();
                    set_cc_op(s, (CCOp)(CC_OP_BMILGB + ot));
                    break;

                case 2: /* blsmsk By,Ey */
                    tcg_gen_mov_tl(cpu_cc_src, cpu_T0);
                    tcg_gen_subi_tl(cpu_T0, cpu_T0, 1);
                    tcg_gen_xor_tl(cpu_T0, cpu_T0, cpu_cc_src);
                    tcg_gen_mov_tl(cpu_cc_dst, cpu_T0);
                    set_cc_op(s, (CCOp)(CC_OP_BMILGB + ot));
                    break;

                case 3: /* blsi By, Ey */
                    tcg_gen_mov_tl(cpu_cc_src, cpu_T0);
                    tcg_gen_subi_tl(cpu_T0, cpu_T0, 1);
                    tcg_gen_and_tl(cpu_T0, cpu_T0, cpu_cc_src);
                    tcg_gen_mov_tl(cpu_cc_dst, cpu_T0);
                    set_cc_op(s, (CCOp)(CC_OP_BMILGB + ot));
                    break;

                default:
                    goto unknown_op;
                }
                break;

            default:
                goto unknown_op;
            }
            break;

        case 0x03a:
        case 0x13a:
            b = modrm;
            modrm = x86_ldub_code(env, s);
            rm = modrm & 7;
            reg = ((modrm >> 3) & 7) | rex_r;
            mod = (modrm >> 6) & 3;
            if (b1 >= 2) {
                goto unknown_op;
            }

            sse_fn_eppi = sse_op_table7[b].op[b1];
            if (!sse_fn_eppi) {
                goto unknown_op;
            }
            if (!(s->cpuid_ext_features & sse_op_table7[b].ext_mask))
                goto illegal_op;

            s->rip_offset = 1;

            if (sse_fn_eppi == SSE_SPECIAL) {
                ot = mo_64_32(s->dflag);
                rm = (modrm & 7) | REX_B(s);
                if (mod != 3)
                    gen_lea_modrm(env, s, modrm);
                reg = ((modrm >> 3) & 7) | rex_r;
                val = x86_ldub_code(env, s);
                switch (b) {
                case 0x14: /* pextrb */
                    tcg_gen_ld8u_tl(cpu_T0, cpu_env, offsetof(CPUX86State,
                                            xmm_regs[reg].ZMM_B(val & 15)));
                    if (mod == 3) {
                        gen_op_mov_reg_v(ot, rm, cpu_T0);
                    } else {
                        tcg_gen_qemu_st_tl(cpu_T0, cpu_A0,
                                           s->mem_index, MO_UB);
                    }
                    break;
                case 0x15: /* pextrw */
                    tcg_gen_ld16u_tl(cpu_T0, cpu_env, offsetof(CPUX86State,
                                            xmm_regs[reg].ZMM_W(val & 7)));
                    if (mod == 3) {
                        gen_op_mov_reg_v(ot, rm, cpu_T0);
                    } else {
                        tcg_gen_qemu_st_tl(cpu_T0, cpu_A0,
                                           s->mem_index, MO_LEUW);
                    }
                    break;
                case 0x16:
                    if (ot == MO_32) { /* pextrd */
                        tcg_gen_ld_i32(cpu_tmp2_i32, cpu_env,
                                        offsetof(CPUX86State,
                                                xmm_regs[reg].ZMM_L(val & 3)));
                        if (mod == 3) {
                            tcg_gen_extu_i32_tl(cpu_regs[rm], cpu_tmp2_i32);
                        } else {
                            tcg_gen_qemu_st_i32(cpu_tmp2_i32, cpu_A0,
                                                s->mem_index, MO_LEUL);
                        }
                    } else { /* pextrq */
#ifdef TARGET_X86_64
                        tcg_gen_ld_i64(cpu_tmp1_i64, cpu_env,
                                        offsetof(CPUX86State,
                                                xmm_regs[reg].ZMM_Q(val & 1)));
                        if (mod == 3) {
                            tcg_gen_mov_i64(cpu_regs[rm], cpu_tmp1_i64);
                        } else {
                            tcg_gen_qemu_st_i64(cpu_tmp1_i64, cpu_A0,
                                                s->mem_index, MO_LEQ);
                        }
#else
                        goto illegal_op;
#endif
                    }
                    break;
                case 0x17: /* extractps */
                    tcg_gen_ld32u_tl(cpu_T0, cpu_env, offsetof(CPUX86State,
                                            xmm_regs[reg].ZMM_L(val & 3)));
                    if (mod == 3) {
                        gen_op_mov_reg_v(ot, rm, cpu_T0);
                    } else {
                        tcg_gen_qemu_st_tl(cpu_T0, cpu_A0,
                                           s->mem_index, MO_LEUL);
                    }
                    break;
                case 0x20: /* pinsrb */
                    if (mod == 3) {
                        gen_op_mov_v_reg(MO_32, cpu_T0, rm);
                    } else {
                        tcg_gen_qemu_ld_tl(cpu_T0, cpu_A0,
                                           s->mem_index, MO_UB);
                    }
                    tcg_gen_st8_tl(cpu_T0, cpu_env, offsetof(CPUX86State,
                                            xmm_regs[reg].ZMM_B(val & 15)));
                    break;
                case 0x21: /* insertps */
                    if (mod == 3) {
                        tcg_gen_ld_i32(cpu_tmp2_i32, cpu_env,
                                        offsetof(CPUX86State,xmm_regs[rm]
                                                .ZMM_L((val >> 6) & 3)));
                    } else {
                        tcg_gen_qemu_ld_i32(cpu_tmp2_i32, cpu_A0,
                                            s->mem_index, MO_LEUL);
                    }
                    tcg_gen_st_i32(cpu_tmp2_i32, cpu_env,
                                    offsetof(CPUX86State,xmm_regs[reg]
                                            .ZMM_L((val >> 4) & 3)));
                    if ((val >> 0) & 1)
                        tcg_gen_st_i32(tcg_const_i32(0 /*float32_zero*/),
                                        cpu_env, offsetof(CPUX86State,
                                                xmm_regs[reg].ZMM_L(0)));
                    if ((val >> 1) & 1)
                        tcg_gen_st_i32(tcg_const_i32(0 /*float32_zero*/),
                                        cpu_env, offsetof(CPUX86State,
                                                xmm_regs[reg].ZMM_L(1)));
                    if ((val >> 2) & 1)
                        tcg_gen_st_i32(tcg_const_i32(0 /*float32_zero*/),
                                        cpu_env, offsetof(CPUX86State,
                                                xmm_regs[reg].ZMM_L(2)));
                    if ((val >> 3) & 1)
                        tcg_gen_st_i32(tcg_const_i32(0 /*float32_zero*/),
                                        cpu_env, offsetof(CPUX86State,
                                                xmm_regs[reg].ZMM_L(3)));
                    break;
                case 0x22:
                    if (ot == MO_32) { /* pinsrd */
                        if (mod == 3) {
                            tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_regs[rm]);
                        } else {
                            tcg_gen_qemu_ld_i32(cpu_tmp2_i32, cpu_A0,
                                                s->mem_index, MO_LEUL);
                        }
                        tcg_gen_st_i32(cpu_tmp2_i32, cpu_env,
                                        offsetof(CPUX86State,
                                                xmm_regs[reg].ZMM_L(val & 3)));
                    } else { /* pinsrq */
#ifdef TARGET_X86_64
                        if (mod == 3) {
                            gen_op_mov_v_reg(ot, cpu_tmp1_i64, rm);
                        } else {
                            tcg_gen_qemu_ld_i64(cpu_tmp1_i64, cpu_A0,
                                                s->mem_index, MO_LEQ);
                        }
                        tcg_gen_st_i64(cpu_tmp1_i64, cpu_env,
                                        offsetof(CPUX86State,
                                                xmm_regs[reg].ZMM_Q(val & 1)));
#else
                        goto illegal_op;
#endif
                    }
                    break;
                }
                return;
            }

            if (b1) {
                op1_offset = offsetof(CPUX86State,xmm_regs[reg]);
                if (mod == 3) {
                    op2_offset = offsetof(CPUX86State,xmm_regs[rm | REX_B(s)]);
                } else {
                    op2_offset = offsetof(CPUX86State,xmm_t0);
                    gen_lea_modrm(env, s, modrm);
                    gen_ldo_env_A0(s, op2_offset);
                }
            } else {
                op1_offset = offsetof(CPUX86State,fpregs[reg].mmx);
                if (mod == 3) {
                    op2_offset = offsetof(CPUX86State,fpregs[rm].mmx);
                } else {
                    op2_offset = offsetof(CPUX86State,mmx_t0);
                    gen_lea_modrm(env, s, modrm);
                    gen_ldq_env_A0(s, op2_offset);
                }
            }
            val = x86_ldub_code(env, s);

            if ((b & 0xfc) == 0x60) { /* pcmpXstrX */
                set_cc_op(s, CC_OP_EFLAGS);

                if (s->dflag == MO_64) {
                    /* The helper must use entire 64-bit gp registers */
                    val |= 1 << 8;
                }
            }

            tcg_gen_addi_ptr(cpu_ptr0, cpu_env, op1_offset);
            tcg_gen_addi_ptr(cpu_ptr1, cpu_env, op2_offset);
            sse_fn_eppi(cpu_env, cpu_ptr0, cpu_ptr1, tcg_const_i32(val));
            break;

        case 0x33a:
            /* Various integer extensions at 0f 3a f[0-f].  */
            b = modrm | (b1 << 8);
            modrm = x86_ldub_code(env, s);
            reg = ((modrm >> 3) & 7) | rex_r;

            switch (b) {
            case 0x3f0: /* rorx Gy,Ey, Ib */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_BMI2)
                    || !(s->prefix & PREFIX_VEX)
                    || s->vex_l != 0) {
                    goto illegal_op;
                }
                ot = mo_64_32(s->dflag);
                gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
                b = x86_ldub_code(env, s);
                if (ot == MO_64) {
                    tcg_gen_rotri_tl(cpu_T0, cpu_T0, b & 63);
                } else {
                    tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_T0);
                    tcg_gen_rotri_i32(cpu_tmp2_i32, cpu_tmp2_i32, b & 31);
                    tcg_gen_extu_i32_tl(cpu_T0, cpu_tmp2_i32);
                }
                gen_op_mov_reg_v(ot, reg, cpu_T0);
                break;

            default:
                goto unknown_op;
            }
            break;

        default:
        unknown_op:
            gen_unknown_opcode(env, s);
            return;
        }
    } else {
        /* generic MMX or SSE operation */
        switch(b) {
        case 0x70: /* pshufx insn */
        case 0xc6: /* pshufx insn */
        case 0xc2: /* compare insns */
            s->rip_offset = 1;
            break;
        default:
            break;
        }
        if (is_xmm) {
            op1_offset = offsetof(CPUX86State,xmm_regs[reg]);
            if (mod != 3) {
                int sz = 4;

                gen_lea_modrm(env, s, modrm);
                op2_offset = offsetof(CPUX86State,xmm_t0);

                switch (b) {
                case 0x50 ... 0x5a:
                case 0x5c ... 0x5f:
                case 0xc2:
                    /* Most sse scalar operations.  */
                    if (b1 == 2) {
                        sz = 2;
                    } else if (b1 == 3) {
                        sz = 3;
                    }
                    break;

                case 0x2e:  /* ucomis[sd] */
                case 0x2f:  /* comis[sd] */
                    if (b1 == 0) {
                        sz = 2;
                    } else {
                        sz = 3;
                    }
                    break;
                }

                switch (sz) {
                case 2:
                    /* 32 bit access */
                    gen_op_ld_v(s, MO_32, cpu_T0, cpu_A0);
                    tcg_gen_st32_tl(cpu_T0, cpu_env,
                                    offsetof(CPUX86State,xmm_t0.ZMM_L(0)));
                    break;
                case 3:
                    /* 64 bit access */
                    gen_ldq_env_A0(s, offsetof(CPUX86State, xmm_t0.ZMM_D(0)));
                    break;
                default:
                    /* 128 bit access */
                    gen_ldo_env_A0(s, op2_offset);
                    break;
                }
            } else {
                rm = (modrm & 7) | REX_B(s);
                op2_offset = offsetof(CPUX86State,xmm_regs[rm]);
            }
        } else {
            op1_offset = offsetof(CPUX86State,fpregs[reg].mmx);
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                op2_offset = offsetof(CPUX86State,mmx_t0);
                gen_ldq_env_A0(s, op2_offset);
            } else {
                rm = (modrm & 7);
                op2_offset = offsetof(CPUX86State,fpregs[rm].mmx);
            }
        }
        switch(b) {
        case 0x0f: /* 3DNow! data insns */
            val = x86_ldub_code(env, s);
            sse_fn_epp = sse_op_table5[val];
            if (!sse_fn_epp) {
                goto unknown_op;
            }
            if (!(s->cpuid_ext2_features & CPUID_EXT2_3DNOW)) {
                goto illegal_op;
            }
            tcg_gen_addi_ptr(cpu_ptr0, cpu_env, op1_offset);
            tcg_gen_addi_ptr(cpu_ptr1, cpu_env, op2_offset);
            sse_fn_epp(cpu_env, cpu_ptr0, cpu_ptr1);
            break;
        case 0x70: /* pshufx insn */
        case 0xc6: /* pshufx insn */
            val = x86_ldub_code(env, s);
            tcg_gen_addi_ptr(cpu_ptr0, cpu_env, op1_offset);
            tcg_gen_addi_ptr(cpu_ptr1, cpu_env, op2_offset);
            /* XXX: introduce a new table? */
            sse_fn_ppi = (SSEFunc_0_ppi)sse_fn_epp;
            sse_fn_ppi(cpu_ptr0, cpu_ptr1, tcg_const_i32(val));
            break;
        case 0xc2:
            /* compare insns */
            val = x86_ldub_code(env, s);
            if (val >= 8)
                goto unknown_op;
            sse_fn_epp = sse_op_table4[val][b1];

            tcg_gen_addi_ptr(cpu_ptr0, cpu_env, op1_offset);
            tcg_gen_addi_ptr(cpu_ptr1, cpu_env, op2_offset);
            sse_fn_epp(cpu_env, cpu_ptr0, cpu_ptr1);
            break;
        case 0xf7:
            /* maskmov : we must prepare A0 */
            if (mod != 3)
                goto illegal_op;
            tcg_gen_mov_tl(cpu_A0, cpu_regs[R_EDI]);
            gen_extu(s->aflag, cpu_A0);
            gen_add_A0_ds_seg(s);

            tcg_gen_addi_ptr(cpu_ptr0, cpu_env, op1_offset);
            tcg_gen_addi_ptr(cpu_ptr1, cpu_env, op2_offset);
            /* XXX: introduce a new table? */
            sse_fn_eppt = (SSEFunc_0_eppt)sse_fn_epp;
            sse_fn_eppt(cpu_env, cpu_ptr0, cpu_ptr1, cpu_A0);
            break;
        default:
            tcg_gen_addi_ptr(cpu_ptr0, cpu_env, op1_offset);
            tcg_gen_addi_ptr(cpu_ptr1, cpu_env, op2_offset);
            sse_fn_epp(cpu_env, cpu_ptr0, cpu_ptr1);
            break;
        }
        if (b == 0x2e || b == 0x2f) {
            set_cc_op(s, CC_OP_EFLAGS);
        }
    }
}

static target_ulong disas_insn(DisasContext *s, CPUState *cpu)
{
    CPUX86State *env = (CPUX86State *)cpu->env_ptr;
    int b, prefixes;
    int shift;
    TCGMemOp ot, aflag, dflag;
    int modrm, reg, rm, mod, op, opreg, val;
    target_ulong next_eip, tval;
    int rex_w, rex_r;
    target_ulong pc_start = s->base.pc_next;

    s->pc_start = s->pc = pc_start;
    prefixes = 0;
    s->override = -1;
    rex_w = -1;
    rex_r = 0;
#ifdef TARGET_X86_64
    s->rex_x = 0;
    s->rex_b = 0;
    x86_64_hregs = 0;
#endif
    s->rip_offset = 0; /* for relative ip address */
    s->vex_l = 0;
    s->vex_v = 0;
    if (sigsetjmp(s->jmpbuf, 0) != 0) {
        gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        return s->pc;
    }

 next_byte:
    b = x86_ldub_code(env, s);
    /* Collect prefixes.  */
    switch (b) {
    case 0xf3:
        prefixes |= PREFIX_REPZ;
        goto next_byte;
    case 0xf2:
        prefixes |= PREFIX_REPNZ;
        goto next_byte;
    case 0xf0:
        prefixes |= PREFIX_LOCK;
        goto next_byte;
    case 0x2e:
        s->override = R_CS;
        goto next_byte;
    case 0x36:
        s->override = R_SS;
        goto next_byte;
    case 0x3e:
        s->override = R_DS;
        goto next_byte;
    case 0x26:
        s->override = R_ES;
        goto next_byte;
    case 0x64:
        s->override = R_FS;
        goto next_byte;
    case 0x65:
        s->override = R_GS;
        goto next_byte;
    case 0x66:
        prefixes |= PREFIX_DATA;
        goto next_byte;
    case 0x67:
        prefixes |= PREFIX_ADR;
        goto next_byte;
#ifdef TARGET_X86_64
    case 0x40 ... 0x4f:
        if (CODE64(s)) {
            /* REX prefix */
            rex_w = (b >> 3) & 1;
            rex_r = (b & 0x4) << 1;
            s->rex_x = (b & 0x2) << 2;
            REX_B(s) = (b & 0x1) << 3;
            x86_64_hregs = 1; /* select uniform byte register addressing */
            goto next_byte;
        }
        break;
#endif
    case 0xc5: /* 2-byte VEX */
    case 0xc4: /* 3-byte VEX */
        /* VEX prefixes cannot be used except in 32-bit mode.
           Otherwise the instruction is LES or LDS.  */
        if (s->code32 && !s->vm86) {
            static const int pp_prefix[4] = {
                0, PREFIX_DATA, PREFIX_REPZ, PREFIX_REPNZ
            };
            int vex3, vex2 = x86_ldub_code(env, s);

            if (!CODE64(s) && (vex2 & 0xc0) != 0xc0) {
                /* 4.1.4.6: In 32-bit mode, bits [7:6] must be 11b,
                   otherwise the instruction is LES or LDS.  */
                s->pc--; /* rewind the advance_pc() x86_ldub_code() did */
                break;
            }

            /* 4.1.1-4.1.3: No preceding lock, 66, f2, f3, or rex prefixes. */
            if (prefixes & (PREFIX_REPZ | PREFIX_REPNZ
                            | PREFIX_LOCK | PREFIX_DATA)) {
                goto illegal_op;
            }
#ifdef TARGET_X86_64
            if (x86_64_hregs) {
                goto illegal_op;
            }
#endif
            rex_r = (~vex2 >> 4) & 8;
            if (b == 0xc5) {
                vex3 = vex2;
                b = x86_ldub_code(env, s);
            } else {
#ifdef TARGET_X86_64
                s->rex_x = (~vex2 >> 3) & 8;
                s->rex_b = (~vex2 >> 2) & 8;
#endif
                vex3 = x86_ldub_code(env, s);
                rex_w = (vex3 >> 7) & 1;
                switch (vex2 & 0x1f) {
                case 0x01: /* Implied 0f leading opcode bytes.  */
                    b = x86_ldub_code(env, s) | 0x100;
                    break;
                case 0x02: /* Implied 0f 38 leading opcode bytes.  */
                    b = 0x138;
                    break;
                case 0x03: /* Implied 0f 3a leading opcode bytes.  */
                    b = 0x13a;
                    break;
                default:   /* Reserved for future use.  */
                    goto unknown_op;
                }
            }
            s->vex_v = (~vex3 >> 3) & 0xf;
            s->vex_l = (vex3 >> 2) & 1;
            prefixes |= pp_prefix[vex3 & 3] | PREFIX_VEX;
        }
        break;
    }

    /* Post-process prefixes.  */
    if (CODE64(s)) {
        /* In 64-bit mode, the default data size is 32-bit.  Select 64-bit
           data with rex_w, and 16-bit data with 0x66; rex_w takes precedence
           over 0x66 if both are present.  */
        dflag = (rex_w > 0 ? MO_64 : prefixes & PREFIX_DATA ? MO_16 : MO_32);
        /* In 64-bit mode, 0x67 selects 32-bit addressing.  */
        aflag = (prefixes & PREFIX_ADR ? MO_32 : MO_64);
    } else {
        /* In 16/32-bit mode, 0x66 selects the opposite data size.  */
        if (s->code32 ^ ((prefixes & PREFIX_DATA) != 0)) {
            dflag = MO_32;
        } else {
            dflag = MO_16;
        }
        /* In 16/32-bit mode, 0x67 selects the opposite addressing.  */
        if (s->code32 ^ ((prefixes & PREFIX_ADR) != 0)) {
            aflag = MO_32;
        }  else {
            aflag = MO_16;
        }
    }

    s->prefix = prefixes;
    s->aflag = aflag;
    s->dflag = dflag;

    /* now check op code */
 reswitch:
    switch(b) {
    case 0x0f:
        /**************************/
        /* extended op code */
        b = x86_ldub_code(env, s) | 0x100;
        goto reswitch;

        /**************************/
        /* arith & logic */
    case 0x00 ... 0x05:
    case 0x08 ... 0x0d:
    case 0x10 ... 0x15:
    case 0x18 ... 0x1d:
    case 0x20 ... 0x25:
    case 0x28 ... 0x2d:
    case 0x30 ... 0x35:
    case 0x38 ... 0x3d:
        {
            int op, f, val;
            op = (b >> 3) & 7;
            f = (b >> 1) & 3;

            ot = mo_b_d(b, dflag);

            switch(f) {
            case 0: /* OP Ev, Gv */
                modrm = x86_ldub_code(env, s);
                reg = ((modrm >> 3) & 7) | rex_r;
                mod = (modrm >> 6) & 3;
                rm = (modrm & 7) | REX_B(s);
                if (mod != 3) {
                    gen_lea_modrm(env, s, modrm);
                    opreg = OR_TMP0;
                } else if (op == OP_XORL && rm == reg) {
                xor_zero:
                    /* xor reg, reg optimisation */
                    set_cc_op(s, CC_OP_CLR);
                    tcg_gen_movi_tl(cpu_T0, 0);
                    gen_op_mov_reg_v(ot, reg, cpu_T0);
                    break;
                } else {
                    opreg = rm;
                }
                gen_op_mov_v_reg(ot, cpu_T1, reg);
                gen_op(s, op, ot, opreg);
                break;
            case 1: /* OP Gv, Ev */
                modrm = x86_ldub_code(env, s);
                mod = (modrm >> 6) & 3;
                reg = ((modrm >> 3) & 7) | rex_r;
                rm = (modrm & 7) | REX_B(s);
                if (mod != 3) {
                    gen_lea_modrm(env, s, modrm);
                    gen_op_ld_v(s, ot, cpu_T1, cpu_A0);
                } else if (op == OP_XORL && rm == reg) {
                    goto xor_zero;
                } else {
                    gen_op_mov_v_reg(ot, cpu_T1, rm);
                }
                gen_op(s, op, ot, reg);
                break;
            case 2: /* OP A, Iv */
                val = insn_get(env, s, ot);
                tcg_gen_movi_tl(cpu_T1, val);
                gen_op(s, op, ot, OR_EAX);
                break;
            }
        }
        break;

    case 0x82:
        if (CODE64(s))
            goto illegal_op;
    case 0x80: /* GRP1 */
    case 0x81:
    case 0x83:
        {
            int val;

            ot = mo_b_d(b, dflag);

            modrm = x86_ldub_code(env, s);
            mod = (modrm >> 6) & 3;
            rm = (modrm & 7) | REX_B(s);
            op = (modrm >> 3) & 7;

            if (mod != 3) {
                if (b == 0x83)
                    s->rip_offset = 1;
                else
                    s->rip_offset = insn_const_size(ot);
                gen_lea_modrm(env, s, modrm);
                opreg = OR_TMP0;
            } else {
                opreg = rm;
            }

            switch(b) {
            default:
            case 0x80:
            case 0x81:
            case 0x82:
                val = insn_get(env, s, ot);
                break;
            case 0x83:
                val = (int8_t)insn_get(env, s, MO_8);
                break;
            }
            tcg_gen_movi_tl(cpu_T1, val);
            gen_op(s, op, ot, opreg);
        }
        break;

        /**************************/
        /* inc, dec, and other misc arith */
    case 0x40 ... 0x47: /* inc Gv */
        ot = dflag;
        gen_inc(s, ot, OR_EAX + (b & 7), 1);
        break;
    case 0x48 ... 0x4f: /* dec Gv */
        ot = dflag;
        gen_inc(s, ot, OR_EAX + (b & 7), -1);
        break;
    case 0xf6: /* GRP3 */
    case 0xf7:
        ot = mo_b_d(b, dflag);

        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        rm = (modrm & 7) | REX_B(s);
        op = (modrm >> 3) & 7;
        if (mod != 3) {
            if (op == 0) {
                s->rip_offset = insn_const_size(ot);
            }
            gen_lea_modrm(env, s, modrm);
            /* For those below that handle locked memory, don't load here.  */
            if (!(s->prefix & PREFIX_LOCK)
                || op != 2) {
                gen_op_ld_v(s, ot, cpu_T0, cpu_A0);
            }
        } else {
            gen_op_mov_v_reg(ot, cpu_T0, rm);
        }

        switch(op) {
        case 0: /* test */
            val = insn_get(env, s, ot);
            tcg_gen_movi_tl(cpu_T1, val);
            gen_op_testl_T0_T1_cc();
            set_cc_op(s, (CCOp)(CC_OP_LOGICB + ot));
            break;
        case 2: /* not */
            if (s->prefix & PREFIX_LOCK) {
                if (mod == 3) {
                    goto illegal_op;
                }
                tcg_gen_movi_tl(cpu_T0, ~0);
                tcg_gen_atomic_xor_fetch_tl(cpu_T0, cpu_A0, cpu_T0,
                                            s->mem_index, (TCGMemOp)(ot | MO_LE));
            } else {
                tcg_gen_not_tl(cpu_T0, cpu_T0);
                if (mod != 3) {
                    gen_op_st_v(s, ot, cpu_T0, cpu_A0);
                } else {
                    gen_op_mov_reg_v(ot, rm, cpu_T0);
                }
            }
            break;
        case 3: /* neg */
            if (s->prefix & PREFIX_LOCK) {
                TCGLabel *label1;
                TCGv a0, t0, t1, t2;

                if (mod == 3) {
                    goto illegal_op;
                }
                a0 = tcg_temp_local_new();
                t0 = tcg_temp_local_new();
                label1 = gen_new_label();

                tcg_gen_mov_tl(a0, cpu_A0);
                tcg_gen_mov_tl(t0, cpu_T0);

                gen_set_label(label1);
                t1 = tcg_temp_new();
                t2 = tcg_temp_new();
                tcg_gen_mov_tl(t2, t0);
                tcg_gen_neg_tl(t1, t0);
                tcg_gen_atomic_cmpxchg_tl(t0, a0, t0, t1,
                                          s->mem_index, (TCGMemOp)(ot | MO_LE));
                tcg_temp_free(t1);
                tcg_gen_brcond_tl(TCG_COND_NE, t0, t2, label1);

                tcg_temp_free(t2);
                tcg_temp_free(a0);
                tcg_gen_mov_tl(cpu_T0, t0);
                tcg_temp_free(t0);
            } else {
                tcg_gen_neg_tl(cpu_T0, cpu_T0);
                if (mod != 3) {
                    gen_op_st_v(s, ot, cpu_T0, cpu_A0);
                } else {
                    gen_op_mov_reg_v(ot, rm, cpu_T0);
                }
            }
            gen_op_update_neg_cc();
            set_cc_op(s, (CCOp)(CC_OP_SUBB + ot));
            break;
        case 4: /* mul */
            switch(ot) {
            case MO_8:
                gen_op_mov_v_reg(MO_8, cpu_T1, R_EAX);
                tcg_gen_ext8u_tl(cpu_T0, cpu_T0);
                tcg_gen_ext8u_tl(cpu_T1, cpu_T1);
                /* XXX: use 32 bit mul which could be faster */
                tcg_gen_mul_tl(cpu_T0, cpu_T0, cpu_T1);
                gen_op_mov_reg_v(MO_16, R_EAX, cpu_T0);
                tcg_gen_mov_tl(cpu_cc_dst, cpu_T0);
                tcg_gen_andi_tl(cpu_cc_src, cpu_T0, 0xff00);
                set_cc_op(s, CC_OP_MULB);
                break;
            case MO_16:
                gen_op_mov_v_reg(MO_16, cpu_T1, R_EAX);
                tcg_gen_ext16u_tl(cpu_T0, cpu_T0);
                tcg_gen_ext16u_tl(cpu_T1, cpu_T1);
                /* XXX: use 32 bit mul which could be faster */
                tcg_gen_mul_tl(cpu_T0, cpu_T0, cpu_T1);
                gen_op_mov_reg_v(MO_16, R_EAX, cpu_T0);
                tcg_gen_mov_tl(cpu_cc_dst, cpu_T0);
                tcg_gen_shri_tl(cpu_T0, cpu_T0, 16);
                gen_op_mov_reg_v(MO_16, R_EDX, cpu_T0);
                tcg_gen_mov_tl(cpu_cc_src, cpu_T0);
                set_cc_op(s, CC_OP_MULW);
                break;
            default:
            case MO_32:
                tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_T0);
                tcg_gen_trunc_tl_i32(cpu_tmp3_i32, cpu_regs[R_EAX]);
                tcg_gen_mulu2_i32(cpu_tmp2_i32, cpu_tmp3_i32,
                                  cpu_tmp2_i32, cpu_tmp3_i32);
                tcg_gen_extu_i32_tl(cpu_regs[R_EAX], cpu_tmp2_i32);
                tcg_gen_extu_i32_tl(cpu_regs[R_EDX], cpu_tmp3_i32);
                tcg_gen_mov_tl(cpu_cc_dst, cpu_regs[R_EAX]);
                tcg_gen_mov_tl(cpu_cc_src, cpu_regs[R_EDX]);
                set_cc_op(s, CC_OP_MULL);
                break;
#ifdef TARGET_X86_64
            case MO_64:
                tcg_gen_mulu2_i64(cpu_regs[R_EAX], cpu_regs[R_EDX],
                                  cpu_T0, cpu_regs[R_EAX]);
                tcg_gen_mov_tl(cpu_cc_dst, cpu_regs[R_EAX]);
                tcg_gen_mov_tl(cpu_cc_src, cpu_regs[R_EDX]);
                set_cc_op(s, CC_OP_MULQ);
                break;
#endif
            }
            break;
        case 5: /* imul */
            switch(ot) {
            case MO_8:
                gen_op_mov_v_reg(MO_8, cpu_T1, R_EAX);
                tcg_gen_ext8s_tl(cpu_T0, cpu_T0);
                tcg_gen_ext8s_tl(cpu_T1, cpu_T1);
                /* XXX: use 32 bit mul which could be faster */
                tcg_gen_mul_tl(cpu_T0, cpu_T0, cpu_T1);
                gen_op_mov_reg_v(MO_16, R_EAX, cpu_T0);
                tcg_gen_mov_tl(cpu_cc_dst, cpu_T0);
                tcg_gen_ext8s_tl(cpu_tmp0, cpu_T0);
                tcg_gen_sub_tl(cpu_cc_src, cpu_T0, cpu_tmp0);
                set_cc_op(s, CC_OP_MULB);
                break;
            case MO_16:
                gen_op_mov_v_reg(MO_16, cpu_T1, R_EAX);
                tcg_gen_ext16s_tl(cpu_T0, cpu_T0);
                tcg_gen_ext16s_tl(cpu_T1, cpu_T1);
                /* XXX: use 32 bit mul which could be faster */
                tcg_gen_mul_tl(cpu_T0, cpu_T0, cpu_T1);
                gen_op_mov_reg_v(MO_16, R_EAX, cpu_T0);
                tcg_gen_mov_tl(cpu_cc_dst, cpu_T0);
                tcg_gen_ext16s_tl(cpu_tmp0, cpu_T0);
                tcg_gen_sub_tl(cpu_cc_src, cpu_T0, cpu_tmp0);
                tcg_gen_shri_tl(cpu_T0, cpu_T0, 16);
                gen_op_mov_reg_v(MO_16, R_EDX, cpu_T0);
                set_cc_op(s, CC_OP_MULW);
                break;
            default:
            case MO_32:
                tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_T0);
                tcg_gen_trunc_tl_i32(cpu_tmp3_i32, cpu_regs[R_EAX]);
                tcg_gen_muls2_i32(cpu_tmp2_i32, cpu_tmp3_i32,
                                  cpu_tmp2_i32, cpu_tmp3_i32);
                tcg_gen_extu_i32_tl(cpu_regs[R_EAX], cpu_tmp2_i32);
                tcg_gen_extu_i32_tl(cpu_regs[R_EDX], cpu_tmp3_i32);
                tcg_gen_sari_i32(cpu_tmp2_i32, cpu_tmp2_i32, 31);
                tcg_gen_mov_tl(cpu_cc_dst, cpu_regs[R_EAX]);
                tcg_gen_sub_i32(cpu_tmp2_i32, cpu_tmp2_i32, cpu_tmp3_i32);
                tcg_gen_extu_i32_tl(cpu_cc_src, cpu_tmp2_i32);
                set_cc_op(s, CC_OP_MULL);
                break;
#ifdef TARGET_X86_64
            case MO_64:
                tcg_gen_muls2_i64(cpu_regs[R_EAX], cpu_regs[R_EDX],
                                  cpu_T0, cpu_regs[R_EAX]);
                tcg_gen_mov_tl(cpu_cc_dst, cpu_regs[R_EAX]);
                tcg_gen_sari_tl(cpu_cc_src, cpu_regs[R_EAX], 63);
                tcg_gen_sub_tl(cpu_cc_src, cpu_cc_src, cpu_regs[R_EDX]);
                set_cc_op(s, CC_OP_MULQ);
                break;
#endif
            }
            break;
        case 6: /* div */
            switch(ot) {
            case MO_8:
                gen_helper_divb_AL(cpu_env, cpu_T0);
                break;
            case MO_16:
                gen_helper_divw_AX(cpu_env, cpu_T0);
                break;
            default:
            case MO_32:
                gen_helper_divl_EAX(cpu_env, cpu_T0);
                break;
#ifdef TARGET_X86_64
            case MO_64:
                gen_helper_divq_EAX(cpu_env, cpu_T0);
                break;
#endif
            }
            break;
        case 7: /* idiv */
            switch(ot) {
            case MO_8:
                gen_helper_idivb_AL(cpu_env, cpu_T0);
                break;
            case MO_16:
                gen_helper_idivw_AX(cpu_env, cpu_T0);
                break;
            default:
            case MO_32:
                gen_helper_idivl_EAX(cpu_env, cpu_T0);
                break;
#ifdef TARGET_X86_64
            case MO_64:
                gen_helper_idivq_EAX(cpu_env, cpu_T0);
                break;
#endif
            }
            break;
        default:
            goto unknown_op;
        }
        break;

    case 0xfe: /* GRP4 */
    case 0xff: /* GRP5 */
        ot = mo_b_d(b, dflag);

        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        rm = (modrm & 7) | REX_B(s);
        op = (modrm >> 3) & 7;
        if (op >= 2 && b == 0xfe) {
            goto unknown_op;
        }
        if (CODE64(s)) {
            if (op == 2 || op == 4) {
                /* operand size for jumps is 64 bit */
                ot = MO_64;
            } else if (op == 3 || op == 5) {
                ot = (TCGMemOp)(dflag != MO_16 ? MO_32 + (rex_w == 1) : MO_16);
            } else if (op == 6) {
                /* default push size is 64 bit */
                ot = mo_pushpop(s, dflag);
            }
        }
        if (mod != 3) {
            gen_lea_modrm(env, s, modrm);
            if (op >= 2 && op != 3 && op != 5)
                gen_op_ld_v(s, ot, cpu_T0, cpu_A0);
        } else {
            gen_op_mov_v_reg(ot, cpu_T0, rm);
        }

        switch(op) {
        case 0: /* inc Ev */
            if (mod != 3)
                opreg = OR_TMP0;
            else
                opreg = rm;
            gen_inc(s, ot, opreg, 1);
            break;
        case 1: /* dec Ev */
            if (mod != 3)
                opreg = OR_TMP0;
            else
                opreg = rm;
            gen_inc(s, ot, opreg, -1);
            break;
        case 2: /* call Ev */
            /* XXX: optimize if memory (no 'and' is necessary) */
            if (dflag == MO_16) {
                tcg_gen_ext16u_tl(cpu_T0, cpu_T0);
            }
            next_eip = s->pc - s->cs_base;
            tcg_gen_movi_tl(cpu_T1, next_eip);
            gen_push_v(s, cpu_T1);
            gen_op_jmp_v(cpu_T0);
            gen_bnd_jmp(s);
            gen_jr(s, cpu_T0);
            break;
        case 3: /* lcall Ev */
            gen_op_ld_v(s, ot, cpu_T1, cpu_A0);
            gen_add_A0_im(s, 1 << ot);
            gen_op_ld_v(s, MO_16, cpu_T0, cpu_A0);
        do_lcall:
            if (s->pe && !s->vm86) {
                tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_T0);
                gen_helper_lcall_protected(cpu_env, cpu_tmp2_i32, cpu_T1,
                                           tcg_const_i32(dflag - 1),
                                           tcg_const_tl(s->pc - s->cs_base));
            } else {
                tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_T0);
                gen_helper_lcall_real(cpu_env, cpu_tmp2_i32, cpu_T1,
                                      tcg_const_i32(dflag - 1),
                                      tcg_const_i32(s->pc - s->cs_base));
            }
            tcg_gen_ld_tl(cpu_tmp4, cpu_env, offsetof(CPUX86State, eip));
            gen_jr(s, cpu_tmp4);
            break;
        case 4: /* jmp Ev */
            if (dflag == MO_16) {
                tcg_gen_ext16u_tl(cpu_T0, cpu_T0);
            }
            gen_op_jmp_v(cpu_T0);
            gen_bnd_jmp(s);
            gen_jr(s, cpu_T0);
            break;
        case 5: /* ljmp Ev */
            gen_op_ld_v(s, ot, cpu_T1, cpu_A0);
            gen_add_A0_im(s, 1 << ot);
            gen_op_ld_v(s, MO_16, cpu_T0, cpu_A0);
        do_ljmp:
            if (s->pe && !s->vm86) {
                tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_T0);
                gen_helper_ljmp_protected(cpu_env, cpu_tmp2_i32, cpu_T1,
                                          tcg_const_tl(s->pc - s->cs_base));
            } else {
                gen_op_movl_seg_T0_vm(R_CS);
                gen_op_jmp_v(cpu_T1);
            }
            tcg_gen_ld_tl(cpu_tmp4, cpu_env, offsetof(CPUX86State, eip));
            gen_jr(s, cpu_tmp4);
            break;
        case 6: /* push Ev */
            gen_push_v(s, cpu_T0);
            break;
        default:
            goto unknown_op;
        }
        break;

    case 0x84: /* test Ev, Gv */
    case 0x85:
        ot = mo_b_d(b, dflag);

        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;

        gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
        gen_op_mov_v_reg(ot, cpu_T1, reg);
        gen_op_testl_T0_T1_cc();
        set_cc_op(s, (CCOp)(CC_OP_LOGICB + ot));
        break;

    case 0xa8: /* test eAX, Iv */
    case 0xa9:
        ot = mo_b_d(b, dflag);
        val = insn_get(env, s, ot);

        gen_op_mov_v_reg(ot, cpu_T0, OR_EAX);
        tcg_gen_movi_tl(cpu_T1, val);
        gen_op_testl_T0_T1_cc();
        set_cc_op(s, (CCOp)(CC_OP_LOGICB + ot));
        break;

    case 0x98: /* CWDE/CBW */
        switch (dflag) {
#ifdef TARGET_X86_64
        case MO_64:
            gen_op_mov_v_reg(MO_32, cpu_T0, R_EAX);
            tcg_gen_ext32s_tl(cpu_T0, cpu_T0);
            gen_op_mov_reg_v(MO_64, R_EAX, cpu_T0);
            break;
#endif
        case MO_32:
            gen_op_mov_v_reg(MO_16, cpu_T0, R_EAX);
            tcg_gen_ext16s_tl(cpu_T0, cpu_T0);
            gen_op_mov_reg_v(MO_32, R_EAX, cpu_T0);
            break;
        case MO_16:
            gen_op_mov_v_reg(MO_8, cpu_T0, R_EAX);
            tcg_gen_ext8s_tl(cpu_T0, cpu_T0);
            gen_op_mov_reg_v(MO_16, R_EAX, cpu_T0);
            break;
        default:
            tcg_abort();
        }
        break;
    case 0x99: /* CDQ/CWD */
        switch (dflag) {
#ifdef TARGET_X86_64
        case MO_64:
            gen_op_mov_v_reg(MO_64, cpu_T0, R_EAX);
            tcg_gen_sari_tl(cpu_T0, cpu_T0, 63);
            gen_op_mov_reg_v(MO_64, R_EDX, cpu_T0);
            break;
#endif
        case MO_32:
            gen_op_mov_v_reg(MO_32, cpu_T0, R_EAX);
            tcg_gen_ext32s_tl(cpu_T0, cpu_T0);
            tcg_gen_sari_tl(cpu_T0, cpu_T0, 31);
            gen_op_mov_reg_v(MO_32, R_EDX, cpu_T0);
            break;
        case MO_16:
            gen_op_mov_v_reg(MO_16, cpu_T0, R_EAX);
            tcg_gen_ext16s_tl(cpu_T0, cpu_T0);
            tcg_gen_sari_tl(cpu_T0, cpu_T0, 15);
            gen_op_mov_reg_v(MO_16, R_EDX, cpu_T0);
            break;
        default:
            tcg_abort();
        }
        break;
    case 0x1af: /* imul Gv, Ev */
    case 0x69: /* imul Gv, Ev, I */
    case 0x6b:
        ot = dflag;
        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;
        if (b == 0x69)
            s->rip_offset = insn_const_size(ot);
        else if (b == 0x6b)
            s->rip_offset = 1;
        gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
        if (b == 0x69) {
            val = insn_get(env, s, ot);
            tcg_gen_movi_tl(cpu_T1, val);
        } else if (b == 0x6b) {
            val = (int8_t)insn_get(env, s, MO_8);
            tcg_gen_movi_tl(cpu_T1, val);
        } else {
            gen_op_mov_v_reg(ot, cpu_T1, reg);
        }
        switch (ot) {
#ifdef TARGET_X86_64
        case MO_64:
            tcg_gen_muls2_i64(cpu_regs[reg], cpu_T1, cpu_T0, cpu_T1);
            tcg_gen_mov_tl(cpu_cc_dst, cpu_regs[reg]);
            tcg_gen_sari_tl(cpu_cc_src, cpu_cc_dst, 63);
            tcg_gen_sub_tl(cpu_cc_src, cpu_cc_src, cpu_T1);
            break;
#endif
        case MO_32:
            tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_T0);
            tcg_gen_trunc_tl_i32(cpu_tmp3_i32, cpu_T1);
            tcg_gen_muls2_i32(cpu_tmp2_i32, cpu_tmp3_i32,
                              cpu_tmp2_i32, cpu_tmp3_i32);
            tcg_gen_extu_i32_tl(cpu_regs[reg], cpu_tmp2_i32);
            tcg_gen_sari_i32(cpu_tmp2_i32, cpu_tmp2_i32, 31);
            tcg_gen_mov_tl(cpu_cc_dst, cpu_regs[reg]);
            tcg_gen_sub_i32(cpu_tmp2_i32, cpu_tmp2_i32, cpu_tmp3_i32);
            tcg_gen_extu_i32_tl(cpu_cc_src, cpu_tmp2_i32);
            break;
        default:
            tcg_gen_ext16s_tl(cpu_T0, cpu_T0);
            tcg_gen_ext16s_tl(cpu_T1, cpu_T1);
            /* XXX: use 32 bit mul which could be faster */
            tcg_gen_mul_tl(cpu_T0, cpu_T0, cpu_T1);
            tcg_gen_mov_tl(cpu_cc_dst, cpu_T0);
            tcg_gen_ext16s_tl(cpu_tmp0, cpu_T0);
            tcg_gen_sub_tl(cpu_cc_src, cpu_T0, cpu_tmp0);
            gen_op_mov_reg_v(ot, reg, cpu_T0);
            break;
        }
        set_cc_op(s, (CCOp)(CC_OP_MULB + ot));
        break;
    case 0x1c0:
    case 0x1c1: /* xadd Ev, Gv */
        ot = mo_b_d(b, dflag);
        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;
        mod = (modrm >> 6) & 3;
        gen_op_mov_v_reg(ot, cpu_T0, reg);
        if (mod == 3) {
            rm = (modrm & 7) | REX_B(s);
            gen_op_mov_v_reg(ot, cpu_T1, rm);
            tcg_gen_add_tl(cpu_T0, cpu_T0, cpu_T1);
            gen_op_mov_reg_v(ot, reg, cpu_T1);
            gen_op_mov_reg_v(ot, rm, cpu_T0);
        } else {
            gen_lea_modrm(env, s, modrm);
            if (s->prefix & PREFIX_LOCK) {
                tcg_gen_atomic_fetch_add_tl(cpu_T1, cpu_A0, cpu_T0,
                                            s->mem_index, (TCGMemOp)(ot | MO_LE));
                tcg_gen_add_tl(cpu_T0, cpu_T0, cpu_T1);
            } else {
                gen_op_ld_v(s, ot, cpu_T1, cpu_A0);
                tcg_gen_add_tl(cpu_T0, cpu_T0, cpu_T1);
                gen_op_st_v(s, ot, cpu_T0, cpu_A0);
            }
            gen_op_mov_reg_v(ot, reg, cpu_T1);
        }
        gen_op_update2_cc();
        set_cc_op(s, (CCOp)(CC_OP_ADDB + ot));
        break;
    case 0x1b0:
    case 0x1b1: /* cmpxchg Ev, Gv */
        {
            TCGv oldv, newv, cmpv;

            ot = mo_b_d(b, dflag);
            modrm = x86_ldub_code(env, s);
            reg = ((modrm >> 3) & 7) | rex_r;
            mod = (modrm >> 6) & 3;
            oldv = tcg_temp_new();
            newv = tcg_temp_new();
            cmpv = tcg_temp_new();
            gen_op_mov_v_reg(ot, newv, reg);
            tcg_gen_mov_tl(cmpv, cpu_regs[R_EAX]);

            if (s->prefix & PREFIX_LOCK) {
                if (mod == 3) {
                    goto illegal_op;
                }
                gen_lea_modrm(env, s, modrm);
                tcg_gen_atomic_cmpxchg_tl(oldv, cpu_A0, cmpv, newv,
                                          s->mem_index, (TCGMemOp)(ot | MO_LE));
                gen_op_mov_reg_v(ot, R_EAX, oldv);
            } else {
                if (mod == 3) {
                    rm = (modrm & 7) | REX_B(s);
                    gen_op_mov_v_reg(ot, oldv, rm);
                } else {
                    gen_lea_modrm(env, s, modrm);
                    gen_op_ld_v(s, ot, oldv, cpu_A0);
                    rm = 0; /* avoid warning */
                }
                gen_extu(ot, oldv);
                gen_extu(ot, cmpv);
                /* store value = (old == cmp ? new : old);  */
                tcg_gen_movcond_tl(TCG_COND_EQ, newv, oldv, cmpv, newv, oldv);
                if (mod == 3) {
                    gen_op_mov_reg_v(ot, R_EAX, oldv);
                    gen_op_mov_reg_v(ot, rm, newv);
                } else {
                    /* Perform an unconditional store cycle like physical cpu;
                       must be before changing accumulator to ensure
                       idempotency if the store faults and the instruction
                       is restarted */
                    gen_op_st_v(s, ot, newv, cpu_A0);
                    gen_op_mov_reg_v(ot, R_EAX, oldv);
                }
            }
            tcg_gen_mov_tl(cpu_cc_src, oldv);
            tcg_gen_mov_tl(cpu_cc_srcT, cmpv);
            tcg_gen_sub_tl(cpu_cc_dst, cmpv, oldv);
            set_cc_op(s, (CCOp)(CC_OP_SUBB + ot));
            tcg_temp_free(oldv);
            tcg_temp_free(newv);
            tcg_temp_free(cmpv);
        }
        break;
    case 0x1c7: /* cmpxchg8b */
        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        if ((mod == 3) || ((modrm & 0x38) != 0x8))
            goto illegal_op;
#ifdef TARGET_X86_64
        if (dflag == MO_64) {
            if (!(s->cpuid_ext_features & CPUID_EXT_CX16))
                goto illegal_op;
            gen_lea_modrm(env, s, modrm);
            if ((s->prefix & PREFIX_LOCK) && (tb_cflags(s->base.tb) & CF_PARALLEL)) {
                gen_helper_cmpxchg16b(cpu_env, cpu_A0);
            } else {
                gen_helper_cmpxchg16b_unlocked(cpu_env, cpu_A0);
            }
        } else
#endif        
        {
            if (!(s->cpuid_features & CPUID_CX8))
                goto illegal_op;
            gen_lea_modrm(env, s, modrm);
            if ((s->prefix & PREFIX_LOCK) && (tb_cflags(s->base.tb) & CF_PARALLEL)) {
                gen_helper_cmpxchg8b(cpu_env, cpu_A0);
            } else {
                gen_helper_cmpxchg8b_unlocked(cpu_env, cpu_A0);
            }
        }
        set_cc_op(s, CC_OP_EFLAGS);
        break;

        /**************************/
        /* push/pop */
    case 0x50 ... 0x57: /* push */
        gen_op_mov_v_reg(MO_32, cpu_T0, (b & 7) | REX_B(s));
        gen_push_v(s, cpu_T0);
        break;
    case 0x58 ... 0x5f: /* pop */
        ot = gen_pop_T0(s);
        /* NOTE: order is important for pop %sp */
        gen_pop_update(s, ot);
        gen_op_mov_reg_v(ot, (b & 7) | REX_B(s), cpu_T0);
        break;
    case 0x60: /* pusha */
        if (CODE64(s))
            goto illegal_op;
        gen_pusha(s);
        break;
    case 0x61: /* popa */
        if (CODE64(s))
            goto illegal_op;
        gen_popa(s);
        break;
    case 0x68: /* push Iv */
    case 0x6a:
        ot = mo_pushpop(s, dflag);
        if (b == 0x68)
            val = insn_get(env, s, ot);
        else
            val = (int8_t)insn_get(env, s, MO_8);
        tcg_gen_movi_tl(cpu_T0, val);
        gen_push_v(s, cpu_T0);
        break;
    case 0x8f: /* pop Ev */
        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        ot = gen_pop_T0(s);
        if (mod == 3) {
            /* NOTE: order is important for pop %sp */
            gen_pop_update(s, ot);
            rm = (modrm & 7) | REX_B(s);
            gen_op_mov_reg_v(ot, rm, cpu_T0);
        } else {
            /* NOTE: order is important too for MMU exceptions */
            s->popl_esp_hack = 1 << ot;
            gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 1);
            s->popl_esp_hack = 0;
            gen_pop_update(s, ot);
        }
        break;
    case 0xc8: /* enter */
        {
            int level;
            val = x86_lduw_code(env, s);
            level = x86_ldub_code(env, s);
            gen_enter(s, val, level);
        }
        break;
    case 0xc9: /* leave */
        gen_leave(s);
        break;
    case 0x06: /* push es */
    case 0x0e: /* push cs */
    case 0x16: /* push ss */
    case 0x1e: /* push ds */
        if (CODE64(s))
            goto illegal_op;
        gen_op_movl_T0_seg(b >> 3);
        gen_push_v(s, cpu_T0);
        break;
    case 0x1a0: /* push fs */
    case 0x1a8: /* push gs */
        gen_op_movl_T0_seg((b >> 3) & 7);
        gen_push_v(s, cpu_T0);
        break;
    case 0x07: /* pop es */
    case 0x17: /* pop ss */
    case 0x1f: /* pop ds */
        if (CODE64(s))
            goto illegal_op;
        reg = b >> 3;
        ot = gen_pop_T0(s);
        gen_movl_seg_T0(s, reg);
        gen_pop_update(s, ot);
        /* Note that reg == R_SS in gen_movl_seg_T0 always sets is_jmp.  */
        if (s->base.is_jmp) {
            gen_jmp_im(s->pc - s->cs_base);
            if (reg == R_SS) {
                s->tf = 0;
                gen_eob_inhibit_irq(s, true);
            } else {
                gen_eob(s);
            }
        }
        break;
    case 0x1a1: /* pop fs */
    case 0x1a9: /* pop gs */
        ot = gen_pop_T0(s);
        gen_movl_seg_T0(s, (b >> 3) & 7);
        gen_pop_update(s, ot);
        if (s->base.is_jmp) {
            gen_jmp_im(s->pc - s->cs_base);
            gen_eob(s);
        }
        break;

        /**************************/
        /* mov */
    case 0x88:
    case 0x89: /* mov Gv, Ev */
        ot = mo_b_d(b, dflag);
        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;

        /* generate a generic store */
        gen_ldst_modrm(env, s, modrm, ot, reg, 1);
        break;
    case 0xc6:
    case 0xc7: /* mov Ev, Iv */
        ot = mo_b_d(b, dflag);
        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        if (mod != 3) {
            s->rip_offset = insn_const_size(ot);
            gen_lea_modrm(env, s, modrm);
        }
        val = insn_get(env, s, ot);
        tcg_gen_movi_tl(cpu_T0, val);
        if (mod != 3) {
            gen_op_st_v(s, ot, cpu_T0, cpu_A0);
        } else {
            gen_op_mov_reg_v(ot, (modrm & 7) | REX_B(s), cpu_T0);
        }
        break;
    case 0x8a:
    case 0x8b: /* mov Ev, Gv */
        ot = mo_b_d(b, dflag);
        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;

        gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
        gen_op_mov_reg_v(ot, reg, cpu_T0);
        break;
    case 0x8e: /* mov seg, Gv */
        modrm = x86_ldub_code(env, s);
        reg = (modrm >> 3) & 7;
        if (reg >= 6 || reg == R_CS)
            goto illegal_op;
        gen_ldst_modrm(env, s, modrm, MO_16, OR_TMP0, 0);
        gen_movl_seg_T0(s, reg);
        /* Note that reg == R_SS in gen_movl_seg_T0 always sets is_jmp.  */
        if (s->base.is_jmp) {
            gen_jmp_im(s->pc - s->cs_base);
            if (reg == R_SS) {
                s->tf = 0;
                gen_eob_inhibit_irq(s, true);
            } else {
                gen_eob(s);
            }
        }
        break;
    case 0x8c: /* mov Gv, seg */
        modrm = x86_ldub_code(env, s);
        reg = (modrm >> 3) & 7;
        mod = (modrm >> 6) & 3;
        if (reg >= 6)
            goto illegal_op;
        gen_op_movl_T0_seg(reg);
        ot = mod == 3 ? dflag : MO_16;
        gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 1);
        break;

    case 0x1b6: /* movzbS Gv, Eb */
    case 0x1b7: /* movzwS Gv, Eb */
    case 0x1be: /* movsbS Gv, Eb */
    case 0x1bf: /* movswS Gv, Eb */
        {
            TCGMemOp d_ot;
            TCGMemOp s_ot;

            /* d_ot is the size of destination */
            d_ot = dflag;
            /* ot is the size of source */
            ot = (TCGMemOp)((b & 1) + MO_8);
            /* s_ot is the sign+size of source */
            s_ot = (TCGMemOp)(b & 8 ? MO_SIGN | ot : ot);

            modrm = x86_ldub_code(env, s);
            reg = ((modrm >> 3) & 7) | rex_r;
            mod = (modrm >> 6) & 3;
            rm = (modrm & 7) | REX_B(s);

            if (mod == 3) {
                if (s_ot == MO_SB && byte_reg_is_xH(rm)) {
                    tcg_gen_sextract_tl(cpu_T0, cpu_regs[rm - 4], 8, 8);
                } else {
                    gen_op_mov_v_reg(ot, cpu_T0, rm);
                    switch (s_ot) {
                    case MO_UB:
                        tcg_gen_ext8u_tl(cpu_T0, cpu_T0);
                        break;
                    case MO_SB:
                        tcg_gen_ext8s_tl(cpu_T0, cpu_T0);
                        break;
                    case MO_UW:
                        tcg_gen_ext16u_tl(cpu_T0, cpu_T0);
                        break;
                    default:
                    case MO_SW:
                        tcg_gen_ext16s_tl(cpu_T0, cpu_T0);
                        break;
                    }
                }
                gen_op_mov_reg_v(d_ot, reg, cpu_T0);
            } else {
                gen_lea_modrm(env, s, modrm);
                gen_op_ld_v(s, s_ot, cpu_T0, cpu_A0);
                gen_op_mov_reg_v(d_ot, reg, cpu_T0);
            }
        }
        break;

    case 0x8d: /* lea */
        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        if (mod == 3)
            goto illegal_op;
        reg = ((modrm >> 3) & 7) | rex_r;
        {
            AddressParts a = gen_lea_modrm_0(env, s, modrm);
            TCGv ea = gen_lea_modrm_1(a);
            gen_lea_v_seg(s, s->aflag, ea, -1, -1);
            gen_op_mov_reg_v(dflag, reg, cpu_A0);
        }
        break;

    case 0xa0: /* mov EAX, Ov */
    case 0xa1:
    case 0xa2: /* mov Ov, EAX */
    case 0xa3:
        {
            target_ulong offset_addr;

            ot = mo_b_d(b, dflag);
            switch (s->aflag) {
#ifdef TARGET_X86_64
            case MO_64:
                offset_addr = x86_ldq_code(env, s);
                break;
#endif
            default:
                offset_addr = insn_get(env, s, s->aflag);
                break;
            }
            tcg_gen_movi_tl(cpu_A0, offset_addr);
            gen_add_A0_ds_seg(s);
            if ((b & 2) == 0) {
                gen_op_ld_v(s, ot, cpu_T0, cpu_A0);
                gen_op_mov_reg_v(ot, R_EAX, cpu_T0);
            } else {
                gen_op_mov_v_reg(ot, cpu_T0, R_EAX);
                gen_op_st_v(s, ot, cpu_T0, cpu_A0);
            }
        }
        break;
    case 0xd7: /* xlat */
        tcg_gen_mov_tl(cpu_A0, cpu_regs[R_EBX]);
        tcg_gen_ext8u_tl(cpu_T0, cpu_regs[R_EAX]);
        tcg_gen_add_tl(cpu_A0, cpu_A0, cpu_T0);
        gen_extu(s->aflag, cpu_A0);
        gen_add_A0_ds_seg(s);
        gen_op_ld_v(s, MO_8, cpu_T0, cpu_A0);
        gen_op_mov_reg_v(MO_8, R_EAX, cpu_T0);
        break;
    case 0xb0 ... 0xb7: /* mov R, Ib */
        val = insn_get(env, s, MO_8);
        tcg_gen_movi_tl(cpu_T0, val);
        gen_op_mov_reg_v(MO_8, (b & 7) | REX_B(s), cpu_T0);
        break;
    case 0xb8 ... 0xbf: /* mov R, Iv */
#ifdef TARGET_X86_64
        if (dflag == MO_64) {
            uint64_t tmp;
            /* 64 bit case */
            tmp = x86_ldq_code(env, s);
            reg = (b & 7) | REX_B(s);
            tcg_gen_movi_tl(cpu_T0, tmp);
            gen_op_mov_reg_v(MO_64, reg, cpu_T0);
        } else
#endif
        {
            ot = dflag;
            val = insn_get(env, s, ot);
            reg = (b & 7) | REX_B(s);
            tcg_gen_movi_tl(cpu_T0, val);
            gen_op_mov_reg_v(ot, reg, cpu_T0);
        }
        break;

    case 0x91 ... 0x97: /* xchg R, EAX */
    do_xchg_reg_eax:
        ot = dflag;
        reg = (b & 7) | REX_B(s);
        rm = R_EAX;
        goto do_xchg_reg;
    case 0x86:
    case 0x87: /* xchg Ev, Gv */
        ot = mo_b_d(b, dflag);
        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;
        mod = (modrm >> 6) & 3;
        if (mod == 3) {
            rm = (modrm & 7) | REX_B(s);
        do_xchg_reg:
            gen_op_mov_v_reg(ot, cpu_T0, reg);
            gen_op_mov_v_reg(ot, cpu_T1, rm);
            gen_op_mov_reg_v(ot, rm, cpu_T0);
            gen_op_mov_reg_v(ot, reg, cpu_T1);
        } else {
            gen_lea_modrm(env, s, modrm);
            gen_op_mov_v_reg(ot, cpu_T0, reg);
            /* for xchg, lock is implicit */
            tcg_gen_atomic_xchg_tl(cpu_T1, cpu_A0, cpu_T0,
                                   s->mem_index, (TCGMemOp)(ot | MO_LE));
            gen_op_mov_reg_v(ot, reg, cpu_T1);
        }
        break;
    case 0xc4: /* les Gv */
        /* In CODE64 this is VEX3; see above.  */
        op = R_ES;
        goto do_lxx;
    case 0xc5: /* lds Gv */
        /* In CODE64 this is VEX2; see above.  */
        op = R_DS;
        goto do_lxx;
    case 0x1b2: /* lss Gv */
        op = R_SS;
        goto do_lxx;
    case 0x1b4: /* lfs Gv */
        op = R_FS;
        goto do_lxx;
    case 0x1b5: /* lgs Gv */
        op = R_GS;
    do_lxx:
        ot = dflag != MO_16 ? MO_32 : MO_16;
        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;
        mod = (modrm >> 6) & 3;
        if (mod == 3)
            goto illegal_op;
        gen_lea_modrm(env, s, modrm);
        gen_op_ld_v(s, ot, cpu_T1, cpu_A0);
        gen_add_A0_im(s, 1 << ot);
        /* load the segment first to handle exceptions properly */
        gen_op_ld_v(s, MO_16, cpu_T0, cpu_A0);
        gen_movl_seg_T0(s, op);
        /* then put the data */
        gen_op_mov_reg_v(ot, reg, cpu_T1);
        if (s->base.is_jmp) {
            gen_jmp_im(s->pc - s->cs_base);
            gen_eob(s);
        }
        break;

        /************************/
        /* shifts */
    case 0xc0:
    case 0xc1:
        /* shift Ev,Ib */
        shift = 2;
    grp2:
        {
            ot = mo_b_d(b, dflag);
            modrm = x86_ldub_code(env, s);
            mod = (modrm >> 6) & 3;
            op = (modrm >> 3) & 7;

            if (mod != 3) {
                if (shift == 2) {
                    s->rip_offset = 1;
                }
                gen_lea_modrm(env, s, modrm);
                opreg = OR_TMP0;
            } else {
                opreg = (modrm & 7) | REX_B(s);
            }

            /* simpler op */
            if (shift == 0) {
                gen_shift(s, op, ot, opreg, OR_ECX);
            } else {
                if (shift == 2) {
                    shift = x86_ldub_code(env, s);
                }
                gen_shifti(s, op, ot, opreg, shift);
            }
        }
        break;
    case 0xd0:
    case 0xd1:
        /* shift Ev,1 */
        shift = 1;
        goto grp2;
    case 0xd2:
    case 0xd3:
        /* shift Ev,cl */
        shift = 0;
        goto grp2;

    case 0x1a4: /* shld imm */
        op = 0;
        shift = 1;
        goto do_shiftd;
    case 0x1a5: /* shld cl */
        op = 0;
        shift = 0;
        goto do_shiftd;
    case 0x1ac: /* shrd imm */
        op = 1;
        shift = 1;
        goto do_shiftd;
    case 0x1ad: /* shrd cl */
        op = 1;
        shift = 0;
    do_shiftd:
        ot = dflag;
        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        rm = (modrm & 7) | REX_B(s);
        reg = ((modrm >> 3) & 7) | rex_r;
        if (mod != 3) {
            gen_lea_modrm(env, s, modrm);
            opreg = OR_TMP0;
        } else {
            opreg = rm;
        }
        gen_op_mov_v_reg(ot, cpu_T1, reg);

        if (shift) {
            TCGv imm = tcg_const_tl(x86_ldub_code(env, s));
            gen_shiftd_rm_T1(s, ot, opreg, op, imm);
            tcg_temp_free(imm);
        } else {
            gen_shiftd_rm_T1(s, ot, opreg, op, cpu_regs[R_ECX]);
        }
        break;

        /************************/
        /* floats */
    case 0xd8 ... 0xdf:
        if (s->flags & (HF_EM_MASK | HF_TS_MASK)) {
            /* if CR0.EM or CR0.TS are set, generate an FPU exception */
            /* XXX: what to do if illegal op ? */
            gen_exception(s, EXCP07_PREX, pc_start - s->cs_base);
            break;
        }
        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        rm = modrm & 7;
        op = ((b & 7) << 3) | ((modrm >> 3) & 7);
        if (mod != 3) {
            /* memory op */
            gen_lea_modrm(env, s, modrm);
            switch(op) {
            case 0x00 ... 0x07: /* fxxxs */
            case 0x10 ... 0x17: /* fixxxl */
            case 0x20 ... 0x27: /* fxxxl */
            case 0x30 ... 0x37: /* fixxx */
                {
                    int op1;
                    op1 = op & 7;

                    switch(op >> 4) {
                    case 0:
                        tcg_gen_qemu_ld_i32(cpu_tmp2_i32, cpu_A0,
                                            s->mem_index, MO_LEUL);
                        gen_helper_flds_FT0(cpu_env, cpu_tmp2_i32);
                        break;
                    case 1:
                        tcg_gen_qemu_ld_i32(cpu_tmp2_i32, cpu_A0,
                                            s->mem_index, MO_LEUL);
                        gen_helper_fildl_FT0(cpu_env, cpu_tmp2_i32);
                        break;
                    case 2:
                        tcg_gen_qemu_ld_i64(cpu_tmp1_i64, cpu_A0,
                                            s->mem_index, MO_LEQ);
                        gen_helper_fldl_FT0(cpu_env, cpu_tmp1_i64);
                        break;
                    case 3:
                    default:
                        tcg_gen_qemu_ld_i32(cpu_tmp2_i32, cpu_A0,
                                            s->mem_index, MO_LESW);
                        gen_helper_fildl_FT0(cpu_env, cpu_tmp2_i32);
                        break;
                    }

                    gen_helper_fp_arith_ST0_FT0(op1);
                    if (op1 == 3) {
                        /* fcomp needs pop */
                        gen_helper_fpop(cpu_env);
                    }
                }
                break;
            case 0x08: /* flds */
            case 0x0a: /* fsts */
            case 0x0b: /* fstps */
            case 0x18 ... 0x1b: /* fildl, fisttpl, fistl, fistpl */
            case 0x28 ... 0x2b: /* fldl, fisttpll, fstl, fstpl */
            case 0x38 ... 0x3b: /* filds, fisttps, fists, fistps */
                switch(op & 7) {
                case 0:
                    switch(op >> 4) {
                    case 0:
                        tcg_gen_qemu_ld_i32(cpu_tmp2_i32, cpu_A0,
                                            s->mem_index, MO_LEUL);
                        gen_helper_flds_ST0(cpu_env, cpu_tmp2_i32);
                        break;
                    case 1:
                        tcg_gen_qemu_ld_i32(cpu_tmp2_i32, cpu_A0,
                                            s->mem_index, MO_LEUL);
                        gen_helper_fildl_ST0(cpu_env, cpu_tmp2_i32);
                        break;
                    case 2:
                        tcg_gen_qemu_ld_i64(cpu_tmp1_i64, cpu_A0,
                                            s->mem_index, MO_LEQ);
                        gen_helper_fldl_ST0(cpu_env, cpu_tmp1_i64);
                        break;
                    case 3:
                    default:
                        tcg_gen_qemu_ld_i32(cpu_tmp2_i32, cpu_A0,
                                            s->mem_index, MO_LESW);
                        gen_helper_fildl_ST0(cpu_env, cpu_tmp2_i32);
                        break;
                    }
                    break;
                case 1:
                    /* XXX: the corresponding CPUID bit must be tested ! */
                    switch(op >> 4) {
                    case 1:
                        gen_helper_fisttl_ST0(cpu_tmp2_i32, cpu_env);
                        tcg_gen_qemu_st_i32(cpu_tmp2_i32, cpu_A0,
                                            s->mem_index, MO_LEUL);
                        break;
                    case 2:
                        gen_helper_fisttll_ST0(cpu_tmp1_i64, cpu_env);
                        tcg_gen_qemu_st_i64(cpu_tmp1_i64, cpu_A0,
                                            s->mem_index, MO_LEQ);
                        break;
                    case 3:
                    default:
                        gen_helper_fistt_ST0(cpu_tmp2_i32, cpu_env);
                        tcg_gen_qemu_st_i32(cpu_tmp2_i32, cpu_A0,
                                            s->mem_index, MO_LEUW);
                        break;
                    }
                    gen_helper_fpop(cpu_env);
                    break;
                default:
                    switch(op >> 4) {
                    case 0:
                        gen_helper_fsts_ST0(cpu_tmp2_i32, cpu_env);
                        tcg_gen_qemu_st_i32(cpu_tmp2_i32, cpu_A0,
                                            s->mem_index, MO_LEUL);
                        break;
                    case 1:
                        gen_helper_fistl_ST0(cpu_tmp2_i32, cpu_env);
                        tcg_gen_qemu_st_i32(cpu_tmp2_i32, cpu_A0,
                                            s->mem_index, MO_LEUL);
                        break;
                    case 2:
                        gen_helper_fstl_ST0(cpu_tmp1_i64, cpu_env);
                        tcg_gen_qemu_st_i64(cpu_tmp1_i64, cpu_A0,
                                            s->mem_index, MO_LEQ);
                        break;
                    case 3:
                    default:
                        gen_helper_fist_ST0(cpu_tmp2_i32, cpu_env);
                        tcg_gen_qemu_st_i32(cpu_tmp2_i32, cpu_A0,
                                            s->mem_index, MO_LEUW);
                        break;
                    }
                    if ((op & 7) == 3)
                        gen_helper_fpop(cpu_env);
                    break;
                }
                break;
            case 0x0c: /* fldenv mem */
                gen_helper_fldenv(cpu_env, cpu_A0, tcg_const_i32(dflag - 1));
                break;
            case 0x0d: /* fldcw mem */
                tcg_gen_qemu_ld_i32(cpu_tmp2_i32, cpu_A0,
                                    s->mem_index, MO_LEUW);
                gen_helper_fldcw(cpu_env, cpu_tmp2_i32);
                break;
            case 0x0e: /* fnstenv mem */
                gen_helper_fstenv(cpu_env, cpu_A0, tcg_const_i32(dflag - 1));
                break;
            case 0x0f: /* fnstcw mem */
                gen_helper_fnstcw(cpu_tmp2_i32, cpu_env);
                tcg_gen_qemu_st_i32(cpu_tmp2_i32, cpu_A0,
                                    s->mem_index, MO_LEUW);
                break;
            case 0x1d: /* fldt mem */
                gen_helper_fldt_ST0(cpu_env, cpu_A0);
                break;
            case 0x1f: /* fstpt mem */
                gen_helper_fstt_ST0(cpu_env, cpu_A0);
                gen_helper_fpop(cpu_env);
                break;
            case 0x2c: /* frstor mem */
                gen_helper_frstor(cpu_env, cpu_A0, tcg_const_i32(dflag - 1));
                break;
            case 0x2e: /* fnsave mem */
                gen_helper_fsave(cpu_env, cpu_A0, tcg_const_i32(dflag - 1));
                break;
            case 0x2f: /* fnstsw mem */
                gen_helper_fnstsw(cpu_tmp2_i32, cpu_env);
                tcg_gen_qemu_st_i32(cpu_tmp2_i32, cpu_A0,
                                    s->mem_index, MO_LEUW);
                break;
            case 0x3c: /* fbld */
                gen_helper_fbld_ST0(cpu_env, cpu_A0);
                break;
            case 0x3e: /* fbstp */
                gen_helper_fbst_ST0(cpu_env, cpu_A0);
                gen_helper_fpop(cpu_env);
                break;
            case 0x3d: /* fildll */
                tcg_gen_qemu_ld_i64(cpu_tmp1_i64, cpu_A0, s->mem_index, MO_LEQ);
                gen_helper_fildll_ST0(cpu_env, cpu_tmp1_i64);
                break;
            case 0x3f: /* fistpll */
                gen_helper_fistll_ST0(cpu_tmp1_i64, cpu_env);
                tcg_gen_qemu_st_i64(cpu_tmp1_i64, cpu_A0, s->mem_index, MO_LEQ);
                gen_helper_fpop(cpu_env);
                break;
            default:
                goto unknown_op;
            }
        } else {
            /* register float ops */
            opreg = rm;

            switch(op) {
            case 0x08: /* fld sti */
                gen_helper_fpush(cpu_env);
                gen_helper_fmov_ST0_STN(cpu_env,
                                        tcg_const_i32((opreg + 1) & 7));
                break;
            case 0x09: /* fxchg sti */
            case 0x29: /* fxchg4 sti, undocumented op */
            case 0x39: /* fxchg7 sti, undocumented op */
                gen_helper_fxchg_ST0_STN(cpu_env, tcg_const_i32(opreg));
                break;
            case 0x0a: /* grp d9/2 */
                switch(rm) {
                case 0: /* fnop */
                    /* check exceptions (FreeBSD FPU probe) */
                    gen_helper_fwait(cpu_env);
                    break;
                default:
                    goto unknown_op;
                }
                break;
            case 0x0c: /* grp d9/4 */
                switch(rm) {
                case 0: /* fchs */
                    gen_helper_fchs_ST0(cpu_env);
                    break;
                case 1: /* fabs */
                    gen_helper_fabs_ST0(cpu_env);
                    break;
                case 4: /* ftst */
                    gen_helper_fldz_FT0(cpu_env);
                    gen_helper_fcom_ST0_FT0(cpu_env);
                    break;
                case 5: /* fxam */
                    gen_helper_fxam_ST0(cpu_env);
                    break;
                default:
                    goto unknown_op;
                }
                break;
            case 0x0d: /* grp d9/5 */
                {
                    switch(rm) {
                    case 0:
                        gen_helper_fpush(cpu_env);
                        gen_helper_fld1_ST0(cpu_env);
                        break;
                    case 1:
                        gen_helper_fpush(cpu_env);
                        gen_helper_fldl2t_ST0(cpu_env);
                        break;
                    case 2:
                        gen_helper_fpush(cpu_env);
                        gen_helper_fldl2e_ST0(cpu_env);
                        break;
                    case 3:
                        gen_helper_fpush(cpu_env);
                        gen_helper_fldpi_ST0(cpu_env);
                        break;
                    case 4:
                        gen_helper_fpush(cpu_env);
                        gen_helper_fldlg2_ST0(cpu_env);
                        break;
                    case 5:
                        gen_helper_fpush(cpu_env);
                        gen_helper_fldln2_ST0(cpu_env);
                        break;
                    case 6:
                        gen_helper_fpush(cpu_env);
                        gen_helper_fldz_ST0(cpu_env);
                        break;
                    default:
                        goto unknown_op;
                    }
                }
                break;
            case 0x0e: /* grp d9/6 */
                switch(rm) {
                case 0: /* f2xm1 */
                    gen_helper_f2xm1(cpu_env);
                    break;
                case 1: /* fyl2x */
                    gen_helper_fyl2x(cpu_env);
                    break;
                case 2: /* fptan */
                    gen_helper_fptan(cpu_env);
                    break;
                case 3: /* fpatan */
                    gen_helper_fpatan(cpu_env);
                    break;
                case 4: /* fxtract */
                    gen_helper_fxtract(cpu_env);
                    break;
                case 5: /* fprem1 */
                    gen_helper_fprem1(cpu_env);
                    break;
                case 6: /* fdecstp */
                    gen_helper_fdecstp(cpu_env);
                    break;
                default:
                case 7: /* fincstp */
                    gen_helper_fincstp(cpu_env);
                    break;
                }
                break;
            case 0x0f: /* grp d9/7 */
                switch(rm) {
                case 0: /* fprem */
                    gen_helper_fprem(cpu_env);
                    break;
                case 1: /* fyl2xp1 */
                    gen_helper_fyl2xp1(cpu_env);
                    break;
                case 2: /* fsqrt */
                    gen_helper_fsqrt(cpu_env);
                    break;
                case 3: /* fsincos */
                    gen_helper_fsincos(cpu_env);
                    break;
                case 5: /* fscale */
                    gen_helper_fscale(cpu_env);
                    break;
                case 4: /* frndint */
                    gen_helper_frndint(cpu_env);
                    break;
                case 6: /* fsin */
                    gen_helper_fsin(cpu_env);
                    break;
                default:
                case 7: /* fcos */
                    gen_helper_fcos(cpu_env);
                    break;
                }
                break;
            case 0x00: case 0x01: case 0x04 ... 0x07: /* fxxx st, sti */
            case 0x20: case 0x21: case 0x24 ... 0x27: /* fxxx sti, st */
            case 0x30: case 0x31: case 0x34 ... 0x37: /* fxxxp sti, st */
                {
                    int op1;

                    op1 = op & 7;
                    if (op >= 0x20) {
                        gen_helper_fp_arith_STN_ST0(op1, opreg);
                        if (op >= 0x30)
                            gen_helper_fpop(cpu_env);
                    } else {
                        gen_helper_fmov_FT0_STN(cpu_env, tcg_const_i32(opreg));
                        gen_helper_fp_arith_ST0_FT0(op1);
                    }
                }
                break;
            case 0x02: /* fcom */
            case 0x22: /* fcom2, undocumented op */
                gen_helper_fmov_FT0_STN(cpu_env, tcg_const_i32(opreg));
                gen_helper_fcom_ST0_FT0(cpu_env);
                break;
            case 0x03: /* fcomp */
            case 0x23: /* fcomp3, undocumented op */
            case 0x32: /* fcomp5, undocumented op */
                gen_helper_fmov_FT0_STN(cpu_env, tcg_const_i32(opreg));
                gen_helper_fcom_ST0_FT0(cpu_env);
                gen_helper_fpop(cpu_env);
                break;
            case 0x15: /* da/5 */
                switch(rm) {
                case 1: /* fucompp */
                    gen_helper_fmov_FT0_STN(cpu_env, tcg_const_i32(1));
                    gen_helper_fucom_ST0_FT0(cpu_env);
                    gen_helper_fpop(cpu_env);
                    gen_helper_fpop(cpu_env);
                    break;
                default:
                    goto unknown_op;
                }
                break;
            case 0x1c:
                switch(rm) {
                case 0: /* feni (287 only, just do nop here) */
                    break;
                case 1: /* fdisi (287 only, just do nop here) */
                    break;
                case 2: /* fclex */
                    gen_helper_fclex(cpu_env);
                    break;
                case 3: /* fninit */
                    gen_helper_fninit(cpu_env);
                    break;
                case 4: /* fsetpm (287 only, just do nop here) */
                    break;
                default:
                    goto unknown_op;
                }
                break;
            case 0x1d: /* fucomi */
                if (!(s->cpuid_features & CPUID_CMOV)) {
                    goto illegal_op;
                }
                gen_update_cc_op(s);
                gen_helper_fmov_FT0_STN(cpu_env, tcg_const_i32(opreg));
                gen_helper_fucomi_ST0_FT0(cpu_env);
                set_cc_op(s, CC_OP_EFLAGS);
                break;
            case 0x1e: /* fcomi */
                if (!(s->cpuid_features & CPUID_CMOV)) {
                    goto illegal_op;
                }
                gen_update_cc_op(s);
                gen_helper_fmov_FT0_STN(cpu_env, tcg_const_i32(opreg));
                gen_helper_fcomi_ST0_FT0(cpu_env);
                set_cc_op(s, CC_OP_EFLAGS);
                break;
            case 0x28: /* ffree sti */
                gen_helper_ffree_STN(cpu_env, tcg_const_i32(opreg));
                break;
            case 0x2a: /* fst sti */
                gen_helper_fmov_STN_ST0(cpu_env, tcg_const_i32(opreg));
                break;
            case 0x2b: /* fstp sti */
            case 0x0b: /* fstp1 sti, undocumented op */
            case 0x3a: /* fstp8 sti, undocumented op */
            case 0x3b: /* fstp9 sti, undocumented op */
                gen_helper_fmov_STN_ST0(cpu_env, tcg_const_i32(opreg));
                gen_helper_fpop(cpu_env);
                break;
            case 0x2c: /* fucom st(i) */
                gen_helper_fmov_FT0_STN(cpu_env, tcg_const_i32(opreg));
                gen_helper_fucom_ST0_FT0(cpu_env);
                break;
            case 0x2d: /* fucomp st(i) */
                gen_helper_fmov_FT0_STN(cpu_env, tcg_const_i32(opreg));
                gen_helper_fucom_ST0_FT0(cpu_env);
                gen_helper_fpop(cpu_env);
                break;
            case 0x33: /* de/3 */
                switch(rm) {
                case 1: /* fcompp */
                    gen_helper_fmov_FT0_STN(cpu_env, tcg_const_i32(1));
                    gen_helper_fcom_ST0_FT0(cpu_env);
                    gen_helper_fpop(cpu_env);
                    gen_helper_fpop(cpu_env);
                    break;
                default:
                    goto unknown_op;
                }
                break;
            case 0x38: /* ffreep sti, undocumented op */
                gen_helper_ffree_STN(cpu_env, tcg_const_i32(opreg));
                gen_helper_fpop(cpu_env);
                break;
            case 0x3c: /* df/4 */
                switch(rm) {
                case 0:
                    gen_helper_fnstsw(cpu_tmp2_i32, cpu_env);
                    tcg_gen_extu_i32_tl(cpu_T0, cpu_tmp2_i32);
                    gen_op_mov_reg_v(MO_16, R_EAX, cpu_T0);
                    break;
                default:
                    goto unknown_op;
                }
                break;
            case 0x3d: /* fucomip */
                if (!(s->cpuid_features & CPUID_CMOV)) {
                    goto illegal_op;
                }
                gen_update_cc_op(s);
                gen_helper_fmov_FT0_STN(cpu_env, tcg_const_i32(opreg));
                gen_helper_fucomi_ST0_FT0(cpu_env);
                gen_helper_fpop(cpu_env);
                set_cc_op(s, CC_OP_EFLAGS);
                break;
            case 0x3e: /* fcomip */
                if (!(s->cpuid_features & CPUID_CMOV)) {
                    goto illegal_op;
                }
                gen_update_cc_op(s);
                gen_helper_fmov_FT0_STN(cpu_env, tcg_const_i32(opreg));
                gen_helper_fcomi_ST0_FT0(cpu_env);
                gen_helper_fpop(cpu_env);
                set_cc_op(s, CC_OP_EFLAGS);
                break;
            case 0x10 ... 0x13: /* fcmovxx */
            case 0x18 ... 0x1b:
                {
                    int op1;
                    TCGLabel *l1;
                    static const uint8_t fcmov_cc[8] = {
                        (JCC_B << 1),
                        (JCC_Z << 1),
                        (JCC_BE << 1),
                        (JCC_P << 1),
                    };

                    if (!(s->cpuid_features & CPUID_CMOV)) {
                        goto illegal_op;
                    }
                    op1 = fcmov_cc[op & 3] | (((op >> 3) & 1) ^ 1);
                    l1 = gen_new_label();
                    gen_jcc1_noeob(s, op1, l1);
                    gen_helper_fmov_ST0_STN(cpu_env, tcg_const_i32(opreg));
                    gen_set_label(l1);
                }
                break;
            default:
                goto unknown_op;
            }
        }
        break;
        /************************/
        /* string ops */

    case 0xa4: /* movsS */
    case 0xa5:
        ot = mo_b_d(b, dflag);
        if (prefixes & (PREFIX_REPZ | PREFIX_REPNZ)) {
            gen_repz_movs(s, ot, pc_start - s->cs_base, s->pc - s->cs_base);
        } else {
            gen_movs(s, ot);
        }
        break;

    case 0xaa: /* stosS */
    case 0xab:
        ot = mo_b_d(b, dflag);
        if (prefixes & (PREFIX_REPZ | PREFIX_REPNZ)) {
            gen_repz_stos(s, ot, pc_start - s->cs_base, s->pc - s->cs_base);
        } else {
            gen_stos(s, ot);
        }
        break;
    case 0xac: /* lodsS */
    case 0xad:
        ot = mo_b_d(b, dflag);
        if (prefixes & (PREFIX_REPZ | PREFIX_REPNZ)) {
            gen_repz_lods(s, ot, pc_start - s->cs_base, s->pc - s->cs_base);
        } else {
            gen_lods(s, ot);
        }
        break;
    case 0xae: /* scasS */
    case 0xaf:
        ot = mo_b_d(b, dflag);
        if (prefixes & PREFIX_REPNZ) {
            gen_repz_scas(s, ot, pc_start - s->cs_base, s->pc - s->cs_base, 1);
        } else if (prefixes & PREFIX_REPZ) {
            gen_repz_scas(s, ot, pc_start - s->cs_base, s->pc - s->cs_base, 0);
        } else {
            gen_scas(s, ot);
        }
        break;

    case 0xa6: /* cmpsS */
    case 0xa7:
        ot = mo_b_d(b, dflag);
        if (prefixes & PREFIX_REPNZ) {
            gen_repz_cmps(s, ot, pc_start - s->cs_base, s->pc - s->cs_base, 1);
        } else if (prefixes & PREFIX_REPZ) {
            gen_repz_cmps(s, ot, pc_start - s->cs_base, s->pc - s->cs_base, 0);
        } else {
            gen_cmps(s, ot);
        }
        break;
    case 0x6c: /* insS */
    case 0x6d:
        ot = mo_b_d32(b, dflag);
        tcg_gen_ext16u_tl(cpu_T0, cpu_regs[R_EDX]);
        gen_check_io(s, ot, pc_start - s->cs_base, 
                     SVM_IOIO_TYPE_MASK | svm_is_rep(prefixes) | 4);
        if (prefixes & (PREFIX_REPZ | PREFIX_REPNZ)) {
            gen_repz_ins(s, ot, pc_start - s->cs_base, s->pc - s->cs_base);
        } else {
            gen_ins(s, ot);
            if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
                gen_jmp(s, s->pc - s->cs_base);
            }
        }
        break;
    case 0x6e: /* outsS */
    case 0x6f:
        ot = mo_b_d32(b, dflag);
        tcg_gen_ext16u_tl(cpu_T0, cpu_regs[R_EDX]);
        gen_check_io(s, ot, pc_start - s->cs_base,
                     svm_is_rep(prefixes) | 4);
        if (prefixes & (PREFIX_REPZ | PREFIX_REPNZ)) {
            gen_repz_outs(s, ot, pc_start - s->cs_base, s->pc - s->cs_base);
        } else {
            gen_outs(s, ot);
            if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
                gen_jmp(s, s->pc - s->cs_base);
            }
        }
        break;

        /************************/
        /* port I/O */

    case 0xe4:
    case 0xe5:
        ot = mo_b_d32(b, dflag);
        val = x86_ldub_code(env, s);
        tcg_gen_movi_tl(cpu_T0, val);
        gen_check_io(s, ot, pc_start - s->cs_base,
                     SVM_IOIO_TYPE_MASK | svm_is_rep(prefixes));
        if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
            gen_io_start();
	}
        tcg_gen_movi_i32(cpu_tmp2_i32, val);
        gen_helper_in_func(ot, cpu_T1, cpu_tmp2_i32);
        gen_op_mov_reg_v(ot, R_EAX, cpu_T1);
        gen_bpt_io(s, cpu_tmp2_i32, ot);
        if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
            gen_io_end();
            gen_jmp(s, s->pc - s->cs_base);
        }
        break;
    case 0xe6:
    case 0xe7:
        ot = mo_b_d32(b, dflag);
        val = x86_ldub_code(env, s);
        tcg_gen_movi_tl(cpu_T0, val);
        gen_check_io(s, ot, pc_start - s->cs_base,
                     svm_is_rep(prefixes));
        gen_op_mov_v_reg(ot, cpu_T1, R_EAX);

        if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
            gen_io_start();
	}
        tcg_gen_movi_i32(cpu_tmp2_i32, val);
        tcg_gen_trunc_tl_i32(cpu_tmp3_i32, cpu_T1);
        gen_helper_out_func(ot, cpu_tmp2_i32, cpu_tmp3_i32);
        gen_bpt_io(s, cpu_tmp2_i32, ot);
        if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
            gen_io_end();
            gen_jmp(s, s->pc - s->cs_base);
        }
        break;
    case 0xec:
    case 0xed:
        ot = mo_b_d32(b, dflag);
        tcg_gen_ext16u_tl(cpu_T0, cpu_regs[R_EDX]);
        gen_check_io(s, ot, pc_start - s->cs_base,
                     SVM_IOIO_TYPE_MASK | svm_is_rep(prefixes));
        if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
            gen_io_start();
	}
        tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_T0);
        gen_helper_in_func(ot, cpu_T1, cpu_tmp2_i32);
        gen_op_mov_reg_v(ot, R_EAX, cpu_T1);
        gen_bpt_io(s, cpu_tmp2_i32, ot);
        if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
            gen_io_end();
            gen_jmp(s, s->pc - s->cs_base);
        }
        break;
    case 0xee:
    case 0xef:
        ot = mo_b_d32(b, dflag);
        tcg_gen_ext16u_tl(cpu_T0, cpu_regs[R_EDX]);
        gen_check_io(s, ot, pc_start - s->cs_base,
                     svm_is_rep(prefixes));
        gen_op_mov_v_reg(ot, cpu_T1, R_EAX);

        if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
            gen_io_start();
	}
        tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_T0);
        tcg_gen_trunc_tl_i32(cpu_tmp3_i32, cpu_T1);
        gen_helper_out_func(ot, cpu_tmp2_i32, cpu_tmp3_i32);
        gen_bpt_io(s, cpu_tmp2_i32, ot);
        if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
            gen_io_end();
            gen_jmp(s, s->pc - s->cs_base);
        }
        break;

        /************************/
        /* control */
    case 0xc2: /* ret im */
        val = x86_ldsw_code(env, s);
        ot = gen_pop_T0(s);
        gen_stack_update(s, val + (1 << ot));
        /* Note that gen_pop_T0 uses a zero-extending load.  */
        gen_op_jmp_v(cpu_T0);
        gen_bnd_jmp(s);
        gen_jr(s, cpu_T0);
        break;
    case 0xc3: /* ret */
        ot = gen_pop_T0(s);
        gen_pop_update(s, ot);
        /* Note that gen_pop_T0 uses a zero-extending load.  */
        gen_op_jmp_v(cpu_T0);
        gen_bnd_jmp(s);
        gen_jr(s, cpu_T0);
        break;
    case 0xca: /* lret im */
        val = x86_ldsw_code(env, s);
    do_lret:
        if (s->pe && !s->vm86) {
            gen_update_cc_op(s);
            gen_jmp_im(pc_start - s->cs_base);
            gen_helper_lret_protected(cpu_env, tcg_const_i32(dflag - 1),
                                      tcg_const_i32(val));
        } else {
            gen_stack_A0(s);
            /* pop offset */
            gen_op_ld_v(s, dflag, cpu_T0, cpu_A0);
            /* NOTE: keeping EIP updated is not a problem in case of
               exception */
            gen_op_jmp_v(cpu_T0);
            /* pop selector */
            gen_add_A0_im(s, 1 << dflag);
            gen_op_ld_v(s, dflag, cpu_T0, cpu_A0);
            gen_op_movl_seg_T0_vm(R_CS);
            /* add stack offset */
            gen_stack_update(s, val + (2 << dflag));
        }
        gen_eob(s);
        break;
    case 0xcb: /* lret */
        val = 0;
        goto do_lret;
    case 0xcf: /* iret */
        gen_svm_check_intercept(s, pc_start, SVM_EXIT_IRET);
        if (!s->pe) {
            /* real mode */
            gen_helper_iret_real(cpu_env, tcg_const_i32(dflag - 1));
            set_cc_op(s, CC_OP_EFLAGS);
        } else if (s->vm86) {
            if (s->iopl != 3) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
            } else {
                gen_helper_iret_real(cpu_env, tcg_const_i32(dflag - 1));
                set_cc_op(s, CC_OP_EFLAGS);
            }
        } else {
            gen_helper_iret_protected(cpu_env, tcg_const_i32(dflag - 1),
                                      tcg_const_i32(s->pc - s->cs_base));
            set_cc_op(s, CC_OP_EFLAGS);
        }
        gen_eob(s);
        break;
    case 0xe8: /* call im */
        {
            if (dflag != MO_16) {
                tval = (int32_t)insn_get(env, s, MO_32);
            } else {
                tval = (int16_t)insn_get(env, s, MO_16);
            }
            next_eip = s->pc - s->cs_base;
            tval += next_eip;
            if (dflag == MO_16) {
                tval &= 0xffff;
            } else if (!CODE64(s)) {
                tval &= 0xffffffff;
            }
            tcg_gen_movi_tl(cpu_T0, next_eip);
            gen_push_v(s, cpu_T0);
            gen_bnd_jmp(s);
            gen_jmp(s, tval);
        }
        break;
    case 0x9a: /* lcall im */
        {
            unsigned int selector, offset;

            if (CODE64(s))
                goto illegal_op;
            ot = dflag;
            offset = insn_get(env, s, ot);
            selector = insn_get(env, s, MO_16);

            tcg_gen_movi_tl(cpu_T0, selector);
            tcg_gen_movi_tl(cpu_T1, offset);
        }
        goto do_lcall;
    case 0xe9: /* jmp im */
        if (dflag != MO_16) {
            tval = (int32_t)insn_get(env, s, MO_32);
        } else {
            tval = (int16_t)insn_get(env, s, MO_16);
        }
        tval += s->pc - s->cs_base;
        if (dflag == MO_16) {
            tval &= 0xffff;
        } else if (!CODE64(s)) {
            tval &= 0xffffffff;
        }
        gen_bnd_jmp(s);
        gen_jmp(s, tval);
        break;
    case 0xea: /* ljmp im */
        {
            unsigned int selector, offset;

            if (CODE64(s))
                goto illegal_op;
            ot = dflag;
            offset = insn_get(env, s, ot);
            selector = insn_get(env, s, MO_16);

            tcg_gen_movi_tl(cpu_T0, selector);
            tcg_gen_movi_tl(cpu_T1, offset);
        }
        goto do_ljmp;
    case 0xeb: /* jmp Jb */
        tval = (int8_t)insn_get(env, s, MO_8);
        tval += s->pc - s->cs_base;
        if (dflag == MO_16) {
            tval &= 0xffff;
        }
        gen_jmp(s, tval);
        break;
    case 0x70 ... 0x7f: /* jcc Jb */
        tval = (int8_t)insn_get(env, s, MO_8);
        goto do_jcc;
    case 0x180 ... 0x18f: /* jcc Jv */
        if (dflag != MO_16) {
            tval = (int32_t)insn_get(env, s, MO_32);
        } else {
            tval = (int16_t)insn_get(env, s, MO_16);
        }
    do_jcc:
        next_eip = s->pc - s->cs_base;
        tval += next_eip;
        if (dflag == MO_16) {
            tval &= 0xffff;
        }
        gen_bnd_jmp(s);
        gen_jcc(s, b, tval, next_eip);
        break;

    case 0x190 ... 0x19f: /* setcc Gv */
        modrm = x86_ldub_code(env, s);
        gen_setcc1(s, b, cpu_T0);
        gen_ldst_modrm(env, s, modrm, MO_8, OR_TMP0, 1);
        break;
    case 0x140 ... 0x14f: /* cmov Gv, Ev */
        if (!(s->cpuid_features & CPUID_CMOV)) {
            goto illegal_op;
        }
        ot = dflag;
        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;
        gen_cmovcc1(env, s, ot, b, modrm, reg);
        break;

        /************************/
        /* flags */
    case 0x9c: /* pushf */
        gen_svm_check_intercept(s, pc_start, SVM_EXIT_PUSHF);
        if (s->vm86 && s->iopl != 3) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            gen_update_cc_op(s);
            gen_helper_read_eflags(cpu_T0, cpu_env);
            gen_push_v(s, cpu_T0);
        }
        break;
    case 0x9d: /* popf */
        gen_svm_check_intercept(s, pc_start, SVM_EXIT_POPF);
        if (s->vm86 && s->iopl != 3) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            ot = gen_pop_T0(s);
            if (s->cpl == 0) {
                if (dflag != MO_16) {
                    gen_helper_write_eflags(cpu_env, cpu_T0,
                                            tcg_const_i32((TF_MASK | AC_MASK |
                                                           ID_MASK | NT_MASK |
                                                           IF_MASK |
                                                           IOPL_MASK)));
                } else {
                    gen_helper_write_eflags(cpu_env, cpu_T0,
                                            tcg_const_i32((TF_MASK | AC_MASK |
                                                           ID_MASK | NT_MASK |
                                                           IF_MASK | IOPL_MASK)
                                                          & 0xffff));
                }
            } else {
                if (s->cpl <= s->iopl) {
                    if (dflag != MO_16) {
                        gen_helper_write_eflags(cpu_env, cpu_T0,
                                                tcg_const_i32((TF_MASK |
                                                               AC_MASK |
                                                               ID_MASK |
                                                               NT_MASK |
                                                               IF_MASK)));
                    } else {
                        gen_helper_write_eflags(cpu_env, cpu_T0,
                                                tcg_const_i32((TF_MASK |
                                                               AC_MASK |
                                                               ID_MASK |
                                                               NT_MASK |
                                                               IF_MASK)
                                                              & 0xffff));
                    }
                } else {
                    if (dflag != MO_16) {
                        gen_helper_write_eflags(cpu_env, cpu_T0,
                                           tcg_const_i32((TF_MASK | AC_MASK |
                                                          ID_MASK | NT_MASK)));
                    } else {
                        gen_helper_write_eflags(cpu_env, cpu_T0,
                                           tcg_const_i32((TF_MASK | AC_MASK |
                                                          ID_MASK | NT_MASK)
                                                         & 0xffff));
                    }
                }
            }
            gen_pop_update(s, ot);
            set_cc_op(s, CC_OP_EFLAGS);
            /* abort translation because TF/AC flag may change */
            gen_jmp_im(s->pc - s->cs_base);
            gen_eob(s);
        }
        break;
    case 0x9e: /* sahf */
        if (CODE64(s) && !(s->cpuid_ext3_features & CPUID_EXT3_LAHF_LM))
            goto illegal_op;
        gen_op_mov_v_reg(MO_8, cpu_T0, R_AH);
        gen_compute_eflags(s);
        tcg_gen_andi_tl(cpu_cc_src, cpu_cc_src, CC_O);
        tcg_gen_andi_tl(cpu_T0, cpu_T0, CC_S | CC_Z | CC_A | CC_P | CC_C);
        tcg_gen_or_tl(cpu_cc_src, cpu_cc_src, cpu_T0);
        break;
    case 0x9f: /* lahf */
        if (CODE64(s) && !(s->cpuid_ext3_features & CPUID_EXT3_LAHF_LM))
            goto illegal_op;
        gen_compute_eflags(s);
        /* Note: gen_compute_eflags() only gives the condition codes */
        tcg_gen_ori_tl(cpu_T0, cpu_cc_src, 0x02);
        gen_op_mov_reg_v(MO_8, R_AH, cpu_T0);
        break;
    case 0xf5: /* cmc */
        gen_compute_eflags(s);
        tcg_gen_xori_tl(cpu_cc_src, cpu_cc_src, CC_C);
        break;
    case 0xf8: /* clc */
        gen_compute_eflags(s);
        tcg_gen_andi_tl(cpu_cc_src, cpu_cc_src, ~CC_C);
        break;
    case 0xf9: /* stc */
        gen_compute_eflags(s);
        tcg_gen_ori_tl(cpu_cc_src, cpu_cc_src, CC_C);
        break;
    case 0xfc: /* cld */
        tcg_gen_movi_i32(cpu_tmp2_i32, 1);
        tcg_gen_st_i32(cpu_tmp2_i32, cpu_env, offsetof(CPUX86State, df));
        break;
    case 0xfd: /* std */
        tcg_gen_movi_i32(cpu_tmp2_i32, -1);
        tcg_gen_st_i32(cpu_tmp2_i32, cpu_env, offsetof(CPUX86State, df));
        break;

        /************************/
        /* bit operations */
    case 0x1ba: /* bt/bts/btr/btc Gv, im */
        ot = dflag;
        modrm = x86_ldub_code(env, s);
        op = (modrm >> 3) & 7;
        mod = (modrm >> 6) & 3;
        rm = (modrm & 7) | REX_B(s);
        if (mod != 3) {
            s->rip_offset = 1;
            gen_lea_modrm(env, s, modrm);
            if (!(s->prefix & PREFIX_LOCK)) {
                gen_op_ld_v(s, ot, cpu_T0, cpu_A0);
            }
        } else {
            gen_op_mov_v_reg(ot, cpu_T0, rm);
        }
        /* load shift */
        val = x86_ldub_code(env, s);
        tcg_gen_movi_tl(cpu_T1, val);
        if (op < 4)
            goto unknown_op;
        op -= 4;
        goto bt_op;
    case 0x1a3: /* bt Gv, Ev */
        op = 0;
        goto do_btx;
    case 0x1ab: /* bts */
        op = 1;
        goto do_btx;
    case 0x1b3: /* btr */
        op = 2;
        goto do_btx;
    case 0x1bb: /* btc */
        op = 3;
    do_btx:
        ot = dflag;
        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;
        mod = (modrm >> 6) & 3;
        rm = (modrm & 7) | REX_B(s);
        gen_op_mov_v_reg(MO_32, cpu_T1, reg);
        if (mod != 3) {
            AddressParts a = gen_lea_modrm_0(env, s, modrm);
            /* specific case: we need to add a displacement */
            gen_exts(ot, cpu_T1);
            tcg_gen_sari_tl(cpu_tmp0, cpu_T1, 3 + ot);
            tcg_gen_shli_tl(cpu_tmp0, cpu_tmp0, ot);
            tcg_gen_add_tl(cpu_A0, gen_lea_modrm_1(a), cpu_tmp0);
            gen_lea_v_seg(s, s->aflag, cpu_A0, a.def_seg, s->override);
            if (!(s->prefix & PREFIX_LOCK)) {
                gen_op_ld_v(s, ot, cpu_T0, cpu_A0);
            }
        } else {
            gen_op_mov_v_reg(ot, cpu_T0, rm);
        }
    bt_op:
        tcg_gen_andi_tl(cpu_T1, cpu_T1, (1 << (3 + ot)) - 1);
        tcg_gen_movi_tl(cpu_tmp0, 1);
        tcg_gen_shl_tl(cpu_tmp0, cpu_tmp0, cpu_T1);
        if (s->prefix & PREFIX_LOCK) {
            switch (op) {
            case 0: /* bt */
                /* Needs no atomic ops; we surpressed the normal
                   memory load for LOCK above so do it now.  */
                gen_op_ld_v(s, ot, cpu_T0, cpu_A0);
                break;
            case 1: /* bts */
                tcg_gen_atomic_fetch_or_tl(cpu_T0, cpu_A0, cpu_tmp0,
                                           s->mem_index, (TCGMemOp)(ot | MO_LE));
                break;
            case 2: /* btr */
                tcg_gen_not_tl(cpu_tmp0, cpu_tmp0);
                tcg_gen_atomic_fetch_and_tl(cpu_T0, cpu_A0, cpu_tmp0,
                                            s->mem_index, (TCGMemOp)(ot | MO_LE));
                break;
            default:
            case 3: /* btc */
                tcg_gen_atomic_fetch_xor_tl(cpu_T0, cpu_A0, cpu_tmp0,
                                            s->mem_index, (TCGMemOp)(ot | MO_LE));
                break;
            }
            tcg_gen_shr_tl(cpu_tmp4, cpu_T0, cpu_T1);
        } else {
            tcg_gen_shr_tl(cpu_tmp4, cpu_T0, cpu_T1);
            switch (op) {
            case 0: /* bt */
                /* Data already loaded; nothing to do.  */
                break;
            case 1: /* bts */
                tcg_gen_or_tl(cpu_T0, cpu_T0, cpu_tmp0);
                break;
            case 2: /* btr */
                tcg_gen_andc_tl(cpu_T0, cpu_T0, cpu_tmp0);
                break;
            default:
            case 3: /* btc */
                tcg_gen_xor_tl(cpu_T0, cpu_T0, cpu_tmp0);
                break;
            }
            if (op != 0) {
                if (mod != 3) {
                    gen_op_st_v(s, ot, cpu_T0, cpu_A0);
                } else {
                    gen_op_mov_reg_v(ot, rm, cpu_T0);
                }
            }
        }

        /* Delay all CC updates until after the store above.  Note that
           C is the result of the test, Z is unchanged, and the others
           are all undefined.  */
        switch (s->cc_op) {
        case CC_OP_MULB ... CC_OP_MULQ:
        case CC_OP_ADDB ... CC_OP_ADDQ:
        case CC_OP_ADCB ... CC_OP_ADCQ:
        case CC_OP_SUBB ... CC_OP_SUBQ:
        case CC_OP_SBBB ... CC_OP_SBBQ:
        case CC_OP_LOGICB ... CC_OP_LOGICQ:
        case CC_OP_INCB ... CC_OP_INCQ:
        case CC_OP_DECB ... CC_OP_DECQ:
        case CC_OP_SHLB ... CC_OP_SHLQ:
        case CC_OP_SARB ... CC_OP_SARQ:
        case CC_OP_BMILGB ... CC_OP_BMILGQ:
            /* Z was going to be computed from the non-zero status of CC_DST.
               We can get that same Z value (and the new C value) by leaving
               CC_DST alone, setting CC_SRC, and using a CC_OP_SAR of the
               same width.  */
            tcg_gen_mov_tl(cpu_cc_src, cpu_tmp4);
            set_cc_op(s, (CCOp)(((s->cc_op - CC_OP_MULB) & 3) + CC_OP_SARB));
            break;
        default:
            /* Otherwise, generate EFLAGS and replace the C bit.  */
            gen_compute_eflags(s);
            tcg_gen_deposit_tl(cpu_cc_src, cpu_cc_src, cpu_tmp4,
                               ctz32(CC_C), 1);
            break;
        }
        break;
    case 0x1bc: /* bsf / tzcnt */
    case 0x1bd: /* bsr / lzcnt */
        ot = dflag;
        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;
        gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
        gen_extu(ot, cpu_T0);

        /* Note that lzcnt and tzcnt are in different extensions.  */
        if ((prefixes & PREFIX_REPZ)
            && (b & 1
                ? s->cpuid_ext3_features & CPUID_EXT3_ABM
                : s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_BMI1)) {
            int size = 8 << ot;
            /* For lzcnt/tzcnt, C bit is defined related to the input. */
            tcg_gen_mov_tl(cpu_cc_src, cpu_T0);
            if (b & 1) {
                /* For lzcnt, reduce the target_ulong result by the
                   number of zeros that we expect to find at the top.  */
                tcg_gen_clzi_tl(cpu_T0, cpu_T0, TARGET_LONG_BITS);
                tcg_gen_subi_tl(cpu_T0, cpu_T0, TARGET_LONG_BITS - size);
            } else {
                /* For tzcnt, a zero input must return the operand size.  */
                tcg_gen_ctzi_tl(cpu_T0, cpu_T0, size);
            }
            /* For lzcnt/tzcnt, Z bit is defined related to the result.  */
            gen_op_update1_cc();
            set_cc_op(s, (CCOp)(CC_OP_BMILGB + ot));
        } else {
            /* For bsr/bsf, only the Z bit is defined and it is related
               to the input and not the result.  */
            tcg_gen_mov_tl(cpu_cc_dst, cpu_T0);
            set_cc_op(s, (CCOp)(CC_OP_LOGICB + ot));

            /* ??? The manual says that the output is undefined when the
               input is zero, but real hardware leaves it unchanged, and
               real programs appear to depend on that.  Accomplish this
               by passing the output as the value to return upon zero.  */
            if (b & 1) {
                /* For bsr, return the bit index of the first 1 bit,
                   not the count of leading zeros.  */
                tcg_gen_xori_tl(cpu_T1, cpu_regs[reg], TARGET_LONG_BITS - 1);
                tcg_gen_clz_tl(cpu_T0, cpu_T0, cpu_T1);
                tcg_gen_xori_tl(cpu_T0, cpu_T0, TARGET_LONG_BITS - 1);
            } else {
                tcg_gen_ctz_tl(cpu_T0, cpu_T0, cpu_regs[reg]);
            }
        }
        gen_op_mov_reg_v(ot, reg, cpu_T0);
        break;
        /************************/
        /* bcd */
    case 0x27: /* daa */
        if (CODE64(s))
            goto illegal_op;
        gen_update_cc_op(s);
        gen_helper_daa(cpu_env);
        set_cc_op(s, CC_OP_EFLAGS);
        break;
    case 0x2f: /* das */
        if (CODE64(s))
            goto illegal_op;
        gen_update_cc_op(s);
        gen_helper_das(cpu_env);
        set_cc_op(s, CC_OP_EFLAGS);
        break;
    case 0x37: /* aaa */
        if (CODE64(s))
            goto illegal_op;
        gen_update_cc_op(s);
        gen_helper_aaa(cpu_env);
        set_cc_op(s, CC_OP_EFLAGS);
        break;
    case 0x3f: /* aas */
        if (CODE64(s))
            goto illegal_op;
        gen_update_cc_op(s);
        gen_helper_aas(cpu_env);
        set_cc_op(s, CC_OP_EFLAGS);
        break;
    case 0xd4: /* aam */
        if (CODE64(s))
            goto illegal_op;
        val = x86_ldub_code(env, s);
        if (val == 0) {
            gen_exception(s, EXCP00_DIVZ, pc_start - s->cs_base);
        } else {
            gen_helper_aam(cpu_env, tcg_const_i32(val));
            set_cc_op(s, CC_OP_LOGICB);
        }
        break;
    case 0xd5: /* aad */
        if (CODE64(s))
            goto illegal_op;
        val = x86_ldub_code(env, s);
        gen_helper_aad(cpu_env, tcg_const_i32(val));
        set_cc_op(s, CC_OP_LOGICB);
        break;
        /************************/
        /* misc */
    case 0x90: /* nop */
        /* XXX: correct lock test for all insn */
        if (prefixes & PREFIX_LOCK) {
            goto illegal_op;
        }
        /* If REX_B is set, then this is xchg eax, r8d, not a nop.  */
        if (REX_B(s)) {
            goto do_xchg_reg_eax;
        }
        if (prefixes & PREFIX_REPZ) {
            gen_update_cc_op(s);
            gen_jmp_im(pc_start - s->cs_base);
            gen_helper_pause(cpu_env, tcg_const_i32(s->pc - pc_start));
            s->base.is_jmp = DISAS_NORETURN;
        }
        break;
    case 0x9b: /* fwait */
        if ((s->flags & (HF_MP_MASK | HF_TS_MASK)) ==
            (HF_MP_MASK | HF_TS_MASK)) {
            gen_exception(s, EXCP07_PREX, pc_start - s->cs_base);
        } else {
            gen_helper_fwait(cpu_env);
        }
        break;
    case 0xcc: /* int3 */
        gen_interrupt(s, EXCP03_INT3, pc_start - s->cs_base, s->pc - s->cs_base);
        break;
    case 0xcd: /* int N */
        val = x86_ldub_code(env, s);
        if (s->vm86 && s->iopl != 3) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            gen_interrupt(s, val, pc_start - s->cs_base, s->pc - s->cs_base);
        }
        break;
    case 0xce: /* into */
        if (CODE64(s))
            goto illegal_op;
        gen_update_cc_op(s);
        gen_jmp_im(pc_start - s->cs_base);
        gen_helper_into(cpu_env, tcg_const_i32(s->pc - pc_start));
        break;
#ifdef WANT_ICEBP
    case 0xf1: /* icebp (undocumented, exits to external debugger) */
        gen_svm_check_intercept(s, pc_start, SVM_EXIT_ICEBP);
#if 1
        gen_debug(s, pc_start - s->cs_base);
#else
        /* start debug */
        tb_flush(CPU(x86_env_get_cpu(env)));
        qemu_set_log(CPU_LOG_INT | CPU_LOG_TB_IN_ASM);
#endif
        break;
#endif
    case 0xfa: /* cli */
        if (!s->vm86) {
            if (s->cpl <= s->iopl) {
                gen_helper_cli(cpu_env);
            } else {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
            }
        } else {
            if (s->iopl == 3) {
                gen_helper_cli(cpu_env);
            } else {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
            }
        }
        break;
    case 0xfb: /* sti */
        if (s->vm86 ? s->iopl == 3 : s->cpl <= s->iopl) {
            gen_helper_sti(cpu_env);
            /* interruptions are enabled only the first insn after sti */
            gen_jmp_im(s->pc - s->cs_base);
            gen_eob_inhibit_irq(s, true);
        } else {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        }
        break;
    case 0x62: /* bound */
        if (CODE64(s))
            goto illegal_op;
        ot = dflag;
        modrm = x86_ldub_code(env, s);
        reg = (modrm >> 3) & 7;
        mod = (modrm >> 6) & 3;
        if (mod == 3)
            goto illegal_op;
        gen_op_mov_v_reg(ot, cpu_T0, reg);
        gen_lea_modrm(env, s, modrm);
        tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_T0);
        if (ot == MO_16) {
            gen_helper_boundw(cpu_env, cpu_A0, cpu_tmp2_i32);
        } else {
            gen_helper_boundl(cpu_env, cpu_A0, cpu_tmp2_i32);
        }
        break;
    case 0x1c8 ... 0x1cf: /* bswap reg */
        reg = (b & 7) | REX_B(s);
#ifdef TARGET_X86_64
        if (dflag == MO_64) {
            gen_op_mov_v_reg(MO_64, cpu_T0, reg);
            tcg_gen_bswap64_i64(cpu_T0, cpu_T0);
            gen_op_mov_reg_v(MO_64, reg, cpu_T0);
        } else
#endif
        {
            gen_op_mov_v_reg(MO_32, cpu_T0, reg);
            tcg_gen_ext32u_tl(cpu_T0, cpu_T0);
            tcg_gen_bswap32_tl(cpu_T0, cpu_T0);
            gen_op_mov_reg_v(MO_32, reg, cpu_T0);
        }
        break;
    case 0xd6: /* salc */
        if (CODE64(s))
            goto illegal_op;
        gen_compute_eflags_c(s, cpu_T0);
        tcg_gen_neg_tl(cpu_T0, cpu_T0);
        gen_op_mov_reg_v(MO_8, R_EAX, cpu_T0);
        break;
    case 0xe0: /* loopnz */
    case 0xe1: /* loopz */
    case 0xe2: /* loop */
    case 0xe3: /* jecxz */
        {
            TCGLabel *l1, *l2, *l3;

            tval = (int8_t)insn_get(env, s, MO_8);
            next_eip = s->pc - s->cs_base;
            tval += next_eip;
            if (dflag == MO_16) {
                tval &= 0xffff;
            }

            l1 = gen_new_label();
            l2 = gen_new_label();
            l3 = gen_new_label();
            b &= 3;
            switch(b) {
            case 0: /* loopnz */
            case 1: /* loopz */
                gen_op_add_reg_im(s->aflag, R_ECX, -1);
                gen_op_jz_ecx(s->aflag, l3);
                gen_jcc1(s, (JCC_Z << 1) | (b ^ 1), l1);
                break;
            case 2: /* loop */
                gen_op_add_reg_im(s->aflag, R_ECX, -1);
                gen_op_jnz_ecx(s->aflag, l1);
                break;
            default:
            case 3: /* jcxz */
                gen_op_jz_ecx(s->aflag, l1);
                break;
            }

            gen_set_label(l3);
            gen_jmp_im(next_eip);
            tcg_gen_br(l2);

            gen_set_label(l1);
            gen_jmp_im(tval);
            gen_set_label(l2);
            gen_eob(s);
        }
        break;
    case 0x130: /* wrmsr */
    case 0x132: /* rdmsr */
        if (s->cpl != 0) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            gen_update_cc_op(s);
            gen_jmp_im(pc_start - s->cs_base);
            if (b & 2) {
                gen_helper_rdmsr(cpu_env);
            } else {
                gen_helper_wrmsr(cpu_env);
            }
        }
        break;
    case 0x131: /* rdtsc */
        gen_update_cc_op(s);
        gen_jmp_im(pc_start - s->cs_base);
        if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
            gen_io_start();
	}
        gen_helper_rdtsc(cpu_env);
        if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
            gen_io_end();
            gen_jmp(s, s->pc - s->cs_base);
        }
        break;
    case 0x133: /* rdpmc */
        gen_update_cc_op(s);
        gen_jmp_im(pc_start - s->cs_base);
        gen_helper_rdpmc(cpu_env);
        break;
    case 0x134: /* sysenter */
        /* For Intel SYSENTER is valid on 64-bit */
        if (CODE64(s) && env->cpuid_vendor1 != CPUID_VENDOR_INTEL_1)
            goto illegal_op;
        if (!s->pe) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            gen_helper_sysenter(cpu_env);
            gen_eob(s);
        }
        break;
    case 0x135: /* sysexit */
        /* For Intel SYSEXIT is valid on 64-bit */
        if (CODE64(s) && env->cpuid_vendor1 != CPUID_VENDOR_INTEL_1)
            goto illegal_op;
        if (!s->pe) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            gen_helper_sysexit(cpu_env, tcg_const_i32(dflag - 1));
            gen_eob(s);
        }
        break;
#ifdef TARGET_X86_64
    case 0x105: /* syscall */
        /* XXX: is it usable in real mode ? */
        gen_update_cc_op(s);
        gen_jmp_im(pc_start - s->cs_base);
        gen_helper_syscall(cpu_env, tcg_const_i32(s->pc - pc_start));
        /* TF handling for the syscall insn is different. The TF bit is  checked
           after the syscall insn completes. This allows #DB to not be
           generated after one has entered CPL0 if TF is set in FMASK.  */
        gen_eob_worker(s, false, true);
        break;
    case 0x107: /* sysret */
        if (!s->pe) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            gen_helper_sysret(cpu_env, tcg_const_i32(dflag - 1));
            /* condition codes are modified only in long mode */
            if (s->lma) {
                set_cc_op(s, CC_OP_EFLAGS);
            }
            /* TF handling for the sysret insn is different. The TF bit is
               checked after the sysret insn completes. This allows #DB to be
               generated "as if" the syscall insn in userspace has just
               completed.  */
            gen_eob_worker(s, false, true);
        }
        break;
#endif
    case 0x1a2: /* cpuid */
        gen_update_cc_op(s);
        gen_jmp_im(pc_start - s->cs_base);
        gen_helper_cpuid(cpu_env);
        break;
    case 0xf4: /* hlt */
        if (s->cpl != 0) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            gen_update_cc_op(s);
            gen_jmp_im(pc_start - s->cs_base);
            gen_helper_hlt(cpu_env, tcg_const_i32(s->pc - pc_start));
            s->base.is_jmp = DISAS_NORETURN;
        }
        break;
    case 0x100:
        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        op = (modrm >> 3) & 7;
        switch(op) {
        case 0: /* sldt */
            if (!s->pe || s->vm86)
                goto illegal_op;
            gen_svm_check_intercept(s, pc_start, SVM_EXIT_LDTR_READ);
            tcg_gen_ld32u_tl(cpu_T0, cpu_env,
                             offsetof(CPUX86State, ldt.selector));
            ot = mod == 3 ? dflag : MO_16;
            gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 1);
            break;
        case 2: /* lldt */
            if (!s->pe || s->vm86)
                goto illegal_op;
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
            } else {
                gen_svm_check_intercept(s, pc_start, SVM_EXIT_LDTR_WRITE);
                gen_ldst_modrm(env, s, modrm, MO_16, OR_TMP0, 0);
                tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_T0);
                gen_helper_lldt(cpu_env, cpu_tmp2_i32);
            }
            break;
        case 1: /* str */
            if (!s->pe || s->vm86)
                goto illegal_op;
            gen_svm_check_intercept(s, pc_start, SVM_EXIT_TR_READ);
            tcg_gen_ld32u_tl(cpu_T0, cpu_env,
                             offsetof(CPUX86State, tr.selector));
            ot = mod == 3 ? dflag : MO_16;
            gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 1);
            break;
        case 3: /* ltr */
            if (!s->pe || s->vm86)
                goto illegal_op;
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
            } else {
                gen_svm_check_intercept(s, pc_start, SVM_EXIT_TR_WRITE);
                gen_ldst_modrm(env, s, modrm, MO_16, OR_TMP0, 0);
                tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_T0);
                gen_helper_ltr(cpu_env, cpu_tmp2_i32);
            }
            break;
        case 4: /* verr */
        case 5: /* verw */
            if (!s->pe || s->vm86)
                goto illegal_op;
            gen_ldst_modrm(env, s, modrm, MO_16, OR_TMP0, 0);
            gen_update_cc_op(s);
            if (op == 4) {
                gen_helper_verr(cpu_env, cpu_T0);
            } else {
                gen_helper_verw(cpu_env, cpu_T0);
            }
            set_cc_op(s, CC_OP_EFLAGS);
            break;
        default:
            goto unknown_op;
        }
        break;

    case 0x101:
        modrm = x86_ldub_code(env, s);
        switch (modrm) {
        CASE_MODRM_MEM_OP(0): /* sgdt */
            gen_svm_check_intercept(s, pc_start, SVM_EXIT_GDTR_READ);
            gen_lea_modrm(env, s, modrm);
            tcg_gen_ld32u_tl(cpu_T0,
                             cpu_env, offsetof(CPUX86State, gdt.limit));
            gen_op_st_v(s, MO_16, cpu_T0, cpu_A0);
            gen_add_A0_im(s, 2);
            tcg_gen_ld_tl(cpu_T0, cpu_env, offsetof(CPUX86State, gdt.base));
            if (dflag == MO_16) {
                tcg_gen_andi_tl(cpu_T0, cpu_T0, 0xffffff);
            }
            gen_op_st_v(s, CODE64(s) + MO_32, cpu_T0, cpu_A0);
            break;

        case 0xc8: /* monitor */
            if (!(s->cpuid_ext_features & CPUID_EXT_MONITOR) || s->cpl != 0) {
                goto illegal_op;
            }
            gen_update_cc_op(s);
            gen_jmp_im(pc_start - s->cs_base);
            tcg_gen_mov_tl(cpu_A0, cpu_regs[R_EAX]);
            gen_extu(s->aflag, cpu_A0);
            gen_add_A0_ds_seg(s);
            gen_helper_monitor(cpu_env, cpu_A0);
            break;

        case 0xc9: /* mwait */
            if (!(s->cpuid_ext_features & CPUID_EXT_MONITOR) || s->cpl != 0) {
                goto illegal_op;
            }
            gen_update_cc_op(s);
            gen_jmp_im(pc_start - s->cs_base);
            gen_helper_mwait(cpu_env, tcg_const_i32(s->pc - pc_start));
            gen_eob(s);
            break;

        case 0xca: /* clac */
            if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_SMAP)
                || s->cpl != 0) {
                goto illegal_op;
            }
            gen_helper_clac(cpu_env);
            gen_jmp_im(s->pc - s->cs_base);
            gen_eob(s);
            break;

        case 0xcb: /* stac */
            if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_SMAP)
                || s->cpl != 0) {
                goto illegal_op;
            }
            gen_helper_stac(cpu_env);
            gen_jmp_im(s->pc - s->cs_base);
            gen_eob(s);
            break;

        CASE_MODRM_MEM_OP(1): /* sidt */
            gen_svm_check_intercept(s, pc_start, SVM_EXIT_IDTR_READ);
            gen_lea_modrm(env, s, modrm);
            tcg_gen_ld32u_tl(cpu_T0, cpu_env, offsetof(CPUX86State, idt.limit));
            gen_op_st_v(s, MO_16, cpu_T0, cpu_A0);
            gen_add_A0_im(s, 2);
            tcg_gen_ld_tl(cpu_T0, cpu_env, offsetof(CPUX86State, idt.base));
            if (dflag == MO_16) {
                tcg_gen_andi_tl(cpu_T0, cpu_T0, 0xffffff);
            }
            gen_op_st_v(s, CODE64(s) + MO_32, cpu_T0, cpu_A0);
            break;

        case 0xd0: /* xgetbv */
            if ((s->cpuid_ext_features & CPUID_EXT_XSAVE) == 0
                || (s->prefix & (PREFIX_LOCK | PREFIX_DATA
                                 | PREFIX_REPZ | PREFIX_REPNZ))) {
                goto illegal_op;
            }
            tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_regs[R_ECX]);
            gen_helper_xgetbv(cpu_tmp1_i64, cpu_env, cpu_tmp2_i32);
            tcg_gen_extr_i64_tl(cpu_regs[R_EAX], cpu_regs[R_EDX], cpu_tmp1_i64);
            break;

        case 0xd1: /* xsetbv */
            if ((s->cpuid_ext_features & CPUID_EXT_XSAVE) == 0
                || (s->prefix & (PREFIX_LOCK | PREFIX_DATA
                                 | PREFIX_REPZ | PREFIX_REPNZ))) {
                goto illegal_op;
            }
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            tcg_gen_concat_tl_i64(cpu_tmp1_i64, cpu_regs[R_EAX],
                                  cpu_regs[R_EDX]);
            tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_regs[R_ECX]);
            gen_helper_xsetbv(cpu_env, cpu_tmp2_i32, cpu_tmp1_i64);
            /* End TB because translation flags may change.  */
            gen_jmp_im(s->pc - s->cs_base);
            gen_eob(s);
            break;

        case 0xd8: /* VMRUN */
            if (!(s->flags & HF_SVME_MASK) || !s->pe) {
                goto illegal_op;
            }
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            gen_update_cc_op(s);
            gen_jmp_im(pc_start - s->cs_base);
            gen_helper_vmrun(cpu_env, tcg_const_i32(s->aflag - 1),
                             tcg_const_i32(s->pc - pc_start));
            tcg_gen_exit_tb(0);
            s->base.is_jmp = DISAS_NORETURN;
            break;

        case 0xd9: /* VMMCALL */
            if (!(s->flags & HF_SVME_MASK)) {
                goto illegal_op;
            }
            gen_update_cc_op(s);
            gen_jmp_im(pc_start - s->cs_base);
            gen_helper_vmmcall(cpu_env);
            break;

        case 0xda: /* VMLOAD */
            if (!(s->flags & HF_SVME_MASK) || !s->pe) {
                goto illegal_op;
            }
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            gen_update_cc_op(s);
            gen_jmp_im(pc_start - s->cs_base);
            gen_helper_vmload(cpu_env, tcg_const_i32(s->aflag - 1));
            break;

        case 0xdb: /* VMSAVE */
            if (!(s->flags & HF_SVME_MASK) || !s->pe) {
                goto illegal_op;
            }
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            gen_update_cc_op(s);
            gen_jmp_im(pc_start - s->cs_base);
            gen_helper_vmsave(cpu_env, tcg_const_i32(s->aflag - 1));
            break;

        case 0xdc: /* STGI */
            if ((!(s->flags & HF_SVME_MASK)
                   && !(s->cpuid_ext3_features & CPUID_EXT3_SKINIT))
                || !s->pe) {
                goto illegal_op;
            }
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            gen_update_cc_op(s);
            gen_jmp_im(pc_start - s->cs_base);
            gen_helper_stgi(cpu_env);
            break;

        case 0xdd: /* CLGI */
            if (!(s->flags & HF_SVME_MASK) || !s->pe) {
                goto illegal_op;
            }
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            gen_update_cc_op(s);
            gen_jmp_im(pc_start - s->cs_base);
            gen_helper_clgi(cpu_env);
            break;

        case 0xde: /* SKINIT */
            if ((!(s->flags & HF_SVME_MASK)
                 && !(s->cpuid_ext3_features & CPUID_EXT3_SKINIT))
                || !s->pe) {
                goto illegal_op;
            }
            gen_update_cc_op(s);
            gen_jmp_im(pc_start - s->cs_base);
            gen_helper_skinit(cpu_env);
            break;

        case 0xdf: /* INVLPGA */
            if (!(s->flags & HF_SVME_MASK) || !s->pe) {
                goto illegal_op;
            }
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            gen_update_cc_op(s);
            gen_jmp_im(pc_start - s->cs_base);
            gen_helper_invlpga(cpu_env, tcg_const_i32(s->aflag - 1));
            break;

        CASE_MODRM_MEM_OP(2): /* lgdt */
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            gen_svm_check_intercept(s, pc_start, SVM_EXIT_GDTR_WRITE);
            gen_lea_modrm(env, s, modrm);
            gen_op_ld_v(s, MO_16, cpu_T1, cpu_A0);
            gen_add_A0_im(s, 2);
            gen_op_ld_v(s, CODE64(s) + MO_32, cpu_T0, cpu_A0);
            if (dflag == MO_16) {
                tcg_gen_andi_tl(cpu_T0, cpu_T0, 0xffffff);
            }
            tcg_gen_st_tl(cpu_T0, cpu_env, offsetof(CPUX86State, gdt.base));
            tcg_gen_st32_tl(cpu_T1, cpu_env, offsetof(CPUX86State, gdt.limit));
            break;

        CASE_MODRM_MEM_OP(3): /* lidt */
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            gen_svm_check_intercept(s, pc_start, SVM_EXIT_IDTR_WRITE);
            gen_lea_modrm(env, s, modrm);
            gen_op_ld_v(s, MO_16, cpu_T1, cpu_A0);
            gen_add_A0_im(s, 2);
            gen_op_ld_v(s, CODE64(s) + MO_32, cpu_T0, cpu_A0);
            if (dflag == MO_16) {
                tcg_gen_andi_tl(cpu_T0, cpu_T0, 0xffffff);
            }
            tcg_gen_st_tl(cpu_T0, cpu_env, offsetof(CPUX86State, idt.base));
            tcg_gen_st32_tl(cpu_T1, cpu_env, offsetof(CPUX86State, idt.limit));
            break;

        CASE_MODRM_OP(4): /* smsw */
            gen_svm_check_intercept(s, pc_start, SVM_EXIT_READ_CR0);
            tcg_gen_ld_tl(cpu_T0, cpu_env, offsetof(CPUX86State, cr[0]));
            if (CODE64(s)) {
                mod = (modrm >> 6) & 3;
                ot = (mod != 3 ? MO_16 : s->dflag);
            } else {
                ot = MO_16;
            }
            gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 1);
            break;
        case 0xee: /* rdpkru */
            if (prefixes & PREFIX_LOCK) {
                goto illegal_op;
            }
            tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_regs[R_ECX]);
            gen_helper_rdpkru(cpu_tmp1_i64, cpu_env, cpu_tmp2_i32);
            tcg_gen_extr_i64_tl(cpu_regs[R_EAX], cpu_regs[R_EDX], cpu_tmp1_i64);
            break;
        case 0xef: /* wrpkru */
            if (prefixes & PREFIX_LOCK) {
                goto illegal_op;
            }
            tcg_gen_concat_tl_i64(cpu_tmp1_i64, cpu_regs[R_EAX],
                                  cpu_regs[R_EDX]);
            tcg_gen_trunc_tl_i32(cpu_tmp2_i32, cpu_regs[R_ECX]);
            gen_helper_wrpkru(cpu_env, cpu_tmp2_i32, cpu_tmp1_i64);
            break;
        CASE_MODRM_OP(6): /* lmsw */
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            gen_svm_check_intercept(s, pc_start, SVM_EXIT_WRITE_CR0);
            gen_ldst_modrm(env, s, modrm, MO_16, OR_TMP0, 0);
            gen_helper_lmsw(cpu_env, cpu_T0);
            gen_jmp_im(s->pc - s->cs_base);
            gen_eob(s);
            break;

        CASE_MODRM_MEM_OP(7): /* invlpg */
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            gen_update_cc_op(s);
            gen_jmp_im(pc_start - s->cs_base);
            gen_lea_modrm(env, s, modrm);
            gen_helper_invlpg(cpu_env, cpu_A0);
            gen_jmp_im(s->pc - s->cs_base);
            gen_eob(s);
            break;

        case 0xf8: /* swapgs */
#ifdef TARGET_X86_64
            if (CODE64(s)) {
                if (s->cpl != 0) {
                    gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                } else {
                    tcg_gen_mov_tl(cpu_T0, cpu_seg_base[R_GS]);
                    tcg_gen_ld_tl(cpu_seg_base[R_GS], cpu_env,
                                  offsetof(CPUX86State, kernelgsbase));
                    tcg_gen_st_tl(cpu_T0, cpu_env,
                                  offsetof(CPUX86State, kernelgsbase));
                }
                break;
            }
#endif
            goto illegal_op;

        case 0xf9: /* rdtscp */
            if (!(s->cpuid_ext2_features & CPUID_EXT2_RDTSCP)) {
                goto illegal_op;
            }
            gen_update_cc_op(s);
            gen_jmp_im(pc_start - s->cs_base);
            if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
                gen_io_start();
            }
            gen_helper_rdtscp(cpu_env);
            if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
                gen_io_end();
                gen_jmp(s, s->pc - s->cs_base);
            }
            break;

        default:
            goto unknown_op;
        }
        break;

    case 0x108: /* invd */
    case 0x109: /* wbinvd */
        if (s->cpl != 0) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            gen_svm_check_intercept(s, pc_start, (b & 2) ? SVM_EXIT_INVD : SVM_EXIT_WBINVD);
            /* nothing to do */
        }
        break;
    case 0x63: /* arpl or movslS (x86_64) */
#ifdef TARGET_X86_64
        if (CODE64(s)) {
            int d_ot;
            /* d_ot is the size of destination */
            d_ot = dflag;

            modrm = x86_ldub_code(env, s);
            reg = ((modrm >> 3) & 7) | rex_r;
            mod = (modrm >> 6) & 3;
            rm = (modrm & 7) | REX_B(s);

            if (mod == 3) {
                gen_op_mov_v_reg(MO_32, cpu_T0, rm);
                /* sign extend */
                if (d_ot == MO_64) {
                    tcg_gen_ext32s_tl(cpu_T0, cpu_T0);
                }
                gen_op_mov_reg_v((TCGMemOp)d_ot, reg, cpu_T0);
            } else {
                gen_lea_modrm(env, s, modrm);
                gen_op_ld_v(s, MO_32 | MO_SIGN, cpu_T0, cpu_A0);
                gen_op_mov_reg_v((TCGMemOp)d_ot, reg, cpu_T0);
            }
        } else
#endif
        {
            TCGLabel *label1;
            TCGv t0, t1, t2, a0;

            if (!s->pe || s->vm86)
                goto illegal_op;
            t0 = tcg_temp_local_new();
            t1 = tcg_temp_local_new();
            t2 = tcg_temp_local_new();
            ot = MO_16;
            modrm = x86_ldub_code(env, s);
            reg = (modrm >> 3) & 7;
            mod = (modrm >> 6) & 3;
            rm = modrm & 7;
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_op_ld_v(s, ot, t0, cpu_A0);
                a0 = tcg_temp_local_new();
                tcg_gen_mov_tl(a0, cpu_A0);
            } else {
                gen_op_mov_v_reg(ot, t0, rm);
                TCGV_UNUSED(a0);
            }
            gen_op_mov_v_reg(ot, t1, reg);
            tcg_gen_andi_tl(cpu_tmp0, t0, 3);
            tcg_gen_andi_tl(t1, t1, 3);
            tcg_gen_movi_tl(t2, 0);
            label1 = gen_new_label();
            tcg_gen_brcond_tl(TCG_COND_GE, cpu_tmp0, t1, label1);
            tcg_gen_andi_tl(t0, t0, ~3);
            tcg_gen_or_tl(t0, t0, t1);
            tcg_gen_movi_tl(t2, CC_Z);
            gen_set_label(label1);
            if (mod != 3) {
                gen_op_st_v(s, ot, t0, a0);
                tcg_temp_free(a0);
           } else {
                gen_op_mov_reg_v(ot, rm, t0);
            }
            gen_compute_eflags(s);
            tcg_gen_andi_tl(cpu_cc_src, cpu_cc_src, ~CC_Z);
            tcg_gen_or_tl(cpu_cc_src, cpu_cc_src, t2);
            tcg_temp_free(t0);
            tcg_temp_free(t1);
            tcg_temp_free(t2);
        }
        break;
    case 0x102: /* lar */
    case 0x103: /* lsl */
        {
            TCGLabel *label1;
            TCGv t0;
            if (!s->pe || s->vm86)
                goto illegal_op;
            ot = dflag != MO_16 ? MO_32 : MO_16;
            modrm = x86_ldub_code(env, s);
            reg = ((modrm >> 3) & 7) | rex_r;
            gen_ldst_modrm(env, s, modrm, MO_16, OR_TMP0, 0);
            t0 = tcg_temp_local_new();
            gen_update_cc_op(s);
            if (b == 0x102) {
                gen_helper_lar(t0, cpu_env, cpu_T0);
            } else {
                gen_helper_lsl(t0, cpu_env, cpu_T0);
            }
            tcg_gen_andi_tl(cpu_tmp0, cpu_cc_src, CC_Z);
            label1 = gen_new_label();
            tcg_gen_brcondi_tl(TCG_COND_EQ, cpu_tmp0, 0, label1);
            gen_op_mov_reg_v(ot, reg, t0);
            gen_set_label(label1);
            set_cc_op(s, CC_OP_EFLAGS);
            tcg_temp_free(t0);
        }
        break;
    case 0x118:
        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        op = (modrm >> 3) & 7;
        switch(op) {
        case 0: /* prefetchnta */
        case 1: /* prefetchnt0 */
        case 2: /* prefetchnt0 */
        case 3: /* prefetchnt0 */
            if (mod == 3)
                goto illegal_op;
            gen_nop_modrm(env, s, modrm);
            /* nothing more to do */
            break;
        default: /* nop (multi byte) */
            gen_nop_modrm(env, s, modrm);
            break;
        }
        break;
    case 0x11a:
        modrm = x86_ldub_code(env, s);
        if (s->flags & HF_MPX_EN_MASK) {
            mod = (modrm >> 6) & 3;
            reg = ((modrm >> 3) & 7) | rex_r;
            if (prefixes & PREFIX_REPZ) {
                /* bndcl */
                if (reg >= 4
                    || (prefixes & PREFIX_LOCK)
                    || s->aflag == MO_16) {
                    goto illegal_op;
                }
                gen_bndck(env, s, modrm, TCG_COND_LTU, cpu_bndl[reg]);
            } else if (prefixes & PREFIX_REPNZ) {
                /* bndcu */
                if (reg >= 4
                    || (prefixes & PREFIX_LOCK)
                    || s->aflag == MO_16) {
                    goto illegal_op;
                }
                TCGv_i64 notu = tcg_temp_new_i64();
                tcg_gen_not_i64(notu, cpu_bndu[reg]);
                gen_bndck(env, s, modrm, TCG_COND_GTU, notu);
                tcg_temp_free_i64(notu);
            } else if (prefixes & PREFIX_DATA) {
                /* bndmov -- from reg/mem */
                if (reg >= 4 || s->aflag == MO_16) {
                    goto illegal_op;
                }
                if (mod == 3) {
                    int reg2 = (modrm & 7) | REX_B(s);
                    if (reg2 >= 4 || (prefixes & PREFIX_LOCK)) {
                        goto illegal_op;
                    }
                    if (s->flags & HF_MPX_IU_MASK) {
                        tcg_gen_mov_i64(cpu_bndl[reg], cpu_bndl[reg2]);
                        tcg_gen_mov_i64(cpu_bndu[reg], cpu_bndu[reg2]);
                    }
                } else {
                    gen_lea_modrm(env, s, modrm);
                    if (CODE64(s)) {
                        tcg_gen_qemu_ld_i64(cpu_bndl[reg], cpu_A0,
                                            s->mem_index, MO_LEQ);
                        tcg_gen_addi_tl(cpu_A0, cpu_A0, 8);
                        tcg_gen_qemu_ld_i64(cpu_bndu[reg], cpu_A0,
                                            s->mem_index, MO_LEQ);
                    } else {
                        tcg_gen_qemu_ld_i64(cpu_bndl[reg], cpu_A0,
                                            s->mem_index, MO_LEUL);
                        tcg_gen_addi_tl(cpu_A0, cpu_A0, 4);
                        tcg_gen_qemu_ld_i64(cpu_bndu[reg], cpu_A0,
                                            s->mem_index, MO_LEUL);
                    }
                    /* bnd registers are now in-use */
                    gen_set_hflag(s, HF_MPX_IU_MASK);
                }
            } else if (mod != 3) {
                /* bndldx */
                AddressParts a = gen_lea_modrm_0(env, s, modrm);
                if (reg >= 4
                    || (prefixes & PREFIX_LOCK)
                    || s->aflag == MO_16
                    || a.base < -1) {
                    goto illegal_op;
                }
                if (a.base >= 0) {
                    tcg_gen_addi_tl(cpu_A0, cpu_regs[a.base], a.disp);
                } else {
                    tcg_gen_movi_tl(cpu_A0, 0);
                }
                gen_lea_v_seg(s, s->aflag, cpu_A0, a.def_seg, s->override);
                if (a.index >= 0) {
                    tcg_gen_mov_tl(cpu_T0, cpu_regs[a.index]);
                } else {
                    tcg_gen_movi_tl(cpu_T0, 0);
                }
                if (CODE64(s)) {
                    gen_helper_bndldx64(cpu_bndl[reg], cpu_env, cpu_A0, cpu_T0);
                    tcg_gen_ld_i64(cpu_bndu[reg], cpu_env,
                                   offsetof(CPUX86State, mmx_t0.MMX_Q(0)));
                } else {
                    gen_helper_bndldx32(cpu_bndu[reg], cpu_env, cpu_A0, cpu_T0);
                    tcg_gen_ext32u_i64(cpu_bndl[reg], cpu_bndu[reg]);
                    tcg_gen_shri_i64(cpu_bndu[reg], cpu_bndu[reg], 32);
                }
                gen_set_hflag(s, HF_MPX_IU_MASK);
            }
        }
        gen_nop_modrm(env, s, modrm);
        break;
    case 0x11b:
        modrm = x86_ldub_code(env, s);
        if (s->flags & HF_MPX_EN_MASK) {
            mod = (modrm >> 6) & 3;
            reg = ((modrm >> 3) & 7) | rex_r;
            if (mod != 3 && (prefixes & PREFIX_REPZ)) {
                /* bndmk */
                if (reg >= 4
                    || (prefixes & PREFIX_LOCK)
                    || s->aflag == MO_16) {
                    goto illegal_op;
                }
                AddressParts a = gen_lea_modrm_0(env, s, modrm);
                if (a.base >= 0) {
                    tcg_gen_extu_tl_i64(cpu_bndl[reg], cpu_regs[a.base]);
                    if (!CODE64(s)) {
                        tcg_gen_ext32u_i64(cpu_bndl[reg], cpu_bndl[reg]);
                    }
                } else if (a.base == -1) {
                    /* no base register has lower bound of 0 */
                    tcg_gen_movi_i64(cpu_bndl[reg], 0);
                } else {
                    /* rip-relative generates #ud */
                    goto illegal_op;
                }
                tcg_gen_not_tl(cpu_A0, gen_lea_modrm_1(a));
                if (!CODE64(s)) {
                    tcg_gen_ext32u_tl(cpu_A0, cpu_A0);
                }
                tcg_gen_extu_tl_i64(cpu_bndu[reg], cpu_A0);
                /* bnd registers are now in-use */
                gen_set_hflag(s, HF_MPX_IU_MASK);
                break;
            } else if (prefixes & PREFIX_REPNZ) {
                /* bndcn */
                if (reg >= 4
                    || (prefixes & PREFIX_LOCK)
                    || s->aflag == MO_16) {
                    goto illegal_op;
                }
                gen_bndck(env, s, modrm, TCG_COND_GTU, cpu_bndu[reg]);
            } else if (prefixes & PREFIX_DATA) {
                /* bndmov -- to reg/mem */
                if (reg >= 4 || s->aflag == MO_16) {
                    goto illegal_op;
                }
                if (mod == 3) {
                    int reg2 = (modrm & 7) | REX_B(s);
                    if (reg2 >= 4 || (prefixes & PREFIX_LOCK)) {
                        goto illegal_op;
                    }
                    if (s->flags & HF_MPX_IU_MASK) {
                        tcg_gen_mov_i64(cpu_bndl[reg2], cpu_bndl[reg]);
                        tcg_gen_mov_i64(cpu_bndu[reg2], cpu_bndu[reg]);
                    }
                } else {
                    gen_lea_modrm(env, s, modrm);
                    if (CODE64(s)) {
                        tcg_gen_qemu_st_i64(cpu_bndl[reg], cpu_A0,
                                            s->mem_index, MO_LEQ);
                        tcg_gen_addi_tl(cpu_A0, cpu_A0, 8);
                        tcg_gen_qemu_st_i64(cpu_bndu[reg], cpu_A0,
                                            s->mem_index, MO_LEQ);
                    } else {
                        tcg_gen_qemu_st_i64(cpu_bndl[reg], cpu_A0,
                                            s->mem_index, MO_LEUL);
                        tcg_gen_addi_tl(cpu_A0, cpu_A0, 4);
                        tcg_gen_qemu_st_i64(cpu_bndu[reg], cpu_A0,
                                            s->mem_index, MO_LEUL);
                    }
                }
            } else if (mod != 3) {
                /* bndstx */
                AddressParts a = gen_lea_modrm_0(env, s, modrm);
                if (reg >= 4
                    || (prefixes & PREFIX_LOCK)
                    || s->aflag == MO_16
                    || a.base < -1) {
                    goto illegal_op;
                }
                if (a.base >= 0) {
                    tcg_gen_addi_tl(cpu_A0, cpu_regs[a.base], a.disp);
                } else {
                    tcg_gen_movi_tl(cpu_A0, 0);
                }
                gen_lea_v_seg(s, s->aflag, cpu_A0, a.def_seg, s->override);
                if (a.index >= 0) {
                    tcg_gen_mov_tl(cpu_T0, cpu_regs[a.index]);
                } else {
                    tcg_gen_movi_tl(cpu_T0, 0);
                }
                if (CODE64(s)) {
                    gen_helper_bndstx64(cpu_env, cpu_A0, cpu_T0,
                                        cpu_bndl[reg], cpu_bndu[reg]);
                } else {
                    gen_helper_bndstx32(cpu_env, cpu_A0, cpu_T0,
                                        cpu_bndl[reg], cpu_bndu[reg]);
                }
            }
        }
        gen_nop_modrm(env, s, modrm);
        break;
    case 0x119: case 0x11c ... 0x11f: /* nop (multi byte) */
        modrm = x86_ldub_code(env, s);
        gen_nop_modrm(env, s, modrm);
        break;
    case 0x120: /* mov reg, crN */
    case 0x122: /* mov crN, reg */
        if (s->cpl != 0) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            modrm = x86_ldub_code(env, s);
            /* Ignore the mod bits (assume (modrm&0xc0)==0xc0).
             * AMD documentation (24594.pdf) and testing of
             * intel 386 and 486 processors all show that the mod bits
             * are assumed to be 1's, regardless of actual values.
             */
            rm = (modrm & 7) | REX_B(s);
            reg = ((modrm >> 3) & 7) | rex_r;
            if (CODE64(s))
                ot = MO_64;
            else
                ot = MO_32;
            if ((prefixes & PREFIX_LOCK) && (reg == 0) &&
                (s->cpuid_ext3_features & CPUID_EXT3_CR8LEG)) {
                reg = 8;
            }
            switch(reg) {
            case 0:
            case 2:
            case 3:
            case 4:
            case 8:
                gen_update_cc_op(s);
                gen_jmp_im(pc_start - s->cs_base);
                if (b & 2) {
                    if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
                        gen_io_start();
                    }
                    gen_op_mov_v_reg(ot, cpu_T0, rm);
                    gen_helper_write_crN(cpu_env, tcg_const_i32(reg),
                                         cpu_T0);
                    if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
                        gen_io_end();
                    }
                    gen_jmp_im(s->pc - s->cs_base);
                    gen_eob(s);
                } else {
                    if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
                        gen_io_start();
                    }
                    gen_helper_read_crN(cpu_T0, cpu_env, tcg_const_i32(reg));
                    gen_op_mov_reg_v(ot, rm, cpu_T0);
                    if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
                        gen_io_end();
                    }
                }
                break;
            default:
                goto unknown_op;
            }
        }
        break;
    case 0x121: /* mov reg, drN */
    case 0x123: /* mov drN, reg */
        if (s->cpl != 0) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            modrm = x86_ldub_code(env, s);
            /* Ignore the mod bits (assume (modrm&0xc0)==0xc0).
             * AMD documentation (24594.pdf) and testing of
             * intel 386 and 486 processors all show that the mod bits
             * are assumed to be 1's, regardless of actual values.
             */
            rm = (modrm & 7) | REX_B(s);
            reg = ((modrm >> 3) & 7) | rex_r;
            if (CODE64(s))
                ot = MO_64;
            else
                ot = MO_32;
            if (reg >= 8) {
                goto illegal_op;
            }
            if (b & 2) {
                gen_svm_check_intercept(s, pc_start, SVM_EXIT_WRITE_DR0 + reg);
                gen_op_mov_v_reg(ot, cpu_T0, rm);
                tcg_gen_movi_i32(cpu_tmp2_i32, reg);
                gen_helper_set_dr(cpu_env, cpu_tmp2_i32, cpu_T0);
                gen_jmp_im(s->pc - s->cs_base);
                gen_eob(s);
            } else {
                gen_svm_check_intercept(s, pc_start, SVM_EXIT_READ_DR0 + reg);
                tcg_gen_movi_i32(cpu_tmp2_i32, reg);
                gen_helper_get_dr(cpu_T0, cpu_env, cpu_tmp2_i32);
                gen_op_mov_reg_v(ot, rm, cpu_T0);
            }
        }
        break;
    case 0x106: /* clts */
        if (s->cpl != 0) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            gen_svm_check_intercept(s, pc_start, SVM_EXIT_WRITE_CR0);
            gen_helper_clts(cpu_env);
            /* abort block because static cpu state changed */
            gen_jmp_im(s->pc - s->cs_base);
            gen_eob(s);
        }
        break;
    /* MMX/3DNow!/SSE/SSE2/SSE3/SSSE3/SSE4 support */
    case 0x1c3: /* MOVNTI reg, mem */
        if (!(s->cpuid_features & CPUID_SSE2))
            goto illegal_op;
        ot = mo_64_32(dflag);
        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        if (mod == 3)
            goto illegal_op;
        reg = ((modrm >> 3) & 7) | rex_r;
        /* generate a generic store */
        gen_ldst_modrm(env, s, modrm, ot, reg, 1);
        break;
    case 0x1ae:
        modrm = x86_ldub_code(env, s);
        switch (modrm) {
        CASE_MODRM_MEM_OP(0): /* fxsave */
            if (!(s->cpuid_features & CPUID_FXSR)
                || (prefixes & PREFIX_LOCK)) {
                goto illegal_op;
            }
            if ((s->flags & HF_EM_MASK) || (s->flags & HF_TS_MASK)) {
                gen_exception(s, EXCP07_PREX, pc_start - s->cs_base);
                break;
            }
            gen_lea_modrm(env, s, modrm);
            gen_helper_fxsave(cpu_env, cpu_A0);
            break;

        CASE_MODRM_MEM_OP(1): /* fxrstor */
            if (!(s->cpuid_features & CPUID_FXSR)
                || (prefixes & PREFIX_LOCK)) {
                goto illegal_op;
            }
            if ((s->flags & HF_EM_MASK) || (s->flags & HF_TS_MASK)) {
                gen_exception(s, EXCP07_PREX, pc_start - s->cs_base);
                break;
            }
            gen_lea_modrm(env, s, modrm);
            gen_helper_fxrstor(cpu_env, cpu_A0);
            break;

        CASE_MODRM_MEM_OP(2): /* ldmxcsr */
            if ((s->flags & HF_EM_MASK) || !(s->flags & HF_OSFXSR_MASK)) {
                goto illegal_op;
            }
            if (s->flags & HF_TS_MASK) {
                gen_exception(s, EXCP07_PREX, pc_start - s->cs_base);
                break;
            }
            gen_lea_modrm(env, s, modrm);
            tcg_gen_qemu_ld_i32(cpu_tmp2_i32, cpu_A0, s->mem_index, MO_LEUL);
            gen_helper_ldmxcsr(cpu_env, cpu_tmp2_i32);
            break;

        CASE_MODRM_MEM_OP(3): /* stmxcsr */
            if ((s->flags & HF_EM_MASK) || !(s->flags & HF_OSFXSR_MASK)) {
                goto illegal_op;
            }
            if (s->flags & HF_TS_MASK) {
                gen_exception(s, EXCP07_PREX, pc_start - s->cs_base);
                break;
            }
            gen_lea_modrm(env, s, modrm);
            tcg_gen_ld32u_tl(cpu_T0, cpu_env, offsetof(CPUX86State, mxcsr));
            gen_op_st_v(s, MO_32, cpu_T0, cpu_A0);
            break;

        CASE_MODRM_MEM_OP(4): /* xsave */
            if ((s->cpuid_ext_features & CPUID_EXT_XSAVE) == 0
                || (prefixes & (PREFIX_LOCK | PREFIX_DATA
                                | PREFIX_REPZ | PREFIX_REPNZ))) {
                goto illegal_op;
            }
            gen_lea_modrm(env, s, modrm);
            tcg_gen_concat_tl_i64(cpu_tmp1_i64, cpu_regs[R_EAX],
                                  cpu_regs[R_EDX]);
            gen_helper_xsave(cpu_env, cpu_A0, cpu_tmp1_i64);
            break;

        CASE_MODRM_MEM_OP(5): /* xrstor */
            if ((s->cpuid_ext_features & CPUID_EXT_XSAVE) == 0
                || (prefixes & (PREFIX_LOCK | PREFIX_DATA
                                | PREFIX_REPZ | PREFIX_REPNZ))) {
                goto illegal_op;
            }
            gen_lea_modrm(env, s, modrm);
            tcg_gen_concat_tl_i64(cpu_tmp1_i64, cpu_regs[R_EAX],
                                  cpu_regs[R_EDX]);
            gen_helper_xrstor(cpu_env, cpu_A0, cpu_tmp1_i64);
            /* XRSTOR is how MPX is enabled, which changes how
               we translate.  Thus we need to end the TB.  */
            gen_update_cc_op(s);
            gen_jmp_im(s->pc - s->cs_base);
            gen_eob(s);
            break;

        CASE_MODRM_MEM_OP(6): /* xsaveopt / clwb */
            if (prefixes & PREFIX_LOCK) {
                goto illegal_op;
            }
            if (prefixes & PREFIX_DATA) {
                /* clwb */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_CLWB)) {
                    goto illegal_op;
                }
                gen_nop_modrm(env, s, modrm);
            } else {
                /* xsaveopt */
                if ((s->cpuid_ext_features & CPUID_EXT_XSAVE) == 0
                    || (s->cpuid_xsave_features & CPUID_XSAVE_XSAVEOPT) == 0
                    || (prefixes & (PREFIX_REPZ | PREFIX_REPNZ))) {
                    goto illegal_op;
                }
                gen_lea_modrm(env, s, modrm);
                tcg_gen_concat_tl_i64(cpu_tmp1_i64, cpu_regs[R_EAX],
                                      cpu_regs[R_EDX]);
                gen_helper_xsaveopt(cpu_env, cpu_A0, cpu_tmp1_i64);
            }
            break;

        CASE_MODRM_MEM_OP(7): /* clflush / clflushopt */
            if (prefixes & PREFIX_LOCK) {
                goto illegal_op;
            }
            if (prefixes & PREFIX_DATA) {
                /* clflushopt */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_CLFLUSHOPT)) {
                    goto illegal_op;
                }
            } else {
                /* clflush */
                if ((s->prefix & (PREFIX_REPZ | PREFIX_REPNZ))
                    || !(s->cpuid_features & CPUID_CLFLUSH)) {
                    goto illegal_op;
                }
            }
            gen_nop_modrm(env, s, modrm);
            break;

        case 0xc0 ... 0xc7: /* rdfsbase (f3 0f ae /0) */
        case 0xc8 ... 0xcf: /* rdgsbase (f3 0f ae /1) */
        case 0xd0 ... 0xd7: /* wrfsbase (f3 0f ae /2) */
        case 0xd8 ... 0xdf: /* wrgsbase (f3 0f ae /3) */
            if (CODE64(s)
                && (prefixes & PREFIX_REPZ)
                && !(prefixes & PREFIX_LOCK)
                && (s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_FSGSBASE)) {
                TCGv base, treg, src, dst;

                /* Preserve hflags bits by testing CR4 at runtime.  */
                tcg_gen_movi_i32(cpu_tmp2_i32, CR4_FSGSBASE_MASK);
                gen_helper_cr4_testbit(cpu_env, cpu_tmp2_i32);

                base = cpu_seg_base[modrm & 8 ? R_GS : R_FS];
                treg = cpu_regs[(modrm & 7) | REX_B(s)];

                if (modrm & 0x10) {
                    /* wr*base */
                    dst = base, src = treg;
                } else {
                    /* rd*base */
                    dst = treg, src = base;
                }

                if (s->dflag == MO_32) {
                    tcg_gen_ext32u_tl(dst, src);
                } else {
                    tcg_gen_mov_tl(dst, src);
                }
                break;
            }
            goto unknown_op;

        case 0xf8: /* sfence / pcommit */
            if (prefixes & PREFIX_DATA) {
                /* pcommit */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_PCOMMIT)
                    || (prefixes & PREFIX_LOCK)) {
                    goto illegal_op;
                }
                break;
            }
            /* fallthru */
        case 0xf9 ... 0xff: /* sfence */
            if (!(s->cpuid_features & CPUID_SSE)
                || (prefixes & PREFIX_LOCK)) {
                goto illegal_op;
            }
            tcg_gen_mb((TCGBar)(TCG_MO_ST_ST | TCG_BAR_SC));
            break;
        case 0xe8 ... 0xef: /* lfence */
            if (!(s->cpuid_features & CPUID_SSE)
                || (prefixes & PREFIX_LOCK)) {
                goto illegal_op;
            }
            tcg_gen_mb((TCGBar)(TCG_MO_LD_LD | TCG_BAR_SC));
            break;
        case 0xf0 ... 0xf7: /* mfence */
            if (!(s->cpuid_features & CPUID_SSE2)
                || (prefixes & PREFIX_LOCK)) {
                goto illegal_op;
            }
            tcg_gen_mb((TCGBar)(TCG_MO_ALL | TCG_BAR_SC));
            break;

        default:
            goto unknown_op;
        }
        break;

    case 0x10d: /* 3DNow! prefetch(w) */
        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        if (mod == 3)
            goto illegal_op;
        gen_nop_modrm(env, s, modrm);
        break;
    case 0x1aa: /* rsm */
        gen_svm_check_intercept(s, pc_start, SVM_EXIT_RSM);
        if (!(s->flags & HF_SMM_MASK))
            goto illegal_op;
        gen_update_cc_op(s);
        gen_jmp_im(s->pc - s->cs_base);
        gen_helper_rsm(cpu_env);
        gen_eob(s);
        break;
    case 0x1b8: /* SSE4.2 popcnt */
        if ((prefixes & (PREFIX_REPZ | PREFIX_LOCK | PREFIX_REPNZ)) !=
             PREFIX_REPZ)
            goto illegal_op;
        if (!(s->cpuid_ext_features & CPUID_EXT_POPCNT))
            goto illegal_op;

        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;

        if (s->prefix & PREFIX_DATA) {
            ot = MO_16;
        } else {
            ot = mo_64_32(dflag);
        }

        gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
        gen_extu(ot, cpu_T0);
        tcg_gen_mov_tl(cpu_cc_src, cpu_T0);
        tcg_gen_ctpop_tl(cpu_T0, cpu_T0);
        gen_op_mov_reg_v(ot, reg, cpu_T0);

        set_cc_op(s, CC_OP_POPCNT);
        break;
    case 0x10e ... 0x10f:
        /* 3DNow! instructions, ignore prefixes */
        s->prefix &= ~(PREFIX_REPZ | PREFIX_REPNZ | PREFIX_DATA);
    case 0x110 ... 0x117:
    case 0x128 ... 0x12f:
    case 0x138 ... 0x13a:
    case 0x150 ... 0x179:
    case 0x17c ... 0x17f:
    case 0x1c2:
    case 0x1c4 ... 0x1c6:
    case 0x1d0 ... 0x1fe:
        gen_sse(env, s, b, pc_start, rex_r);
        break;
    default:
        goto unknown_op;
    }
    return s->pc;
 illegal_op:
    gen_illegal_opcode(s);
    return s->pc;
 unknown_op:
    gen_unknown_opcode(env, s);
    return s->pc;
}

static int i386_tr_init_disas_context(DisasContextBase *dcbase, CPUState *cpu,
                                      int max_insns)
{
    DisasContext *dc = container_of(dcbase, DisasContext, base);
    CPUX86State *env = (CPUX86State *)cpu->env_ptr;
    uint32_t flags = dc->base.tb->flags;
    target_ulong cs_base = dc->base.tb->cs_base;

    dc->pe = (flags >> HF_PE_SHIFT) & 1;
    dc->code32 = (flags >> HF_CS32_SHIFT) & 1;
    dc->ss32 = (flags >> HF_SS32_SHIFT) & 1;
    dc->addseg = (flags >> HF_ADDSEG_SHIFT) & 1;
    dc->f_st = 0;
    dc->vm86 = (flags >> VM_SHIFT) & 1;
    dc->cpl = (flags >> HF_CPL_SHIFT) & 3;
    dc->iopl = (flags >> IOPL_SHIFT) & 3;
    dc->tf = (flags >> TF_SHIFT) & 1;
    dc->cc_op = CC_OP_DYNAMIC;
    dc->cc_op_dirty = false;
    dc->cs_base = cs_base;
    dc->popl_esp_hack = 0;
    /* select memory access functions */
    dc->mem_index = 0;
#ifdef CONFIG_SOFTMMU
    dc->mem_index = cpu_mmu_index(env, false);
#endif
    dc->cpuid_features = env->features[FEAT_1_EDX];
    dc->cpuid_ext_features = env->features[FEAT_1_ECX];
    dc->cpuid_ext2_features = env->features[FEAT_8000_0001_EDX];
    dc->cpuid_ext3_features = env->features[FEAT_8000_0001_ECX];
    dc->cpuid_7_0_ebx_features = env->features[FEAT_7_0_EBX];
    dc->cpuid_xsave_features = env->features[FEAT_XSAVE];
#ifdef TARGET_X86_64
    dc->lma = (flags >> HF_LMA_SHIFT) & 1;
    dc->code64 = (flags >> HF_CS64_SHIFT) & 1;
#endif
    dc->flags = flags;
    dc->jmp_opt = !(dc->tf || dc->base.singlestep_enabled ||
                    (flags & HF_INHIBIT_IRQ_MASK));
    /* Do not optimize repz jumps at all in icount mode, because
       rep movsS instructions are execured with different paths
       in !repz_opt and repz_opt modes. The first one was used
       always except single step mode. And this setting
       disables jumps optimization and control paths become
       equivalent in run and single step modes.
       Now there will be no jump optimization for repz in
       record/replay modes and there will always be an
       additional step for ecx=0 when icount is enabled.
     */
    dc->repz_opt = !dc->jmp_opt && !(tb_cflags(dc->base.tb) & CF_USE_ICOUNT);
#if 0
    /* check addseg logic */
    if (!dc->addseg && (dc->vm86 || !dc->pe || !dc->code32))
        printf("ERROR addseg\n");
#endif

    cpu_T0 = tcg_temp_new();
    cpu_T1 = tcg_temp_new();
    cpu_A0 = tcg_temp_new();

    cpu_tmp0 = tcg_temp_new();
    cpu_tmp1_i64 = tcg_temp_new_i64();
    cpu_tmp2_i32 = tcg_temp_new_i32();
    cpu_tmp3_i32 = tcg_temp_new_i32();
    cpu_tmp4 = tcg_temp_new();
    cpu_ptr0 = tcg_temp_new_ptr();
    cpu_ptr1 = tcg_temp_new_ptr();
    cpu_cc_srcT = tcg_temp_local_new();

    return max_insns;
}

static void i386_tr_tb_start(DisasContextBase *db, CPUState *cpu)
{
}

static void i386_tr_insn_start(DisasContextBase *dcbase, CPUState *cpu)
{
    DisasContext *dc = container_of(dcbase, DisasContext, base);

    tcg_gen_insn_start(dc->base.pc_next, dc->cc_op);
}

static bool i386_tr_breakpoint_check(DisasContextBase *dcbase, CPUState *cpu,
                                     const CPUBreakpoint *bp)
{
    DisasContext *dc = container_of(dcbase, DisasContext, base);
    /* If RF is set, suppress an internally generated breakpoint.  */
    int flags = dc->base.tb->flags & HF_RF_MASK ? BP_GDB : BP_ANY;
    if (bp->flags & flags) {
        gen_debug(dc, dc->base.pc_next - dc->cs_base);
        dc->base.is_jmp = DISAS_NORETURN;
        /* The address covered by the breakpoint must be included in
           [tb->pc, tb->pc + tb->size) in order to for it to be
           properly cleared -- thus we increment the PC here so that
           the generic logic setting tb->size later does the right thing.  */
        dc->base.pc_next += 1;
        return true;
    } else {
        return false;
    }
}

static void i386_tr_translate_insn(DisasContextBase *dcbase, CPUState *cpu)
{
    DisasContext *dc = container_of(dcbase, DisasContext, base);
    target_ulong pc_next = disas_insn(dc, cpu);

    if (dc->tf || (dc->base.tb->flags & HF_INHIBIT_IRQ_MASK)) {
        /* if single step mode, we generate only one instruction and
           generate an exception */
        /* if irq were inhibited with HF_INHIBIT_IRQ_MASK, we clear
           the flag and abort the translation to give the irqs a
           chance to happen */
        dc->base.is_jmp = DISAS_TOO_MANY;
    } else if ((tb_cflags(dc->base.tb) & CF_USE_ICOUNT)
               && ((dc->base.pc_next & TARGET_PAGE_MASK)
                   != ((dc->base.pc_next + TARGET_MAX_INSN_SIZE - 1)
                       & TARGET_PAGE_MASK)
                   || (dc->base.pc_next & ~TARGET_PAGE_MASK) == 0)) {
        /* Do not cross the boundary of the pages in icount mode,
           it can cause an exception. Do it only when boundary is
           crossed by the first instruction in the block.
           If current instruction already crossed the bound - it's ok,
           because an exception hasn't stopped this code.
         */
        dc->base.is_jmp = DISAS_TOO_MANY;
    } else if ((pc_next - dc->base.pc_first) >= (TARGET_PAGE_SIZE - 32)) {
        dc->base.is_jmp = DISAS_TOO_MANY;
    }

    dc->base.pc_next = pc_next;
}

static void i386_tr_tb_stop(DisasContextBase *dcbase, CPUState *cpu)
{
    DisasContext *dc = container_of(dcbase, DisasContext, base);

    if (dc->base.is_jmp == DISAS_TOO_MANY) {
        gen_jmp_im(dc->base.pc_next - dc->cs_base);
        gen_eob(dc);
    }
}

static void i386_tr_disas_log(const DisasContextBase *dcbase,
                              CPUState *cpu)
{
    DisasContext *dc = container_of(dcbase, DisasContext, base);

    qemu_log("IN: %s\n", lookup_symbol(dc->base.pc_first));
    log_target_disas(cpu, dc->base.pc_first, dc->base.tb->size);
}

static const TranslatorOps i386_tr_ops = {
    .init_disas_context = i386_tr_init_disas_context,
    .tb_start           = i386_tr_tb_start,
    .insn_start         = i386_tr_insn_start,
    .breakpoint_check   = i386_tr_breakpoint_check,
    .translate_insn     = i386_tr_translate_insn,
    .tb_stop            = i386_tr_tb_stop,
    .disas_log          = i386_tr_disas_log,
};

void gen_intermediate_code(CPUState *cpu, TranslationBlock *tb)
{
    DisasContext dc;

    translator_loop(&i386_tr_ops, &dc.base, cpu, tb);
}

static TCGContext **tcg_ctxs;

static unsigned int n_tcg_ctxs;

TCGv_env cpu_env = 0;

static TCGRegSet tcg_target_available_regs[2];

static TCGRegSet tcg_target_call_clobber_regs;

TCGLabel *gen_new_label(void)
{
    TCGContext *s = tcg_ctx;
    TCGLabel *l = (TCGLabel *)tcg_malloc(sizeof(TCGLabel));

    *l = (TCGLabel){
        .id = (unsigned)s->nb_labels++
    };

    return l;
}

static const int tcg_target_reg_alloc_order[] = {
#if TCG_TARGET_REG_BITS == 64
    TCG_REG_RBP,
    TCG_REG_RBX,
    TCG_REG_R12,
    TCG_REG_R13,
    TCG_REG_R14,
    TCG_REG_R15,
    TCG_REG_R10,
    TCG_REG_R11,
    TCG_REG_R9,
    TCG_REG_R8,
    TCG_REG_RCX,
    TCG_REG_RDX,
    TCG_REG_RSI,
    TCG_REG_RDI,
    TCG_REG_RAX,
#else
    TCG_REG_EBX,
    TCG_REG_ESI,
    TCG_REG_EDI,
    TCG_REG_EBP,
    TCG_REG_ECX,
    TCG_REG_EDX,
    TCG_REG_EAX,
#endif
};

static const int tcg_target_call_iarg_regs[] = {
#if TCG_TARGET_REG_BITS == 64
#if defined(_WIN64)
    TCG_REG_RCX,
    TCG_REG_RDX,
#else
    TCG_REG_RDI,
    TCG_REG_RSI,
    TCG_REG_RDX,
    TCG_REG_RCX,
#endif
    TCG_REG_R8,
    TCG_REG_R9,
#else
    /* 32 bit mode uses stack based calling convention (GCC default). */
#endif
};

#define TCG_CT_CONST_S32 0x100

#define TCG_CT_CONST_U32 0x200

#define TCG_CT_CONST_I32 0x400

#define TCG_CT_CONST_WSZ 0x800

# define TCG_REG_L0 tcg_target_call_iarg_regs[0]

# define TCG_REG_L1 tcg_target_call_iarg_regs[1]

#include <cpuid.h>

# define have_cmov 1

bool have_bmi1;

bool have_popcnt;

static bool have_movbe;

static bool have_bmi2;

static bool have_lzcnt;

static const char *target_parse_constraint(TCGArgConstraint *ct,
                                           const char *ct_str, TCGType type)
{
    switch(*ct_str++) {
    case 'a':
        ct->ct |= TCG_CT_REG;
        tcg_regset_set_reg(ct->u.regs, TCG_REG_EAX);
        break;
    case 'b':
        ct->ct |= TCG_CT_REG;
        tcg_regset_set_reg(ct->u.regs, TCG_REG_EBX);
        break;
    case 'c':
        ct->ct |= TCG_CT_REG;
        tcg_regset_set_reg(ct->u.regs, TCG_REG_ECX);
        break;
    case 'd':
        ct->ct |= TCG_CT_REG;
        tcg_regset_set_reg(ct->u.regs, TCG_REG_EDX);
        break;
    case 'S':
        ct->ct |= TCG_CT_REG;
        tcg_regset_set_reg(ct->u.regs, TCG_REG_ESI);
        break;
    case 'D':
        ct->ct |= TCG_CT_REG;
        tcg_regset_set_reg(ct->u.regs, TCG_REG_EDI);
        break;
    case 'q':
        ct->ct |= TCG_CT_REG;
        ct->u.regs = TCG_TARGET_REG_BITS == 64 ? 0xffff : 0xf;
        break;
    case 'Q':
        ct->ct |= TCG_CT_REG;
        ct->u.regs = 0xf;
        break;
    case 'r':
        ct->ct |= TCG_CT_REG;
        ct->u.regs = TCG_TARGET_REG_BITS == 64 ? 0xffff : 0xff;
        break;
    case 'W':
        /* With TZCNT/LZCNT, we can have operand-size as an input.  */
        ct->ct |= TCG_CT_CONST_WSZ;
        break;

        /* qemu_ld/st address constraint */
    case 'L':
        ct->ct |= TCG_CT_REG;
        ct->u.regs = TCG_TARGET_REG_BITS == 64 ? 0xffff : 0xff;
        tcg_regset_reset_reg(ct->u.regs, TCG_REG_L0);
        tcg_regset_reset_reg(ct->u.regs, TCG_REG_L1);
        break;

    case 'e':
        ct->ct |= (type == TCG_TYPE_I32 ? TCG_CT_CONST : TCG_CT_CONST_S32);
        break;
    case 'Z':
        ct->ct |= (type == TCG_TYPE_I32 ? TCG_CT_CONST : TCG_CT_CONST_U32);
        break;
    case 'I':
        ct->ct |= (type == TCG_TYPE_I32 ? TCG_CT_CONST : TCG_CT_CONST_I32);
        break;

    default:
        return NULL;
    }
    return ct_str;
}

static const TCGTargetOpDef *tcg_target_op_def(TCGOpcode op)
{
    static const TCGTargetOpDef r = { .args_ct_str = { "r" } };
    static const TCGTargetOpDef ri_r = { .args_ct_str = { "ri", "r" } };
    static const TCGTargetOpDef re_r = { .args_ct_str = { "re", "r" } };
    static const TCGTargetOpDef qi_r = { .args_ct_str = { "qi", "r" } };
    static const TCGTargetOpDef r_r = { .args_ct_str = { "r", "r" } };
    static const TCGTargetOpDef r_q = { .args_ct_str = { "r", "q" } };
    static const TCGTargetOpDef r_re = { .args_ct_str = { "r", "re" } };
    static const TCGTargetOpDef r_0 = { .args_ct_str = { "r", "0" } };
    static const TCGTargetOpDef r_r_ri = { .args_ct_str = { "r", "r", "ri" } };
    static const TCGTargetOpDef r_r_re = { .args_ct_str = { "r", "r", "re" } };
    static const TCGTargetOpDef r_0_re = { .args_ct_str = { "r", "0", "re" } };
    static const TCGTargetOpDef r_0_ci = { .args_ct_str = { "r", "0", "ci" } };
    static const TCGTargetOpDef r_L = { .args_ct_str = { "r", "L" } };
    static const TCGTargetOpDef L_L = { .args_ct_str = { "L", "L" } };
    static const TCGTargetOpDef r_L_L = { .args_ct_str = { "r", "L", "L" } };
    static const TCGTargetOpDef r_r_L = { .args_ct_str = { "r", "r", "L" } };
    static const TCGTargetOpDef L_L_L = { .args_ct_str = { "L", "L", "L" } };
    static const TCGTargetOpDef r_r_L_L
        = { .args_ct_str = { "r", "r", "L", "L" } };
    static const TCGTargetOpDef L_L_L_L
        = { .args_ct_str = { "L", "L", "L", "L" } };

    switch (op) {
    case INDEX_op_goto_ptr:
        return &r;

    case INDEX_op_ld8u_i32:
    case INDEX_op_ld8u_i64:
    case INDEX_op_ld8s_i32:
    case INDEX_op_ld8s_i64:
    case INDEX_op_ld16u_i32:
    case INDEX_op_ld16u_i64:
    case INDEX_op_ld16s_i32:
    case INDEX_op_ld16s_i64:
    case INDEX_op_ld_i32:
    case INDEX_op_ld32u_i64:
    case INDEX_op_ld32s_i64:
    case INDEX_op_ld_i64:
        return &r_r;

    case INDEX_op_st8_i32:
    case INDEX_op_st8_i64:
        return &qi_r;
    case INDEX_op_st16_i32:
    case INDEX_op_st16_i64:
    case INDEX_op_st_i32:
    case INDEX_op_st32_i64:
        return &ri_r;
    case INDEX_op_st_i64:
        return &re_r;

    case INDEX_op_add_i32:
    case INDEX_op_add_i64:
        return &r_r_re;
    case INDEX_op_sub_i32:
    case INDEX_op_sub_i64:
    case INDEX_op_mul_i32:
    case INDEX_op_mul_i64:
    case INDEX_op_or_i32:
    case INDEX_op_or_i64:
    case INDEX_op_xor_i32:
    case INDEX_op_xor_i64:
        return &r_0_re;

    case INDEX_op_and_i32:
    case INDEX_op_and_i64:
        {
            static const TCGTargetOpDef _and
                = { .args_ct_str = { "r", "0", "reZ" } };
            return &_and;
        }
        break;
    case INDEX_op_andc_i32:
    case INDEX_op_andc_i64:
        {
            static const TCGTargetOpDef andc
                = { .args_ct_str = { "r", "r", "rI" } };
            return &andc;
        }
        break;

    case INDEX_op_shl_i32:
    case INDEX_op_shl_i64:
    case INDEX_op_shr_i32:
    case INDEX_op_shr_i64:
    case INDEX_op_sar_i32:
    case INDEX_op_sar_i64:
        return have_bmi2 ? &r_r_ri : &r_0_ci;
    case INDEX_op_rotl_i32:
    case INDEX_op_rotl_i64:
    case INDEX_op_rotr_i32:
    case INDEX_op_rotr_i64:
        return &r_0_ci;

    case INDEX_op_brcond_i32:
    case INDEX_op_brcond_i64:
        return &r_re;

    case INDEX_op_bswap16_i32:
    case INDEX_op_bswap16_i64:
    case INDEX_op_bswap32_i32:
    case INDEX_op_bswap32_i64:
    case INDEX_op_bswap64_i64:
    case INDEX_op_neg_i32:
    case INDEX_op_neg_i64:
    case INDEX_op_not_i32:
    case INDEX_op_not_i64:
        return &r_0;

    case INDEX_op_ext8s_i32:
    case INDEX_op_ext8s_i64:
    case INDEX_op_ext8u_i32:
    case INDEX_op_ext8u_i64:
        return &r_q;
    case INDEX_op_ext16s_i32:
    case INDEX_op_ext16s_i64:
    case INDEX_op_ext16u_i32:
    case INDEX_op_ext16u_i64:
    case INDEX_op_ext32s_i64:
    case INDEX_op_ext32u_i64:
    case INDEX_op_ext_i32_i64:
    case INDEX_op_extu_i32_i64:
    case INDEX_op_extract_i32:
    case INDEX_op_extract_i64:
    case INDEX_op_sextract_i32:
    case INDEX_op_ctpop_i32:
    case INDEX_op_ctpop_i64:
        return &r_r;

    case INDEX_op_deposit_i32:
    case INDEX_op_deposit_i64:
        {
            static const TCGTargetOpDef dep
                = { .args_ct_str = { "Q", "0", "Q" } };
            return &dep;
        }
    case INDEX_op_setcond_i32:
    case INDEX_op_setcond_i64:
        {
            static const TCGTargetOpDef setc
                = { .args_ct_str = { "q", "r", "re" } };
            return &setc;
        }
    case INDEX_op_movcond_i32:
    case INDEX_op_movcond_i64:
        {
            static const TCGTargetOpDef movc
                = { .args_ct_str = { "r", "r", "re", "r", "0" } };
            return &movc;
        }
    case INDEX_op_div2_i32:
    case INDEX_op_div2_i64:
    case INDEX_op_divu2_i32:
    case INDEX_op_divu2_i64:
        {
            static const TCGTargetOpDef div2
                = { .args_ct_str = { "a", "d", "0", "1", "r" } };
            return &div2;
        }
    case INDEX_op_mulu2_i32:
    case INDEX_op_mulu2_i64:
    case INDEX_op_muls2_i32:
    case INDEX_op_muls2_i64:
        {
            static const TCGTargetOpDef mul2
                = { .args_ct_str = { "a", "d", "a", "r" } };
            return &mul2;
        }
    case INDEX_op_add2_i32:
    case INDEX_op_add2_i64:
    case INDEX_op_sub2_i32:
    case INDEX_op_sub2_i64:
        {
            static const TCGTargetOpDef arith2
                = { .args_ct_str = { "r", "r", "0", "1", "re", "re" } };
            return &arith2;
        }
    case INDEX_op_ctz_i32:
    case INDEX_op_ctz_i64:
        {
            static const TCGTargetOpDef ctz[2] = {
                { .args_ct_str = { "&r", "r", "r" } },
                { .args_ct_str = { "&r", "r", "rW" } },
            };
            return &ctz[have_bmi1];
        }
    case INDEX_op_clz_i32:
    case INDEX_op_clz_i64:
        {
            static const TCGTargetOpDef clz[2] = {
                { .args_ct_str = { "&r", "r", "r" } },
                { .args_ct_str = { "&r", "r", "rW" } },
            };
            return &clz[have_lzcnt];
        }

    case INDEX_op_qemu_ld_i32:
        return TARGET_LONG_BITS <= TCG_TARGET_REG_BITS ? &r_L : &r_L_L;
    case INDEX_op_qemu_st_i32:
        return TARGET_LONG_BITS <= TCG_TARGET_REG_BITS ? &L_L : &L_L_L;
    case INDEX_op_qemu_ld_i64:
        return (TCG_TARGET_REG_BITS == 64 ? &r_L
                : TARGET_LONG_BITS <= TCG_TARGET_REG_BITS ? &r_r_L
                : &r_r_L_L);
    case INDEX_op_qemu_st_i64:
        return (TCG_TARGET_REG_BITS == 64 ? &L_L
                : TARGET_LONG_BITS <= TCG_TARGET_REG_BITS ? &L_L_L
                : &L_L_L_L);

    case INDEX_op_brcond2_i32:
        {
            static const TCGTargetOpDef b2
                = { .args_ct_str = { "r", "r", "ri", "ri" } };
            return &b2;
        }
    case INDEX_op_setcond2_i32:
        {
            static const TCGTargetOpDef s2
                = { .args_ct_str = { "r", "r", "r", "ri", "ri" } };
            return &s2;
        }

    default:
        break;
    }
    return NULL;
}

static void tcg_target_init(TCGContext *s)
{
#ifdef CONFIG_CPUID_H
    unsigned a, b, c, d;
    int max = __get_cpuid_max(0, 0);

    if (max >= 1) {
        __cpuid(1, a, b, c, d);
#ifndef have_cmov
        /* For 32-bit, 99% certainty that we're running on hardware that
           supports cmov, but we still need to check.  In case cmov is not
           available, we'll use a small forward branch.  */
        have_cmov = (d & bit_CMOV) != 0;
#endif
        /* MOVBE is only available on Intel Atom and Haswell CPUs, so we
           need to probe for it.  */
        have_movbe = (c & bit_MOVBE) != 0;
        have_popcnt = (c & bit_POPCNT) != 0;
    }

    if (max >= 7) {
        /* BMI1 is available on AMD Piledriver and Intel Haswell CPUs.  */
        __cpuid_count(7, 0, a, b, c, d);
        have_bmi1 = (b & bit_BMI) != 0;
        have_bmi2 = (b & bit_BMI2) != 0;
    }

    max = __get_cpuid_max(0x8000000, 0);
    if (max >= 1) {
        __cpuid(0x80000001, a, b, c, d);
        /* LZCNT was introduced with AMD Barcelona and Intel Haswell CPUs.  */
        have_lzcnt = (c & bit_LZCNT) != 0;
    }
#endif /* CONFIG_CPUID_H */

    if (TCG_TARGET_REG_BITS == 64) {
        tcg_target_available_regs[TCG_TYPE_I32] = 0xffff;
        tcg_target_available_regs[TCG_TYPE_I64] = 0xffff;
    } else {
        tcg_target_available_regs[TCG_TYPE_I32] = 0xff;
    }

    tcg_target_call_clobber_regs = 0;
    tcg_regset_set_reg(tcg_target_call_clobber_regs, TCG_REG_EAX);
    tcg_regset_set_reg(tcg_target_call_clobber_regs, TCG_REG_EDX);
    tcg_regset_set_reg(tcg_target_call_clobber_regs, TCG_REG_ECX);
    if (TCG_TARGET_REG_BITS == 64) {
#if !defined(_WIN64)
        tcg_regset_set_reg(tcg_target_call_clobber_regs, TCG_REG_RDI);
        tcg_regset_set_reg(tcg_target_call_clobber_regs, TCG_REG_RSI);
#endif
        tcg_regset_set_reg(tcg_target_call_clobber_regs, TCG_REG_R8);
        tcg_regset_set_reg(tcg_target_call_clobber_regs, TCG_REG_R9);
        tcg_regset_set_reg(tcg_target_call_clobber_regs, TCG_REG_R10);
        tcg_regset_set_reg(tcg_target_call_clobber_regs, TCG_REG_R11);
    }

    s->reserved_regs = 0;
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_CALL_STACK);
}

void *tcg_malloc_internal(TCGContext *s, int size)
{
    TCGPool *p;
    int pool_size;
    
    if (size > TCG_POOL_CHUNK_SIZE) {
        /* big malloc: insert a new pool (XXX: could optimize) */
        p = (TCGPool *)g_malloc(sizeof(TCGPool) + size);
        p->size = size;
        p->next = s->pool_first_large;
        s->pool_first_large = p;
        return p->data;
    } else {
        p = s->pool_current;
        if (!p) {
            p = s->pool_first;
            if (!p)
                goto new_pool;
        } else {
            if (!p->next) {
            new_pool:
                pool_size = TCG_POOL_CHUNK_SIZE;
                p = (TCGPool *)g_malloc(sizeof(TCGPool) + pool_size);
                p->size = pool_size;
                p->next = NULL;
                if (s->pool_current) 
                    s->pool_current->next = p;
                else
                    s->pool_first = p;
            } else {
                p = p->next;
            }
        }
    }
    s->pool_current = p;
    s->pool_cur = p->data + size;
    s->pool_end = p->data + p->size;
    return p->data;
}

void tcg_pool_reset(TCGContext *s)
{
    TCGPool *p, *t;
    for (p = s->pool_first_large; p; p = t) {
        t = p->next;
        g_free(p);
    }
    s->pool_first_large = NULL;
    s->pool_cur = s->pool_end = NULL;
    s->pool_current = NULL;
}

typedef struct TCGHelperInfo {
    void *func;
    const char *name;
    unsigned flags;
    unsigned sizemask;
} TCGHelperInfo;

#include "exec/helper-proto.h"

static const TCGHelperInfo all_helpers[] = {
#include "exec/helper-tcg.h"
};

static GHashTable *helper_table;

static int indirect_reg_alloc_order[ARRAY_SIZE(tcg_target_reg_alloc_order)];

static void process_op_defs(TCGContext *s);

static TCGTemp *tcg_global_reg_new_internal(TCGContext *s, TCGType type,
                                            TCGReg reg, const char *name);

void tcg_context_init(TCGContext *s)
{
    int op, total_args, n, i;
    TCGOpDef *def;
    TCGArgConstraint *args_ct;
    int *sorted_args;
    TCGTemp *ts;

    memset(s, 0, sizeof(*s));
    s->nb_globals = 0;

    /* Count total number of arguments and allocate the corresponding
       space */
    total_args = 0;
    for(op = 0; op < NB_OPS; op++) {
        def = &tcg_op_defs[op];
        n = def->nb_iargs + def->nb_oargs;
        total_args += n;
    }

    args_ct = (TCGArgConstraint *)g_malloc(sizeof(TCGArgConstraint) * total_args);
    sorted_args = (int *)g_malloc(sizeof(int) * total_args);

    for(op = 0; op < NB_OPS; op++) {
        def = &tcg_op_defs[op];
        def->args_ct = args_ct;
        def->sorted_args = sorted_args;
        n = def->nb_iargs + def->nb_oargs;
        sorted_args += n;
        args_ct += n;
    }

    /* Register helpers.  */
    /* Use g_direct_hash/equal for direct pointer comparisons on func.  */
    helper_table = g_hash_table_new(NULL, NULL);

    for (i = 0; i < ARRAY_SIZE(all_helpers); ++i) {
        g_hash_table_insert(helper_table, (gpointer)all_helpers[i].func,
                            (gpointer)&all_helpers[i]);
    }

    tcg_target_init(s);
    process_op_defs(s);

    /* Reverse the order of the saved registers, assuming they're all at
       the start of tcg_target_reg_alloc_order.  */
    for (n = 0; n < ARRAY_SIZE(tcg_target_reg_alloc_order); ++n) {
        int r = tcg_target_reg_alloc_order[n];
        if (tcg_regset_test_reg(tcg_target_call_clobber_regs, r)) {
            break;
        }
    }
    for (i = 0; i < n; ++i) {
        indirect_reg_alloc_order[i] = tcg_target_reg_alloc_order[n - 1 - i];
    }
    for (; i < ARRAY_SIZE(tcg_target_reg_alloc_order); ++i) {
        indirect_reg_alloc_order[i] = tcg_target_reg_alloc_order[i];
    }

    tcg_ctx = s;
    /*
     * In user-mode we simply share the init context among threads, since we
     * use a single region. See the documentation tcg_region_init() for the
     * reasoning behind this.
     * In softmmu we will have at most max_cpus TCG threads.
     */
#ifdef CONFIG_USER_ONLY
    tcg_ctxs = &tcg_ctx;
    n_tcg_ctxs = 1;
#else
    tcg_ctxs = g_new(TCGContext *, max_cpus);
#endif

    tcg_debug_assert(!tcg_regset_test_reg(s->reserved_regs, TCG_AREG0));
    ts = tcg_global_reg_new_internal(s, TCG_TYPE_PTR, TCG_AREG0, "env");
    cpu_env = temp_tcgv_ptr(ts);
}

void tcg_func_start(TCGContext *s)
{
    tcg_pool_reset(s);
    s->nb_temps = s->nb_globals;

    /* No temps have been previously allocated for size or locality.  */
    memset(s->free_temps, 0, sizeof(s->free_temps));

    s->nb_labels = 0;
    s->current_frame_offset = s->frame_start;

#ifdef CONFIG_DEBUG_TCG
    s->goto_tb_issue_mask = 0;
#endif

    s->gen_op_buf[0].next = 1;
    s->gen_op_buf[0].prev = 0;
    s->gen_next_op_idx = 1;
}

static inline TCGTemp *tcg_temp_alloc(TCGContext *s)
{
    int n = s->nb_temps++;
    tcg_debug_assert(n < TCG_MAX_TEMPS);
    return (TCGTemp *)memset(&s->temps[n], 0, sizeof(TCGTemp));
}

static inline TCGTemp *tcg_global_alloc(TCGContext *s)
{
    TCGTemp *ts;

    tcg_debug_assert(s->nb_globals == s->nb_temps);
    s->nb_globals++;
    ts = tcg_temp_alloc(s);
    ts->temp_global = 1;

    return ts;
}

static TCGTemp *tcg_global_reg_new_internal(TCGContext *s, TCGType type,
                                            TCGReg reg, const char *name)
{
    TCGTemp *ts;

    if (TCG_TARGET_REG_BITS == 32 && type != TCG_TYPE_I32) {
        tcg_abort();
    }

    ts = tcg_global_alloc(s);
    ts->base_type = type;
    ts->type = type;
    ts->fixed_reg = 1;
    ts->reg = reg;
    ts->name = name;
    tcg_regset_set_reg(s->reserved_regs, reg);

    return ts;
}

static TCGTemp *tcg_temp_new_internal(TCGType type, int temp_local)
{
    TCGContext *s = tcg_ctx;
    TCGTemp *ts;
    int idx, k;

    k = type + (temp_local ? TCG_TYPE_COUNT : 0);
    idx = find_first_bit(s->free_temps[k].l, TCG_MAX_TEMPS);
    if (idx < TCG_MAX_TEMPS) {
        /* There is already an available temp with the right type.  */
        clear_bit(idx, s->free_temps[k].l);

        ts = &s->temps[idx];
        ts->temp_allocated = 1;
        tcg_debug_assert(ts->base_type == type);
        tcg_debug_assert(ts->temp_local == temp_local);
    } else {
        ts = tcg_temp_alloc(s);
        if (TCG_TARGET_REG_BITS == 32 && type == TCG_TYPE_I64) {
            TCGTemp *ts2 = tcg_temp_alloc(s);

            ts->base_type = type;
            ts->type = TCG_TYPE_I32;
            ts->temp_allocated = 1;
            ts->temp_local = temp_local;

            tcg_debug_assert(ts2 == ts + 1);
            ts2->base_type = TCG_TYPE_I64;
            ts2->type = TCG_TYPE_I32;
            ts2->temp_allocated = 1;
            ts2->temp_local = temp_local;
        } else {
            ts->base_type = type;
            ts->type = type;
            ts->temp_allocated = 1;
            ts->temp_local = temp_local;
        }
    }

#if defined(CONFIG_DEBUG_TCG)
    s->temps_in_use++;
#endif
    return ts;
}

TCGv_i32 tcg_temp_new_internal_i32(int temp_local)
{
    TCGTemp *t = tcg_temp_new_internal(TCG_TYPE_I32, temp_local);
    return temp_tcgv_i32(t);
}

TCGv_i64 tcg_temp_new_internal_i64(int temp_local)
{
    TCGTemp *t = tcg_temp_new_internal(TCG_TYPE_I64, temp_local);
    return temp_tcgv_i64(t);
}

static void tcg_temp_free_internal(TCGTemp *ts)
{
    TCGContext *s = tcg_ctx;
    int k, idx;

#if defined(CONFIG_DEBUG_TCG)
    s->temps_in_use--;
    if (s->temps_in_use < 0) {
        fprintf(stderr, "More temporaries freed than allocated!\n");
    }
#endif

    tcg_debug_assert(ts->temp_global == 0);
    tcg_debug_assert(ts->temp_allocated != 0);
    ts->temp_allocated = 0;

    idx = temp_idx(ts);
    k = ts->base_type + (ts->temp_local ? TCG_TYPE_COUNT : 0);
    set_bit(idx, s->free_temps[k].l);
}

void tcg_temp_free_i32(TCGv_i32 arg)
{
    tcg_temp_free_internal(tcgv_i32_temp(arg));
}

void tcg_temp_free_i64(TCGv_i64 arg)
{
    tcg_temp_free_internal(tcgv_i64_temp(arg));
}

TCGv_i32 tcg_const_i32(int32_t val)
{
    TCGv_i32 t0;
    t0 = tcg_temp_new_i32();
    tcg_gen_movi_i32(t0, val);
    return t0;
}

TCGv_i64 tcg_const_i64(int64_t val)
{
    TCGv_i64 t0;
    t0 = tcg_temp_new_i64();
    tcg_gen_movi_i64(t0, val);
    return t0;
}

void tcg_gen_callN(void *func, TCGTemp *ret, int nargs, TCGTemp **args)
{
    TCGContext *s = tcg_ctx;
    int i, real_args, nb_rets, pi;
    unsigned sizemask, flags;
    TCGHelperInfo *info;
    TCGOp *op;

    info = (TCGHelperInfo *)g_hash_table_lookup(helper_table, (gpointer)func);
    flags = info->flags;
    sizemask = info->sizemask;

#if defined(__sparc__) && !defined(__arch64__) \
    && !defined(CONFIG_TCG_INTERPRETER)
    /* We have 64-bit values in one register, but need to pass as two
       separate parameters.  Split them.  */
    int orig_sizemask = sizemask;
    int orig_nargs = nargs;
    TCGv_i64 retl, reth;
    TCGTemp *split_args[MAX_OPC_PARAM];

    TCGV_UNUSED_I64(retl);
    TCGV_UNUSED_I64(reth);
    if (sizemask != 0) {
        for (i = real_args = 0; i < nargs; ++i) {
            int is_64bit = sizemask & (1 << (i+1)*2);
            if (is_64bit) {
                TCGv_i64 orig = temp_tcgv_i64(args[i]);
                TCGv_i32 h = tcg_temp_new_i32();
                TCGv_i32 l = tcg_temp_new_i32();
                tcg_gen_extr_i64_i32(l, h, orig);
                split_args[real_args++] = tcgv_i32_temp(h);
                split_args[real_args++] = tcgv_i32_temp(l);
            } else {
                split_args[real_args++] = args[i];
            }
        }
        nargs = real_args;
        args = split_args;
        sizemask = 0;
    }
#elif defined(TCG_TARGET_EXTEND_ARGS) && TCG_TARGET_REG_BITS == 64
    for (i = 0; i < nargs; ++i) {
        int is_64bit = sizemask & (1 << (i+1)*2);
        int is_signed = sizemask & (2 << (i+1)*2);
        if (!is_64bit) {
            TCGv_i64 temp = tcg_temp_new_i64();
            TCGv_i64 orig = temp_tcgv_i64(args[i]);
            if (is_signed) {
                tcg_gen_ext32s_i64(temp, orig);
            } else {
                tcg_gen_ext32u_i64(temp, orig);
            }
            args[i] = tcgv_i64_temp(temp);
        }
    }
#endif /* TCG_TARGET_EXTEND_ARGS */

    i = s->gen_next_op_idx;
    tcg_debug_assert(i < OPC_BUF_SIZE);
    s->gen_op_buf[0].prev = i;
    s->gen_next_op_idx = i + 1;
    op = &s->gen_op_buf[i];

    /* Set links for sequential allocation during translation.  */
    memset(op, 0, offsetof(TCGOp, args));
    op->opc = INDEX_op_call;
    op->prev = i - 1;
    op->next = i + 1;

    pi = 0;
    if (ret != NULL) {
#if defined(__sparc__) && !defined(__arch64__) \
    && !defined(CONFIG_TCG_INTERPRETER)
        if (orig_sizemask & 1) {
            /* The 32-bit ABI is going to return the 64-bit value in
               the %o0/%o1 register pair.  Prepare for this by using
               two return temporaries, and reassemble below.  */
            retl = tcg_temp_new_i64();
            reth = tcg_temp_new_i64();
            op->args[pi++] = tcgv_i64_arg(reth);
            op->args[pi++] = tcgv_i64_arg(retl);
            nb_rets = 2;
        } else {
            op->args[pi++] = temp_arg(ret);
            nb_rets = 1;
        }
#else
        if (TCG_TARGET_REG_BITS < 64 && (sizemask & 1)) {
#ifdef HOST_WORDS_BIGENDIAN
            op->args[pi++] = temp_arg(ret + 1);
            op->args[pi++] = temp_arg(ret);
#else
            op->args[pi++] = temp_arg(ret);
            op->args[pi++] = temp_arg(ret + 1);
#endif
            nb_rets = 2;
        } else {
            op->args[pi++] = temp_arg(ret);
            nb_rets = 1;
        }
#endif
    } else {
        nb_rets = 0;
    }
    op->callo = nb_rets;

    real_args = 0;
    for (i = 0; i < nargs; i++) {
        int is_64bit = sizemask & (1 << (i+1)*2);
        if (TCG_TARGET_REG_BITS < 64 && is_64bit) {
#ifdef TCG_TARGET_CALL_ALIGN_ARGS
            /* some targets want aligned 64 bit args */
            if (real_args & 1) {
                op->args[pi++] = TCG_CALL_DUMMY_ARG;
                real_args++;
            }
#endif
           /* If stack grows up, then we will be placing successive
              arguments at lower addresses, which means we need to
              reverse the order compared to how we would normally
              treat either big or little-endian.  For those arguments
              that will wind up in registers, this still works for
              HPPA (the only current STACK_GROWSUP target) since the
              argument registers are *also* allocated in decreasing
              order.  If another such target is added, this logic may
              have to get more complicated to differentiate between
              stack arguments and register arguments.  */
#if defined(HOST_WORDS_BIGENDIAN) != defined(TCG_TARGET_STACK_GROWSUP)
            op->args[pi++] = temp_arg(args[i] + 1);
            op->args[pi++] = temp_arg(args[i]);
#else
            op->args[pi++] = temp_arg(args[i]);
            op->args[pi++] = temp_arg(args[i] + 1);
#endif
            real_args += 2;
            continue;
        }

        op->args[pi++] = temp_arg(args[i]);
        real_args++;
    }
    op->args[pi++] = (uintptr_t)func;
    op->args[pi++] = flags;
    op->calli = real_args;

    /* Make sure the fields didn't overflow.  */
    tcg_debug_assert(op->calli == real_args);
    tcg_debug_assert(pi <= ARRAY_SIZE(op->args));

#if defined(__sparc__) && !defined(__arch64__) \
    && !defined(CONFIG_TCG_INTERPRETER)
    /* Free all of the parts we allocated above.  */
    for (i = real_args = 0; i < orig_nargs; ++i) {
        int is_64bit = orig_sizemask & (1 << (i+1)*2);
        if (is_64bit) {
            tcg_temp_free_internal(args[real_args++]);
            tcg_temp_free_internal(args[real_args++]);
        } else {
            real_args++;
        }
    }
    if (orig_sizemask & 1) {
        /* The 32-bit ABI returned two 32-bit pieces.  Re-assemble them.
           Note that describing these as TCGv_i64 eliminates an unnecessary
           zero-extension that tcg_gen_concat_i32_i64 would create.  */
        tcg_gen_concat32_i64(temp_tcgv_i64(ret), retl, reth);
        tcg_temp_free_i64(retl);
        tcg_temp_free_i64(reth);
    }
#elif defined(TCG_TARGET_EXTEND_ARGS) && TCG_TARGET_REG_BITS == 64
    for (i = 0; i < nargs; ++i) {
        int is_64bit = sizemask & (1 << (i+1)*2);
        if (!is_64bit) {
            tcg_temp_free_internal(args[i]);
        }
    }
#endif /* TCG_TARGET_EXTEND_ARGS */
}

static int get_constraint_priority(const TCGOpDef *def, int k)
{
    const TCGArgConstraint *arg_ct;

    int i, n;
    arg_ct = &def->args_ct[k];
    if (arg_ct->ct & TCG_CT_ALIAS) {
        /* an alias is equivalent to a single register */
        n = 1;
    } else {
        if (!(arg_ct->ct & TCG_CT_REG))
            return 0;
        n = 0;
        for(i = 0; i < TCG_TARGET_NB_REGS; i++) {
            if (tcg_regset_test_reg(arg_ct->u.regs, i))
                n++;
        }
    }
    return TCG_TARGET_NB_REGS - n + 1;
}

static void sort_constraints(TCGOpDef *def, int start, int n)
{
    int i, j, p1, p2, tmp;

    for(i = 0; i < n; i++)
        def->sorted_args[start + i] = start + i;
    if (n <= 1)
        return;
    for(i = 0; i < n - 1; i++) {
        for(j = i + 1; j < n; j++) {
            p1 = get_constraint_priority(def, def->sorted_args[start + i]);
            p2 = get_constraint_priority(def, def->sorted_args[start + j]);
            if (p1 < p2) {
                tmp = def->sorted_args[start + i];
                def->sorted_args[start + i] = def->sorted_args[start + j];
                def->sorted_args[start + j] = tmp;
            }
        }
    }
}

static void process_op_defs(TCGContext *s)
{
    TCGOpcode op;

    for (op = (TCGOpcode)0; op < NB_OPS; op = (TCGOpcode)(op + 1)) {
        TCGOpDef *def = &tcg_op_defs[op];
        const TCGTargetOpDef *tdefs;
        TCGType type;
        int i, nb_args;

        if (def->flags & TCG_OPF_NOT_PRESENT) {
            continue;
        }

        nb_args = def->nb_iargs + def->nb_oargs;
        if (nb_args == 0) {
            continue;
        }

        tdefs = tcg_target_op_def(op);
        /* Missing TCGTargetOpDef entry. */
        tcg_debug_assert(tdefs != NULL);

        type = (def->flags & TCG_OPF_64BIT ? TCG_TYPE_I64 : TCG_TYPE_I32);
        for (i = 0; i < nb_args; i++) {
            const char *ct_str = tdefs->args_ct_str[i];
            /* Incomplete TCGTargetOpDef entry. */
            tcg_debug_assert(ct_str != NULL);

            def->args_ct[i].u.regs = 0;
            def->args_ct[i].ct = 0;
            while (*ct_str != '\0') {
                switch(*ct_str) {
                case '0' ... '9':
                    {
                        int oarg = *ct_str - '0';
                        tcg_debug_assert(ct_str == tdefs->args_ct_str[i]);
                        tcg_debug_assert(oarg < def->nb_oargs);
                        tcg_debug_assert(def->args_ct[oarg].ct & TCG_CT_REG);
                        /* TCG_CT_ALIAS is for the output arguments.
                           The input is tagged with TCG_CT_IALIAS. */
                        def->args_ct[i] = def->args_ct[oarg];
                        def->args_ct[oarg].ct |= TCG_CT_ALIAS;
                        def->args_ct[oarg].alias_index = i;
                        def->args_ct[i].ct |= TCG_CT_IALIAS;
                        def->args_ct[i].alias_index = oarg;
                    }
                    ct_str++;
                    break;
                case '&':
                    def->args_ct[i].ct |= TCG_CT_NEWREG;
                    ct_str++;
                    break;
                case 'i':
                    def->args_ct[i].ct |= TCG_CT_CONST;
                    ct_str++;
                    break;
                default:
                    ct_str = target_parse_constraint(&def->args_ct[i],
                                                     ct_str, type);
                    /* Typo in TCGTargetOpDef constraint. */
                    tcg_debug_assert(ct_str != NULL);
                }
            }
        }

        /* TCGTargetOpDef entry with too much information? */
        tcg_debug_assert(i == TCG_MAX_OP_ARGS || tdefs->args_ct_str[i] == NULL);

        /* sort the constraints (XXX: this is just an heuristic) */
        sort_constraints(def, 0, def->nb_oargs);
        sort_constraints(def, def->nb_oargs, def->nb_iargs);
    }
}

//
// helper function stubs
//
target_ulong helper_cc_compute_all (target_ulong, target_ulong, target_ulong, int) { return 0u; }
target_ulong helper_cc_compute_c (target_ulong, target_ulong, target_ulong, int) { return 0u; }
void helper_write_eflags (struct CPUX86State *, target_ulong, uint32_t) {}
target_ulong helper_read_eflags (struct CPUX86State *) { return 0; }
void helper_divb_AL (struct CPUX86State *, target_ulong) {}
void helper_idivb_AL (struct CPUX86State *, target_ulong) {}
void helper_divw_AX (struct CPUX86State *, target_ulong) {}
void helper_idivw_AX (struct CPUX86State *, target_ulong) {}
void helper_divl_EAX (struct CPUX86State *, target_ulong) {}
void helper_idivl_EAX (struct CPUX86State *, target_ulong) {}
void helper_divq_EAX (struct CPUX86State *, target_ulong) {}
void helper_idivq_EAX (struct CPUX86State *, target_ulong) {}
void helper_cr4_testbit (struct CPUX86State *, uint32_t) {}
void helper_bndck (struct CPUX86State *, uint32_t) {}
uint64_t helper_bndldx32 (struct CPUX86State *, target_ulong, target_ulong) { return 0u; }
uint64_t helper_bndldx64 (struct CPUX86State *, target_ulong, target_ulong) { return 0u; }
void helper_bndstx32 (struct CPUX86State *, target_ulong, target_ulong, uint64_t, uint64_t) {}
void helper_bndstx64 (struct CPUX86State *, target_ulong, target_ulong, uint64_t, uint64_t) {}
void helper_bnd_jmp (struct CPUX86State *) {}
void helper_aam (struct CPUX86State *, int) {}
void helper_aad (struct CPUX86State *, int) {}
void helper_aaa (struct CPUX86State *) {}
void helper_aas (struct CPUX86State *) {}
void helper_daa (struct CPUX86State *) {}
void helper_das (struct CPUX86State *) {}
target_ulong helper_lsl (struct CPUX86State *, target_ulong) { return 0u; }
target_ulong helper_lar (struct CPUX86State *, target_ulong) { return 0u; }
void helper_verr (struct CPUX86State *, target_ulong) {}
void helper_verw (struct CPUX86State *, target_ulong) {}
void helper_lldt (struct CPUX86State *, int) {}
void helper_ltr (struct CPUX86State *, int) {}
void helper_load_seg (struct CPUX86State *, int, int) {}
void helper_ljmp_protected (struct CPUX86State *, int, target_ulong, target_ulong) {}
void helper_lcall_real (struct CPUX86State *, int, target_ulong, int, int) {}
void helper_lcall_protected (struct CPUX86State *, int, target_ulong, int, target_ulong) {}
void helper_iret_real (struct CPUX86State *, int) {}
void helper_iret_protected (struct CPUX86State *, int, int) {}
void helper_lret_protected (struct CPUX86State *, int, int) {}
target_ulong helper_read_crN (struct CPUX86State *, int) { return 0u; }
void helper_write_crN (struct CPUX86State *, int, target_ulong) {}
void helper_lmsw (struct CPUX86State *, target_ulong) {}
void helper_clts (struct CPUX86State *) {}
void helper_set_dr (struct CPUX86State *, int, target_ulong) {}
target_ulong helper_get_dr (struct CPUX86State *, int) { return 0u; }
void helper_invlpg (struct CPUX86State *, target_ulong) {}
void helper_sysenter (struct CPUX86State *) {}
void helper_sysexit (struct CPUX86State *, int) {}
void helper_syscall (struct CPUX86State *, int) {}
void helper_sysret (struct CPUX86State *, int) {}
void helper_hlt (struct CPUX86State *, int) {}
void helper_monitor (struct CPUX86State *, target_ulong) {}
void helper_mwait (struct CPUX86State *, int) {}
void helper_pause (struct CPUX86State *, int) {}
void helper_debug (struct CPUX86State *) {}
void helper_reset_rf (struct CPUX86State *) {}
void helper_raise_interrupt (struct CPUX86State *, int, int) {}
void helper_raise_exception (struct CPUX86State *, int) {}
void helper_cli (struct CPUX86State *) {}
void helper_sti (struct CPUX86State *) {}
void helper_clac (struct CPUX86State *) {}
void helper_stac (struct CPUX86State *) {}
void helper_boundw (struct CPUX86State *, target_ulong, int) {}
void helper_boundl (struct CPUX86State *, target_ulong, int) {}
void helper_rsm (struct CPUX86State *) {}
void helper_into (struct CPUX86State *, int) {}
void helper_cmpxchg8b_unlocked (struct CPUX86State *, target_ulong) {}
void helper_cmpxchg8b (struct CPUX86State *, target_ulong) {}
void helper_cmpxchg16b_unlocked (struct CPUX86State *, target_ulong) {}
void helper_cmpxchg16b (struct CPUX86State *, target_ulong) {}
void helper_single_step (struct CPUX86State *) {}
void helper_rechecking_single_step (struct CPUX86State *) {}
void helper_cpuid (struct CPUX86State *) {}
void helper_rdtsc (struct CPUX86State *) {}
void helper_rdtscp (struct CPUX86State *) {}
void helper_rdpmc (struct CPUX86State *) {}
void helper_rdmsr (struct CPUX86State *) {}
void helper_wrmsr (struct CPUX86State *) {}
void helper_check_iob (struct CPUX86State *, uint32_t) {}
void helper_check_iow (struct CPUX86State *, uint32_t) {}
void helper_check_iol (struct CPUX86State *, uint32_t) {}
void helper_outb (struct CPUX86State *, uint32_t, uint32_t) {}
target_ulong helper_inb (struct CPUX86State *, uint32_t) { return 0u; }
void helper_outw (struct CPUX86State *, uint32_t, uint32_t) {}
target_ulong helper_inw (struct CPUX86State *, uint32_t) { return 0u; }
void helper_outl (struct CPUX86State *, uint32_t, uint32_t) {}
target_ulong helper_inl (struct CPUX86State *, uint32_t) { return 0u; }
void helper_bpt_io (struct CPUX86State *, uint32_t, uint32_t, target_ulong) {}
void helper_svm_check_intercept_param (struct CPUX86State *, uint32_t, uint64_t) {}
void helper_svm_check_io (struct CPUX86State *, uint32_t, uint32_t, uint32_t) {}
void helper_vmrun (struct CPUX86State *, int, int) {}
void helper_vmmcall (struct CPUX86State *) {}
void helper_vmload (struct CPUX86State *, int) {}
void helper_vmsave (struct CPUX86State *, int) {}
void helper_stgi (struct CPUX86State *) {}
void helper_clgi (struct CPUX86State *) {}
void helper_skinit (struct CPUX86State *) {}
void helper_invlpga (struct CPUX86State *, int) {}
void helper_flds_FT0 (struct CPUX86State *, uint32_t) {}
void helper_fldl_FT0 (struct CPUX86State *, uint64_t) {}
void helper_fildl_FT0 (struct CPUX86State *, int32_t) {}
void helper_flds_ST0 (struct CPUX86State *, uint32_t) {}
void helper_fldl_ST0 (struct CPUX86State *, uint64_t) {}
void helper_fildl_ST0 (struct CPUX86State *, int32_t) {}
void helper_fildll_ST0 (struct CPUX86State *, int64_t) {}
uint32_t helper_fsts_ST0 (struct CPUX86State *) { return 0u; }
uint64_t helper_fstl_ST0 (struct CPUX86State *) { return 0u; }
int32_t helper_fist_ST0 (struct CPUX86State *) { return 0; }
int32_t helper_fistl_ST0 (struct CPUX86State *) { return 0; }
int64_t helper_fistll_ST0 (struct CPUX86State *) { return 0; }
int32_t helper_fistt_ST0 (struct CPUX86State *) { return 0; }
int32_t helper_fisttl_ST0 (struct CPUX86State *) { return 0; }
int64_t helper_fisttll_ST0 (struct CPUX86State *) { return 0; }
void helper_fldt_ST0 (struct CPUX86State *, target_ulong) {}
void helper_fstt_ST0 (struct CPUX86State *, target_ulong) {}
void helper_fpush (struct CPUX86State *) {}
void helper_fpop (struct CPUX86State *) {}
void helper_fdecstp (struct CPUX86State *) {}
void helper_fincstp (struct CPUX86State *) {}
void helper_ffree_STN (struct CPUX86State *, int) {}
void helper_fmov_ST0_FT0 (struct CPUX86State *) {}
void helper_fmov_FT0_STN (struct CPUX86State *, int) {}
void helper_fmov_ST0_STN (struct CPUX86State *, int) {}
void helper_fmov_STN_ST0 (struct CPUX86State *, int) {}
void helper_fxchg_ST0_STN (struct CPUX86State *, int) {}
void helper_fcom_ST0_FT0 (struct CPUX86State *) {}
void helper_fucom_ST0_FT0 (struct CPUX86State *) {}
void helper_fcomi_ST0_FT0 (struct CPUX86State *) {}
void helper_fucomi_ST0_FT0 (struct CPUX86State *) {}
void helper_fadd_ST0_FT0 (struct CPUX86State *) {}
void helper_fmul_ST0_FT0 (struct CPUX86State *) {}
void helper_fsub_ST0_FT0 (struct CPUX86State *) {}
void helper_fsubr_ST0_FT0 (struct CPUX86State *) {}
void helper_fdiv_ST0_FT0 (struct CPUX86State *) {}
void helper_fdivr_ST0_FT0 (struct CPUX86State *) {}
void helper_fadd_STN_ST0 (struct CPUX86State *, int) {}
void helper_fmul_STN_ST0 (struct CPUX86State *, int) {}
void helper_fsub_STN_ST0 (struct CPUX86State *, int) {}
void helper_fsubr_STN_ST0 (struct CPUX86State *, int) {}
void helper_fdiv_STN_ST0 (struct CPUX86State *, int) {}
void helper_fdivr_STN_ST0 (struct CPUX86State *, int) {}
void helper_fchs_ST0 (struct CPUX86State *) {}
void helper_fabs_ST0 (struct CPUX86State *) {}
void helper_fxam_ST0 (struct CPUX86State *) {}
void helper_fld1_ST0 (struct CPUX86State *) {}
void helper_fldl2t_ST0 (struct CPUX86State *) {}
void helper_fldl2e_ST0 (struct CPUX86State *) {}
void helper_fldpi_ST0 (struct CPUX86State *) {}
void helper_fldlg2_ST0 (struct CPUX86State *) {}
void helper_fldln2_ST0 (struct CPUX86State *) {}
void helper_fldz_ST0 (struct CPUX86State *) {}
void helper_fldz_FT0 (struct CPUX86State *) {}
uint32_t helper_fnstsw (struct CPUX86State *) { return 0u; }
uint32_t helper_fnstcw (struct CPUX86State *) { return 0u; }
void helper_fldcw (struct CPUX86State *, uint32_t) {}
void helper_fclex (struct CPUX86State *) {}
void helper_fwait (struct CPUX86State *) {}
void helper_fninit (struct CPUX86State *) {}
void helper_fbld_ST0 (struct CPUX86State *, target_ulong) {}
void helper_fbst_ST0 (struct CPUX86State *, target_ulong) {}
void helper_f2xm1 (struct CPUX86State *) {}
void helper_fyl2x (struct CPUX86State *) {}
void helper_fptan (struct CPUX86State *) {}
void helper_fpatan (struct CPUX86State *) {}
void helper_fxtract (struct CPUX86State *) {}
void helper_fprem1 (struct CPUX86State *) {}
void helper_fprem (struct CPUX86State *) {}
void helper_fyl2xp1 (struct CPUX86State *) {}
void helper_fsqrt (struct CPUX86State *) {}
void helper_fsincos (struct CPUX86State *) {}
void helper_frndint (struct CPUX86State *) {}
void helper_fscale (struct CPUX86State *) {}
void helper_fsin (struct CPUX86State *) {}
void helper_fcos (struct CPUX86State *) {}
void helper_fstenv (struct CPUX86State *, target_ulong, int) {}
void helper_fldenv (struct CPUX86State *, target_ulong, int) {}
void helper_fsave (struct CPUX86State *, target_ulong, int) {}
void helper_frstor (struct CPUX86State *, target_ulong, int) {}
void helper_fxsave (struct CPUX86State *, target_ulong) {}
void helper_fxrstor (struct CPUX86State *, target_ulong) {}
void helper_xsave (struct CPUX86State *, target_ulong, uint64_t) {}
void helper_xsaveopt (struct CPUX86State *, target_ulong, uint64_t) {}
void helper_xrstor (struct CPUX86State *, target_ulong, uint64_t) {}
uint64_t helper_xgetbv (struct CPUX86State *, uint32_t) { return 0u; }
void helper_xsetbv (struct CPUX86State *, uint32_t, uint64_t) {}
uint64_t helper_rdpkru (struct CPUX86State *, uint32_t) { return 0u; }
void helper_wrpkru (struct CPUX86State *, uint32_t, uint64_t) {}
target_ulong helper_pdep (target_ulong, target_ulong) { return 0u; }
target_ulong helper_pext (target_ulong, target_ulong) { return 0u; }
void helper_ldmxcsr (struct CPUX86State *, uint32_t) {}
void helper_enter_mmx (struct CPUX86State *) {}
void helper_emms (struct CPUX86State *) {}
void helper_movq (struct CPUX86State *, void *, void *) {}
void helper_psrlw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psraw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psllw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psrld_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psrad_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pslld_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psrlq_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psllq_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_paddb_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_paddw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_paddl_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_paddq_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psubb_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psubw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psubl_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psubq_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_paddusb_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_paddsb_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psubusb_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psubsb_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_paddusw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_paddsw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psubusw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psubsw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pminub_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pmaxub_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pminsw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pmaxsw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pand_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pandn_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_por_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pxor_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pcmpgtb_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pcmpgtw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pcmpgtl_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pcmpeqb_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pcmpeqw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pcmpeql_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pmullw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pmulhrw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pmulhuw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pmulhw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pavgb_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pavgw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pmuludq_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pmaddwd_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psadbw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_maskmov_mmx (struct CPUX86State *, MMXReg *, MMXReg *, target_ulong) {}
void helper_movl_mm_T0_mmx (MMXReg *, uint32_t) {}
void helper_movq_mm_T0_mmx (MMXReg *, uint64_t) {}
void helper_pshufw_mmx (MMXReg *, MMXReg *, int) {}
uint32_t helper_pmovmskb_mmx (struct CPUX86State *, MMXReg *) { return 0u; }
void helper_packsswb_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_packuswb_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_packssdw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_punpcklbw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_punpcklwd_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_punpckldq_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_punpckhbw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_punpckhwd_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_punpckhdq_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pi2fd (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pi2fw (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pf2id (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pf2iw (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pfacc (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pfadd (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pfcmpeq (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pfcmpge (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pfcmpgt (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pfmax (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pfmin (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pfmul (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pfnacc (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pfpnacc (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pfrcp (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pfrsqrt (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pfsub (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pfsubr (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pswapd (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_phaddw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_phaddd_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_phaddsw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_phsubw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_phsubd_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_phsubsw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pabsb_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pabsw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pabsd_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pmaddubsw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pmulhrsw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_pshufb_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psignb_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psignw_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_psignd_mmx (struct CPUX86State *, MMXReg *, MMXReg *) {}
void helper_palignr_mmx (struct CPUX86State *, MMXReg *, MMXReg *, int32_t) {}
void helper_psrlw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psraw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psllw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psrld_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psrad_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pslld_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psrlq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psllq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psrldq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pslldq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_paddb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_paddw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_paddl_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_paddq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psubb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psubw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psubl_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psubq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_paddusb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_paddsb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psubusb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psubsb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_paddusw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_paddsw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psubusw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psubsw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pminub_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmaxub_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pminsw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmaxsw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pand_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pandn_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_por_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pxor_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pcmpgtb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pcmpgtw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pcmpgtl_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pcmpeqb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pcmpeqw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pcmpeql_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmullw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmulhuw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmulhw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pavgb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pavgw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmuludq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmaddwd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psadbw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_maskmov_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, target_ulong) {}
void helper_movl_mm_T0_xmm (ZMMReg *, uint32_t) {}
void helper_movq_mm_T0_xmm (ZMMReg *, uint64_t) {}
void helper_shufps (ZMMReg *, ZMMReg *, int) {}
void helper_shufpd (ZMMReg *, ZMMReg *, int) {}
void helper_pshufd_xmm (ZMMReg *, ZMMReg *, int) {}
void helper_pshuflw_xmm (ZMMReg *, ZMMReg *, int) {}
void helper_pshufhw_xmm (ZMMReg *, ZMMReg *, int) {}
void helper_addps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_addss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_addpd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_addsd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_subps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_subss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_subpd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_subsd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_mulps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_mulss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_mulpd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_mulsd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_divps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_divss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_divpd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_divsd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_minps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_minss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_minpd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_minsd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_maxps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_maxss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_maxpd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_maxsd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_sqrtps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_sqrtss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_sqrtpd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_sqrtsd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cvtps2pd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cvtpd2ps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cvtss2sd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cvtsd2ss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cvtdq2ps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cvtdq2pd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cvtpi2ps (struct CPUX86State *, ZMMReg *, MMXReg *) {}
void helper_cvtpi2pd (struct CPUX86State *, ZMMReg *, MMXReg *) {}
void helper_cvtsi2ss (struct CPUX86State *, ZMMReg *, uint32_t) {}
void helper_cvtsi2sd (struct CPUX86State *, ZMMReg *, uint32_t) {}
void helper_cvtsq2ss (struct CPUX86State *, ZMMReg *, uint64_t) {}
void helper_cvtsq2sd (struct CPUX86State *, ZMMReg *, uint64_t) {}
void helper_cvtps2dq (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cvtpd2dq (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cvtps2pi (struct CPUX86State *, MMXReg *, ZMMReg *) {}
void helper_cvtpd2pi (struct CPUX86State *, MMXReg *, ZMMReg *) {}
int32_t helper_cvtss2si (struct CPUX86State *, ZMMReg *) { return 0; }
int32_t helper_cvtsd2si (struct CPUX86State *, ZMMReg *) { return 0; }
int64_t helper_cvtss2sq (struct CPUX86State *, ZMMReg *) { return 0; }
int64_t helper_cvtsd2sq (struct CPUX86State *, ZMMReg *) { return 0; }
void helper_cvttps2dq (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cvttpd2dq (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cvttps2pi (struct CPUX86State *, MMXReg *, ZMMReg *) {}
void helper_cvttpd2pi (struct CPUX86State *, MMXReg *, ZMMReg *) {}
int32_t helper_cvttss2si (struct CPUX86State *, ZMMReg *) { return 0; }
int32_t helper_cvttsd2si (struct CPUX86State *, ZMMReg *) { return 0; }
int64_t helper_cvttss2sq (struct CPUX86State *, ZMMReg *) { return 0; }
int64_t helper_cvttsd2sq (struct CPUX86State *, ZMMReg *) { return 0; }
void helper_rsqrtps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_rsqrtss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_rcpps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_rcpss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_extrq_r (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_extrq_i (struct CPUX86State *, ZMMReg *, int, int) {}
void helper_insertq_r (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_insertq_i (struct CPUX86State *, ZMMReg *, int, int) {}
void helper_haddps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_haddpd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_hsubps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_hsubpd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_addsubps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_addsubpd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpeqps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpeqss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpeqpd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpeqsd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpltps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpltss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpltpd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpltsd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpleps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpless (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmplepd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmplesd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpunordps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpunordss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpunordpd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpunordsd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpneqps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpneqss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpneqpd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpneqsd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpnltps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpnltss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpnltpd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpnltsd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpnleps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpnless (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpnlepd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpnlesd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpordps (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpordss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpordpd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_cmpordsd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_ucomiss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_comiss (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_ucomisd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_comisd (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
uint32_t helper_movmskps (struct CPUX86State *, ZMMReg *) { return 0u; }
uint32_t helper_movmskpd (struct CPUX86State *, ZMMReg *) { return 0u; }
uint32_t helper_pmovmskb_xmm (struct CPUX86State *, ZMMReg *) { return 0u; }
void helper_packsswb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_packuswb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_packssdw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_punpcklbw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_punpcklwd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_punpckldq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_punpckhbw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_punpckhwd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_punpckhdq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_punpcklqdq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_punpckhqdq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_phaddw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_phaddd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_phaddsw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_phsubw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_phsubd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_phsubsw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pabsb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pabsw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pabsd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmaddubsw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmulhrsw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pshufb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psignb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psignw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_psignd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_palignr_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, int32_t) {}
void helper_pblendvb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_blendvps_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_blendvpd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_ptest_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmovsxbw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmovsxbd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmovsxbq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmovsxwd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmovsxwq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmovsxdq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmovzxbw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmovzxbd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmovzxbq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmovzxwd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmovzxwq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmovzxdq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmuldq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pcmpeqq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_packusdw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pminsb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pminsd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pminuw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pminud_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmaxsb_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmaxsd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmaxuw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmaxud_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pmulld_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_phminposuw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_roundps_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_roundpd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_roundss_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_roundsd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_blendps_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_blendpd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_pblendw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_dpps_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_dppd_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_mpsadbw_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_pcmpgtq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_pcmpestri_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_pcmpestrm_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_pcmpistri_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_pcmpistrm_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, uint32_t) {}
target_ulong helper_crc32 (uint32_t, target_ulong, uint32_t) { return 0u; }
void helper_aesdec_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_aesdeclast_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_aesenc_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_aesenclast_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_aesimc_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *) {}
void helper_aeskeygenassist_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, uint32_t) {}
void helper_pclmulqdq_xmm (struct CPUX86State *, ZMMReg *, ZMMReg *, uint32_t) {}
target_ulong helper_rclb (struct CPUX86State *, target_ulong, target_ulong) { return 0u; }
target_ulong helper_rclw (struct CPUX86State *, target_ulong, target_ulong) { return 0u; }
target_ulong helper_rcll (struct CPUX86State *, target_ulong, target_ulong) { return 0u; }
target_ulong helper_rcrb (struct CPUX86State *, target_ulong, target_ulong) { return 0u; }
target_ulong helper_rcrw (struct CPUX86State *, target_ulong, target_ulong) { return 0u; }
target_ulong helper_rcrl (struct CPUX86State *, target_ulong, target_ulong) { return 0u; }
target_ulong helper_rclq (struct CPUX86State *, target_ulong, target_ulong) { return 0u; }
target_ulong helper_rcrq (struct CPUX86State *, target_ulong, target_ulong) { return 0u; }
void helper_trace_guest_mem_before_exec_proxy (struct CPUX86State *, target_ulong, uint32_t) {}
int32_t helper_div_i32 (int32_t, int32_t) { return 0; }
int32_t helper_rem_i32 (int32_t, int32_t) { return 0; }
uint32_t helper_divu_i32 (uint32_t, uint32_t) { return 0u; }
uint32_t helper_remu_i32 (uint32_t, uint32_t) { return 0u; }
int64_t helper_div_i64 (int64_t, int64_t) { return 0; }
int64_t helper_rem_i64 (int64_t, int64_t) { return 0; }
uint64_t helper_divu_i64 (uint64_t, uint64_t) { return 0u; }
uint64_t helper_remu_i64 (uint64_t, uint64_t) { return 0u; }
uint64_t helper_shl_i64 (uint64_t, uint64_t) { return 0u; }
uint64_t helper_shr_i64 (uint64_t, uint64_t) { return 0u; }
int64_t helper_sar_i64 (int64_t, int64_t) { return 0; }
int64_t helper_mulsh_i64 (int64_t, int64_t) { return 0; }
uint64_t helper_muluh_i64 (uint64_t, uint64_t) { return 0u; }
uint32_t helper_clz_i32 (uint32_t, uint32_t) { return 0u; }
uint32_t helper_ctz_i32 (uint32_t, uint32_t) { return 0u; }
uint64_t helper_clz_i64 (uint64_t, uint64_t) { return 0u; }
uint64_t helper_ctz_i64 (uint64_t, uint64_t) { return 0u; }
uint32_t helper_clrsb_i32 (uint32_t) { return 0u; }
uint64_t helper_clrsb_i64 (uint64_t) { return 0u; }
uint32_t helper_ctpop_i32 (uint32_t) { return 0u; }
uint64_t helper_ctpop_i64 (uint64_t) { return 0u; }
void * helper_lookup_tb_ptr (struct CPUX86State *) { return nullptr; }
void helper_exit_atomic (struct CPUX86State *) { __builtin_unreachable(); }
uint32_t helper_atomic_cmpxchgb (struct CPUX86State *, target_ulong, uint32_t, uint32_t) { return 0u; }
uint32_t helper_atomic_cmpxchgw_be (struct CPUX86State *, target_ulong, uint32_t, uint32_t) { return 0u; }
uint32_t helper_atomic_cmpxchgw_le (struct CPUX86State *, target_ulong, uint32_t, uint32_t) { return 0u; }
uint32_t helper_atomic_cmpxchgl_be (struct CPUX86State *, target_ulong, uint32_t, uint32_t) { return 0u; }
uint32_t helper_atomic_cmpxchgl_le (struct CPUX86State *, target_ulong, uint32_t, uint32_t) { return 0u; }
uint32_t helper_atomic_fetch_addb (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_fetch_addw_le (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_fetch_addw_be (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_fetch_addl_le (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_fetch_addl_be (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_fetch_andb (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_fetch_andw_le (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_fetch_andw_be (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_fetch_andl_le (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_fetch_andl_be (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_fetch_orb (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_fetch_orw_le (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_fetch_orw_be (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_fetch_orl_le (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_fetch_orl_be (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_fetch_xorb (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_fetch_xorw_le (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_fetch_xorw_be (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_fetch_xorl_le (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_fetch_xorl_be (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_add_fetchb (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_add_fetchw_le (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_add_fetchw_be (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_add_fetchl_le (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_add_fetchl_be (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_and_fetchb (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_and_fetchw_le (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_and_fetchw_be (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_and_fetchl_le (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_and_fetchl_be (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_or_fetchb (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_or_fetchw_le (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_or_fetchw_be (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_or_fetchl_le (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_or_fetchl_be (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_xor_fetchb (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_xor_fetchw_le (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_xor_fetchw_be (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_xor_fetchl_le (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_xor_fetchl_be (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_xchgb (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_xchgw_le (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_xchgw_be (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_xchgl_le (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }
uint32_t helper_atomic_xchgl_be (struct CPUX86State *, target_ulong, uint32_t) { return 0u; }

//
// global stubs
//
TraceEvent _TRACE_GUEST_MEM_BEFORE_EXEC_EVENT = {0};
TraceEvent _TRACE_GUEST_MEM_BEFORE_TRANS_EVENT = {0};
uint16_t _TRACE_OBJECT_CLASS_DYNAMIC_CAST_ASSERT_DSTATE;
__thread TCGContext *tcg_ctx;
int singlestep;
int qemu_loglevel;
int trace_events_enabled_count;
unsigned long guest_base;
FILE *qemu_logfile;
int qemu_log(const char *fmt, ...) { return 0; }
bool qemu_log_in_addr_range(uint64_t addr) { return false; }
const char *lookup_symbol(target_ulong orig_addr) { return nullptr; }
void target_disas(FILE *out, CPUState *cpu, target_ulong code,
                  target_ulong size) {}
void translator_loop(const TranslatorOps *ops, DisasContextBase *db,
                     CPUState *cpu, TranslationBlock *tb) {}
