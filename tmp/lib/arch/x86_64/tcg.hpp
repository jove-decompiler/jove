#define USE_TCG_OPTIMIZATIONS

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

#define QEMU_BUILD_BUG_MSG(x, msg) _Static_assert(!(x), msg)

#define QEMU_BUILD_BUG_ON(x) QEMU_BUILD_BUG_MSG(x, "not expecting: " #x)

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

#include <sys/mman.h>

static inline void qemu_flockfile(FILE *f)
{
    flockfile(f);
}

#define G_GNUC_EXTENSION __extension__

#define G_GNUC_MALLOC __attribute__((__malloc__))

#define G_GNUC_ALLOC_SIZE(x) __attribute__((__alloc_size__(x)))

#define G_GNUC_ALLOC_SIZE2(x,y) __attribute__((__alloc_size__(x,y)))

#define G_GNUC_NORETURN                         \
  __attribute__((__noreturn__))

#define G_STRFUNC     ((const char*) (__func__))

#define G_STMT_START  do

#define G_STMT_END    while (0)

#define _G_BOOLEAN_EXPR(expr)                   \
 G_GNUC_EXTENSION ({                            \
   int _g_boolean_var_;                         \
   if (expr)                                    \
      _g_boolean_var_ = 1;                      \
   else                                         \
      _g_boolean_var_ = 0;                      \
   _g_boolean_var_;                             \
})

#define G_LIKELY(expr) (__builtin_expect (_G_BOOLEAN_EXPR((expr)), 1))

#define _GLIB_EXTERN extern "C"

#define G_MAXULONG	ULONG_MAX

static inline void qemu_funlockfile(FILE *f)
{
    funlockfile(f);
}

#define G_MAXSIZE	G_MAXULONG

typedef unsigned long gsize;

#define GLIB_AVAILABLE_IN_ALL                   _GLIB_EXTERN

typedef char   gchar;

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

GLIB_AVAILABLE_IN_ALL
gpointer g_malloc0        (gsize	 n_bytes) G_GNUC_MALLOC G_GNUC_ALLOC_SIZE(1);

GLIB_AVAILABLE_IN_ALL
gpointer g_malloc0_n      (gsize	 n_blocks,
			   gsize	 n_block_bytes) G_GNUC_MALLOC G_GNUC_ALLOC_SIZE2(1,2);

#  define _G_NEW(struct_type, n_structs, func) \
	(struct_type *) (G_GNUC_EXTENSION ({			\
	  gsize __n = (gsize) (n_structs);			\
	  gsize __s = sizeof (struct_type);			\
	  gpointer __p;						\
	  if (__s == 1)						\
	    __p = g_##func (__n);				\
	  else if (__builtin_constant_p (__n) &&		\
	           (__s == 0 || __n <= G_MAXSIZE / __s))	\
	    __p = g_##func (__n * __s);				\
	  else							\
	    __p = g_##func##_n (__n, __s);			\
	  __p;							\
	}))

#define g_new0(struct_type, n_structs)			_G_NEW (struct_type, n_structs, malloc0)

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

#define G_LOG_DOMAIN    ((gchar*) 0)

#define g_assert_not_reached()          G_STMT_START { g_assertion_message_expr (G_LOG_DOMAIN, __FILE__, __LINE__, G_STRFUNC, NULL); } G_STMT_END

#define g_assert(expr)                  G_STMT_START { \
                                             if G_LIKELY (expr) ; else \
                                               g_assertion_message_expr (G_LOG_DOMAIN, __FILE__, __LINE__, G_STRFUNC, \
                                                                         #expr); \
                                        } G_STMT_END

GLIB_AVAILABLE_IN_ALL
void    g_assertion_message_expr        (const char     *domain,
                                         const char     *file,
                                         int             line,
                                         const char     *func,
                                         const char     *expr) G_GNUC_NORETURN;

typedef struct _GTree  GTree;

typedef gboolean (*GTraverseFunc) (gpointer  key,
                                   gpointer  value,
                                   gpointer  data);

GLIB_AVAILABLE_IN_ALL
GTree*   g_tree_ref             (GTree            *tree);

GLIB_AVAILABLE_IN_ALL
void     g_tree_destroy         (GTree            *tree);

GLIB_AVAILABLE_IN_ALL
void     g_tree_insert          (GTree            *tree,
                                 gpointer          key,
                                 gpointer          value);

GLIB_AVAILABLE_IN_ALL
void     g_tree_foreach         (GTree            *tree,
                                 GTraverseFunc	   func,
                                 gpointer	   user_data);

GLIB_AVAILABLE_IN_ALL
gint     g_tree_nnodes          (GTree            *tree);

#include <pthread.h>

typedef struct AddressSpace AddressSpace;

typedef struct BusState BusState;

typedef struct CPUAddressSpace CPUAddressSpace;

typedef struct CPUState CPUState;

typedef struct DeviceState DeviceState;

typedef struct MemoryRegion MemoryRegion;

typedef struct QemuMutex QemuMutex;

typedef struct QemuOpts QemuOpts;

#define QEMU_ALIGN_DOWN(n, m) ((n) / (m) * (m))

#define QEMU_ALIGN_UP(n, m) QEMU_ALIGN_DOWN((n) + (m) - 1, (m))

#define QEMU_ALIGN_PTR_UP(p, n) \
    ((typeof(p))QEMU_ALIGN_UP((uintptr_t)(p), (n)))

#define ROUND_UP(n, d) (((n) + (d) - 1) & -(0 ? (n) : (d)))

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

extern int qemu_icache_linesize;

void pstrcpy(char *buf, int buf_size, const char *str);

char *pstrcat(char *buf, int buf_size, const char *s);

typedef uint8_t flag;

typedef uint32_t float32;

typedef uint64_t float64;

typedef struct {
    uint64_t low;
    uint16_t high;
} floatx80;

#include <byteswap.h>

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

static inline uint16_t bswap16(uint16_t x)
{
    return bswap_16(x);
}

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

static inline void mulu64(uint64_t *plow, uint64_t *phigh,
                          uint64_t a, uint64_t b)
{
    __uint128_t r = (__uint128_t)a * b;
    *plow = r;
    *phigh = r >> 64;
}

static inline void muls64(uint64_t *plow, uint64_t *phigh,
                          int64_t a, int64_t b)
{
    __int128_t r = (__int128_t)a * b;
    *plow = r;
    *phigh = r >> 64;
}

static inline int clz32(uint32_t val)
{
    return val ? __builtin_clz(val) : 32;
}

static inline int clz64(uint64_t val)
{
    return val ? __builtin_clzll(val) : 64;
}

static inline int ctz32(uint32_t val)
{
    return val ? __builtin_ctz(val) : 32;
}

static inline int ctz64(uint64_t val)
{
    return val ? __builtin_ctzll(val) : 64;
}

static inline int ctpop8(uint8_t val)
{
    return __builtin_popcount(val);
}

static inline int ctpop32(uint32_t val)
{
    return __builtin_popcount(val);
}

static inline int ctpop64(uint64_t val)
{
    return __builtin_popcountll(val);
}

# define ctzl   ctz64

static inline bool is_power_of_2(uint64_t value)
{
    if (!value) {
        return false;
    }

    return !(value & (value - 1));
}

extern bool tcg_allowed;

#define tcg_enabled() (tcg_allowed)

#define barrier()   ({ asm volatile("" ::: "memory"); (void)0; })

#define smp_read_barrier_depends()   barrier()

# define ATOMIC_REG_SIZE  8

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

#define atomic_rcu_read(ptr)                          \
    ({                                                \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > ATOMIC_REG_SIZE); \
    __auto_type _val = __atomic_load_n(ptr, __ATOMIC_RELAXED);       \
    smp_read_barrier_depends();                       \
    _val;                                             \
    })

#define atomic_rcu_set(ptr, i) do {                   \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > ATOMIC_REG_SIZE); \
    __atomic_store_n(ptr, i, __ATOMIC_RELEASE);       \
} while(0)

#define atomic_load_acquire(ptr)                        \
    ({                                                  \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > ATOMIC_REG_SIZE);  \
    __atomic_load_n(ptr, __ATOMIC_ACQUIRE);        \
    })

#define atomic_xchg__nocheck(ptr, i)    ({                  \
    __atomic_exchange_n(ptr, (i), __ATOMIC_SEQ_CST);        \
})

#define atomic_xchg(ptr, i)    ({                           \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > ATOMIC_REG_SIZE);      \
    atomic_xchg__nocheck(ptr, i);                           \
})

#define atomic_mb_set(ptr, i)  ((void)atomic_xchg(ptr, i))

#define atomic_mb_read(ptr)                             \
    atomic_load_acquire(ptr)

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

#define QTAILQ_INIT(head) do {                                          \
        (head)->tqh_first = NULL;                                       \
        (head)->tqh_last = &(head)->tqh_first;                          \
} while (/*CONSTCOND*/0)

#define QTAILQ_INSERT_TAIL(head, elm, field) do {                       \
        (elm)->field.tqe_next = NULL;                                   \
        (elm)->field.tqe_prev = (head)->tqh_last;                       \
        *(head)->tqh_last = (elm);                                      \
        (head)->tqh_last = &(elm)->field.tqe_next;                      \
} while (/*CONSTCOND*/0)

#define QTAILQ_INSERT_AFTER(head, listelm, elm, field) do {             \
        if (((elm)->field.tqe_next = (listelm)->field.tqe_next) != NULL)\
                (elm)->field.tqe_next->field.tqe_prev =                 \
                    &(elm)->field.tqe_next;                             \
        else                                                            \
                (head)->tqh_last = &(elm)->field.tqe_next;              \
        (listelm)->field.tqe_next = (elm);                              \
        (elm)->field.tqe_prev = &(listelm)->field.tqe_next;             \
} while (/*CONSTCOND*/0)

#define QTAILQ_INSERT_BEFORE(listelm, elm, field) do {                  \
        (elm)->field.tqe_prev = (listelm)->field.tqe_prev;              \
        (elm)->field.tqe_next = (listelm);                              \
        *(listelm)->field.tqe_prev = (elm);                             \
        (listelm)->field.tqe_prev = &(elm)->field.tqe_next;             \
} while (/*CONSTCOND*/0)

#define QTAILQ_REMOVE(head, elm, field) do {                            \
        if (((elm)->field.tqe_next) != NULL)                            \
                (elm)->field.tqe_next->field.tqe_prev =                 \
                    (elm)->field.tqe_prev;                              \
        else                                                            \
                (head)->tqh_last = (elm)->field.tqe_prev;               \
        *(elm)->field.tqe_prev = (elm)->field.tqe_next;                 \
        (elm)->field.tqe_prev = NULL;                                   \
} while (/*CONSTCOND*/0)

#define QTAILQ_FOREACH(var, head, field)                                \
        for ((var) = ((head)->tqh_first);                               \
                (var);                                                  \
                (var) = ((var)->field.tqe_next))

#define QTAILQ_FOREACH_SAFE(var, head, field, next_var)                 \
        for ((var) = ((head)->tqh_first);                               \
                (var) && ((next_var) = ((var)->field.tqe_next), 1);     \
                (var) = (next_var))

#define QTAILQ_FOREACH_REVERSE_SAFE(var, head, headname, field, prev_var) \
        for ((var) = (*(((struct headname *)((head)->tqh_last))->tqh_last)); \
             (var) && ((prev_var) = (*(((struct headname *)((var)->field.tqe_prev))->tqh_last)), 1); \
             (var) = (prev_var))

#define QTAILQ_EMPTY(head)               ((head)->tqh_first == NULL)

#define QTAILQ_FIRST(head)               ((head)->tqh_first)

#define QTAILQ_LAST(head, headname) \
        (*(((struct headname *)((head)->tqh_last))->tqh_last))

struct Notifier;

typedef struct Notifier Notifier;

struct Notifier
{
    void (*notify)(Notifier *notifier, void *data);
    QLIST_ENTRY(Notifier) node;
};

#define BITS_PER_BYTE           CHAR_BIT

#define BITS_TO_LONGS(nr)       DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))

#define DECLARE_BITMAP(name,bits)                  \
        unsigned long name[BITS_TO_LONGS(bits)]

typedef struct Object Object;

typedef struct ObjectClass ObjectClass;

typedef void (ObjectFree)(void *obj);

struct TypeImpl;

typedef struct TypeImpl *Type;

typedef void (ObjectUnparent)(Object *obj);

#define OBJECT_CLASS_CAST_CACHE 4

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

#define BITS_PER_LONG           (sizeof (unsigned long) * BITS_PER_BYTE)

#define BIT_MASK(nr)            (1UL << ((nr) % BITS_PER_LONG))

#define BIT_WORD(nr)            ((nr) / BITS_PER_LONG)

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

static inline uint32_t rol32(uint32_t word, unsigned int shift)
{
    return (word << shift) | (word >> ((32 - shift) & 31));
}

static inline uint32_t ror32(uint32_t word, unsigned int shift)
{
    return (word >> shift) | (word << ((32 - shift) & 31));
}

static inline uint64_t rol64(uint64_t word, unsigned int shift)
{
    return (word << shift) | (word >> ((64 - shift) & 63));
}

static inline uint64_t ror64(uint64_t word, unsigned int shift)
{
    return (word >> shift) | (word << ((64 - shift) & 63));
}

static inline uint64_t extract64(uint64_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 64 - start);
    return (value >> start) & (~0ULL >> (64 - length));
}

static inline int64_t sextract64(uint64_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 64 - start);
    /* Note that this implementation relies on right shift of signed
     * integers being an arithmetic shift.
     */
    return ((int64_t)(value << (64 - length - start))) >> (64 - length);
}

static inline uint64_t deposit64(uint64_t value, int start, int length,
                                 uint64_t fieldval)
{
    uint64_t mask;
    assert(start >= 0 && length > 0 && length <= 64 - start);
    mask = (~0ULL >> (64 - length)) << start;
    return (value & ~mask) | ((fieldval << start) & mask);
}

#define small_nbits(nbits)                      \
        ((nbits) <= BITS_PER_LONG)

static inline void bitmap_zero(unsigned long *dst, long nbits)
{
    if (small_nbits(nbits)) {
        *dst = 0UL;
    } else {
        long len = BITS_TO_LONGS(nbits) * sizeof(unsigned long);
        memset(dst, 0, len);
    }
}

void qemu_mutex_lock_impl(QemuMutex *mutex, const char *file, const int line);

#define qemu_mutex_lock(mutex) \
        qemu_mutex_lock_impl(mutex, __FILE__, __LINE__)

#define qemu_mutex_unlock(mutex) \
        qemu_mutex_unlock_impl(mutex, __FILE__, __LINE__)

void qemu_mutex_unlock_impl(QemuMutex *mutex, const char *file, const int line);

#define CPU(obj) ((CPUState *)(obj))

#define RUN_ON_CPU_HOST_INT(i)    ((run_on_cpu_data){.host_int = (int)(i)})

typedef union {
    int           host_int;
    unsigned long host_ulong;
    void         *host_ptr;
    vaddr         target_ptr;
} run_on_cpu_data;

typedef void (*run_on_cpu_func)(CPUState *cpu, run_on_cpu_data data);

QTAILQ_HEAD(CPUTailQ, CPUState);

#define CPU_FOREACH(cpu) QTAILQ_FOREACH(cpu, &cpus, node)

extern struct CPUTailQ cpus;

static inline void cpu_tb_jmp_cache_clear(CPUState *cpu)
{
    unsigned int i;

    for (i = 0; i < TB_JMP_CACHE_SIZE; i++) {
        atomic_set(&cpu->tb_jmp_cache[i], NULL);
    }
}

void async_safe_run_on_cpu(CPUState *cpu, run_on_cpu_func func, run_on_cpu_data data);

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

#define TCG_TARGET_INSN_UNIT_SIZE  1

# define TCG_TARGET_REG_BITS  64

# define TCG_TARGET_NB_REGS   32

#define TCG_REG_CALL_STACK TCG_REG_ESP

#define TCG_TARGET_STACK_ALIGN 16

#define TCG_TARGET_CALL_STACK_OFFSET 0

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

    TCG_REG_XMM0,
    TCG_REG_XMM1,
    TCG_REG_XMM2,
    TCG_REG_XMM3,
    TCG_REG_XMM4,
    TCG_REG_XMM5,
    TCG_REG_XMM6,
    TCG_REG_XMM7,

    /* 64-bit registers; likewise always define.  */
    TCG_REG_XMM8,
    TCG_REG_XMM9,
    TCG_REG_XMM10,
    TCG_REG_XMM11,
    TCG_REG_XMM12,
    TCG_REG_XMM13,
    TCG_REG_XMM14,
    TCG_REG_XMM15,

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

extern bool have_popcnt;

#define TCG_TARGET_HAS_div2_i32         1

#define TCG_TARGET_HAS_rot_i32          1

#define TCG_TARGET_HAS_ext8s_i32        1

#define TCG_TARGET_HAS_ext16s_i32       1

#define TCG_TARGET_HAS_ext8u_i32        1

#define TCG_TARGET_HAS_ext16u_i32       1

#define TCG_TARGET_HAS_bswap16_i32      1

#define TCG_TARGET_HAS_bswap32_i32      1

#define TCG_TARGET_HAS_neg_i32          1

#define TCG_TARGET_HAS_not_i32          1

#define TCG_TARGET_HAS_andc_i32         have_bmi1

#define TCG_TARGET_HAS_orc_i32          0

#define TCG_TARGET_HAS_eqv_i32          0

#define TCG_TARGET_HAS_nand_i32         0

#define TCG_TARGET_HAS_nor_i32          0

#define TCG_TARGET_HAS_clz_i32          1

#define TCG_TARGET_HAS_ctz_i32          1

#define TCG_TARGET_HAS_ctpop_i32        have_popcnt

#define TCG_TARGET_HAS_deposit_i32      1

#define TCG_TARGET_HAS_extract_i32      1

#define TCG_TARGET_HAS_sextract_i32     1

#define TCG_TARGET_HAS_movcond_i32      1

#define TCG_TARGET_HAS_add2_i32         1

#define TCG_TARGET_HAS_sub2_i32         1

#define TCG_TARGET_HAS_mulu2_i32        1

#define TCG_TARGET_HAS_muls2_i32        1

#define TCG_TARGET_HAS_muluh_i32        0

#define TCG_TARGET_HAS_mulsh_i32        0

#define TCG_TARGET_HAS_goto_ptr         1

#define TCG_TARGET_HAS_direct_jump      1

#define TCG_TARGET_HAS_extrl_i64_i32    0

#define TCG_TARGET_HAS_extrh_i64_i32    0

#define TCG_TARGET_HAS_div2_i64         1

#define TCG_TARGET_HAS_rot_i64          1

#define TCG_TARGET_HAS_ext8s_i64        1

#define TCG_TARGET_HAS_ext16s_i64       1

#define TCG_TARGET_HAS_ext32s_i64       1

#define TCG_TARGET_HAS_ext8u_i64        1

#define TCG_TARGET_HAS_ext16u_i64       1

#define TCG_TARGET_HAS_ext32u_i64       1

#define TCG_TARGET_HAS_bswap16_i64      1

#define TCG_TARGET_HAS_bswap32_i64      1

#define TCG_TARGET_HAS_bswap64_i64      1

#define TCG_TARGET_HAS_neg_i64          1

#define TCG_TARGET_HAS_not_i64          1

#define TCG_TARGET_HAS_andc_i64         have_bmi1

#define TCG_TARGET_HAS_orc_i64          0

#define TCG_TARGET_HAS_eqv_i64          0

#define TCG_TARGET_HAS_nand_i64         0

#define TCG_TARGET_HAS_nor_i64          0

#define TCG_TARGET_HAS_clz_i64          1

#define TCG_TARGET_HAS_ctz_i64          1

#define TCG_TARGET_HAS_ctpop_i64        have_popcnt

#define TCG_TARGET_HAS_deposit_i64      1

#define TCG_TARGET_HAS_extract_i64      1

#define TCG_TARGET_HAS_sextract_i64     0

#define TCG_TARGET_HAS_movcond_i64      1

#define TCG_TARGET_HAS_add2_i64         1

#define TCG_TARGET_HAS_sub2_i64         1

#define TCG_TARGET_HAS_mulu2_i64        1

#define TCG_TARGET_HAS_muls2_i64        1

#define TCG_TARGET_HAS_muluh_i64        0

#define TCG_TARGET_HAS_mulsh_i64        0

#define TCG_TARGET_HAS_v64              have_avx1

#define TCG_TARGET_HAS_v128             have_avx1

#define TCG_TARGET_HAS_v256             have_avx2

#define TCG_TARGET_HAS_andc_vec         1

#define TCG_TARGET_HAS_orc_vec          0

#define TCG_TARGET_HAS_not_vec          0

#define TCG_TARGET_HAS_neg_vec          0

#define TCG_TARGET_HAS_shi_vec          1

#define TCG_TARGET_HAS_shs_vec          0

#define TCG_TARGET_HAS_shv_vec          0

#define TCG_TARGET_HAS_mul_vec          1

#define TCG_TARGET_deposit_i32_valid(ofs, len) \
    (((ofs) == 0 && (len) == 8) || ((ofs) == 8 && (len) == 8) || \
     ((ofs) == 0 && (len) == 16))

#define TCG_TARGET_deposit_i64_valid    TCG_TARGET_deposit_i32_valid

#define TCG_TARGET_extract_i32_valid(ofs, len) ((ofs) == 8 && (len) == 8)

#define TCG_TARGET_extract_i64_valid(ofs, len) \
    (((ofs) == 8 && (len) == 8) || ((ofs) + (len)) == 32)

# define TCG_AREG0 TCG_REG_R14

static inline void flush_icache_range(uintptr_t start, uintptr_t stop)
{
}

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

#define TCG_GUEST_DEFAULT_MO      (TCG_MO_ALL & ~TCG_MO_ST_LD)

#define TARGET_MAX_INSN_SIZE 16

#define CPUArchState struct CPUX86State

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

#define ENV_GET_CPU(e) CPU(x86_env_get_cpu(e))

#define ENV_OFFSET offsetof(X86CPU, env)

static inline X86CPU *x86_env_get_cpu(CPUX86State *env)
{
    return container_of(env, X86CPU, env);
}

#define TARGET_PAGE_BITS 12

#define EXCP_INTERRUPT 	0x10000

#define lduw_p(p) lduw_le_p(p)

#define ldsw_p(p) ldsw_le_p(p)

#define ldl_p(p) ldl_le_p(p)

#define ldq_p(p) ldq_le_p(p)

#define TARGET_ABI_BITS TARGET_LONG_BITS

#define ABI_LONG_ALIGNMENT (TARGET_ABI_BITS / 8)

typedef target_ulong abi_ulong __attribute__((aligned(ABI_LONG_ALIGNMENT)));

#define TARGET_ABI_FMT_lx TARGET_FMT_lx

extern unsigned long guest_base;

#define TARGET_PAGE_SIZE (1 << TARGET_PAGE_BITS)

#define TARGET_PAGE_MASK ~(TARGET_PAGE_SIZE - 1)

extern uintptr_t qemu_host_page_size;

#define PAGE_READ      0x0001

#define PAGE_WRITE     0x0002

#define PAGE_EXEC      0x0004

#define PAGE_BITS      (PAGE_READ | PAGE_WRITE | PAGE_EXEC)

extern intptr_t qemu_host_page_mask;

int page_get_flags(target_ulong address);

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

struct qht {
    struct qht_map *map;
    QemuMutex lock; /* serializes setters of ht->map */
    unsigned int mode;
};

typedef void (*qht_iter_func_t)(struct qht *ht, void *p, uint32_t h, void *up);

bool qht_insert(struct qht *ht, void *p, uint32_t hash);

bool qht_reset_size(struct qht *ht, size_t n_elems);

void qht_iter(struct qht *ht, qht_iter_func_t func, void *userp);

#define CODE_GEN_HTABLE_BITS     15

#define CODE_GEN_HTABLE_SIZE     (1 << CODE_GEN_HTABLE_BITS)

typedef struct TranslationBlock TranslationBlock;

typedef struct TBContext TBContext;

struct TBContext {

    GTree *tb_tree;
    struct qht htable;
    /* any access to the tbs or the page table must use this lock */
    QemuMutex tb_lock;

    /* statistics */
    unsigned tb_flush_count;
    int tb_phys_invalidate_count;
};

#define DEBUG_DISAS

#define TB_PAGE_ADDR_FMT TARGET_ABI_FMT_lx

typedef abi_ulong tb_page_addr_t;

extern int qemu_loglevel;

static inline bool qemu_loglevel_mask(int mask)
{
    return (qemu_loglevel & mask) != 0;
}

int GCC_FMT_ATTR(1, 2) qemu_log(const char *fmt, ...);

extern FILE *qemu_logfile;

#define CPU_LOG_TB_OUT_ASM (1 << 0)

#define CPU_LOG_TB_IN_ASM  (1 << 1)

#define CPU_LOG_TB_OP      (1 << 2)

#define CPU_LOG_TB_OP_OPT  (1 << 3)

#define LOG_UNIMP          (1 << 10)

#define CPU_LOG_TB_NOCHAIN (1 << 13)

#define CPU_LOG_TB_OP_IND  (1 << 16)

static inline void qemu_log_lock(void)
{
    qemu_flockfile(qemu_logfile);
}

static inline void qemu_log_unlock(void)
{
    qemu_funlockfile(qemu_logfile);
}

bool qemu_log_in_addr_range(uint64_t addr);

void qemu_log_flush(void);

void gen_intermediate_code(CPUState *cpu, struct TranslationBlock *tb);

void QEMU_NORETURN cpu_loop_exit(CPUState *cpu);

#define CODE_GEN_ALIGN           16

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

    struct {
      jove::terminator_info_t T;
    } jove;
};

static inline uint32_t tb_cflags(const TranslationBlock *tb)
{
    return atomic_read(&tb->cflags);
}

void tb_set_jmp_target(TranslationBlock *tb, int n, uintptr_t addr);

void mmap_unlock(void);

bool have_mmap_lock(void);

static inline tb_page_addr_t get_page_addr_code(CPUArchState *env1, target_ulong addr)
{
    return addr;
}

#define MAX_OPC_PARAM_PER_ARG 1

#define MAX_OPC_PARAM_IARGS 6

#define MAX_OPC_PARAM_OARGS 1

#define MAX_OPC_PARAM_ARGS (MAX_OPC_PARAM_IARGS + MAX_OPC_PARAM_OARGS)

#define MAX_OPC_PARAM (4 + (MAX_OPC_PARAM_PER_ARG * MAX_OPC_PARAM_ARGS))

extern int singlestep;

typedef int64_t tcg_target_long;

#define TCG_PRIlx PRIx64

typedef uint64_t tcg_target_ulong;

#define TCG_TARGET_HAS_div_i32          0

#define TCG_TARGET_HAS_rem_i32          0

#define TCG_TARGET_HAS_div_i64          0

#define TCG_TARGET_HAS_rem_i64          0

#define TCG_TARGET_MAYBE_vec            1

# define TARGET_INSN_START_WORDS (1 + TARGET_INSN_START_EXTRA_WORDS)

typedef uint32_t TCGRegSet;

#define tcg_regset_set_reg(d, r)   ((d) |= (TCGRegSet)1 << (r))

#define tcg_regset_reset_reg(d, r) ((d) &= ~((TCGRegSet)1 << (r)))

#define tcg_regset_test_reg(d, r)  (((d) >> (r)) & 1)

typedef enum TCGOpcode {
#define DEF(name, oargs, iargs, cargs, flags) INDEX_op_ ## name,
/* XXX jove */
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

#define IMPL(X) (__builtin_constant_p(X) && !(X) ? TCG_OPF_NOT_PRESENT : 0)
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
DEF(exit_tb, 0, 0, 1, TCG_OPF_BB_END)
DEF(goto_tb, 0, 0, 1, TCG_OPF_BB_END)
DEF(goto_ptr, 0, 1, 0, TCG_OPF_BB_END | IMPL(TCG_TARGET_HAS_goto_ptr))

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

DEF(add_vec, 1, 2, 0, IMPLVEC)
DEF(sub_vec, 1, 2, 0, IMPLVEC)
DEF(mul_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_mul_vec))
DEF(neg_vec, 1, 1, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_neg_vec))

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

DEF(last_generic, 0, 0, 0, TCG_OPF_NOT_PRESENT)

#if TCG_TARGET_MAYBE_vec
/* Target-specific opcodes for host vector expansion.  These will be
   emitted by tcg_expand_vec_op.  For those familiar with GCC internals,
   consider these to be UNSPEC with names.  */

DEF(x86_shufps_vec, 1, 2, 1, IMPLVEC)
DEF(x86_vpblendvb_vec, 1, 3, 0, IMPLVEC)
DEF(x86_blend_vec, 1, 2, 1, IMPLVEC)
DEF(x86_packss_vec, 1, 2, 0, IMPLVEC)
DEF(x86_packus_vec, 1, 2, 0, IMPLVEC)
DEF(x86_psrldq_vec, 1, 1, 1, IMPLVEC)
DEF(x86_vperm2i128_vec, 1, 2, 1, IMPLVEC)
DEF(x86_punpckl_vec, 1, 2, 0, IMPLVEC)
DEF(x86_punpckh_vec, 1, 2, 0, IMPLVEC)
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

#define TCG_STATIC_CALL_ARGS_SIZE 128

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

#define TCG_CALL_NO_READ_GLOBALS    0x0010

#define TCG_CALL_NO_WRITE_GLOBALS   0x0020

#define TCG_CALL_NO_SIDE_EFFECTS    0x0040

#define TCG_CALL_NO_RWG         TCG_CALL_NO_READ_GLOBALS

#define TCG_CALL_NO_WG          TCG_CALL_NO_WRITE_GLOBALS

#define TCG_CALL_NO_SE          TCG_CALL_NO_SIDE_EFFECTS

#define TCG_CALL_NO_RWG_SE      (TCG_CALL_NO_RWG | TCG_CALL_NO_SE)

#define TCG_CALL_NO_WG_SE       (TCG_CALL_NO_WG | TCG_CALL_NO_SE)

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

static inline TCGCond tcg_swap_cond(TCGCond c)
{
    return c & 6 ? (TCGCond)(c ^ 9) : c;
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

#define DEAD_ARG  4

#define SYNC_ARG  1

typedef struct TCGTempSet {
    unsigned long l[BITS_TO_LONGS(TCG_MAX_TEMPS)];
} TCGTempSet;

typedef uint16_t TCGLifeData;

#define TCGOP_CALLI(X)    (X)->param1

#define TCGOP_CALLO(X)    (X)->param2

#define TCGOP_VECL(X)     (X)->param1

#define TCGOP_VECE(X)     (X)->param2

typedef struct TCGOp {
    TCGOpcode opc   : 8;        /*  8 */

    /* Parameters for this opcode.  See below.  */
    unsigned param1 : 4;        /* 12 */
    unsigned param2 : 4;        /* 16 */

    /* Lifetime data of the operands.  */
    unsigned life   : 16;       /* 32 */

    /* Next and previous opcodes.  */
    QTAILQ_ENTRY(TCGOp) link;

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

    QTAILQ_HEAD(TCGOpHead, TCGOp) ops, free_ops;

    /* Tells which temporary holds a given register.
       It does not take into account fixed registers */
    TCGTemp *reg_to_temp[TCG_TARGET_NB_REGS];

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

static inline TCGTemp *arg_temp(TCGArg a)
{
    return (TCGTemp *)(uintptr_t)a;
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

static inline void tcg_set_insn_param(TCGOp *op, int arg, TCGArg v)
{
    op->args[arg] = v;
}

static inline TCGOp *tcg_last_op(void)
{
#ifdef __cplusplus
    return QTAILQ_LAST(&tcg_ctx->ops, TCGContext::TCGOpHead);
#else
    return QTAILQ_LAST(&tcg_ctx->ops, TCGOpHead);
#endif
}

static inline bool tcg_op_buf_full(void)
{
    return false;
}

void *tcg_malloc_internal(TCGContext *s, int size);

TranslationBlock *tcg_tb_alloc(TCGContext *s);

void tcg_region_reset_all(void);

size_t tcg_code_size(void);

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

void tcg_func_start(TCGContext *s);

int tcg_gen_code(TCGContext *s, TranslationBlock *tb);

TCGTemp *tcg_global_mem_new_internal(TCGType, TCGv_ptr,
                                     intptr_t, const char *);

TCGv_i32 tcg_temp_new_internal_i32(int temp_local);

TCGv_i64 tcg_temp_new_internal_i64(int temp_local);

void tcg_temp_free_i32(TCGv_i32 arg);

void tcg_temp_free_i64(TCGv_i64 arg);

static inline TCGv_i32 tcg_global_mem_new_i32(TCGv_ptr reg, intptr_t offset,
                                              const char *name)
{
    TCGTemp *t = tcg_global_mem_new_internal(TCG_TYPE_I32, reg, offset, name);
    return temp_tcgv_i32(t);
}

static inline TCGv_i32 tcg_temp_new_i32(void)
{
    return tcg_temp_new_internal_i32(0);
}

static inline TCGv_i32 tcg_temp_local_new_i32(void)
{
    return tcg_temp_new_internal_i32(1);
}

static inline TCGv_i64 tcg_global_mem_new_i64(TCGv_ptr reg, intptr_t offset,
                                              const char *name)
{
    TCGTemp *t = tcg_global_mem_new_internal(TCG_TYPE_I64, reg, offset, name);
    return temp_tcgv_i64(t);
}

static inline TCGv_i64 tcg_temp_new_i64(void)
{
    return tcg_temp_new_internal_i64(0);
}

#define tcg_clear_temp_count() do { } while (0)

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
    /* Instruction operands are vectors.  */
    TCG_OPF_VECTOR       = 0x20,
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

extern TCGOpDef tcg_op_defs[];

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

TCGOp *tcg_emit_op(TCGOpcode opc);

void tcg_op_remove(TCGContext *s, TCGOp *op);

TCGOp *tcg_op_insert_before(TCGContext *s, TCGOp *op, TCGOpcode opc, int narg);

void tcg_optimize(TCGContext *s);

TCGv_i32 tcg_const_i32(int32_t val);

TCGv_i64 tcg_const_i64(int64_t val);

TCGLabel *gen_new_label(void);

static inline TCGArg label_arg(TCGLabel *l)
{
    return (uintptr_t)l;
}

static inline TCGLabel *arg_label(TCGArg i)
{
    return (TCGLabel *)(uintptr_t)i;
}

static inline ptrdiff_t tcg_ptr_byte_diff(void *a, void *b)
{
    return (char *)a - (char *)b;
}

static inline ptrdiff_t tcg_pcrel_diff(TCGContext *s, void *target)
{
    return tcg_ptr_byte_diff(target, s->code_ptr);
}

static inline size_t tcg_current_code_size(TCGContext *s)
{
    return tcg_ptr_byte_diff(s->code_ptr, s->code_buf);
}

typedef uint32_t TCGMemOpIdx;

static inline TCGMemOpIdx make_memop_idx(TCGMemOp op, unsigned idx)
{
    tcg_debug_assert(idx <= 15);
    return (op << 4) | idx;
}

static inline TCGMemOp get_memop(TCGMemOpIdx oi)
{
    return (TCGMemOp)(oi >> 4);
}

#define TB_EXIT_REQUESTED 3

static inline unsigned get_mmuidx(TCGMemOpIdx oi)
{
    return oi & 15;
}

/* Duplicate C as per VECE.  */
uint64_t (dup_const)(unsigned vece, uint64_t c)
{
    switch (vece) {
    case MO_8:
        return 0x0101010101010101ull * (uint8_t)c;
    case MO_16:
        return 0x0001000100010001ull * (uint16_t)c;
    case MO_32:
        return 0x0000000100000001ull * (uint32_t)c;
    case MO_64:
        return c;
    default:
        g_assert_not_reached();
    }
}

#define dup_const(VECE, C)                                         \
    (__builtin_constant_p(VECE)                                    \
     ? (  (VECE) == MO_8  ? 0x0101010101010101ull * (uint8_t)(C)   \
        : (VECE) == MO_16 ? 0x0001000100010001ull * (uint16_t)(C)  \
        : (VECE) == MO_32 ? 0x0000000100000001ull * (uint32_t)(C)  \
        : dup_const(VECE, C))                                      \
     : dup_const(VECE, C))

#define EXEC_HELPER_HEAD_H

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

#define dh_is_64bit_void 0

#define dh_is_64bit_noreturn 0

#define dh_is_64bit_i32 0

#define dh_is_64bit_i64 1

#define dh_is_64bit_ptr (sizeof(void *) == 8)

#define dh_is_64bit(t) glue(dh_is_64bit_, dh_alias(t))

#define dh_is_signed_void 0

#define dh_is_signed_noreturn 0

#define dh_is_signed_i32 0

#define dh_is_signed_s32 1

#define dh_is_signed_i64 0

#define dh_is_signed_s64 1

#define dh_is_signed_tl  0

#define dh_is_signed_int 1

#define dh_is_signed_ptr 0

#define dh_is_signed_env dh_is_signed_ptr

#define dh_is_signed(t) dh_is_signed_##t

#define dh_sizemask(t, n) \
  ((dh_is_64bit(t) << (n*2)) | (dh_is_signed(t) << (n*2+1)))

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

DEF_HELPER_1(fmov_ST0_FT0, void, env)

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

DEF_HELPER_2(glue(movq_mm_T0, SUFFIX), void, Reg, i64)

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

DEF_HELPER_FLAGS_2(div_i32, TCG_CALL_NO_RWG_SE, s32, s32, s32)

DEF_HELPER_FLAGS_2(rem_i32, TCG_CALL_NO_RWG_SE, s32, s32, s32)

DEF_HELPER_FLAGS_2(divu_i32, TCG_CALL_NO_RWG_SE, i32, i32, i32)

DEF_HELPER_FLAGS_2(remu_i32, TCG_CALL_NO_RWG_SE, i32, i32, i32)

DEF_HELPER_FLAGS_2(div_i64, TCG_CALL_NO_RWG_SE, s64, s64, s64)

DEF_HELPER_FLAGS_2(rem_i64, TCG_CALL_NO_RWG_SE, s64, s64, s64)

DEF_HELPER_FLAGS_2(divu_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64)

DEF_HELPER_FLAGS_2(remu_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64)

DEF_HELPER_FLAGS_2(shl_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64)

DEF_HELPER_FLAGS_2(shr_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64)

DEF_HELPER_FLAGS_2(sar_i64, TCG_CALL_NO_RWG_SE, s64, s64, s64)

DEF_HELPER_FLAGS_2(mulsh_i64, TCG_CALL_NO_RWG_SE, s64, s64, s64)

DEF_HELPER_FLAGS_2(muluh_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64)

DEF_HELPER_FLAGS_2(clz_i32, TCG_CALL_NO_RWG_SE, i32, i32, i32)

DEF_HELPER_FLAGS_2(ctz_i32, TCG_CALL_NO_RWG_SE, i32, i32, i32)

DEF_HELPER_FLAGS_2(clz_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64)

DEF_HELPER_FLAGS_2(ctz_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64)

DEF_HELPER_FLAGS_1(clrsb_i32, TCG_CALL_NO_RWG_SE, i32, i32)

DEF_HELPER_FLAGS_1(clrsb_i64, TCG_CALL_NO_RWG_SE, i64, i64)

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

DEF_HELPER_FLAGS_3(gvec_mov, TCG_CALL_NO_RWG, void, ptr, ptr, i32)

DEF_HELPER_FLAGS_3(gvec_dup8, TCG_CALL_NO_RWG, void, ptr, i32, i32)

DEF_HELPER_FLAGS_3(gvec_dup16, TCG_CALL_NO_RWG, void, ptr, i32, i32)

DEF_HELPER_FLAGS_3(gvec_dup32, TCG_CALL_NO_RWG, void, ptr, i32, i32)

DEF_HELPER_FLAGS_3(gvec_dup64, TCG_CALL_NO_RWG, void, ptr, i32, i64)

DEF_HELPER_FLAGS_4(gvec_add8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_add16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_add32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_add64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_adds8, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)

DEF_HELPER_FLAGS_4(gvec_adds16, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)

DEF_HELPER_FLAGS_4(gvec_adds32, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)

DEF_HELPER_FLAGS_4(gvec_adds64, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)

DEF_HELPER_FLAGS_4(gvec_sub8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_sub16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_sub32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_sub64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_subs8, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)

DEF_HELPER_FLAGS_4(gvec_subs16, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)

DEF_HELPER_FLAGS_4(gvec_subs32, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)

DEF_HELPER_FLAGS_4(gvec_subs64, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)

DEF_HELPER_FLAGS_4(gvec_mul8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_mul16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_mul32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_mul64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_muls8, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)

DEF_HELPER_FLAGS_4(gvec_muls16, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)

DEF_HELPER_FLAGS_4(gvec_muls32, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)

DEF_HELPER_FLAGS_4(gvec_muls64, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)

DEF_HELPER_FLAGS_4(gvec_ssadd8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_ssadd16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_ssadd32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_ssadd64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_sssub8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_sssub16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_sssub32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_sssub64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_usadd8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_usadd16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_usadd32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_usadd64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_ussub8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_ussub16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_ussub32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_ussub64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_3(gvec_neg8, TCG_CALL_NO_RWG, void, ptr, ptr, i32)

DEF_HELPER_FLAGS_3(gvec_neg16, TCG_CALL_NO_RWG, void, ptr, ptr, i32)

DEF_HELPER_FLAGS_3(gvec_neg32, TCG_CALL_NO_RWG, void, ptr, ptr, i32)

DEF_HELPER_FLAGS_3(gvec_neg64, TCG_CALL_NO_RWG, void, ptr, ptr, i32)

DEF_HELPER_FLAGS_3(gvec_not, TCG_CALL_NO_RWG, void, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_and, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_or, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_xor, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_andc, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_orc, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_ands, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)

DEF_HELPER_FLAGS_4(gvec_xors, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)

DEF_HELPER_FLAGS_4(gvec_ors, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)

DEF_HELPER_FLAGS_3(gvec_shl8i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)

DEF_HELPER_FLAGS_3(gvec_shl16i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)

DEF_HELPER_FLAGS_3(gvec_shl32i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)

DEF_HELPER_FLAGS_3(gvec_shl64i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)

DEF_HELPER_FLAGS_3(gvec_shr8i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)

DEF_HELPER_FLAGS_3(gvec_shr16i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)

DEF_HELPER_FLAGS_3(gvec_shr32i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)

DEF_HELPER_FLAGS_3(gvec_shr64i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)

DEF_HELPER_FLAGS_3(gvec_sar8i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)

DEF_HELPER_FLAGS_3(gvec_sar16i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)

DEF_HELPER_FLAGS_3(gvec_sar32i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)

DEF_HELPER_FLAGS_3(gvec_sar64i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_eq8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_eq16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_eq32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_eq64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_ne8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_ne16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_ne32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_ne64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_lt8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_lt16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_lt32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_lt64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_le8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_le16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_le32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_le64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_ltu8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_ltu16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_ltu32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_ltu64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_leu8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_leu16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_leu32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_leu64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

#define DEF_HELPER_FLAGS_1(name, flags, ret, t1)                        \
static inline void glue(gen_helper_, name)(dh_retvar_decl(ret)          \
    dh_arg_decl(t1, 1))                                                 \
{                                                                       \
  TCGTemp *args[1] = { dh_arg(t1, 1) };                                 \
  tcg_gen_callN((void *)HELPER(name), dh_retvar(ret), 1, args);                 \
}

#define DEF_HELPER_FLAGS_2(name, flags, ret, t1, t2)                    \
static inline void glue(gen_helper_, name)(dh_retvar_decl(ret)          \
    dh_arg_decl(t1, 1), dh_arg_decl(t2, 2))                             \
{                                                                       \
  TCGTemp *args[2] = { dh_arg(t1, 1), dh_arg(t2, 2) };                  \
  tcg_gen_callN((void *)HELPER(name), dh_retvar(ret), 2, args);                 \
}

#define DEF_HELPER_FLAGS_3(name, flags, ret, t1, t2, t3)                \
static inline void glue(gen_helper_, name)(dh_retvar_decl(ret)          \
    dh_arg_decl(t1, 1), dh_arg_decl(t2, 2), dh_arg_decl(t3, 3))         \
{                                                                       \
  TCGTemp *args[3] = { dh_arg(t1, 1), dh_arg(t2, 2), dh_arg(t3, 3) };   \
  tcg_gen_callN((void *)HELPER(name), dh_retvar(ret), 3, args);                 \
}

#define DEF_HELPER_FLAGS_4(name, flags, ret, t1, t2, t3, t4)            \
static inline void glue(gen_helper_, name)(dh_retvar_decl(ret)          \
    dh_arg_decl(t1, 1), dh_arg_decl(t2, 2),                             \
    dh_arg_decl(t3, 3), dh_arg_decl(t4, 4))                             \
{                                                                       \
  TCGTemp *args[4] = { dh_arg(t1, 1), dh_arg(t2, 2),                    \
                     dh_arg(t3, 3), dh_arg(t4, 4) };                    \
  tcg_gen_callN((void *)HELPER(name), dh_retvar(ret), 4, args);                 \
}

#define DEF_HELPER_FLAGS_5(name, flags, ret, t1, t2, t3, t4, t5)        \
static inline void glue(gen_helper_, name)(dh_retvar_decl(ret)          \
    dh_arg_decl(t1, 1),  dh_arg_decl(t2, 2), dh_arg_decl(t3, 3),        \
    dh_arg_decl(t4, 4), dh_arg_decl(t5, 5))                             \
{                                                                       \
  TCGTemp *args[5] = { dh_arg(t1, 1), dh_arg(t2, 2), dh_arg(t3, 3),     \
                     dh_arg(t4, 4), dh_arg(t5, 5) };                    \
  tcg_gen_callN((void *)HELPER(name), dh_retvar(ret), 5, args);                 \
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

void tcg_gen_andi_i32(TCGv_i32 ret, TCGv_i32 arg1, int32_t arg2);

void tcg_gen_ori_i32(TCGv_i32 ret, TCGv_i32 arg1, int32_t arg2);

void tcg_gen_xori_i32(TCGv_i32 ret, TCGv_i32 arg1, int32_t arg2);

void tcg_gen_sari_i32(TCGv_i32 ret, TCGv_i32 arg1, int32_t arg2);

void tcg_gen_ctpop_i32(TCGv_i32 a1, TCGv_i32 a2);

void tcg_gen_rotl_i32(TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2);

void tcg_gen_rotli_i32(TCGv_i32 ret, TCGv_i32 arg1, unsigned arg2);

void tcg_gen_rotr_i32(TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2);

void tcg_gen_rotri_i32(TCGv_i32 ret, TCGv_i32 arg1, unsigned arg2);

void tcg_gen_brcondi_i32(TCGCond cond, TCGv_i32 arg1, int32_t arg2, TCGLabel *);

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

static inline void tcg_gen_st16_i32(TCGv_i32 arg1, TCGv_ptr arg2,
                                    tcg_target_long offset)
{
    tcg_gen_ldst_op_i32(INDEX_op_st16_i32, arg1, arg2, offset);
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

void tcg_gen_andi_i64(TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2);

void tcg_gen_ori_i64(TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2);

void tcg_gen_xori_i64(TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2);

void tcg_gen_shli_i64(TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2);

void tcg_gen_shri_i64(TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2);

void tcg_gen_sari_i64(TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2);

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

#define tcg_global_mem_new tcg_global_mem_new_i64

#define tcg_temp_local_new() tcg_temp_local_new_i64()

#define tcg_temp_free tcg_temp_free_i64

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

void tcg_gen_atomic_xor_fetch_i64(TCGv_i64, TCGv, TCGv_i64, TCGArg, TCGMemOp);

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

#define R_386_32	1

#define R_386_PC32	2

#define R_386_PC8	23

void disas(FILE *out, void *code, unsigned long size);

void target_disas(FILE *out, CPUState *cpu, target_ulong code,
                  target_ulong size);

const char *lookup_symbol(target_ulong orig_addr);

static inline void log_target_disas(CPUState *cpu, target_ulong start,
                                    target_ulong len)
{
    target_disas(qemu_logfile, cpu, start, len);
}

static inline void log_disas(void *code, unsigned long size)
{
    disas(qemu_logfile, code, size);
}

static void patch_reloc(tcg_insn_unit *code_ptr, int type,
                        intptr_t value, intptr_t addend);

#define TCG_HIGHWATER 1024

static TCGContext **tcg_ctxs;

static unsigned int n_tcg_ctxs;

TCGv_env cpu_env = 0;

struct tcg_region_state {
    QemuMutex lock;

    /* fields set at init time */
    void *start;
    void *start_aligned;
    void *end;
    size_t n;
    size_t size; /* size of one region */
    size_t stride; /* .size + guard size */

    /* fields protected by the lock */
    size_t current; /* current region index */
    size_t agg_size_full; /* aggregate size of full regions */
};

static struct tcg_region_state region;

static TCGRegSet tcg_target_available_regs[TCG_TYPE_COUNT];

static TCGRegSet tcg_target_call_clobber_regs;

static __attribute__((unused)) inline void tcg_out8(TCGContext *s, uint8_t v)
{
    *s->code_ptr++ = v;
}

static __attribute__((unused)) inline void tcg_patch8(tcg_insn_unit *p,
                                                      uint8_t v)
{
    *p = v;
}

static __attribute__((unused)) inline void tcg_out16(TCGContext *s, uint16_t v)
{
    if (TCG_TARGET_INSN_UNIT_SIZE == 2) {
        *s->code_ptr++ = v;
    } else {
        tcg_insn_unit *p = s->code_ptr;
        memcpy(p, &v, sizeof(v));
        s->code_ptr = p + (2 / TCG_TARGET_INSN_UNIT_SIZE);
    }
}

static __attribute__((unused)) inline void tcg_out32(TCGContext *s, uint32_t v)
{
    if (TCG_TARGET_INSN_UNIT_SIZE == 4) {
        *s->code_ptr++ = v;
    } else {
        tcg_insn_unit *p = s->code_ptr;
        memcpy(p, &v, sizeof(v));
        s->code_ptr = p + (4 / TCG_TARGET_INSN_UNIT_SIZE);
    }
}

static __attribute__((unused)) inline void tcg_patch32(tcg_insn_unit *p,
                                                       uint32_t v)
{
    if (TCG_TARGET_INSN_UNIT_SIZE == 4) {
        *p = v;
    } else {
        memcpy(p, &v, sizeof(v));
    }
}

static __attribute__((unused)) inline void tcg_out64(TCGContext *s, uint64_t v)
{
    if (TCG_TARGET_INSN_UNIT_SIZE == 8) {
        *s->code_ptr++ = v;
    } else {
        tcg_insn_unit *p = s->code_ptr;
        memcpy(p, &v, sizeof(v));
        s->code_ptr = p + (8 / TCG_TARGET_INSN_UNIT_SIZE);
    }
}

static void tcg_out_reloc(TCGContext *s, tcg_insn_unit *code_ptr, int type,
                          TCGLabel *l, intptr_t addend)
{
    TCGRelocation *r;

    if (l->has_value) {
        /* FIXME: This may break relocations on RISC targets that
           modify instruction fields in place.  The caller may not have 
           written the initial value.  */
        patch_reloc(code_ptr, type, l->u.value, addend);
    } else {
        /* add a new relocation entry */
        r = (TCGRelocation *)tcg_malloc(sizeof(TCGRelocation));
        r->type = type;
        r->ptr = code_ptr;
        r->addend = addend;
        r->next = l->u.first_reloc;
        l->u.first_reloc = r;
    }
}

static void tcg_out_label(TCGContext *s, TCGLabel *l, tcg_insn_unit *ptr)
{
    intptr_t value = (intptr_t)ptr;
    TCGRelocation *r;

    tcg_debug_assert(!l->has_value);

    for (r = l->u.first_reloc; r != NULL; r = r->next) {
        patch_reloc(r->ptr, r->type, value, r->addend);
    }

    l->has_value = 1;
    l->u.value_ptr = ptr;
}

TCGLabel *gen_new_label(void)
{
    TCGContext *s = tcg_ctx;
    TCGLabel *l = (TCGLabel *)tcg_malloc(sizeof(TCGLabel));

    *l = (TCGLabel){
        .id = (unsigned)s->nb_labels++
    };

    return l;
}

typedef struct TCGLabelPoolData {
    struct TCGLabelPoolData *next;
    tcg_insn_unit *label;
    intptr_t addend;
    int rtype;
    unsigned nlong;
    tcg_target_ulong data[];
} TCGLabelPoolData;

static TCGLabelPoolData *new_pool_alloc(TCGContext *s, int nlong, int rtype,
                                        tcg_insn_unit *label, intptr_t addend)
{
    TCGLabelPoolData *n = (TCGLabelPoolData *)tcg_malloc(sizeof(TCGLabelPoolData)
                                     + sizeof(tcg_target_ulong) * nlong);

    n->label = label;
    n->addend = addend;
    n->rtype = rtype;
    n->nlong = nlong;
    return n;
}

static void new_pool_insert(TCGContext *s, TCGLabelPoolData *n)
{
    TCGLabelPoolData *i, **pp;
    int nlong = n->nlong;

    /* Insertion sort on the pool.  */
    for (pp = &s->pool_labels; (i = *pp) != NULL; pp = &i->next) {
        if (nlong > i->nlong) {
            break;
        }
        if (nlong < i->nlong) {
            continue;
        }
        if (memcmp(n->data, i->data, sizeof(tcg_target_ulong) * nlong) >= 0) {
            break;
        }
    }
    n->next = *pp;
    *pp = n;
}

static inline void new_pool_label(TCGContext *s, tcg_target_ulong d, int rtype,
                                  tcg_insn_unit *label, intptr_t addend)
{
    TCGLabelPoolData *n = new_pool_alloc(s, 1, rtype, label, addend);
    n->data[0] = d;
    new_pool_insert(s, n);
}

static void tcg_out_nop_fill(tcg_insn_unit *p, int count);

static bool tcg_out_pool_finalize(TCGContext *s)
{
    TCGLabelPoolData *p = s->pool_labels;
    TCGLabelPoolData *l = NULL;
    void *a;

    if (p == NULL) {
        return true;
    }

    /* ??? Round up to qemu_icache_linesize, but then do not round
       again when allocating the next TranslationBlock structure.  */
    a = (void *)ROUND_UP((uintptr_t)s->code_ptr,
                         sizeof(tcg_target_ulong) * p->nlong);
    tcg_out_nop_fill(s->code_ptr, (tcg_insn_unit *)a - s->code_ptr);
    s->data_gen_ptr = a;

    for (; p != NULL; p = p->next) {
        size_t size = sizeof(tcg_target_ulong) * p->nlong;
        if (!l || l->nlong != p->nlong || memcmp(l->data, p->data, size)) {
            if (unlikely(a > s->code_gen_highwater)) {
                return false;
            }
            memcpy(a, p->data, size);
            a = ((char *)a + size);
            l = p;
        }
        patch_reloc(p->label, p->rtype, (intptr_t)a - size, p->addend);
    }

    s->code_ptr = (tcg_insn_unit *)a;
    return true;
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
    TCG_REG_XMM0,
    TCG_REG_XMM1,
    TCG_REG_XMM2,
    TCG_REG_XMM3,
    TCG_REG_XMM4,
    TCG_REG_XMM5,
#ifndef _WIN64
    /* The Win64 ABI has xmm6-xmm15 as caller-saves, and we do not save
       any of them.  Therefore only allow xmm0-xmm5 to be allocated.  */
    TCG_REG_XMM6,
    TCG_REG_XMM7,
#if TCG_TARGET_REG_BITS == 64
    TCG_REG_XMM8,
    TCG_REG_XMM9,
    TCG_REG_XMM10,
    TCG_REG_XMM11,
    TCG_REG_XMM12,
    TCG_REG_XMM13,
    TCG_REG_XMM14,
    TCG_REG_XMM15,
#endif
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

static const int tcg_target_call_oarg_regs[] = {
    TCG_REG_EAX,
#if TCG_TARGET_REG_BITS == 32
    TCG_REG_EDX
#endif
};

# define have_cmov 1

bool have_bmi1;

bool have_popcnt;

bool have_avx1;

bool have_avx2;

static bool have_movbe;

static bool have_bmi2;

static bool have_lzcnt;

static tcg_insn_unit *tb_ret_addr;

#define ALL_GENERAL_REGS   0x0000ffffu

#define ALL_VECTOR_REGS    0xffff0000u

static void patch_reloc(tcg_insn_unit *code_ptr, int type,
                        intptr_t value, intptr_t addend)
{
    value += addend;
    switch(type) {
    case R_386_PC32:
        value -= (uintptr_t)code_ptr;
        if (value != (int32_t)value) {
            tcg_abort();
        }
        /* FALLTHRU */
    case R_386_32:
        tcg_patch32(code_ptr, value);
        break;
    case R_386_PC8:
        value -= (uintptr_t)code_ptr;
        if (value != (int8_t)value) {
            tcg_abort();
        }
        tcg_patch8(code_ptr, value);
        break;
    default:
        tcg_abort();
    }
}

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
        /* A register that can be used as a byte operand.  */
        ct->ct |= TCG_CT_REG;
        ct->u.regs = TCG_TARGET_REG_BITS == 64 ? 0xffff : 0xf;
        break;
    case 'Q':
        /* A register with an addressable second byte (e.g. %ah).  */
        ct->ct |= TCG_CT_REG;
        ct->u.regs = 0xf;
        break;
    case 'r':
        /* A general register.  */
        ct->ct |= TCG_CT_REG;
        ct->u.regs |= ALL_GENERAL_REGS;
        break;
    case 'W':
        /* With TZCNT/LZCNT, we can have operand-size as an input.  */
        ct->ct |= TCG_CT_CONST_WSZ;
        break;
    case 'x':
        /* A vector register.  */
        ct->ct |= TCG_CT_REG;
        ct->u.regs |= ALL_VECTOR_REGS;
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

# define LOWREGMASK(x)	((x) & 7)

#define P_EXT		0x100

#define P_EXT38         0x200

#define P_DATA16        0x400

# define P_ADDR32       0x800

# define P_REXW         0x1000

# define P_REXB_R       0x2000

# define P_REXB_RM      0x4000

# define P_GS           0x8000

#define P_EXT3A         0x10000

#define P_SIMDF3        0x20000

#define P_SIMDF2        0x40000

#define P_VEXL          0x80000

#define OPC_ARITH_EvIz	(0x81)

#define OPC_ARITH_EvIb	(0x83)

#define OPC_ARITH_GvEv	(0x03)

#define OPC_ANDN        (0xf2 | P_EXT38)

#define OPC_BLENDPS     (0x0c | P_EXT3A | P_DATA16)

#define OPC_BSF         (0xbc | P_EXT)

#define OPC_BSR         (0xbd | P_EXT)

#define OPC_BSWAP	(0xc8 | P_EXT)

#define OPC_CALL_Jz	(0xe8)

#define OPC_CMOVCC      (0x40 | P_EXT)

#define OPC_DEC_r32	(0x48)

#define OPC_IMUL_GvEv	(0xaf | P_EXT)

#define OPC_IMUL_GvEvIb	(0x6b)

#define OPC_IMUL_GvEvIz	(0x69)

#define OPC_INC_r32	(0x40)

#define OPC_JCC_long	(0x80 | P_EXT)

#define OPC_JCC_short	(0x70)

#define OPC_JMP_long	(0xe9)

#define OPC_JMP_short	(0xeb)

#define OPC_LEA         (0x8d)

#define OPC_LZCNT       (0xbd | P_EXT | P_SIMDF3)

#define OPC_MOVB_EvGv	(0x88)

#define OPC_MOVL_EvGv	(0x89)

#define OPC_MOVL_GvEv	(0x8b)

#define OPC_MOVB_EvIz   (0xc6)

#define OPC_MOVL_EvIz	(0xc7)

#define OPC_MOVL_Iv     (0xb8)

#define OPC_MOVBE_GyMy  (0xf0 | P_EXT38)

#define OPC_MOVBE_MyGy  (0xf1 | P_EXT38)

#define OPC_MOVD_VyEy   (0x6e | P_EXT | P_DATA16)

#define OPC_MOVD_EyVy   (0x7e | P_EXT | P_DATA16)

#define OPC_MOVDDUP     (0x12 | P_EXT | P_SIMDF2)

#define OPC_MOVDQA_VxWx (0x6f | P_EXT | P_DATA16)

#define OPC_MOVDQU_VxWx (0x6f | P_EXT | P_SIMDF3)

#define OPC_MOVDQU_WxVx (0x7f | P_EXT | P_SIMDF3)

#define OPC_MOVQ_VqWq   (0x7e | P_EXT | P_SIMDF3)

#define OPC_MOVQ_WqVq   (0xd6 | P_EXT | P_DATA16)

#define OPC_MOVSBL	(0xbe | P_EXT)

#define OPC_MOVSWL	(0xbf | P_EXT)

#define OPC_MOVSLQ	(0x63 | P_REXW)

#define OPC_MOVZBL	(0xb6 | P_EXT)

#define OPC_MOVZWL	(0xb7 | P_EXT)

#define OPC_PACKSSDW    (0x6b | P_EXT | P_DATA16)

#define OPC_PACKSSWB    (0x63 | P_EXT | P_DATA16)

#define OPC_PACKUSDW    (0x2b | P_EXT38 | P_DATA16)

#define OPC_PACKUSWB    (0x67 | P_EXT | P_DATA16)

#define OPC_PADDB       (0xfc | P_EXT | P_DATA16)

#define OPC_PADDW       (0xfd | P_EXT | P_DATA16)

#define OPC_PADDD       (0xfe | P_EXT | P_DATA16)

#define OPC_PADDQ       (0xd4 | P_EXT | P_DATA16)

#define OPC_PAND        (0xdb | P_EXT | P_DATA16)

#define OPC_PANDN       (0xdf | P_EXT | P_DATA16)

#define OPC_PBLENDW     (0x0e | P_EXT3A | P_DATA16)

#define OPC_PCMPEQB     (0x74 | P_EXT | P_DATA16)

#define OPC_PCMPEQW     (0x75 | P_EXT | P_DATA16)

#define OPC_PCMPEQD     (0x76 | P_EXT | P_DATA16)

#define OPC_PCMPEQQ     (0x29 | P_EXT38 | P_DATA16)

#define OPC_PCMPGTB     (0x64 | P_EXT | P_DATA16)

#define OPC_PCMPGTW     (0x65 | P_EXT | P_DATA16)

#define OPC_PCMPGTD     (0x66 | P_EXT | P_DATA16)

#define OPC_PCMPGTQ     (0x37 | P_EXT38 | P_DATA16)

#define OPC_PMULLW      (0xd5 | P_EXT | P_DATA16)

#define OPC_PMULLD      (0x40 | P_EXT38 | P_DATA16)

#define OPC_POR         (0xeb | P_EXT | P_DATA16)

#define OPC_PSHUFD      (0x70 | P_EXT | P_DATA16)

#define OPC_PSHIFTW_Ib  (0x71 | P_EXT | P_DATA16)

#define OPC_PSHIFTD_Ib  (0x72 | P_EXT | P_DATA16)

#define OPC_PSHIFTQ_Ib  (0x73 | P_EXT | P_DATA16)

#define OPC_PSUBB       (0xf8 | P_EXT | P_DATA16)

#define OPC_PSUBW       (0xf9 | P_EXT | P_DATA16)

#define OPC_PSUBD       (0xfa | P_EXT | P_DATA16)

#define OPC_PSUBQ       (0xfb | P_EXT | P_DATA16)

#define OPC_PUNPCKLBW   (0x60 | P_EXT | P_DATA16)

#define OPC_PUNPCKLWD   (0x61 | P_EXT | P_DATA16)

#define OPC_PUNPCKLDQ   (0x62 | P_EXT | P_DATA16)

#define OPC_PUNPCKLQDQ  (0x6c | P_EXT | P_DATA16)

#define OPC_PUNPCKHBW   (0x68 | P_EXT | P_DATA16)

#define OPC_PUNPCKHWD   (0x69 | P_EXT | P_DATA16)

#define OPC_PUNPCKHDQ   (0x6a | P_EXT | P_DATA16)

#define OPC_PUNPCKHQDQ  (0x6d | P_EXT | P_DATA16)

#define OPC_PXOR        (0xef | P_EXT | P_DATA16)

#define OPC_POPCNT      (0xb8 | P_EXT | P_SIMDF3)

#define OPC_SETCC	(0x90 | P_EXT | P_REXB_RM)

#define OPC_SHIFT_1	(0xd1)

#define OPC_SHIFT_Ib	(0xc1)

#define OPC_SHIFT_cl	(0xd3)

#define OPC_SARX        (0xf7 | P_EXT38 | P_SIMDF3)

#define OPC_SHUFPS      (0xc6 | P_EXT)

#define OPC_SHLX        (0xf7 | P_EXT38 | P_DATA16)

#define OPC_SHRX        (0xf7 | P_EXT38 | P_SIMDF2)

#define OPC_TESTL	(0x85)

#define OPC_TZCNT       (0xbc | P_EXT | P_SIMDF3)

#define OPC_UD2         (0x0b | P_EXT)

#define OPC_VPBLENDD    (0x02 | P_EXT3A | P_DATA16)

#define OPC_VPBLENDVB   (0x4c | P_EXT3A | P_DATA16)

#define OPC_VPBROADCASTB (0x78 | P_EXT38 | P_DATA16)

#define OPC_VPBROADCASTW (0x79 | P_EXT38 | P_DATA16)

#define OPC_VPBROADCASTD (0x58 | P_EXT38 | P_DATA16)

#define OPC_VPBROADCASTQ (0x59 | P_EXT38 | P_DATA16)

#define OPC_VPERM2I128  (0x46 | P_EXT3A | P_DATA16 | P_VEXL)

#define OPC_GRP3_Ev	(0xf7)

#define OPC_GRP5	(0xff)

#define OPC_GRP14       (0x73 | P_EXT | P_DATA16)

#define ARITH_ADD 0

#define ARITH_OR  1

#define ARITH_ADC 2

#define ARITH_SBB 3

#define ARITH_AND 4

#define ARITH_SUB 5

#define ARITH_XOR 6

#define ARITH_CMP 7

#define SHIFT_ROL 0

#define SHIFT_ROR 1

#define SHIFT_SHL 4

#define SHIFT_SHR 5

#define SHIFT_SAR 7

#define EXT3_NOT   2

#define EXT3_NEG   3

#define EXT3_MUL   4

#define EXT3_IMUL  5

#define EXT3_DIV   6

#define EXT3_IDIV  7

#define EXT5_INC_Ev	0

#define EXT5_DEC_Ev	1

#define EXT5_CALLN_Ev	2

#define EXT5_JMPN_Ev	4

#define JCC_JMP (-1)

#define JCC_JB  0x2

#define JCC_JAE 0x3

#define JCC_JE  0x4

#define JCC_JNE 0x5

#define JCC_JBE 0x6

#define JCC_JA  0x7

#define JCC_JL  0xc

#define JCC_JGE 0xd

#define JCC_JLE 0xe

#define JCC_JG  0xf

static inline int tcg_target_const_match(tcg_target_long val, TCGType type,
                                         const TCGArgConstraint *arg_ct)
{
    int ct = arg_ct->ct;
    if (ct & TCG_CT_CONST) {
        return 1;
    }
    if ((ct & TCG_CT_CONST_S32) && val == (int32_t)val) {
        return 1;
    }
    if ((ct & TCG_CT_CONST_U32) && val == (uint32_t)val) {
        return 1;
    }
    if ((ct & TCG_CT_CONST_I32) && ~val == (int32_t)~val) {
        return 1;
    }
    if ((ct & TCG_CT_CONST_WSZ) && val == (type == TCG_TYPE_I32 ? 32 : 64)) {
        return 1;
    }
    return 0;
}

static const uint8_t tcg_cond_to_jcc[] = {
    [TCG_COND_EQ] = JCC_JE,
    [TCG_COND_NE] = JCC_JNE,
    [TCG_COND_LT] = JCC_JL,
    [TCG_COND_GE] = JCC_JGE,
    [TCG_COND_LE] = JCC_JLE,
    [TCG_COND_GT] = JCC_JG,
    [TCG_COND_LTU] = JCC_JB,
    [TCG_COND_GEU] = JCC_JAE,
    [TCG_COND_LEU] = JCC_JBE,
    [TCG_COND_GTU] = JCC_JA,
};

static void tcg_out_opc(TCGContext *s, int opc, int r, int rm, int x)
{
    int rex;

    if (opc & P_GS) {
        tcg_out8(s, 0x65);
    }
    if (opc & P_DATA16) {
        /* We should never be asking for both 16 and 64-bit operation.  */
        tcg_debug_assert((opc & P_REXW) == 0);
        tcg_out8(s, 0x66);
    }
    if (opc & P_ADDR32) {
        tcg_out8(s, 0x67);
    }
    if (opc & P_SIMDF3) {
        tcg_out8(s, 0xf3);
    } else if (opc & P_SIMDF2) {
        tcg_out8(s, 0xf2);
    }

    rex = 0;
    rex |= (opc & P_REXW) ? 0x8 : 0x0;  /* REX.W */
    rex |= (r & 8) >> 1;                /* REX.R */
    rex |= (x & 8) >> 2;                /* REX.X */
    rex |= (rm & 8) >> 3;               /* REX.B */

    /* P_REXB_{R,RM} indicates that the given register is the low byte.
       For %[abcd]l we need no REX prefix, but for %{si,di,bp,sp}l we do,
       as otherwise the encoding indicates %[abcd]h.  Note that the values
       that are ORed in merely indicate that the REX byte must be present;
       those bits get discarded in output.  */
    rex |= opc & (r >= 4 ? P_REXB_R : 0);
    rex |= opc & (rm >= 4 ? P_REXB_RM : 0);

    if (rex) {
        tcg_out8(s, (uint8_t)(rex | 0x40));
    }

    if (opc & (P_EXT | P_EXT38 | P_EXT3A)) {
        tcg_out8(s, 0x0f);
        if (opc & P_EXT38) {
            tcg_out8(s, 0x38);
        } else if (opc & P_EXT3A) {
            tcg_out8(s, 0x3a);
        }
    }

    tcg_out8(s, opc);
}

static void tcg_out_modrm(TCGContext *s, int opc, int r, int rm)
{
    tcg_out_opc(s, opc, r, rm, 0);
    tcg_out8(s, 0xc0 | (LOWREGMASK(r) << 3) | LOWREGMASK(rm));
}

static void tcg_out_vex_opc(TCGContext *s, int opc, int r, int v,
                            int rm, int index)
{
    int tmp;

    /* Use the two byte form if possible, which cannot encode
       VEX.W, VEX.B, VEX.X, or an m-mmmm field other than P_EXT.  */
    if ((opc & (P_EXT | P_EXT38 | P_EXT3A | P_REXW)) == P_EXT
        && ((rm | index) & 8) == 0) {
        /* Two byte VEX prefix.  */
        tcg_out8(s, 0xc5);

        tmp = (r & 8 ? 0 : 0x80);              /* VEX.R */
    } else {
        /* Three byte VEX prefix.  */
        tcg_out8(s, 0xc4);

        /* VEX.m-mmmm */
        if (opc & P_EXT3A) {
            tmp = 3;
        } else if (opc & P_EXT38) {
            tmp = 2;
        } else if (opc & P_EXT) {
            tmp = 1;
        } else {
            g_assert_not_reached();
        }
        tmp |= (r & 8 ? 0 : 0x80);             /* VEX.R */
        tmp |= (index & 8 ? 0 : 0x40);         /* VEX.X */
        tmp |= (rm & 8 ? 0 : 0x20);            /* VEX.B */
        tcg_out8(s, tmp);

        tmp = (opc & P_REXW ? 0x80 : 0);       /* VEX.W */
    }

    tmp |= (opc & P_VEXL ? 0x04 : 0);      /* VEX.L */
    /* VEX.pp */
    if (opc & P_DATA16) {
        tmp |= 1;                          /* 0x66 */
    } else if (opc & P_SIMDF3) {
        tmp |= 2;                          /* 0xf3 */
    } else if (opc & P_SIMDF2) {
        tmp |= 3;                          /* 0xf2 */
    }
    tmp |= (~v & 15) << 3;                 /* VEX.vvvv */
    tcg_out8(s, tmp);
    tcg_out8(s, opc);
}

static void tcg_out_vex_modrm(TCGContext *s, int opc, int r, int v, int rm)
{
    tcg_out_vex_opc(s, opc, r, v, rm, 0);
    tcg_out8(s, 0xc0 | (LOWREGMASK(r) << 3) | LOWREGMASK(rm));
}

static void tcg_out_sib_offset(TCGContext *s, int r, int rm, int index,
                               int shift, intptr_t offset)
{
    int mod, len;

    if (index < 0 && rm < 0) {
        if (TCG_TARGET_REG_BITS == 64) {
            /* Try for a rip-relative addressing mode.  This has replaced
               the 32-bit-mode absolute addressing encoding.  */
            intptr_t pc = (intptr_t)s->code_ptr + 5 + ~rm;
            intptr_t disp = offset - pc;
            if (disp == (int32_t)disp) {
                tcg_out8(s, (LOWREGMASK(r) << 3) | 5);
                tcg_out32(s, disp);
                return;
            }

            /* Try for an absolute address encoding.  This requires the
               use of the MODRM+SIB encoding and is therefore larger than
               rip-relative addressing.  */
            if (offset == (int32_t)offset) {
                tcg_out8(s, (LOWREGMASK(r) << 3) | 4);
                tcg_out8(s, (4 << 3) | 5);
                tcg_out32(s, offset);
                return;
            }

            /* ??? The memory isn't directly addressable.  */
            g_assert_not_reached();
        } else {
            /* Absolute address.  */
            tcg_out8(s, (r << 3) | 5);
            tcg_out32(s, offset);
            return;
        }
    }

    /* Find the length of the immediate addend.  Note that the encoding
       that would be used for (%ebp) indicates absolute addressing.  */
    if (rm < 0) {
        mod = 0, len = 4, rm = 5;
    } else if (offset == 0 && LOWREGMASK(rm) != TCG_REG_EBP) {
        mod = 0, len = 0;
    } else if (offset == (int8_t)offset) {
        mod = 0x40, len = 1;
    } else {
        mod = 0x80, len = 4;
    }

    /* Use a single byte MODRM format if possible.  Note that the encoding
       that would be used for %esp is the escape to the two byte form.  */
    if (index < 0 && LOWREGMASK(rm) != TCG_REG_ESP) {
        /* Single byte MODRM format.  */
        tcg_out8(s, mod | (LOWREGMASK(r) << 3) | LOWREGMASK(rm));
    } else {
        /* Two byte MODRM+SIB format.  */

        /* Note that the encoding that would place %esp into the index
           field indicates no index register.  In 64-bit mode, the REX.X
           bit counts, so %r12 can be used as the index.  */
        if (index < 0) {
            index = 4;
        } else {
            tcg_debug_assert(index != TCG_REG_ESP);
        }

        tcg_out8(s, mod | (LOWREGMASK(r) << 3) | 4);
        tcg_out8(s, (shift << 6) | (LOWREGMASK(index) << 3) | LOWREGMASK(rm));
    }

    if (len == 1) {
        tcg_out8(s, offset);
    } else if (len == 4) {
        tcg_out32(s, offset);
    }
}

static void tcg_out_modrm_sib_offset(TCGContext *s, int opc, int r, int rm,
                                     int index, int shift, intptr_t offset)
{
    tcg_out_opc(s, opc, r, rm < 0 ? 0 : rm, index < 0 ? 0 : index);
    tcg_out_sib_offset(s, r, rm, index, shift, offset);
}

static void tcg_out_vex_modrm_sib_offset(TCGContext *s, int opc, int r, int v,
                                         int rm, int index, int shift,
                                         intptr_t offset)
{
    tcg_out_vex_opc(s, opc, r, v, rm < 0 ? 0 : rm, index < 0 ? 0 : index);
    tcg_out_sib_offset(s, r, rm, index, shift, offset);
}

static inline void tcg_out_modrm_offset(TCGContext *s, int opc, int r,
                                        int rm, intptr_t offset)
{
    tcg_out_modrm_sib_offset(s, opc, r, rm, -1, 0, offset);
}

static inline void tcg_out_vex_modrm_offset(TCGContext *s, int opc, int r,
                                            int v, int rm, intptr_t offset)
{
    tcg_out_vex_modrm_sib_offset(s, opc, r, v, rm, -1, 0, offset);
}

static inline void tcg_out_vex_modrm_pool(TCGContext *s, int opc, int r)
{
    tcg_out_vex_opc(s, opc, r, 0, 0, 0);
    /* Absolute for 32-bit, pc-relative for 64-bit.  */
    tcg_out8(s, LOWREGMASK(r) << 3 | 5);
    tcg_out32(s, 0);
}

static inline void tgen_arithr(TCGContext *s, int subop, int dest, int src)
{
    /* Propagate an opcode prefix, such as P_REXW.  */
    int ext = subop & ~0x7;
    subop &= 0x7;

    tcg_out_modrm(s, OPC_ARITH_GvEv + (subop << 3) + ext, dest, src);
}

static void tcg_out_mov(TCGContext *s, TCGType type, TCGReg ret, TCGReg arg)
{
    int rexw = 0;

    if (arg == ret) {
        return;
    }
    switch (type) {
    case TCG_TYPE_I64:
        rexw = P_REXW;
        /* fallthru */
    case TCG_TYPE_I32:
        if (ret < 16) {
            if (arg < 16) {
                tcg_out_modrm(s, OPC_MOVL_GvEv + rexw, ret, arg);
            } else {
                tcg_out_vex_modrm(s, OPC_MOVD_EyVy + rexw, arg, 0, ret);
            }
        } else {
            if (arg < 16) {
                tcg_out_vex_modrm(s, OPC_MOVD_VyEy + rexw, ret, 0, arg);
            } else {
                tcg_out_vex_modrm(s, OPC_MOVQ_VqWq, ret, 0, arg);
            }
        }
        break;

    case TCG_TYPE_V64:
        tcg_debug_assert(ret >= 16 && arg >= 16);
        tcg_out_vex_modrm(s, OPC_MOVQ_VqWq, ret, 0, arg);
        break;
    case TCG_TYPE_V128:
        tcg_debug_assert(ret >= 16 && arg >= 16);
        tcg_out_vex_modrm(s, OPC_MOVDQA_VxWx, ret, 0, arg);
        break;
    case TCG_TYPE_V256:
        tcg_debug_assert(ret >= 16 && arg >= 16);
        tcg_out_vex_modrm(s, OPC_MOVDQA_VxWx | P_VEXL, ret, 0, arg);
        break;

    default:
        g_assert_not_reached();
    }
}

static void tcg_out_dup_vec(TCGContext *s, TCGType type, unsigned vece,
                            TCGReg r, TCGReg a)
{
    if (have_avx2) {
        static const int dup_insn[4] = {
            OPC_VPBROADCASTB, OPC_VPBROADCASTW,
            OPC_VPBROADCASTD, OPC_VPBROADCASTQ,
        };
        int vex_l = (type == TCG_TYPE_V256 ? P_VEXL : 0);
        tcg_out_vex_modrm(s, dup_insn[vece] + vex_l, r, 0, a);
    } else {
        switch (vece) {
        case MO_8:
            /* ??? With zero in a register, use PSHUFB.  */
            tcg_out_vex_modrm(s, OPC_PUNPCKLBW, r, 0, a);
            a = r;
            /* FALLTHRU */
        case MO_16:
            tcg_out_vex_modrm(s, OPC_PUNPCKLWD, r, 0, a);
            a = r;
            /* FALLTHRU */
        case MO_32:
            tcg_out_vex_modrm(s, OPC_PSHUFD, r, 0, a);
            /* imm8 operand: all output lanes selected from input lane 0.  */
            tcg_out8(s, 0);
            break;
        case MO_64:
            tcg_out_vex_modrm(s, OPC_PUNPCKLQDQ, r, 0, a);
            break;
        default:
            g_assert_not_reached();
        }
    }
}

static void tcg_out_dupi_vec(TCGContext *s, TCGType type,
                             TCGReg ret, tcg_target_long arg)
{
    int vex_l = (type == TCG_TYPE_V256 ? P_VEXL : 0);

    if (arg == 0) {
        tcg_out_vex_modrm(s, OPC_PXOR, ret, ret, ret);
        return;
    }
    if (arg == -1) {
        tcg_out_vex_modrm(s, OPC_PCMPEQB + vex_l, ret, ret, ret);
        return;
    }

    if (TCG_TARGET_REG_BITS == 64) {
        if (type == TCG_TYPE_V64) {
            tcg_out_vex_modrm_pool(s, OPC_MOVQ_VqWq, ret);
        } else if (have_avx2) {
            tcg_out_vex_modrm_pool(s, OPC_VPBROADCASTQ + vex_l, ret);
        } else {
            tcg_out_vex_modrm_pool(s, OPC_MOVDDUP, ret);
        }
        new_pool_label(s, arg, R_386_PC32, s->code_ptr - 4, -4);
    } else if (have_avx2) {
        tcg_out_vex_modrm_pool(s, OPC_VPBROADCASTD + vex_l, ret);
        new_pool_label(s, arg, R_386_32, s->code_ptr - 4, 0);
    } else {
        tcg_out_vex_modrm_pool(s, OPC_MOVD_VyEy, ret);
        new_pool_label(s, arg, R_386_32, s->code_ptr - 4, 0);
        tcg_out_dup_vec(s, type, MO_32, ret, ret);
    }
}

static void tcg_out_movi(TCGContext *s, TCGType type,
                         TCGReg ret, tcg_target_long arg)
{
    tcg_target_long diff;

    switch (type) {
    case TCG_TYPE_I32:
#if TCG_TARGET_REG_BITS == 64
    case TCG_TYPE_I64:
#endif
        if (ret < 16) {
            break;
        }
        /* fallthru */
    case TCG_TYPE_V64:
    case TCG_TYPE_V128:
    case TCG_TYPE_V256:
        tcg_debug_assert(ret >= 16);
        tcg_out_dupi_vec(s, type, ret, arg);
        return;
    default:
        g_assert_not_reached();
    }

    if (arg == 0) {
        tgen_arithr(s, ARITH_XOR, ret, ret);
        return;
    }
    if (arg == (uint32_t)arg || type == TCG_TYPE_I32) {
        tcg_out_opc(s, OPC_MOVL_Iv + LOWREGMASK(ret), 0, ret, 0);
        tcg_out32(s, arg);
        return;
    }
    if (arg == (int32_t)arg) {
        tcg_out_modrm(s, OPC_MOVL_EvIz + P_REXW, 0, ret);
        tcg_out32(s, arg);
        return;
    }

    /* Try a 7 byte pc-relative lea before the 10 byte movq.  */
    diff = arg - ((uintptr_t)s->code_ptr + 7);
    if (diff == (int32_t)diff) {
        tcg_out_opc(s, OPC_LEA | P_REXW, ret, 0, 0);
        tcg_out8(s, (LOWREGMASK(ret) << 3) | 5);
        tcg_out32(s, diff);
        return;
    }

    tcg_out_opc(s, OPC_MOVL_Iv + P_REXW + LOWREGMASK(ret), 0, ret, 0);
    tcg_out64(s, arg);
}

static inline void tcg_out_mb(TCGContext *s, TCGArg a0)
{
    /* Given the strength of x86 memory ordering, we only need care for
       store-load ordering.  Experimentally, "lock orl $0,0(%esp)" is
       faster than "mfence", so don't bother with the sse insn.  */
    if (a0 & TCG_MO_ST_LD) {
        tcg_out8(s, 0xf0);
        tcg_out_modrm_offset(s, OPC_ARITH_EvIb, ARITH_OR, TCG_REG_ESP, 0);
        tcg_out8(s, 0);
    }
}

static void tcg_out_ld(TCGContext *s, TCGType type, TCGReg ret,
                       TCGReg arg1, intptr_t arg2)
{
    switch (type) {
    case TCG_TYPE_I32:
        if (ret < 16) {
            tcg_out_modrm_offset(s, OPC_MOVL_GvEv, ret, arg1, arg2);
        } else {
            tcg_out_vex_modrm_offset(s, OPC_MOVD_VyEy, ret, 0, arg1, arg2);
        }
        break;
    case TCG_TYPE_I64:
        if (ret < 16) {
            tcg_out_modrm_offset(s, OPC_MOVL_GvEv | P_REXW, ret, arg1, arg2);
            break;
        }
        /* FALLTHRU */
    case TCG_TYPE_V64:
        tcg_debug_assert(ret >= 16);
        tcg_out_vex_modrm_offset(s, OPC_MOVQ_VqWq, ret, 0, arg1, arg2);
        break;
    case TCG_TYPE_V128:
        tcg_debug_assert(ret >= 16);
        tcg_out_vex_modrm_offset(s, OPC_MOVDQU_VxWx, ret, 0, arg1, arg2);
        break;
    case TCG_TYPE_V256:
        tcg_debug_assert(ret >= 16);
        tcg_out_vex_modrm_offset(s, OPC_MOVDQU_VxWx | P_VEXL,
                                 ret, 0, arg1, arg2);
        break;
    default:
        g_assert_not_reached();
    }
}

static void tcg_out_st(TCGContext *s, TCGType type, TCGReg arg,
                       TCGReg arg1, intptr_t arg2)
{
    switch (type) {
    case TCG_TYPE_I32:
        if (arg < 16) {
            tcg_out_modrm_offset(s, OPC_MOVL_EvGv, arg, arg1, arg2);
        } else {
            tcg_out_vex_modrm_offset(s, OPC_MOVD_EyVy, arg, 0, arg1, arg2);
        }
        break;
    case TCG_TYPE_I64:
        if (arg < 16) {
            tcg_out_modrm_offset(s, OPC_MOVL_EvGv | P_REXW, arg, arg1, arg2);
            break;
        }
        /* FALLTHRU */
    case TCG_TYPE_V64:
        tcg_debug_assert(arg >= 16);
        tcg_out_vex_modrm_offset(s, OPC_MOVQ_WqVq, arg, 0, arg1, arg2);
        break;
    case TCG_TYPE_V128:
        tcg_debug_assert(arg >= 16);
        tcg_out_vex_modrm_offset(s, OPC_MOVDQU_WxVx, arg, 0, arg1, arg2);
        break;
    case TCG_TYPE_V256:
        tcg_debug_assert(arg >= 16);
        tcg_out_vex_modrm_offset(s, OPC_MOVDQU_WxVx | P_VEXL,
                                 arg, 0, arg1, arg2);
        break;
    default:
        g_assert_not_reached();
    }
}

static bool tcg_out_sti(TCGContext *s, TCGType type, TCGArg val,
                        TCGReg base, intptr_t ofs)
{
    int rexw = 0;
    if (TCG_TARGET_REG_BITS == 64 && type == TCG_TYPE_I64) {
        if (val != (int32_t)val) {
            return false;
        }
        rexw = P_REXW;
    } else if (type != TCG_TYPE_I32) {
        return false;
    }
    tcg_out_modrm_offset(s, OPC_MOVL_EvIz | rexw, 0, base, ofs);
    tcg_out32(s, val);
    return true;
}

static void tcg_out_shifti(TCGContext *s, int subopc, int reg, int count)
{
    /* Propagate an opcode prefix, such as P_DATA16.  */
    int ext = subopc & ~0x7;
    subopc &= 0x7;

    if (count == 1) {
        tcg_out_modrm(s, OPC_SHIFT_1 + ext, subopc, reg);
    } else {
        tcg_out_modrm(s, OPC_SHIFT_Ib + ext, subopc, reg);
        tcg_out8(s, count);
    }
}

static inline void tcg_out_bswap32(TCGContext *s, int reg)
{
    tcg_out_opc(s, OPC_BSWAP + LOWREGMASK(reg), 0, reg, 0);
}

static inline void tcg_out_rolw_8(TCGContext *s, int reg)
{
    tcg_out_shifti(s, SHIFT_ROL + P_DATA16, reg, 8);
}

static inline void tcg_out_ext8u(TCGContext *s, int dest, int src)
{
    /* movzbl */
    tcg_debug_assert(src < 4 || TCG_TARGET_REG_BITS == 64);
    tcg_out_modrm(s, OPC_MOVZBL + P_REXB_RM, dest, src);
}

static void tcg_out_ext8s(TCGContext *s, int dest, int src, int rexw)
{
    /* movsbl */
    tcg_debug_assert(src < 4 || TCG_TARGET_REG_BITS == 64);
    tcg_out_modrm(s, OPC_MOVSBL + P_REXB_RM + rexw, dest, src);
}

static inline void tcg_out_ext16u(TCGContext *s, int dest, int src)
{
    /* movzwl */
    tcg_out_modrm(s, OPC_MOVZWL, dest, src);
}

static inline void tcg_out_ext16s(TCGContext *s, int dest, int src, int rexw)
{
    /* movsw[lq] */
    tcg_out_modrm(s, OPC_MOVSWL + rexw, dest, src);
}

static inline void tcg_out_ext32u(TCGContext *s, int dest, int src)
{
    /* 32-bit mov zero extends.  */
    tcg_out_modrm(s, OPC_MOVL_GvEv, dest, src);
}

static inline void tcg_out_ext32s(TCGContext *s, int dest, int src)
{
    tcg_out_modrm(s, OPC_MOVSLQ, dest, src);
}

static inline void tcg_out_bswap64(TCGContext *s, int reg)
{
    tcg_out_opc(s, OPC_BSWAP + P_REXW + LOWREGMASK(reg), 0, reg, 0);
}

static void tgen_arithi(TCGContext *s, int c, int r0,
                        tcg_target_long val, int cf)
{
    int rexw = 0;

    if (TCG_TARGET_REG_BITS == 64) {
        rexw = c & -8;
        c &= 7;
    }

    /* ??? While INC is 2 bytes shorter than ADDL $1, they also induce
       partial flags update stalls on Pentium4 and are not recommended
       by current Intel optimization manuals.  */
    if (!cf && (c == ARITH_ADD || c == ARITH_SUB) && (val == 1 || val == -1)) {
        int is_inc = (c == ARITH_ADD) ^ (val < 0);
        if (TCG_TARGET_REG_BITS == 64) {
            /* The single-byte increment encodings are re-tasked as the
               REX prefixes.  Use the MODRM encoding.  */
            tcg_out_modrm(s, OPC_GRP5 + rexw,
                          (is_inc ? EXT5_INC_Ev : EXT5_DEC_Ev), r0);
        } else {
            tcg_out8(s, (is_inc ? OPC_INC_r32 : OPC_DEC_r32) + r0);
        }
        return;
    }

    if (c == ARITH_AND) {
        if (TCG_TARGET_REG_BITS == 64) {
            if (val == 0xffffffffu) {
                tcg_out_ext32u(s, r0, r0);
                return;
            }
            if (val == (uint32_t)val) {
                /* AND with no high bits set can use a 32-bit operation.  */
                rexw = 0;
            }
        }
        if (val == 0xffu && (r0 < 4 || TCG_TARGET_REG_BITS == 64)) {
            tcg_out_ext8u(s, r0, r0);
            return;
        }
        if (val == 0xffffu) {
            tcg_out_ext16u(s, r0, r0);
            return;
        }
    }

    if (val == (int8_t)val) {
        tcg_out_modrm(s, OPC_ARITH_EvIb + rexw, c, r0);
        tcg_out8(s, val);
        return;
    }
    if (rexw == 0 || val == (int32_t)val) {
        tcg_out_modrm(s, OPC_ARITH_EvIz + rexw, c, r0);
        tcg_out32(s, val);
        return;
    }

    tcg_abort();
}

static void tcg_out_jxx(TCGContext *s, int opc, TCGLabel *l, int small)
{
    int32_t val, val1;

    if (l->has_value) {
        val = tcg_pcrel_diff(s, l->u.value_ptr);
        val1 = val - 2;
        if ((int8_t)val1 == val1) {
            if (opc == -1) {
                tcg_out8(s, OPC_JMP_short);
            } else {
                tcg_out8(s, OPC_JCC_short + opc);
            }
            tcg_out8(s, val1);
        } else {
            if (small) {
                tcg_abort();
            }
            if (opc == -1) {
                tcg_out8(s, OPC_JMP_long);
                tcg_out32(s, val - 5);
            } else {
                tcg_out_opc(s, OPC_JCC_long + opc, 0, 0, 0);
                tcg_out32(s, val - 6);
            }
        }
    } else if (small) {
        if (opc == -1) {
            tcg_out8(s, OPC_JMP_short);
        } else {
            tcg_out8(s, OPC_JCC_short + opc);
        }
        tcg_out_reloc(s, s->code_ptr, R_386_PC8, l, -1);
        s->code_ptr += 1;
    } else {
        if (opc == -1) {
            tcg_out8(s, OPC_JMP_long);
        } else {
            tcg_out_opc(s, OPC_JCC_long + opc, 0, 0, 0);
        }
        tcg_out_reloc(s, s->code_ptr, R_386_PC32, l, -4);
        s->code_ptr += 4;
    }
}

static void tcg_out_cmp(TCGContext *s, TCGArg arg1, TCGArg arg2,
                        int const_arg2, int rexw)
{
    if (const_arg2) {
        if (arg2 == 0) {
            /* test r, r */
            tcg_out_modrm(s, OPC_TESTL + rexw, arg1, arg1);
        } else {
            tgen_arithi(s, ARITH_CMP + rexw, arg1, arg2, 0);
        }
    } else {
        tgen_arithr(s, ARITH_CMP + rexw, arg1, arg2);
    }
}

static void tcg_out_brcond32(TCGContext *s, TCGCond cond,
                             TCGArg arg1, TCGArg arg2, int const_arg2,
                             TCGLabel *label, int small)
{
    tcg_out_cmp(s, arg1, arg2, const_arg2, 0);
    tcg_out_jxx(s, tcg_cond_to_jcc[cond], label, small);
}

static void tcg_out_brcond64(TCGContext *s, TCGCond cond,
                             TCGArg arg1, TCGArg arg2, int const_arg2,
                             TCGLabel *label, int small)
{
    tcg_out_cmp(s, arg1, arg2, const_arg2, P_REXW);
    tcg_out_jxx(s, tcg_cond_to_jcc[cond], label, small);
}

static void tcg_out_setcond32(TCGContext *s, TCGCond cond, TCGArg dest,
                              TCGArg arg1, TCGArg arg2, int const_arg2)
{
    tcg_out_cmp(s, arg1, arg2, const_arg2, 0);
    tcg_out_modrm(s, OPC_SETCC | tcg_cond_to_jcc[cond], 0, dest);
    tcg_out_ext8u(s, dest, dest);
}

static void tcg_out_setcond64(TCGContext *s, TCGCond cond, TCGArg dest,
                              TCGArg arg1, TCGArg arg2, int const_arg2)
{
    tcg_out_cmp(s, arg1, arg2, const_arg2, P_REXW);
    tcg_out_modrm(s, OPC_SETCC | tcg_cond_to_jcc[cond], 0, dest);
    tcg_out_ext8u(s, dest, dest);
}

static void tcg_out_cmov(TCGContext *s, TCGCond cond, int rexw,
                         TCGReg dest, TCGReg v1)
{
    if (have_cmov) {
        tcg_out_modrm(s, OPC_CMOVCC | tcg_cond_to_jcc[cond] | rexw, dest, v1);
    } else {
        TCGLabel *over = gen_new_label();
        tcg_out_jxx(s, tcg_cond_to_jcc[tcg_invert_cond(cond)], over, 1);
        tcg_out_mov(s, TCG_TYPE_I32, dest, v1);
        tcg_out_label(s, over, s->code_ptr);
    }
}

static void tcg_out_movcond32(TCGContext *s, TCGCond cond, TCGReg dest,
                              TCGReg c1, TCGArg c2, int const_c2,
                              TCGReg v1)
{
    tcg_out_cmp(s, c1, c2, const_c2, 0);
    tcg_out_cmov(s, cond, 0, dest, v1);
}

static void tcg_out_movcond64(TCGContext *s, TCGCond cond, TCGReg dest,
                              TCGReg c1, TCGArg c2, int const_c2,
                              TCGReg v1)
{
    tcg_out_cmp(s, c1, c2, const_c2, P_REXW);
    tcg_out_cmov(s, cond, P_REXW, dest, v1);
}

static void tcg_out_ctz(TCGContext *s, int rexw, TCGReg dest, TCGReg arg1,
                        TCGArg arg2, bool const_a2)
{
    if (have_bmi1) {
        tcg_out_modrm(s, OPC_TZCNT + rexw, dest, arg1);
        if (const_a2) {
            tcg_debug_assert(arg2 == (rexw ? 64 : 32));
        } else {
            tcg_debug_assert(dest != arg2);
            tcg_out_cmov(s, TCG_COND_LTU, rexw, dest, (TCGReg)arg2);
        }
    } else {
        tcg_debug_assert(dest != arg2);
        tcg_out_modrm(s, OPC_BSF + rexw, dest, arg1);
        tcg_out_cmov(s, TCG_COND_EQ, rexw, dest, (TCGReg)arg2);
    }
}

static void tcg_out_clz(TCGContext *s, int rexw, TCGReg dest, TCGReg arg1,
                        TCGArg arg2, bool const_a2)
{
    if (have_lzcnt) {
        tcg_out_modrm(s, OPC_LZCNT + rexw, dest, arg1);
        if (const_a2) {
            tcg_debug_assert(arg2 == (rexw ? 64 : 32));
        } else {
            tcg_debug_assert(dest != arg2);
            tcg_out_cmov(s, TCG_COND_LTU, rexw, dest, (TCGReg)arg2);
        }
    } else {
        tcg_debug_assert(!const_a2);
        tcg_debug_assert(dest != arg1);
        tcg_debug_assert(dest != arg2);

        /* Recall that the output of BSR is the index not the count.  */
        tcg_out_modrm(s, OPC_BSR + rexw, dest, arg1);
        tgen_arithi(s, ARITH_XOR + rexw, dest, rexw ? 63 : 31, 0);

        /* Since we have destroyed the flags from BSR, we have to re-test.  */
        tcg_out_cmp(s, arg1, 0, 1, rexw);
        tcg_out_cmov(s, TCG_COND_EQ, rexw, dest, (TCGReg)arg2);
    }
}

static void tcg_out_branch(TCGContext *s, int call, tcg_insn_unit *dest)
{
    intptr_t disp = tcg_pcrel_diff(s, dest) - 5;

    if (disp == (int32_t)disp) {
        tcg_out_opc(s, call ? OPC_CALL_Jz : OPC_JMP_long, 0, 0, 0);
        tcg_out32(s, disp);
    } else {
        /* rip-relative addressing into the constant pool.
           This is 6 + 8 = 14 bytes, as compared to using an
           an immediate load 10 + 6 = 16 bytes, plus we may
           be able to re-use the pool constant for more calls.  */
        tcg_out_opc(s, OPC_GRP5, 0, 0, 0);
        tcg_out8(s, (call ? EXT5_CALLN_Ev : EXT5_JMPN_Ev) << 3 | 5);
        new_pool_label(s, (uintptr_t)dest, R_386_PC32, s->code_ptr, -4);
        tcg_out32(s, 0);
    }
}

static inline void tcg_out_call(TCGContext *s, tcg_insn_unit *dest)
{
    tcg_out_branch(s, 1, dest);
}

static void tcg_out_jmp(TCGContext *s, tcg_insn_unit *dest)
{
    tcg_out_branch(s, 0, dest);
}

static void tcg_out_nopn(TCGContext *s, int n)
{
    int i;
    /* Emit 1 or 2 operand size prefixes for the standard one byte nop,
     * "xchg %eax,%eax", forming "xchg %ax,%ax". All cores accept the
     * duplicate prefix, and all of the interesting recent cores can
     * decode and discard the duplicates in a single cycle.
     */
    tcg_debug_assert(n >= 1);
    for (i = 1; i < n; ++i) {
        tcg_out8(s, 0x66);
    }
    tcg_out8(s, 0x90);
}

static int guest_base_flags;

static void tcg_out_qemu_ld_direct(TCGContext *s, TCGReg datalo, TCGReg datahi,
                                   TCGReg base, int index, intptr_t ofs,
                                   int seg, TCGMemOp memop)
{
    const TCGMemOp real_bswap = (TCGMemOp)(memop & MO_BSWAP);
    TCGMemOp bswap = real_bswap;
    int movop = OPC_MOVL_GvEv;

    if (have_movbe && real_bswap) {
        bswap = (TCGMemOp)0;
        movop = OPC_MOVBE_GyMy;
    }

    switch (memop & MO_SSIZE) {
    case MO_UB:
        tcg_out_modrm_sib_offset(s, OPC_MOVZBL + seg, datalo,
                                 base, index, 0, ofs);
        break;
    case MO_SB:
        tcg_out_modrm_sib_offset(s, OPC_MOVSBL + P_REXW + seg, datalo,
                                 base, index, 0, ofs);
        break;
    case MO_UW:
        tcg_out_modrm_sib_offset(s, OPC_MOVZWL + seg, datalo,
                                 base, index, 0, ofs);
        if (real_bswap) {
            tcg_out_rolw_8(s, datalo);
        }
        break;
    case MO_SW:
        if (real_bswap) {
            if (have_movbe) {
                tcg_out_modrm_sib_offset(s, OPC_MOVBE_GyMy + P_DATA16 + seg,
                                         datalo, base, index, 0, ofs);
            } else {
                tcg_out_modrm_sib_offset(s, OPC_MOVZWL + seg, datalo,
                                         base, index, 0, ofs);
                tcg_out_rolw_8(s, datalo);
            }
            tcg_out_modrm(s, OPC_MOVSWL + P_REXW, datalo, datalo);
        } else {
            tcg_out_modrm_sib_offset(s, OPC_MOVSWL + P_REXW + seg,
                                     datalo, base, index, 0, ofs);
        }
        break;
    case MO_UL:
        tcg_out_modrm_sib_offset(s, movop + seg, datalo, base, index, 0, ofs);
        if (bswap) {
            tcg_out_bswap32(s, datalo);
        }
        break;
#if TCG_TARGET_REG_BITS == 64
    case MO_SL:
        if (real_bswap) {
            tcg_out_modrm_sib_offset(s, movop + seg, datalo,
                                     base, index, 0, ofs);
            if (bswap) {
                tcg_out_bswap32(s, datalo);
            }
            tcg_out_ext32s(s, datalo, datalo);
        } else {
            tcg_out_modrm_sib_offset(s, OPC_MOVSLQ + seg, datalo,
                                     base, index, 0, ofs);
        }
        break;
#endif
    case MO_Q:
        if (TCG_TARGET_REG_BITS == 64) {
            tcg_out_modrm_sib_offset(s, movop + P_REXW + seg, datalo,
                                     base, index, 0, ofs);
            if (bswap) {
                tcg_out_bswap64(s, datalo);
            }
        } else {
            if (real_bswap) {
                int t = datalo;
                datalo = datahi;
                datahi = (TCGReg)t;
            }
            if (base != datalo) {
                tcg_out_modrm_sib_offset(s, movop + seg, datalo,
                                         base, index, 0, ofs);
                tcg_out_modrm_sib_offset(s, movop + seg, datahi,
                                         base, index, 0, ofs + 4);
            } else {
                tcg_out_modrm_sib_offset(s, movop + seg, datahi,
                                         base, index, 0, ofs + 4);
                tcg_out_modrm_sib_offset(s, movop + seg, datalo,
                                         base, index, 0, ofs);
            }
            if (bswap) {
                tcg_out_bswap32(s, datalo);
                tcg_out_bswap32(s, datahi);
            }
        }
        break;
    default:
        tcg_abort();
    }
}

static void tcg_out_qemu_ld(TCGContext *s, const TCGArg *args, bool is64)
{
    TCGReg datalo, datahi, addrlo;
    TCGReg addrhi __attribute__((unused));
    TCGMemOpIdx oi;
    TCGMemOp opc;
#if defined(CONFIG_SOFTMMU)
    int mem_index;
    tcg_insn_unit *label_ptr[2];
#endif

    datalo = (TCGReg)*args++;
    datahi = (TCGReg)(TCG_TARGET_REG_BITS == 32 && is64 ? *args++ : 0);
    addrlo = (TCGReg)*args++;
    addrhi = (TCGReg)(TARGET_LONG_BITS > TCG_TARGET_REG_BITS ? *args++ : 0);
    oi = *args++;
    opc = get_memop(oi);

#if defined(CONFIG_SOFTMMU)
    mem_index = get_mmuidx(oi);

    tcg_out_tlb_load(s, addrlo, addrhi, mem_index, opc,
                     label_ptr, offsetof(CPUTLBEntry, addr_read));

    /* TLB Hit.  */
    tcg_out_qemu_ld_direct(s, datalo, datahi, TCG_REG_L1, -1, 0, 0, opc);

    /* Record the current context of a load into ldst label */
    add_qemu_ldst_label(s, true, oi, datalo, datahi, addrlo, addrhi,
                        s->code_ptr, label_ptr);
#else
    {
        int32_t offset = guest_base;
        TCGReg base = addrlo;
        int index = -1;
        int seg = 0;

        /* For a 32-bit guest, the high 32 bits may contain garbage.
           We can do this with the ADDR32 prefix if we're not using
           a guest base, or when using segmentation.  Otherwise we
           need to zero-extend manually.  */
        if (guest_base == 0 || guest_base_flags) {
            seg = guest_base_flags;
            offset = 0;
            if (TCG_TARGET_REG_BITS > TARGET_LONG_BITS) {
                seg |= P_ADDR32;
            }
        } else if (TCG_TARGET_REG_BITS == 64) {
            if (TARGET_LONG_BITS == 32) {
                tcg_out_ext32u(s, TCG_REG_L0, base);
                base = (TCGReg)TCG_REG_L0;
            }
            if (offset != guest_base) {
                tcg_out_movi(s, TCG_TYPE_I64, (TCGReg)TCG_REG_L1, guest_base);
                index = TCG_REG_L1;
                offset = 0;
            }
        }

        tcg_out_qemu_ld_direct(s, datalo, datahi,
                               base, index, offset, seg, opc);
    }
#endif
}

static void tcg_out_qemu_st_direct(TCGContext *s, TCGReg datalo, TCGReg datahi,
                                   TCGReg base, intptr_t ofs, int seg,
                                   TCGMemOp memop)
{
    /* ??? Ideally we wouldn't need a scratch register.  For user-only,
       we could perform the bswap twice to restore the original value
       instead of moving to the scratch.  But as it is, the L constraint
       means that TCG_REG_L0 is definitely free here.  */
    const TCGReg scratch = (TCGReg)TCG_REG_L0;
    const TCGMemOp real_bswap = (TCGMemOp)(memop & MO_BSWAP);
    TCGMemOp bswap = real_bswap;
    int movop = OPC_MOVL_EvGv;

    if (have_movbe && real_bswap) {
        bswap = (TCGMemOp)0;
        movop = OPC_MOVBE_MyGy;
    }

    switch (memop & MO_SIZE) {
    case MO_8:
        /* In 32-bit mode, 8-bit stores can only happen from [abcd]x.
           Use the scratch register if necessary.  */
        if (TCG_TARGET_REG_BITS == 32 && datalo >= 4) {
            tcg_out_mov(s, TCG_TYPE_I32, scratch, datalo);
            datalo = scratch;
        }
        tcg_out_modrm_offset(s, OPC_MOVB_EvGv + P_REXB_R + seg,
                             datalo, base, ofs);
        break;
    case MO_16:
        if (bswap) {
            tcg_out_mov(s, TCG_TYPE_I32, scratch, datalo);
            tcg_out_rolw_8(s, scratch);
            datalo = scratch;
        }
        tcg_out_modrm_offset(s, movop + P_DATA16 + seg, datalo, base, ofs);
        break;
    case MO_32:
        if (bswap) {
            tcg_out_mov(s, TCG_TYPE_I32, scratch, datalo);
            tcg_out_bswap32(s, scratch);
            datalo = scratch;
        }
        tcg_out_modrm_offset(s, movop + seg, datalo, base, ofs);
        break;
    case MO_64:
        if (TCG_TARGET_REG_BITS == 64) {
            if (bswap) {
                tcg_out_mov(s, TCG_TYPE_I64, scratch, datalo);
                tcg_out_bswap64(s, scratch);
                datalo = scratch;
            }
            tcg_out_modrm_offset(s, movop + P_REXW + seg, datalo, base, ofs);
        } else if (bswap) {
            tcg_out_mov(s, TCG_TYPE_I32, scratch, datahi);
            tcg_out_bswap32(s, scratch);
            tcg_out_modrm_offset(s, OPC_MOVL_EvGv + seg, scratch, base, ofs);
            tcg_out_mov(s, TCG_TYPE_I32, scratch, datalo);
            tcg_out_bswap32(s, scratch);
            tcg_out_modrm_offset(s, OPC_MOVL_EvGv + seg, scratch, base, ofs+4);
        } else {
            if (real_bswap) {
                int t = datalo;
                datalo = datahi;
                datahi = (TCGReg)t;
            }
            tcg_out_modrm_offset(s, movop + seg, datalo, base, ofs);
            tcg_out_modrm_offset(s, movop + seg, datahi, base, ofs+4);
        }
        break;
    default:
        tcg_abort();
    }
}

static void tcg_out_qemu_st(TCGContext *s, const TCGArg *args, bool is64)
{
    TCGReg datalo, datahi, addrlo;
    TCGReg addrhi __attribute__((unused));
    TCGMemOpIdx oi;
    TCGMemOp opc;
#if defined(CONFIG_SOFTMMU)
    int mem_index;
    tcg_insn_unit *label_ptr[2];
#endif

    datalo = (TCGReg)*args++;
    datahi = (TCGReg)(TCG_TARGET_REG_BITS == 32 && is64 ? *args++ : 0);
    addrlo = (TCGReg)*args++;
    addrhi = (TCGReg)(TARGET_LONG_BITS > TCG_TARGET_REG_BITS ? *args++ : 0);
    oi = *args++;
    opc = get_memop(oi);

#if defined(CONFIG_SOFTMMU)
    mem_index = get_mmuidx(oi);

    tcg_out_tlb_load(s, addrlo, addrhi, mem_index, opc,
                     label_ptr, offsetof(CPUTLBEntry, addr_write));

    /* TLB Hit.  */
    tcg_out_qemu_st_direct(s, datalo, datahi, TCG_REG_L1, 0, 0, opc);

    /* Record the current context of a store into ldst label */
    add_qemu_ldst_label(s, false, oi, datalo, datahi, addrlo, addrhi,
                        s->code_ptr, label_ptr);
#else
    {
        int32_t offset = guest_base;
        TCGReg base = addrlo;
        int seg = 0;

        /* See comment in tcg_out_qemu_ld re zero-extension of addrlo.  */
        if (guest_base == 0 || guest_base_flags) {
            seg = guest_base_flags;
            offset = 0;
            if (TCG_TARGET_REG_BITS > TARGET_LONG_BITS) {
                seg |= P_ADDR32;
            }
        } else if (TCG_TARGET_REG_BITS == 64) {
            /* ??? Note that we can't use the same SIB addressing scheme
               as for loads, since we require L0 free for bswap.  */
            if (offset != guest_base) {
                if (TARGET_LONG_BITS == 32) {
                    tcg_out_ext32u(s, TCG_REG_L0, base);
                    base = (TCGReg)TCG_REG_L0;
                }
                tcg_out_movi(s, TCG_TYPE_I64, (TCGReg)TCG_REG_L1, guest_base);
                tgen_arithr(s, ARITH_ADD + P_REXW, TCG_REG_L1, base);
                base = (TCGReg)TCG_REG_L1;
                offset = 0;
            } else if (TARGET_LONG_BITS == 32) {
                tcg_out_ext32u(s, TCG_REG_L1, base);
                base = (TCGReg)TCG_REG_L1;
            }
        }

        tcg_out_qemu_st_direct(s, datalo, datahi, base, offset, seg, opc);
    }
#endif
}

static inline void tcg_out_op(TCGContext *s, TCGOpcode opc,
                              const TCGArg *args, const int *const_args)
{
    TCGArg a0, a1, a2;
    int c, const_a2, vexop, rexw = 0;

#if TCG_TARGET_REG_BITS == 64
# define OP_32_64(x) \
        case glue(glue(INDEX_op_, x), _i64): \
            rexw = P_REXW; /* FALLTHRU */    \
        case glue(glue(INDEX_op_, x), _i32)
#else
# define OP_32_64(x) \
        case glue(glue(INDEX_op_, x), _i32)
#endif

    /* Hoist the loads of the most common arguments.  */
    a0 = args[0];
    a1 = args[1];
    a2 = args[2];
    const_a2 = const_args[2];

    switch (opc) {
    case INDEX_op_exit_tb:
        /* Reuse the zeroing that exists for goto_ptr.  */
        if (a0 == 0) {
            tcg_out_jmp(s, (tcg_insn_unit *)s->code_gen_epilogue);
        } else {
            tcg_out_movi(s, TCG_TYPE_PTR, TCG_REG_EAX, a0);
            tcg_out_jmp(s, tb_ret_addr);
        }
        break;
    case INDEX_op_goto_tb:
        if (s->tb_jmp_insn_offset) {
            /* direct jump method */
            int gap;
            /* jump displacement must be aligned for atomic patching;
             * see if we need to add extra nops before jump
             */
            gap = tcg_pcrel_diff(s, QEMU_ALIGN_PTR_UP(s->code_ptr + 1, 4));
            if (gap != 1) {
                tcg_out_nopn(s, gap - 1);
            }
            tcg_out8(s, OPC_JMP_long); /* jmp im */
            s->tb_jmp_insn_offset[a0] = tcg_current_code_size(s);
            tcg_out32(s, 0);
        } else {
            /* indirect jump method */
            tcg_out_modrm_offset(s, OPC_GRP5, EXT5_JMPN_Ev, -1,
                                 (intptr_t)(s->tb_jmp_target_addr + a0));
        }
        s->tb_jmp_reset_offset[a0] = tcg_current_code_size(s);
        break;
    case INDEX_op_goto_ptr:
        /* jmp to the given host address (could be epilogue) */
        tcg_out_modrm(s, OPC_GRP5, EXT5_JMPN_Ev, a0);
        break;
    case INDEX_op_br:
        tcg_out_jxx(s, JCC_JMP, arg_label(a0), 0);
        break;
    OP_32_64(ld8u):
        /* Note that we can ignore REXW for the zero-extend to 64-bit.  */
        tcg_out_modrm_offset(s, OPC_MOVZBL, a0, a1, a2);
        break;
    OP_32_64(ld8s):
        tcg_out_modrm_offset(s, OPC_MOVSBL + rexw, a0, a1, a2);
        break;
    OP_32_64(ld16u):
        /* Note that we can ignore REXW for the zero-extend to 64-bit.  */
        tcg_out_modrm_offset(s, OPC_MOVZWL, a0, a1, a2);
        break;
    OP_32_64(ld16s):
        tcg_out_modrm_offset(s, OPC_MOVSWL + rexw, a0, a1, a2);
        break;
#if TCG_TARGET_REG_BITS == 64
    case INDEX_op_ld32u_i64:
#endif
    case INDEX_op_ld_i32:
        tcg_out_ld(s, TCG_TYPE_I32, (TCGReg)a0, (TCGReg)a1, a2);
        break;

    OP_32_64(st8):
        if (const_args[0]) {
            tcg_out_modrm_offset(s, OPC_MOVB_EvIz, 0, a1, a2);
            tcg_out8(s, a0);
        } else {
            tcg_out_modrm_offset(s, OPC_MOVB_EvGv | P_REXB_R, a0, a1, a2);
        }
        break;
    OP_32_64(st16):
        if (const_args[0]) {
            tcg_out_modrm_offset(s, OPC_MOVL_EvIz | P_DATA16, 0, a1, a2);
            tcg_out16(s, a0);
        } else {
            tcg_out_modrm_offset(s, OPC_MOVL_EvGv | P_DATA16, a0, a1, a2);
        }
        break;
#if TCG_TARGET_REG_BITS == 64
    case INDEX_op_st32_i64:
#endif
    case INDEX_op_st_i32:
        if (const_args[0]) {
            tcg_out_modrm_offset(s, OPC_MOVL_EvIz, 0, a1, a2);
            tcg_out32(s, a0);
        } else {
            tcg_out_st(s, TCG_TYPE_I32, (TCGReg)a0, (TCGReg)a1, a2);
        }
        break;

    OP_32_64(add):
        /* For 3-operand addition, use LEA.  */
        if (a0 != a1) {
            TCGArg c3 = 0;
            if (const_a2) {
                c3 = a2, a2 = -1;
            } else if (a0 == a2) {
                /* Watch out for dest = src + dest, since we've removed
                   the matching constraint on the add.  */
                tgen_arithr(s, ARITH_ADD + rexw, a0, a1); break;
            }

            tcg_out_modrm_sib_offset(s, OPC_LEA + rexw, a0, a1, a2, 0, c3);
            break;
        }
        c = ARITH_ADD;
        goto gen_arith;
    OP_32_64(sub):
        c = ARITH_SUB;
        goto gen_arith;
    OP_32_64(and):
        c = ARITH_AND;
        goto gen_arith;
    OP_32_64(or):
        c = ARITH_OR;
        goto gen_arith;
    OP_32_64(xor):
        c = ARITH_XOR;
        goto gen_arith;
    gen_arith:
        if (const_a2) {
            tgen_arithi(s, c + rexw, a0, a2, 0);
        } else {
            tgen_arithr(s, c + rexw, a0, a2);
        }
        break;

    OP_32_64(andc):
        if (const_a2) {
            tcg_out_mov(s, rexw ? TCG_TYPE_I64 : TCG_TYPE_I32, (TCGReg)a0, (TCGReg)a1);
            tgen_arithi(s, ARITH_AND + rexw, a0, ~a2, 0);
        } else {
            tcg_out_vex_modrm(s, OPC_ANDN + rexw, a0, a2, a1);
        }
        break;

    OP_32_64(mul):
        if (const_a2) {
            int32_t val;
            val = a2;
            if (val == (int8_t)val) {
                tcg_out_modrm(s, OPC_IMUL_GvEvIb + rexw, a0, a0);
                tcg_out8(s, val);
            } else {
                tcg_out_modrm(s, OPC_IMUL_GvEvIz + rexw, a0, a0);
                tcg_out32(s, val);
            }
        } else {
            tcg_out_modrm(s, OPC_IMUL_GvEv + rexw, a0, a2);
        }
        break;

    OP_32_64(div2):
        tcg_out_modrm(s, OPC_GRP3_Ev + rexw, EXT3_IDIV, args[4]);
        break;
    OP_32_64(divu2):
        tcg_out_modrm(s, OPC_GRP3_Ev + rexw, EXT3_DIV, args[4]);
        break;

    OP_32_64(shl):
        /* For small constant 3-operand shift, use LEA.  */
        if (const_a2 && a0 != a1 && (a2 - 1) < 3) {
            if (a2 - 1 == 0) {
                /* shl $1,a1,a0 -> lea (a1,a1),a0 */
                tcg_out_modrm_sib_offset(s, OPC_LEA + rexw, a0, a1, a1, 0, 0);
            } else {
                /* shl $n,a1,a0 -> lea 0(,a1,n),a0 */
                tcg_out_modrm_sib_offset(s, OPC_LEA + rexw, a0, -1, a1, a2, 0);
            }
            break;
        }
        c = SHIFT_SHL;
        vexop = OPC_SHLX;
        goto gen_shift_maybe_vex;
    OP_32_64(shr):
        c = SHIFT_SHR;
        vexop = OPC_SHRX;
        goto gen_shift_maybe_vex;
    OP_32_64(sar):
        c = SHIFT_SAR;
        vexop = OPC_SARX;
        goto gen_shift_maybe_vex;
    OP_32_64(rotl):
        c = SHIFT_ROL;
        goto gen_shift;
    OP_32_64(rotr):
        c = SHIFT_ROR;
        goto gen_shift;
    gen_shift_maybe_vex:
        if (have_bmi2) {
            if (!const_a2) {
                tcg_out_vex_modrm(s, vexop + rexw, a0, a2, a1);
                break;
            }
            tcg_out_mov(s, rexw ? TCG_TYPE_I64 : TCG_TYPE_I32, (TCGReg)a0, (TCGReg)a1);
        }
        /* FALLTHRU */
    gen_shift:
        if (const_a2) {
            tcg_out_shifti(s, c + rexw, a0, a2);
        } else {
            tcg_out_modrm(s, OPC_SHIFT_cl + rexw, c, a0);
        }
        break;

    OP_32_64(ctz):
        tcg_out_ctz(s, rexw, (TCGReg)args[0], (TCGReg)args[1], args[2], const_args[2]);
        break;
    OP_32_64(clz):
        tcg_out_clz(s, rexw, (TCGReg)args[0], (TCGReg)args[1], args[2], const_args[2]);
        break;
    OP_32_64(ctpop):
        tcg_out_modrm(s, OPC_POPCNT + rexw, a0, a1);
        break;

    case INDEX_op_brcond_i32:
        tcg_out_brcond32(s, (TCGCond)a2, a0, a1, const_args[1], arg_label(args[3]), 0);
        break;
    case INDEX_op_setcond_i32:
        tcg_out_setcond32(s, (TCGCond)args[3], a0, a1, a2, const_a2);
        break;
    case INDEX_op_movcond_i32:
        tcg_out_movcond32(s, (TCGCond)args[5], (TCGReg)a0, (TCGReg)a1, a2, const_a2, (TCGReg)args[3]);
        break;

    OP_32_64(bswap16):
        tcg_out_rolw_8(s, a0);
        break;
    OP_32_64(bswap32):
        tcg_out_bswap32(s, a0);
        break;

    OP_32_64(neg):
        tcg_out_modrm(s, OPC_GRP3_Ev + rexw, EXT3_NEG, a0);
        break;
    OP_32_64(not):
        tcg_out_modrm(s, OPC_GRP3_Ev + rexw, EXT3_NOT, a0);
        break;

    OP_32_64(ext8s):
        tcg_out_ext8s(s, a0, a1, rexw);
        break;
    OP_32_64(ext16s):
        tcg_out_ext16s(s, a0, a1, rexw);
        break;
    OP_32_64(ext8u):
        tcg_out_ext8u(s, a0, a1);
        break;
    OP_32_64(ext16u):
        tcg_out_ext16u(s, a0, a1);
        break;

    case INDEX_op_qemu_ld_i32:
        tcg_out_qemu_ld(s, args, 0);
        break;
    case INDEX_op_qemu_ld_i64:
        tcg_out_qemu_ld(s, args, 1);
        break;
    case INDEX_op_qemu_st_i32:
        tcg_out_qemu_st(s, args, 0);
        break;
    case INDEX_op_qemu_st_i64:
        tcg_out_qemu_st(s, args, 1);
        break;

    OP_32_64(mulu2):
        tcg_out_modrm(s, OPC_GRP3_Ev + rexw, EXT3_MUL, args[3]);
        break;
    OP_32_64(muls2):
        tcg_out_modrm(s, OPC_GRP3_Ev + rexw, EXT3_IMUL, args[3]);
        break;
    OP_32_64(add2):
        if (const_args[4]) {
            tgen_arithi(s, ARITH_ADD + rexw, a0, args[4], 1);
        } else {
            tgen_arithr(s, ARITH_ADD + rexw, a0, args[4]);
        }
        if (const_args[5]) {
            tgen_arithi(s, ARITH_ADC + rexw, a1, args[5], 1);
        } else {
            tgen_arithr(s, ARITH_ADC + rexw, a1, args[5]);
        }
        break;
    OP_32_64(sub2):
        if (const_args[4]) {
            tgen_arithi(s, ARITH_SUB + rexw, a0, args[4], 1);
        } else {
            tgen_arithr(s, ARITH_SUB + rexw, a0, args[4]);
        }
        if (const_args[5]) {
            tgen_arithi(s, ARITH_SBB + rexw, a1, args[5], 1);
        } else {
            tgen_arithr(s, ARITH_SBB + rexw, a1, args[5]);
        }
        break;

#if TCG_TARGET_REG_BITS == 32
    case INDEX_op_brcond2_i32:
        tcg_out_brcond2(s, args, const_args, 0);
        break;
    case INDEX_op_setcond2_i32:
        tcg_out_setcond2(s, args, const_args);
        break;
#else /* TCG_TARGET_REG_BITS == 64 */
    case INDEX_op_ld32s_i64:
        tcg_out_modrm_offset(s, OPC_MOVSLQ, a0, a1, a2);
        break;
    case INDEX_op_ld_i64:
        tcg_out_ld(s, TCG_TYPE_I64, (TCGReg)a0, (TCGReg)a1, a2);
        break;
    case INDEX_op_st_i64:
        if (const_args[0]) {
            tcg_out_modrm_offset(s, OPC_MOVL_EvIz | P_REXW, 0, a1, a2);
            tcg_out32(s, a0);
        } else {
            tcg_out_st(s, TCG_TYPE_I64, (TCGReg)a0, (TCGReg)a1, a2);
        }
        break;

    case INDEX_op_brcond_i64:
        tcg_out_brcond64(s, (TCGCond)a2, a0, a1, const_args[1], arg_label(args[3]), 0);
        break;
    case INDEX_op_setcond_i64:
        tcg_out_setcond64(s, (TCGCond)args[3], a0, a1, a2, const_a2);
        break;
    case INDEX_op_movcond_i64:
        tcg_out_movcond64(s, (TCGCond)args[5], (TCGReg)a0, (TCGReg)a1, a2, const_a2, (TCGReg)args[3]);
        break;

    case INDEX_op_bswap64_i64:
        tcg_out_bswap64(s, a0);
        break;
    case INDEX_op_extu_i32_i64:
    case INDEX_op_ext32u_i64:
        tcg_out_ext32u(s, a0, a1);
        break;
    case INDEX_op_ext_i32_i64:
    case INDEX_op_ext32s_i64:
        tcg_out_ext32s(s, a0, a1);
        break;
#endif

    OP_32_64(deposit):
        if (args[3] == 0 && args[4] == 8) {
            /* load bits 0..7 */
            tcg_out_modrm(s, OPC_MOVB_EvGv | P_REXB_R | P_REXB_RM, a2, a0);
        } else if (args[3] == 8 && args[4] == 8) {
            /* load bits 8..15 */
            tcg_out_modrm(s, OPC_MOVB_EvGv, a2, a0 + 4);
        } else if (args[3] == 0 && args[4] == 16) {
            /* load bits 0..15 */
            tcg_out_modrm(s, OPC_MOVL_EvGv | P_DATA16, a2, a0);
        } else {
            tcg_abort();
        }
        break;

    case INDEX_op_extract_i64:
        if (a2 + args[3] == 32) {
            /* This is a 32-bit zero-extending right shift.  */
            tcg_out_mov(s, TCG_TYPE_I32, (TCGReg)a0, (TCGReg)a1);
            tcg_out_shifti(s, SHIFT_SHR, a0, a2);
            break;
        }
        /* FALLTHRU */
    case INDEX_op_extract_i32:
        /* On the off-chance that we can use the high-byte registers.
           Otherwise we emit the same ext16 + shift pattern that we
           would have gotten from the normal tcg-op.c expansion.  */
        tcg_debug_assert(a2 == 8 && args[3] == 8);
        if (a1 < 4 && a0 < 8) {
            tcg_out_modrm(s, OPC_MOVZBL, a0, a1 + 4);
        } else {
            tcg_out_ext16u(s, a0, a1);
            tcg_out_shifti(s, SHIFT_SHR, a0, 8);
        }
        break;

    case INDEX_op_sextract_i32:
        /* We don't implement sextract_i64, as we cannot sign-extend to
           64-bits without using the REX prefix that explicitly excludes
           access to the high-byte registers.  */
        tcg_debug_assert(a2 == 8 && args[3] == 8);
        if (a1 < 4 && a0 < 8) {
            tcg_out_modrm(s, OPC_MOVSBL, a0, a1 + 4);
        } else {
            tcg_out_ext16s(s, a0, a1, 0);
            tcg_out_shifti(s, SHIFT_SAR, a0, 8);
        }
        break;

    case INDEX_op_mb:
        tcg_out_mb(s, a0);
        break;
    case INDEX_op_mov_i32:  /* Always emitted via tcg_out_mov.  */
    case INDEX_op_mov_i64:
    case INDEX_op_mov_vec:
    case INDEX_op_movi_i32: /* Always emitted via tcg_out_movi.  */
    case INDEX_op_movi_i64:
    case INDEX_op_dupi_vec:
    case INDEX_op_call:     /* Always emitted via tcg_out_call.  */
    default:
        tcg_abort();
    }

#undef OP_32_64
}

static void tcg_out_vec_op(TCGContext *s, TCGOpcode opc,
                           unsigned vecl, unsigned vece,
                           const TCGArg *args, const int *const_args)
{
    static int const add_insn[4] = {
        OPC_PADDB, OPC_PADDW, OPC_PADDD, OPC_PADDQ
    };
    static int const sub_insn[4] = {
        OPC_PSUBB, OPC_PSUBW, OPC_PSUBD, OPC_PSUBQ
    };
    static int const mul_insn[4] = {
        OPC_UD2, OPC_PMULLW, OPC_PMULLD, OPC_UD2
    };
    static int const shift_imm_insn[4] = {
        OPC_UD2, OPC_PSHIFTW_Ib, OPC_PSHIFTD_Ib, OPC_PSHIFTQ_Ib
    };
    static int const cmpeq_insn[4] = {
        OPC_PCMPEQB, OPC_PCMPEQW, OPC_PCMPEQD, OPC_PCMPEQQ
    };
    static int const cmpgt_insn[4] = {
        OPC_PCMPGTB, OPC_PCMPGTW, OPC_PCMPGTD, OPC_PCMPGTQ
    };
    static int const punpckl_insn[4] = {
        OPC_PUNPCKLBW, OPC_PUNPCKLWD, OPC_PUNPCKLDQ, OPC_PUNPCKLQDQ
    };
    static int const punpckh_insn[4] = {
        OPC_PUNPCKHBW, OPC_PUNPCKHWD, OPC_PUNPCKHDQ, OPC_PUNPCKHQDQ
    };
    static int const packss_insn[4] = {
        OPC_PACKSSWB, OPC_PACKSSDW, OPC_UD2, OPC_UD2
    };
    static int const packus_insn[4] = {
        OPC_PACKUSWB, OPC_PACKUSDW, OPC_UD2, OPC_UD2
    };

    TCGType type = (TCGType)(vecl + TCG_TYPE_V64);
    int insn, sub;
    TCGArg a0, a1, a2;

    a0 = args[0];
    a1 = args[1];
    a2 = args[2];

    switch (opc) {
    case INDEX_op_add_vec:
        insn = add_insn[vece];
        goto gen_simd;
    case INDEX_op_sub_vec:
        insn = sub_insn[vece];
        goto gen_simd;
    case INDEX_op_mul_vec:
        insn = mul_insn[vece];
        goto gen_simd;
    case INDEX_op_and_vec:
        insn = OPC_PAND;
        goto gen_simd;
    case INDEX_op_or_vec:
        insn = OPC_POR;
        goto gen_simd;
    case INDEX_op_xor_vec:
        insn = OPC_PXOR;
        goto gen_simd;
    case INDEX_op_x86_punpckl_vec:
        insn = punpckl_insn[vece];
        goto gen_simd;
    case INDEX_op_x86_punpckh_vec:
        insn = punpckh_insn[vece];
        goto gen_simd;
    case INDEX_op_x86_packss_vec:
        insn = packss_insn[vece];
        goto gen_simd;
    case INDEX_op_x86_packus_vec:
        insn = packus_insn[vece];
        goto gen_simd;
#if TCG_TARGET_REG_BITS == 32
    case INDEX_op_dup2_vec:
        /* Constraints have already placed both 32-bit inputs in xmm regs.  */
        insn = OPC_PUNPCKLDQ;
        goto gen_simd;
#endif
    gen_simd:
        tcg_debug_assert(insn != OPC_UD2);
        if (type == TCG_TYPE_V256) {
            insn |= P_VEXL;
        }
        tcg_out_vex_modrm(s, insn, a0, a1, a2);
        break;

    case INDEX_op_cmp_vec:
        sub = args[3];
        if (sub == TCG_COND_EQ) {
            insn = cmpeq_insn[vece];
        } else if (sub == TCG_COND_GT) {
            insn = cmpgt_insn[vece];
        } else {
            g_assert_not_reached();
        }
        goto gen_simd;

    case INDEX_op_andc_vec:
        insn = OPC_PANDN;
        if (type == TCG_TYPE_V256) {
            insn |= P_VEXL;
        }
        tcg_out_vex_modrm(s, insn, a0, a2, a1);
        break;

    case INDEX_op_shli_vec:
        sub = 6;
        goto gen_shift;
    case INDEX_op_shri_vec:
        sub = 2;
        goto gen_shift;
    case INDEX_op_sari_vec:
        tcg_debug_assert(vece != MO_64);
        sub = 4;
    gen_shift:
        tcg_debug_assert(vece != MO_8);
        insn = shift_imm_insn[vece];
        if (type == TCG_TYPE_V256) {
            insn |= P_VEXL;
        }
        tcg_out_vex_modrm(s, insn, sub, a0, a1);
        tcg_out8(s, a2);
        break;

    case INDEX_op_ld_vec:
        tcg_out_ld(s, type, (TCGReg)a0, (TCGReg)a1, a2);
        break;
    case INDEX_op_st_vec:
        tcg_out_st(s, type, (TCGReg)a0, (TCGReg)a1, a2);
        break;
    case INDEX_op_dup_vec:
        tcg_out_dup_vec(s, type, vece, (TCGReg)a0, (TCGReg)a1);
        break;

    case INDEX_op_x86_shufps_vec:
        insn = OPC_SHUFPS;
        sub = args[3];
        goto gen_simd_imm8;
    case INDEX_op_x86_blend_vec:
        if (vece == MO_16) {
            insn = OPC_PBLENDW;
        } else if (vece == MO_32) {
            insn = (have_avx2 ? OPC_VPBLENDD : OPC_BLENDPS);
        } else {
            g_assert_not_reached();
        }
        sub = args[3];
        goto gen_simd_imm8;
    case INDEX_op_x86_vperm2i128_vec:
        insn = OPC_VPERM2I128;
        sub = args[3];
        goto gen_simd_imm8;
    gen_simd_imm8:
        if (type == TCG_TYPE_V256) {
            insn |= P_VEXL;
        }
        tcg_out_vex_modrm(s, insn, a0, a1, a2);
        tcg_out8(s, sub);
        break;

    case INDEX_op_x86_vpblendvb_vec:
        insn = OPC_VPBLENDVB;
        if (type == TCG_TYPE_V256) {
            insn |= P_VEXL;
        }
        tcg_out_vex_modrm(s, insn, a0, a1, a2);
        tcg_out8(s, args[3] << 4);
        break;

    case INDEX_op_x86_psrldq_vec:
        tcg_out_vex_modrm(s, OPC_GRP14, 3, a0, a1);
        tcg_out8(s, a2);
        break;

    default:
        g_assert_not_reached();
    }
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
    static const TCGTargetOpDef x_x = { .args_ct_str = { "x", "x" } };
    static const TCGTargetOpDef x_x_x = { .args_ct_str = { "x", "x", "x" } };
    static const TCGTargetOpDef x_x_x_x
        = { .args_ct_str = { "x", "x", "x", "x" } };
    static const TCGTargetOpDef x_r = { .args_ct_str = { "x", "r" } };

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

    case INDEX_op_ld_vec:
    case INDEX_op_st_vec:
        return &x_r;

    case INDEX_op_add_vec:
    case INDEX_op_sub_vec:
    case INDEX_op_mul_vec:
    case INDEX_op_and_vec:
    case INDEX_op_or_vec:
    case INDEX_op_xor_vec:
    case INDEX_op_andc_vec:
    case INDEX_op_cmp_vec:
    case INDEX_op_x86_shufps_vec:
    case INDEX_op_x86_blend_vec:
    case INDEX_op_x86_packss_vec:
    case INDEX_op_x86_packus_vec:
    case INDEX_op_x86_vperm2i128_vec:
    case INDEX_op_x86_punpckl_vec:
    case INDEX_op_x86_punpckh_vec:
#if TCG_TARGET_REG_BITS == 32
    case INDEX_op_dup2_vec:
#endif
        return &x_x_x;
    case INDEX_op_dup_vec:
    case INDEX_op_shli_vec:
    case INDEX_op_shri_vec:
    case INDEX_op_sari_vec:
    case INDEX_op_x86_psrldq_vec:
        return &x_x;
    case INDEX_op_x86_vpblendvb_vec:
        return &x_x_x_x;

    default:
        break;
    }
    return NULL;
}

static void tcg_out_nop_fill(tcg_insn_unit *p, int count)
{
    memset(p, 0x90, count);
}

static void tcg_target_init(TCGContext *s)
{
#ifdef CONFIG_CPUID_H
    unsigned a, b, c, d, b7 = 0;
    int max = __get_cpuid_max(0, 0);

    if (max >= 7) {
        /* BMI1 is available on AMD Piledriver and Intel Haswell CPUs.  */
        __cpuid_count(7, 0, a, b7, c, d);
        have_bmi1 = (b7 & bit_BMI) != 0;
        have_bmi2 = (b7 & bit_BMI2) != 0;
    }

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

        /* There are a number of things we must check before we can be
           sure of not hitting invalid opcode.  */
        if (c & bit_OSXSAVE) {
            unsigned xcrl, xcrh;
            asm ("xgetbv" : "=a" (xcrl), "=d" (xcrh) : "c" (0));
            if ((xcrl & 6) == 6) {
                have_avx1 = (c & bit_AVX) != 0;
                have_avx2 = (b7 & bit_AVX2) != 0;
            }
        }
    }

    max = __get_cpuid_max(0x8000000, 0);
    if (max >= 1) {
        __cpuid(0x80000001, a, b, c, d);
        /* LZCNT was introduced with AMD Barcelona and Intel Haswell CPUs.  */
        have_lzcnt = (c & bit_LZCNT) != 0;
    }
#endif /* CONFIG_CPUID_H */

    tcg_target_available_regs[TCG_TYPE_I32] = ALL_GENERAL_REGS;
    if (TCG_TARGET_REG_BITS == 64) {
        tcg_target_available_regs[TCG_TYPE_I64] = ALL_GENERAL_REGS;
    }
    if (have_avx1) {
        tcg_target_available_regs[TCG_TYPE_V64] = ALL_VECTOR_REGS;
        tcg_target_available_regs[TCG_TYPE_V128] = ALL_VECTOR_REGS;
    }
    if (have_avx2) {
        tcg_target_available_regs[TCG_TYPE_V256] = ALL_VECTOR_REGS;
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

static void tcg_region_bounds(size_t curr_region, void **pstart, void **pend)
{
    void *start, *end;

    start = (char *)region.start_aligned + curr_region * region.stride;
    end = (char *)start + region.size;

    if (curr_region == 0) {
        start = region.start;
    }
    if (curr_region == region.n - 1) {
        end = region.end;
    }

    *pstart = start;
    *pend = end;
}

static void tcg_region_assign(TCGContext *s, size_t curr_region)
{
    void *start, *end;

    tcg_region_bounds(curr_region, &start, &end);

    s->code_gen_buffer = start;
    s->code_gen_ptr = start;
    s->code_gen_buffer_size = (char *)end - (char *)start;
    s->code_gen_highwater = (char *)end - TCG_HIGHWATER;
}

static bool tcg_region_alloc__locked(TCGContext *s)
{
    if (region.current == region.n) {
        return true;
    }
    tcg_region_assign(s, region.current);
    region.current++;
    return false;
}

static bool tcg_region_alloc(TCGContext *s)
{
    bool err;
    /* read the region size now; alloc__locked will overwrite it on success */
    size_t size_full = s->code_gen_buffer_size;

    qemu_mutex_lock(&region.lock);
    err = tcg_region_alloc__locked(s);
    if (!err) {
        region.agg_size_full += size_full - TCG_HIGHWATER;
    }
    qemu_mutex_unlock(&region.lock);
    return err;
}

static inline bool tcg_region_initial_alloc__locked(TCGContext *s)
{
    return tcg_region_alloc__locked(s);
}

void tcg_region_reset_all(void)
{
    unsigned int n_ctxs = atomic_read(&n_tcg_ctxs);
    unsigned int i;

    qemu_mutex_lock(&region.lock);
    region.current = 0;
    region.agg_size_full = 0;

    for (i = 0; i < n_ctxs; i++) {
        TCGContext *s = atomic_read(&tcg_ctxs[i]);
        bool err = tcg_region_initial_alloc__locked(s);

        g_assert(!err);
    }
    qemu_mutex_unlock(&region.lock);
}

size_t tcg_code_size(void)
{
    unsigned int n_ctxs = atomic_read(&n_tcg_ctxs);
    unsigned int i;
    size_t total;

    qemu_mutex_lock(&region.lock);
    total = region.agg_size_full;
    for (i = 0; i < n_ctxs; i++) {
        const TCGContext *s = atomic_read(&tcg_ctxs[i]);
        size_t size;

        size = (char *)atomic_read(&s->code_gen_ptr) - (char *)s->code_gen_buffer;
        g_assert(size <= s->code_gen_buffer_size);
        total += size;
    }
    qemu_mutex_unlock(&region.lock);
    return total;
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

static const TCGHelperInfo all_helpers[] = {
/* XXX jove */
/* Helper file for declaring TCG helper functions.
   This one defines data structures private to tcg.c.  */

#ifndef HELPER_TCG_H
#define HELPER_TCG_H

/* Helper file for declaring TCG helper functions.
   Used by other helper files.

   Targets should use DEF_HELPER_N and DEF_HELPER_FLAGS_N to declare helper
   functions.  Names should be specified without the helper_ prefix, and
   the return and argument types specified.  3 basic types are understood
   (i32, i64 and ptr).  Additional aliases are provided for convenience and
   to match the types used by the C helper implementation.

   The target helper.h should be included in all files that use/define
   helper functions.  THis will ensure that function prototypes are
   consistent.  In addition it should be included an extra two times for
   helper.c, defining:
    GEN_HELPER 1 to produce op generation functions (gen_helper_*)
    GEN_HELPER 2 to do runtime registration helper functions.
 */

#ifndef EXEC_HELPER_HEAD_H
#define EXEC_HELPER_HEAD_H

#define HELPER(name) glue(helper_, name)

/* Some types that make sense in C, but not for TCG.  */
#define dh_alias_i32 i32
#define dh_alias_s32 i32
#define dh_alias_int i32
#define dh_alias_i64 i64
#define dh_alias_s64 i64
#define dh_alias_f16 i32
#define dh_alias_f32 i32
#define dh_alias_f64 i64
#define dh_alias_ptr ptr
#define dh_alias_void void
#define dh_alias_noreturn noreturn
#define dh_alias(t) glue(dh_alias_, t)

#define dh_ctype_i32 uint32_t
#define dh_ctype_s32 int32_t
#define dh_ctype_int int
#define dh_ctype_i64 uint64_t
#define dh_ctype_s64 int64_t
#define dh_ctype_f16 float16
#define dh_ctype_f32 float32
#define dh_ctype_f64 float64
#define dh_ctype_ptr void *
#define dh_ctype_void void
#define dh_ctype_noreturn void QEMU_NORETURN
#define dh_ctype(t) dh_ctype_##t

#ifdef NEED_CPU_H
# ifdef TARGET_LONG_BITS
#  if TARGET_LONG_BITS == 32
#   define dh_alias_tl i32
#  else
#   define dh_alias_tl i64
#  endif
# endif
# define dh_alias_env ptr
# define dh_ctype_tl target_ulong
# define dh_ctype_env CPUArchState *
#endif

/* We can't use glue() here because it falls foul of C preprocessor
   recursive expansion rules.  */
#define dh_retvar_decl0_void void
#define dh_retvar_decl0_noreturn void
#define dh_retvar_decl0_i32 TCGv_i32 retval
#define dh_retvar_decl0_i64 TCGv_i64 retval
#define dh_retvar_decl0_ptr TCGv_ptr retval
#define dh_retvar_decl0(t) glue(dh_retvar_decl0_, dh_alias(t))

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

#define dh_is_64bit_void 0
#define dh_is_64bit_noreturn 0
#define dh_is_64bit_i32 0
#define dh_is_64bit_i64 1
#define dh_is_64bit_ptr (sizeof(void *) == 8)
#define dh_is_64bit(t) glue(dh_is_64bit_, dh_alias(t))

#define dh_is_signed_void 0
#define dh_is_signed_noreturn 0
#define dh_is_signed_i32 0
#define dh_is_signed_s32 1
#define dh_is_signed_i64 0
#define dh_is_signed_s64 1
#define dh_is_signed_f16 0
#define dh_is_signed_f32 0
#define dh_is_signed_f64 0
#define dh_is_signed_tl  0
#define dh_is_signed_int 1
/* ??? This is highly specific to the host cpu.  There are even special
   extension instructions that may be required, e.g. ia64's addp4.  But
   for now we don't support any 64-bit targets with 32-bit pointers.  */
#define dh_is_signed_ptr 0
#define dh_is_signed_env dh_is_signed_ptr
#define dh_is_signed(t) dh_is_signed_##t

#define dh_sizemask(t, n) \
  ((dh_is_64bit(t) << (n*2)) | (dh_is_signed(t) << (n*2+1)))

#define dh_arg(t, n) \
  glue(glue(tcgv_, dh_alias(t)), _temp)(glue(arg, n))

#define dh_arg_decl(t, n) glue(TCGv_, dh_alias(t)) glue(arg, n)

#define DEF_HELPER_0(name, ret) \
    DEF_HELPER_FLAGS_0(name, 0, ret)
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
#define DEF_HELPER_6(name, ret, t1, t2, t3, t4, t5, t6) \
    DEF_HELPER_FLAGS_6(name, 0, ret, t1, t2, t3, t4, t5, t6)

/* MAX_OPC_PARAM_IARGS must be set to n if last entry is DEF_HELPER_FLAGS_n. */

#endif /* EXEC_HELPER_HEAD_H */

/* Need one more level of indirection before stringification
   to get all the macros expanded first.  */
#define str(s) #s

#define DEF_HELPER_FLAGS_0(NAME, FLAGS, ret) \
  { .func = (void *)HELPER(NAME), .name = str(NAME), .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0) },

#define DEF_HELPER_FLAGS_1(NAME, FLAGS, ret, t1) \
  { .func = (void *)HELPER(NAME), .name = str(NAME), .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1) },

#define DEF_HELPER_FLAGS_2(NAME, FLAGS, ret, t1, t2) \
  { .func = (void *)HELPER(NAME), .name = str(NAME), .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1) \
    | dh_sizemask(t2, 2) },

#define DEF_HELPER_FLAGS_3(NAME, FLAGS, ret, t1, t2, t3) \
  { .func = (void *)HELPER(NAME), .name = str(NAME), .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1) \
    | dh_sizemask(t2, 2) | dh_sizemask(t3, 3) },

#define DEF_HELPER_FLAGS_4(NAME, FLAGS, ret, t1, t2, t3, t4) \
  { .func = (void *)HELPER(NAME), .name = str(NAME), .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1) \
    | dh_sizemask(t2, 2) | dh_sizemask(t3, 3) | dh_sizemask(t4, 4) },

#define DEF_HELPER_FLAGS_5(NAME, FLAGS, ret, t1, t2, t3, t4, t5) \
  { .func = (void *)HELPER(NAME), .name = str(NAME), .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1) \
    | dh_sizemask(t2, 2) | dh_sizemask(t3, 3) | dh_sizemask(t4, 4) \
    | dh_sizemask(t5, 5) },

#define DEF_HELPER_FLAGS_6(NAME, FLAGS, ret, t1, t2, t3, t4, t5, t6) \
  { .func = HELPER(NAME), .name = str(NAME), .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1) \
    | dh_sizemask(t2, 2) | dh_sizemask(t3, 3) | dh_sizemask(t4, 4) \
    | dh_sizemask(t5, 5) | dh_sizemask(t6, 6) },

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
#ifdef TARGET_X86_64
DEF_HELPER_2(divq_EAX, void, env, tl)
DEF_HELPER_2(idivq_EAX, void, env, tl)
#endif
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
#ifdef TARGET_X86_64
DEF_HELPER_2(syscall, void, env, int)
DEF_HELPER_2(sysret, void, env, int)
#endif
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
#ifdef TARGET_X86_64
DEF_HELPER_2(cmpxchg16b_unlocked, void, env, tl)
DEF_HELPER_2(cmpxchg16b, void, env, tl)
#endif
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

/* x86 FPU */

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
DEF_HELPER_1(fmov_ST0_FT0, void, env)
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

/* MMX/SSE */

DEF_HELPER_2(ldmxcsr, void, env, i32)
DEF_HELPER_1(enter_mmx, void, env)
DEF_HELPER_1(emms, void, env)
DEF_HELPER_3(movq, void, env, ptr, ptr)

#define SHIFT 0
/*
 *  MMX/3DNow!/SSE/SSE2/SSE3/SSSE3/SSE4/PNI support
 *
 *  Copyright (c) 2005 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#if SHIFT == 0
#define Reg MMXReg
#define SUFFIX _mmx
#else
#define Reg ZMMReg
#define SUFFIX _xmm
#endif

#define dh_alias_Reg ptr
#define dh_alias_ZMMReg ptr
#define dh_alias_MMXReg ptr
#define dh_ctype_Reg Reg *
#define dh_ctype_ZMMReg ZMMReg *
#define dh_ctype_MMXReg MMXReg *
#define dh_is_signed_Reg dh_is_signed_ptr
#define dh_is_signed_ZMMReg dh_is_signed_ptr
#define dh_is_signed_MMXReg dh_is_signed_ptr

DEF_HELPER_3(glue(psrlw, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(psraw, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(psllw, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(psrld, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(psrad, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(pslld, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(psrlq, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(psllq, SUFFIX), void, env, Reg, Reg)

#if SHIFT == 1
DEF_HELPER_3(glue(psrldq, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(pslldq, SUFFIX), void, env, Reg, Reg)
#endif

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
#if SHIFT == 0
SSE_HELPER_W(pmulhrw, FMULHRW)
#endif
SSE_HELPER_W(pmulhuw, FMULHUW)
SSE_HELPER_W(pmulhw, FMULHW)

SSE_HELPER_B(pavgb, FAVG)
SSE_HELPER_W(pavgw, FAVG)

DEF_HELPER_3(glue(pmuludq, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(pmaddwd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psadbw, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_4(glue(maskmov, SUFFIX), void, env, Reg, Reg, tl)
DEF_HELPER_2(glue(movl_mm_T0, SUFFIX), void, Reg, i32)
#ifdef TARGET_X86_64
DEF_HELPER_2(glue(movq_mm_T0, SUFFIX), void, Reg, i64)
#endif

#if SHIFT == 0
DEF_HELPER_3(glue(pshufw, SUFFIX), void, Reg, Reg, int)
#else
DEF_HELPER_3(shufps, void, Reg, Reg, int)
DEF_HELPER_3(shufpd, void, Reg, Reg, int)
DEF_HELPER_3(glue(pshufd, SUFFIX), void, Reg, Reg, int)
DEF_HELPER_3(glue(pshuflw, SUFFIX), void, Reg, Reg, int)
DEF_HELPER_3(glue(pshufhw, SUFFIX), void, Reg, Reg, int)
#endif

#if SHIFT == 1
/* FPU ops */
/* XXX: not accurate */

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

#ifdef TARGET_X86_64
DEF_HELPER_3(cvtsq2ss, void, env, ZMMReg, i64)
DEF_HELPER_3(cvtsq2sd, void, env, ZMMReg, i64)
#endif

DEF_HELPER_3(cvtps2dq, void, env, ZMMReg, ZMMReg)
DEF_HELPER_3(cvtpd2dq, void, env, ZMMReg, ZMMReg)
DEF_HELPER_3(cvtps2pi, void, env, MMXReg, ZMMReg)
DEF_HELPER_3(cvtpd2pi, void, env, MMXReg, ZMMReg)
DEF_HELPER_2(cvtss2si, s32, env, ZMMReg)
DEF_HELPER_2(cvtsd2si, s32, env, ZMMReg)
#ifdef TARGET_X86_64
DEF_HELPER_2(cvtss2sq, s64, env, ZMMReg)
DEF_HELPER_2(cvtsd2sq, s64, env, ZMMReg)
#endif

DEF_HELPER_3(cvttps2dq, void, env, ZMMReg, ZMMReg)
DEF_HELPER_3(cvttpd2dq, void, env, ZMMReg, ZMMReg)
DEF_HELPER_3(cvttps2pi, void, env, MMXReg, ZMMReg)
DEF_HELPER_3(cvttpd2pi, void, env, MMXReg, ZMMReg)
DEF_HELPER_2(cvttss2si, s32, env, ZMMReg)
DEF_HELPER_2(cvttsd2si, s32, env, ZMMReg)
#ifdef TARGET_X86_64
DEF_HELPER_2(cvttss2sq, s64, env, ZMMReg)
DEF_HELPER_2(cvttsd2sq, s64, env, ZMMReg)
#endif

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
#endif

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

#if SHIFT == 1
DEF_HELPER_3(glue(punpcklqdq, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(punpckhqdq, SUFFIX), void, env, Reg, Reg)
#endif

/* 3DNow! float ops */
#if SHIFT == 0
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
#endif

/* SSSE3 op helpers */
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

/* SSE4.1 op helpers */
#if SHIFT == 1
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
#endif

/* SSE4.2 op helpers */
#if SHIFT == 1
DEF_HELPER_3(glue(pcmpgtq, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_4(glue(pcmpestri, SUFFIX), void, env, Reg, Reg, i32)
DEF_HELPER_4(glue(pcmpestrm, SUFFIX), void, env, Reg, Reg, i32)
DEF_HELPER_4(glue(pcmpistri, SUFFIX), void, env, Reg, Reg, i32)
DEF_HELPER_4(glue(pcmpistrm, SUFFIX), void, env, Reg, Reg, i32)
DEF_HELPER_3(crc32, tl, i32, tl, i32)
#endif

/* AES-NI op helpers */
#if SHIFT == 1
DEF_HELPER_3(glue(aesdec, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(aesdeclast, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(aesenc, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(aesenclast, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(aesimc, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_4(glue(aeskeygenassist, SUFFIX), void, env, Reg, Reg, i32)
DEF_HELPER_4(glue(pclmulqdq, SUFFIX), void, env, Reg, Reg, i32)
#endif

#undef SHIFT
#undef Reg
#undef SUFFIX

#undef SSE_HELPER_B
#undef SSE_HELPER_W
#undef SSE_HELPER_L
#undef SSE_HELPER_Q
#undef SSE_HELPER_S
#undef SSE_HELPER_CMP
#undef UNPCK_OP
#define SHIFT 1
/*
 *  MMX/3DNow!/SSE/SSE2/SSE3/SSSE3/SSE4/PNI support
 *
 *  Copyright (c) 2005 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#if SHIFT == 0
#define Reg MMXReg
#define SUFFIX _mmx
#else
#define Reg ZMMReg
#define SUFFIX _xmm
#endif

#define dh_alias_Reg ptr
#define dh_alias_ZMMReg ptr
#define dh_alias_MMXReg ptr
#define dh_ctype_Reg Reg *
#define dh_ctype_ZMMReg ZMMReg *
#define dh_ctype_MMXReg MMXReg *
#define dh_is_signed_Reg dh_is_signed_ptr
#define dh_is_signed_ZMMReg dh_is_signed_ptr
#define dh_is_signed_MMXReg dh_is_signed_ptr

DEF_HELPER_3(glue(psrlw, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(psraw, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(psllw, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(psrld, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(psrad, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(pslld, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(psrlq, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(psllq, SUFFIX), void, env, Reg, Reg)

#if SHIFT == 1
DEF_HELPER_3(glue(psrldq, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(pslldq, SUFFIX), void, env, Reg, Reg)
#endif

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
#if SHIFT == 0
SSE_HELPER_W(pmulhrw, FMULHRW)
#endif
SSE_HELPER_W(pmulhuw, FMULHUW)
SSE_HELPER_W(pmulhw, FMULHW)

SSE_HELPER_B(pavgb, FAVG)
SSE_HELPER_W(pavgw, FAVG)

DEF_HELPER_3(glue(pmuludq, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(pmaddwd, SUFFIX), void, env, Reg, Reg)

DEF_HELPER_3(glue(psadbw, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_4(glue(maskmov, SUFFIX), void, env, Reg, Reg, tl)
DEF_HELPER_2(glue(movl_mm_T0, SUFFIX), void, Reg, i32)
#ifdef TARGET_X86_64
DEF_HELPER_2(glue(movq_mm_T0, SUFFIX), void, Reg, i64)
#endif

#if SHIFT == 0
DEF_HELPER_3(glue(pshufw, SUFFIX), void, Reg, Reg, int)
#else
DEF_HELPER_3(shufps, void, Reg, Reg, int)
DEF_HELPER_3(shufpd, void, Reg, Reg, int)
DEF_HELPER_3(glue(pshufd, SUFFIX), void, Reg, Reg, int)
DEF_HELPER_3(glue(pshuflw, SUFFIX), void, Reg, Reg, int)
DEF_HELPER_3(glue(pshufhw, SUFFIX), void, Reg, Reg, int)
#endif

#if SHIFT == 1
/* FPU ops */
/* XXX: not accurate */

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

#ifdef TARGET_X86_64
DEF_HELPER_3(cvtsq2ss, void, env, ZMMReg, i64)
DEF_HELPER_3(cvtsq2sd, void, env, ZMMReg, i64)
#endif

DEF_HELPER_3(cvtps2dq, void, env, ZMMReg, ZMMReg)
DEF_HELPER_3(cvtpd2dq, void, env, ZMMReg, ZMMReg)
DEF_HELPER_3(cvtps2pi, void, env, MMXReg, ZMMReg)
DEF_HELPER_3(cvtpd2pi, void, env, MMXReg, ZMMReg)
DEF_HELPER_2(cvtss2si, s32, env, ZMMReg)
DEF_HELPER_2(cvtsd2si, s32, env, ZMMReg)
#ifdef TARGET_X86_64
DEF_HELPER_2(cvtss2sq, s64, env, ZMMReg)
DEF_HELPER_2(cvtsd2sq, s64, env, ZMMReg)
#endif

DEF_HELPER_3(cvttps2dq, void, env, ZMMReg, ZMMReg)
DEF_HELPER_3(cvttpd2dq, void, env, ZMMReg, ZMMReg)
DEF_HELPER_3(cvttps2pi, void, env, MMXReg, ZMMReg)
DEF_HELPER_3(cvttpd2pi, void, env, MMXReg, ZMMReg)
DEF_HELPER_2(cvttss2si, s32, env, ZMMReg)
DEF_HELPER_2(cvttsd2si, s32, env, ZMMReg)
#ifdef TARGET_X86_64
DEF_HELPER_2(cvttss2sq, s64, env, ZMMReg)
DEF_HELPER_2(cvttsd2sq, s64, env, ZMMReg)
#endif

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
#endif

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

#if SHIFT == 1
DEF_HELPER_3(glue(punpcklqdq, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(punpckhqdq, SUFFIX), void, env, Reg, Reg)
#endif

/* 3DNow! float ops */
#if SHIFT == 0
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
#endif

/* SSSE3 op helpers */
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

/* SSE4.1 op helpers */
#if SHIFT == 1
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
#endif

/* SSE4.2 op helpers */
#if SHIFT == 1
DEF_HELPER_3(glue(pcmpgtq, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_4(glue(pcmpestri, SUFFIX), void, env, Reg, Reg, i32)
DEF_HELPER_4(glue(pcmpestrm, SUFFIX), void, env, Reg, Reg, i32)
DEF_HELPER_4(glue(pcmpistri, SUFFIX), void, env, Reg, Reg, i32)
DEF_HELPER_4(glue(pcmpistrm, SUFFIX), void, env, Reg, Reg, i32)
DEF_HELPER_3(crc32, tl, i32, tl, i32)
#endif

/* AES-NI op helpers */
#if SHIFT == 1
DEF_HELPER_3(glue(aesdec, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(aesdeclast, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(aesenc, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(aesenclast, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_3(glue(aesimc, SUFFIX), void, env, Reg, Reg)
DEF_HELPER_4(glue(aeskeygenassist, SUFFIX), void, env, Reg, Reg, i32)
DEF_HELPER_4(glue(pclmulqdq, SUFFIX), void, env, Reg, Reg, i32)
#endif

#undef SHIFT
#undef Reg
#undef SUFFIX

#undef SSE_HELPER_B
#undef SSE_HELPER_W
#undef SSE_HELPER_L
#undef SSE_HELPER_Q
#undef SSE_HELPER_S
#undef SSE_HELPER_CMP
#undef UNPCK_OP

DEF_HELPER_3(rclb, tl, env, tl, tl)
DEF_HELPER_3(rclw, tl, env, tl, tl)
DEF_HELPER_3(rcll, tl, env, tl, tl)
DEF_HELPER_3(rcrb, tl, env, tl, tl)
DEF_HELPER_3(rcrw, tl, env, tl, tl)
DEF_HELPER_3(rcrl, tl, env, tl, tl)
#ifdef TARGET_X86_64
DEF_HELPER_3(rclq, tl, env, tl, tl)
DEF_HELPER_3(rcrq, tl, env, tl, tl)
#endif
/* This file is autogenerated by tracetool, do not edit. */

DEF_HELPER_FLAGS_3(trace_guest_mem_before_exec_proxy, TCG_CALL_NO_RWG, void, env, tl, i32)
DEF_HELPER_FLAGS_2(div_i32, TCG_CALL_NO_RWG_SE, s32, s32, s32)
DEF_HELPER_FLAGS_2(rem_i32, TCG_CALL_NO_RWG_SE, s32, s32, s32)
DEF_HELPER_FLAGS_2(divu_i32, TCG_CALL_NO_RWG_SE, i32, i32, i32)
DEF_HELPER_FLAGS_2(remu_i32, TCG_CALL_NO_RWG_SE, i32, i32, i32)

DEF_HELPER_FLAGS_2(div_i64, TCG_CALL_NO_RWG_SE, s64, s64, s64)
DEF_HELPER_FLAGS_2(rem_i64, TCG_CALL_NO_RWG_SE, s64, s64, s64)
DEF_HELPER_FLAGS_2(divu_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64)
DEF_HELPER_FLAGS_2(remu_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64)

DEF_HELPER_FLAGS_2(shl_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64)
DEF_HELPER_FLAGS_2(shr_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64)
DEF_HELPER_FLAGS_2(sar_i64, TCG_CALL_NO_RWG_SE, s64, s64, s64)

DEF_HELPER_FLAGS_2(mulsh_i64, TCG_CALL_NO_RWG_SE, s64, s64, s64)
DEF_HELPER_FLAGS_2(muluh_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64)

DEF_HELPER_FLAGS_2(clz_i32, TCG_CALL_NO_RWG_SE, i32, i32, i32)
DEF_HELPER_FLAGS_2(ctz_i32, TCG_CALL_NO_RWG_SE, i32, i32, i32)
DEF_HELPER_FLAGS_2(clz_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64)
DEF_HELPER_FLAGS_2(ctz_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64)
DEF_HELPER_FLAGS_1(clrsb_i32, TCG_CALL_NO_RWG_SE, i32, i32)
DEF_HELPER_FLAGS_1(clrsb_i64, TCG_CALL_NO_RWG_SE, i64, i64)
DEF_HELPER_FLAGS_1(ctpop_i32, TCG_CALL_NO_RWG_SE, i32, i32)
DEF_HELPER_FLAGS_1(ctpop_i64, TCG_CALL_NO_RWG_SE, i64, i64)

DEF_HELPER_FLAGS_1(lookup_tb_ptr, TCG_CALL_NO_WG_SE, ptr, env)

DEF_HELPER_FLAGS_1(exit_atomic, TCG_CALL_NO_WG, noreturn, env)

#ifdef CONFIG_SOFTMMU

DEF_HELPER_FLAGS_5(atomic_cmpxchgb, TCG_CALL_NO_WG,
                   i32, env, tl, i32, i32, i32)
DEF_HELPER_FLAGS_5(atomic_cmpxchgw_be, TCG_CALL_NO_WG,
                   i32, env, tl, i32, i32, i32)
DEF_HELPER_FLAGS_5(atomic_cmpxchgw_le, TCG_CALL_NO_WG,
                   i32, env, tl, i32, i32, i32)
DEF_HELPER_FLAGS_5(atomic_cmpxchgl_be, TCG_CALL_NO_WG,
                   i32, env, tl, i32, i32, i32)
DEF_HELPER_FLAGS_5(atomic_cmpxchgl_le, TCG_CALL_NO_WG,
                   i32, env, tl, i32, i32, i32)
#ifdef CONFIG_ATOMIC64
DEF_HELPER_FLAGS_5(atomic_cmpxchgq_be, TCG_CALL_NO_WG,
                   i64, env, tl, i64, i64, i32)
DEF_HELPER_FLAGS_5(atomic_cmpxchgq_le, TCG_CALL_NO_WG,
                   i64, env, tl, i64, i64, i32)
#endif

#ifdef CONFIG_ATOMIC64
#define GEN_ATOMIC_HELPERS(NAME)                                  \
    DEF_HELPER_FLAGS_4(glue(glue(atomic_, NAME), b),              \
                       TCG_CALL_NO_WG, i32, env, tl, i32, i32)    \
    DEF_HELPER_FLAGS_4(glue(glue(atomic_, NAME), w_le),           \
                       TCG_CALL_NO_WG, i32, env, tl, i32, i32)    \
    DEF_HELPER_FLAGS_4(glue(glue(atomic_, NAME), w_be),           \
                       TCG_CALL_NO_WG, i32, env, tl, i32, i32)    \
    DEF_HELPER_FLAGS_4(glue(glue(atomic_, NAME), l_le),           \
                       TCG_CALL_NO_WG, i32, env, tl, i32, i32)    \
    DEF_HELPER_FLAGS_4(glue(glue(atomic_, NAME), l_be),           \
                       TCG_CALL_NO_WG, i32, env, tl, i32, i32)    \
    DEF_HELPER_FLAGS_4(glue(glue(atomic_, NAME), q_le),           \
                       TCG_CALL_NO_WG, i64, env, tl, i64, i32)    \
    DEF_HELPER_FLAGS_4(glue(glue(atomic_, NAME), q_be),           \
                       TCG_CALL_NO_WG, i64, env, tl, i64, i32)
#else
#define GEN_ATOMIC_HELPERS(NAME)                                  \
    DEF_HELPER_FLAGS_4(glue(glue(atomic_, NAME), b),              \
                       TCG_CALL_NO_WG, i32, env, tl, i32, i32)    \
    DEF_HELPER_FLAGS_4(glue(glue(atomic_, NAME), w_le),           \
                       TCG_CALL_NO_WG, i32, env, tl, i32, i32)    \
    DEF_HELPER_FLAGS_4(glue(glue(atomic_, NAME), w_be),           \
                       TCG_CALL_NO_WG, i32, env, tl, i32, i32)    \
    DEF_HELPER_FLAGS_4(glue(glue(atomic_, NAME), l_le),           \
                       TCG_CALL_NO_WG, i32, env, tl, i32, i32)    \
    DEF_HELPER_FLAGS_4(glue(glue(atomic_, NAME), l_be),           \
                       TCG_CALL_NO_WG, i32, env, tl, i32, i32)
#endif /* CONFIG_ATOMIC64 */

#else

DEF_HELPER_FLAGS_4(atomic_cmpxchgb, TCG_CALL_NO_WG, i32, env, tl, i32, i32)
DEF_HELPER_FLAGS_4(atomic_cmpxchgw_be, TCG_CALL_NO_WG, i32, env, tl, i32, i32)
DEF_HELPER_FLAGS_4(atomic_cmpxchgw_le, TCG_CALL_NO_WG, i32, env, tl, i32, i32)
DEF_HELPER_FLAGS_4(atomic_cmpxchgl_be, TCG_CALL_NO_WG, i32, env, tl, i32, i32)
DEF_HELPER_FLAGS_4(atomic_cmpxchgl_le, TCG_CALL_NO_WG, i32, env, tl, i32, i32)
#ifdef CONFIG_ATOMIC64
DEF_HELPER_FLAGS_4(atomic_cmpxchgq_be, TCG_CALL_NO_WG, i64, env, tl, i64, i64)
DEF_HELPER_FLAGS_4(atomic_cmpxchgq_le, TCG_CALL_NO_WG, i64, env, tl, i64, i64)
#endif

#ifdef CONFIG_ATOMIC64
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
                       TCG_CALL_NO_WG, i32, env, tl, i32)    \
    DEF_HELPER_FLAGS_3(glue(glue(atomic_, NAME), q_le),      \
                       TCG_CALL_NO_WG, i64, env, tl, i64)    \
    DEF_HELPER_FLAGS_3(glue(glue(atomic_, NAME), q_be),      \
                       TCG_CALL_NO_WG, i64, env, tl, i64)
#else
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
#endif /* CONFIG_ATOMIC64 */

#endif /* CONFIG_SOFTMMU */

GEN_ATOMIC_HELPERS(fetch_add)
GEN_ATOMIC_HELPERS(fetch_and)
GEN_ATOMIC_HELPERS(fetch_or)
GEN_ATOMIC_HELPERS(fetch_xor)

GEN_ATOMIC_HELPERS(add_fetch)
GEN_ATOMIC_HELPERS(and_fetch)
GEN_ATOMIC_HELPERS(or_fetch)
GEN_ATOMIC_HELPERS(xor_fetch)

GEN_ATOMIC_HELPERS(xchg)

#undef GEN_ATOMIC_HELPERS

DEF_HELPER_FLAGS_3(gvec_mov, TCG_CALL_NO_RWG, void, ptr, ptr, i32)

DEF_HELPER_FLAGS_3(gvec_dup8, TCG_CALL_NO_RWG, void, ptr, i32, i32)
DEF_HELPER_FLAGS_3(gvec_dup16, TCG_CALL_NO_RWG, void, ptr, i32, i32)
DEF_HELPER_FLAGS_3(gvec_dup32, TCG_CALL_NO_RWG, void, ptr, i32, i32)
DEF_HELPER_FLAGS_3(gvec_dup64, TCG_CALL_NO_RWG, void, ptr, i32, i64)

DEF_HELPER_FLAGS_4(gvec_add8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_add16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_add32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_add64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_adds8, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)
DEF_HELPER_FLAGS_4(gvec_adds16, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)
DEF_HELPER_FLAGS_4(gvec_adds32, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)
DEF_HELPER_FLAGS_4(gvec_adds64, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)

DEF_HELPER_FLAGS_4(gvec_sub8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_sub16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_sub32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_sub64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_subs8, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)
DEF_HELPER_FLAGS_4(gvec_subs16, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)
DEF_HELPER_FLAGS_4(gvec_subs32, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)
DEF_HELPER_FLAGS_4(gvec_subs64, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)

DEF_HELPER_FLAGS_4(gvec_mul8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_mul16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_mul32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_mul64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_muls8, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)
DEF_HELPER_FLAGS_4(gvec_muls16, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)
DEF_HELPER_FLAGS_4(gvec_muls32, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)
DEF_HELPER_FLAGS_4(gvec_muls64, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)

DEF_HELPER_FLAGS_4(gvec_ssadd8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_ssadd16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_ssadd32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_ssadd64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_sssub8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_sssub16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_sssub32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_sssub64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_usadd8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_usadd16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_usadd32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_usadd64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_ussub8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_ussub16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_ussub32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_ussub64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_3(gvec_neg8, TCG_CALL_NO_RWG, void, ptr, ptr, i32)
DEF_HELPER_FLAGS_3(gvec_neg16, TCG_CALL_NO_RWG, void, ptr, ptr, i32)
DEF_HELPER_FLAGS_3(gvec_neg32, TCG_CALL_NO_RWG, void, ptr, ptr, i32)
DEF_HELPER_FLAGS_3(gvec_neg64, TCG_CALL_NO_RWG, void, ptr, ptr, i32)

DEF_HELPER_FLAGS_3(gvec_not, TCG_CALL_NO_RWG, void, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_and, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_or, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_xor, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_andc, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_orc, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_ands, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)
DEF_HELPER_FLAGS_4(gvec_xors, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)
DEF_HELPER_FLAGS_4(gvec_ors, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)

DEF_HELPER_FLAGS_3(gvec_shl8i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)
DEF_HELPER_FLAGS_3(gvec_shl16i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)
DEF_HELPER_FLAGS_3(gvec_shl32i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)
DEF_HELPER_FLAGS_3(gvec_shl64i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)

DEF_HELPER_FLAGS_3(gvec_shr8i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)
DEF_HELPER_FLAGS_3(gvec_shr16i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)
DEF_HELPER_FLAGS_3(gvec_shr32i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)
DEF_HELPER_FLAGS_3(gvec_shr64i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)

DEF_HELPER_FLAGS_3(gvec_sar8i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)
DEF_HELPER_FLAGS_3(gvec_sar16i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)
DEF_HELPER_FLAGS_3(gvec_sar32i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)
DEF_HELPER_FLAGS_3(gvec_sar64i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_eq8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_eq16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_eq32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_eq64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_ne8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_ne16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_ne32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_ne64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_lt8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_lt16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_lt32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_lt64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_le8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_le16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_le32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_le64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_ltu8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_ltu16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_ltu32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_ltu64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_leu8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_leu16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_leu32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_leu64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

#undef str
#undef DEF_HELPER_FLAGS_0
#undef DEF_HELPER_FLAGS_1
#undef DEF_HELPER_FLAGS_2
#undef DEF_HELPER_FLAGS_3
#undef DEF_HELPER_FLAGS_4
#undef DEF_HELPER_FLAGS_5
#undef DEF_HELPER_FLAGS_6

#endif /* HELPER_TCG_H */
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

TranslationBlock *tcg_tb_alloc(TCGContext *s)
{
    uintptr_t align = qemu_icache_linesize;
    TranslationBlock *tb;
    void *next;

 retry:
    tb = (TranslationBlock *)ROUND_UP((uintptr_t)s->code_gen_ptr, align);
    next = (void *)ROUND_UP((uintptr_t)(tb + 1), align);

    if (unlikely(next > s->code_gen_highwater)) {
        if (tcg_region_alloc(s)) {
            return NULL;
        }
        goto retry;
    }
    atomic_set(&s->code_gen_ptr, next);
    s->data_gen_ptr = NULL;
    return tb;
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

    QTAILQ_INIT(&s->ops);
    QTAILQ_INIT(&s->free_ops);
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

TCGTemp *tcg_global_mem_new_internal(TCGType type, TCGv_ptr base,
                                     intptr_t offset, const char *name)
{
    TCGContext *s = tcg_ctx;
    TCGTemp *base_ts = tcgv_ptr_temp(base);
    TCGTemp *ts = tcg_global_alloc(s);
    int indirect_reg = 0, bigendian = 0;
#ifdef HOST_WORDS_BIGENDIAN
    bigendian = 1;
#endif

    if (!base_ts->fixed_reg) {
        /* We do not support double-indirect registers.  */
        tcg_debug_assert(!base_ts->indirect_reg);
        base_ts->indirect_base = 1;
        s->nb_indirects += (TCG_TARGET_REG_BITS == 32 && type == TCG_TYPE_I64
                            ? 2 : 1);
        indirect_reg = 1;
    }

    if (TCG_TARGET_REG_BITS == 32 && type == TCG_TYPE_I64) {
        TCGTemp *ts2 = tcg_global_alloc(s);
        char buf[64];

        ts->base_type = TCG_TYPE_I64;
        ts->type = TCG_TYPE_I32;
        ts->indirect_reg = indirect_reg;
        ts->mem_allocated = 1;
        ts->mem_base = base_ts;
        ts->mem_offset = offset + bigendian * 4;
        pstrcpy(buf, sizeof(buf), name);
        pstrcat(buf, sizeof(buf), "_0");
        ts->name = strdup(buf);

        tcg_debug_assert(ts2 == ts + 1);
        ts2->base_type = TCG_TYPE_I64;
        ts2->type = TCG_TYPE_I32;
        ts2->indirect_reg = indirect_reg;
        ts2->mem_allocated = 1;
        ts2->mem_base = base_ts;
        ts2->mem_offset = offset + (1 - bigendian) * 4;
        pstrcpy(buf, sizeof(buf), name);
        pstrcat(buf, sizeof(buf), "_1");
        ts2->name = strdup(buf);
    } else {
        ts->base_type = type;
        ts->type = type;
        ts->indirect_reg = indirect_reg;
        ts->mem_allocated = 1;
        ts->mem_base = base_ts;
        ts->mem_offset = offset;
        ts->name = name;
    }
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

bool tcg_op_supported(TCGOpcode op)
{
    const bool have_vec
        = TCG_TARGET_HAS_v64 | TCG_TARGET_HAS_v128 | TCG_TARGET_HAS_v256;

    switch (op) {
    case INDEX_op_discard:
    case INDEX_op_set_label:
    case INDEX_op_call:
    case INDEX_op_br:
    case INDEX_op_mb:
    case INDEX_op_insn_start:
    case INDEX_op_exit_tb:
    case INDEX_op_goto_tb:
    case INDEX_op_qemu_ld_i32:
    case INDEX_op_qemu_st_i32:
    case INDEX_op_qemu_ld_i64:
    case INDEX_op_qemu_st_i64:
        return true;

    case INDEX_op_goto_ptr:
        return TCG_TARGET_HAS_goto_ptr;

    case INDEX_op_mov_i32:
    case INDEX_op_movi_i32:
    case INDEX_op_setcond_i32:
    case INDEX_op_brcond_i32:
    case INDEX_op_ld8u_i32:
    case INDEX_op_ld8s_i32:
    case INDEX_op_ld16u_i32:
    case INDEX_op_ld16s_i32:
    case INDEX_op_ld_i32:
    case INDEX_op_st8_i32:
    case INDEX_op_st16_i32:
    case INDEX_op_st_i32:
    case INDEX_op_add_i32:
    case INDEX_op_sub_i32:
    case INDEX_op_mul_i32:
    case INDEX_op_and_i32:
    case INDEX_op_or_i32:
    case INDEX_op_xor_i32:
    case INDEX_op_shl_i32:
    case INDEX_op_shr_i32:
    case INDEX_op_sar_i32:
        return true;

    case INDEX_op_movcond_i32:
        return TCG_TARGET_HAS_movcond_i32;
    case INDEX_op_div_i32:
    case INDEX_op_divu_i32:
        return TCG_TARGET_HAS_div_i32;
    case INDEX_op_rem_i32:
    case INDEX_op_remu_i32:
        return TCG_TARGET_HAS_rem_i32;
    case INDEX_op_div2_i32:
    case INDEX_op_divu2_i32:
        return TCG_TARGET_HAS_div2_i32;
    case INDEX_op_rotl_i32:
    case INDEX_op_rotr_i32:
        return TCG_TARGET_HAS_rot_i32;
    case INDEX_op_deposit_i32:
        return TCG_TARGET_HAS_deposit_i32;
    case INDEX_op_extract_i32:
        return TCG_TARGET_HAS_extract_i32;
    case INDEX_op_sextract_i32:
        return TCG_TARGET_HAS_sextract_i32;
    case INDEX_op_add2_i32:
        return TCG_TARGET_HAS_add2_i32;
    case INDEX_op_sub2_i32:
        return TCG_TARGET_HAS_sub2_i32;
    case INDEX_op_mulu2_i32:
        return TCG_TARGET_HAS_mulu2_i32;
    case INDEX_op_muls2_i32:
        return TCG_TARGET_HAS_muls2_i32;
    case INDEX_op_muluh_i32:
        return TCG_TARGET_HAS_muluh_i32;
    case INDEX_op_mulsh_i32:
        return TCG_TARGET_HAS_mulsh_i32;
    case INDEX_op_ext8s_i32:
        return TCG_TARGET_HAS_ext8s_i32;
    case INDEX_op_ext16s_i32:
        return TCG_TARGET_HAS_ext16s_i32;
    case INDEX_op_ext8u_i32:
        return TCG_TARGET_HAS_ext8u_i32;
    case INDEX_op_ext16u_i32:
        return TCG_TARGET_HAS_ext16u_i32;
    case INDEX_op_bswap16_i32:
        return TCG_TARGET_HAS_bswap16_i32;
    case INDEX_op_bswap32_i32:
        return TCG_TARGET_HAS_bswap32_i32;
    case INDEX_op_not_i32:
        return TCG_TARGET_HAS_not_i32;
    case INDEX_op_neg_i32:
        return TCG_TARGET_HAS_neg_i32;
    case INDEX_op_andc_i32:
        return TCG_TARGET_HAS_andc_i32;
    case INDEX_op_orc_i32:
        return TCG_TARGET_HAS_orc_i32;
    case INDEX_op_eqv_i32:
        return TCG_TARGET_HAS_eqv_i32;
    case INDEX_op_nand_i32:
        return TCG_TARGET_HAS_nand_i32;
    case INDEX_op_nor_i32:
        return TCG_TARGET_HAS_nor_i32;
    case INDEX_op_clz_i32:
        return TCG_TARGET_HAS_clz_i32;
    case INDEX_op_ctz_i32:
        return TCG_TARGET_HAS_ctz_i32;
    case INDEX_op_ctpop_i32:
        return TCG_TARGET_HAS_ctpop_i32;

    case INDEX_op_brcond2_i32:
    case INDEX_op_setcond2_i32:
        return TCG_TARGET_REG_BITS == 32;

    case INDEX_op_mov_i64:
    case INDEX_op_movi_i64:
    case INDEX_op_setcond_i64:
    case INDEX_op_brcond_i64:
    case INDEX_op_ld8u_i64:
    case INDEX_op_ld8s_i64:
    case INDEX_op_ld16u_i64:
    case INDEX_op_ld16s_i64:
    case INDEX_op_ld32u_i64:
    case INDEX_op_ld32s_i64:
    case INDEX_op_ld_i64:
    case INDEX_op_st8_i64:
    case INDEX_op_st16_i64:
    case INDEX_op_st32_i64:
    case INDEX_op_st_i64:
    case INDEX_op_add_i64:
    case INDEX_op_sub_i64:
    case INDEX_op_mul_i64:
    case INDEX_op_and_i64:
    case INDEX_op_or_i64:
    case INDEX_op_xor_i64:
    case INDEX_op_shl_i64:
    case INDEX_op_shr_i64:
    case INDEX_op_sar_i64:
    case INDEX_op_ext_i32_i64:
    case INDEX_op_extu_i32_i64:
        return TCG_TARGET_REG_BITS == 64;

    case INDEX_op_movcond_i64:
        return TCG_TARGET_HAS_movcond_i64;
    case INDEX_op_div_i64:
    case INDEX_op_divu_i64:
        return TCG_TARGET_HAS_div_i64;
    case INDEX_op_rem_i64:
    case INDEX_op_remu_i64:
        return TCG_TARGET_HAS_rem_i64;
    case INDEX_op_div2_i64:
    case INDEX_op_divu2_i64:
        return TCG_TARGET_HAS_div2_i64;
    case INDEX_op_rotl_i64:
    case INDEX_op_rotr_i64:
        return TCG_TARGET_HAS_rot_i64;
    case INDEX_op_deposit_i64:
        return TCG_TARGET_HAS_deposit_i64;
    case INDEX_op_extract_i64:
        return TCG_TARGET_HAS_extract_i64;
    case INDEX_op_sextract_i64:
        return TCG_TARGET_HAS_sextract_i64;
    case INDEX_op_extrl_i64_i32:
        return TCG_TARGET_HAS_extrl_i64_i32;
    case INDEX_op_extrh_i64_i32:
        return TCG_TARGET_HAS_extrh_i64_i32;
    case INDEX_op_ext8s_i64:
        return TCG_TARGET_HAS_ext8s_i64;
    case INDEX_op_ext16s_i64:
        return TCG_TARGET_HAS_ext16s_i64;
    case INDEX_op_ext32s_i64:
        return TCG_TARGET_HAS_ext32s_i64;
    case INDEX_op_ext8u_i64:
        return TCG_TARGET_HAS_ext8u_i64;
    case INDEX_op_ext16u_i64:
        return TCG_TARGET_HAS_ext16u_i64;
    case INDEX_op_ext32u_i64:
        return TCG_TARGET_HAS_ext32u_i64;
    case INDEX_op_bswap16_i64:
        return TCG_TARGET_HAS_bswap16_i64;
    case INDEX_op_bswap32_i64:
        return TCG_TARGET_HAS_bswap32_i64;
    case INDEX_op_bswap64_i64:
        return TCG_TARGET_HAS_bswap64_i64;
    case INDEX_op_not_i64:
        return TCG_TARGET_HAS_not_i64;
    case INDEX_op_neg_i64:
        return TCG_TARGET_HAS_neg_i64;
    case INDEX_op_andc_i64:
        return TCG_TARGET_HAS_andc_i64;
    case INDEX_op_orc_i64:
        return TCG_TARGET_HAS_orc_i64;
    case INDEX_op_eqv_i64:
        return TCG_TARGET_HAS_eqv_i64;
    case INDEX_op_nand_i64:
        return TCG_TARGET_HAS_nand_i64;
    case INDEX_op_nor_i64:
        return TCG_TARGET_HAS_nor_i64;
    case INDEX_op_clz_i64:
        return TCG_TARGET_HAS_clz_i64;
    case INDEX_op_ctz_i64:
        return TCG_TARGET_HAS_ctz_i64;
    case INDEX_op_ctpop_i64:
        return TCG_TARGET_HAS_ctpop_i64;
    case INDEX_op_add2_i64:
        return TCG_TARGET_HAS_add2_i64;
    case INDEX_op_sub2_i64:
        return TCG_TARGET_HAS_sub2_i64;
    case INDEX_op_mulu2_i64:
        return TCG_TARGET_HAS_mulu2_i64;
    case INDEX_op_muls2_i64:
        return TCG_TARGET_HAS_muls2_i64;
    case INDEX_op_muluh_i64:
        return TCG_TARGET_HAS_muluh_i64;
    case INDEX_op_mulsh_i64:
        return TCG_TARGET_HAS_mulsh_i64;

    case INDEX_op_mov_vec:
    case INDEX_op_dup_vec:
    case INDEX_op_dupi_vec:
    case INDEX_op_ld_vec:
    case INDEX_op_st_vec:
    case INDEX_op_add_vec:
    case INDEX_op_sub_vec:
    case INDEX_op_and_vec:
    case INDEX_op_or_vec:
    case INDEX_op_xor_vec:
    case INDEX_op_cmp_vec:
        return have_vec;
    case INDEX_op_dup2_vec:
        return have_vec && TCG_TARGET_REG_BITS == 32;
    case INDEX_op_not_vec:
        return have_vec && TCG_TARGET_HAS_not_vec;
    case INDEX_op_neg_vec:
        return have_vec && TCG_TARGET_HAS_neg_vec;
    case INDEX_op_andc_vec:
        return have_vec && TCG_TARGET_HAS_andc_vec;
    case INDEX_op_orc_vec:
        return have_vec && TCG_TARGET_HAS_orc_vec;
    case INDEX_op_mul_vec:
        return have_vec && TCG_TARGET_HAS_mul_vec;
    case INDEX_op_shli_vec:
    case INDEX_op_shri_vec:
    case INDEX_op_sari_vec:
        return have_vec && TCG_TARGET_HAS_shi_vec;
    case INDEX_op_shls_vec:
    case INDEX_op_shrs_vec:
    case INDEX_op_sars_vec:
        return have_vec && TCG_TARGET_HAS_shs_vec;
    case INDEX_op_shlv_vec:
    case INDEX_op_shrv_vec:
    case INDEX_op_sarv_vec:
        return have_vec && TCG_TARGET_HAS_shv_vec;

    default:
        tcg_debug_assert(op > INDEX_op_last_generic && op < NB_OPS);
        return true;
    }
}

void tcg_gen_callN(void *func, TCGTemp *ret, int nargs, TCGTemp **args)
{
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

    retl = NULL;
    reth = NULL;
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

    op = tcg_emit_op(INDEX_op_call);

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
    TCGOP_CALLO(op) = nb_rets;

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
    TCGOP_CALLI(op) = real_args;

    /* Make sure the fields didn't overflow.  */
    tcg_debug_assert(TCGOP_CALLI(op) == real_args);
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

static void tcg_reg_alloc_start(TCGContext *s)
{
    int i, n;
    TCGTemp *ts;

    for (i = 0, n = s->nb_globals; i < n; i++) {
        ts = &s->temps[i];
        ts->val_type = (ts->fixed_reg ? TEMP_VAL_REG : TEMP_VAL_MEM);
    }
    for (n = s->nb_temps; i < n; i++) {
        ts = &s->temps[i];
        ts->val_type = (ts->temp_local ? TEMP_VAL_MEM : TEMP_VAL_DEAD);
        ts->mem_allocated = 0;
        ts->fixed_reg = 0;
    }

    memset(s->reg_to_temp, 0, sizeof(s->reg_to_temp));
}

static char *tcg_get_arg_str_ptr(TCGContext *s, char *buf, int buf_size,
                                 TCGTemp *ts)
{
    int idx = temp_idx(ts);

    if (ts->temp_global) {
        pstrcpy(buf, buf_size, ts->name);
    } else if (ts->temp_local) {
        snprintf(buf, buf_size, "loc%d", idx - s->nb_globals);
    } else {
        snprintf(buf, buf_size, "tmp%d", idx - s->nb_globals);
    }
    return buf;
}

static char *tcg_get_arg_str(TCGContext *s, char *buf,
                             int buf_size, TCGArg arg)
{
    return tcg_get_arg_str_ptr(s, buf, buf_size, arg_temp(arg));
}

static inline const char *tcg_find_helper(TCGContext *s, uintptr_t val)
{
    const char *ret = NULL;
    if (helper_table) {
        TCGHelperInfo *info = (TCGHelperInfo *)g_hash_table_lookup(helper_table, (gpointer)val);
        if (info) {
            ret = info->name;
        }
    }
    return ret;
}

static const char * const cond_name[] =
{
    [TCG_COND_NEVER] = "never",
    [TCG_COND_ALWAYS] = "always",
    [TCG_COND_EQ] = "eq",
    [TCG_COND_NE] = "ne",
    [TCG_COND_LT] = "lt",
    [TCG_COND_GE] = "ge",
    [TCG_COND_LE] = "le",
    [TCG_COND_GT] = "gt",
    [TCG_COND_LTU] = "ltu",
    [TCG_COND_GEU] = "geu",
    [TCG_COND_LEU] = "leu",
    [TCG_COND_GTU] = "gtu"
};

static const char * const ldst_name[] =
{
    [MO_UB]   = "ub",
    [MO_SB]   = "sb",
    [MO_LEUW] = "leuw",
    [MO_LESW] = "lesw",
    [MO_LEUL] = "leul",
    [MO_LESL] = "lesl",
    [MO_LEQ]  = "leq",
    [MO_BEUW] = "beuw",
    [MO_BESW] = "besw",
    [MO_BEUL] = "beul",
    [MO_BESL] = "besl",
    [MO_BEQ]  = "beq",
};

static const char * const alignment_name[(MO_AMASK >> MO_ASHIFT) + 1] = {
#ifdef ALIGNED_ONLY
    [MO_UNALN >> MO_ASHIFT]    = "un+",
    [MO_ALIGN >> MO_ASHIFT]    = "",
#else
    [MO_UNALN >> MO_ASHIFT]    = "",
    [MO_ALIGN >> MO_ASHIFT]    = "al+",
#endif
    [MO_ALIGN_2 >> MO_ASHIFT]  = "al2+",
    [MO_ALIGN_4 >> MO_ASHIFT]  = "al4+",
    [MO_ALIGN_8 >> MO_ASHIFT]  = "al8+",
    [MO_ALIGN_16 >> MO_ASHIFT] = "al16+",
    [MO_ALIGN_32 >> MO_ASHIFT] = "al32+",
    [MO_ALIGN_64 >> MO_ASHIFT] = "al64+",
};

void tcg_dump_ops(TCGContext *s)
{
    char buf[128];
    TCGOp *op;

    QTAILQ_FOREACH(op, &s->ops, link) {
        int i, k, nb_oargs, nb_iargs, nb_cargs;
        const TCGOpDef *def;
        TCGOpcode c;
        int col = 0;

        c = op->opc;
        def = &tcg_op_defs[c];

        if (c == INDEX_op_insn_start) {
            col += qemu_log("\n ----");

            for (i = 0; i < TARGET_INSN_START_WORDS; ++i) {
                target_ulong a;
#if TARGET_LONG_BITS > TCG_TARGET_REG_BITS
                a = deposit64(op->args[i * 2], 32, 32, op->args[i * 2 + 1]);
#else
                a = op->args[i];
#endif
                col += qemu_log(" " TARGET_FMT_lx, a);
            }
        } else if (c == INDEX_op_call) {
            /* variable number of arguments */
            nb_oargs = TCGOP_CALLO(op);
            nb_iargs = TCGOP_CALLI(op);
            nb_cargs = def->nb_cargs;

            /* function name, flags, out args */
            col += qemu_log(" %s %s,$0x%" TCG_PRIlx ",$%d", def->name,
                            tcg_find_helper(s, op->args[nb_oargs + nb_iargs]),
                            op->args[nb_oargs + nb_iargs + 1], nb_oargs);
            for (i = 0; i < nb_oargs; i++) {
                col += qemu_log(",%s", tcg_get_arg_str(s, buf, sizeof(buf),
                                                       op->args[i]));
            }
            for (i = 0; i < nb_iargs; i++) {
                TCGArg arg = op->args[nb_oargs + i];
                const char *t = "<dummy>";
                if (arg != TCG_CALL_DUMMY_ARG) {
                    t = tcg_get_arg_str(s, buf, sizeof(buf), arg);
                }
                col += qemu_log(",%s", t);
            }
        } else {
            col += qemu_log(" %s ", def->name);

            nb_oargs = def->nb_oargs;
            nb_iargs = def->nb_iargs;
            nb_cargs = def->nb_cargs;

            if (def->flags & TCG_OPF_VECTOR) {
                col += qemu_log("v%d,e%d,", 64 << TCGOP_VECL(op),
                                8 << TCGOP_VECE(op));
            }

            k = 0;
            for (i = 0; i < nb_oargs; i++) {
                if (k != 0) {
                    col += qemu_log(",");
                }
                col += qemu_log("%s", tcg_get_arg_str(s, buf, sizeof(buf),
                                                      op->args[k++]));
            }
            for (i = 0; i < nb_iargs; i++) {
                if (k != 0) {
                    col += qemu_log(",");
                }
                col += qemu_log("%s", tcg_get_arg_str(s, buf, sizeof(buf),
                                                      op->args[k++]));
            }
            switch (c) {
            case INDEX_op_brcond_i32:
            case INDEX_op_setcond_i32:
            case INDEX_op_movcond_i32:
            case INDEX_op_brcond2_i32:
            case INDEX_op_setcond2_i32:
            case INDEX_op_brcond_i64:
            case INDEX_op_setcond_i64:
            case INDEX_op_movcond_i64:
            case INDEX_op_cmp_vec:
                if (op->args[k] < ARRAY_SIZE(cond_name)
                    && cond_name[op->args[k]]) {
                    col += qemu_log(",%s", cond_name[op->args[k++]]);
                } else {
                    col += qemu_log(",$0x%" TCG_PRIlx, op->args[k++]);
                }
                i = 1;
                break;
            case INDEX_op_qemu_ld_i32:
            case INDEX_op_qemu_st_i32:
            case INDEX_op_qemu_ld_i64:
            case INDEX_op_qemu_st_i64:
                {
                    TCGMemOpIdx oi = op->args[k++];
                    TCGMemOp op = get_memop(oi);
                    unsigned ix = get_mmuidx(oi);

                    if (op & ~(MO_AMASK | MO_BSWAP | MO_SSIZE)) {
                        col += qemu_log(",$0x%x,%u", op, ix);
                    } else {
                        const char *s_al, *s_op;
                        s_al = alignment_name[(op & MO_AMASK) >> MO_ASHIFT];
                        s_op = ldst_name[op & (MO_BSWAP | MO_SSIZE)];
                        col += qemu_log(",%s%s,%u", s_al, s_op, ix);
                    }
                    i = 1;
                }
                break;
            default:
                i = 0;
                break;
            }
            switch (c) {
            case INDEX_op_set_label:
            case INDEX_op_br:
            case INDEX_op_brcond_i32:
            case INDEX_op_brcond_i64:
            case INDEX_op_brcond2_i32:
                col += qemu_log("%s$L%d", k ? "," : "",
                                arg_label(op->args[k])->id);
                i++, k++;
                break;
            default:
                break;
            }
            for (; i < nb_cargs; i++, k++) {
                col += qemu_log("%s$0x%" TCG_PRIlx, k ? "," : "", op->args[k]);
            }
        }
        if (op->life) {
            unsigned life = op->life;

            for (; col < 48; ++col) {
                putc(' ', qemu_logfile);
            }

            if (life & (SYNC_ARG * 3)) {
                qemu_log("  sync:");
                for (i = 0; i < 2; ++i) {
                    if (life & (SYNC_ARG << i)) {
                        qemu_log(" %d", i);
                    }
                }
            }
            life /= DEAD_ARG;
            if (life) {
                qemu_log("  dead:");
                for (i = 0; life; ++i, life >>= 1) {
                    if (life & 1) {
                        qemu_log(" %d", i);
                    }
                }
            }
        }
        qemu_log("\n");
    }
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

void tcg_op_remove(TCGContext *s, TCGOp *op)
{
    QTAILQ_REMOVE(&s->ops, op, link);
    QTAILQ_INSERT_TAIL(&s->free_ops, op, link);

#ifdef CONFIG_PROFILER
    atomic_set(&s->prof.del_op_count, s->prof.del_op_count + 1);
#endif
}

static TCGOp *tcg_op_alloc(TCGOpcode opc)
{
    TCGContext *s = tcg_ctx;
    TCGOp *op;

    if (likely(QTAILQ_EMPTY(&s->free_ops))) {
        op = (TCGOp *)tcg_malloc(sizeof(TCGOp));
    } else {
        op = QTAILQ_FIRST(&s->free_ops);
        QTAILQ_REMOVE(&s->free_ops, op, link);
    }
    memset(op, 0, offsetof(TCGOp, link));
    op->opc = opc;

    return op;
}

TCGOp *tcg_emit_op(TCGOpcode opc)
{
    TCGOp *op = tcg_op_alloc(opc);
    QTAILQ_INSERT_TAIL(&tcg_ctx->ops, op, link);
    return op;
}

TCGOp *tcg_op_insert_before(TCGContext *s, TCGOp *old_op,
                            TCGOpcode opc, int nargs)
{
    TCGOp *new_op = tcg_op_alloc(opc);
    QTAILQ_INSERT_BEFORE(old_op, new_op, link);
    return new_op;
}

#define TS_DEAD  1

#define TS_MEM   2

#define IS_DEAD_ARG(n)   (arg_life & (DEAD_ARG << (n)))

#define NEED_SYNC_ARG(n) (arg_life & (SYNC_ARG << (n)))

TCGOp *tcg_op_insert_after(TCGContext *s, TCGOp *old_op,
                           TCGOpcode opc, int nargs)
{
    TCGOp *new_op = tcg_op_alloc(opc);
    QTAILQ_INSERT_AFTER(&s->ops, old_op, new_op, link);
    return new_op;
}

static void tcg_la_func_end(TCGContext *s)
{
    int ng = s->nb_globals;
    int nt = s->nb_temps;
    int i;

    for (i = 0; i < ng; ++i) {
        s->temps[i].state = TS_DEAD | TS_MEM;
    }
    for (i = ng; i < nt; ++i) {
        s->temps[i].state = TS_DEAD;
    }
}

static void tcg_la_bb_end(TCGContext *s)
{
    int ng = s->nb_globals;
    int nt = s->nb_temps;
    int i;

    for (i = 0; i < ng; ++i) {
        s->temps[i].state = TS_DEAD | TS_MEM;
    }
    for (i = ng; i < nt; ++i) {
        s->temps[i].state = (s->temps[i].temp_local
                             ? TS_DEAD | TS_MEM
                             : TS_DEAD);
    }
}

static void liveness_pass_1(TCGContext *s)
{
    int nb_globals = s->nb_globals;
    TCGOp *op, *op_prev;

    tcg_la_func_end(s);

#ifdef __cplusplus
    QTAILQ_FOREACH_REVERSE_SAFE(op, &s->ops, TCGContext::TCGOpHead, link, op_prev) {
#else
    QTAILQ_FOREACH_REVERSE_SAFE(op, &s->ops, TCGOpHead, link, op_prev) {
#endif
        int i, nb_iargs, nb_oargs;
        TCGOpcode opc_new, opc_new2;
        bool have_opc_new2;
        TCGLifeData arg_life = 0;
        TCGTemp *arg_ts;
        TCGOpcode opc = op->opc;
        const TCGOpDef *def = &tcg_op_defs[opc];

        switch (opc) {
        case INDEX_op_call:
            {
                int call_flags;

                nb_oargs = TCGOP_CALLO(op);
                nb_iargs = TCGOP_CALLI(op);
                call_flags = op->args[nb_oargs + nb_iargs + 1];

                /* pure functions can be removed if their result is unused */
                if (call_flags & TCG_CALL_NO_SIDE_EFFECTS) {
                    for (i = 0; i < nb_oargs; i++) {
                        arg_ts = arg_temp(op->args[i]);
                        if (arg_ts->state != TS_DEAD) {
                            goto do_not_remove_call;
                        }
                    }
                    goto do_remove;
                } else {
                do_not_remove_call:

                    /* output args are dead */
                    for (i = 0; i < nb_oargs; i++) {
                        arg_ts = arg_temp(op->args[i]);
                        if (arg_ts->state & TS_DEAD) {
                            arg_life |= DEAD_ARG << i;
                        }
                        if (arg_ts->state & TS_MEM) {
                            arg_life |= SYNC_ARG << i;
                        }
                        arg_ts->state = TS_DEAD;
                    }

                    if (!(call_flags & (TCG_CALL_NO_WRITE_GLOBALS |
                                        TCG_CALL_NO_READ_GLOBALS))) {
                        /* globals should go back to memory */
                        for (i = 0; i < nb_globals; i++) {
                            s->temps[i].state = TS_DEAD | TS_MEM;
                        }
                    } else if (!(call_flags & TCG_CALL_NO_READ_GLOBALS)) {
                        /* globals should be synced to memory */
                        for (i = 0; i < nb_globals; i++) {
                            s->temps[i].state |= TS_MEM;
                        }
                    }

                    /* record arguments that die in this helper */
                    for (i = nb_oargs; i < nb_iargs + nb_oargs; i++) {
                        arg_ts = arg_temp(op->args[i]);
                        if (arg_ts && arg_ts->state & TS_DEAD) {
                            arg_life |= DEAD_ARG << i;
                        }
                    }
                    /* input arguments are live for preceding opcodes */
                    for (i = nb_oargs; i < nb_iargs + nb_oargs; i++) {
                        arg_ts = arg_temp(op->args[i]);
                        if (arg_ts) {
                            arg_ts->state &= ~TS_DEAD;
                        }
                    }
                }
            }
            break;
        case INDEX_op_insn_start:
            break;
        case INDEX_op_discard:
            /* mark the temporary as dead */
            arg_temp(op->args[0])->state = TS_DEAD;
            break;

        case INDEX_op_add2_i32:
            opc_new = INDEX_op_add_i32;
            goto do_addsub2;
        case INDEX_op_sub2_i32:
            opc_new = INDEX_op_sub_i32;
            goto do_addsub2;
        case INDEX_op_add2_i64:
            opc_new = INDEX_op_add_i64;
            goto do_addsub2;
        case INDEX_op_sub2_i64:
            opc_new = INDEX_op_sub_i64;
        do_addsub2:
            nb_iargs = 4;
            nb_oargs = 2;
            /* Test if the high part of the operation is dead, but not
               the low part.  The result can be optimized to a simple
               add or sub.  This happens often for x86_64 guest when the
               cpu mode is set to 32 bit.  */
            if (arg_temp(op->args[1])->state == TS_DEAD) {
                if (arg_temp(op->args[0])->state == TS_DEAD) {
                    goto do_remove;
                }
                /* Replace the opcode and adjust the args in place,
                   leaving 3 unused args at the end.  */
                op->opc = opc = opc_new;
                op->args[1] = op->args[2];
                op->args[2] = op->args[4];
                /* Fall through and mark the single-word operation live.  */
                nb_iargs = 2;
                nb_oargs = 1;
            }
            goto do_not_remove;

        case INDEX_op_mulu2_i32:
            opc_new = INDEX_op_mul_i32;
            opc_new2 = INDEX_op_muluh_i32;
            have_opc_new2 = TCG_TARGET_HAS_muluh_i32;
            goto do_mul2;
        case INDEX_op_muls2_i32:
            opc_new = INDEX_op_mul_i32;
            opc_new2 = INDEX_op_mulsh_i32;
            have_opc_new2 = TCG_TARGET_HAS_mulsh_i32;
            goto do_mul2;
        case INDEX_op_mulu2_i64:
            opc_new = INDEX_op_mul_i64;
            opc_new2 = INDEX_op_muluh_i64;
            have_opc_new2 = TCG_TARGET_HAS_muluh_i64;
            goto do_mul2;
        case INDEX_op_muls2_i64:
            opc_new = INDEX_op_mul_i64;
            opc_new2 = INDEX_op_mulsh_i64;
            have_opc_new2 = TCG_TARGET_HAS_mulsh_i64;
            goto do_mul2;
        do_mul2:
            nb_iargs = 2;
            nb_oargs = 2;
            if (arg_temp(op->args[1])->state == TS_DEAD) {
                if (arg_temp(op->args[0])->state == TS_DEAD) {
                    /* Both parts of the operation are dead.  */
                    goto do_remove;
                }
                /* The high part of the operation is dead; generate the low. */
                op->opc = opc = opc_new;
                op->args[1] = op->args[2];
                op->args[2] = op->args[3];
            } else if (arg_temp(op->args[0])->state == TS_DEAD && have_opc_new2) {
                /* The low part of the operation is dead; generate the high. */
                op->opc = opc = opc_new2;
                op->args[0] = op->args[1];
                op->args[1] = op->args[2];
                op->args[2] = op->args[3];
            } else {
                goto do_not_remove;
            }
            /* Mark the single-word operation live.  */
            nb_oargs = 1;
            goto do_not_remove;

        default:
            /* XXX: optimize by hardcoding common cases (e.g. triadic ops) */
            nb_iargs = def->nb_iargs;
            nb_oargs = def->nb_oargs;

            /* Test if the operation can be removed because all
               its outputs are dead. We assume that nb_oargs == 0
               implies side effects */
            if (!(def->flags & TCG_OPF_SIDE_EFFECTS) && nb_oargs != 0) {
                for (i = 0; i < nb_oargs; i++) {
                    if (arg_temp(op->args[i])->state != TS_DEAD) {
                        goto do_not_remove;
                    }
                }
            do_remove:
                tcg_op_remove(s, op);
            } else {
            do_not_remove:
                /* output args are dead */
                for (i = 0; i < nb_oargs; i++) {
                    arg_ts = arg_temp(op->args[i]);
                    if (arg_ts->state & TS_DEAD) {
                        arg_life |= DEAD_ARG << i;
                    }
                    if (arg_ts->state & TS_MEM) {
                        arg_life |= SYNC_ARG << i;
                    }
                    arg_ts->state = TS_DEAD;
                }

                /* if end of basic block, update */
                if (def->flags & TCG_OPF_BB_END) {
                    tcg_la_bb_end(s);
                } else if (def->flags & TCG_OPF_SIDE_EFFECTS) {
                    /* globals should be synced to memory */
                    for (i = 0; i < nb_globals; i++) {
                        s->temps[i].state |= TS_MEM;
                    }
                }

                /* record arguments that die in this opcode */
                for (i = nb_oargs; i < nb_oargs + nb_iargs; i++) {
                    arg_ts = arg_temp(op->args[i]);
                    if (arg_ts->state & TS_DEAD) {
                        arg_life |= DEAD_ARG << i;
                    }
                }
                /* input arguments are live for preceding opcodes */
                for (i = nb_oargs; i < nb_oargs + nb_iargs; i++) {
                    arg_temp(op->args[i])->state &= ~TS_DEAD;
                }
            }
            break;
        }
        op->life = arg_life;
    }
}

static bool liveness_pass_2(TCGContext *s)
{
    int nb_globals = s->nb_globals;
    int nb_temps, i;
    bool changes = false;
    TCGOp *op, *op_next;

    /* Create a temporary for each indirect global.  */
    for (i = 0; i < nb_globals; ++i) {
        TCGTemp *its = &s->temps[i];
        if (its->indirect_reg) {
            TCGTemp *dts = tcg_temp_alloc(s);
            dts->type = its->type;
            dts->base_type = its->base_type;
            its->state_ptr = dts;
        } else {
            its->state_ptr = NULL;
        }
        /* All globals begin dead.  */
        its->state = TS_DEAD;
    }
    for (nb_temps = s->nb_temps; i < nb_temps; ++i) {
        TCGTemp *its = &s->temps[i];
        its->state_ptr = NULL;
        its->state = TS_DEAD;
    }

    QTAILQ_FOREACH_SAFE(op, &s->ops, link, op_next) {
        TCGOpcode opc = op->opc;
        const TCGOpDef *def = &tcg_op_defs[opc];
        TCGLifeData arg_life = op->life;
        int nb_iargs, nb_oargs, call_flags;
        TCGTemp *arg_ts, *dir_ts;

        if (opc == INDEX_op_call) {
            nb_oargs = TCGOP_CALLO(op);
            nb_iargs = TCGOP_CALLI(op);
            call_flags = op->args[nb_oargs + nb_iargs + 1];
        } else {
            nb_iargs = def->nb_iargs;
            nb_oargs = def->nb_oargs;

            /* Set flags similar to how calls require.  */
            if (def->flags & TCG_OPF_BB_END) {
                /* Like writing globals: save_globals */
                call_flags = 0;
            } else if (def->flags & TCG_OPF_SIDE_EFFECTS) {
                /* Like reading globals: sync_globals */
                call_flags = TCG_CALL_NO_WRITE_GLOBALS;
            } else {
                /* No effect on globals.  */
                call_flags = (TCG_CALL_NO_READ_GLOBALS |
                              TCG_CALL_NO_WRITE_GLOBALS);
            }
        }

        /* Make sure that input arguments are available.  */
        for (i = nb_oargs; i < nb_iargs + nb_oargs; i++) {
            arg_ts = arg_temp(op->args[i]);
            if (arg_ts) {
                dir_ts = (TCGTemp *)arg_ts->state_ptr;
                if (dir_ts && arg_ts->state == TS_DEAD) {
                    TCGOpcode lopc = (arg_ts->type == TCG_TYPE_I32
                                      ? INDEX_op_ld_i32
                                      : INDEX_op_ld_i64);
                    TCGOp *lop = tcg_op_insert_before(s, op, lopc, 3);

                    lop->args[0] = temp_arg(dir_ts);
                    lop->args[1] = temp_arg(arg_ts->mem_base);
                    lop->args[2] = arg_ts->mem_offset;

                    /* Loaded, but synced with memory.  */
                    arg_ts->state = TS_MEM;
                }
            }
        }

        /* Perform input replacement, and mark inputs that became dead.
           No action is required except keeping temp_state up to date
           so that we reload when needed.  */
        for (i = nb_oargs; i < nb_iargs + nb_oargs; i++) {
            arg_ts = arg_temp(op->args[i]);
            if (arg_ts) {
                dir_ts = (TCGTemp *)arg_ts->state_ptr;
                if (dir_ts) {
                    op->args[i] = temp_arg(dir_ts);
                    changes = true;
                    if (IS_DEAD_ARG(i)) {
                        arg_ts->state = TS_DEAD;
                    }
                }
            }
        }

        /* Liveness analysis should ensure that the following are
           all correct, for call sites and basic block end points.  */
        if (call_flags & TCG_CALL_NO_READ_GLOBALS) {
            /* Nothing to do */
        } else if (call_flags & TCG_CALL_NO_WRITE_GLOBALS) {
            for (i = 0; i < nb_globals; ++i) {
                /* Liveness should see that globals are synced back,
                   that is, either TS_DEAD or TS_MEM.  */
                arg_ts = &s->temps[i];
                tcg_debug_assert(arg_ts->state_ptr == 0
                                 || arg_ts->state != 0);
            }
        } else {
            for (i = 0; i < nb_globals; ++i) {
                /* Liveness should see that globals are saved back,
                   that is, TS_DEAD, waiting to be reloaded.  */
                arg_ts = &s->temps[i];
                tcg_debug_assert(arg_ts->state_ptr == 0
                                 || arg_ts->state == TS_DEAD);
            }
        }

        /* Outputs become available.  */
        for (i = 0; i < nb_oargs; i++) {
            arg_ts = arg_temp(op->args[i]);
            dir_ts = (TCGTemp *)arg_ts->state_ptr;
            if (!dir_ts) {
                continue;
            }
            op->args[i] = temp_arg(dir_ts);
            changes = true;

            /* The output is now live and modified.  */
            arg_ts->state = 0;

            /* Sync outputs upon their last write.  */
            if (NEED_SYNC_ARG(i)) {
                TCGOpcode sopc = (arg_ts->type == TCG_TYPE_I32
                                  ? INDEX_op_st_i32
                                  : INDEX_op_st_i64);
                TCGOp *sop = tcg_op_insert_after(s, op, sopc, 3);

                sop->args[0] = temp_arg(dir_ts);
                sop->args[1] = temp_arg(arg_ts->mem_base);
                sop->args[2] = arg_ts->mem_offset;

                arg_ts->state = TS_MEM;
            }
            /* Drop outputs that are dead.  */
            if (IS_DEAD_ARG(i)) {
                arg_ts->state = TS_DEAD;
            }
        }
    }

    return changes;
}

static void temp_allocate_frame(TCGContext *s, TCGTemp *ts)
{
#if !(defined(__sparc__) && TCG_TARGET_REG_BITS == 64)
    /* Sparc64 stack is accessed with offset of 2047 */
    s->current_frame_offset = (s->current_frame_offset +
                               (tcg_target_long)sizeof(tcg_target_long) - 1) &
        ~(sizeof(tcg_target_long) - 1);
#endif
    if (s->current_frame_offset + (tcg_target_long)sizeof(tcg_target_long) >
        s->frame_end) {
        tcg_abort();
    }
    ts->mem_offset = s->current_frame_offset;
    ts->mem_base = s->frame_temp;
    ts->mem_allocated = 1;
    s->current_frame_offset += sizeof(tcg_target_long);
}

static void temp_load(TCGContext *, TCGTemp *, TCGRegSet, TCGRegSet);

static void temp_free_or_dead(TCGContext *s, TCGTemp *ts, int free_or_dead)
{
    if (ts->fixed_reg) {
        return;
    }
    if (ts->val_type == TEMP_VAL_REG) {
        s->reg_to_temp[ts->reg] = NULL;
    }
    ts->val_type = (free_or_dead < 0
                    || ts->temp_local
                    || ts->temp_global
                    ? TEMP_VAL_MEM : TEMP_VAL_DEAD);
}

static inline void temp_dead(TCGContext *s, TCGTemp *ts)
{
    temp_free_or_dead(s, ts, 1);
}

static void temp_sync(TCGContext *s, TCGTemp *ts,
                      TCGRegSet allocated_regs, int free_or_dead)
{
    if (ts->fixed_reg) {
        return;
    }
    if (!ts->mem_coherent) {
        if (!ts->mem_allocated) {
            temp_allocate_frame(s, ts);
        }
        switch (ts->val_type) {
        case TEMP_VAL_CONST:
            /* If we're going to free the temp immediately, then we won't
               require it later in a register, so attempt to store the
               constant to memory directly.  */
            if (free_or_dead
                && tcg_out_sti(s, ts->type, ts->val,
                               ts->mem_base->reg, ts->mem_offset)) {
                break;
            }
            temp_load(s, ts, tcg_target_available_regs[ts->type],
                      allocated_regs);
            /* fallthrough */

        case TEMP_VAL_REG:
            tcg_out_st(s, ts->type, ts->reg,
                       ts->mem_base->reg, ts->mem_offset);
            break;

        case TEMP_VAL_MEM:
            break;

        case TEMP_VAL_DEAD:
        default:
            tcg_abort();
        }
        ts->mem_coherent = 1;
    }
    if (free_or_dead) {
        temp_free_or_dead(s, ts, free_or_dead);
    }
}

static void tcg_reg_free(TCGContext *s, TCGReg reg, TCGRegSet allocated_regs)
{
    TCGTemp *ts = s->reg_to_temp[reg];
    if (ts != NULL) {
        temp_sync(s, ts, allocated_regs, -1);
    }
}

static TCGReg tcg_reg_alloc(TCGContext *s, TCGRegSet desired_regs,
                            TCGRegSet allocated_regs, bool rev)
{
    int i, n = ARRAY_SIZE(tcg_target_reg_alloc_order);
    const int *order;
    TCGReg reg;
    TCGRegSet reg_ct;

    reg_ct = desired_regs & ~allocated_regs;
    order = rev ? indirect_reg_alloc_order : tcg_target_reg_alloc_order;

    /* first try free registers */
    for(i = 0; i < n; i++) {
        reg = (TCGReg)order[i];
        if (tcg_regset_test_reg(reg_ct, reg) && s->reg_to_temp[reg] == NULL)
            return reg;
    }

    /* XXX: do better spill choice */
    for(i = 0; i < n; i++) {
        reg = (TCGReg)order[i];
        if (tcg_regset_test_reg(reg_ct, reg)) {
            tcg_reg_free(s, reg, allocated_regs);
            return reg;
        }
    }

    tcg_abort();
}

static void temp_load(TCGContext *s, TCGTemp *ts, TCGRegSet desired_regs,
                      TCGRegSet allocated_regs)
{
    TCGReg reg;

    switch (ts->val_type) {
    case TEMP_VAL_REG:
        return;
    case TEMP_VAL_CONST:
        reg = tcg_reg_alloc(s, desired_regs, allocated_regs, ts->indirect_base);
        tcg_out_movi(s, ts->type, reg, ts->val);
        ts->mem_coherent = 0;
        break;
    case TEMP_VAL_MEM:
        reg = tcg_reg_alloc(s, desired_regs, allocated_regs, ts->indirect_base);
        tcg_out_ld(s, ts->type, reg, ts->mem_base->reg, ts->mem_offset);
        ts->mem_coherent = 1;
        break;
    case TEMP_VAL_DEAD:
    default:
        tcg_abort();
    }
    ts->reg = reg;
    ts->val_type = TEMP_VAL_REG;
    s->reg_to_temp[reg] = ts;
}

static void temp_save(TCGContext *s, TCGTemp *ts, TCGRegSet allocated_regs)
{
    /* The liveness analysis already ensures that globals are back
       in memory. Keep an tcg_debug_assert for safety. */
    tcg_debug_assert(ts->val_type == TEMP_VAL_MEM || ts->fixed_reg);
}

static void save_globals(TCGContext *s, TCGRegSet allocated_regs)
{
    int i, n;

    for (i = 0, n = s->nb_globals; i < n; i++) {
        temp_save(s, &s->temps[i], allocated_regs);
    }
}

static void sync_globals(TCGContext *s, TCGRegSet allocated_regs)
{
    int i, n;

    for (i = 0, n = s->nb_globals; i < n; i++) {
        TCGTemp *ts = &s->temps[i];
        tcg_debug_assert(ts->val_type != TEMP_VAL_REG
                         || ts->fixed_reg
                         || ts->mem_coherent);
    }
}

static void tcg_reg_alloc_bb_end(TCGContext *s, TCGRegSet allocated_regs)
{
    int i;

    for (i = s->nb_globals; i < s->nb_temps; i++) {
        TCGTemp *ts = &s->temps[i];
        if (ts->temp_local) {
            temp_save(s, ts, allocated_regs);
        } else {
            /* The liveness analysis already ensures that temps are dead.
               Keep an tcg_debug_assert for safety. */
            tcg_debug_assert(ts->val_type == TEMP_VAL_DEAD);
        }
    }

    save_globals(s, allocated_regs);
}

static void tcg_reg_alloc_do_movi(TCGContext *s, TCGTemp *ots,
                                  tcg_target_ulong val, TCGLifeData arg_life)
{
    if (ots->fixed_reg) {
        /* For fixed registers, we do not do any constant propagation.  */
        tcg_out_movi(s, ots->type, ots->reg, val);
        return;
    }

    /* The movi is not explicitly generated here.  */
    if (ots->val_type == TEMP_VAL_REG) {
        s->reg_to_temp[ots->reg] = NULL;
    }
    ots->val_type = TEMP_VAL_CONST;
    ots->val = val;
    ots->mem_coherent = 0;
    if (NEED_SYNC_ARG(0)) {
        temp_sync(s, ots, s->reserved_regs, IS_DEAD_ARG(0));
    } else if (IS_DEAD_ARG(0)) {
        temp_dead(s, ots);
    }
}

static void tcg_reg_alloc_movi(TCGContext *s, const TCGOp *op)
{
    TCGTemp *ots = arg_temp(op->args[0]);
    tcg_target_ulong val = op->args[1];

    tcg_reg_alloc_do_movi(s, ots, val, op->life);
}

static void tcg_reg_alloc_mov(TCGContext *s, const TCGOp *op)
{
    const TCGLifeData arg_life = op->life;
    TCGRegSet allocated_regs;
    TCGTemp *ts, *ots;
    TCGType otype, itype;

    allocated_regs = s->reserved_regs;
    ots = arg_temp(op->args[0]);
    ts = arg_temp(op->args[1]);

    /* Note that otype != itype for no-op truncation.  */
    otype = ots->type;
    itype = ts->type;

    if (ts->val_type == TEMP_VAL_CONST) {
        /* propagate constant or generate sti */
        tcg_target_ulong val = ts->val;
        if (IS_DEAD_ARG(1)) {
            temp_dead(s, ts);
        }
        tcg_reg_alloc_do_movi(s, ots, val, arg_life);
        return;
    }

    /* If the source value is in memory we're going to be forced
       to have it in a register in order to perform the copy.  Copy
       the SOURCE value into its own register first, that way we
       don't have to reload SOURCE the next time it is used. */
    if (ts->val_type == TEMP_VAL_MEM) {
        temp_load(s, ts, tcg_target_available_regs[itype], allocated_regs);
    }

    tcg_debug_assert(ts->val_type == TEMP_VAL_REG);
    if (IS_DEAD_ARG(0) && !ots->fixed_reg) {
        /* mov to a non-saved dead register makes no sense (even with
           liveness analysis disabled). */
        tcg_debug_assert(NEED_SYNC_ARG(0));
        if (!ots->mem_allocated) {
            temp_allocate_frame(s, ots);
        }
        tcg_out_st(s, otype, ts->reg, ots->mem_base->reg, ots->mem_offset);
        if (IS_DEAD_ARG(1)) {
            temp_dead(s, ts);
        }
        temp_dead(s, ots);
    } else {
        if (IS_DEAD_ARG(1) && !ts->fixed_reg && !ots->fixed_reg) {
            /* the mov can be suppressed */
            if (ots->val_type == TEMP_VAL_REG) {
                s->reg_to_temp[ots->reg] = NULL;
            }
            ots->reg = ts->reg;
            temp_dead(s, ts);
        } else {
            if (ots->val_type != TEMP_VAL_REG) {
                /* When allocating a new register, make sure to not spill the
                   input one. */
                tcg_regset_set_reg(allocated_regs, ts->reg);
                ots->reg = tcg_reg_alloc(s, tcg_target_available_regs[otype],
                                         allocated_regs, ots->indirect_base);
            }
            tcg_out_mov(s, otype, ots->reg, ts->reg);
        }
        ots->val_type = TEMP_VAL_REG;
        ots->mem_coherent = 0;
        s->reg_to_temp[ots->reg] = ots;
        if (NEED_SYNC_ARG(0)) {
            temp_sync(s, ots, allocated_regs, 0);
        }
    }
}

static void tcg_reg_alloc_op(TCGContext *s, const TCGOp *op)
{
    const TCGLifeData arg_life = op->life;
    const TCGOpDef * const def = &tcg_op_defs[op->opc];
    TCGRegSet i_allocated_regs;
    TCGRegSet o_allocated_regs;
    int i, k, nb_iargs, nb_oargs;
    TCGReg reg;
    TCGArg arg;
    const TCGArgConstraint *arg_ct;
    TCGTemp *ts;
    TCGArg new_args[TCG_MAX_OP_ARGS];
    int const_args[TCG_MAX_OP_ARGS];

    nb_oargs = def->nb_oargs;
    nb_iargs = def->nb_iargs;

    /* copy constants */
    memcpy(new_args + nb_oargs + nb_iargs, 
           op->args + nb_oargs + nb_iargs,
           sizeof(TCGArg) * def->nb_cargs);

    i_allocated_regs = s->reserved_regs;
    o_allocated_regs = s->reserved_regs;

    /* satisfy input constraints */ 
    for (k = 0; k < nb_iargs; k++) {
        i = def->sorted_args[nb_oargs + k];
        arg = op->args[i];
        arg_ct = &def->args_ct[i];
        ts = arg_temp(arg);

        if (ts->val_type == TEMP_VAL_CONST
            && tcg_target_const_match(ts->val, ts->type, arg_ct)) {
            /* constant is OK for instruction */
            const_args[i] = 1;
            new_args[i] = ts->val;
            goto iarg_end;
        }

        temp_load(s, ts, arg_ct->u.regs, i_allocated_regs);

        if (arg_ct->ct & TCG_CT_IALIAS) {
            if (ts->fixed_reg) {
                /* if fixed register, we must allocate a new register
                   if the alias is not the same register */
                if (arg != op->args[arg_ct->alias_index])
                    goto allocate_in_reg;
            } else {
                /* if the input is aliased to an output and if it is
                   not dead after the instruction, we must allocate
                   a new register and move it */
                if (!IS_DEAD_ARG(i)) {
                    goto allocate_in_reg;
                }
                /* check if the current register has already been allocated
                   for another input aliased to an output */
                int k2, i2;
                for (k2 = 0 ; k2 < k ; k2++) {
                    i2 = def->sorted_args[nb_oargs + k2];
                    if ((def->args_ct[i2].ct & TCG_CT_IALIAS) &&
                        (new_args[i2] == ts->reg)) {
                        goto allocate_in_reg;
                    }
                }
            }
        }
        reg = ts->reg;
        if (tcg_regset_test_reg(arg_ct->u.regs, reg)) {
            /* nothing to do : the constraint is satisfied */
        } else {
        allocate_in_reg:
            /* allocate a new register matching the constraint 
               and move the temporary register into it */
            reg = tcg_reg_alloc(s, arg_ct->u.regs, i_allocated_regs,
                                ts->indirect_base);
            tcg_out_mov(s, ts->type, reg, ts->reg);
        }
        new_args[i] = reg;
        const_args[i] = 0;
        tcg_regset_set_reg(i_allocated_regs, reg);
    iarg_end: ;
    }
    
    /* mark dead temporaries and free the associated registers */
    for (i = nb_oargs; i < nb_oargs + nb_iargs; i++) {
        if (IS_DEAD_ARG(i)) {
            temp_dead(s, arg_temp(op->args[i]));
        }
    }

    if (def->flags & TCG_OPF_BB_END) {
        tcg_reg_alloc_bb_end(s, i_allocated_regs);
    } else {
        if (def->flags & TCG_OPF_CALL_CLOBBER) {
            /* XXX: permit generic clobber register list ? */ 
            for (i = 0; i < TCG_TARGET_NB_REGS; i++) {
                if (tcg_regset_test_reg(tcg_target_call_clobber_regs, i)) {
                    tcg_reg_free(s, (TCGReg)i, i_allocated_regs);
                }
            }
        }
        if (def->flags & TCG_OPF_SIDE_EFFECTS) {
            /* sync globals if the op has side effects and might trigger
               an exception. */
            sync_globals(s, i_allocated_regs);
        }
        
        /* satisfy the output constraints */
        for(k = 0; k < nb_oargs; k++) {
            i = def->sorted_args[k];
            arg = op->args[i];
            arg_ct = &def->args_ct[i];
            ts = arg_temp(arg);
            if ((arg_ct->ct & TCG_CT_ALIAS)
                && !const_args[arg_ct->alias_index]) {
                reg = (TCGReg)new_args[arg_ct->alias_index];
            } else if (arg_ct->ct & TCG_CT_NEWREG) {
                reg = tcg_reg_alloc(s, arg_ct->u.regs,
                                    i_allocated_regs | o_allocated_regs,
                                    ts->indirect_base);
            } else {
                /* if fixed register, we try to use it */
                reg = ts->reg;
                if (ts->fixed_reg &&
                    tcg_regset_test_reg(arg_ct->u.regs, reg)) {
                    goto oarg_end;
                }
                reg = tcg_reg_alloc(s, arg_ct->u.regs, o_allocated_regs,
                                    ts->indirect_base);
            }
            tcg_regset_set_reg(o_allocated_regs, reg);
            /* if a fixed register is used, then a move will be done afterwards */
            if (!ts->fixed_reg) {
                if (ts->val_type == TEMP_VAL_REG) {
                    s->reg_to_temp[ts->reg] = NULL;
                }
                ts->val_type = TEMP_VAL_REG;
                ts->reg = reg;
                /* temp value is modified, so the value kept in memory is
                   potentially not the same */
                ts->mem_coherent = 0;
                s->reg_to_temp[reg] = ts;
            }
        oarg_end:
            new_args[i] = reg;
        }
    }

    /* emit instruction */
    if (def->flags & TCG_OPF_VECTOR) {
        tcg_out_vec_op(s, op->opc, TCGOP_VECL(op), TCGOP_VECE(op),
                       new_args, const_args);
    } else {
        tcg_out_op(s, op->opc, new_args, const_args);
    }

    /* move the outputs in the correct register if needed */
    for(i = 0; i < nb_oargs; i++) {
        ts = arg_temp(op->args[i]);
        reg = (TCGReg)new_args[i];
        if (ts->fixed_reg && ts->reg != reg) {
            tcg_out_mov(s, ts->type, ts->reg, reg);
        }
        if (NEED_SYNC_ARG(i)) {
            temp_sync(s, ts, o_allocated_regs, IS_DEAD_ARG(i));
        } else if (IS_DEAD_ARG(i)) {
            temp_dead(s, ts);
        }
    }
}

static void tcg_reg_alloc_call(TCGContext *s, TCGOp *op)
{
    const int nb_oargs = TCGOP_CALLO(op);
    const int nb_iargs = TCGOP_CALLI(op);
    const TCGLifeData arg_life = op->life;
    int flags, nb_regs, i;
    TCGReg reg;
    TCGArg arg;
    TCGTemp *ts;
    intptr_t stack_offset;
    size_t call_stack_size;
    tcg_insn_unit *func_addr;
    int allocate_args;
    TCGRegSet allocated_regs;

    func_addr = (tcg_insn_unit *)(intptr_t)op->args[nb_oargs + nb_iargs];
    flags = op->args[nb_oargs + nb_iargs + 1];

    nb_regs = ARRAY_SIZE(tcg_target_call_iarg_regs);
    if (nb_regs > nb_iargs) {
        nb_regs = nb_iargs;
    }

    /* assign stack slots first */
    call_stack_size = (nb_iargs - nb_regs) * sizeof(tcg_target_long);
    call_stack_size = (call_stack_size + TCG_TARGET_STACK_ALIGN - 1) & 
        ~(TCG_TARGET_STACK_ALIGN - 1);
    allocate_args = (call_stack_size > TCG_STATIC_CALL_ARGS_SIZE);
    if (allocate_args) {
        /* XXX: if more than TCG_STATIC_CALL_ARGS_SIZE is needed,
           preallocate call stack */
        tcg_abort();
    }

    stack_offset = TCG_TARGET_CALL_STACK_OFFSET;
    for (i = nb_regs; i < nb_iargs; i++) {
        arg = op->args[nb_oargs + i];
#ifdef TCG_TARGET_STACK_GROWSUP
        stack_offset -= sizeof(tcg_target_long);
#endif
        if (arg != TCG_CALL_DUMMY_ARG) {
            ts = arg_temp(arg);
            temp_load(s, ts, tcg_target_available_regs[ts->type],
                      s->reserved_regs);
            tcg_out_st(s, ts->type, ts->reg, TCG_REG_CALL_STACK, stack_offset);
        }
#ifndef TCG_TARGET_STACK_GROWSUP
        stack_offset += sizeof(tcg_target_long);
#endif
    }
    
    /* assign input registers */
    allocated_regs = s->reserved_regs;
    for (i = 0; i < nb_regs; i++) {
        arg = op->args[nb_oargs + i];
        if (arg != TCG_CALL_DUMMY_ARG) {
            ts = arg_temp(arg);
            reg = (TCGReg)tcg_target_call_iarg_regs[i];
            tcg_reg_free(s, (TCGReg)reg, allocated_regs);

            if (ts->val_type == TEMP_VAL_REG) {
                if (ts->reg != reg) {
                    tcg_out_mov(s, ts->type, reg, ts->reg);
                }
            } else {
                TCGRegSet arg_set = 0;

                tcg_regset_set_reg(arg_set, reg);
                temp_load(s, ts, arg_set, allocated_regs);
            }

            tcg_regset_set_reg(allocated_regs, reg);
        }
    }
    
    /* mark dead temporaries and free the associated registers */
    for (i = nb_oargs; i < nb_iargs + nb_oargs; i++) {
        if (IS_DEAD_ARG(i)) {
            temp_dead(s, arg_temp(op->args[i]));
        }
    }
    
    /* clobber call registers */
    for (i = 0; i < TCG_TARGET_NB_REGS; i++) {
        if (tcg_regset_test_reg(tcg_target_call_clobber_regs, i)) {
            tcg_reg_free(s, (TCGReg)i, allocated_regs);
        }
    }

    /* Save globals if they might be written by the helper, sync them if
       they might be read. */
    if (flags & TCG_CALL_NO_READ_GLOBALS) {
        /* Nothing to do */
    } else if (flags & TCG_CALL_NO_WRITE_GLOBALS) {
        sync_globals(s, allocated_regs);
    } else {
        save_globals(s, allocated_regs);
    }

    tcg_out_call(s, func_addr);

    /* assign output registers and emit moves if needed */
    for(i = 0; i < nb_oargs; i++) {
        arg = op->args[i];
        ts = arg_temp(arg);
        reg = (TCGReg)tcg_target_call_oarg_regs[i];
        tcg_debug_assert(s->reg_to_temp[reg] == NULL);

        if (ts->fixed_reg) {
            if (ts->reg != reg) {
                tcg_out_mov(s, ts->type, ts->reg, reg);
            }
        } else {
            if (ts->val_type == TEMP_VAL_REG) {
                s->reg_to_temp[ts->reg] = NULL;
            }
            ts->val_type = TEMP_VAL_REG;
            ts->reg = reg;
            ts->mem_coherent = 0;
            s->reg_to_temp[reg] = ts;
            if (NEED_SYNC_ARG(i)) {
                temp_sync(s, ts, allocated_regs, IS_DEAD_ARG(i));
            } else if (IS_DEAD_ARG(i)) {
                temp_dead(s, ts);
            }
        }
    }
}

int tcg_gen_code(TCGContext *s, TranslationBlock *tb)
{
#ifdef CONFIG_PROFILER
    TCGProfile *prof = &s->prof;
#endif
    int i, num_insns;
    TCGOp *op;

#ifdef CONFIG_PROFILER
    {
        int n;

        QTAILQ_FOREACH(op, &s->ops, link) {
            n++;
        }
        atomic_set(&prof->op_count, prof->op_count + n);
        if (n > prof->op_count_max) {
            atomic_set(&prof->op_count_max, n);
        }

        n = s->nb_temps;
        atomic_set(&prof->temp_count, prof->temp_count + n);
        if (n > prof->temp_count_max) {
            atomic_set(&prof->temp_count_max, n);
        }
    }
#endif

#ifdef DEBUG_DISAS
    if (unlikely(qemu_loglevel_mask(CPU_LOG_TB_OP)
                 && qemu_log_in_addr_range(tb->pc))) {
        qemu_log_lock();
        qemu_log("OP:\n");
        tcg_dump_ops(s);
        qemu_log("\n");
        qemu_log_unlock();
    }
#endif

#ifdef CONFIG_PROFILER
    atomic_set(&prof->opt_time, prof->opt_time - profile_getclock());
#endif

#ifdef USE_TCG_OPTIMIZATIONS
    tcg_optimize(s);
#endif

#ifdef CONFIG_PROFILER
    atomic_set(&prof->opt_time, prof->opt_time + profile_getclock());
    atomic_set(&prof->la_time, prof->la_time - profile_getclock());
#endif

    liveness_pass_1(s);

    if (s->nb_indirects > 0) {
#ifdef DEBUG_DISAS
        if (unlikely(qemu_loglevel_mask(CPU_LOG_TB_OP_IND)
                     && qemu_log_in_addr_range(tb->pc))) {
            qemu_log_lock();
            qemu_log("OP before indirect lowering:\n");
            tcg_dump_ops(s);
            qemu_log("\n");
            qemu_log_unlock();
        }
#endif
        /* Replace indirect temps with direct temps.  */
        if (liveness_pass_2(s)) {
            /* If changes were made, re-run liveness.  */
            liveness_pass_1(s);
        }
    }

#ifdef CONFIG_PROFILER
    atomic_set(&prof->la_time, prof->la_time + profile_getclock());
#endif

#ifdef DEBUG_DISAS
    if (unlikely(qemu_loglevel_mask(CPU_LOG_TB_OP_OPT)
                 && qemu_log_in_addr_range(tb->pc))) {
        qemu_log_lock();
        qemu_log("OP after optimization and liveness analysis:\n");
        tcg_dump_ops(s);
        qemu_log("\n");
        qemu_log_unlock();
    }
#endif

    tcg_reg_alloc_start(s);

    s->code_buf = (tcg_insn_unit *)tb->tc.ptr;
    s->code_ptr = (tcg_insn_unit *)tb->tc.ptr;

#ifdef TCG_TARGET_NEED_LDST_LABELS
    s->ldst_labels = NULL;
#endif
#ifdef TCG_TARGET_NEED_POOL_LABELS
    s->pool_labels = NULL;
#endif

    num_insns = -1;
    QTAILQ_FOREACH(op, &s->ops, link) {
        TCGOpcode opc = op->opc;

#ifdef CONFIG_PROFILER
        atomic_set(&prof->table_op_count[opc], prof->table_op_count[opc] + 1);
#endif

        switch (opc) {
        case INDEX_op_mov_i32:
        case INDEX_op_mov_i64:
        case INDEX_op_mov_vec:
            tcg_reg_alloc_mov(s, op);
            break;
        case INDEX_op_movi_i32:
        case INDEX_op_movi_i64:
        case INDEX_op_dupi_vec:
            tcg_reg_alloc_movi(s, op);
            break;
        case INDEX_op_insn_start:
            if (num_insns >= 0) {
                s->gen_insn_end_off[num_insns] = tcg_current_code_size(s);
            }
            num_insns++;
            for (i = 0; i < TARGET_INSN_START_WORDS; ++i) {
                target_ulong a;
#if TARGET_LONG_BITS > TCG_TARGET_REG_BITS
                a = deposit64(op->args[i * 2], 32, 32, op->args[i * 2 + 1]);
#else
                a = op->args[i];
#endif
                s->gen_insn_data[num_insns][i] = a;
            }
            break;
        case INDEX_op_discard:
            temp_dead(s, arg_temp(op->args[0]));
            break;
        case INDEX_op_set_label:
            tcg_reg_alloc_bb_end(s, s->reserved_regs);
            tcg_out_label(s, arg_label(op->args[0]), s->code_ptr);
            break;
        case INDEX_op_call:
            tcg_reg_alloc_call(s, op);
            break;
        default:
            /* Sanity check that we've not introduced any unhandled opcodes. */
            tcg_debug_assert(tcg_op_supported(opc));
            /* Note: in order to speed up the code, it would be much
               faster to have specialized register allocator functions for
               some common argument patterns */
            tcg_reg_alloc_op(s, op);
            break;
        }
#ifdef CONFIG_DEBUG_TCG
        check_regs(s);
#endif
        /* Test for (pending) buffer overflow.  The assumption is that any
           one operation beginning below the high water mark cannot overrun
           the buffer completely.  Thus we can test for overflow after
           generating code without having to check during generation.  */
        if (unlikely((void *)s->code_ptr > s->code_gen_highwater)) {
            return -1;
        }
    }
    tcg_debug_assert(num_insns >= 0);
    s->gen_insn_end_off[num_insns] = tcg_current_code_size(s);

    /* Generate TB finalization at the end of block */
#ifdef TCG_TARGET_NEED_LDST_LABELS
    if (!tcg_out_ldst_finalize(s)) {
        return -1;
    }
#endif
#ifdef TCG_TARGET_NEED_POOL_LABELS
    if (!tcg_out_pool_finalize(s)) {
        return -1;
    }
#endif

    /* flush instruction cache */
    flush_icache_range((uintptr_t)s->code_buf, (uintptr_t)s->code_ptr);

    return tcg_current_code_size(s);
}

#define CASE_OP_32_64(x)                        \
        glue(glue(case INDEX_op_, x), _i32):    \
        glue(glue(case INDEX_op_, x), _i64)

#define CASE_OP_32_64_VEC(x)                    \
        glue(glue(case INDEX_op_, x), _i32):    \
        glue(glue(case INDEX_op_, x), _i64):    \
        glue(glue(case INDEX_op_, x), _vec)

struct tcg_temp_info {
    bool is_const;
    TCGTemp *prev_copy;
    TCGTemp *next_copy;
    tcg_target_ulong val;
    tcg_target_ulong mask;
};

static inline struct tcg_temp_info *ts_info(TCGTemp *ts)
{
    return (struct tcg_temp_info *)ts->state_ptr;
}

static inline struct tcg_temp_info *arg_info(TCGArg arg)
{
    return ts_info(arg_temp(arg));
}

static inline bool ts_is_const(TCGTemp *ts)
{
    return ts_info(ts)->is_const;
}

static inline bool arg_is_const(TCGArg arg)
{
    return ts_is_const(arg_temp(arg));
}

static inline bool ts_is_copy(TCGTemp *ts)
{
    return ts_info(ts)->next_copy != ts;
}

static void reset_ts(TCGTemp *ts)
{
    struct tcg_temp_info *ti = ts_info(ts);
    struct tcg_temp_info *pi = ts_info(ti->prev_copy);
    struct tcg_temp_info *ni = ts_info(ti->next_copy);

    ni->prev_copy = ti->prev_copy;
    pi->next_copy = ti->next_copy;
    ti->next_copy = ts;
    ti->prev_copy = ts;
    ti->is_const = false;
    ti->mask = -1;
}

static void reset_temp(TCGArg arg)
{
    reset_ts(arg_temp(arg));
}

static void init_ts_info(struct tcg_temp_info *infos,
                         TCGTempSet *temps_used, TCGTemp *ts)
{
    size_t idx = temp_idx(ts);
    if (!test_bit(idx, temps_used->l)) {
        struct tcg_temp_info *ti = &infos[idx];

        ts->state_ptr = ti;
        ti->next_copy = ts;
        ti->prev_copy = ts;
        ti->is_const = false;
        ti->mask = -1;
        set_bit(idx, temps_used->l);
    }
}

static void init_arg_info(struct tcg_temp_info *infos,
                          TCGTempSet *temps_used, TCGArg arg)
{
    init_ts_info(infos, temps_used, arg_temp(arg));
}

static TCGTemp *find_better_copy(TCGContext *s, TCGTemp *ts)
{
    TCGTemp *i;

    /* If this is already a global, we can't do better. */
    if (ts->temp_global) {
        return ts;
    }

    /* Search for a global first. */
    for (i = ts_info(ts)->next_copy; i != ts; i = ts_info(i)->next_copy) {
        if (i->temp_global) {
            return i;
        }
    }

    /* If it is a temp, search for a temp local. */
    if (!ts->temp_local) {
        for (i = ts_info(ts)->next_copy; i != ts; i = ts_info(i)->next_copy) {
            if (ts->temp_local) {
                return i;
            }
        }
    }

    /* Failure to find a better representation, return the same temp. */
    return ts;
}

static bool ts_are_copies(TCGTemp *ts1, TCGTemp *ts2)
{
    TCGTemp *i;

    if (ts1 == ts2) {
        return true;
    }

    if (!ts_is_copy(ts1) || !ts_is_copy(ts2)) {
        return false;
    }

    for (i = ts_info(ts1)->next_copy; i != ts1; i = ts_info(i)->next_copy) {
        if (i == ts2) {
            return true;
        }
    }

    return false;
}

static bool args_are_copies(TCGArg arg1, TCGArg arg2)
{
    return ts_are_copies(arg_temp(arg1), arg_temp(arg2));
}

static void tcg_opt_gen_movi(TCGContext *s, TCGOp *op, TCGArg dst, TCGArg val)
{
    const TCGOpDef *def;
    TCGOpcode new_op;
    tcg_target_ulong mask;
    struct tcg_temp_info *di = arg_info(dst);

    def = &tcg_op_defs[op->opc];
    if (def->flags & TCG_OPF_VECTOR) {
        new_op = INDEX_op_dupi_vec;
    } else if (def->flags & TCG_OPF_64BIT) {
        new_op = INDEX_op_movi_i64;
    } else {
        new_op = INDEX_op_movi_i32;
    }
    op->opc = new_op;
    /* TCGOP_VECL and TCGOP_VECE remain unchanged.  */
    op->args[0] = dst;
    op->args[1] = val;

    reset_temp(dst);
    di->is_const = true;
    di->val = val;
    mask = val;
    if (TCG_TARGET_REG_BITS > 32 && new_op == INDEX_op_movi_i32) {
        /* High bits of the destination are now garbage.  */
        mask |= ~0xffffffffull;
    }
    di->mask = mask;
}

static void tcg_opt_gen_mov(TCGContext *s, TCGOp *op, TCGArg dst, TCGArg src)
{
    TCGTemp *dst_ts = arg_temp(dst);
    TCGTemp *src_ts = arg_temp(src);
    const TCGOpDef *def;
    struct tcg_temp_info *di;
    struct tcg_temp_info *si;
    tcg_target_ulong mask;
    TCGOpcode new_op;

    if (ts_are_copies(dst_ts, src_ts)) {
        tcg_op_remove(s, op);
        return;
    }

    reset_ts(dst_ts);
    di = ts_info(dst_ts);
    si = ts_info(src_ts);
    def = &tcg_op_defs[op->opc];
    if (def->flags & TCG_OPF_VECTOR) {
        new_op = INDEX_op_mov_vec;
    } else if (def->flags & TCG_OPF_64BIT) {
        new_op = INDEX_op_mov_i64;
    } else {
        new_op = INDEX_op_mov_i32;
    }
    op->opc = new_op;
    /* TCGOP_VECL and TCGOP_VECE remain unchanged.  */
    op->args[0] = dst;
    op->args[1] = src;

    mask = si->mask;
    if (TCG_TARGET_REG_BITS > 32 && new_op == INDEX_op_mov_i32) {
        /* High bits of the destination are now garbage.  */
        mask |= ~0xffffffffull;
    }
    di->mask = mask;

    if (src_ts->type == dst_ts->type) {
        struct tcg_temp_info *ni = ts_info(si->next_copy);

        di->next_copy = si->next_copy;
        di->prev_copy = src_ts;
        ni->prev_copy = dst_ts;
        si->next_copy = dst_ts;
        di->is_const = si->is_const;
        di->val = si->val;
    }
}

static TCGArg do_constant_folding_2(TCGOpcode op, TCGArg x, TCGArg y)
{
    uint64_t l64, h64;

    switch (op) {
    CASE_OP_32_64(add):
        return x + y;

    CASE_OP_32_64(sub):
        return x - y;

    CASE_OP_32_64(mul):
        return x * y;

    CASE_OP_32_64(and):
        return x & y;

    CASE_OP_32_64(or):
        return x | y;

    CASE_OP_32_64(xor):
        return x ^ y;

    case INDEX_op_shl_i32:
        return (uint32_t)x << (y & 31);

    case INDEX_op_shl_i64:
        return (uint64_t)x << (y & 63);

    case INDEX_op_shr_i32:
        return (uint32_t)x >> (y & 31);

    case INDEX_op_shr_i64:
        return (uint64_t)x >> (y & 63);

    case INDEX_op_sar_i32:
        return (int32_t)x >> (y & 31);

    case INDEX_op_sar_i64:
        return (int64_t)x >> (y & 63);

    case INDEX_op_rotr_i32:
        return ror32(x, y & 31);

    case INDEX_op_rotr_i64:
        return ror64(x, y & 63);

    case INDEX_op_rotl_i32:
        return rol32(x, y & 31);

    case INDEX_op_rotl_i64:
        return rol64(x, y & 63);

    CASE_OP_32_64(not):
        return ~x;

    CASE_OP_32_64(neg):
        return -x;

    CASE_OP_32_64(andc):
        return x & ~y;

    CASE_OP_32_64(orc):
        return x | ~y;

    CASE_OP_32_64(eqv):
        return ~(x ^ y);

    CASE_OP_32_64(nand):
        return ~(x & y);

    CASE_OP_32_64(nor):
        return ~(x | y);

    case INDEX_op_clz_i32:
        return (uint32_t)x ? clz32(x) : y;

    case INDEX_op_clz_i64:
        return x ? clz64(x) : y;

    case INDEX_op_ctz_i32:
        return (uint32_t)x ? ctz32(x) : y;

    case INDEX_op_ctz_i64:
        return x ? ctz64(x) : y;

    case INDEX_op_ctpop_i32:
        return ctpop32(x);

    case INDEX_op_ctpop_i64:
        return ctpop64(x);

    CASE_OP_32_64(ext8s):
        return (int8_t)x;

    CASE_OP_32_64(ext16s):
        return (int16_t)x;

    CASE_OP_32_64(ext8u):
        return (uint8_t)x;

    CASE_OP_32_64(ext16u):
        return (uint16_t)x;

    case INDEX_op_ext_i32_i64:
    case INDEX_op_ext32s_i64:
        return (int32_t)x;

    case INDEX_op_extu_i32_i64:
    case INDEX_op_extrl_i64_i32:
    case INDEX_op_ext32u_i64:
        return (uint32_t)x;

    case INDEX_op_extrh_i64_i32:
        return (uint64_t)x >> 32;

    case INDEX_op_muluh_i32:
        return ((uint64_t)(uint32_t)x * (uint32_t)y) >> 32;
    case INDEX_op_mulsh_i32:
        return ((int64_t)(int32_t)x * (int32_t)y) >> 32;

    case INDEX_op_muluh_i64:
        mulu64(&l64, &h64, x, y);
        return h64;
    case INDEX_op_mulsh_i64:
        muls64(&l64, &h64, x, y);
        return h64;

    case INDEX_op_div_i32:
        /* Avoid crashing on divide by zero, otherwise undefined.  */
        return (int32_t)x / ((int32_t)y ? : 1);
    case INDEX_op_divu_i32:
        return (uint32_t)x / ((uint32_t)y ? : 1);
    case INDEX_op_div_i64:
        return (int64_t)x / ((int64_t)y ? : 1);
    case INDEX_op_divu_i64:
        return (uint64_t)x / ((uint64_t)y ? : 1);

    case INDEX_op_rem_i32:
        return (int32_t)x % ((int32_t)y ? : 1);
    case INDEX_op_remu_i32:
        return (uint32_t)x % ((uint32_t)y ? : 1);
    case INDEX_op_rem_i64:
        return (int64_t)x % ((int64_t)y ? : 1);
    case INDEX_op_remu_i64:
        return (uint64_t)x % ((uint64_t)y ? : 1);

    default:
        fprintf(stderr,
                "Unrecognized operation %d in do_constant_folding.\n", op);
        tcg_abort();
    }
}

static TCGArg do_constant_folding(TCGOpcode op, TCGArg x, TCGArg y)
{
    const TCGOpDef *def = &tcg_op_defs[op];
    TCGArg res = do_constant_folding_2(op, x, y);
    if (!(def->flags & TCG_OPF_64BIT)) {
        res = (int32_t)res;
    }
    return res;
}

static bool do_constant_folding_cond_32(uint32_t x, uint32_t y, TCGCond c)
{
    switch (c) {
    case TCG_COND_EQ:
        return x == y;
    case TCG_COND_NE:
        return x != y;
    case TCG_COND_LT:
        return (int32_t)x < (int32_t)y;
    case TCG_COND_GE:
        return (int32_t)x >= (int32_t)y;
    case TCG_COND_LE:
        return (int32_t)x <= (int32_t)y;
    case TCG_COND_GT:
        return (int32_t)x > (int32_t)y;
    case TCG_COND_LTU:
        return x < y;
    case TCG_COND_GEU:
        return x >= y;
    case TCG_COND_LEU:
        return x <= y;
    case TCG_COND_GTU:
        return x > y;
    default:
        tcg_abort();
    }
}

static bool do_constant_folding_cond_64(uint64_t x, uint64_t y, TCGCond c)
{
    switch (c) {
    case TCG_COND_EQ:
        return x == y;
    case TCG_COND_NE:
        return x != y;
    case TCG_COND_LT:
        return (int64_t)x < (int64_t)y;
    case TCG_COND_GE:
        return (int64_t)x >= (int64_t)y;
    case TCG_COND_LE:
        return (int64_t)x <= (int64_t)y;
    case TCG_COND_GT:
        return (int64_t)x > (int64_t)y;
    case TCG_COND_LTU:
        return x < y;
    case TCG_COND_GEU:
        return x >= y;
    case TCG_COND_LEU:
        return x <= y;
    case TCG_COND_GTU:
        return x > y;
    default:
        tcg_abort();
    }
}

static bool do_constant_folding_cond_eq(TCGCond c)
{
    switch (c) {
    case TCG_COND_GT:
    case TCG_COND_LTU:
    case TCG_COND_LT:
    case TCG_COND_GTU:
    case TCG_COND_NE:
        return 0;
    case TCG_COND_GE:
    case TCG_COND_GEU:
    case TCG_COND_LE:
    case TCG_COND_LEU:
    case TCG_COND_EQ:
        return 1;
    default:
        tcg_abort();
    }
}

static TCGArg do_constant_folding_cond(TCGOpcode op, TCGArg x,
                                       TCGArg y, TCGCond c)
{
    tcg_target_ulong xv = arg_info(x)->val;
    tcg_target_ulong yv = arg_info(y)->val;
    if (arg_is_const(x) && arg_is_const(y)) {
        const TCGOpDef *def = &tcg_op_defs[op];
        tcg_debug_assert(!(def->flags & TCG_OPF_VECTOR));
        if (def->flags & TCG_OPF_64BIT) {
            return do_constant_folding_cond_64(xv, yv, c);
        } else {
            return do_constant_folding_cond_32(xv, yv, c);
        }
    } else if (args_are_copies(x, y)) {
        return do_constant_folding_cond_eq(c);
    } else if (arg_is_const(y) && yv == 0) {
        switch (c) {
        case TCG_COND_LTU:
            return 0;
        case TCG_COND_GEU:
            return 1;
        default:
            return 2;
        }
    }
    return 2;
}

static TCGArg do_constant_folding_cond2(TCGArg *p1, TCGArg *p2, TCGCond c)
{
    TCGArg al = p1[0], ah = p1[1];
    TCGArg bl = p2[0], bh = p2[1];

    if (arg_is_const(bl) && arg_is_const(bh)) {
        tcg_target_ulong blv = arg_info(bl)->val;
        tcg_target_ulong bhv = arg_info(bh)->val;
        uint64_t b = deposit64(blv, 32, 32, bhv);

        if (arg_is_const(al) && arg_is_const(ah)) {
            tcg_target_ulong alv = arg_info(al)->val;
            tcg_target_ulong ahv = arg_info(ah)->val;
            uint64_t a = deposit64(alv, 32, 32, ahv);
            return do_constant_folding_cond_64(a, b, c);
        }
        if (b == 0) {
            switch (c) {
            case TCG_COND_LTU:
                return 0;
            case TCG_COND_GEU:
                return 1;
            default:
                break;
            }
        }
    }
    if (args_are_copies(al, bl) && args_are_copies(ah, bh)) {
        return do_constant_folding_cond_eq(c);
    }
    return 2;
}

static bool swap_commutative(TCGArg dest, TCGArg *p1, TCGArg *p2)
{
    TCGArg a1 = *p1, a2 = *p2;
    int sum = 0;
    sum += arg_is_const(a1);
    sum -= arg_is_const(a2);

    /* Prefer the constant in second argument, and then the form
       op a, a, b, which is better handled on non-RISC hosts. */
    if (sum > 0 || (sum == 0 && dest == a2)) {
        *p1 = a2;
        *p2 = a1;
        return true;
    }
    return false;
}

static bool swap_commutative2(TCGArg *p1, TCGArg *p2)
{
    int sum = 0;
    sum += arg_is_const(p1[0]);
    sum += arg_is_const(p1[1]);
    sum -= arg_is_const(p2[0]);
    sum -= arg_is_const(p2[1]);
    if (sum > 0) {
        TCGArg t;
        t = p1[0], p1[0] = p2[0], p2[0] = t;
        t = p1[1], p1[1] = p2[1], p2[1] = t;
        return true;
    }
    return false;
}

void tcg_optimize(TCGContext *s)
{
    int nb_temps, nb_globals;
    TCGOp *op, *op_next, *prev_mb = NULL;
    struct tcg_temp_info *infos;
    TCGTempSet temps_used;

    /* Array VALS has an element for each temp.
       If this temp holds a constant then its value is kept in VALS' element.
       If this temp is a copy of other ones then the other copies are
       available through the doubly linked circular list. */

    nb_temps = s->nb_temps;
    nb_globals = s->nb_globals;
    bitmap_zero(temps_used.l, nb_temps);
    infos = (struct tcg_temp_info *)tcg_malloc(sizeof(struct tcg_temp_info) * nb_temps);

    QTAILQ_FOREACH_SAFE(op, &s->ops, link, op_next) {
        tcg_target_ulong mask, partmask, affected;
        int nb_oargs, nb_iargs, i;
        TCGArg tmp;
        TCGOpcode opc = op->opc;
        const TCGOpDef *def = &tcg_op_defs[opc];

        /* Count the arguments, and initialize the temps that are
           going to be used */
        if (opc == INDEX_op_call) {
            nb_oargs = TCGOP_CALLO(op);
            nb_iargs = TCGOP_CALLI(op);
            for (i = 0; i < nb_oargs + nb_iargs; i++) {
                TCGTemp *ts = arg_temp(op->args[i]);
                if (ts) {
                    init_ts_info(infos, &temps_used, ts);
                }
            }
        } else {
            nb_oargs = def->nb_oargs;
            nb_iargs = def->nb_iargs;
            for (i = 0; i < nb_oargs + nb_iargs; i++) {
                init_arg_info(infos, &temps_used, op->args[i]);
            }
        }

        /* Do copy propagation */
        for (i = nb_oargs; i < nb_oargs + nb_iargs; i++) {
            TCGTemp *ts = arg_temp(op->args[i]);
            if (ts && ts_is_copy(ts)) {
                op->args[i] = temp_arg(find_better_copy(s, ts));
            }
        }

        /* For commutative operations make constant second argument */
        switch (opc) {
        CASE_OP_32_64_VEC(add):
        CASE_OP_32_64_VEC(mul):
        CASE_OP_32_64_VEC(and):
        CASE_OP_32_64_VEC(or):
        CASE_OP_32_64_VEC(xor):
        CASE_OP_32_64(eqv):
        CASE_OP_32_64(nand):
        CASE_OP_32_64(nor):
        CASE_OP_32_64(muluh):
        CASE_OP_32_64(mulsh):
            swap_commutative(op->args[0], &op->args[1], &op->args[2]);
            break;
        CASE_OP_32_64(brcond):
            if (swap_commutative(-1, &op->args[0], &op->args[1])) {
                op->args[2] = tcg_swap_cond((TCGCond)op->args[2]);
            }
            break;
        CASE_OP_32_64(setcond):
            if (swap_commutative(op->args[0], &op->args[1], &op->args[2])) {
                op->args[3] = tcg_swap_cond((TCGCond)op->args[3]);
            }
            break;
        CASE_OP_32_64(movcond):
            if (swap_commutative(-1, &op->args[1], &op->args[2])) {
                op->args[5] = tcg_swap_cond((TCGCond)op->args[5]);
            }
            /* For movcond, we canonicalize the "false" input reg to match
               the destination reg so that the tcg backend can implement
               a "move if true" operation.  */
            if (swap_commutative(op->args[0], &op->args[4], &op->args[3])) {
                op->args[5] = tcg_invert_cond((TCGCond)op->args[5]);
            }
            break;
        CASE_OP_32_64(add2):
            swap_commutative(op->args[0], &op->args[2], &op->args[4]);
            swap_commutative(op->args[1], &op->args[3], &op->args[5]);
            break;
        CASE_OP_32_64(mulu2):
        CASE_OP_32_64(muls2):
            swap_commutative(op->args[0], &op->args[2], &op->args[3]);
            break;
        case INDEX_op_brcond2_i32:
            if (swap_commutative2(&op->args[0], &op->args[2])) {
                op->args[4] = tcg_swap_cond((TCGCond)op->args[4]);
            }
            break;
        case INDEX_op_setcond2_i32:
            if (swap_commutative2(&op->args[1], &op->args[3])) {
                op->args[5] = tcg_swap_cond((TCGCond)op->args[5]);
            }
            break;
        default:
            break;
        }

        /* Simplify expressions for "shift/rot r, 0, a => movi r, 0",
           and "sub r, 0, a => neg r, a" case.  */
        switch (opc) {
        CASE_OP_32_64(shl):
        CASE_OP_32_64(shr):
        CASE_OP_32_64(sar):
        CASE_OP_32_64(rotl):
        CASE_OP_32_64(rotr):
            if (arg_is_const(op->args[1])
                && arg_info(op->args[1])->val == 0) {
                tcg_opt_gen_movi(s, op, op->args[0], 0);
                continue;
            }
            break;
        CASE_OP_32_64_VEC(sub):
            {
                TCGOpcode neg_op;
                bool have_neg;

                if (arg_is_const(op->args[2])) {
                    /* Proceed with possible constant folding. */
                    break;
                }
                if (opc == INDEX_op_sub_i32) {
                    neg_op = INDEX_op_neg_i32;
                    have_neg = TCG_TARGET_HAS_neg_i32;
                } else if (opc == INDEX_op_sub_i64) {
                    neg_op = INDEX_op_neg_i64;
                    have_neg = TCG_TARGET_HAS_neg_i64;
                } else {
                    neg_op = INDEX_op_neg_vec;
                    have_neg = TCG_TARGET_HAS_neg_vec;
                }
                if (!have_neg) {
                    break;
                }
                if (arg_is_const(op->args[1])
                    && arg_info(op->args[1])->val == 0) {
                    op->opc = neg_op;
                    reset_temp(op->args[0]);
                    op->args[1] = op->args[2];
                    continue;
                }
            }
            break;
        CASE_OP_32_64_VEC(xor):
        CASE_OP_32_64(nand):
            if (!arg_is_const(op->args[1])
                && arg_is_const(op->args[2])
                && arg_info(op->args[2])->val == -1) {
                i = 1;
                goto try_not;
            }
            break;
        CASE_OP_32_64(nor):
            if (!arg_is_const(op->args[1])
                && arg_is_const(op->args[2])
                && arg_info(op->args[2])->val == 0) {
                i = 1;
                goto try_not;
            }
            break;
        CASE_OP_32_64_VEC(andc):
            if (!arg_is_const(op->args[2])
                && arg_is_const(op->args[1])
                && arg_info(op->args[1])->val == -1) {
                i = 2;
                goto try_not;
            }
            break;
        CASE_OP_32_64_VEC(orc):
        CASE_OP_32_64(eqv):
            if (!arg_is_const(op->args[2])
                && arg_is_const(op->args[1])
                && arg_info(op->args[1])->val == 0) {
                i = 2;
                goto try_not;
            }
            break;
        try_not:
            {
                TCGOpcode not_op;
                bool have_not;

                if (def->flags & TCG_OPF_VECTOR) {
                    not_op = INDEX_op_not_vec;
                    have_not = TCG_TARGET_HAS_not_vec;
                } else if (def->flags & TCG_OPF_64BIT) {
                    not_op = INDEX_op_not_i64;
                    have_not = TCG_TARGET_HAS_not_i64;
                } else {
                    not_op = INDEX_op_not_i32;
                    have_not = TCG_TARGET_HAS_not_i32;
                }
                if (!have_not) {
                    break;
                }
                op->opc = not_op;
                reset_temp(op->args[0]);
                op->args[1] = op->args[i];
                continue;
            }
        default:
            break;
        }

        /* Simplify expression for "op r, a, const => mov r, a" cases */
        switch (opc) {
        CASE_OP_32_64_VEC(add):
        CASE_OP_32_64_VEC(sub):
        CASE_OP_32_64_VEC(or):
        CASE_OP_32_64_VEC(xor):
        CASE_OP_32_64_VEC(andc):
        CASE_OP_32_64(shl):
        CASE_OP_32_64(shr):
        CASE_OP_32_64(sar):
        CASE_OP_32_64(rotl):
        CASE_OP_32_64(rotr):
            if (!arg_is_const(op->args[1])
                && arg_is_const(op->args[2])
                && arg_info(op->args[2])->val == 0) {
                tcg_opt_gen_mov(s, op, op->args[0], op->args[1]);
                continue;
            }
            break;
        CASE_OP_32_64_VEC(and):
        CASE_OP_32_64_VEC(orc):
        CASE_OP_32_64(eqv):
            if (!arg_is_const(op->args[1])
                && arg_is_const(op->args[2])
                && arg_info(op->args[2])->val == -1) {
                tcg_opt_gen_mov(s, op, op->args[0], op->args[1]);
                continue;
            }
            break;
        default:
            break;
        }

        /* Simplify using known-zero bits. Currently only ops with a single
           output argument is supported. */
        mask = -1;
        affected = -1;
        switch (opc) {
        CASE_OP_32_64(ext8s):
            if ((arg_info(op->args[1])->mask & 0x80) != 0) {
                break;
            }
        CASE_OP_32_64(ext8u):
            mask = 0xff;
            goto and_const;
        CASE_OP_32_64(ext16s):
            if ((arg_info(op->args[1])->mask & 0x8000) != 0) {
                break;
            }
        CASE_OP_32_64(ext16u):
            mask = 0xffff;
            goto and_const;
        case INDEX_op_ext32s_i64:
            if ((arg_info(op->args[1])->mask & 0x80000000) != 0) {
                break;
            }
        case INDEX_op_ext32u_i64:
            mask = 0xffffffffU;
            goto and_const;

        CASE_OP_32_64(and):
            mask = arg_info(op->args[2])->mask;
            if (arg_is_const(op->args[2])) {
        and_const:
                affected = arg_info(op->args[1])->mask & ~mask;
            }
            mask = arg_info(op->args[1])->mask & mask;
            break;

        case INDEX_op_ext_i32_i64:
            if ((arg_info(op->args[1])->mask & 0x80000000) != 0) {
                break;
            }
        case INDEX_op_extu_i32_i64:
            /* We do not compute affected as it is a size changing op.  */
            mask = (uint32_t)arg_info(op->args[1])->mask;
            break;

        CASE_OP_32_64(andc):
            /* Known-zeros does not imply known-ones.  Therefore unless
               op->args[2] is constant, we can't infer anything from it.  */
            if (arg_is_const(op->args[2])) {
                mask = ~arg_info(op->args[2])->mask;
                goto and_const;
            }
            /* But we certainly know nothing outside args[1] may be set. */
            mask = arg_info(op->args[1])->mask;
            break;

        case INDEX_op_sar_i32:
            if (arg_is_const(op->args[2])) {
                tmp = arg_info(op->args[2])->val & 31;
                mask = (int32_t)arg_info(op->args[1])->mask >> tmp;
            }
            break;
        case INDEX_op_sar_i64:
            if (arg_is_const(op->args[2])) {
                tmp = arg_info(op->args[2])->val & 63;
                mask = (int64_t)arg_info(op->args[1])->mask >> tmp;
            }
            break;

        case INDEX_op_shr_i32:
            if (arg_is_const(op->args[2])) {
                tmp = arg_info(op->args[2])->val & 31;
                mask = (uint32_t)arg_info(op->args[1])->mask >> tmp;
            }
            break;
        case INDEX_op_shr_i64:
            if (arg_is_const(op->args[2])) {
                tmp = arg_info(op->args[2])->val & 63;
                mask = (uint64_t)arg_info(op->args[1])->mask >> tmp;
            }
            break;

        case INDEX_op_extrl_i64_i32:
            mask = (uint32_t)arg_info(op->args[1])->mask;
            break;
        case INDEX_op_extrh_i64_i32:
            mask = (uint64_t)arg_info(op->args[1])->mask >> 32;
            break;

        CASE_OP_32_64(shl):
            if (arg_is_const(op->args[2])) {
                tmp = arg_info(op->args[2])->val & (TCG_TARGET_REG_BITS - 1);
                mask = arg_info(op->args[1])->mask << tmp;
            }
            break;

        CASE_OP_32_64(neg):
            /* Set to 1 all bits to the left of the rightmost.  */
            mask = -(arg_info(op->args[1])->mask
                     & -arg_info(op->args[1])->mask);
            break;

        CASE_OP_32_64(deposit):
            mask = deposit64(arg_info(op->args[1])->mask,
                             op->args[3], op->args[4],
                             arg_info(op->args[2])->mask);
            break;

        CASE_OP_32_64(extract):
            mask = extract64(arg_info(op->args[1])->mask,
                             op->args[2], op->args[3]);
            if (op->args[2] == 0) {
                affected = arg_info(op->args[1])->mask & ~mask;
            }
            break;
        CASE_OP_32_64(sextract):
            mask = sextract64(arg_info(op->args[1])->mask,
                              op->args[2], op->args[3]);
            if (op->args[2] == 0 && (tcg_target_long)mask >= 0) {
                affected = arg_info(op->args[1])->mask & ~mask;
            }
            break;

        CASE_OP_32_64(or):
        CASE_OP_32_64(xor):
            mask = arg_info(op->args[1])->mask | arg_info(op->args[2])->mask;
            break;

        case INDEX_op_clz_i32:
        case INDEX_op_ctz_i32:
            mask = arg_info(op->args[2])->mask | 31;
            break;

        case INDEX_op_clz_i64:
        case INDEX_op_ctz_i64:
            mask = arg_info(op->args[2])->mask | 63;
            break;

        case INDEX_op_ctpop_i32:
            mask = 32 | 31;
            break;
        case INDEX_op_ctpop_i64:
            mask = 64 | 63;
            break;

        CASE_OP_32_64(setcond):
        case INDEX_op_setcond2_i32:
            mask = 1;
            break;

        CASE_OP_32_64(movcond):
            mask = arg_info(op->args[3])->mask | arg_info(op->args[4])->mask;
            break;

        CASE_OP_32_64(ld8u):
            mask = 0xff;
            break;
        CASE_OP_32_64(ld16u):
            mask = 0xffff;
            break;
        case INDEX_op_ld32u_i64:
            mask = 0xffffffffu;
            break;

        CASE_OP_32_64(qemu_ld):
            {
                TCGMemOpIdx oi = op->args[nb_oargs + nb_iargs];
                TCGMemOp mop = get_memop(oi);
                if (!(mop & MO_SIGN)) {
                    mask = (2ULL << ((8 << (mop & MO_SIZE)) - 1)) - 1;
                }
            }
            break;

        default:
            break;
        }

        /* 32-bit ops generate 32-bit results.  For the result is zero test
           below, we can ignore high bits, but for further optimizations we
           need to record that the high bits contain garbage.  */
        partmask = mask;
        if (!(def->flags & TCG_OPF_64BIT)) {
            mask |= ~(tcg_target_ulong)0xffffffffu;
            partmask &= 0xffffffffu;
            affected &= 0xffffffffu;
        }

        if (partmask == 0) {
            tcg_debug_assert(nb_oargs == 1);
            tcg_opt_gen_movi(s, op, op->args[0], 0);
            continue;
        }
        if (affected == 0) {
            tcg_debug_assert(nb_oargs == 1);
            tcg_opt_gen_mov(s, op, op->args[0], op->args[1]);
            continue;
        }

        /* Simplify expression for "op r, a, 0 => movi r, 0" cases */
        switch (opc) {
        CASE_OP_32_64_VEC(and):
        CASE_OP_32_64_VEC(mul):
        CASE_OP_32_64(muluh):
        CASE_OP_32_64(mulsh):
            if (arg_is_const(op->args[2])
                && arg_info(op->args[2])->val == 0) {
                tcg_opt_gen_movi(s, op, op->args[0], 0);
                continue;
            }
            break;
        default:
            break;
        }

        /* Simplify expression for "op r, a, a => mov r, a" cases */
        switch (opc) {
        CASE_OP_32_64_VEC(or):
        CASE_OP_32_64_VEC(and):
            if (args_are_copies(op->args[1], op->args[2])) {
                tcg_opt_gen_mov(s, op, op->args[0], op->args[1]);
                continue;
            }
            break;
        default:
            break;
        }

        /* Simplify expression for "op r, a, a => movi r, 0" cases */
        switch (opc) {
        CASE_OP_32_64_VEC(andc):
        CASE_OP_32_64_VEC(sub):
        CASE_OP_32_64_VEC(xor):
            if (args_are_copies(op->args[1], op->args[2])) {
                tcg_opt_gen_movi(s, op, op->args[0], 0);
                continue;
            }
            break;
        default:
            break;
        }

        /* Propagate constants through copy operations and do constant
           folding.  Constants will be substituted to arguments by register
           allocator where needed and possible.  Also detect copies. */
        switch (opc) {
        CASE_OP_32_64_VEC(mov):
            tcg_opt_gen_mov(s, op, op->args[0], op->args[1]);
            break;
        CASE_OP_32_64(movi):
        case INDEX_op_dupi_vec:
            tcg_opt_gen_movi(s, op, op->args[0], op->args[1]);
            break;

        case INDEX_op_dup_vec:
            if (arg_is_const(op->args[1])) {
                tmp = arg_info(op->args[1])->val;
                tmp = dup_const(TCGOP_VECE(op), tmp);
                tcg_opt_gen_movi(s, op, op->args[0], tmp);
                continue;
            }
            break;

        CASE_OP_32_64(not):
        CASE_OP_32_64(neg):
        CASE_OP_32_64(ext8s):
        CASE_OP_32_64(ext8u):
        CASE_OP_32_64(ext16s):
        CASE_OP_32_64(ext16u):
        CASE_OP_32_64(ctpop):
        case INDEX_op_ext32s_i64:
        case INDEX_op_ext32u_i64:
        case INDEX_op_ext_i32_i64:
        case INDEX_op_extu_i32_i64:
        case INDEX_op_extrl_i64_i32:
        case INDEX_op_extrh_i64_i32:
            if (arg_is_const(op->args[1])) {
                tmp = do_constant_folding(opc, arg_info(op->args[1])->val, 0);
                tcg_opt_gen_movi(s, op, op->args[0], tmp);
                break;
            }
            goto do_default;

        CASE_OP_32_64(add):
        CASE_OP_32_64(sub):
        CASE_OP_32_64(mul):
        CASE_OP_32_64(or):
        CASE_OP_32_64(and):
        CASE_OP_32_64(xor):
        CASE_OP_32_64(shl):
        CASE_OP_32_64(shr):
        CASE_OP_32_64(sar):
        CASE_OP_32_64(rotl):
        CASE_OP_32_64(rotr):
        CASE_OP_32_64(andc):
        CASE_OP_32_64(orc):
        CASE_OP_32_64(eqv):
        CASE_OP_32_64(nand):
        CASE_OP_32_64(nor):
        CASE_OP_32_64(muluh):
        CASE_OP_32_64(mulsh):
        CASE_OP_32_64(div):
        CASE_OP_32_64(divu):
        CASE_OP_32_64(rem):
        CASE_OP_32_64(remu):
            if (arg_is_const(op->args[1]) && arg_is_const(op->args[2])) {
                tmp = do_constant_folding(opc, arg_info(op->args[1])->val,
                                          arg_info(op->args[2])->val);
                tcg_opt_gen_movi(s, op, op->args[0], tmp);
                break;
            }
            goto do_default;

        CASE_OP_32_64(clz):
        CASE_OP_32_64(ctz):
            if (arg_is_const(op->args[1])) {
                TCGArg v = arg_info(op->args[1])->val;
                if (v != 0) {
                    tmp = do_constant_folding(opc, v, 0);
                    tcg_opt_gen_movi(s, op, op->args[0], tmp);
                } else {
                    tcg_opt_gen_mov(s, op, op->args[0], op->args[2]);
                }
                break;
            }
            goto do_default;

        CASE_OP_32_64(deposit):
            if (arg_is_const(op->args[1]) && arg_is_const(op->args[2])) {
                tmp = deposit64(arg_info(op->args[1])->val,
                                op->args[3], op->args[4],
                                arg_info(op->args[2])->val);
                tcg_opt_gen_movi(s, op, op->args[0], tmp);
                break;
            }
            goto do_default;

        CASE_OP_32_64(extract):
            if (arg_is_const(op->args[1])) {
                tmp = extract64(arg_info(op->args[1])->val,
                                op->args[2], op->args[3]);
                tcg_opt_gen_movi(s, op, op->args[0], tmp);
                break;
            }
            goto do_default;

        CASE_OP_32_64(sextract):
            if (arg_is_const(op->args[1])) {
                tmp = sextract64(arg_info(op->args[1])->val,
                                 op->args[2], op->args[3]);
                tcg_opt_gen_movi(s, op, op->args[0], tmp);
                break;
            }
            goto do_default;

        CASE_OP_32_64(setcond):
            tmp = do_constant_folding_cond(opc, op->args[1],
                                           op->args[2], (TCGCond)op->args[3]);
            if (tmp != 2) {
                tcg_opt_gen_movi(s, op, op->args[0], tmp);
                break;
            }
            goto do_default;

        CASE_OP_32_64(brcond):
            tmp = do_constant_folding_cond(opc, op->args[0],
                                           op->args[1], (TCGCond)op->args[2]);
            if (tmp != 2) {
                if (tmp) {
                    bitmap_zero(temps_used.l, nb_temps);
                    op->opc = INDEX_op_br;
                    op->args[0] = op->args[3];
                } else {
                    tcg_op_remove(s, op);
                }
                break;
            }
            goto do_default;

        CASE_OP_32_64(movcond):
            tmp = do_constant_folding_cond(opc, op->args[1],
                                           op->args[2], (TCGCond)op->args[5]);
            if (tmp != 2) {
                tcg_opt_gen_mov(s, op, op->args[0], op->args[4-tmp]);
                break;
            }
            if (arg_is_const(op->args[3]) && arg_is_const(op->args[4])) {
                tcg_target_ulong tv = arg_info(op->args[3])->val;
                tcg_target_ulong fv = arg_info(op->args[4])->val;
                TCGCond cond = (TCGCond)op->args[5];
                if (fv == 1 && tv == 0) {
                    cond = tcg_invert_cond(cond);
                } else if (!(tv == 1 && fv == 0)) {
                    goto do_default;
                }
                op->args[3] = cond;
                op->opc = opc = (opc == INDEX_op_movcond_i32
                                 ? INDEX_op_setcond_i32
                                 : INDEX_op_setcond_i64);
                nb_iargs = 2;
            }
            goto do_default;

        case INDEX_op_add2_i32:
        case INDEX_op_sub2_i32:
            if (arg_is_const(op->args[2]) && arg_is_const(op->args[3])
                && arg_is_const(op->args[4]) && arg_is_const(op->args[5])) {
                uint32_t al = arg_info(op->args[2])->val;
                uint32_t ah = arg_info(op->args[3])->val;
                uint32_t bl = arg_info(op->args[4])->val;
                uint32_t bh = arg_info(op->args[5])->val;
                uint64_t a = ((uint64_t)ah << 32) | al;
                uint64_t b = ((uint64_t)bh << 32) | bl;
                TCGArg rl, rh;
                TCGOp *op2 = tcg_op_insert_before(s, op, INDEX_op_movi_i32, 2);

                if (opc == INDEX_op_add2_i32) {
                    a += b;
                } else {
                    a -= b;
                }

                rl = op->args[0];
                rh = op->args[1];
                tcg_opt_gen_movi(s, op, rl, (int32_t)a);
                tcg_opt_gen_movi(s, op2, rh, (int32_t)(a >> 32));
                break;
            }
            goto do_default;

        case INDEX_op_mulu2_i32:
            if (arg_is_const(op->args[2]) && arg_is_const(op->args[3])) {
                uint32_t a = arg_info(op->args[2])->val;
                uint32_t b = arg_info(op->args[3])->val;
                uint64_t r = (uint64_t)a * b;
                TCGArg rl, rh;
                TCGOp *op2 = tcg_op_insert_before(s, op, INDEX_op_movi_i32, 2);

                rl = op->args[0];
                rh = op->args[1];
                tcg_opt_gen_movi(s, op, rl, (int32_t)r);
                tcg_opt_gen_movi(s, op2, rh, (int32_t)(r >> 32));
                break;
            }
            goto do_default;

        case INDEX_op_brcond2_i32:
            tmp = do_constant_folding_cond2(&op->args[0], &op->args[2],
                                            (TCGCond)op->args[4]);
            if (tmp != 2) {
                if (tmp) {
            do_brcond_true:
                    bitmap_zero(temps_used.l, nb_temps);
                    op->opc = INDEX_op_br;
                    op->args[0] = op->args[5];
                } else {
            do_brcond_false:
                    tcg_op_remove(s, op);
                }
            } else if ((op->args[4] == TCG_COND_LT
                        || op->args[4] == TCG_COND_GE)
                       && arg_is_const(op->args[2])
                       && arg_info(op->args[2])->val == 0
                       && arg_is_const(op->args[3])
                       && arg_info(op->args[3])->val == 0) {
                /* Simplify LT/GE comparisons vs zero to a single compare
                   vs the high word of the input.  */
            do_brcond_high:
                bitmap_zero(temps_used.l, nb_temps);
                op->opc = INDEX_op_brcond_i32;
                op->args[0] = op->args[1];
                op->args[1] = op->args[3];
                op->args[2] = op->args[4];
                op->args[3] = op->args[5];
            } else if (op->args[4] == TCG_COND_EQ) {
                /* Simplify EQ comparisons where one of the pairs
                   can be simplified.  */
                tmp = do_constant_folding_cond(INDEX_op_brcond_i32,
                                               op->args[0], op->args[2],
                                               TCG_COND_EQ);
                if (tmp == 0) {
                    goto do_brcond_false;
                } else if (tmp == 1) {
                    goto do_brcond_high;
                }
                tmp = do_constant_folding_cond(INDEX_op_brcond_i32,
                                               op->args[1], op->args[3],
                                               TCG_COND_EQ);
                if (tmp == 0) {
                    goto do_brcond_false;
                } else if (tmp != 1) {
                    goto do_default;
                }
            do_brcond_low:
                bitmap_zero(temps_used.l, nb_temps);
                op->opc = INDEX_op_brcond_i32;
                op->args[1] = op->args[2];
                op->args[2] = op->args[4];
                op->args[3] = op->args[5];
            } else if (op->args[4] == TCG_COND_NE) {
                /* Simplify NE comparisons where one of the pairs
                   can be simplified.  */
                tmp = do_constant_folding_cond(INDEX_op_brcond_i32,
                                               op->args[0], op->args[2],
                                               TCG_COND_NE);
                if (tmp == 0) {
                    goto do_brcond_high;
                } else if (tmp == 1) {
                    goto do_brcond_true;
                }
                tmp = do_constant_folding_cond(INDEX_op_brcond_i32,
                                               op->args[1], op->args[3],
                                               TCG_COND_NE);
                if (tmp == 0) {
                    goto do_brcond_low;
                } else if (tmp == 1) {
                    goto do_brcond_true;
                }
                goto do_default;
            } else {
                goto do_default;
            }
            break;

        case INDEX_op_setcond2_i32:
            tmp = do_constant_folding_cond2(&op->args[1], &op->args[3],
                                            (TCGCond)op->args[5]);
            if (tmp != 2) {
            do_setcond_const:
                tcg_opt_gen_movi(s, op, op->args[0], tmp);
            } else if ((op->args[5] == TCG_COND_LT
                        || op->args[5] == TCG_COND_GE)
                       && arg_is_const(op->args[3])
                       && arg_info(op->args[3])->val == 0
                       && arg_is_const(op->args[4])
                       && arg_info(op->args[4])->val == 0) {
                /* Simplify LT/GE comparisons vs zero to a single compare
                   vs the high word of the input.  */
            do_setcond_high:
                reset_temp(op->args[0]);
                arg_info(op->args[0])->mask = 1;
                op->opc = INDEX_op_setcond_i32;
                op->args[1] = op->args[2];
                op->args[2] = op->args[4];
                op->args[3] = op->args[5];
            } else if (op->args[5] == TCG_COND_EQ) {
                /* Simplify EQ comparisons where one of the pairs
                   can be simplified.  */
                tmp = do_constant_folding_cond(INDEX_op_setcond_i32,
                                               op->args[1], op->args[3],
                                               TCG_COND_EQ);
                if (tmp == 0) {
                    goto do_setcond_const;
                } else if (tmp == 1) {
                    goto do_setcond_high;
                }
                tmp = do_constant_folding_cond(INDEX_op_setcond_i32,
                                               op->args[2], op->args[4],
                                               TCG_COND_EQ);
                if (tmp == 0) {
                    goto do_setcond_high;
                } else if (tmp != 1) {
                    goto do_default;
                }
            do_setcond_low:
                reset_temp(op->args[0]);
                arg_info(op->args[0])->mask = 1;
                op->opc = INDEX_op_setcond_i32;
                op->args[2] = op->args[3];
                op->args[3] = op->args[5];
            } else if (op->args[5] == TCG_COND_NE) {
                /* Simplify NE comparisons where one of the pairs
                   can be simplified.  */
                tmp = do_constant_folding_cond(INDEX_op_setcond_i32,
                                               op->args[1], op->args[3],
                                               TCG_COND_NE);
                if (tmp == 0) {
                    goto do_setcond_high;
                } else if (tmp == 1) {
                    goto do_setcond_const;
                }
                tmp = do_constant_folding_cond(INDEX_op_setcond_i32,
                                               op->args[2], op->args[4],
                                               TCG_COND_NE);
                if (tmp == 0) {
                    goto do_setcond_low;
                } else if (tmp == 1) {
                    goto do_setcond_const;
                }
                goto do_default;
            } else {
                goto do_default;
            }
            break;

        case INDEX_op_call:
            if (!(op->args[nb_oargs + nb_iargs + 1]
                  & (TCG_CALL_NO_READ_GLOBALS | TCG_CALL_NO_WRITE_GLOBALS))) {
                for (i = 0; i < nb_globals; i++) {
                    if (test_bit(i, temps_used.l)) {
                        reset_ts(&s->temps[i]);
                    }
                }
            }
            goto do_reset_output;

        default:
        do_default:
            /* Default case: we know nothing about operation (or were unable
               to compute the operation result) so no propagation is done.
               We trash everything if the operation is the end of a basic
               block, otherwise we only trash the output args.  "mask" is
               the non-zero bits mask for the first output arg.  */
            if (def->flags & TCG_OPF_BB_END) {
                bitmap_zero(temps_used.l, nb_temps);
            } else {
        do_reset_output:
                for (i = 0; i < nb_oargs; i++) {
                    reset_temp(op->args[i]);
                    /* Save the corresponding known-zero bits mask for the
                       first output argument (only one supported so far). */
                    if (i == 0) {
                        arg_info(op->args[i])->mask = mask;
                    }
                }
            }
            break;
        }

        /* Eliminate duplicate and redundant fence instructions.  */
        if (prev_mb) {
            switch (opc) {
            case INDEX_op_mb:
                /* Merge two barriers of the same type into one,
                 * or a weaker barrier into a stronger one,
                 * or two weaker barriers into a stronger one.
                 *   mb X; mb Y => mb X|Y
                 *   mb; strl => mb; st
                 *   ldaq; mb => ld; mb
                 *   ldaq; strl => ld; mb; st
                 * Other combinations are also merged into a strong
                 * barrier.  This is stricter than specified but for
                 * the purposes of TCG is better than not optimizing.
                 */
                prev_mb->args[0] |= op->args[0];
                tcg_op_remove(s, op);
                break;

            default:
                /* Opcodes that end the block stop the optimization.  */
                if ((def->flags & TCG_OPF_BB_END) == 0) {
                    break;
                }
                /* fallthru */
            case INDEX_op_qemu_ld_i32:
            case INDEX_op_qemu_ld_i64:
            case INDEX_op_qemu_st_i32:
            case INDEX_op_qemu_st_i64:
            case INDEX_op_call:
                /* Opcodes that touch guest memory stop the optimization.  */
                prev_mb = NULL;
                break;
            }
        } else if (opc == INDEX_op_mb) {
            prev_mb = op;
        }
    }
}

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

void tcg_gen_andi_i32(TCGv_i32 ret, TCGv_i32 arg1, int32_t arg2)
{
    TCGv_i32 t0;
    /* Some cases can be optimized here.  */
    switch (arg2) {
    case 0:
        tcg_gen_movi_i32(ret, 0);
        return;
    case -1:
        tcg_gen_mov_i32(ret, arg1);
        return;
    case 0xff:
        /* Don't recurse with tcg_gen_ext8u_i32.  */
        if (TCG_TARGET_HAS_ext8u_i32) {
            tcg_gen_op2_i32(INDEX_op_ext8u_i32, ret, arg1);
            return;
        }
        break;
    case 0xffff:
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

void tcg_gen_shli_i32(TCGv_i32 ret, TCGv_i32 arg1, int32_t arg2)
{
    tcg_debug_assert(arg2 >= 0 && arg2 < 32);
    if (arg2 == 0) {
        tcg_gen_mov_i32(ret, arg1);
    } else {
        TCGv_i32 t0 = tcg_const_i32(arg2);
        tcg_gen_shl_i32(ret, arg1, t0);
        tcg_temp_free_i32(t0);
    }
}

void tcg_gen_shri_i32(TCGv_i32 ret, TCGv_i32 arg1, int32_t arg2)
{
    tcg_debug_assert(arg2 >= 0 && arg2 < 32);
    if (arg2 == 0) {
        tcg_gen_mov_i32(ret, arg1);
    } else {
        TCGv_i32 t0 = tcg_const_i32(arg2);
        tcg_gen_shr_i32(ret, arg1, t0);
        tcg_temp_free_i32(t0);
    }
}

void tcg_gen_sari_i32(TCGv_i32 ret, TCGv_i32 arg1, int32_t arg2)
{
    tcg_debug_assert(arg2 >= 0 && arg2 < 32);
    if (arg2 == 0) {
        tcg_gen_mov_i32(ret, arg1);
    } else {
        TCGv_i32 t0 = tcg_const_i32(arg2);
        tcg_gen_sar_i32(ret, arg1, t0);
        tcg_temp_free_i32(t0);
    }
}

void tcg_gen_brcond_i32(TCGCond cond, TCGv_i32 arg1, TCGv_i32 arg2, TCGLabel *l)
{
    if (cond == TCG_COND_ALWAYS) {
        tcg_gen_br(l);
    } else if (cond != TCG_COND_NEVER) {
        tcg_gen_op4ii_i32(INDEX_op_brcond_i32, arg1, arg2, cond, label_arg(l));
    }
}

void tcg_gen_brcondi_i32(TCGCond cond, TCGv_i32 arg1, int32_t arg2, TCGLabel *l)
{
    if (cond == TCG_COND_ALWAYS) {
        tcg_gen_br(l);
    } else if (cond != TCG_COND_NEVER) {
        TCGv_i32 t0 = tcg_const_i32(arg2);
        tcg_gen_brcond_i32(cond, arg1, t0, l);
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

void tcg_gen_andi_i64(TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2)
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
    case -1:
        tcg_gen_mov_i64(ret, arg1);
        return;
    case 0xff:
        /* Don't recurse with tcg_gen_ext8u_i64.  */
        if (TCG_TARGET_HAS_ext8u_i64) {
            tcg_gen_op2_i64(INDEX_op_ext8u_i64, ret, arg1);
            return;
        }
        break;
    case 0xffff:
        if (TCG_TARGET_HAS_ext16u_i64) {
            tcg_gen_op2_i64(INDEX_op_ext16u_i64, ret, arg1);
            return;
        }
        break;
    case 0xffffffffu:
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

void tcg_gen_shli_i64(TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2)
{
    tcg_debug_assert(arg2 >= 0 && arg2 < 64);
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

void tcg_gen_shri_i64(TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2)
{
    tcg_debug_assert(arg2 >= 0 && arg2 < 64);
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

void tcg_gen_sari_i64(TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2)
{
    tcg_debug_assert(arg2 >= 0 && arg2 < 64);
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
    if (arg2 == 0) {
        tcg_gen_movi_i64(ret, 0);
    } else if (is_power_of_2(arg2)) {
        tcg_gen_shli_i64(ret, arg1, ctz64(arg2));
    } else {
        TCGv_i64 t0 = tcg_const_i64(arg2);
        tcg_gen_mul_i64(ret, arg1, t0);
        tcg_temp_free_i64(t0);
    }
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

//#define g2h(x) ((void *)((unsigned long)(target_ulong)(x) + guest_base))

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

static TCGOp *icount_start_insn;

static inline void gen_tb_start(TranslationBlock *tb)
{
#if 0
    TCGv_i32 count, imm;

    tcg_ctx->exitreq_label = gen_new_label();
    if (tb_cflags(tb) & CF_USE_ICOUNT) {
        count = tcg_temp_local_new_i32();
    } else {
        count = tcg_temp_new_i32();
    }

    tcg_gen_ld_i32(count, cpu_env,
                   -ENV_OFFSET + offsetof(CPUState, icount_decr.u32));

    if (tb_cflags(tb) & CF_USE_ICOUNT) {
        imm = tcg_temp_new_i32();
        /* We emit a movi with a dummy immediate argument. Keep the insn index
         * of the movi so that we later (when we know the actual insn count)
         * can update the immediate argument with the actual insn count.  */
        tcg_gen_movi_i32(imm, 0xdeadbeef);
        icount_start_insn = tcg_last_op();

        tcg_gen_sub_i32(count, count, imm);
        tcg_temp_free_i32(imm);
    }

    tcg_gen_brcondi_i32(TCG_COND_LT, count, 0, tcg_ctx->exitreq_label);

    if (tb_cflags(tb) & CF_USE_ICOUNT) {
        tcg_gen_st16_i32(count, cpu_env,
                         -ENV_OFFSET + offsetof(CPUState, icount_decr.u16.low));
    }

    tcg_temp_free_i32(count);
#endif
}

static inline void gen_tb_end(TranslationBlock *tb, int num_insns)
{
#if 0
    if (tb_cflags(tb) & CF_USE_ICOUNT) {
        /* Update the num_insn immediate parameter now that we know
         * the actual insn count.  */
        tcg_set_insn_param(icount_start_insn, 1, num_insns);
    }

    gen_set_label(tcg_ctx->exitreq_label);
    tcg_gen_exit_tb((uintptr_t)tb + TB_EXIT_REQUESTED);
#endif
}

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

    zero = NULL;
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
            TCGv t0 = gen_ext_tl(reg, cpu_cc_dst, (TCGMemOp)size, true);
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
    TCGv ea = NULL;

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
    if (!ea) {
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
                tcg_gen_andc_tl(cpu_T0, cpu_T0, cpu_regs[s->vex_v]);
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
                    carry_in = NULL;
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
                    if (!carry_in) {
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
    s->override = -1;
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

    prefixes = 0;
    rex_w = -1;
    rex_r = 0;

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
                /* 2-byte VEX prefix: RVVVVlpp, implied 0f leading opcode byte */
                vex3 = vex2;
                b = x86_ldub_code(env, s) | 0x100;
            } else {
                /* 3-byte VEX prefix: RXBmmmmm wVVVVlpp */
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

        s->base.tb->jove.T.Type = jove::TERMINATOR::RETURN;
        break;
    case 0xc3: /* ret */
        ot = gen_pop_T0(s);
        gen_pop_update(s, ot);
        /* Note that gen_pop_T0 uses a zero-extending load.  */
        gen_op_jmp_v(cpu_T0);
        gen_bnd_jmp(s);
        gen_jr(s, cpu_T0);

        s->base.tb->jove.T.Type = jove::TERMINATOR::RETURN;
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

            s->base.tb->jove.T.Type = jove::TERMINATOR::RETURN;
            s->base.tb->jove.T._call.Target = tval;
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

        s->base.tb->jove.T.Type = jove::TERMINATOR::UNCONDITIONAL_JUMP;
        s->base.tb->jove.T._unconditional_jump.Target = tval;
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

        s->base.tb->jove.T.Type = jove::TERMINATOR::UNCONDITIONAL_JUMP;
        s->base.tb->jove.T._unconditional_jump.Target = tval;
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

        s->base.tb->jove.T.Type = jove::TERMINATOR::CONDITIONAL_JUMP;
        s->base.tb->jove.T._conditional_jump.Target = tval;
        s->base.tb->jove.T._conditional_jump.NextPC = next_eip;
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
                a0 = NULL;
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

void tcg_x86_init(void)
{
    static const char reg_names[CPU_NB_REGS][4] = {
#ifdef TARGET_X86_64
        [R_EAX] = "rax",
        [R_EBX] = "rbx",
        [R_ECX] = "rcx",
        [R_EDX] = "rdx",
        [R_ESI] = "rsi",
        [R_EDI] = "rdi",
        [R_EBP] = "rbp",
        [R_ESP] = "rsp",
        [8]  = "r8",
        [9]  = "r9",
        [10] = "r10",
        [11] = "r11",
        [12] = "r12",
        [13] = "r13",
        [14] = "r14",
        [15] = "r15",
#else
        [R_EAX] = "eax",
        [R_EBX] = "ebx",
        [R_ECX] = "ecx",
        [R_EDX] = "edx",
        [R_ESI] = "esi",
        [R_EDI] = "edi",
        [R_EBP] = "ebp",
        [R_ESP] = "esp",
#endif
    };
    static const char seg_base_names[6][8] = {
        [R_CS] = "cs_base",
        [R_DS] = "ds_base",
        [R_ES] = "es_base",
        [R_FS] = "fs_base",
        [R_GS] = "gs_base",
        [R_SS] = "ss_base",
    };
    static const char bnd_regl_names[4][8] = {
        "bnd0_lb", "bnd1_lb", "bnd2_lb", "bnd3_lb"
    };
    static const char bnd_regu_names[4][8] = {
        "bnd0_ub", "bnd1_ub", "bnd2_ub", "bnd3_ub"
    };
    int i;

    cpu_cc_op = tcg_global_mem_new_i32(cpu_env,
                                       offsetof(CPUX86State, cc_op), "cc_op");
    cpu_cc_dst = tcg_global_mem_new(cpu_env, offsetof(CPUX86State, cc_dst),
                                    "cc_dst");
    cpu_cc_src = tcg_global_mem_new(cpu_env, offsetof(CPUX86State, cc_src),
                                    "cc_src");
    cpu_cc_src2 = tcg_global_mem_new(cpu_env, offsetof(CPUX86State, cc_src2),
                                     "cc_src2");

    for (i = 0; i < CPU_NB_REGS; ++i) {
        cpu_regs[i] = tcg_global_mem_new(cpu_env,
                                         offsetof(CPUX86State, regs[i]),
                                         reg_names[i]);
    }

    for (i = 0; i < 6; ++i) {
        cpu_seg_base[i]
            = tcg_global_mem_new(cpu_env,
                                 offsetof(CPUX86State, segs[i].base),
                                 seg_base_names[i]);
    }

    for (i = 0; i < 4; ++i) {
        cpu_bndl[i]
            = tcg_global_mem_new_i64(cpu_env,
                                     offsetof(CPUX86State, bnd_regs[i].lb),
                                     bnd_regl_names[i]);
        cpu_bndu[i]
            = tcg_global_mem_new_i64(cpu_env,
                                     offsetof(CPUX86State, bnd_regs[i].ub),
                                     bnd_regu_names[i]);
    }
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

TCGOpDef tcg_op_defs[] = {
#define DEF(s, oargs, iargs, cargs, flags) \
         { #s, oargs, iargs, cargs, iargs + oargs + cargs, flags },
/* XXX jove */
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

#define IMPL(X) (__builtin_constant_p(X) && !(X) ? TCG_OPF_NOT_PRESENT : 0)
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
DEF(exit_tb, 0, 0, 1, TCG_OPF_BB_END)
DEF(goto_tb, 0, 0, 1, TCG_OPF_BB_END)
DEF(goto_ptr, 0, 1, 0, TCG_OPF_BB_END | IMPL(TCG_TARGET_HAS_goto_ptr))

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

DEF(add_vec, 1, 2, 0, IMPLVEC)
DEF(sub_vec, 1, 2, 0, IMPLVEC)
DEF(mul_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_mul_vec))
DEF(neg_vec, 1, 1, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_neg_vec))

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

DEF(last_generic, 0, 0, 0, TCG_OPF_NOT_PRESENT)

#if TCG_TARGET_MAYBE_vec
/* Target-specific opcodes for host vector expansion.  These will be
   emitted by tcg_expand_vec_op.  For those familiar with GCC internals,
   consider these to be UNSPEC with names.  */

DEF(x86_shufps_vec, 1, 2, 1, IMPLVEC)
DEF(x86_vpblendvb_vec, 1, 3, 0, IMPLVEC)
DEF(x86_blend_vec, 1, 2, 1, IMPLVEC)
DEF(x86_packss_vec, 1, 2, 0, IMPLVEC)
DEF(x86_packus_vec, 1, 2, 0, IMPLVEC)
DEF(x86_psrldq_vec, 1, 1, 1, IMPLVEC)
DEF(x86_vperm2i128_vec, 1, 2, 1, IMPLVEC)
DEF(x86_punpckl_vec, 1, 2, 0, IMPLVEC)
DEF(x86_punpckh_vec, 1, 2, 0, IMPLVEC)
#endif

#undef TLADDR_ARGS
#undef DATA64_ARGS
#undef IMPL
#undef IMPL64
#undef IMPLVEC
#undef DEF
#undef DEF
};

static inline void _nocheck__trace_translate_block(void * tb, uintptr_t pc, uint8_t * tb_code)
{
}

static inline void trace_translate_block(void * tb, uintptr_t pc, uint8_t * tb_code)
{
    if (true) {
        _nocheck__trace_translate_block(tb, pc, tb_code);
    }
}

#define PRIME32_1   2654435761U

#define PRIME32_2   2246822519U

#define PRIME32_3   3266489917U

#define PRIME32_4    668265263U

#define TB_HASH_XX_SEED 1

static inline uint32_t
tb_hash_func7(uint64_t a0, uint64_t b0, uint32_t e, uint32_t f, uint32_t g)
{
    uint32_t v1 = TB_HASH_XX_SEED + PRIME32_1 + PRIME32_2;
    uint32_t v2 = TB_HASH_XX_SEED + PRIME32_2;
    uint32_t v3 = TB_HASH_XX_SEED + 0;
    uint32_t v4 = TB_HASH_XX_SEED - PRIME32_1;
    uint32_t a = a0 >> 32;
    uint32_t b = a0;
    uint32_t c = b0 >> 32;
    uint32_t d = b0;
    uint32_t h32;

    v1 += a * PRIME32_2;
    v1 = rol32(v1, 13);
    v1 *= PRIME32_1;

    v2 += b * PRIME32_2;
    v2 = rol32(v2, 13);
    v2 *= PRIME32_1;

    v3 += c * PRIME32_2;
    v3 = rol32(v3, 13);
    v3 *= PRIME32_1;

    v4 += d * PRIME32_2;
    v4 = rol32(v4, 13);
    v4 *= PRIME32_1;

    h32 = rol32(v1, 1) + rol32(v2, 7) + rol32(v3, 12) + rol32(v4, 18);
    h32 += 28;

    h32 += e * PRIME32_3;
    h32  = rol32(h32, 17) * PRIME32_4;

    h32 += f * PRIME32_3;
    h32  = rol32(h32, 17) * PRIME32_4;

    h32 += g * PRIME32_3;
    h32  = rol32(h32, 17) * PRIME32_4;

    h32 ^= h32 >> 15;
    h32 *= PRIME32_2;
    h32 ^= h32 >> 13;
    h32 *= PRIME32_3;
    h32 ^= h32 >> 16;

    return h32;
}

static inline
uint32_t tb_hash_func(tb_page_addr_t phys_pc, target_ulong pc, uint32_t flags,
                      uint32_t cf_mask, uint32_t trace_vcpu_dstate)
{
    return tb_hash_func7(phys_pc, pc, flags, cf_mask, trace_vcpu_dstate);
}

#define DEBUG_TB_INVALIDATE_GATE 0

#define DEBUG_TB_FLUSH_GATE 0

#define DEBUG_TB_CHECK_GATE 0

#define assert_memory_lock() tcg_debug_assert(have_mmap_lock())

#define V_L2_BITS 10

#define V_L2_SIZE (1 << V_L2_BITS)

typedef struct PageDesc {
    /* list of TBs intersecting this ram page */
    TranslationBlock *first_tb;
#ifdef CONFIG_SOFTMMU
    /* in order to optimize self modifying code, we count the number
       of lookups we do to a given page to use a bitmap */
    unsigned int code_write_count;
    unsigned long *code_bitmap;
#else
    unsigned long flags;
#endif
} PageDesc;

static int v_l1_size;

static int v_l1_shift;

#define V_L1_MAX_BITS (V_L2_BITS + 3)

#define V_L1_MAX_SIZE (1 << V_L1_MAX_BITS)

static int v_l2_levels;

static void *l1_map[V_L1_MAX_SIZE];

__thread TCGContext *tcg_ctx;

TBContext tb_ctx;

static __thread int have_tb_lock;

#define assert_tb_locked() tcg_debug_assert(have_tb_lock)

#define assert_tb_unlocked() tcg_debug_assert(!have_tb_lock)

void tb_lock(void)
{
    assert_tb_unlocked();
    qemu_mutex_lock(&tb_ctx.tb_lock);
    have_tb_lock++;
}

void tb_unlock(void)
{
    assert_tb_locked();
    have_tb_lock--;
    qemu_mutex_unlock(&tb_ctx.tb_lock);
}

static uint8_t *encode_sleb128(uint8_t *p, target_long val)
{
    int more, byte;

    do {
        byte = val & 0x7f;
        val >>= 7;
        more = !((val == 0 && (byte & 0x40) == 0)
                 || (val == -1 && (byte & 0x40) != 0));
        if (more) {
            byte |= 0x80;
        }
        *p++ = byte;
    } while (more);

    return p;
}

static int encode_search(TranslationBlock *tb, uint8_t *block)
{
    uint8_t *highwater = (uint8_t *)tcg_ctx->code_gen_highwater;
    uint8_t *p = block;
    int i, j, n;

    for (i = 0, n = tb->icount; i < n; ++i) {
        target_ulong prev;

        for (j = 0; j < TARGET_INSN_START_WORDS; ++j) {
            if (i == 0) {
                prev = (j == 0 ? tb->pc : 0);
            } else {
                prev = tcg_ctx->gen_insn_data[i - 1][j];
            }
            p = encode_sleb128(p, tcg_ctx->gen_insn_data[i][j] - prev);
        }
        prev = (i == 0 ? 0 : tcg_ctx->gen_insn_end_off[i - 1]);
        p = encode_sleb128(p, tcg_ctx->gen_insn_end_off[i] - prev);

        /* Test for (pending) buffer overflow.  The assumption is that any
           one row beginning below the high water mark cannot overrun
           the buffer completely.  Thus we can test for overflow after
           encoding a row without having to check during encoding.  */
        if (unlikely(p > highwater)) {
            return -1;
        }
    }

    return p - block;
}

static PageDesc *page_find_alloc(tb_page_addr_t index, int alloc)
{
    PageDesc *pd;
    void **lp;
    int i;

    if (alloc) {
        assert_memory_lock();
    }

    /* Level 1.  Always allocated.  */
    lp = l1_map + ((index >> v_l1_shift) & (v_l1_size - 1));

    /* Level 2..N-1.  */
    for (i = v_l2_levels; i > 0; i--) {
        void **p = (void **)atomic_rcu_read(lp);

        if (p == NULL) {
            if (!alloc) {
                return NULL;
            }
            p = g_new0(void *, V_L2_SIZE);
            atomic_rcu_set(lp, p);
        }

        lp = p + ((index >> (i * V_L2_BITS)) & (V_L2_SIZE - 1));
    }

    pd = (PageDesc *)atomic_rcu_read(lp);
    if (pd == NULL) {
        if (!alloc) {
            return NULL;
        }
        pd = g_new0(PageDesc, V_L2_SIZE);
        atomic_rcu_set(lp, pd);
    }

    return pd + (index & (V_L2_SIZE - 1));
}

static inline PageDesc *page_find(tb_page_addr_t index)
{
    return page_find_alloc(index, 0);
}

static TranslationBlock *tb_alloc(target_ulong pc)
{
    TranslationBlock *tb;

    assert_tb_locked();

    tb = tcg_tb_alloc(tcg_ctx);
    if (unlikely(tb == NULL)) {
        return NULL;
    }
    return tb;
}

static inline void invalidate_page_bitmap(PageDesc *p)
{
#ifdef CONFIG_SOFTMMU
    g_free(p->code_bitmap);
    p->code_bitmap = NULL;
    p->code_write_count = 0;
#endif
}

static void page_flush_tb_1(int level, void **lp)
{
    int i;

    if (*lp == NULL) {
        return;
    }
    if (level == 0) {
        PageDesc *pd = (PageDesc *)*lp;

        for (i = 0; i < V_L2_SIZE; ++i) {
            pd[i].first_tb = NULL;
            invalidate_page_bitmap(pd + i);
        }
    } else {
        void **pp = (void **)*lp;

        for (i = 0; i < V_L2_SIZE; ++i) {
            page_flush_tb_1(level - 1, pp + i);
        }
    }
}

static void page_flush_tb(void)
{
    int i, l1_sz = v_l1_size;

    for (i = 0; i < l1_sz; i++) {
        page_flush_tb_1(v_l2_levels, l1_map + i);
    }
}

static gboolean tb_host_size_iter(gpointer key, gpointer value, gpointer data)
{
    const TranslationBlock *tb = (TranslationBlock *)value;
    size_t *size = (size_t *)data;

    *size += tb->tc.size;
    return false;
}

static void do_tb_flush(CPUState *cpu, run_on_cpu_data tb_flush_count)
{
    tb_lock();

    /* If it is already been done on request of another CPU,
     * just retry.
     */
    if (tb_ctx.tb_flush_count != tb_flush_count.host_int) {
        goto done;
    }

    if (DEBUG_TB_FLUSH_GATE) {
        size_t nb_tbs = g_tree_nnodes(tb_ctx.tb_tree);
        size_t host_size = 0;

        g_tree_foreach(tb_ctx.tb_tree, tb_host_size_iter, &host_size);
        printf("qemu: flush code_size=%zu nb_tbs=%zu avg_tb_size=%zu\n",
               tcg_code_size(), nb_tbs, nb_tbs > 0 ? host_size / nb_tbs : 0);
    }

    CPU_FOREACH(cpu) {
        cpu_tb_jmp_cache_clear(cpu);
    }

    /* Increment the refcount first so that destroy acts as a reset */
    g_tree_ref(tb_ctx.tb_tree);
    g_tree_destroy(tb_ctx.tb_tree);

    qht_reset_size(&tb_ctx.htable, CODE_GEN_HTABLE_SIZE);
    page_flush_tb();

    tcg_region_reset_all();
    /* XXX: flush processor icache at this point if cache flush is
       expensive */
    atomic_mb_set(&tb_ctx.tb_flush_count, tb_ctx.tb_flush_count + 1);

done:
    tb_unlock();
}

void tb_flush(CPUState *cpu)
{
    if (tcg_enabled()) {
        unsigned tb_flush_count = atomic_mb_read(&tb_ctx.tb_flush_count);
        async_safe_run_on_cpu(cpu, do_tb_flush,
                              RUN_ON_CPU_HOST_INT(tb_flush_count));
    }
}

static void
do_tb_page_check(struct qht *ht, void *p, uint32_t hash, void *userp)
{
    TranslationBlock *tb = (TranslationBlock *)p;
    int flags1, flags2;

    flags1 = page_get_flags(tb->pc);
    flags2 = page_get_flags(tb->pc + tb->size - 1);
    if ((flags1 & PAGE_WRITE) || (flags2 & PAGE_WRITE)) {
        printf("ERROR page flags: PC=%08lx size=%04x f1=%x f2=%x\n",
               (long)tb->pc, tb->size, flags1, flags2);
    }
}

static void tb_page_check(void)
{
    qht_iter(&tb_ctx.htable, do_tb_page_check, NULL);
}

static inline void tb_reset_jump(TranslationBlock *tb, int n)
{
    uintptr_t addr = (uintptr_t)((char *)tb->tc.ptr + tb->jmp_reset_offset[n]);
    tb_set_jmp_target(tb, n, addr);
}

static inline void tb_alloc_page(TranslationBlock *tb,
                                 unsigned int n, tb_page_addr_t page_addr)
{
    PageDesc *p;
#ifndef CONFIG_USER_ONLY
    bool page_already_protected;
#endif

    assert_memory_lock();

    tb->page_addr[n] = page_addr;
    p = page_find_alloc(page_addr >> TARGET_PAGE_BITS, 1);
    tb->page_next[n] = p->first_tb;
#ifndef CONFIG_USER_ONLY
    page_already_protected = p->first_tb != NULL;
#endif
    p->first_tb = (TranslationBlock *)((uintptr_t)tb | n);
    invalidate_page_bitmap(p);

#if defined(CONFIG_USER_ONLY)
    if (p->flags & PAGE_WRITE) {
        target_ulong addr;
        PageDesc *p2;
        int prot;

        /* force the host page as non writable (writes will have a
           page fault + mprotect overhead) */
        page_addr &= qemu_host_page_mask;
        prot = 0;
        for (addr = page_addr; addr < page_addr + qemu_host_page_size;
            addr += TARGET_PAGE_SIZE) {

            p2 = page_find(addr >> TARGET_PAGE_BITS);
            if (!p2) {
                continue;
            }
            prot |= p2->flags;
            p2->flags &= ~PAGE_WRITE;
          }
        mprotect(g2h(page_addr), qemu_host_page_size,
                 (prot & PAGE_BITS) & ~PAGE_WRITE);
        if (DEBUG_TB_INVALIDATE_GATE) {
            printf("protecting code page: 0x" TB_PAGE_ADDR_FMT "\n", page_addr);
        }
    }
#else
    /* if some code is already present, then the pages are already
       protected. So we handle the case where only the first TB is
       allocated in a physical page */
    if (!page_already_protected) {
        tlb_protect_code(page_addr);
    }
#endif
}

static void tb_link_page(TranslationBlock *tb, tb_page_addr_t phys_pc,
                         tb_page_addr_t phys_page2)
{
    uint32_t h;

    assert_memory_lock();

    /* add in the page list */
    tb_alloc_page(tb, 0, phys_pc & TARGET_PAGE_MASK);
    if (phys_page2 != -1) {
        tb_alloc_page(tb, 1, phys_page2);
    } else {
        tb->page_addr[1] = -1;
    }

    /* add in the hash table */
    h = tb_hash_func(phys_pc, tb->pc, tb->flags, tb->cflags & CF_HASH_MASK,
                     tb->trace_vcpu_dstate);
    qht_insert(&tb_ctx.htable, tb, h);

#ifdef CONFIG_USER_ONLY
    if (DEBUG_TB_CHECK_GATE) {
        tb_page_check();
    }
#endif
}

TranslationBlock *tb_gen_code(CPUState *cpu,
                              target_ulong pc, target_ulong cs_base,
                              uint32_t flags, int cflags)
{
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
    TranslationBlock *tb;
    tb_page_addr_t phys_pc, phys_page2;
    target_ulong virt_page2;
    tcg_insn_unit *gen_code_buf;
    int gen_code_size, search_size;
#ifdef CONFIG_PROFILER
    TCGProfile *prof = &tcg_ctx->prof;
    int64_t ti;
#endif
    assert_memory_lock();

    phys_pc = get_page_addr_code(env, pc);

 buffer_overflow:
    tb = tb_alloc(pc);
    if (unlikely(!tb)) {
        /* flush must be done */
        tb_flush(cpu);
        mmap_unlock();
        /* Make the execution loop process the flush as soon as possible.  */
        cpu->exception_index = EXCP_INTERRUPT;
        cpu_loop_exit(cpu);
    }

    gen_code_buf = (tcg_insn_unit *)tcg_ctx->code_gen_ptr;
    tb->tc.ptr = gen_code_buf;
    tb->pc = pc;
    tb->cs_base = cs_base;
    tb->flags = flags;
    tb->cflags = cflags;
    tb->trace_vcpu_dstate = *cpu->trace_dstate;
    tcg_ctx->tb_cflags = cflags;

#ifdef CONFIG_PROFILER
    /* includes aborted translations because of exceptions */
    atomic_set(&prof->tb_count1, prof->tb_count1 + 1);
    ti = profile_getclock();
#endif

    tcg_func_start(tcg_ctx);

    tcg_ctx->cpu = ENV_GET_CPU(env);
    gen_intermediate_code(cpu, tb);
    tcg_ctx->cpu = NULL;

    trace_translate_block(tb, tb->pc, (uint8_t *)tb->tc.ptr);

    /* generate machine code */
    tb->jmp_reset_offset[0] = TB_JMP_RESET_OFFSET_INVALID;
    tb->jmp_reset_offset[1] = TB_JMP_RESET_OFFSET_INVALID;
    tcg_ctx->tb_jmp_reset_offset = tb->jmp_reset_offset;
    if (TCG_TARGET_HAS_direct_jump) {
        tcg_ctx->tb_jmp_insn_offset = tb->jmp_target_arg;
        tcg_ctx->tb_jmp_target_addr = NULL;
    } else {
        tcg_ctx->tb_jmp_insn_offset = NULL;
        tcg_ctx->tb_jmp_target_addr = tb->jmp_target_arg;
    }

#ifdef CONFIG_PROFILER
    atomic_set(&prof->tb_count, prof->tb_count + 1);
    atomic_set(&prof->interm_time, prof->interm_time + profile_getclock() - ti);
    ti = profile_getclock();
#endif

    /* ??? Overflow could be handled better here.  In particular, we
       don't need to re-do gen_intermediate_code, nor should we re-do
       the tcg optimization currently hidden inside tcg_gen_code.  All
       that should be required is to flush the TBs, allocate a new TB,
       re-initialize it per above, and re-do the actual code generation.  */
    gen_code_size = tcg_gen_code(tcg_ctx, tb);
    if (unlikely(gen_code_size < 0)) {
        goto buffer_overflow;
    }
    search_size = encode_search(tb, (uint8_t *)gen_code_buf + gen_code_size);
    if (unlikely(search_size < 0)) {
        goto buffer_overflow;
    }
    tb->tc.size = gen_code_size;

#ifdef CONFIG_PROFILER
    atomic_set(&prof->code_time, prof->code_time + profile_getclock() - ti);
    atomic_set(&prof->code_in_len, prof->code_in_len + tb->size);
    atomic_set(&prof->code_out_len, prof->code_out_len + gen_code_size);
    atomic_set(&prof->search_out_len, prof->search_out_len + search_size);
#endif

#ifdef DEBUG_DISAS
    if (qemu_loglevel_mask(CPU_LOG_TB_OUT_ASM) &&
        qemu_log_in_addr_range(tb->pc)) {
        qemu_log_lock();
        qemu_log("OUT: [size=%d]\n", gen_code_size);
        if (tcg_ctx->data_gen_ptr) {
            size_t code_size = (char *)tcg_ctx->data_gen_ptr - (char *)tb->tc.ptr;
            size_t data_size = gen_code_size - code_size;
            size_t i;

            log_disas(tb->tc.ptr, code_size);

            for (i = 0; i < data_size; i += sizeof(tcg_target_ulong)) {
                if (sizeof(tcg_target_ulong) == 8) {
                    qemu_log("0x%08" PRIxPTR ":  .quad  0x%016" PRIx64 "\n",
                             (uintptr_t)tcg_ctx->data_gen_ptr + i,
                             *(uint64_t *)((char *)tcg_ctx->data_gen_ptr + i));
                } else {
                    qemu_log("0x%08" PRIxPTR ":  .long  0x%08x\n",
                             (uintptr_t)tcg_ctx->data_gen_ptr + i,
                             *(uint32_t *)((char *)tcg_ctx->data_gen_ptr + i));
                }
            }
        } else {
            log_disas(tb->tc.ptr, gen_code_size);
        }
        qemu_log("\n");
        qemu_log_flush();
        qemu_log_unlock();
    }
#endif

    atomic_set(&tcg_ctx->code_gen_ptr, (void *)
        ROUND_UP((uintptr_t)gen_code_buf + gen_code_size + search_size,
                 CODE_GEN_ALIGN));

    /* init jump list */
    assert(((uintptr_t)tb & 3) == 0);
    tb->jmp_list_first = (uintptr_t)tb | 2;
    tb->jmp_list_next[0] = (uintptr_t)NULL;
    tb->jmp_list_next[1] = (uintptr_t)NULL;

    /* init original jump addresses wich has been set during tcg_gen_code() */
    if (tb->jmp_reset_offset[0] != TB_JMP_RESET_OFFSET_INVALID) {
        tb_reset_jump(tb, 0);
    }
    if (tb->jmp_reset_offset[1] != TB_JMP_RESET_OFFSET_INVALID) {
        tb_reset_jump(tb, 1);
    }

    /* check next page if needed */
    virt_page2 = (pc + tb->size - 1) & TARGET_PAGE_MASK;
    phys_page2 = -1;
    if ((pc & TARGET_PAGE_MASK) != virt_page2) {
        phys_page2 = get_page_addr_code(env, virt_page2);
    }
    /* As long as consistency of the TB stuff is provided by tb_lock in user
     * mode and is implicit in single-threaded softmmu emulation, no explicit
     * memory barrier is required before tb_link_page() makes the TB visible
     * through the physical hash table and physical page list.
     */
    tb_link_page(tb, phys_pc, phys_page2);
    g_tree_insert(tb_ctx.tb_tree, &tb->tc, tb);
    return tb;
}

int page_get_flags(target_ulong address)
{
    PageDesc *p;

    p = page_find(address >> TARGET_PAGE_BITS);
    if (!p) {
        return 0;
    }
    return p->flags;
}

void translator_loop(const TranslatorOps *ops, DisasContextBase *db,
                     CPUState *cpu, TranslationBlock *tb)
{
    int max_insns;

    /* Initialize DisasContext */
    db->tb = tb;
    db->pc_first = tb->pc;
    db->pc_next = db->pc_first;
    db->is_jmp = DISAS_NEXT;
    db->num_insns = 0;
    db->singlestep_enabled = cpu->singlestep_enabled;

    /* Instruction counting */
    max_insns = tb_cflags(db->tb) & CF_COUNT_MASK;
    if (max_insns == 0) {
        max_insns = CF_COUNT_MASK;
    }
    if (max_insns > TCG_MAX_INSNS) {
        max_insns = TCG_MAX_INSNS;
    }
    if (db->singlestep_enabled || singlestep) {
        max_insns = 1;
    }

    max_insns = ops->init_disas_context(db, cpu, max_insns);
    tcg_debug_assert(db->is_jmp == DISAS_NEXT);  /* no early exit */

    /* Reset the temp count so that we can identify leaks */
    tcg_clear_temp_count();

    /* Start translating.  */
    gen_tb_start(db->tb);
    ops->tb_start(db, cpu);
    tcg_debug_assert(db->is_jmp == DISAS_NEXT);  /* no early exit */

    while (true) {
        db->num_insns++;
        ops->insn_start(db, cpu);
        tcg_debug_assert(db->is_jmp == DISAS_NEXT);  /* no early exit */

        /* Pass breakpoint hits to target for further processing */
        if (unlikely(!QTAILQ_EMPTY(&cpu->breakpoints))) {
            CPUBreakpoint *bp;
            QTAILQ_FOREACH(bp, &cpu->breakpoints, entry) {
                if (bp->pc == db->pc_next) {
                    if (ops->breakpoint_check(db, cpu, bp)) {
                        break;
                    }
                }
            }
            /* The breakpoint_check hook may use DISAS_TOO_MANY to indicate
               that only one more instruction is to be executed.  Otherwise
               it should use DISAS_NORETURN when generating an exception,
               but may use a DISAS_TARGET_* value for Something Else.  */
            if (db->is_jmp > DISAS_TOO_MANY) {
                break;
            }
        }

        /* Disassemble one instruction.  The translate_insn hook should
           update db->pc_next and db->is_jmp to indicate what should be
           done next -- either exiting this loop or locate the start of
           the next instruction.  */
        if (db->num_insns == max_insns && (tb_cflags(db->tb) & CF_LAST_IO)) {
            /* Accept I/O on the last instruction.  */
            gen_io_start();
            ops->translate_insn(db, cpu);
            gen_io_end();
        } else {
            ops->translate_insn(db, cpu);
        }

        /* Stop translation if translate_insn so indicated.  */
        if (db->is_jmp != DISAS_NEXT) {
            break;
        }

        /* Stop translation if the output buffer is full,
           or we have executed all of the allowed instructions.  */
        if (tcg_op_buf_full() || db->num_insns >= max_insns) {
            db->is_jmp = DISAS_TOO_MANY;
            break;
        }
    }

    /* Emit code to exit the TB, as indicated by db->is_jmp.  */
    ops->tb_stop(db, cpu);
    gen_tb_end(db->tb, db->num_insns);

    /* The disas_log hook may use these values rather than recompute.  */
    db->tb->size = db->pc_next - db->pc_first;
    db->tb->icount = db->num_insns;

#ifdef DEBUG_DISAS
    if (qemu_loglevel_mask(CPU_LOG_TB_IN_ASM)
        && qemu_log_in_addr_range(db->pc_first)) {
        qemu_log_lock();
        qemu_log("----------------\n");
        ops->disas_log(db, cpu);
        qemu_log("\n");
        qemu_log_unlock();
    }
#endif
}

void pstrcpy(char *buf, int buf_size, const char *str)
{
    int c;
    char *q = buf;

    if (buf_size <= 0)
        return;

    for(;;) {
        c = *str++;
        if (c == 0 || q >= buf + buf_size - 1)
            break;
        *q++ = c;
    }
    *q = '\0';
}

char *pstrcat(char *buf, int buf_size, const char *s)
{
    int len;
    len = strlen(buf);
    if (len < buf_size)
        pstrcpy(buf + len, buf_size - len, s);
    return buf;
}

