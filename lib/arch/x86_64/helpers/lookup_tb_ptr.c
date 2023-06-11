#define CONFIG_LINUX 1

#define CONFIG_USER_ONLY 1

#define TARGET_I386 1

#define TARGET_X86_64 1

#define HOST_BIG_ENDIAN (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)

#define QEMU_ALIGNED(X) __attribute__((aligned(X)))

#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#define likely(x)   __builtin_expect(!!(x), 1)

#define unlikely(x)   __builtin_expect(!!(x), 0)

#define container_of(ptr, type, member) ({                      \
        const typeof(((type *) 0)->member) *__mptr = (ptr);     \
        (type *) ((char *) __mptr - offsetof(type, member));})

# define QEMU_ERROR(X) __attribute__((error(X)))

#include <stddef.h>

#include <stdbool.h>

#include <stdint.h>

#include <sys/types.h>

#include <stdio.h>

#include <inttypes.h>

#include <limits.h>

#include <setjmp.h>

#define G_GNUC_PRINTF( format_idx, arg_idx )    \
  __attribute__((__format__ (__printf__, format_idx, arg_idx)))

#define G_GNUC_UNUSED \
  __attribute__ ((__unused__))

#define G_GNUC_BEGIN_IGNORE_DEPRECATIONS \
  _Pragma("clang diagnostic push") \
  _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"")

#define G_GNUC_END_IGNORE_DEPRECATIONS \
  _Pragma("clang diagnostic pop")

#define G_GNUC_WARN_UNUSED_RESULT __attribute__((warn_unused_result))

#define G_STRFUNC     ((const char*) (__func__))

#define G_STMT_START  do

#define G_STMT_END    while (0)

# define G_NORETURN __attribute__ ((__noreturn__))

#define _GLIB_EXTERN extern

#define _GLIB_AUTOPTR_FUNC_NAME(TypeName) glib_autoptr_cleanup_##TypeName

#define _GLIB_AUTOPTR_CLEAR_FUNC_NAME(TypeName) glib_autoptr_clear_##TypeName

#define _GLIB_AUTOPTR_TYPENAME(TypeName)  TypeName##_autoptr

#define _GLIB_AUTOPTR_LIST_FUNC_NAME(TypeName) glib_listautoptr_cleanup_##TypeName

#define _GLIB_AUTOPTR_LIST_TYPENAME(TypeName)  TypeName##_listautoptr

#define _GLIB_AUTOPTR_SLIST_FUNC_NAME(TypeName) glib_slistautoptr_cleanup_##TypeName

#define _GLIB_AUTOPTR_SLIST_TYPENAME(TypeName)  TypeName##_slistautoptr

#define _GLIB_AUTOPTR_QUEUE_FUNC_NAME(TypeName) glib_queueautoptr_cleanup_##TypeName

#define _GLIB_AUTOPTR_QUEUE_TYPENAME(TypeName)  TypeName##_queueautoptr

#define _GLIB_DEFINE_AUTOPTR_CLEANUP_FUNCS(TypeName, ParentName, cleanup) \
  typedef TypeName *_GLIB_AUTOPTR_TYPENAME(TypeName);                                                           \
  typedef GList *_GLIB_AUTOPTR_LIST_TYPENAME(TypeName);                                                         \
  typedef GSList *_GLIB_AUTOPTR_SLIST_TYPENAME(TypeName);                                                       \
  typedef GQueue *_GLIB_AUTOPTR_QUEUE_TYPENAME(TypeName);                                                       \
  G_GNUC_BEGIN_IGNORE_DEPRECATIONS                                                                              \
  static G_GNUC_UNUSED inline void _GLIB_AUTOPTR_CLEAR_FUNC_NAME(TypeName) (TypeName *_ptr)                     \
    { if (_ptr) (cleanup) ((ParentName *) _ptr); }                                                              \
  static G_GNUC_UNUSED inline void _GLIB_AUTOPTR_FUNC_NAME(TypeName) (TypeName **_ptr)                          \
    { _GLIB_AUTOPTR_CLEAR_FUNC_NAME(TypeName) (*_ptr); }                                                        \
  static G_GNUC_UNUSED inline void _GLIB_AUTOPTR_LIST_FUNC_NAME(TypeName) (GList **_l)                          \
    { g_list_free_full (*_l, (GDestroyNotify) (void(*)(void)) cleanup); }                                       \
  static G_GNUC_UNUSED inline void _GLIB_AUTOPTR_SLIST_FUNC_NAME(TypeName) (GSList **_l)                        \
    { g_slist_free_full (*_l, (GDestroyNotify) (void(*)(void)) cleanup); }                                      \
  static G_GNUC_UNUSED inline void _GLIB_AUTOPTR_QUEUE_FUNC_NAME(TypeName) (GQueue **_q)                        \
    { if (*_q) g_queue_free_full (*_q, (GDestroyNotify) (void(*)(void)) cleanup); }                             \
  G_GNUC_END_IGNORE_DEPRECATIONS

#define G_DEFINE_AUTOPTR_CLEANUP_FUNC(TypeName, func) \
  _GLIB_DEFINE_AUTOPTR_CLEANUP_FUNCS(TypeName, TypeName, func)

typedef unsigned char guint8;

#define GLIB_AVAILABLE_IN_ALL                   _GLIB_EXTERN

typedef char   gchar;

typedef unsigned int    guint;

typedef void* gpointer;

typedef void            (*GDestroyNotify)       (gpointer       data);

typedef struct _GArray		GArray;

typedef struct _GByteArray	GByteArray;

struct _GArray
{
  gchar *data;
  guint len;
};

struct _GByteArray
{
  guint8 *data;
  guint	  len;
};

typedef struct _GList GList;

struct _GList
{
  gpointer data;
  GList *next;
  GList *prev;
};

GLIB_AVAILABLE_IN_ALL
void     g_list_free_full               (GList            *list,
					 GDestroyNotify    free_func);

typedef struct _GHashTable  GHashTable;

typedef struct _GSList GSList;

struct _GSList
{
  gpointer data;
  GSList *next;
};

GLIB_AVAILABLE_IN_ALL
void     g_slist_free_full               (GSList           *list,
					  GDestroyNotify    free_func);

#define G_LOG_DOMAIN    ((gchar*) 0)

typedef struct _GQueue GQueue;

struct _GQueue
{
  GList *head;
  GList *tail;
  guint  length;
};

GLIB_AVAILABLE_IN_ALL
void     g_queue_free_full      (GQueue           *queue,
				GDestroyNotify    free_func);

#define g_assert_not_reached()          G_STMT_START { g_assertion_message_expr (G_LOG_DOMAIN, __FILE__, __LINE__, G_STRFUNC, NULL); } G_STMT_END

GLIB_AVAILABLE_IN_ALL
G_NORETURN
void    g_assertion_message_expr        (const char     *domain,
                                         const char     *file,
                                         int             line,
                                         const char     *func,
                                         const char     *expr);

typedef struct AddressSpace AddressSpace;

typedef struct ArchCPU ArchCPU;

typedef struct BusState BusState;

typedef struct Clock Clock;

typedef struct CPUAddressSpace CPUAddressSpace;

typedef struct CPUArchState CPUArchState;

typedef struct CpuInfoFast CpuInfoFast;

typedef struct CPUJumpCache CPUJumpCache;

typedef struct CPUState CPUState;

typedef struct DeviceState DeviceState;

typedef struct Error Error;

typedef struct MemoryRegion MemoryRegion;

typedef struct Object Object;

typedef struct ObjectClass ObjectClass;

typedef struct Property Property;

typedef struct QDict QDict;

typedef struct QemuMutex QemuMutex;

typedef struct QemuSpin QemuSpin;

typedef struct TranslationBlock TranslationBlock;

typedef struct VMChangeStateEntry VMChangeStateEntry;

typedef struct VMStateDescription VMStateDescription;

typedef struct IRQState *qemu_irq;

#define qemu_build_not_reached()  qemu_build_not_reached_always()

#define qemu_build_assert(test)  while (!(test)) qemu_build_not_reached()

#define ROUND_DOWN(n, d) ((n) & -(0 ? (n) : (d)))

#define ROUND_UP(n, d) ROUND_DOWN((n) + (d) - 1, (d))

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

G_NORETURN extern
void QEMU_ERROR("code path is reachable")
    qemu_build_not_reached_always(void);

typedef enum OnOffAuto {
    ON_OFF_AUTO_AUTO,
    ON_OFF_AUTO_ON,
    ON_OFF_AUTO_OFF,
    ON_OFF_AUTO__MAX,
} OnOffAuto;

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

# define ATOMIC_REG_SIZE  8

#define qatomic_read__nocheck(ptr) \
    __atomic_load_n(ptr, __ATOMIC_RELAXED)

#define qatomic_read(ptr)                              \
    ({                                                 \
    qemu_build_assert(sizeof(*ptr) <= ATOMIC_REG_SIZE); \
    qatomic_read__nocheck(ptr);                        \
    })

#define qatomic_set__nocheck(ptr, i) \
    __atomic_store_n(ptr, i, __ATOMIC_RELAXED)

#define qatomic_set(ptr, i)  do {                      \
    qemu_build_assert(sizeof(*ptr) <= ATOMIC_REG_SIZE); \
    qatomic_set__nocheck(ptr, i);                      \
} while(0)

#define qatomic_rcu_read__nocheck(ptr, valptr)           \
    __atomic_load(ptr, valptr, __ATOMIC_RELAXED);        \
    smp_read_barrier_depends();

#define qatomic_rcu_read(ptr)                          \
    ({                                                 \
    qemu_build_assert(sizeof(*ptr) <= ATOMIC_REG_SIZE); \
    typeof_strip_qual(*ptr) _val;                      \
    qatomic_rcu_read__nocheck(ptr, &_val);             \
    _val;                                              \
    })

#define qatomic_load_acquire(ptr)                       \
    ({                                                  \
    qemu_build_assert(sizeof(*ptr) <= ATOMIC_REG_SIZE); \
    typeof_strip_qual(*ptr) _val;                       \
    __atomic_load(ptr, &_val, __ATOMIC_ACQUIRE);        \
    _val;                                               \
    })

#define qatomic_store_release(ptr, i)  do {             \
    qemu_build_assert(sizeof(*ptr) <= ATOMIC_REG_SIZE); \
    __atomic_store_n(ptr, i, __ATOMIC_RELEASE);         \
} while(0)

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

#define QTAILQ_FOREACH(var, head, field)                                \
        for ((var) = ((head)->tqh_first);                               \
                (var);                                                  \
                (var) = ((var)->field.tqe_next))

#define QTAILQ_EMPTY(head)               ((head)->tqh_first == NULL)

typedef struct QTailQLink {
    void *tql_next;
    struct QTailQLink *tql_prev;
} QTailQLink;

#define BITS_PER_BYTE           CHAR_BIT

#define BITS_TO_LONGS(nr)       DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))

static inline uint32_t rol32(uint32_t word, unsigned int shift)
{
    return (word << (shift & 31)) | (word >> (-shift & 31));
}

#define DECLARE_BITMAP(name,bits)                  \
        unsigned long name[BITS_TO_LONGS(bits)]

typedef struct QemuLockCnt QemuLockCnt;

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

struct QemuSpin {
    int value;
};

struct QemuLockCnt {
#ifndef CONFIG_LINUX
    QemuMutex mutex;
#endif
    unsigned count;
};

typedef struct Notifier Notifier;

struct Notifier
{
    void (*notify)(Notifier *notifier, void *data);
    QLIST_ENTRY(Notifier) node;
};

struct rcu_head;

typedef void RCUCBFunc(struct rcu_head *head);

struct rcu_head {
    struct rcu_head *next;
    RCUCBFunc *func;
};

struct TypeImpl;

typedef struct TypeImpl *Type;

typedef void (ObjectUnparent)(Object *obj);

#define OBJECT_CLASS_CAST_CACHE 4

typedef void (ObjectFree)(void *obj);

struct ObjectClass
{
    /* private: */
    Type type;
    GSList *interfaces;

    const char *object_cast_cache[OBJECT_CLASS_CAST_CACHE];
    const char *class_cast_cache[OBJECT_CLASS_CAST_CACHE];

    ObjectUnparent *unparent;

    GHashTable *properties;
};

#define DECLARE_INSTANCE_CHECKER(InstanceType, OBJ_NAME, TYPENAME) \
    static inline G_GNUC_UNUSED InstanceType * \
    OBJ_NAME(const void *obj) \
    { return OBJECT_CHECK(InstanceType, obj, TYPENAME); }

#define DECLARE_CLASS_CHECKERS(ClassType, OBJ_NAME, TYPENAME) \
    static inline G_GNUC_UNUSED ClassType * \
    OBJ_NAME##_GET_CLASS(const void *obj) \
    { return OBJECT_GET_CLASS(ClassType, obj, TYPENAME); } \
    \
    static inline G_GNUC_UNUSED ClassType * \
    OBJ_NAME##_CLASS(const void *klass) \
    { return OBJECT_CLASS_CHECK(ClassType, klass, TYPENAME); }

#define DECLARE_OBJ_CHECKERS(InstanceType, ClassType, OBJ_NAME, TYPENAME) \
    DECLARE_INSTANCE_CHECKER(InstanceType, OBJ_NAME, TYPENAME) \
    \
    DECLARE_CLASS_CHECKERS(ClassType, OBJ_NAME, TYPENAME)

#define OBJECT_DECLARE_TYPE(InstanceType, ClassType, MODULE_OBJ_NAME) \
    typedef struct InstanceType InstanceType; \
    typedef struct ClassType ClassType; \
    \
    G_DEFINE_AUTOPTR_CLEANUP_FUNC(InstanceType, object_unref) \
    \
    DECLARE_OBJ_CHECKERS(InstanceType, ClassType, \
                         MODULE_OBJ_NAME, TYPE_##MODULE_OBJ_NAME)

struct Object
{
    /* private: */
    ObjectClass *clazz;
    ObjectFree *free;
    GHashTable *properties;
    uint32_t ref;
    Object *parent;
};

#define OBJECT(obj) \
    ((Object *)(obj))

#define OBJECT_CLASS(class) \
    ((ObjectClass *)(class))

#define OBJECT_CHECK(type, obj, name) \
    ((type *)object_dynamic_cast_assert(OBJECT(obj), (name), \
                                        __FILE__, __LINE__, __func__))

#define OBJECT_CLASS_CHECK(class_type, class, name) \
    ((class_type *)object_class_dynamic_cast_assert(OBJECT_CLASS(class), (name), \
                                               __FILE__, __LINE__, __func__))

#define OBJECT_GET_CLASS(class, obj, name) \
    OBJECT_CLASS_CHECK(class, object_get_class(OBJECT(obj)), name)

Object *object_dynamic_cast_assert(Object *obj, const char *,
                                   const char *file, int line, const char *func);

ObjectClass *object_get_class(Object *obj);

ObjectClass *object_class_dynamic_cast_assert(ObjectClass *klass,
                                              const char *,
                                              const char *file, int line,
                                              const char *func);

void object_unref(void *obj);

typedef struct ResettableState ResettableState;

struct ResettableState {
    unsigned count;
    bool hold_phase_pending;
    bool exit_phase_in_progress;
};

#define TYPE_DEVICE "device"

OBJECT_DECLARE_TYPE(DeviceState, DeviceClass, DEVICE)

typedef enum DeviceCategory {
    DEVICE_CATEGORY_BRIDGE,
    DEVICE_CATEGORY_USB,
    DEVICE_CATEGORY_STORAGE,
    DEVICE_CATEGORY_NETWORK,
    DEVICE_CATEGORY_INPUT,
    DEVICE_CATEGORY_DISPLAY,
    DEVICE_CATEGORY_SOUND,
    DEVICE_CATEGORY_MISC,
    DEVICE_CATEGORY_CPU,
    DEVICE_CATEGORY_WATCHDOG,
    DEVICE_CATEGORY_MAX
} DeviceCategory;

typedef void (*DeviceRealize)(DeviceState *dev, Error **errp);

typedef void (*DeviceUnrealize)(DeviceState *dev);

typedef void (*DeviceReset)(DeviceState *dev);

struct DeviceClass {
    /*< private >*/
    ObjectClass parent_class;
    /*< public >*/

    DECLARE_BITMAP(categories, DEVICE_CATEGORY_MAX);
    const char *fw_name;
    const char *desc;

    /*
     * The underscore at the end ensures a compile-time error if someone
     * assigns to dc->props instead of using device_class_set_props.
     */
    Property *props_;

    /*
     * Can this device be instantiated with -device / device_add?
     * All devices should support instantiation with device_add, and
     * this flag should not exist.  But we're not there, yet.  Some
     * devices fail to instantiate with cryptic error messages.
     * Others instantiate, but don't work.  Exposing users to such
     * behavior would be cruel; clearing this flag will protect them.
     * It should never be cleared without a comment explaining why it
     * is cleared.
     * TODO remove once we're there
     */
    bool user_creatable;
    bool hotpluggable;

    /* callbacks */
    /*
     * Reset method here is deprecated and replaced by methods in the
     * resettable class interface to implement a multi-phase reset.
     * TODO: remove once every reset callback is unused
     */
    DeviceReset reset;
    DeviceRealize realize;
    DeviceUnrealize unrealize;

    /* device state */
    const VMStateDescription *vmsd;

    /* Private to qdev / bus.  */
    const char *bus_type;
};

struct NamedGPIOList {
    char *name;
    qemu_irq *in;
    int num_in;
    int num_out;
    QLIST_ENTRY(NamedGPIOList) node;
};

typedef struct Clock Clock;

struct NamedClockList {
    char *name;
    Clock *clock;
    bool output;
    bool alias;
    QLIST_ENTRY(NamedClockList) node;
};

typedef struct {
    bool engaged_in_io;
} MemReentrancyGuard;

struct DeviceState {
    /*< private >*/
    Object parent_obj;
    /*< public >*/

    char *id;
    char *canonical_path;
    bool realized;
    bool pending_deleted_event;
    int64_t pending_deleted_expires_ms;
    QDict *opts;
    int hotplugged;
    bool allow_unplug_during_migration;
    BusState *parent_bus;
    QLIST_HEAD(, NamedGPIOList) gpios;
    QLIST_HEAD(, NamedClockList) clocks;
    QLIST_HEAD(, BusState) child_bus;
    int num_child_bus;
    int instance_id_alias;
    int alias_required_for_version;
    ResettableState reset;
    GSList *unplug_blockers;

    /* Is the device currently in mmio/pio/dma? Used to prevent re-entrancy */
    MemReentrancyGuard mem_reentrancy_guard;
};

typedef void *PTR;

typedef uint64_t bfd_vma;

typedef uint8_t bfd_byte;

enum bfd_flavour {
  bfd_target_unknown_flavour,
  bfd_target_aout_flavour,
  bfd_target_coff_flavour,
  bfd_target_ecoff_flavour,
  bfd_target_elf_flavour,
  bfd_target_ieee_flavour,
  bfd_target_nlm_flavour,
  bfd_target_oasys_flavour,
  bfd_target_tekhex_flavour,
  bfd_target_srec_flavour,
  bfd_target_ihex_flavour,
  bfd_target_som_flavour,
  bfd_target_os9k_flavour,
  bfd_target_versados_flavour,
  bfd_target_msdos_flavour,
  bfd_target_evax_flavour
};

enum bfd_endian { BFD_ENDIAN_BIG, BFD_ENDIAN_LITTLE, BFD_ENDIAN_UNKNOWN };

enum bfd_architecture
{
  bfd_arch_unknown,    /* File arch not known */
  bfd_arch_obscure,    /* Arch known, not one of these */
  bfd_arch_m68k,       /* Motorola 68xxx */
#define bfd_mach_m68000 1
#define bfd_mach_m68008 2
#define bfd_mach_m68010 3
#define bfd_mach_m68020 4
#define bfd_mach_m68030 5
#define bfd_mach_m68040 6
#define bfd_mach_m68060 7
#define bfd_mach_cpu32  8
#define bfd_mach_mcf5200  9
#define bfd_mach_mcf5206e 10
#define bfd_mach_mcf5307  11
#define bfd_mach_mcf5407  12
#define bfd_mach_mcf528x  13
#define bfd_mach_mcfv4e   14
#define bfd_mach_mcf521x   15
#define bfd_mach_mcf5249   16
#define bfd_mach_mcf547x   17
#define bfd_mach_mcf548x   18
  bfd_arch_vax,        /* DEC Vax */
  bfd_arch_i960,       /* Intel 960 */
     /* The order of the following is important.
       lower number indicates a machine type that
       only accepts a subset of the instructions
       available to machines with higher numbers.
       The exception is the "ca", which is
       incompatible with all other machines except
       "core". */

#define bfd_mach_i960_core      1
#define bfd_mach_i960_ka_sa     2
#define bfd_mach_i960_kb_sb     3
#define bfd_mach_i960_mc        4
#define bfd_mach_i960_xa        5
#define bfd_mach_i960_ca        6
#define bfd_mach_i960_jx        7
#define bfd_mach_i960_hx        8

  bfd_arch_a29k,       /* AMD 29000 */
  bfd_arch_sparc,      /* SPARC */
#define bfd_mach_sparc                 1
/* The difference between v8plus and v9 is that v9 is a true 64 bit env.  */
#define bfd_mach_sparc_sparclet        2
#define bfd_mach_sparc_sparclite       3
#define bfd_mach_sparc_v8plus          4
#define bfd_mach_sparc_v8plusa         5 /* with ultrasparc add'ns.  */
#define bfd_mach_sparc_sparclite_le    6
#define bfd_mach_sparc_v9              7
#define bfd_mach_sparc_v9a             8 /* with ultrasparc add'ns.  */
#define bfd_mach_sparc_v8plusb         9 /* with cheetah add'ns.  */
#define bfd_mach_sparc_v9b             10 /* with cheetah add'ns.  */
/* Nonzero if MACH has the v9 instruction set.  */
#define bfd_mach_sparc_v9_p(mach) \
  ((mach) >= bfd_mach_sparc_v8plus && (mach) <= bfd_mach_sparc_v9b \
   && (mach) != bfd_mach_sparc_sparclite_le)
  bfd_arch_mips,       /* MIPS Rxxxx */
#define bfd_mach_mips3000              3000
#define bfd_mach_mips3900              3900
#define bfd_mach_mips4000              4000
#define bfd_mach_mips4010              4010
#define bfd_mach_mips4100              4100
#define bfd_mach_mips4300              4300
#define bfd_mach_mips4400              4400
#define bfd_mach_mips4600              4600
#define bfd_mach_mips4650              4650
#define bfd_mach_mips5000              5000
#define bfd_mach_mips6000              6000
#define bfd_mach_mips8000              8000
#define bfd_mach_mips10000             10000
#define bfd_mach_mips16                16
  bfd_arch_i386,       /* Intel 386 */
#define bfd_mach_i386_i386 0
#define bfd_mach_i386_i8086 1
#define bfd_mach_i386_i386_intel_syntax 2
#define bfd_mach_x86_64 3
#define bfd_mach_x86_64_intel_syntax 4
  bfd_arch_we32k,      /* AT&T WE32xxx */
  bfd_arch_tahoe,      /* CCI/Harris Tahoe */
  bfd_arch_i860,       /* Intel 860 */
  bfd_arch_romp,       /* IBM ROMP PC/RT */
  bfd_arch_alliant,    /* Alliant */
  bfd_arch_convex,     /* Convex */
  bfd_arch_m88k,       /* Motorola 88xxx */
  bfd_arch_pyramid,    /* Pyramid Technology */
  bfd_arch_h8300,      /* Hitachi H8/300 */
#define bfd_mach_h8300   1
#define bfd_mach_h8300h  2
#define bfd_mach_h8300s  3
  bfd_arch_powerpc,    /* PowerPC */
#define bfd_mach_ppc           0
#define bfd_mach_ppc64         1
#define bfd_mach_ppc_403       403
#define bfd_mach_ppc_403gc     4030
#define bfd_mach_ppc_e500      500
#define bfd_mach_ppc_505       505
#define bfd_mach_ppc_601       601
#define bfd_mach_ppc_602       602
#define bfd_mach_ppc_603       603
#define bfd_mach_ppc_ec603e    6031
#define bfd_mach_ppc_604       604
#define bfd_mach_ppc_620       620
#define bfd_mach_ppc_630       630
#define bfd_mach_ppc_750       750
#define bfd_mach_ppc_860       860
#define bfd_mach_ppc_a35       35
#define bfd_mach_ppc_rs64ii    642
#define bfd_mach_ppc_rs64iii   643
#define bfd_mach_ppc_7400      7400
  bfd_arch_rs6000,     /* IBM RS/6000 */
  bfd_arch_hppa,       /* HP PA RISC */
#define bfd_mach_hppa10        10
#define bfd_mach_hppa11        11
#define bfd_mach_hppa20        20
#define bfd_mach_hppa20w       25
  bfd_arch_d10v,       /* Mitsubishi D10V */
  bfd_arch_z8k,        /* Zilog Z8000 */
#define bfd_mach_z8001         1
#define bfd_mach_z8002         2
  bfd_arch_h8500,      /* Hitachi H8/500 */
  bfd_arch_sh,         /* Hitachi SH */
#define bfd_mach_sh            1
#define bfd_mach_sh2        0x20
#define bfd_mach_sh_dsp     0x2d
#define bfd_mach_sh2a       0x2a
#define bfd_mach_sh2a_nofpu 0x2b
#define bfd_mach_sh2e       0x2e
#define bfd_mach_sh3        0x30
#define bfd_mach_sh3_nommu  0x31
#define bfd_mach_sh3_dsp    0x3d
#define bfd_mach_sh3e       0x3e
#define bfd_mach_sh4        0x40
#define bfd_mach_sh4_nofpu  0x41
#define bfd_mach_sh4_nommu_nofpu  0x42
#define bfd_mach_sh4a       0x4a
#define bfd_mach_sh4a_nofpu 0x4b
#define bfd_mach_sh4al_dsp  0x4d
#define bfd_mach_sh5        0x50
  bfd_arch_alpha,      /* Dec Alpha */
#define bfd_mach_alpha 1
#define bfd_mach_alpha_ev4  0x10
#define bfd_mach_alpha_ev5  0x20
#define bfd_mach_alpha_ev6  0x30
  bfd_arch_arm,        /* Advanced Risc Machines ARM */
#define bfd_mach_arm_unknown  0
#define bfd_mach_arm_2        1
#define bfd_mach_arm_2a       2
#define bfd_mach_arm_3        3
#define bfd_mach_arm_3M       4
#define bfd_mach_arm_4        5
#define bfd_mach_arm_4T       6
#define bfd_mach_arm_5        7
#define bfd_mach_arm_5T       8
#define bfd_mach_arm_5TE      9
#define bfd_mach_arm_XScale   10
#define bfd_mach_arm_ep9312   11
#define bfd_mach_arm_iWMMXt   12
#define bfd_mach_arm_iWMMXt2  13
  bfd_arch_ns32k,      /* National Semiconductors ns32000 */
  bfd_arch_w65,        /* WDC 65816 */
  bfd_arch_tic30,      /* Texas Instruments TMS320C30 */
  bfd_arch_v850,       /* NEC V850 */
#define bfd_mach_v850          0
  bfd_arch_arc,        /* Argonaut RISC Core */
#define bfd_mach_arc_base 0
  bfd_arch_m32r,       /* Mitsubishi M32R/D */
#define bfd_mach_m32r          0  /* backwards compatibility */
  bfd_arch_mn10200,    /* Matsushita MN10200 */
  bfd_arch_mn10300,    /* Matsushita MN10300 */
  bfd_arch_avr,        /* AVR microcontrollers */
#define bfd_mach_avr1       1
#define bfd_mach_avr2       2
#define bfd_mach_avr25      25
#define bfd_mach_avr3       3
#define bfd_mach_avr31      31
#define bfd_mach_avr35      35
#define bfd_mach_avr4       4
#define bfd_mach_avr5       5
#define bfd_mach_avr51      51
#define bfd_mach_avr6       6
#define bfd_mach_avrtiny    100
#define bfd_mach_avrxmega1  101
#define bfd_mach_avrxmega2  102
#define bfd_mach_avrxmega3  103
#define bfd_mach_avrxmega4  104
#define bfd_mach_avrxmega5  105
#define bfd_mach_avrxmega6  106
#define bfd_mach_avrxmega7  107
  bfd_arch_cris,       /* Axis CRIS */
#define bfd_mach_cris_v0_v10   255
#define bfd_mach_cris_v32      32
#define bfd_mach_cris_v10_v32  1032
  bfd_arch_microblaze, /* Xilinx MicroBlaze.  */
  bfd_arch_moxie,      /* The Moxie core.  */
  bfd_arch_ia64,      /* HP/Intel ia64 */
#define bfd_mach_ia64_elf64    64
#define bfd_mach_ia64_elf32    32
  bfd_arch_nios2,      /* Nios II */
#define bfd_mach_nios2          0
#define bfd_mach_nios2r1        1
#define bfd_mach_nios2r2        2
  bfd_arch_rx,       /* Renesas RX */
#define bfd_mach_rx            0x75
#define bfd_mach_rx_v2         0x76
#define bfd_mach_rx_v3         0x77
  bfd_arch_loongarch,
  bfd_arch_last
  };

typedef struct symbol_cache_entry
{
    const char *name;
    union
    {
        PTR p;
        bfd_vma i;
    } udata;
} asymbol;

typedef int (*fprintf_function)(FILE *f, const char *fmt, ...)
    G_GNUC_PRINTF(2, 3);

enum dis_insn_type {
  dis_noninsn,          /* Not a valid instruction */
  dis_nonbranch,        /* Not a branch instruction */
  dis_branch,           /* Unconditional branch */
  dis_condbranch,       /* Conditional branch */
  dis_jsr,              /* Jump to subroutine */
  dis_condjsr,          /* Conditional jump to subroutine */
  dis_dref,             /* Data reference instruction */
  dis_dref2             /* Two data references in instruction */
};

typedef struct disassemble_info {
  fprintf_function fprintf_func;
  FILE *stream;
  PTR application_data;

  /* Target description.  We could replace this with a pointer to the bfd,
     but that would require one.  There currently isn't any such requirement
     so to avoid introducing one we record these explicitly.  */
  /* The bfd_flavour.  This can be bfd_target_unknown_flavour.  */
  enum bfd_flavour flavour;
  /* The bfd_arch value.  */
  enum bfd_architecture arch;
  /* The bfd_mach value.  */
  unsigned long mach;
  /* Endianness (for bi-endian cpus).  Mono-endian cpus can ignore this.  */
  enum bfd_endian endian;

  /* An array of pointers to symbols either at the location being disassembled
     or at the start of the function being disassembled.  The array is sorted
     so that the first symbol is intended to be the one used.  The others are
     present for any misc. purposes.  This is not set reliably, but if it is
     not NULL, it is correct.  */
  asymbol **symbols;
  /* Number of symbols in array.  */
  int num_symbols;

  /* For use by the disassembler.
     The top 16 bits are reserved for public use (and are documented here).
     The bottom 16 bits are for the internal use of the disassembler.  */
  unsigned long flags;
#define INSN_HAS_RELOC  0x80000000
#define INSN_ARM_BE32   0x00010000
  PTR private_data;

  /* Function used to get bytes to disassemble.  MEMADDR is the
     address of the stuff to be disassembled, MYADDR is the address to
     put the bytes in, and LENGTH is the number of bytes to read.
     INFO is a pointer to this struct.
     Returns an errno value or 0 for success.  */
  int (*read_memory_func)
    (bfd_vma memaddr, bfd_byte *myaddr, int length,
        struct disassemble_info *info);

  /* Function which should be called if we get an error that we can't
     recover from.  STATUS is the errno value from read_memory_func and
     MEMADDR is the address that we were trying to read.  INFO is a
     pointer to this struct.  */
  void (*memory_error_func)
    (int status, bfd_vma memaddr, struct disassemble_info *info);

  /* Function called to print ADDR.  */
  void (*print_address_func)
    (bfd_vma addr, struct disassemble_info *info);

    /* Function called to print an instruction. The function is architecture
     * specific.
     */
    int (*print_insn)(bfd_vma addr, struct disassemble_info *info);

  /* Function called to determine if there is a symbol at the given ADDR.
     If there is, the function returns 1, otherwise it returns 0.
     This is used by ports which support an overlay manager where
     the overlay number is held in the top part of an address.  In
     some circumstances we want to include the overlay number in the
     address, (normally because there is a symbol associated with
     that address), but sometimes we want to mask out the overlay bits.  */
  int (* symbol_at_address_func)
    (bfd_vma addr, struct disassemble_info * info);

  /* These are for buffer_read_memory.  */
  const bfd_byte *buffer;
  bfd_vma buffer_vma;
  int buffer_length;

  /* This variable may be set by the instruction decoder.  It suggests
      the number of bytes objdump should display on a single line.  If
      the instruction decoder sets this, it should always set it to
      the same value in order to get reasonable looking output.  */
  int bytes_per_line;

  /* the next two variables control the way objdump displays the raw data */
  /* For example, if bytes_per_line is 8 and bytes_per_chunk is 4, the */
  /* output will look like this:
     00:   00000000 00000000
     with the chunks displayed according to "display_endian". */
  int bytes_per_chunk;
  enum bfd_endian display_endian;

  /* Results from instruction decoders.  Not all decoders yet support
     this information.  This info is set each time an instruction is
     decoded, and is only valid for the last such instruction.

     To determine whether this decoder supports this information, set
     insn_info_valid to 0, decode an instruction, then check it.  */

  char insn_info_valid;         /* Branch info has been set. */
  char branch_delay_insns;      /* How many sequential insn's will run before
                                   a branch takes effect.  (0 = normal) */
  char data_size;               /* Size of data reference in insn, in bytes */
  enum dis_insn_type insn_type; /* Type of instruction */
  bfd_vma target;               /* Target address of branch or dref, if known;
                                   zero if unknown.  */
  bfd_vma target2;              /* Second target address for dref2 */

  /* Command line options specific to the target disassembler.  */
  char * disassembler_options;

  /* Field intended to be used by targets in any way they deem suitable.  */
  int64_t target_info;

  /* Options for Capstone disassembly.  */
  int cap_arch;
  int cap_mode;
  int cap_insn_unit;
  int cap_insn_split;

} disassemble_info;

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

typedef struct CPUClass CPUClass;

#define OBJECT_DECLARE_CPU_TYPE(CpuInstanceType, CpuClassType, CPU_MODULE_OBJ_NAME) \
    typedef struct ArchCPU CpuInstanceType; \
    OBJECT_DECLARE_TYPE(ArchCPU, CpuClassType, CPU_MODULE_OBJ_NAME);

typedef struct CPUWatchpoint CPUWatchpoint;

struct TCGCPUOps;

struct AccelCPUClass;

struct SysemuCPUOps;

struct CPUClass {
    /*< private >*/
    DeviceClass parent_class;
    /*< public >*/

    ObjectClass *(*class_by_name)(const char *cpu_model);
    void (*parse_features)(const char *, char *str, Error **errp);

    bool (*has_work)(CPUState *cpu);
    int (*memory_rw_debug)(CPUState *cpu, vaddr addr,
                           uint8_t *buf, int len, bool is_write);
    void (*dump_state)(CPUState *cpu, FILE *, int flags);
    void (*query_cpu_fast)(CPUState *cpu, CpuInfoFast *value);
    int64_t (*get_arch_id)(CPUState *cpu);
    void (*set_pc)(CPUState *cpu, vaddr value);
    vaddr (*get_pc)(CPUState *cpu);
    int (*gdb_read_register)(CPUState *cpu, GByteArray *buf, int reg);
    int (*gdb_write_register)(CPUState *cpu, uint8_t *buf, int reg);
    vaddr (*gdb_adjust_breakpoint)(CPUState *cpu, vaddr addr);

    const char *gdb_core_xml_file;
    gchar * (*gdb_arch_name)(CPUState *cpu);
    const char * (*gdb_get_dynamic_xml)(CPUState *cpu, const char *xmlname);

    void (*disas_set_info)(CPUState *cpu, disassemble_info *info);

    const char *deprecation_note;
    struct AccelCPUClass *accel_cpu;

    /* when system emulation is not available, this pointer is NULL */
    const struct SysemuCPUOps *sysemu_ops;

    /* when TCG is not available, this pointer is NULL */
    const struct TCGCPUOps *tcg_ops;

    /*
     * if not NULL, this is called in order for the CPUClass to initialize
     * class data that depends on the accelerator, see accel/accel-common.c.
     */
    void (*init_accel_cpu)(struct AccelCPUClass *accel_cpu, CPUClass *cc);

    /*
     * Keep non-pointer data at the end to minimize holes.
     */
    int reset_dump_flags;
    int gdb_num_core_regs;
    bool gdb_stop_before_watchpoint;
};

typedef union IcountDecr {
    uint32_t u32;
    struct {
#if HOST_BIG_ENDIAN
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
    vaddr _vaddr;
    vaddr len;
    vaddr hitaddr;
    MemTxAttrs hitattrs;
    int flags; /* BP_* */
    QTAILQ_ENTRY(CPUWatchpoint) entry;
};

struct KVMState;

struct kvm_run;

struct hax_vcpu_state;

struct hvf_vcpu_state;

struct qemu_work_item;

struct CPUState {
    /*< private >*/
    DeviceState parent_obj;
    /* cache to avoid expensive CPU_GET_CLASS */
    CPUClass *cc;
    /*< public >*/

    int nr_cores;
    int nr_threads;

    struct QemuThread *thread;
#ifdef _WIN32
    HANDLE hThread;
    QemuSemaphore sem;
#endif
    int thread_id;
    bool running, has_waiter;
    struct QemuCond *halt_cond;
    bool thread_kicked;
    bool created;
    bool stop;
    bool stopped;

    /* Should CPU start in powered-off state? */
    bool start_powered_off;

    bool unplug;
    bool crash_occurred;
    bool exit_request;
    int exclusive_context_count;
    uint32_t cflags_next_tb;
    /* updates protected by BQL */
    uint32_t interrupt_request;
    int singlestep_enabled;
    int64_t icount_budget;
    int64_t icount_extra;
    uint64_t random_seed;
    sigjmp_buf jmp_env;

    QemuMutex work_mutex;
    QSIMPLEQ_HEAD(, qemu_work_item) work_list;

    CPUAddressSpace *cpu_ases;
    int num_ases;
    AddressSpace *as;
    MemoryRegion *memory;

    CPUArchState *env_ptr;
    IcountDecr *icount_decr_ptr;

    CPUJumpCache *tb_jmp_cache;

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

    /* Only used in KVM */
    int kvm_fd;
    struct KVMState *kvm_state;
    struct kvm_run *kvm_run;
    struct kvm_dirty_gfn *kvm_dirty_gfns;
    uint32_t kvm_fetch_index;
    uint64_t dirty_pages;

    /* Use by accel-block: CPU is executing an ioctl() */
    QemuLockCnt in_ioctl_lock;

    DECLARE_BITMAP(plugin_mask, QEMU_PLUGIN_EV_MAX);

#ifdef CONFIG_PLUGIN
    GArray *plugin_mem_cbs;
    /* saved iotlb data from io_writex */
    SavedIOTLB saved_iotlb;
#endif

    /* TODO Move common fields from CPUArchState here. */
    int cpu_index;
    int cluster_index;
    uint32_t tcg_cflags;
    uint32_t halted;
    uint32_t can_do_io;
    int32_t exception_index;

    /* shared by kvm, hax and hvf */
    bool vcpu_dirty;

    /* Used to keep track of an outstanding cpu throttle thread for migration
     * autoconverge
     */
    bool throttle_thread_scheduled;

    /*
     * Sleep throttle_us_per_full microseconds once dirty ring is full
     * if dirty page rate limit is enabled.
     */
    int64_t throttle_us_per_full;

    bool ignore_memory_transaction_failures;

    /* Used for user-only emulation of prctl(PR_SET_UNALIGN). */
    bool prctl_unalign_sigbus;

    struct hax_vcpu_state *hax_vcpu;

    struct hvf_vcpu_state *hvf;

    /* track IOMMUs whose translations we've cached in the TCG TLB */
    GArray *iommu_notifiers;
};

enum CPUDumpFlags {
    CPU_DUMP_CODE = 0x00010000,
    CPU_DUMP_FPU  = 0x00020000,
    CPU_DUMP_CCOP = 0x00040000,
};

void cpu_dump_state(CPUState *cpu, FILE *f, int flags);

#define BP_GDB                0x10

#define BP_CPU                0x20

extern int qemu_loglevel;

static inline bool qemu_loglevel_mask(int mask)
{
    return (qemu_loglevel & mask) != 0;
}

void G_GNUC_PRINTF(1, 2) qemu_log(const char *fmt, ...);

const char *lookup_symbol(uint64_t orig_addr);

#define TYPE_X86_CPU "x86_64-cpu"

OBJECT_DECLARE_CPU_TYPE(X86CPU, X86CPUClass, X86_CPU)

#define HV_SINT_COUNT                         16

#define HV_X64_MSR_CRASH_P0                     0x40000100

#define HV_X64_MSR_CRASH_P4                     0x40000104

#define HV_CRASH_PARAMS    (HV_X64_MSR_CRASH_P4 - HV_X64_MSR_CRASH_P0 + 1)

#define HV_STIMER_COUNT                       4

#define TARGET_PAGE_BITS 12

typedef int64_t target_long;

#define TARGET_FMT_lx "%016" PRIx64

typedef uint64_t target_ulong;

typedef struct CPUTLB { } CPUTLB;

typedef struct CPUNegativeOffsetState {
    CPUTLB tlb;
    IcountDecr icount_decr;
} CPUNegativeOffsetState;

typedef uint16_t float16;

typedef uint32_t float32;

typedef uint64_t float64;

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

#define TF_MASK                 0x00000100

#define IOPL_MASK               0x00003000

#define RF_MASK                 0x00010000

#define VM_MASK                 0x00020000

#define AC_MASK                 0x00040000

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

#define CPU_NB_REGS64 16

#define CPU_NB_REGS CPU_NB_REGS64

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

struct kvm_msrs;

struct ArchCPU {
    /*< private >*/
    CPUState parent_obj;
    /*< public >*/

    CPUNegativeOffsetState neg;
    CPUX86State env;
    VMChangeStateEntry *vmsentry;

    uint64_t ucode_rev;

    uint32_t hyperv_spinlock_attempts;
    char *hyperv_vendor;
    bool hyperv_synic_kvm_only;
    uint64_t hyperv_features;
    bool hyperv_passthrough;
    OnOffAuto hyperv_no_nonarch_cs;
    uint32_t hyperv_vendor_id[3];
    uint32_t hyperv_interface_id[4];
    uint32_t hyperv_limits[3];
    bool hyperv_enforce_cpuid;
    uint32_t hyperv_ver_id_build;
    uint16_t hyperv_ver_id_major;
    uint16_t hyperv_ver_id_minor;
    uint32_t hyperv_ver_id_sp;
    uint8_t hyperv_ver_id_sb;
    uint32_t hyperv_ver_id_sn;

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

    /*
     * Enable LBR_FMT bits of IA32_PERF_CAPABILITIES MSR.
     * This can't be initialized with a default because it doesn't have
     * stable ABI support yet. It is only allowed to pass all LBR_FMT bits
     * returned by kvm_arch_get_supported_msr_feature()(which depends on both
     * host CPU and kernel capabilities) to the guest.
     */
    uint64_t lbr_fmt;

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

    /* Only advertise CPUID leaves defined by the vendor */
    bool vendor_cpuid_only;

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

    /* Forcefully disable KVM PV features not exposed in guest CPUIDs */
    bool kvm_pv_enforce_cpuid;

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

    bool xen_vapic;
};

#define EXCP_DEBUG      0x10002

#define TARGET_PAGE_SIZE   (1 << TARGET_PAGE_BITS)

#define TARGET_PAGE_MASK   ((target_long)-1 << TARGET_PAGE_BITS)

#define TARGET_PAGE_ALIGN(addr) ROUND_UP((addr), TARGET_PAGE_SIZE)

static inline ArchCPU *env_archcpu(CPUArchState *env)
{
    return container_of(env, ArchCPU, env);
}

static inline CPUState *env_cpu(CPUArchState *env)
{
    return &env_archcpu(env)->parent_obj;
}

static inline void cpu_get_tb_cpu_state(CPUX86State *env, target_ulong *pc,
                                        target_ulong *cs_base, uint32_t *flags)
{
    *cs_base = env->segs[R_CS].base;
    *pc = *cs_base + env->eip;
    *flags = env->hflags |
        (env->eflags & (IOPL_MASK | TF_MASK | RF_MASK | VM_MASK | AC_MASK));
}

typedef struct RBNode
{
    /* Encodes parent with color in the lsb. */
    uintptr_t rb_parent_color;
    struct RBNode *rb_right;
    struct RBNode *rb_left;
} RBNode;

typedef struct IntervalTreeNode
{
    RBNode rb;

    uint64_t start;    /* Start of interval */
    uint64_t last;     /* Last location _in_ interval */
    uint64_t subtree_last;
} IntervalTreeNode;

typedef vaddr tb_page_addr_t;

struct tb_tc {
    const void *ptr;    /* pointer to the translated code */
    size_t size;
};

struct TranslationBlock {
    /*
     * Guest PC corresponding to this block.  This must be the true
     * virtual address.  Therefore e.g. x86 stores EIP + CS_BASE, and
     * targets like Arm, MIPS, HP-PA, which reuse low bits for ISA or
     * privilege, must store those bits elsewhere.
     *
     * If CF_PCREL, the opcodes for the TranslationBlock are written
     * such that the TB is associated only with the physical page and
     * may be run in any virtual address context.  In this case, PC
     * must always be taken from ENV in a target-specific manner.
     * Unwind information is taken as offsets from the page, to be
     * deposited into the "current" PC.
     */
    vaddr pc;

    /*
     * Target-specific data associated with the TranslationBlock, e.g.:
     * x86: the original user, the Code Segment virtual base,
     * arm: an extension of tb->flags,
     * s390x: instruction data for EXECUTE,
     * sparc: the next pc of the instruction queue (for delay slots).
     */
    uint64_t cs_base;

    uint32_t flags; /* flags defining in which context the code was generated */
    uint32_t cflags;    /* compile flags */

/* Note that TCG_MAX_INSNS is 512; we validate this match elsewhere. */
#define CF_COUNT_MASK    0x000001ff
#define CF_NO_GOTO_TB    0x00000200 /* Do not chain with goto_tb */
#define CF_NO_GOTO_PTR   0x00000400 /* Do not chain with goto_ptr */
#define CF_SINGLE_STEP   0x00000800 /* gdbstub single-step in effect */
#define CF_LAST_IO       0x00008000 /* Last insn may be an IO access.  */
#define CF_MEMI_ONLY     0x00010000 /* Only instrument memory ops */
#define CF_USE_ICOUNT    0x00020000
#define CF_INVALID       0x00040000 /* TB is stale. Set with @jmp_lock held */
#define CF_PARALLEL      0x00080000 /* Generate code for a parallel context */
#define CF_NOIRQ         0x00100000 /* Generate an uninterruptible TB */
#define CF_PCREL         0x00200000 /* Opcodes in TB are PC-relative */
#define CF_CLUSTER_MASK  0xff000000 /* Top 8 bits are cluster ID */
#define CF_CLUSTER_SHIFT 24

    /*
     * Above fields used for comparing
     */

    /* size of target code for this block (1 <= size <= TARGET_PAGE_SIZE) */
    uint16_t size;
    uint16_t icount;

    struct tb_tc tc;

    /*
     * Track tb_page_addr_t intervals that intersect this TB.
     * For user-only, the virtual addresses are always contiguous,
     * and we use a unified interval tree.  For system, we use a
     * linked list headed in each PageDesc.  Within the list, the lsb
     * of the previous pointer tells the index of page_next[], and the
     * list is protected by the PageDesc lock(s).
     */
#ifdef CONFIG_USER_ONLY
    IntervalTreeNode itree;
#else
    uintptr_t page_next[2];
    tb_page_addr_t page_addr[2];
#endif

    /* jmp_lock placed here to fill a 4-byte hole. Its documentation is below */
    QemuSpin jmp_lock;

    /* The following data are used to directly call another TB from
     * the code of this one. This can be done either by emitting direct or
     * indirect native jump instructions. These jumps are reset so that the TB
     * just continues its execution. The TB can be linked to another one by
     * setting one of the jump targets (or patching the jump instruction). Only
     * two of such jumps are supported.
     */
#define TB_JMP_OFFSET_INVALID 0xffff /* indicates no jump generated */
    uint16_t jmp_reset_offset[2]; /* offset of original jump target */
    uint16_t jmp_insn_offset[2];  /* offset of direct jump insn */
    uintptr_t jmp_target_addr[2]; /* target address */

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

G_NORETURN static inline void cpu_loop_exit_noexc(CPUState *cpu) {
  __builtin_trap();
  __builtin_unreachable();
}

G_NORETURN static inline void cpu_loop_exit(CPUState *cpu) {
  __builtin_trap();
  __builtin_unreachable();
}

static inline uint32_t tb_cflags(const TranslationBlock *tb)
{
    return qatomic_read(&tb->cflags);
}

static inline tb_page_addr_t tb_page_addr0(const TranslationBlock *tb)
{
#ifdef CONFIG_USER_ONLY
    return tb->itree.start;
#else
    return tb->page_addr[0];
#endif
}

static inline tb_page_addr_t tb_page_addr1(const TranslationBlock *tb)
{
#ifdef CONFIG_USER_ONLY
    tb_page_addr_t next = tb->itree.last & TARGET_PAGE_MASK;
    return next == (tb->itree.start & TARGET_PAGE_MASK) ? -1 : next;
#else
    return tb->page_addr[1];
#endif
}

tb_page_addr_t get_page_addr_code_hostp(CPUArchState *env, target_ulong addr,
                                        void **hostp);

static inline tb_page_addr_t get_page_addr_code(CPUArchState *env,
                                                target_ulong addr)
{
    return get_page_addr_code_hostp(env, addr, NULL);
}

# define tcg_debug_assert(X) \
    do { if (!(X)) { __builtin_unreachable(); } } while (0)

extern const void *tcg_code_gen_epilogue;

#define CPU_LOG_EXEC       (1 << 5)

#define CPU_LOG_TB_CPU     (1 << 8)

#define CPU_LOG_TB_NOCHAIN (1 << 13)

#define CPU_LOG_TB_FPU     (1 << 17)

FILE *qemu_log_trylock(void) G_GNUC_WARN_UNUSED_RESULT;

#define qemu_log_mask(MASK, FMT, ...)                   \
    do {                                                \
        if (unlikely(qemu_loglevel_mask(MASK))) {       \
            qemu_log(FMT, ## __VA_ARGS__);              \
        }                                               \
    } while (0)

void qemu_log_unlock(FILE *fd);

bool qemu_log_in_addr_range(uint64_t addr);

#define HELPER(name) glue(helper_, name)

#define TB_JMP_CACHE_BITS 12

#define TB_JMP_CACHE_SIZE (1 << TB_JMP_CACHE_BITS)

#define PRIME32_1   2654435761U

#define PRIME32_2   2246822519U

#define PRIME32_3   3266489917U

#define PRIME32_4    668265263U

#define QEMU_XXHASH_SEED 1

struct CPUJumpCache {
    struct rcu_head rcu;
    struct {
        TranslationBlock *tb;
        target_ulong pc;
    } array[TB_JMP_CACHE_SIZE];
};

static inline uint32_t qemu_xxhash8(uint64_t ab, uint64_t cd, uint64_t ef,
                                    uint32_t g, uint32_t h)
{
    uint32_t v1 = QEMU_XXHASH_SEED + PRIME32_1 + PRIME32_2;
    uint32_t v2 = QEMU_XXHASH_SEED + PRIME32_2;
    uint32_t v3 = QEMU_XXHASH_SEED + 0;
    uint32_t v4 = QEMU_XXHASH_SEED - PRIME32_1;
    uint32_t a = ab;
    uint32_t b = ab >> 32;
    uint32_t c = cd;
    uint32_t d = cd >> 32;
    uint32_t e = ef;
    uint32_t f = ef >> 32;
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

    h32 += h * PRIME32_3;
    h32  = rol32(h32, 17) * PRIME32_4;

    h32 ^= h32 >> 15;
    h32 *= PRIME32_2;
    h32 ^= h32 >> 13;
    h32 *= PRIME32_3;
    h32 ^= h32 >> 16;

    return h32;
}

static inline unsigned int tb_jmp_cache_hash_func(target_ulong pc)
{
    return (pc ^ (pc >> TB_JMP_CACHE_BITS)) & (TB_JMP_CACHE_SIZE - 1);
}

static inline
uint32_t tb_hash_func(tb_page_addr_t phys_pc, target_ulong pc,
                      uint32_t flags, uint64_t flags2, uint32_t cf_mask)
{
    return qemu_xxhash8(phys_pc, pc, flags2, flags, cf_mask);
}

typedef bool (*qht_cmp_func_t)(const void *a, const void *b);

struct qht {
    struct qht_map *map;
    qht_cmp_func_t cmp;
    QemuMutex lock; /* serializes setters of ht->map */
    unsigned int mode;
};

typedef bool (*qht_lookup_func_t)(const void *obj, const void *userp);

void *qht_lookup_custom(const struct qht *ht, const void *userp, uint32_t hash,
                        qht_lookup_func_t func);

typedef struct TBContext TBContext;

struct TBContext {

    struct qht htable;

    /* statistics */
    unsigned tb_flush_count;
    unsigned tb_phys_invalidate_count;
};

extern TBContext tb_ctx;

extern bool one_insn_per_tb;

uint32_t curr_cflags(CPUState *cpu)
{
    uint32_t cflags = cpu->tcg_cflags;

    /*
     * Record gdb single-step.  We should be exiting the TB by raising
     * EXCP_DEBUG, but to simplify other tests, disable chaining too.
     *
     * For singlestep and -d nochain, suppress goto_tb so that
     * we can log -d cpu,exec after every TB.
     */
    if (unlikely(cpu->singlestep_enabled)) {
        cflags |= CF_NO_GOTO_TB | CF_NO_GOTO_PTR | CF_SINGLE_STEP | 1;
    } else if (qatomic_read(&one_insn_per_tb)) {
        cflags |= CF_NO_GOTO_TB | 1;
    } else if (qemu_loglevel_mask(CPU_LOG_TB_NOCHAIN)) {
        cflags |= CF_NO_GOTO_TB;
    }

    return cflags;
}

struct tb_desc {
    target_ulong pc;
    target_ulong cs_base;
    CPUArchState *env;
    tb_page_addr_t page_addr0;
    uint32_t flags;
    uint32_t cflags;
};

static bool tb_lookup_cmp(const void *p, const void *d)
{
    const TranslationBlock *tb = p;
    const struct tb_desc *desc = d;

    if ((tb_cflags(tb) & CF_PCREL || tb->pc == desc->pc) &&
        tb_page_addr0(tb) == desc->page_addr0 &&
        tb->cs_base == desc->cs_base &&
        tb->flags == desc->flags &&
        tb_cflags(tb) == desc->cflags) {
        /* check next page if needed */
        tb_page_addr_t tb_phys_page1 = tb_page_addr1(tb);
        if (tb_phys_page1 == -1) {
            return true;
        } else {
            tb_page_addr_t phys_page1;
            target_ulong virt_page1;

            /*
             * We know that the first page matched, and an otherwise valid TB
             * encountered an incomplete instruction at the end of that page,
             * therefore we know that generating a new TB from the current PC
             * must also require reading from the next page -- even if the
             * second pages do not match, and therefore the resulting insn
             * is different for the new TB.  Therefore any exception raised
             * here by the faulting lookup is not premature.
             */
            virt_page1 = TARGET_PAGE_ALIGN(desc->pc);
            phys_page1 = get_page_addr_code(desc->env, virt_page1);
            if (tb_phys_page1 == phys_page1) {
                return true;
            }
        }
    }
    return false;
}

static TranslationBlock *tb_htable_lookup(CPUState *cpu, target_ulong pc,
                                          target_ulong cs_base, uint32_t flags,
                                          uint32_t cflags)
{
    tb_page_addr_t phys_pc;
    struct tb_desc desc;
    uint32_t h;

    desc.env = cpu->env_ptr;
    desc.cs_base = cs_base;
    desc.flags = flags;
    desc.cflags = cflags;
    desc.pc = pc;
    phys_pc = get_page_addr_code(desc.env, pc);
    if (phys_pc == -1) {
        return NULL;
    }
    desc.page_addr0 = phys_pc;
    h = tb_hash_func(phys_pc, (cflags & CF_PCREL ? 0 : pc),
                     flags, cs_base, cflags);
    return qht_lookup_custom(&tb_ctx.htable, &desc, h, tb_lookup_cmp);
}

static inline TranslationBlock *tb_lookup(CPUState *cpu, target_ulong pc,
                                          target_ulong cs_base,
                                          uint32_t flags, uint32_t cflags)
{
    TranslationBlock *tb;
    CPUJumpCache *jc;
    uint32_t hash;

    /* we should never be trying to look up an INVALID tb */
    tcg_debug_assert(!(cflags & CF_INVALID));

    hash = tb_jmp_cache_hash_func(pc);
    jc = cpu->tb_jmp_cache;

    if (cflags & CF_PCREL) {
        /* Use acquire to ensure current load of pc from jc. */
        tb = qatomic_load_acquire(&jc->array[hash].tb);

        if (likely(tb &&
                   jc->array[hash].pc == pc &&
                   tb->cs_base == cs_base &&
                   tb->flags == flags &&
                   tb_cflags(tb) == cflags)) {
            return tb;
        }
        tb = tb_htable_lookup(cpu, pc, cs_base, flags, cflags);
        if (tb == NULL) {
            return NULL;
        }
        jc->array[hash].pc = pc;
        /* Ensure pc is written first. */
        qatomic_store_release(&jc->array[hash].tb, tb);
    } else {
        /* Use rcu_read to ensure current load of pc from *tb. */
        tb = qatomic_rcu_read(&jc->array[hash].tb);

        if (likely(tb &&
                   tb->pc == pc &&
                   tb->cs_base == cs_base &&
                   tb->flags == flags &&
                   tb_cflags(tb) == cflags)) {
            return tb;
        }
        tb = tb_htable_lookup(cpu, pc, cs_base, flags, cflags);
        if (tb == NULL) {
            return NULL;
        }
        /* Use the pc value already stored in tb->pc. */
        qatomic_set(&jc->array[hash].tb, tb);
    }

    return tb;
}

static void log_cpu_exec(target_ulong pc, CPUState *cpu,
                         const TranslationBlock *tb)
{
    if (qemu_log_in_addr_range(pc)) {
        qemu_log_mask(CPU_LOG_EXEC,
                      "Trace %d: %p [%08" PRIx64
                      "/" TARGET_FMT_lx "/%08x/%08x] %s\n",
                      cpu->cpu_index, tb->tc.ptr, tb->cs_base, pc,
                      tb->flags, tb->cflags, lookup_symbol(pc));

        if (qemu_loglevel_mask(CPU_LOG_TB_CPU)) {
            FILE *logfile = qemu_log_trylock();
            if (logfile) {
                int flags = 0;

                if (qemu_loglevel_mask(CPU_LOG_TB_FPU)) {
                    flags |= CPU_DUMP_FPU;
                }
#if defined(TARGET_I386)
                flags |= CPU_DUMP_CCOP;
#endif
                cpu_dump_state(cpu, logfile, flags);
                qemu_log_unlock(logfile);
            }
        }
    }
}

static bool check_for_breakpoints_slow(CPUState *cpu, target_ulong pc,
                                       uint32_t *cflags)
{
    CPUBreakpoint *bp;
    bool match_page = false;

    /*
     * Singlestep overrides breakpoints.
     * This requirement is visible in the record-replay tests, where
     * we would fail to make forward progress in reverse-continue.
     *
     * TODO: gdb singlestep should only override gdb breakpoints,
     * so that one could (gdb) singlestep into the guest kernel's
     * architectural breakpoint handler.
     */
    if (cpu->singlestep_enabled) {
        return false;
    }

    QTAILQ_FOREACH(bp, &cpu->breakpoints, entry) {
        /*
         * If we have an exact pc match, trigger the breakpoint.
         * Otherwise, note matches within the page.
         */
        if (pc == bp->pc) {
            bool match_bp = false;

            if (bp->flags & BP_GDB) {
                match_bp = true;
            } else if (bp->flags & BP_CPU) {
#ifdef CONFIG_USER_ONLY
                g_assert_not_reached();
#else
                CPUClass *cc = CPU_GET_CLASS(cpu);
                assert(cc->tcg_ops->debug_check_breakpoint);
                match_bp = cc->tcg_ops->debug_check_breakpoint(cpu);
#endif
            }

            if (match_bp) {
                cpu->exception_index = EXCP_DEBUG;
                return true;
            }
        } else if (((pc ^ bp->pc) & TARGET_PAGE_MASK) == 0) {
            match_page = true;
        }
    }

    /*
     * Within the same page as a breakpoint, single-step,
     * returning to helper_lookup_tb_ptr after each insn looking
     * for the actual breakpoint.
     *
     * TODO: Perhaps better to record all of the TBs associated
     * with a given virtual page that contains a breakpoint, and
     * then invalidate them when a new overlapping breakpoint is
     * set on the page.  Non-overlapping TBs would not be
     * invalidated, nor would any TB need to be invalidated as
     * breakpoints are removed.
     */
    if (match_page) {
        *cflags = (*cflags & ~CF_COUNT_MASK) | CF_NO_GOTO_TB | 1;
    }
    return false;
}

static inline bool check_for_breakpoints(CPUState *cpu, target_ulong pc,
                                         uint32_t *cflags)
{
    return unlikely(!QTAILQ_EMPTY(&cpu->breakpoints)) &&
        check_for_breakpoints_slow(cpu, pc, cflags);
}

const void *HELPER(lookup_tb_ptr)(CPUArchState *env)
{
    CPUState *cpu = env_cpu(env);
    TranslationBlock *tb;
    target_ulong cs_base, pc;
    uint32_t flags, cflags;

    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);

    cflags = curr_cflags(cpu);
    if (check_for_breakpoints(cpu, pc, &cflags)) {
        cpu_loop_exit(cpu);
    }

    tb = tb_lookup(cpu, pc, cs_base, flags, cflags);
    if (tb == NULL) {
        return tcg_code_gen_epilogue;
    }

    if (qemu_loglevel_mask(CPU_LOG_TB_CPU | CPU_LOG_EXEC)) {
        log_cpu_exec(pc, cpu, tb);
    }

    return tb->tc.ptr;
}

