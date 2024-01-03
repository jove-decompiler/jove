#define CONFIG_LINUX 1

#define CONFIG_USER_ONLY 1

#define HOST_BIG_ENDIAN (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)

#define QEMU_ALIGNED(X) __attribute__((aligned(X)))

#define ___4116N_ QEMU_ALIGNED(16)

#define ___4132N_ QEMU_ALIGNED(32)

#define container_of(ptr, type, member) ({                      \
        const typeof(((type *) 0)->member) *__mptr = (ptr);     \
        (type *) ((char *) __mptr - offsetof(type, member));})

#define QEMU_BUILD_BUG_ON_STRUCT(x) \
    struct { \
        int:(x) ? -1 : 1; \
    }

#define QEMU_BUILD_BUG_ON_ZERO(x) (sizeof(QEMU_BUILD_BUG_ON_STRUCT(x)) - \
                                   sizeof(QEMU_BUILD_BUG_ON_STRUCT(x)))

#include <stddef.h>

#include <stdbool.h>

#include <stdint.h>

#include <sys/types.h>

#include <stdio.h>

#include <string.h>

#include <limits.h>

#include <assert.h>

#include <setjmp.h>

#define G_GNUC_EXTENSION __extension__

#define G_GNUC_PRINTF( format_idx, arg_idx )    \
  __attribute__((__format__ (__printf__, format_idx, arg_idx)))

#define G_GNUC_UNUSED \
  __attribute__ ((__unused__))

#define G_GNUC_BEGIN_IGNORE_DEPRECATIONS \
  _Pragma("clang diagnostic push") \
  _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"")

#define G_GNUC_END_IGNORE_DEPRECATIONS \
  _Pragma("clang diagnostic pop")

#define G_STRFUNC     ((const char*) (__func__))

#define G_STMT_START  do

#define G_STMT_END    while (0)

# define G_NORETURN __attribute__ ((__noreturn__))

#define _G_BOOLEAN_EXPR(expr)                   \
 G_GNUC_EXTENSION ({                            \
   int _g_boolean_var_;                         \
   if (expr)                                    \
      _g_boolean_var_ = 1;                      \
   else                                         \
      _g_boolean_var_ = 0;                      \
   _g_boolean_var_;                             \
})

#define G_LIKELY(expr) (__builtin_expect (_G_BOOLEAN_EXPR(expr), 1))

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

#define g_assert(expr)                  G_STMT_START { \
                                             if G_LIKELY (expr) ; else \
                                               g_assertion_message_expr (G_LOG_DOMAIN, __FILE__, __LINE__, G_STRFUNC, \
                                                                         #expr); \
                                        } G_STMT_END

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

typedef struct VMChangeStateEntry VMChangeStateEntry;

typedef struct VMStateDescription VMStateDescription;

typedef struct IRQState *qemu_irq;

#define MAX(a, b)                                       \
    ({                                                  \
        typeof(1 ? (a) : (b)) _a = (a), _b = (b);       \
        _a > _b ? _a : _b;                              \
    })

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

#define QEMU_IS_ARRAY(x) (!__builtin_types_compatible_p(typeof(x), \
                                                        typeof(&(x)[0])))

#define ARRAY_SIZE(x) ((sizeof(x) / sizeof((x)[0])) + \
                       QEMU_BUILD_BUG_ON_ZERO(!QEMU_IS_ARRAY(x)))

#define KiB     (INT64_C(1) << 10)

#define MiB     (INT64_C(1) << 20)

#define tcg_enabled() (tcg_allowed)

static bool tcg_allowed = true;

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

typedef struct QTailQLink {
    void *tql_next;
    struct QTailQLink *tql_prev;
} QTailQLink;

typedef struct Int128 Int128;

struct Int128 {
#if HOST_BIG_ENDIAN
    int64_t hi;
    uint64_t lo;
#else
    uint64_t lo;
    int64_t hi;
#endif
};

static inline int clz128(Int128 a)
{
    if (a.hi) {
        return __builtin_clzll(a.hi);
    } else {
        return (a.lo) ? __builtin_clzll(a.lo) + 64 : 128;
    }
}

static inline int clz8(uint8_t val)
{
    return val ? __builtin_clz(val) - 24 : 8;
}

static inline int clz32(uint32_t val)
{
    return val ? __builtin_clz(val) : 32;
}

static inline int clz64(uint64_t val)
{
    return val ? __builtin_clzll(val) : 64;
}

static inline uint64_t pow2ceil(uint64_t value)
{
    int n = clz64(value - 1);

    if (!n) {
        /*
         * @value - 1 has no leading zeroes, thus @value - 1 >= 2^63
         * Therefore, either @value == 0 or @value > 2^63.
         * If it's 0, return 1, else return 0.
         */
        return !value;
    }
    return 0x8000000000000000ull >> (n - 1);
}

#define BITS_PER_BYTE           CHAR_BIT

#define BITS_TO_LONGS(nr)       DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))

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

#define TYPE_X86_CPU "i386-cpu"

OBJECT_DECLARE_CPU_TYPE(X86CPU, X86CPUClass, X86_CPU)

#define HV_SINT_COUNT                         16

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

#define HF_CPL_SHIFT         0

#define HF_MPX_EN_SHIFT     25

#define HF_AVX_EN_SHIFT     28

#define HF_CPL_MASK          (3 << HF_CPL_SHIFT)

#define HF_MPX_EN_MASK       (1 << HF_MPX_EN_SHIFT)

#define HF_AVX_EN_MASK       (1 << HF_AVX_EN_SHIFT)

#define HF2_MPX_PR_SHIFT         5

#define HF2_MPX_PR_MASK         (1 << HF2_MPX_PR_SHIFT)

#define CR4_OSXSAVE_MASK (1U << 18)

#define CR4_PKE_MASK   (1U << 22)

#define MCE_BANKS_DEF   10

#define MSR_MTRRcap_VCNT                8

#define MSR_P6_EVNTSEL0                 0x186

#define MSR_IA32_PERF_STATUS            0x198

#define MAX_RTIT_ADDRS                  8

#define XSTATE_FP_BIT                   0

#define XSTATE_SSE_BIT                  1

#define XSTATE_YMM_BIT                  2

#define XSTATE_BNDREGS_BIT              3

#define XSTATE_BNDCSR_BIT               4

#define XSTATE_OPMASK_BIT               5

#define XSTATE_ZMM_Hi256_BIT            6

#define XSTATE_Hi16_ZMM_BIT             7

#define XSTATE_PKRU_BIT                 9

#define XSTATE_ARCH_LBR_BIT             15

#define XSTATE_XTILE_CFG_BIT            17

#define XSTATE_XTILE_DATA_BIT           18

#define XSTATE_FP_MASK                  (1ULL << XSTATE_FP_BIT)

#define XSTATE_SSE_MASK                 (1ULL << XSTATE_SSE_BIT)

#define XSTATE_YMM_MASK                 (1ULL << XSTATE_YMM_BIT)

#define XSTATE_BNDREGS_MASK             (1ULL << XSTATE_BNDREGS_BIT)

#define XSTATE_BNDCSR_MASK              (1ULL << XSTATE_BNDCSR_BIT)

#define XSTATE_ARCH_LBR_MASK            (1ULL << XSTATE_ARCH_LBR_BIT)

#define ESA_FEATURE_ALIGN64_BIT         1

#define ESA_FEATURE_XFD_BIT             2

#define ESA_FEATURE_ALIGN64_MASK        (1U << ESA_FEATURE_ALIGN64_BIT)

#define ESA_FEATURE_XFD_MASK            (1U << ESA_FEATURE_XFD_BIT)

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

#define CPUID_HT (1U << 28)

#define CPUID_EXT_PDCM     (1U << 15)

#define CPUID_EXT_XSAVE    (1U << 26)

#define CPUID_EXT_OSXSAVE  (1U << 27)

#define CPUID_EXT_AVX      (1U << 28)

#define CPUID_EXT2_LM      (1U << 29)

#define CPUID_EXT3_SVM     (1U << 2)

#define CPUID_7_0_EBX_SGX               (1U << 2)

#define CPUID_7_0_EBX_MPX               (1U << 14)

#define CPUID_7_0_EBX_AVX512F           (1U << 16)

#define CPUID_7_0_EBX_INTEL_PT          (1U << 25)

#define CPUID_7_0_ECX_PKU               (1U << 3)

#define CPUID_7_0_ECX_OSPKE             (1U << 4)

#define CPUID_7_0_ECX_LA57              (1U << 16)

#define CPUID_7_0_ECX_SGX_LC            (1U << 30)

#define CPUID_7_0_EDX_ARCH_LBR          (1U << 19)

#define CPUID_7_0_EDX_AMX_TILE          (1U << 24)

#define CPUID_14_0_ECX_LIP              (1U << 31)

#define CPUID_XSAVE_XSAVES     (1U << 3)

#define CPUID_VENDOR_INTEL_1 0x756e6547

#define CPUID_VENDOR_INTEL_2 0x49656e69

#define CPUID_VENDOR_INTEL_3 0x6c65746e

#define CPUID_VENDOR_AMD_1   0x68747541

#define CPUID_VENDOR_AMD_2   0x69746e65

#define CPUID_VENDOR_AMD_3   0x444d4163

#define IS_AMD_CPU(env) ((env)->cpuid_vendor1 == CPUID_VENDOR_AMD_1 && \
                         (env)->cpuid_vendor2 == CPUID_VENDOR_AMD_2 && \
                         (env)->cpuid_vendor3 == CPUID_VENDOR_AMD_3)

#define CPUID_TOPOLOGY_LEVEL_INVALID  (0U << 8)

#define CPUID_TOPOLOGY_LEVEL_SMT      (1U << 8)

#define CPUID_TOPOLOGY_LEVEL_CORE     (2U << 8)

#define CPUID_TOPOLOGY_LEVEL_DIE      (5U << 8)

#define EXCP06_ILLOP	6

#define EXCP0D_GPF	13

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

#define BNDCFG_ENABLE       1ULL

#define BNDCFG_BNDPRESERVE  2ULL

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

typedef union X86LegacyXSaveArea {
    struct {
        uint16_t fcw;
        uint16_t fsw;
        uint8_t ftw;
        uint8_t reserved;
        uint16_t fpop;
        uint64_t fpip;
        uint64_t fpdp;
        uint32_t mxcsr;
        uint32_t mxcsr_mask;
        FPReg fpregs[8];
        uint8_t xmm_regs[16][16];
    };
    uint8_t data[512];
} X86LegacyXSaveArea;

typedef struct X86XSaveHeader {
    uint64_t xstate_bv;
    uint64_t xcomp_bv;
    uint64_t reserve0;
    uint8_t reserved[40];
} X86XSaveHeader;

typedef struct XSaveAVX {
    uint8_t ymmh[16][16];
} XSaveAVX;

typedef struct XSaveBNDREG {
    BNDReg bnd_regs[4];
} XSaveBNDREG;

typedef union XSaveBNDCSR {
    BNDCSReg bndcsr;
    uint8_t data[64];
} XSaveBNDCSR;

typedef struct XSaveOpmask {
    uint64_t opmask_regs[NB_OPMASK_REGS];
} XSaveOpmask;

typedef struct XSaveZMM_Hi256 {
    uint8_t zmm_hi256[16][32];
} XSaveZMM_Hi256;

typedef struct XSaveHi16_ZMM {
    uint8_t hi16_zmm[16][64];
} XSaveHi16_ZMM;

typedef struct XSavePKRU {
    uint32_t pkru;
    uint32_t padding;
} XSavePKRU;

typedef struct XSaveXTILECFG {
    uint8_t xtilecfg[64];
} XSaveXTILECFG;

typedef struct XSaveXTILEDATA {
    uint8_t xtiledata[8][1024];
} XSaveXTILEDATA;

#define ARCH_LBR_NR_ENTRIES            32

typedef struct {
       uint64_t from;
       uint64_t to;
       uint64_t info;
} LBREntry;

typedef struct XSavesArchLBR {
    uint64_t lbr_ctl;
    uint64_t lbr_depth;
    uint64_t ler_from;
    uint64_t ler_to;
    uint64_t ler_info;
    LBREntry lbr_records[ARCH_LBR_NR_ENTRIES];
} XSavesArchLBR;

#define XSAVE_STATE_AREA_COUNT (XSTATE_XTILE_DATA_BIT + 1)

typedef struct ExtSaveArea {
    uint32_t feature, bits;
    uint32_t offset, size;
    uint32_t ecx;
} ExtSaveArea;

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
    uint64_t pdptrs[4] ___4116N_;
    int32_t a20_mask;

    BNDReg bnd_regs[4] ___4116N_;
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

    float_status mmx_status ___4116N_; /* for 3DNow! float ops */
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
    uint64_t star ___4116N_;

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
    uint64_t msr_smi_count ___4116N_;

    uint32_t pkru;
    uint32_t pkrs;
    uint32_t tsx_ctrl;

    uint64_t spec_ctrl ___4116N_;
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
    } ___4132N_; /* break/watchpoints for dr[0..3] */
    int old_exception;  /* exception in flight */

    uint64_t vm_vmcb ___4116N_;
    uint64_t tsc_offset;
    uint64_t intercept;
    uint16_t intercept_cr_read;
    uint16_t intercept_cr_write;
    uint16_t intercept_dr_read;
    uint16_t intercept_dr_write;
    uint32_t intercept_exceptions;
    uint64_t nested_cr3 ___4116N_;
    uint32_t nested_pg_mode;
    uint8_t v_tpr;
    uint32_t int_ctl;

    /* KVM states, automatically cleared on reset */
    uint8_t nmi_injected;
    uint8_t nmi_pending;

    uintptr_t retaddr;

    /* Fields up to this point are cleared by a CPU reset */
    struct {} end_reset_fields ___4116N_;

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
    FeatureWordArray features ___4116N_;
    /* Features that were explicitly enabled/disabled */
    FeatureWordArray user_features;
    uint32_t cpuid_model[12];
    /* Cache information for CPUID.  When legacy-cache=on, the cache data
     * on each CPUID leaf will be different, because we keep compatibility
     * with old QEMU versions.
     */
    CPUCaches cache_info_cpuid2 ___4132N_, cache_info_cpuid4 ___4132N_, cache_info_amd ___4132N_;

    /* MTRRs */
    uint64_t mtrr_fixed[11] ___4132N_;
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
    uint64_t exception_payload ___4116N_;
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

void cpu_sync_bndcs_hflags(CPUX86State *env);

void cpu_x86_cpuid(CPUX86State *env, uint32_t index, uint32_t count,
                   uint32_t *eax, uint32_t *ebx,
                   uint32_t *ecx, uint32_t *edx);

void cpu_sync_avx_hflag(CPUX86State *env);

static inline ArchCPU *env_archcpu(CPUArchState *env)
{
    return container_of(env, ArchCPU, env);
}

static inline CPUState *env_cpu(CPUArchState *env)
{
    return &env_archcpu(env)->parent_obj;
}

G_NORETURN static inline void cpu_loop_exit_noexc(CPUState *cpu) {
  __builtin_trap();
  __builtin_unreachable();
}

# define GETPC() 0

inline G_NORETURN void raise_exception_ra(CPUX86State *env, int exception_index,
                                          uintptr_t retaddr) {
  __builtin_trap();
  __builtin_unreachable();
}

#define hvf_enabled() 0

#define hvf_get_supported_cpuid(func, idx, reg) 0

#define kvm_enabled()           (0)

typedef struct KVMState KVMState;

extern KVMState *kvm_state;

uint32_t kvm_arch_get_supported_cpuid(KVMState *env, uint32_t function,
                                      uint32_t index, int reg);

#define sev_enabled() 0

#define sev_es_enabled() 0

extern uint32_t sev_get_cbit_position(void);

extern uint32_t sev_get_reduced_phys_bits(void);

typedef uint32_t apic_id_t;

typedef struct X86CPUTopoIDs {
    unsigned pkg_id;
    unsigned die_id;
    unsigned core_id;
    unsigned smt_id;
} X86CPUTopoIDs;

typedef struct X86CPUTopoInfo {
    unsigned dies_per_pkg;
    unsigned cores_per_die;
    unsigned threads_per_core;
} X86CPUTopoInfo;

static unsigned apicid_bitwidth_for_count(unsigned count)
{
    g_assert(count >= 1);
    count -= 1;
    return count ? 32 - clz32(count) : 0;
}

static inline unsigned apicid_smt_width(X86CPUTopoInfo *topo_info)
{
    return apicid_bitwidth_for_count(topo_info->threads_per_core);
}

static inline unsigned apicid_core_width(X86CPUTopoInfo *topo_info)
{
    return apicid_bitwidth_for_count(topo_info->cores_per_die);
}

static inline unsigned apicid_die_width(X86CPUTopoInfo *topo_info)
{
    return apicid_bitwidth_for_count(topo_info->dies_per_pkg);
}

static inline unsigned apicid_core_offset(X86CPUTopoInfo *topo_info)
{
    return apicid_smt_width(topo_info);
}

static inline unsigned apicid_die_offset(X86CPUTopoInfo *topo_info)
{
    return apicid_core_offset(topo_info) + apicid_core_width(topo_info);
}

static inline unsigned apicid_pkg_offset(X86CPUTopoInfo *topo_info)
{
    return apicid_die_offset(topo_info) + apicid_die_width(topo_info);
}

static inline void x86_topo_ids_from_apicid(apic_id_t apicid,
                                            X86CPUTopoInfo *topo_info,
                                            X86CPUTopoIDs *topo_ids)
{
    topo_ids->smt_id = apicid &
            ~(0xFFFFFFFFUL << apicid_smt_width(topo_info));
    topo_ids->core_id =
            (apicid >> apicid_core_offset(topo_info)) &
            ~(0xFFFFFFFFUL << apicid_core_width(topo_info));
    topo_ids->die_id =
            (apicid >> apicid_die_offset(topo_info)) &
            ~(0xFFFFFFFFUL << apicid_die_width(topo_info));
    topo_ids->pkg_id = apicid >> apicid_pkg_offset(topo_info);
}

struct CPUID2CacheDescriptorInfo {
    enum CacheType type;
    int level;
    int size;
    int line_size;
    int associativity;
};

#define CACHE_DESCRIPTOR_UNAVAILABLE 0xFF

struct CPUID2CacheDescriptorInfo cpuid2_cache_descriptors[] = {
    [0x06] = { .level = 1, .type = INSTRUCTION_CACHE, .size =   8 * KiB,
               .associativity = 4,  .line_size = 32, },
    [0x08] = { .level = 1, .type = INSTRUCTION_CACHE, .size =  16 * KiB,
               .associativity = 4,  .line_size = 32, },
    [0x09] = { .level = 1, .type = INSTRUCTION_CACHE, .size =  32 * KiB,
               .associativity = 4,  .line_size = 64, },
    [0x0A] = { .level = 1, .type = DATA_CACHE,        .size =   8 * KiB,
               .associativity = 2,  .line_size = 32, },
    [0x0C] = { .level = 1, .type = DATA_CACHE,        .size =  16 * KiB,
               .associativity = 4,  .line_size = 32, },
    [0x0D] = { .level = 1, .type = DATA_CACHE,        .size =  16 * KiB,
               .associativity = 4,  .line_size = 64, },
    [0x0E] = { .level = 1, .type = DATA_CACHE,        .size =  24 * KiB,
               .associativity = 6,  .line_size = 64, },
    [0x1D] = { .level = 2, .type = UNIFIED_CACHE,     .size = 128 * KiB,
               .associativity = 2,  .line_size = 64, },
    [0x21] = { .level = 2, .type = UNIFIED_CACHE,     .size = 256 * KiB,
               .associativity = 8,  .line_size = 64, },
    /* lines per sector is not supported cpuid2_cache_descriptor(),
    * so descriptors 0x22, 0x23 are not included
    */
    [0x24] = { .level = 2, .type = UNIFIED_CACHE,     .size =   1 * MiB,
               .associativity = 16, .line_size = 64, },
    /* lines per sector is not supported cpuid2_cache_descriptor(),
    * so descriptors 0x25, 0x20 are not included
    */
    [0x2C] = { .level = 1, .type = DATA_CACHE,        .size =  32 * KiB,
               .associativity = 8,  .line_size = 64, },
    [0x30] = { .level = 1, .type = INSTRUCTION_CACHE, .size =  32 * KiB,
               .associativity = 8,  .line_size = 64, },
    [0x41] = { .level = 2, .type = UNIFIED_CACHE,     .size = 128 * KiB,
               .associativity = 4,  .line_size = 32, },
    [0x42] = { .level = 2, .type = UNIFIED_CACHE,     .size = 256 * KiB,
               .associativity = 4,  .line_size = 32, },
    [0x43] = { .level = 2, .type = UNIFIED_CACHE,     .size = 512 * KiB,
               .associativity = 4,  .line_size = 32, },
    [0x44] = { .level = 2, .type = UNIFIED_CACHE,     .size =   1 * MiB,
               .associativity = 4,  .line_size = 32, },
    [0x45] = { .level = 2, .type = UNIFIED_CACHE,     .size =   2 * MiB,
               .associativity = 4,  .line_size = 32, },
    [0x46] = { .level = 3, .type = UNIFIED_CACHE,     .size =   4 * MiB,
               .associativity = 4,  .line_size = 64, },
    [0x47] = { .level = 3, .type = UNIFIED_CACHE,     .size =   8 * MiB,
               .associativity = 8,  .line_size = 64, },
    [0x48] = { .level = 2, .type = UNIFIED_CACHE,     .size =   3 * MiB,
               .associativity = 12, .line_size = 64, },
    /* Descriptor 0x49 depends on CPU family/model, so it is not included */
    [0x4A] = { .level = 3, .type = UNIFIED_CACHE,     .size =   6 * MiB,
               .associativity = 12, .line_size = 64, },
    [0x4B] = { .level = 3, .type = UNIFIED_CACHE,     .size =   8 * MiB,
               .associativity = 16, .line_size = 64, },
    [0x4C] = { .level = 3, .type = UNIFIED_CACHE,     .size =  12 * MiB,
               .associativity = 12, .line_size = 64, },
    [0x4D] = { .level = 3, .type = UNIFIED_CACHE,     .size =  16 * MiB,
               .associativity = 16, .line_size = 64, },
    [0x4E] = { .level = 2, .type = UNIFIED_CACHE,     .size =   6 * MiB,
               .associativity = 24, .line_size = 64, },
    [0x60] = { .level = 1, .type = DATA_CACHE,        .size =  16 * KiB,
               .associativity = 8,  .line_size = 64, },
    [0x66] = { .level = 1, .type = DATA_CACHE,        .size =   8 * KiB,
               .associativity = 4,  .line_size = 64, },
    [0x67] = { .level = 1, .type = DATA_CACHE,        .size =  16 * KiB,
               .associativity = 4,  .line_size = 64, },
    [0x68] = { .level = 1, .type = DATA_CACHE,        .size =  32 * KiB,
               .associativity = 4,  .line_size = 64, },
    [0x78] = { .level = 2, .type = UNIFIED_CACHE,     .size =   1 * MiB,
               .associativity = 4,  .line_size = 64, },
    /* lines per sector is not supported cpuid2_cache_descriptor(),
    * so descriptors 0x79, 0x7A, 0x7B, 0x7C are not included.
    */
    [0x7D] = { .level = 2, .type = UNIFIED_CACHE,     .size =   2 * MiB,
               .associativity = 8,  .line_size = 64, },
    [0x7F] = { .level = 2, .type = UNIFIED_CACHE,     .size = 512 * KiB,
               .associativity = 2,  .line_size = 64, },
    [0x80] = { .level = 2, .type = UNIFIED_CACHE,     .size = 512 * KiB,
               .associativity = 8,  .line_size = 64, },
    [0x82] = { .level = 2, .type = UNIFIED_CACHE,     .size = 256 * KiB,
               .associativity = 8,  .line_size = 32, },
    [0x83] = { .level = 2, .type = UNIFIED_CACHE,     .size = 512 * KiB,
               .associativity = 8,  .line_size = 32, },
    [0x84] = { .level = 2, .type = UNIFIED_CACHE,     .size =   1 * MiB,
               .associativity = 8,  .line_size = 32, },
    [0x85] = { .level = 2, .type = UNIFIED_CACHE,     .size =   2 * MiB,
               .associativity = 8,  .line_size = 32, },
    [0x86] = { .level = 2, .type = UNIFIED_CACHE,     .size = 512 * KiB,
               .associativity = 4,  .line_size = 64, },
    [0x87] = { .level = 2, .type = UNIFIED_CACHE,     .size =   1 * MiB,
               .associativity = 8,  .line_size = 64, },
    [0xD0] = { .level = 3, .type = UNIFIED_CACHE,     .size = 512 * KiB,
               .associativity = 4,  .line_size = 64, },
    [0xD1] = { .level = 3, .type = UNIFIED_CACHE,     .size =   1 * MiB,
               .associativity = 4,  .line_size = 64, },
    [0xD2] = { .level = 3, .type = UNIFIED_CACHE,     .size =   2 * MiB,
               .associativity = 4,  .line_size = 64, },
    [0xD6] = { .level = 3, .type = UNIFIED_CACHE,     .size =   1 * MiB,
               .associativity = 8,  .line_size = 64, },
    [0xD7] = { .level = 3, .type = UNIFIED_CACHE,     .size =   2 * MiB,
               .associativity = 8,  .line_size = 64, },
    [0xD8] = { .level = 3, .type = UNIFIED_CACHE,     .size =   4 * MiB,
               .associativity = 8,  .line_size = 64, },
    [0xDC] = { .level = 3, .type = UNIFIED_CACHE,     .size = 1.5 * MiB,
               .associativity = 12, .line_size = 64, },
    [0xDD] = { .level = 3, .type = UNIFIED_CACHE,     .size =   3 * MiB,
               .associativity = 12, .line_size = 64, },
    [0xDE] = { .level = 3, .type = UNIFIED_CACHE,     .size =   6 * MiB,
               .associativity = 12, .line_size = 64, },
    [0xE2] = { .level = 3, .type = UNIFIED_CACHE,     .size =   2 * MiB,
               .associativity = 16, .line_size = 64, },
    [0xE3] = { .level = 3, .type = UNIFIED_CACHE,     .size =   4 * MiB,
               .associativity = 16, .line_size = 64, },
    [0xE4] = { .level = 3, .type = UNIFIED_CACHE,     .size =   8 * MiB,
               .associativity = 16, .line_size = 64, },
    [0xEA] = { .level = 3, .type = UNIFIED_CACHE,     .size =  12 * MiB,
               .associativity = 24, .line_size = 64, },
    [0xEB] = { .level = 3, .type = UNIFIED_CACHE,     .size =  18 * MiB,
               .associativity = 24, .line_size = 64, },
    [0xEC] = { .level = 3, .type = UNIFIED_CACHE,     .size =  24 * MiB,
               .associativity = 24, .line_size = 64, },
};

#define CACHE_TYPE_D    1

#define CACHE_TYPE_I    2

#define CACHE_TYPE_UNIFIED   3

#define CACHE_LEVEL(l)        (l << 5)

#define CACHE_SELF_INIT_LEVEL (1 << 8)

#define CACHE_NO_INVD_SHARING   (1 << 0)

#define CACHE_INCLUSIVE       (1 << 1)

#define CACHE_COMPLEX_IDX     (1 << 2)

#define CACHE_TYPE(t) (((t) == DATA_CACHE) ? CACHE_TYPE_D : \
                       ((t) == INSTRUCTION_CACHE) ? CACHE_TYPE_I : \
                       ((t) == UNIFIED_CACHE) ? CACHE_TYPE_UNIFIED : \
                       0 /* Invalid value */)

static uint8_t cpuid2_cache_descriptor(CPUCacheInfo *cache)
{
    int i;

    assert(cache->size > 0);
    assert(cache->level > 0);
    assert(cache->line_size > 0);
    assert(cache->associativity > 0);
    for (i = 0; i < ARRAY_SIZE(cpuid2_cache_descriptors); i++) {
        struct CPUID2CacheDescriptorInfo *d = &cpuid2_cache_descriptors[i];
        if (d->level == cache->level && d->type == cache->type &&
            d->size == cache->size && d->line_size == cache->line_size &&
            d->associativity == cache->associativity) {
                return i;
            }
    }

    return CACHE_DESCRIPTOR_UNAVAILABLE;
}

static void encode_cache_cpuid4(CPUCacheInfo *cache,
                                int num_apic_ids, int num_cores,
                                uint32_t *eax, uint32_t *ebx,
                                uint32_t *ecx, uint32_t *edx)
{
    assert(cache->size == cache->line_size * cache->associativity *
                          cache->partitions * cache->sets);

    assert(num_apic_ids > 0);
    *eax = CACHE_TYPE(cache->type) |
           CACHE_LEVEL(cache->level) |
           (cache->self_init ? CACHE_SELF_INIT_LEVEL : 0) |
           ((num_cores - 1) << 26) |
           ((num_apic_ids - 1) << 14);

    assert(cache->line_size > 0);
    assert(cache->partitions > 0);
    assert(cache->associativity > 0);
    /* We don't implement fully-associative caches */
    assert(cache->associativity < cache->sets);
    *ebx = (cache->line_size - 1) |
           ((cache->partitions - 1) << 12) |
           ((cache->associativity - 1) << 22);

    assert(cache->sets > 0);
    *ecx = cache->sets - 1;

    *edx = (cache->no_invd_sharing ? CACHE_NO_INVD_SHARING : 0) |
           (cache->inclusive ? CACHE_INCLUSIVE : 0) |
           (cache->complex_indexing ? CACHE_COMPLEX_IDX : 0);
}

#define ASSOC_FULL 0xFF

#define AMD_ENC_ASSOC(a) (a <=   1 ? a   : \
                          a ==   2 ? 0x2 : \
                          a ==   4 ? 0x4 : \
                          a ==   8 ? 0x6 : \
                          a ==  16 ? 0x8 : \
                          a ==  32 ? 0xA : \
                          a ==  48 ? 0xB : \
                          a ==  64 ? 0xC : \
                          a ==  96 ? 0xD : \
                          a == 128 ? 0xE : \
                          a == ASSOC_FULL ? 0xF : \
                          0 /* invalid value */)

static uint32_t encode_cache_cpuid80000005(CPUCacheInfo *cache)
{
    assert(cache->size % 1024 == 0);
    assert(cache->lines_per_tag > 0);
    assert(cache->associativity > 0);
    assert(cache->line_size > 0);
    return ((cache->size / 1024) << 24) | (cache->associativity << 16) |
           (cache->lines_per_tag << 8) | (cache->line_size);
}

static void encode_cache_cpuid80000006(CPUCacheInfo *l2,
                                       CPUCacheInfo *l3,
                                       uint32_t *ecx, uint32_t *edx)
{
    assert(l2->size % 1024 == 0);
    assert(l2->associativity > 0);
    assert(l2->lines_per_tag > 0);
    assert(l2->line_size > 0);
    *ecx = ((l2->size / 1024) << 16) |
           (AMD_ENC_ASSOC(l2->associativity) << 12) |
           (l2->lines_per_tag << 8) | (l2->line_size);

    if (l3) {
        assert(l3->size % (512 * 1024) == 0);
        assert(l3->associativity > 0);
        assert(l3->lines_per_tag > 0);
        assert(l3->line_size > 0);
        *edx = ((l3->size / (512 * 1024)) << 18) |
               (AMD_ENC_ASSOC(l3->associativity) << 12) |
               (l3->lines_per_tag << 8) | (l3->line_size);
    } else {
        *edx = 0;
    }
}

static void encode_cache_cpuid8000001d(CPUCacheInfo *cache,
                                       X86CPUTopoInfo *topo_info,
                                       uint32_t *eax, uint32_t *ebx,
                                       uint32_t *ecx, uint32_t *edx)
{
    uint32_t l3_threads;
    assert(cache->size == cache->line_size * cache->associativity *
                          cache->partitions * cache->sets);

    *eax = CACHE_TYPE(cache->type) | CACHE_LEVEL(cache->level) |
               (cache->self_init ? CACHE_SELF_INIT_LEVEL : 0);

    /* L3 is shared among multiple cores */
    if (cache->level == 3) {
        l3_threads = topo_info->cores_per_die * topo_info->threads_per_core;
        *eax |= (l3_threads - 1) << 14;
    } else {
        *eax |= ((topo_info->threads_per_core - 1) << 14);
    }

    assert(cache->line_size > 0);
    assert(cache->partitions > 0);
    assert(cache->associativity > 0);
    /* We don't implement fully-associative caches */
    assert(cache->associativity < cache->sets);
    *ebx = (cache->line_size - 1) |
           ((cache->partitions - 1) << 12) |
           ((cache->associativity - 1) << 22);

    assert(cache->sets > 0);
    *ecx = cache->sets - 1;

    *edx = (cache->no_invd_sharing ? CACHE_NO_INVD_SHARING : 0) |
           (cache->inclusive ? CACHE_INCLUSIVE : 0) |
           (cache->complex_indexing ? CACHE_COMPLEX_IDX : 0);
}

static void encode_topo_cpuid8000001e(X86CPU *cpu, X86CPUTopoInfo *topo_info,
                                      uint32_t *eax, uint32_t *ebx,
                                      uint32_t *ecx, uint32_t *edx)
{
    X86CPUTopoIDs topo_ids;

    x86_topo_ids_from_apicid(cpu->apic_id, topo_info, &topo_ids);

    *eax = cpu->apic_id;

    /*
     * CPUID_Fn8000001E_EBX [Core Identifiers] (CoreId)
     * Read-only. Reset: 0000_XXXXh.
     * See Core::X86::Cpuid::ExtApicId.
     * Core::X86::Cpuid::CoreId_lthree[1:0]_core[3:0]_thread[1:0];
     * Bits Description
     * 31:16 Reserved.
     * 15:8 ThreadsPerCore: threads per core. Read-only. Reset: XXh.
     *      The number of threads per core is ThreadsPerCore+1.
     *  7:0 CoreId: core ID. Read-only. Reset: XXh.
     *
     *  NOTE: CoreId is already part of apic_id. Just use it. We can
     *  use all the 8 bits to represent the core_id here.
     */
    *ebx = ((topo_info->threads_per_core - 1) << 8) | (topo_ids.core_id & 0xFF);

    /*
     * CPUID_Fn8000001E_ECX [Node Identifiers] (NodeId)
     * Read-only. Reset: 0000_0XXXh.
     * Core::X86::Cpuid::NodeId_lthree[1:0]_core[3:0]_thread[1:0];
     * Bits Description
     * 31:11 Reserved.
     * 10:8 NodesPerProcessor: Node per processor. Read-only. Reset: XXXb.
     *      ValidValues:
     *      Value Description
     *      000b  1 node per processor.
     *      001b  2 nodes per processor.
     *      010b Reserved.
     *      011b 4 nodes per processor.
     *      111b-100b Reserved.
     *  7:0 NodeId: Node ID. Read-only. Reset: XXh.
     *
     * NOTE: Hardware reserves 3 bits for number of nodes per processor.
     * But users can create more nodes than the actual hardware can
     * support. To genaralize we can use all the upper 8 bits for nodes.
     * NodeId is combination of node and socket_id which is already decoded
     * in apic_id. Just use it by shifting.
     */
    *ecx = ((topo_info->dies_per_pkg - 1) << 8) |
           ((cpu->apic_id >> apicid_die_offset(topo_info)) & 0xFF);

    *edx = 0;
}

#define L1_DTLB_2M_ASSOC       1

#define L1_DTLB_2M_ENTRIES   255

#define L1_DTLB_4K_ASSOC       1

#define L1_DTLB_4K_ENTRIES   255

#define L1_ITLB_2M_ASSOC       1

#define L1_ITLB_2M_ENTRIES   255

#define L1_ITLB_4K_ASSOC       1

#define L1_ITLB_4K_ENTRIES   255

#define L2_DTLB_2M_ASSOC       0

#define L2_DTLB_2M_ENTRIES     0

#define L2_DTLB_4K_ASSOC       4

#define L2_DTLB_4K_ENTRIES   512

#define L2_ITLB_2M_ASSOC       0

#define L2_ITLB_2M_ENTRIES     0

#define L2_ITLB_4K_ASSOC       4

#define L2_ITLB_4K_ENTRIES   512

#define INTEL_PT_MAX_SUBLEAF     0x1

#define INTEL_PT_MINIMAL_EBX     0xf

#define INTEL_PT_MINIMAL_ECX     0x7

#define INTEL_PT_ADDR_RANGES_NUM 0x2

#define INTEL_PT_MTC_BITMAP      (0x0249 << 16)

#define INTEL_PT_CYCLE_BITMAP    0x1fff

#define INTEL_PT_PSB_BITMAP      (0x003f << 16)

#define INTEL_AMX_TILE_MAX_SUBLEAF     0x1

#define INTEL_AMX_TOTAL_TILE_BYTES     0x2000

#define INTEL_AMX_BYTES_PER_TILE       0x400

#define INTEL_AMX_BYTES_PER_ROW        0x40

#define INTEL_AMX_TILE_MAX_NAMES       0x8

#define INTEL_AMX_TILE_MAX_ROWS        0x10

#define INTEL_AMX_TMUL_MAX_K           0x10

#define INTEL_AMX_TMUL_MAX_N           0x40

ExtSaveArea x86_ext_save_areas[XSAVE_STATE_AREA_COUNT] = {
    [XSTATE_FP_BIT] = {
        /* x87 FP state component is always enabled if XSAVE is supported */
        .feature = FEAT_1_ECX, .bits = CPUID_EXT_XSAVE,
        .size = sizeof(X86LegacyXSaveArea) + sizeof(X86XSaveHeader),
    },
    [XSTATE_SSE_BIT] = {
        /* SSE state component is always enabled if XSAVE is supported */
        .feature = FEAT_1_ECX, .bits = CPUID_EXT_XSAVE,
        .size = sizeof(X86LegacyXSaveArea) + sizeof(X86XSaveHeader),
    },
    [XSTATE_YMM_BIT] =
          { .feature = FEAT_1_ECX, .bits = CPUID_EXT_AVX,
            .size = sizeof(XSaveAVX) },
    [XSTATE_BNDREGS_BIT] =
          { .feature = FEAT_7_0_EBX, .bits = CPUID_7_0_EBX_MPX,
            .size = sizeof(XSaveBNDREG)  },
    [XSTATE_BNDCSR_BIT] =
          { .feature = FEAT_7_0_EBX, .bits = CPUID_7_0_EBX_MPX,
            .size = sizeof(XSaveBNDCSR)  },
    [XSTATE_OPMASK_BIT] =
          { .feature = FEAT_7_0_EBX, .bits = CPUID_7_0_EBX_AVX512F,
            .size = sizeof(XSaveOpmask) },
    [XSTATE_ZMM_Hi256_BIT] =
          { .feature = FEAT_7_0_EBX, .bits = CPUID_7_0_EBX_AVX512F,
            .size = sizeof(XSaveZMM_Hi256) },
    [XSTATE_Hi16_ZMM_BIT] =
          { .feature = FEAT_7_0_EBX, .bits = CPUID_7_0_EBX_AVX512F,
            .size = sizeof(XSaveHi16_ZMM) },
    [XSTATE_PKRU_BIT] =
          { .feature = FEAT_7_0_ECX, .bits = CPUID_7_0_ECX_PKU,
            .size = sizeof(XSavePKRU) },
    [XSTATE_ARCH_LBR_BIT] = {
            .feature = FEAT_7_0_EDX, .bits = CPUID_7_0_EDX_ARCH_LBR,
            .offset = 0 /*supervisor mode component, offset = 0 */,
            .size = sizeof(XSavesArchLBR) },
    [XSTATE_XTILE_CFG_BIT] = {
        .feature = FEAT_7_0_EDX, .bits = CPUID_7_0_EDX_AMX_TILE,
        .size = sizeof(XSaveXTILECFG),
    },
    [XSTATE_XTILE_DATA_BIT] = {
        .feature = FEAT_7_0_EDX, .bits = CPUID_7_0_EDX_AMX_TILE,
        .size = sizeof(XSaveXTILEDATA)
    },
};

uint32_t xsave_area_size(uint64_t mask, bool compacted)
{
    uint64_t ret = x86_ext_save_areas[0].size;
    const ExtSaveArea *esa;
    uint32_t offset = 0;
    int i;

    for (i = 2; i < ARRAY_SIZE(x86_ext_save_areas); i++) {
        esa = &x86_ext_save_areas[i];
        if ((mask >> i) & 1) {
            offset = compacted ? ret : esa->offset;
            ret = MAX(ret, offset + esa->size);
        }
    }
    return ret;
}

static inline bool accel_uses_host_cpuid(void)
{
    return kvm_enabled() || hvf_enabled();
}

static inline uint64_t x86_cpu_xsave_xcr0_components(X86CPU *cpu)
{
    return ((uint64_t)cpu->env.features[FEAT_XSAVE_XCR0_HI]) << 32 |
           cpu->env.features[FEAT_XSAVE_XCR0_LO];
}

static inline uint64_t x86_cpu_xsave_xss_components(X86CPU *cpu)
{
    return ((uint64_t)cpu->env.features[FEAT_XSAVE_XSS_HI]) << 32 |
           cpu->env.features[FEAT_XSAVE_XSS_LO];
}

void host_cpuid(uint32_t function, uint32_t count,
                uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
    uint32_t vec[4];

#ifdef __x86_64__
    asm volatile("cpuid"
                 : "=a"(vec[0]), "=b"(vec[1]),
                   "=c"(vec[2]), "=d"(vec[3])
                 : "0"(function), "c"(count) : "cc");
#elif defined(__i386__)
    asm volatile("pusha \n\t"
                 "cpuid \n\t"
                 "mov %%eax, 0(%2) \n\t"
                 "mov %%ebx, 4(%2) \n\t"
                 "mov %%ecx, 8(%2) \n\t"
                 "mov %%edx, 12(%2) \n\t"
                 "popa"
                 : : "a"(function), "c"(count), "S"(vec)
                 : "memory", "cc");
#else
    abort();
#endif

    if (eax)
        *eax = vec[0];
    if (ebx)
        *ebx = vec[1];
    if (ecx)
        *ecx = vec[2];
    if (edx)
        *edx = vec[3];
}

static void x86_cpu_get_supported_cpuid(uint32_t func, uint32_t index,
                                        uint32_t *eax, uint32_t *ebx,
                                        uint32_t *ecx, uint32_t *edx)
{
    if (kvm_enabled()) {
        *eax = kvm_arch_get_supported_cpuid(kvm_state, func, index, R_EAX);
        *ebx = kvm_arch_get_supported_cpuid(kvm_state, func, index, R_EBX);
        *ecx = kvm_arch_get_supported_cpuid(kvm_state, func, index, R_ECX);
        *edx = kvm_arch_get_supported_cpuid(kvm_state, func, index, R_EDX);
    } else if (hvf_enabled()) {
        *eax = hvf_get_supported_cpuid(func, index, R_EAX);
        *ebx = hvf_get_supported_cpuid(func, index, R_EBX);
        *ecx = hvf_get_supported_cpuid(func, index, R_ECX);
        *edx = hvf_get_supported_cpuid(func, index, R_EDX);
    } else {
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
    }
}

static void x86_cpu_get_cache_cpuid(uint32_t func, uint32_t index,
                                    uint32_t *eax, uint32_t *ebx,
                                    uint32_t *ecx, uint32_t *edx)
{
    uint32_t level, unused;

    /* Only return valid host leaves.  */
    switch (func) {
    case 2:
    case 4:
        host_cpuid(0, 0, &level, &unused, &unused, &unused);
        break;
    case 0x80000005:
    case 0x80000006:
    case 0x8000001d:
        host_cpuid(0x80000000, 0, &level, &unused, &unused, &unused);
        break;
    default:
        return;
    }

    if (func > level) {
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
    } else {
        host_cpuid(func, index, eax, ebx, ecx, edx);
    }
}

uint32_t cpu_x86_virtual_addr_width(CPUX86State *env)
{
    if  (env->features[FEAT_7_0_ECX] & CPUID_7_0_ECX_LA57) {
        return 57; /* 57 bits virtual */
    } else {
        return 48; /* 48 bits virtual */
    }
}

void cpu_x86_cpuid(CPUX86State *env, uint32_t index, uint32_t count,
                   uint32_t *eax, uint32_t *ebx,
                   uint32_t *ecx, uint32_t *edx)
{
    X86CPU *cpu = env_archcpu(env);
    CPUState *cs = env_cpu(env);
    uint32_t die_offset;
    uint32_t limit;
    uint32_t signature[3];
    X86CPUTopoInfo topo_info;

    topo_info.dies_per_pkg = env->nr_dies;
    topo_info.cores_per_die = cs->nr_cores;
    topo_info.threads_per_core = cs->nr_threads;

    /* Calculate & apply limits for different index ranges */
    if (index >= 0xC0000000) {
        limit = env->cpuid_xlevel2;
    } else if (index >= 0x80000000) {
        limit = env->cpuid_xlevel;
    } else if (index >= 0x40000000) {
        limit = 0x40000001;
    } else {
        limit = env->cpuid_level;
    }

    if (index > limit) {
        /* Intel documentation states that invalid EAX input will
         * return the same information as EAX=cpuid_level
         * (Intel SDM Vol. 2A - Instruction Set Reference - CPUID)
         */
        index = env->cpuid_level;
    }

    switch(index) {
    case 0:
        *eax = env->cpuid_level;
        *ebx = env->cpuid_vendor1;
        *edx = env->cpuid_vendor2;
        *ecx = env->cpuid_vendor3;
        break;
    case 1:
        *eax = env->cpuid_version;
        *ebx = (cpu->apic_id << 24) |
               8 << 8; /* CLFLUSH size in quad words, Linux wants it. */
        *ecx = env->features[FEAT_1_ECX];
        if ((*ecx & CPUID_EXT_XSAVE) && (env->cr[4] & CR4_OSXSAVE_MASK)) {
            *ecx |= CPUID_EXT_OSXSAVE;
        }
        *edx = env->features[FEAT_1_EDX];
        if (cs->nr_cores * cs->nr_threads > 1) {
            *ebx |= (cs->nr_cores * cs->nr_threads) << 16;
            *edx |= CPUID_HT;
        }
        if (!cpu->enable_pmu) {
            *ecx &= ~CPUID_EXT_PDCM;
        }
        break;
    case 2:
        /* cache info: needed for Pentium Pro compatibility */
        if (cpu->cache_info_passthrough) {
            x86_cpu_get_cache_cpuid(index, 0, eax, ebx, ecx, edx);
            break;
        } else if (cpu->vendor_cpuid_only && IS_AMD_CPU(env)) {
            *eax = *ebx = *ecx = *edx = 0;
            break;
        }
        *eax = 1; /* Number of CPUID[EAX=2] calls required */
        *ebx = 0;
        if (!cpu->enable_l3_cache) {
            *ecx = 0;
        } else {
            *ecx = cpuid2_cache_descriptor(env->cache_info_cpuid2.l3_cache);
        }
        *edx = (cpuid2_cache_descriptor(env->cache_info_cpuid2.l1d_cache) << 16) |
               (cpuid2_cache_descriptor(env->cache_info_cpuid2.l1i_cache) <<  8) |
               (cpuid2_cache_descriptor(env->cache_info_cpuid2.l2_cache));
        break;
    case 4:
        /* cache info: needed for Core compatibility */
        if (cpu->cache_info_passthrough) {
            x86_cpu_get_cache_cpuid(index, count, eax, ebx, ecx, edx);
            /*
             * QEMU has its own number of cores/logical cpus,
             * set 24..14, 31..26 bit to configured values
             */
            if (*eax & 31) {
                int host_vcpus_per_cache = 1 + ((*eax & 0x3FFC000) >> 14);
                int vcpus_per_socket = env->nr_dies * cs->nr_cores *
                                       cs->nr_threads;
                if (cs->nr_cores > 1) {
                    *eax &= ~0xFC000000;
                    *eax |= (pow2ceil(cs->nr_cores) - 1) << 26;
                }
                if (host_vcpus_per_cache > vcpus_per_socket) {
                    *eax &= ~0x3FFC000;
                    *eax |= (pow2ceil(vcpus_per_socket) - 1) << 14;
                }
            }
        } else if (cpu->vendor_cpuid_only && IS_AMD_CPU(env)) {
            *eax = *ebx = *ecx = *edx = 0;
        } else {
            *eax = 0;
            switch (count) {
            case 0: /* L1 dcache info */
                encode_cache_cpuid4(env->cache_info_cpuid4.l1d_cache,
                                    1, cs->nr_cores,
                                    eax, ebx, ecx, edx);
                break;
            case 1: /* L1 icache info */
                encode_cache_cpuid4(env->cache_info_cpuid4.l1i_cache,
                                    1, cs->nr_cores,
                                    eax, ebx, ecx, edx);
                break;
            case 2: /* L2 cache info */
                encode_cache_cpuid4(env->cache_info_cpuid4.l2_cache,
                                    cs->nr_threads, cs->nr_cores,
                                    eax, ebx, ecx, edx);
                break;
            case 3: /* L3 cache info */
                die_offset = apicid_die_offset(&topo_info);
                if (cpu->enable_l3_cache) {
                    encode_cache_cpuid4(env->cache_info_cpuid4.l3_cache,
                                        (1 << die_offset), cs->nr_cores,
                                        eax, ebx, ecx, edx);
                    break;
                }
                /* fall through */
            default: /* end of info */
                *eax = *ebx = *ecx = *edx = 0;
                break;
            }
        }
        break;
    case 5:
        /* MONITOR/MWAIT Leaf */
        *eax = cpu->mwait.eax; /* Smallest monitor-line size in bytes */
        *ebx = cpu->mwait.ebx; /* Largest monitor-line size in bytes */
        *ecx = cpu->mwait.ecx; /* flags */
        *edx = cpu->mwait.edx; /* mwait substates */
        break;
    case 6:
        /* Thermal and Power Leaf */
        *eax = env->features[FEAT_6_EAX];
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    case 7:
        /* Structured Extended Feature Flags Enumeration Leaf */
        if (count == 0) {
            /* Maximum ECX value for sub-leaves */
            *eax = env->cpuid_level_func7;
            *ebx = env->features[FEAT_7_0_EBX]; /* Feature flags */
            *ecx = env->features[FEAT_7_0_ECX]; /* Feature flags */
            if ((*ecx & CPUID_7_0_ECX_PKU) && env->cr[4] & CR4_PKE_MASK) {
                *ecx |= CPUID_7_0_ECX_OSPKE;
            }
            *edx = env->features[FEAT_7_0_EDX]; /* Feature flags */

            /*
             * SGX cannot be emulated in software.  If hardware does not
             * support enabling SGX and/or SGX flexible launch control,
             * then we need to update the VM's CPUID values accordingly.
             */
            if ((*ebx & CPUID_7_0_EBX_SGX) &&
                (!kvm_enabled() ||
                 !(kvm_arch_get_supported_cpuid(cs->kvm_state, 0x7, 0, R_EBX) &
                    CPUID_7_0_EBX_SGX))) {
                *ebx &= ~CPUID_7_0_EBX_SGX;
            }

            if ((*ecx & CPUID_7_0_ECX_SGX_LC) &&
                (!(*ebx & CPUID_7_0_EBX_SGX) || !kvm_enabled() ||
                 !(kvm_arch_get_supported_cpuid(cs->kvm_state, 0x7, 0, R_ECX) &
                    CPUID_7_0_ECX_SGX_LC))) {
                *ecx &= ~CPUID_7_0_ECX_SGX_LC;
            }
        } else if (count == 1) {
            *eax = env->features[FEAT_7_1_EAX];
            *edx = env->features[FEAT_7_1_EDX];
            *ebx = 0;
            *ecx = 0;
        } else {
            *eax = 0;
            *ebx = 0;
            *ecx = 0;
            *edx = 0;
        }
        break;
    case 9:
        /* Direct Cache Access Information Leaf */
        *eax = 0; /* Bits 0-31 in DCA_CAP MSR */
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    case 0xA:
        /* Architectural Performance Monitoring Leaf */
        if (accel_uses_host_cpuid() && cpu->enable_pmu) {
            x86_cpu_get_supported_cpuid(0xA, count, eax, ebx, ecx, edx);
        } else {
            *eax = 0;
            *ebx = 0;
            *ecx = 0;
            *edx = 0;
        }
        break;
    case 0xB:
        /* Extended Topology Enumeration Leaf */
        if (!cpu->enable_cpuid_0xb) {
                *eax = *ebx = *ecx = *edx = 0;
                break;
        }

        *ecx = count & 0xff;
        *edx = cpu->apic_id;

        switch (count) {
        case 0:
            *eax = apicid_core_offset(&topo_info);
            *ebx = cs->nr_threads;
            *ecx |= CPUID_TOPOLOGY_LEVEL_SMT;
            break;
        case 1:
            *eax = apicid_pkg_offset(&topo_info);
            *ebx = cs->nr_cores * cs->nr_threads;
            *ecx |= CPUID_TOPOLOGY_LEVEL_CORE;
            break;
        default:
            *eax = 0;
            *ebx = 0;
            *ecx |= CPUID_TOPOLOGY_LEVEL_INVALID;
        }

        assert(!(*eax & ~0x1f));
        *ebx &= 0xffff; /* The count doesn't need to be reliable. */
        break;
    case 0x1C:
        if (accel_uses_host_cpuid() && cpu->enable_pmu &&
            (env->features[FEAT_7_0_EDX] & CPUID_7_0_EDX_ARCH_LBR)) {
            x86_cpu_get_supported_cpuid(0x1C, 0, eax, ebx, ecx, edx);
            *edx = 0;
        }
        break;
    case 0x1F:
        /* V2 Extended Topology Enumeration Leaf */
        if (env->nr_dies < 2) {
            *eax = *ebx = *ecx = *edx = 0;
            break;
        }

        *ecx = count & 0xff;
        *edx = cpu->apic_id;
        switch (count) {
        case 0:
            *eax = apicid_core_offset(&topo_info);
            *ebx = cs->nr_threads;
            *ecx |= CPUID_TOPOLOGY_LEVEL_SMT;
            break;
        case 1:
            *eax = apicid_die_offset(&topo_info);
            *ebx = cs->nr_cores * cs->nr_threads;
            *ecx |= CPUID_TOPOLOGY_LEVEL_CORE;
            break;
        case 2:
            *eax = apicid_pkg_offset(&topo_info);
            *ebx = env->nr_dies * cs->nr_cores * cs->nr_threads;
            *ecx |= CPUID_TOPOLOGY_LEVEL_DIE;
            break;
        default:
            *eax = 0;
            *ebx = 0;
            *ecx |= CPUID_TOPOLOGY_LEVEL_INVALID;
        }
        assert(!(*eax & ~0x1f));
        *ebx &= 0xffff; /* The count doesn't need to be reliable. */
        break;
    case 0xD: {
        /* Processor Extended State */
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        if (!(env->features[FEAT_1_ECX] & CPUID_EXT_XSAVE)) {
            break;
        }

        if (count == 0) {
            *ecx = xsave_area_size(x86_cpu_xsave_xcr0_components(cpu), false);
            *eax = env->features[FEAT_XSAVE_XCR0_LO];
            *edx = env->features[FEAT_XSAVE_XCR0_HI];
            /*
             * The initial value of xcr0 and ebx == 0, On host without kvm
             * commit 412a3c41(e.g., CentOS 6), the ebx's value always == 0
             * even through guest update xcr0, this will crash some legacy guest
             * (e.g., CentOS 6), So set ebx == ecx to workaroud it.
             */
            *ebx = kvm_enabled() ? *ecx : xsave_area_size(env->xcr0, false);
        } else if (count == 1) {
            uint64_t xstate = x86_cpu_xsave_xcr0_components(cpu) |
                              x86_cpu_xsave_xss_components(cpu);

            *eax = env->features[FEAT_XSAVE];
            *ebx = xsave_area_size(xstate, true);
            *ecx = env->features[FEAT_XSAVE_XSS_LO];
            *edx = env->features[FEAT_XSAVE_XSS_HI];
            if (kvm_enabled() && cpu->enable_pmu &&
                (env->features[FEAT_7_0_EDX] & CPUID_7_0_EDX_ARCH_LBR) &&
                (*eax & CPUID_XSAVE_XSAVES)) {
                *ecx |= XSTATE_ARCH_LBR_MASK;
            } else {
                *ecx &= ~XSTATE_ARCH_LBR_MASK;
            }
        } else if (count == 0xf &&
                   accel_uses_host_cpuid() && cpu->enable_pmu &&
                   (env->features[FEAT_7_0_EDX] & CPUID_7_0_EDX_ARCH_LBR)) {
            x86_cpu_get_supported_cpuid(0xD, count, eax, ebx, ecx, edx);
        } else if (count < ARRAY_SIZE(x86_ext_save_areas)) {
            const ExtSaveArea *esa = &x86_ext_save_areas[count];

            if (x86_cpu_xsave_xcr0_components(cpu) & (1ULL << count)) {
                *eax = esa->size;
                *ebx = esa->offset;
                *ecx = esa->ecx &
                       (ESA_FEATURE_ALIGN64_MASK | ESA_FEATURE_XFD_MASK);
            } else if (x86_cpu_xsave_xss_components(cpu) & (1ULL << count)) {
                *eax = esa->size;
                *ebx = 0;
                *ecx = 1;
            }
        }
        break;
    }
    case 0x12:
#ifndef CONFIG_USER_ONLY
        if (!kvm_enabled() ||
            !(env->features[FEAT_7_0_EBX] & CPUID_7_0_EBX_SGX)) {
            *eax = *ebx = *ecx = *edx = 0;
            break;
        }

        /*
         * SGX sub-leafs CPUID.0x12.{0x2..N} enumerate EPC sections.  Retrieve
         * the EPC properties, e.g. confidentiality and integrity, from the
         * host's first EPC section, i.e. assume there is one EPC section or
         * that all EPC sections have the same security properties.
         */
        if (count > 1) {
            uint64_t epc_addr, epc_size;

            if (sgx_epc_get_section(count - 2, &epc_addr, &epc_size)) {
                *eax = *ebx = *ecx = *edx = 0;
                break;
            }
            host_cpuid(index, 2, eax, ebx, ecx, edx);
            *eax = (uint32_t)(epc_addr & 0xfffff000) | 0x1;
            *ebx = (uint32_t)(epc_addr >> 32);
            *ecx = (uint32_t)(epc_size & 0xfffff000) | (*ecx & 0xf);
            *edx = (uint32_t)(epc_size >> 32);
            break;
        }

        /*
         * SGX sub-leafs CPUID.0x12.{0x0,0x1} are heavily dependent on hardware
         * and KVM, i.e. QEMU cannot emulate features to override what KVM
         * supports.  Features can be further restricted by userspace, but not
         * made more permissive.
         */
        x86_cpu_get_supported_cpuid(0x12, count, eax, ebx, ecx, edx);

        if (count == 0) {
            *eax &= env->features[FEAT_SGX_12_0_EAX];
            *ebx &= env->features[FEAT_SGX_12_0_EBX];
        } else {
            *eax &= env->features[FEAT_SGX_12_1_EAX];
            *ebx &= 0; /* ebx reserve */
            *ecx &= env->features[FEAT_XSAVE_XCR0_LO];
            *edx &= env->features[FEAT_XSAVE_XCR0_HI];

            /* FP and SSE are always allowed regardless of XSAVE/XCR0. */
            *ecx |= XSTATE_FP_MASK | XSTATE_SSE_MASK;

            /* Access to PROVISIONKEY requires additional credentials. */
            if ((*eax & (1U << 4)) &&
                !kvm_enable_sgx_provisioning(cs->kvm_state)) {
                *eax &= ~(1U << 4);
            }
        }
#endif
        break;
    case 0x14: {
        /* Intel Processor Trace Enumeration */
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        if (!(env->features[FEAT_7_0_EBX] & CPUID_7_0_EBX_INTEL_PT) ||
            !kvm_enabled()) {
            break;
        }

        if (count == 0) {
            *eax = INTEL_PT_MAX_SUBLEAF;
            *ebx = INTEL_PT_MINIMAL_EBX;
            *ecx = INTEL_PT_MINIMAL_ECX;
            if (env->features[FEAT_14_0_ECX] & CPUID_14_0_ECX_LIP) {
                *ecx |= CPUID_14_0_ECX_LIP;
            }
        } else if (count == 1) {
            *eax = INTEL_PT_MTC_BITMAP | INTEL_PT_ADDR_RANGES_NUM;
            *ebx = INTEL_PT_PSB_BITMAP | INTEL_PT_CYCLE_BITMAP;
        }
        break;
    }
    case 0x1D: {
        /* AMX TILE, for now hardcoded for Sapphire Rapids*/
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        if (!(env->features[FEAT_7_0_EDX] & CPUID_7_0_EDX_AMX_TILE)) {
            break;
        }

        if (count == 0) {
            /* Highest numbered palette subleaf */
            *eax = INTEL_AMX_TILE_MAX_SUBLEAF;
        } else if (count == 1) {
            *eax = INTEL_AMX_TOTAL_TILE_BYTES |
                   (INTEL_AMX_BYTES_PER_TILE << 16);
            *ebx = INTEL_AMX_BYTES_PER_ROW | (INTEL_AMX_TILE_MAX_NAMES << 16);
            *ecx = INTEL_AMX_TILE_MAX_ROWS;
        }
        break;
    }
    case 0x1E: {
        /* AMX TMUL, for now hardcoded for Sapphire Rapids */
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        if (!(env->features[FEAT_7_0_EDX] & CPUID_7_0_EDX_AMX_TILE)) {
            break;
        }

        if (count == 0) {
            /* Highest numbered palette subleaf */
            *ebx = INTEL_AMX_TMUL_MAX_K | (INTEL_AMX_TMUL_MAX_N << 8);
        }
        break;
    }
    case 0x40000000:
        /*
         * CPUID code in kvm_arch_init_vcpu() ignores stuff
         * set here, but we restrict to TCG none the less.
         */
        if (tcg_enabled() && cpu->expose_tcg) {
            memcpy(signature, "TCGTCGTCGTCG", 12);
            *eax = 0x40000001;
            *ebx = signature[0];
            *ecx = signature[1];
            *edx = signature[2];
        } else {
            *eax = 0;
            *ebx = 0;
            *ecx = 0;
            *edx = 0;
        }
        break;
    case 0x40000001:
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    case 0x80000000:
        *eax = env->cpuid_xlevel;
        *ebx = env->cpuid_vendor1;
        *edx = env->cpuid_vendor2;
        *ecx = env->cpuid_vendor3;
        break;
    case 0x80000001:
        *eax = env->cpuid_version;
        *ebx = 0;
        *ecx = env->features[FEAT_8000_0001_ECX];
        *edx = env->features[FEAT_8000_0001_EDX];

        /* The Linux kernel checks for the CMPLegacy bit and
         * discards multiple thread information if it is set.
         * So don't set it here for Intel to make Linux guests happy.
         */
        if (cs->nr_cores * cs->nr_threads > 1) {
            if (env->cpuid_vendor1 != CPUID_VENDOR_INTEL_1 ||
                env->cpuid_vendor2 != CPUID_VENDOR_INTEL_2 ||
                env->cpuid_vendor3 != CPUID_VENDOR_INTEL_3) {
                *ecx |= 1 << 1;    /* CmpLegacy bit */
            }
        }
        break;
    case 0x80000002:
    case 0x80000003:
    case 0x80000004:
        *eax = env->cpuid_model[(index - 0x80000002) * 4 + 0];
        *ebx = env->cpuid_model[(index - 0x80000002) * 4 + 1];
        *ecx = env->cpuid_model[(index - 0x80000002) * 4 + 2];
        *edx = env->cpuid_model[(index - 0x80000002) * 4 + 3];
        break;
    case 0x80000005:
        /* cache info (L1 cache) */
        if (cpu->cache_info_passthrough) {
            x86_cpu_get_cache_cpuid(index, 0, eax, ebx, ecx, edx);
            break;
        }
        *eax = (L1_DTLB_2M_ASSOC << 24) | (L1_DTLB_2M_ENTRIES << 16) |
               (L1_ITLB_2M_ASSOC <<  8) | (L1_ITLB_2M_ENTRIES);
        *ebx = (L1_DTLB_4K_ASSOC << 24) | (L1_DTLB_4K_ENTRIES << 16) |
               (L1_ITLB_4K_ASSOC <<  8) | (L1_ITLB_4K_ENTRIES);
        *ecx = encode_cache_cpuid80000005(env->cache_info_amd.l1d_cache);
        *edx = encode_cache_cpuid80000005(env->cache_info_amd.l1i_cache);
        break;
    case 0x80000006:
        /* cache info (L2 cache) */
        if (cpu->cache_info_passthrough) {
            x86_cpu_get_cache_cpuid(index, 0, eax, ebx, ecx, edx);
            break;
        }
        *eax = (AMD_ENC_ASSOC(L2_DTLB_2M_ASSOC) << 28) |
               (L2_DTLB_2M_ENTRIES << 16) |
               (AMD_ENC_ASSOC(L2_ITLB_2M_ASSOC) << 12) |
               (L2_ITLB_2M_ENTRIES);
        *ebx = (AMD_ENC_ASSOC(L2_DTLB_4K_ASSOC) << 28) |
               (L2_DTLB_4K_ENTRIES << 16) |
               (AMD_ENC_ASSOC(L2_ITLB_4K_ASSOC) << 12) |
               (L2_ITLB_4K_ENTRIES);
        encode_cache_cpuid80000006(env->cache_info_amd.l2_cache,
                                   cpu->enable_l3_cache ?
                                   env->cache_info_amd.l3_cache : NULL,
                                   ecx, edx);
        break;
    case 0x80000007:
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = env->features[FEAT_8000_0007_EDX];
        break;
    case 0x80000008:
        /* virtual & phys address size in low 2 bytes. */
        *eax = cpu->phys_bits;
        if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_LM) {
            /* 64 bit processor */
             *eax |= (cpu_x86_virtual_addr_width(env) << 8);
        }
        *ebx = env->features[FEAT_8000_0008_EBX];
        if (cs->nr_cores * cs->nr_threads > 1) {
            /*
             * Bits 15:12 is "The number of bits in the initial
             * Core::X86::Apic::ApicId[ApicId] value that indicate
             * thread ID within a package".
             * Bits 7:0 is "The number of threads in the package is NC+1"
             */
            *ecx = (apicid_pkg_offset(&topo_info) << 12) |
                   ((cs->nr_cores * cs->nr_threads) - 1);
        } else {
            *ecx = 0;
        }
        *edx = 0;
        break;
    case 0x8000000A:
        if (env->features[FEAT_8000_0001_ECX] & CPUID_EXT3_SVM) {
            *eax = 0x00000001; /* SVM Revision */
            *ebx = 0x00000010; /* nr of ASIDs */
            *ecx = 0;
            *edx = env->features[FEAT_SVM]; /* optional features */
        } else {
            *eax = 0;
            *ebx = 0;
            *ecx = 0;
            *edx = 0;
        }
        break;
    case 0x8000001D:
        *eax = 0;
        if (cpu->cache_info_passthrough) {
            x86_cpu_get_cache_cpuid(index, count, eax, ebx, ecx, edx);
            break;
        }
        switch (count) {
        case 0: /* L1 dcache info */
            encode_cache_cpuid8000001d(env->cache_info_amd.l1d_cache,
                                       &topo_info, eax, ebx, ecx, edx);
            break;
        case 1: /* L1 icache info */
            encode_cache_cpuid8000001d(env->cache_info_amd.l1i_cache,
                                       &topo_info, eax, ebx, ecx, edx);
            break;
        case 2: /* L2 cache info */
            encode_cache_cpuid8000001d(env->cache_info_amd.l2_cache,
                                       &topo_info, eax, ebx, ecx, edx);
            break;
        case 3: /* L3 cache info */
            encode_cache_cpuid8000001d(env->cache_info_amd.l3_cache,
                                       &topo_info, eax, ebx, ecx, edx);
            break;
        default: /* end of info */
            *eax = *ebx = *ecx = *edx = 0;
            break;
        }
        break;
    case 0x8000001E:
        if (cpu->core_id <= 255) {
            encode_topo_cpuid8000001e(cpu, &topo_info, eax, ebx, ecx, edx);
        } else {
            *eax = 0;
            *ebx = 0;
            *ecx = 0;
            *edx = 0;
        }
        break;
    case 0xC0000000:
        *eax = env->cpuid_xlevel2;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    case 0xC0000001:
        /* Support for VIA CPU's CPUID instruction */
        *eax = env->cpuid_version;
        *ebx = 0;
        *ecx = 0;
        *edx = env->features[FEAT_C000_0001_EDX];
        break;
    case 0xC0000002:
    case 0xC0000003:
    case 0xC0000004:
        /* Reserved for the future, and now filled with zero */
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    case 0x8000001F:
        *eax = *ebx = *ecx = *edx = 0;
        if (sev_enabled()) {
            *eax = 0x2;
            *eax |= sev_es_enabled() ? 0x8 : 0;
            *ebx = sev_get_cbit_position() & 0x3f; /* EBX[5:0] */
            *ebx |= (sev_get_reduced_phys_bits() & 0x3f) << 6; /* EBX[11:6] */
        }
        break;
    case 0x80000021:
        *eax = env->features[FEAT_8000_0021_EAX];
        *ebx = *ecx = *edx = 0;
        break;
    default:
        /* reserved values: zero */
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    }
}

void cpu_sync_avx_hflag(CPUX86State *env)
{
    if ((env->cr[4] & CR4_OSXSAVE_MASK)
        && (env->xcr0 & (XSTATE_SSE_MASK | XSTATE_YMM_MASK))
            == (XSTATE_SSE_MASK | XSTATE_YMM_MASK)) {
        env->hflags |= HF_AVX_EN_MASK;
    } else{
        env->hflags &= ~HF_AVX_EN_MASK;
    }
}

void cpu_sync_bndcs_hflags(CPUX86State *env)
{
    uint32_t hflags = env->hflags;
    uint32_t hflags2 = env->hflags2;
    uint32_t bndcsr;

    if ((hflags & HF_CPL_MASK) == 3) {
        bndcsr = env->bndcs_regs.cfgu;
    } else {
        bndcsr = env->msr_bndcfgs;
    }

    if ((env->cr[4] & CR4_OSXSAVE_MASK)
        && (env->xcr0 & XSTATE_BNDCSR_MASK)
        && (bndcsr & BNDCFG_ENABLE)) {
        hflags |= HF_MPX_EN_MASK;
    } else {
        hflags &= ~HF_MPX_EN_MASK;
    }

    if (bndcsr & BNDCFG_BNDPRESERVE) {
        hflags2 |= HF2_MPX_PR_MASK;
    } else {
        hflags2 &= ~HF2_MPX_PR_MASK;
    }

    env->hflags = hflags;
    env->hflags2 = hflags2;
}

void helper_xsetbv(CPUX86State *env, uint32_t ecx, uint64_t mask)
{
    uint32_t dummy, ena_lo, ena_hi;
    uint64_t ena;

    /* The OS must have enabled XSAVE.  */
    if (!(env->cr[4] & CR4_OSXSAVE_MASK)) {
        raise_exception_ra(env, EXCP06_ILLOP, GETPC());
    }

    /* Only XCR0 is defined at present; the FPU may not be disabled.  */
    if (ecx != 0 || (mask & XSTATE_FP_MASK) == 0) {
        goto do_gpf;
    }

    /* Disallow enabling unimplemented features.  */
    cpu_x86_cpuid(env, 0x0d, 0, &ena_lo, &dummy, &dummy, &ena_hi);
    ena = ((uint64_t)ena_hi << 32) | ena_lo;
    if (mask & ~ena) {
        goto do_gpf;
    }

    /* Disallow enabling only half of MPX.  */
    if ((mask ^ (mask * (XSTATE_BNDCSR_MASK / XSTATE_BNDREGS_MASK)))
        & XSTATE_BNDCSR_MASK) {
        goto do_gpf;
    }

    env->xcr0 = mask;
    cpu_sync_bndcs_hflags(env);
    cpu_sync_avx_hflag(env);
    return;

 do_gpf:
    raise_exception_ra(env, EXCP0D_GPF, GETPC());
}

