#define CONFIG_LINUX 1

#define CONFIG_USER_ONLY 1

#define TARGET_AARCH64 1

#define TARGET_BIG_ENDIAN 0

#define HOST_BIG_ENDIAN (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)

#define QEMU_ALIGNED(X) __attribute__((aligned(X)))

#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#define likely(x)   __builtin_expect(!!(x), 1)

#define unlikely(x)   __builtin_expect(!!(x), 0)

#define QEMU_ALWAYS_INLINE  __attribute__((always_inline))

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

#define g_assert_not_reached()          G_STMT_START { g_assertion_message_expr (G_LOG_DOMAIN, __FILE__, __LINE__, G_STRFUNC, NULL); } G_STMT_END

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

typedef struct VMStateDescription VMStateDescription;

typedef struct IRQState *qemu_irq;

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

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

static inline void bswap16s(uint16_t *s)
{
    *s = __builtin_bswap16(*s);
}

#define le_bswap(v, size) (v)

#define be_bswap(v, size) glue(__builtin_bswap, size)(v)

static inline int lduw_he_p(const void *ptr)
{
    uint16_t r;
    __builtin_memcpy(&r, ptr, sizeof(r));
    return r;
}

static inline int lduw_le_p(const void *ptr)
{
    return (uint16_t)le_bswap(lduw_he_p(ptr), 16);
}

static inline int lduw_be_p(const void *ptr)
{
    return (uint16_t)be_bswap(lduw_he_p(ptr), 16);
}

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

static inline int clz64(uint64_t val)
{
    return val ? __builtin_clzll(val) : 64;
}

static inline int ctz64(uint64_t val)
{
    return val ? __builtin_ctzll(val) : 64;
}

#define BITS_PER_BYTE           CHAR_BIT

#define BITS_TO_LONGS(nr)       DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))

#define MAKE_64BIT_MASK(shift, length) \
    (((~0ULL) >> (64 - (length))) << (shift))

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

static inline uint64_t extract64(uint64_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 64 - start);
    return (value >> start) & (~0ULL >> (64 - length));
}

static inline int32_t sextract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    /* Note that this implementation relies on right shift of signed
     * integers being an arithmetic shift.
     */
    return ((int32_t)(value << (32 - length - start))) >> (32 - length);
}

static inline int64_t sextract64(uint64_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 64 - start);
    /* Note that this implementation relies on right shift of signed
     * integers being an arithmetic shift.
     */
    return ((int64_t)(value << (64 - length - start))) >> (64 - length);
}

#define FIELD(reg, field, shift, length)                                  \
    enum { R_ ## reg ## _ ## field ## _SHIFT = (shift)};                  \
    enum { R_ ## reg ## _ ## field ## _LENGTH = (length)};                \
    enum { R_ ## reg ## _ ## field ## _MASK =                             \
                                        MAKE_64BIT_MASK(shift, length)};

#define FIELD_EX32(storage, reg, field)                                   \
    extract32((storage), R_ ## reg ## _ ## field ## _SHIFT,               \
              R_ ## reg ## _ ## field ## _LENGTH)

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

#define DECLARE_BITMAP(name,bits)                  \
        unsigned long name[BITS_TO_LONGS(bits)]

typedef struct QTailQLink {
    void *tql_next;
    struct QTailQLink *tql_prev;
} QTailQLink;

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

struct QemuLockCnt {
#ifndef CONFIG_LINUX
    QemuMutex mutex;
#endif
    unsigned count;
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

typedef enum MMUAccessType {
    MMU_DATA_LOAD  = 0,
    MMU_DATA_STORE = 1,
    MMU_INST_FETCH = 2
} MMUAccessType;

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

#define BP_MEM_READ           0x01

#define TARGET_PAGE_BITS 12

#  define TARGET_TAGGED_ADDRESSES

typedef int64_t target_long;

typedef uint64_t target_ulong;

enum {
    M_REG_NS = 0,
    M_REG_S = 1,
    M_REG_NUM_BANKS = 2,
};

#define NUM_GTIMERS     5

# define ARM_MAX_VQ    16

typedef struct ARMGenericTimer {
    uint64_t cval; /* Timer CompareValue register */
    uint64_t ctl; /* Timer Control register */
} ARMGenericTimer;

typedef struct ARMVectorReg {
    uint64_t d[2 * ARM_MAX_VQ] QEMU_ALIGNED(16);
} ARMVectorReg;

typedef struct ARMPredicateReg {
    uint64_t p[DIV_ROUND_UP(2 * ARM_MAX_VQ, 8)] QEMU_ALIGNED(16);
} ARMPredicateReg;

typedef struct ARMPACKey {
    uint64_t lo, hi;
} ARMPACKey;

typedef struct CPUARMTBFlags {
    uint32_t flags;
    target_ulong flags2;
} CPUARMTBFlags;

typedef struct ARMMMUFaultInfo ARMMMUFaultInfo;

typedef struct CPUArchState {
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
     *  SM and ZA are kept in env->svcr
     *  all other bits are stored in their correct places in env->pstate
     */
    uint32_t pstate;
    bool aarch64; /* True if CPU is in aarch64 state; inverse of PSTATE.nRW */
    bool thumb;   /* True if CPU is in thumb mode; cpsr[5] */

    /* Cached TBFLAGS state.  See below for which bits are included.  */
    CPUARMTBFlags hflags;

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
    uint32_t condexec_bits; /* IT bits.  cpsr[15:10,26:25].  */
    uint32_t btype;  /* BTI branch type.  spsr[11:10].  */
    uint64_t daif; /* exception masks, in the bits they are in PSTATE */
    uint64_t svcr; /* PSTATE.{SM,ZA} in the bits they are in SVCR */

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
        uint64_t vsctlr; /* Virtualization System control register. */
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
        uint64_t vsttbr_el2; /* Secure Virtualization Translation Table. */
        /* MMU translation table base control. */
        uint64_t tcr_el[4];
        uint64_t vtcr_el2; /* Virtualization Translation Control.  */
        uint64_t vstcr_el2; /* Secure Virtualization Translation Control. */
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
        uint64_t hcrx_el2; /* Extended Hypervisor configuration register */
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
#if HOST_BIG_ENDIAN
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
#if HOST_BIG_ENDIAN
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
        uint64_t rvbar; /* rvbar sampled from rvbar property at reset */
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
        uint64_t tpidr2_el0;
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
        uint64_t cnthctl_el2; /* Counter/Timer Hyp Control register */
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
        uint64_t dbgclaim;   /* DBGCLAIM bits */
        uint64_t mdscr_el1;
        uint64_t oslsr_el1; /* OS Lock Status */
        uint64_t osdlr_el1; /* OS DoubleLock status */
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
        uint64_t tfsr_el[4]; /* tfsre0_el1 is index 0.  */
        uint64_t gcr_el1;
        uint64_t rgsr_el1;

        /* Minimal RAS registers */
        uint64_t disr_el1;
        uint64_t vdisr_el2;
        uint64_t vsesr_el2;

        /*
         * Fine-Grained Trap registers. We store these as arrays so the
         * access checking code doesn't have to manually select
         * HFGRTR_EL2 vs HFDFGRTR_EL2 etc when looking up the bit to test.
         * FEAT_FGT2 will add more elements to these arrays.
         */
        uint64_t fgt_read[2]; /* HFGRTR, HDFGRTR */
        uint64_t fgt_write[2]; /* HFGWTR, HDFGWTR */
        uint64_t fgt_exec[1]; /* HFGITR */
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
        uint32_t ltpsize;
        uint32_t vpr;
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

    uint8_t ext_dabt_raised; /* Tracking/verifying injection of ext DABT */

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
         *  standard_fp_status_fp16 : used for half-precision
         *       calculations with the ARM "Standard FPSCR Value"
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
         * The "standard FPSCR but for fp16 ops" is needed because
         * the "standard FPSCR" tracks the FPSCR.FZ16 bit rather than
         * using a fixed value for it.
         *
         * To avoid having to transfer exception bits around, we simply
         * say that the FPSCR cumulative exception flags are the logical
         * OR of the flags in the four fp statuses. This relies on the
         * only thing which needs to read the exception flags being
         * an explicit FPSCR read.
         */
        float_status fp_status;
        float_status fp_status_f16;
        float_status standard_fp_status;
        float_status standard_fp_status_f16;

        uint64_t zcr_el[4];   /* ZCR_EL[1-3] */
        uint64_t smcr_el[4];  /* SMCR_EL[1-3] */
    } vfp;

    uint64_t exclusive_addr;
    uint64_t exclusive_val;
    /*
     * Contains the 'val' for the second 64-bit register of LDXP, which comes
     * from the higher address, not the high part of a complete 128-bit value.
     * In some ways it might be more convenient to record the exclusive value
     * as the low and high halves of a 128 bit data value, but the current
     * semantics of these fields are baked into the migration format.
     */
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

    uint64_t scxtnum_el[4];

    /*
     * SME ZA storage -- 256 x 256 byte array, with bytes in host word order,
     * as we do with vfp.zregs[].  This corresponds to the architectural ZA
     * array, where ZA[N] is in the least-significant bytes of env->zarray[N].
     * When SVL is less than the architectural maximum, the accessible
     * storage is restricted, such that if the SVL is X bytes the guest can
     * see only the bottom X elements of zarray[], and only the least
     * significant X bytes of each element of the array. (In other words,
     * the observable part is always square.)
     *
     * The ZA storage can also be considered as a set of square tiles of
     * elements of different sizes. The mapping from tiles to the ZA array
     * is architecturally defined, such that for tiles of elements of esz
     * bytes, the Nth row (or "horizontal slice") of tile T is in
     * ZA[T + N * esz]. Note that this means that each tile is not contiguous
     * in the ZA storage, because its rows are striped through the ZA array.
     *
     * Because this is so large, keep this toward the end of the reset area,
     * to keep the offsets into the rest of the structure smaller.
     */
    ARMVectorReg zarray[ARM_MAX_VQ * 16];
#endif

    struct CPUBreakpoint *cpu_breakpoint[16];
    struct CPUWatchpoint *cpu_watchpoint[16];

    /* Optional fault info across tlb lookup. */
    ARMMMUFaultInfo *tlb_fi;

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
        uint32_t *hprbar;
        uint32_t *hprlar;
        uint32_t mair0[M_REG_NUM_BANKS];
        uint32_t mair1[M_REG_NUM_BANKS];
        uint32_t hprselr;
    } pmsav8;

    /* v8M SAU */
    struct {
        uint32_t *rbar;
        uint32_t *rlar;
        uint32_t rnr;
        uint32_t ctrl;
    } sau;

#if !defined(CONFIG_USER_ONLY)
    NVICState *nvic;
    const struct arm_boot_info *boot_info;
    /* Store GICv3CPUState to access from this struct */
    void *gicv3state;
#else /* CONFIG_USER_ONLY */
    /* For usermode syscall translation.  */
    bool eabi;
#endif /* CONFIG_USER_ONLY */

#ifdef TARGET_TAGGED_ADDRESSES
    /* Linux syscall tagged address support */
    bool tagged_addr_enable;
#endif
} CPUARMState;

#define TARGET_PAGE_BITS_MIN TARGET_PAGE_BITS

#define TARGET_PAGE_MASK   ((target_long)-1 << TARGET_PAGE_BITS)

#define PAGE_ANON      0x0080

#define PAGE_TARGET_2  0x0400

#define TLB_INVALID_MASK    (1 << (TARGET_PAGE_BITS_MIN - 1))

FIELD(TBFLAG_ANY, MMUIDX, 4, 4)

#define EX_TBFLAG_ANY(IN, WHICH)   FIELD_EX32(IN.flags, TBFLAG_ANY, WHICH)

static inline int cpu_mmu_index(CPUARMState *env, bool ifetch)
{
    return EX_TBFLAG_ANY(env->hflags, MMUIDX);
}

#define PAGE_MTE            PAGE_TARGET_2

extern const uint64_t pred_esz_masks[5];

#define SIMD_MAXSZ_SHIFT   0

#define SIMD_MAXSZ_BITS    8

#define SIMD_OPRSZ_SHIFT   (SIMD_MAXSZ_SHIFT + SIMD_MAXSZ_BITS)

#define SIMD_OPRSZ_BITS    2

#define SIMD_DATA_SHIFT    (SIMD_OPRSZ_SHIFT + SIMD_OPRSZ_BITS)

#define SIMD_DATA_BITS     (32 - SIMD_DATA_SHIFT)

static inline intptr_t simd_maxsz(uint32_t desc)
{
    return extract32(desc, SIMD_MAXSZ_SHIFT, SIMD_MAXSZ_BITS) * 8 + 8;
}

static inline intptr_t simd_oprsz(uint32_t desc)
{
    uint32_t f = extract32(desc, SIMD_OPRSZ_SHIFT, SIMD_OPRSZ_BITS);
    intptr_t o = f * 8 + 8;
    intptr_t m = simd_maxsz(desc);
    return f == 2 ? m : o;
}

static inline int32_t simd_data(uint32_t desc)
{
    return sextract32(desc, SIMD_DATA_SHIFT, SIMD_DATA_BITS);
}

G_NORETURN static inline void arm_cpu_do_unaligned_access(CPUState *cs, vaddr vaddr,
                                                          MMUAccessType access_type,
                                                          int mmu_idx, uintptr_t retaddr)
{
    __builtin_trap();
    __builtin_unreachable();
}

#define SVE_MTEDESC_SHIFT 5

FIELD(MTEDESC, TBI,   4, 2)

FIELD(MTEDESC, TCMA,  6, 2)

uint64_t mte_check(CPUARMState *env, uint32_t desc, uint64_t ptr, uintptr_t ra);

static inline int allocation_tag_from_addr(uint64_t ptr)
{
    return extract64(ptr, 56, 4);
}

static inline bool tbi_check(uint32_t desc, int bit55)
{
    return (desc >> (R_MTEDESC_TBI_SHIFT + bit55)) & 1;
}

static inline bool tcma_check(uint32_t desc, int bit55, int ptr_tag)
{
    /*
     * We had extracted bit55 and ptr_tag for other reasons, so fold
     * (ptr<59:55> == 00000 || ptr<59:55> == 11111) into a single test.
     */
    bool match = ((ptr_tag + bit55) & 0xf) == 0;
    bool tcma = (desc >> (R_MTEDESC_TCMA_SHIFT + bit55)) & 1;
    return tcma && match;
}

static inline uint64_t useronly_clean_ptr(uint64_t ptr)
{
#ifdef CONFIG_USER_ONLY
    /* TBI0 is known to be enabled, while TBI1 is disabled. */
    ptr &= sextract64(ptr, 0, 56);
#endif
    return ptr;
}

typedef enum MemOp {
    MO_8     = 0,
    MO_16    = 1,
    MO_32    = 2,
    MO_64    = 3,
    MO_128   = 4,
    MO_256   = 5,
    MO_512   = 6,
    MO_1024  = 7,
    MO_SIZE  = 0x07,   /* Mask for the above.  */

    MO_SIGN  = 0x08,   /* Sign-extended, otherwise zero-extended.  */

    MO_BSWAP = 0x10,   /* Host reverse endian.  */
#if HOST_BIG_ENDIAN
    MO_LE    = MO_BSWAP,
    MO_BE    = 0,
#else
    MO_LE    = 0,
    MO_BE    = MO_BSWAP,
#endif
#ifdef NEED_CPU_H
#if TARGET_BIG_ENDIAN
    MO_TE    = MO_BE,
#else
    MO_TE    = MO_LE,
#endif
#endif

    /*
     * MO_UNALN accesses are never checked for alignment.
     * MO_ALIGN accesses will result in a call to the CPU's
     * do_unaligned_access hook if the guest address is not aligned.
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
    MO_ASHIFT = 5,
    MO_AMASK = 0x7 << MO_ASHIFT,
    MO_UNALN    = 0,
    MO_ALIGN_2  = 1 << MO_ASHIFT,
    MO_ALIGN_4  = 2 << MO_ASHIFT,
    MO_ALIGN_8  = 3 << MO_ASHIFT,
    MO_ALIGN_16 = 4 << MO_ASHIFT,
    MO_ALIGN_32 = 5 << MO_ASHIFT,
    MO_ALIGN_64 = 6 << MO_ASHIFT,
    MO_ALIGN    = MO_AMASK,

    /*
     * MO_ATOM_* describes the atomicity requirements of the operation:
     * MO_ATOM_IFALIGN: the operation must be single-copy atomic if it
     *    is aligned; if unaligned there is no atomicity.
     * MO_ATOM_IFALIGN_PAIR: the entire operation may be considered to
     *    be a pair of half-sized operations which are packed together
     *    for convenience, with single-copy atomicity on each half if
     *    the half is aligned.
     *    This is the atomicity e.g. of Arm pre-FEAT_LSE2 LDP.
     * MO_ATOM_WITHIN16: the operation is single-copy atomic, even if it
     *    is unaligned, so long as it does not cross a 16-byte boundary;
     *    if it crosses a 16-byte boundary there is no atomicity.
     *    This is the atomicity e.g. of Arm FEAT_LSE2 LDR.
     * MO_ATOM_WITHIN16_PAIR: the entire operation is single-copy atomic,
     *    if it happens to be within a 16-byte boundary, otherwise it
     *    devolves to a pair of half-sized MO_ATOM_WITHIN16 operations.
     *    Depending on alignment, one or both will be single-copy atomic.
     *    This is the atomicity e.g. of Arm FEAT_LSE2 LDP.
     * MO_ATOM_SUBALIGN: the operation is single-copy atomic by parts
     *    by the alignment.  E.g. if the address is 0 mod 4, then each
     *    4-byte subobject is single-copy atomic.
     *    This is the atomicity e.g. of IBM Power.
     * MO_ATOM_NONE: the operation has no atomicity requirements.
     *
     * Note the default (i.e. 0) value is single-copy atomic to the
     * size of the operation, if aligned.  This retains the behaviour
     * from before this field was introduced.
     */
    MO_ATOM_SHIFT         = 8,
    MO_ATOM_IFALIGN       = 0 << MO_ATOM_SHIFT,
    MO_ATOM_IFALIGN_PAIR  = 1 << MO_ATOM_SHIFT,
    MO_ATOM_WITHIN16      = 2 << MO_ATOM_SHIFT,
    MO_ATOM_WITHIN16_PAIR = 3 << MO_ATOM_SHIFT,
    MO_ATOM_SUBALIGN      = 4 << MO_ATOM_SHIFT,
    MO_ATOM_NONE          = 5 << MO_ATOM_SHIFT,
    MO_ATOM_MASK          = 7 << MO_ATOM_SHIFT,

    /* Combinations of the above, for ease of use.  */
    MO_UB    = MO_8,
    MO_UW    = MO_16,
    MO_UL    = MO_32,
    MO_UQ    = MO_64,
    MO_UO    = MO_128,
    MO_SB    = MO_SIGN | MO_8,
    MO_SW    = MO_SIGN | MO_16,
    MO_SL    = MO_SIGN | MO_32,
    MO_SQ    = MO_SIGN | MO_64,
    MO_SO    = MO_SIGN | MO_128,

    MO_LEUW  = MO_LE | MO_UW,
    MO_LEUL  = MO_LE | MO_UL,
    MO_LEUQ  = MO_LE | MO_UQ,
    MO_LESW  = MO_LE | MO_SW,
    MO_LESL  = MO_LE | MO_SL,
    MO_LESQ  = MO_LE | MO_SQ,

    MO_BEUW  = MO_BE | MO_UW,
    MO_BEUL  = MO_BE | MO_UL,
    MO_BEUQ  = MO_BE | MO_UQ,
    MO_BESW  = MO_BE | MO_SW,
    MO_BESL  = MO_BE | MO_SL,
    MO_BESQ  = MO_BE | MO_SQ,

#ifdef NEED_CPU_H
    MO_TEUW  = MO_TE | MO_UW,
    MO_TEUL  = MO_TE | MO_UL,
    MO_TEUQ  = MO_TE | MO_UQ,
    MO_TEUO  = MO_TE | MO_UO,
    MO_TESW  = MO_TE | MO_SW,
    MO_TESL  = MO_TE | MO_SL,
    MO_TESQ  = MO_TE | MO_SQ,
#endif

    MO_SSIZE = MO_SIZE | MO_SIGN,
} MemOp;

typedef uint64_t abi_ptr;

uint32_t cpu_lduw_be_data_ra(CPUArchState *env, abi_ptr ptr, uintptr_t ra);

uint32_t cpu_lduw_le_data_ra(CPUArchState *env, abi_ptr ptr, uintptr_t ra);

int probe_access_flags(CPUArchState *env, target_ulong addr, int size,
                       MMUAccessType access_type, int mmu_idx,
                       bool nonfault, void **phost, uintptr_t retaddr);

# define GETPC() 0

#define HELPER(name) glue(helper_, name)

# define tcg_debug_assert(X) \
    do { if (!(X)) { __builtin_unreachable(); } } while (0)

#define H1_2(x) (x)

typedef void sve_ldst1_host_fn(void *vd, intptr_t reg_off, void *host);

#define DO_LD_HOST(NAME, H, TYPEE, TYPEM, HOST)                              \
static inline void sve_##NAME##_host(void *vd, intptr_t reg_off, void *host) \
{ TYPEM val = HOST(host); *(TYPEE *)(vd + H(reg_off)) = val; }

#define DO_LD_TLB(NAME, H, TYPEE, TYPEM, TLB)                              \
static inline void sve_##NAME##_tlb(CPUARMState *env, void *vd,            \
                        intptr_t reg_off, target_ulong addr, uintptr_t ra) \
{                                                                          \
    TYPEM val = TLB(env, useronly_clean_ptr(addr), ra);                    \
    *(TYPEE *)(vd + H(reg_off)) = val;                                     \
}

typedef void sve_ldst1_tlb_fn(CPUARMState *env, void *vd, intptr_t reg_off,
                              target_ulong vaddr, uintptr_t retaddr);

#define DO_LD_PRIM_2(NAME, H, TE, TM, LD) \
    DO_LD_HOST(ld1##NAME##_be, H, TE, TM, LD##_be_p)    \
    DO_LD_HOST(ld1##NAME##_le, H, TE, TM, LD##_le_p)    \
    DO_LD_TLB(ld1##NAME##_be, H, TE, TM, cpu_##LD##_be_data_ra) \
    DO_LD_TLB(ld1##NAME##_le, H, TE, TM, cpu_##LD##_le_data_ra)

DO_LD_PRIM_2(hh,  H1_2, uint16_t, uint16_t, lduw)

typedef struct {
    void *host;
    int flags;
    MemTxAttrs attrs;
    bool tagged;
} SVEHostPage;

typedef enum {
    FAULT_NO,
    FAULT_FIRST,
    FAULT_ALL,
} SVEContFault;

typedef struct {
    /*
     * First and last element wholly contained within the two pages.
     * mem_off_first[0] and reg_off_first[0] are always set >= 0.
     * reg_off_last[0] may be < 0 if the first element crosses pages.
     * All of mem_off_first[1], reg_off_first[1] and reg_off_last[1]
     * are set >= 0 only if there are complete elements on a second page.
     *
     * The reg_off_* offsets are relative to the internal vector register.
     * The mem_off_first offset is relative to the memory address; the
     * two offsets are different when a load operation extends, a store
     * operation truncates, or for multi-register operations.
     */
    int16_t mem_off_first[2];
    int16_t reg_off_first[2];
    int16_t reg_off_last[2];

    /*
     * One element that is misaligned and spans both pages,
     * or -1 if there is no such active element.
     */
    int16_t mem_off_split;
    int16_t reg_off_split;

    /*
     * The byte offset at which the entire operation crosses a page boundary.
     * Set >= 0 if and only if the entire operation spans two pages.
     */
    int16_t page_split;

    /* TLB data for the two pages. */
    SVEHostPage page[2];
} SVEContLdSt;

static inline void
sve_cont_ldst_watchpoints(SVEContLdSt *info, CPUARMState *env, uint64_t *vg,
                          target_ulong addr, int esize, int msize,
                          int wp_access, uintptr_t retaddr)
{ }

static intptr_t find_next_active(uint64_t *vg, intptr_t reg_off,
                                 intptr_t reg_max, int esz)
{
    uint64_t pg_mask = pred_esz_masks[esz];
    uint64_t pg = (vg[reg_off >> 6] & pg_mask) >> (reg_off & 63);

    /* In normal usage, the first element is active.  */
    if (likely(pg & 1)) {
        return reg_off;
    }

    if (pg == 0) {
        reg_off &= -64;
        do {
            reg_off += 64;
            if (unlikely(reg_off >= reg_max)) {
                /* The entire predicate was false.  */
                return reg_max;
            }
            pg = vg[reg_off >> 6] & pg_mask;
        } while (pg == 0);
    }
    reg_off += ctz64(pg);

    /* We should never see an out of range predicate bit set.  */
    tcg_debug_assert(reg_off < reg_max);
    return reg_off;
}

bool sve_probe_page(SVEHostPage *info, bool nofault, CPUARMState *env,
                    target_ulong addr, int mem_off, MMUAccessType access_type,
                    int mmu_idx, uintptr_t retaddr)
{
    int flags;

    addr += mem_off;

    /*
     * User-only currently always issues with TBI.  See the comment
     * above useronly_clean_ptr.  Usually we clean this top byte away
     * during translation, but we can't do that for e.g. vector + imm
     * addressing modes.
     *
     * We currently always enable TBI for user-only, and do not provide
     * a way to turn it off.  So clean the pointer unconditionally here,
     * rather than look it up here, or pass it down from above.
     */
    addr = useronly_clean_ptr(addr);

#ifdef CONFIG_USER_ONLY
    flags = probe_access_flags(env, addr, 0, access_type, mmu_idx, nofault,
                               &info->host, retaddr);
#else
    CPUTLBEntryFull *full;
    flags = probe_access_full(env, addr, 0, access_type, mmu_idx, nofault,
                              &info->host, &full, retaddr);
#endif
    info->flags = flags;

    if (flags & TLB_INVALID_MASK) {
        g_assert(nofault);
        return false;
    }

#ifdef CONFIG_USER_ONLY
    memset(&info->attrs, 0, sizeof(info->attrs));
    /* Require both ANON and MTE; see allocation_tag_mem(). */
    info->tagged = (flags & PAGE_ANON) && (flags & PAGE_MTE);
#else
    info->attrs = full->attrs;
    info->tagged = full->pte_attrs == 0xf0;
#endif

    /* Ensure that info->host[] is relative to addr, not addr + mem_off. */
    info->host -= mem_off;
    return true;
}

bool sve_cont_ldst_elements(SVEContLdSt *info, target_ulong addr, uint64_t *vg,
                            intptr_t reg_max, int esz, int msize)
{
    const int esize = 1 << esz;
    const uint64_t pg_mask = pred_esz_masks[esz];
    intptr_t reg_off_first = -1, reg_off_last = -1, reg_off_split;
    intptr_t mem_off_last, mem_off_split;
    intptr_t page_split, elt_split;
    intptr_t i;

    /* Set all of the element indices to -1, and the TLB data to 0. */
    memset(info, -1, offsetof(SVEContLdSt, page));
    memset(info->page, 0, sizeof(info->page));

    /* Gross scan over the entire predicate to find bounds. */
    i = 0;
    do {
        uint64_t pg = vg[i] & pg_mask;
        if (pg) {
            reg_off_last = i * 64 + 63 - clz64(pg);
            if (reg_off_first < 0) {
                reg_off_first = i * 64 + ctz64(pg);
            }
        }
    } while (++i * 64 < reg_max);

    if (unlikely(reg_off_first < 0)) {
        /* No active elements, no pages touched. */
        return false;
    }
    tcg_debug_assert(reg_off_last >= 0 && reg_off_last < reg_max);

    info->reg_off_first[0] = reg_off_first;
    info->mem_off_first[0] = (reg_off_first >> esz) * msize;
    mem_off_last = (reg_off_last >> esz) * msize;

    page_split = -(addr | TARGET_PAGE_MASK);
    if (likely(mem_off_last + msize <= page_split)) {
        /* The entire operation fits within a single page. */
        info->reg_off_last[0] = reg_off_last;
        return true;
    }

    info->page_split = page_split;
    elt_split = page_split / msize;
    reg_off_split = elt_split << esz;
    mem_off_split = elt_split * msize;

    /*
     * This is the last full element on the first page, but it is not
     * necessarily active.  If there is no full element, i.e. the first
     * active element is the one that's split, this value remains -1.
     * It is useful as iteration bounds.
     */
    if (elt_split != 0) {
        info->reg_off_last[0] = reg_off_split - esize;
    }

    /* Determine if an unaligned element spans the pages.  */
    if (page_split % msize != 0) {
        /* It is helpful to know if the split element is active. */
        if ((vg[reg_off_split >> 6] >> (reg_off_split & 63)) & 1) {
            info->reg_off_split = reg_off_split;
            info->mem_off_split = mem_off_split;

            if (reg_off_split == reg_off_last) {
                /* The page crossing element is last. */
                return true;
            }
        }
        reg_off_split += esize;
        mem_off_split += msize;
    }

    /*
     * We do want the first active element on the second page, because
     * this may affect the address reported in an exception.
     */
    reg_off_split = find_next_active(vg, reg_off_split, reg_max, esz);
    tcg_debug_assert(reg_off_split <= reg_off_last);
    info->reg_off_first[1] = reg_off_split;
    info->mem_off_first[1] = (reg_off_split >> esz) * msize;
    info->reg_off_last[1] = reg_off_last;
    return true;
}

bool sve_cont_ldst_pages(SVEContLdSt *info, SVEContFault fault,
                         CPUARMState *env, target_ulong addr,
                         MMUAccessType access_type, uintptr_t retaddr)
{
    int mmu_idx = cpu_mmu_index(env, false);
    int mem_off = info->mem_off_first[0];
    bool nofault = fault == FAULT_NO;
    bool have_work = true;

    if (!sve_probe_page(&info->page[0], nofault, env, addr, mem_off,
                        access_type, mmu_idx, retaddr)) {
        /* No work to be done. */
        return false;
    }

    if (likely(info->page_split < 0)) {
        /* The entire operation was on the one page. */
        return true;
    }

    /*
     * If the second page is invalid, then we want the fault address to be
     * the first byte on that page which is accessed.
     */
    if (info->mem_off_split >= 0) {
        /*
         * There is an element split across the pages.  The fault address
         * should be the first byte of the second page.
         */
        mem_off = info->page_split;
        /*
         * If the split element is also the first active element
         * of the vector, then:  For first-fault we should continue
         * to generate faults for the second page.  For no-fault,
         * we have work only if the second page is valid.
         */
        if (info->mem_off_first[0] < info->mem_off_split) {
            nofault = FAULT_FIRST;
            have_work = false;
        }
    } else {
        /*
         * There is no element split across the pages.  The fault address
         * should be the first active element on the second page.
         */
        mem_off = info->mem_off_first[1];
        /*
         * There must have been one active element on the first page,
         * so we're out of first-fault territory.
         */
        nofault = fault != FAULT_ALL;
    }

    have_work |= sve_probe_page(&info->page[1], nofault, env, addr, mem_off,
                                access_type, mmu_idx, retaddr);
    return have_work;
}

void sve_cont_ldst_mte_check(SVEContLdSt *info, CPUARMState *env,
                             uint64_t *vg, target_ulong addr, int esize,
                             int msize, uint32_t mtedesc, uintptr_t ra)
{
    intptr_t mem_off, reg_off, reg_last;

    /* Process the page only if MemAttr == Tagged. */
    if (info->page[0].tagged) {
        mem_off = info->mem_off_first[0];
        reg_off = info->reg_off_first[0];
        reg_last = info->reg_off_split;
        if (reg_last < 0) {
            reg_last = info->reg_off_last[0];
        }

        do {
            uint64_t pg = vg[reg_off >> 6];
            do {
                if ((pg >> (reg_off & 63)) & 1) {
                    mte_check(env, mtedesc, addr, ra);
                }
                reg_off += esize;
                mem_off += msize;
            } while (reg_off <= reg_last && (reg_off & 63));
        } while (reg_off <= reg_last);
    }

    mem_off = info->mem_off_first[1];
    if (mem_off >= 0 && info->page[1].tagged) {
        reg_off = info->reg_off_first[1];
        reg_last = info->reg_off_last[1];

        do {
            uint64_t pg = vg[reg_off >> 6];
            do {
                if ((pg >> (reg_off & 63)) & 1) {
                    mte_check(env, mtedesc, addr, ra);
                }
                reg_off += esize;
                mem_off += msize;
            } while (reg_off & 63);
        } while (reg_off <= reg_last);
    }
}

static inline QEMU_ALWAYS_INLINE
void sve_ldN_r(CPUARMState *env, uint64_t *vg, const target_ulong addr,
               uint32_t desc, const uintptr_t retaddr,
               const int esz, const int msz, const int N, uint32_t mtedesc,
               sve_ldst1_host_fn *host_fn,
               sve_ldst1_tlb_fn *tlb_fn)
{
    const unsigned rd = simd_data(desc);
    const intptr_t reg_max = simd_oprsz(desc);
    intptr_t reg_off, reg_last, mem_off;
    SVEContLdSt info;
    void *host;
    int flags, i;

    /* Find the active elements.  */
    if (!sve_cont_ldst_elements(&info, addr, vg, reg_max, esz, N << msz)) {
        /* The entire predicate was false; no load occurs.  */
        for (i = 0; i < N; ++i) {
            memset(&env->vfp.zregs[(rd + i) & 31], 0, reg_max);
        }
        return;
    }

    /* Probe the page(s).  Exit with exception for any invalid page. */
    sve_cont_ldst_pages(&info, FAULT_ALL, env, addr, MMU_DATA_LOAD, retaddr);

    /* Handle watchpoints for all active elements. */
    sve_cont_ldst_watchpoints(&info, env, vg, addr, 1 << esz, N << msz,
                              BP_MEM_READ, retaddr);

    /*
     * Handle mte checks for all active elements.
     * Since TBI must be set for MTE, !mtedesc => !mte_active.
     */
    if (mtedesc) {
        sve_cont_ldst_mte_check(&info, env, vg, addr, 1 << esz, N << msz,
                                mtedesc, retaddr);
    }

    flags = info.page[0].flags | info.page[1].flags;
    if (unlikely(flags != 0)) {
#ifdef CONFIG_USER_ONLY
        g_assert_not_reached();
#else
        /*
         * At least one page includes MMIO.
         * Any bus operation can fail with cpu_transaction_failed,
         * which for ARM will raise SyncExternal.  Perform the load
         * into scratch memory to preserve register state until the end.
         */
        ARMVectorReg scratch[4] = { };

        mem_off = info.mem_off_first[0];
        reg_off = info.reg_off_first[0];
        reg_last = info.reg_off_last[1];
        if (reg_last < 0) {
            reg_last = info.reg_off_split;
            if (reg_last < 0) {
                reg_last = info.reg_off_last[0];
            }
        }

        do {
            uint64_t pg = vg[reg_off >> 6];
            do {
                if ((pg >> (reg_off & 63)) & 1) {
                    for (i = 0; i < N; ++i) {
                        tlb_fn(env, &scratch[i], reg_off,
                               addr + mem_off + (i << msz), retaddr);
                    }
                }
                reg_off += 1 << esz;
                mem_off += N << msz;
            } while (reg_off & 63);
        } while (reg_off <= reg_last);

        for (i = 0; i < N; ++i) {
            memcpy(&env->vfp.zregs[(rd + i) & 31], &scratch[i], reg_max);
        }
        return;
#endif
    }

    /* The entire operation is in RAM, on valid pages. */

    for (i = 0; i < N; ++i) {
        memset(&env->vfp.zregs[(rd + i) & 31], 0, reg_max);
    }

    mem_off = info.mem_off_first[0];
    reg_off = info.reg_off_first[0];
    reg_last = info.reg_off_last[0];
    host = info.page[0].host;

    while (reg_off <= reg_last) {
        uint64_t pg = vg[reg_off >> 6];
        do {
            if ((pg >> (reg_off & 63)) & 1) {
                for (i = 0; i < N; ++i) {
                    host_fn(&env->vfp.zregs[(rd + i) & 31], reg_off,
                            host + mem_off + (i << msz));
                }
            }
            reg_off += 1 << esz;
            mem_off += N << msz;
        } while (reg_off <= reg_last && (reg_off & 63));
    }

    /*
     * Use the slow path to manage the cross-page misalignment.
     * But we know this is RAM and cannot trap.
     */
    mem_off = info.mem_off_split;
    if (unlikely(mem_off >= 0)) {
        reg_off = info.reg_off_split;
        for (i = 0; i < N; ++i) {
            tlb_fn(env, &env->vfp.zregs[(rd + i) & 31], reg_off,
                   addr + mem_off + (i << msz), retaddr);
        }
    }

    mem_off = info.mem_off_first[1];
    if (unlikely(mem_off >= 0)) {
        reg_off = info.reg_off_first[1];
        reg_last = info.reg_off_last[1];
        host = info.page[1].host;

        do {
            uint64_t pg = vg[reg_off >> 6];
            do {
                if ((pg >> (reg_off & 63)) & 1) {
                    for (i = 0; i < N; ++i) {
                        host_fn(&env->vfp.zregs[(rd + i) & 31], reg_off,
                                host + mem_off + (i << msz));
                    }
                }
                reg_off += 1 << esz;
                mem_off += N << msz;
            } while (reg_off & 63);
        } while (reg_off <= reg_last);
    }
}

static inline QEMU_ALWAYS_INLINE
void sve_ldN_r_mte(CPUARMState *env, uint64_t *vg, target_ulong addr,
                   uint32_t desc, const uintptr_t ra,
                   const int esz, const int msz, const int N,
                   sve_ldst1_host_fn *host_fn,
                   sve_ldst1_tlb_fn *tlb_fn)
{
    uint32_t mtedesc = desc >> (SIMD_DATA_SHIFT + SVE_MTEDESC_SHIFT);
    int bit55 = extract64(addr, 55, 1);

    /* Remove mtedesc from the normal sve descriptor. */
    desc = extract32(desc, 0, SIMD_DATA_SHIFT + SVE_MTEDESC_SHIFT);

    /* Perform gross MTE suppression early. */
    if (!tbi_check(desc, bit55) ||
        tcma_check(desc, bit55, allocation_tag_from_addr(addr))) {
        mtedesc = 0;
    }

    sve_ldN_r(env, vg, addr, desc, ra, esz, msz, N, mtedesc, host_fn, tlb_fn);
}

#define DO_LDN_2(N, SUFF, ESZ)                                          \
void HELPER(sve_ld##N##SUFF##_le_r)(CPUARMState *env, void *vg,         \
                                    target_ulong addr, uint32_t desc)   \
{                                                                       \
    sve_ldN_r(env, vg, addr, desc, GETPC(), ESZ, ESZ, N, 0,             \
              sve_ld1##SUFF##_le_host, sve_ld1##SUFF##_le_tlb);         \
}                                                                       \
void HELPER(sve_ld##N##SUFF##_be_r)(CPUARMState *env, void *vg,         \
                                    target_ulong addr, uint32_t desc)   \
{                                                                       \
    sve_ldN_r(env, vg, addr, desc, GETPC(), ESZ, ESZ, N, 0,             \
              sve_ld1##SUFF##_be_host, sve_ld1##SUFF##_be_tlb);         \
}                                                                       \
void HELPER(sve_ld##N##SUFF##_le_r_mte)(CPUARMState *env, void *vg,     \
                                        target_ulong addr, uint32_t desc) \
{                                                                       \
    sve_ldN_r_mte(env, vg, addr, desc, GETPC(), ESZ, ESZ, N,            \
                  sve_ld1##SUFF##_le_host, sve_ld1##SUFF##_le_tlb);     \
}                                                                       \
void HELPER(sve_ld##N##SUFF##_be_r_mte)(CPUARMState *env, void *vg,     \
                                        target_ulong addr, uint32_t desc) \
{                                                                       \
    sve_ldN_r_mte(env, vg, addr, desc, GETPC(), ESZ, ESZ, N,            \
                  sve_ld1##SUFF##_be_host, sve_ld1##SUFF##_be_tlb);     \
}

DO_LDN_2(3, hh, MO_16)

