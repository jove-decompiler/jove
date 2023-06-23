#define CONFIG_USER_ONLY 1

#define TARGET_MIPS64 1

#include <stddef.h>

#include <stdbool.h>

#include <stdint.h>

#include <stdio.h>

#include <limits.h>

#define G_GNUC_PRINTF( format_idx, arg_idx )    \
  __attribute__((__format__ (__printf__, format_idx, arg_idx)))

#define G_GNUC_UNUSED \
  __attribute__ ((__unused__))

#define G_GNUC_BEGIN_IGNORE_DEPRECATIONS \
  _Pragma("clang diagnostic push") \
  _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"")

#define G_GNUC_END_IGNORE_DEPRECATIONS \
  _Pragma("clang diagnostic pop")

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

typedef struct _GByteArray	GByteArray;

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

typedef struct BusState BusState;

typedef struct Clock Clock;

typedef struct CpuInfoFast CpuInfoFast;

typedef struct CPUState CPUState;

typedef struct DeviceState DeviceState;

typedef struct Error Error;

typedef struct Object Object;

typedef struct ObjectClass ObjectClass;

typedef struct Property Property;

typedef struct QDict QDict;

typedef struct QEMUTimer QEMUTimer;

typedef struct VMStateDescription VMStateDescription;

typedef struct IRQState *qemu_irq;

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

#define BITS_PER_BYTE           CHAR_BIT

#define BITS_TO_LONGS(nr)       DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))

#define DECLARE_BITMAP(name,bits)                  \
        unsigned long name[BITS_TO_LONGS(bits)]

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

typedef enum ResetType {
    RESET_TYPE_COLD,
} ResetType;

typedef void (*ResettableEnterPhase)(Object *obj, ResetType type);

typedef void (*ResettableHoldPhase)(Object *obj);

typedef void (*ResettableExitPhase)(Object *obj);

typedef struct ResettablePhases {
    ResettableEnterPhase enter;
    ResettableHoldPhase hold;
    ResettableExitPhase exit;
} ResettablePhases;

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

typedef struct CPUClass CPUClass;

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

struct MIPSCPUClass {
    /*< private >*/
    CPUClass parent_class;
    /*< public >*/

    DeviceRealize parent_realize;
    ResettablePhases parent_phases;
    const struct mips_def_t *cpu_def;

    /* Used for the jazz board to modify mips_cpu_do_transaction_failed. */
    bool no_data_aborts;
};

typedef uint64_t target_ulong;

typedef uint32_t float32;

typedef uint64_t float64;

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

#define MSA_WRLEN (128)

typedef union wr_t wr_t;

union wr_t {
    int8_t  b[MSA_WRLEN / 8];
    int16_t h[MSA_WRLEN / 16];
    int32_t w[MSA_WRLEN / 32];
    int64_t d[MSA_WRLEN / 64];
};

typedef union fpr_t fpr_t;

union fpr_t {
    float64  fd;   /* ieee double precision */
    float32  fs[2];/* ieee single precision */
    uint64_t d;    /* binary double fixed-point */
    uint32_t w[2]; /* binary single fixed-point */
/* FPU/MSA register mapping is not tested on big-endian hosts. */
    wr_t     wr;   /* vector data */
};

typedef struct CPUMIPSFPUContext CPUMIPSFPUContext;

struct CPUMIPSFPUContext {
    /* Floating point registers */
    fpr_t fpr[32];
    float_status fp_status;
    /* fpu implementation/revision register (fir) */
    uint32_t fcr0;
#define FCR0_FREP 29
#define FCR0_UFRP 28
#define FCR0_HAS2008 23
#define FCR0_F64 22
#define FCR0_L 21
#define FCR0_W 20
#define FCR0_3D 19
#define FCR0_PS 18
#define FCR0_D 17
#define FCR0_S 16
#define FCR0_PRID 8
#define FCR0_REV 0
    /* fcsr */
    uint32_t fcr31_rw_bitmask;
    uint32_t fcr31;
#define FCR31_FS 24
#define FCR31_ABS2008 19
#define FCR31_NAN2008 18
#define SET_FP_COND(num, env)     do { ((env).fcr31) |=                 \
                                       ((num) ? (1 << ((num) + 24)) :   \
                                                (1 << 23));             \
                                     } while (0)
#define CLEAR_FP_COND(num, env)   do { ((env).fcr31) &=                 \
                                       ~((num) ? (1 << ((num) + 24)) :  \
                                                 (1 << 23));            \
                                     } while (0)
#define GET_FP_COND(env)         ((((env).fcr31 >> 24) & 0xfe) |        \
                                 (((env).fcr31 >> 23) & 0x1))
#define GET_FP_CAUSE(reg)        (((reg) >> 12) & 0x3f)
#define GET_FP_ENABLE(reg)       (((reg) >>  7) & 0x1f)
#define GET_FP_FLAGS(reg)        (((reg) >>  2) & 0x1f)
#define SET_FP_CAUSE(reg, v)      do { (reg) = ((reg) & ~(0x3f << 12)) | \
                                               ((v & 0x3f) << 12);       \
                                     } while (0)
#define SET_FP_ENABLE(reg, v)     do { (reg) = ((reg) & ~(0x1f <<  7)) | \
                                               ((v & 0x1f) << 7);        \
                                     } while (0)
#define SET_FP_FLAGS(reg, v)      do { (reg) = ((reg) & ~(0x1f <<  2)) | \
                                               ((v & 0x1f) << 2);        \
                                     } while (0)
#define UPDATE_FP_FLAGS(reg, v)   do { (reg) |= ((v & 0x1f) << 2); } while (0)
#define FP_INEXACT        1
#define FP_UNDERFLOW      2
#define FP_OVERFLOW       4
#define FP_DIV0           8
#define FP_INVALID        16
#define FP_UNIMPLEMENTED  32
};

typedef struct CPUMIPSMVPContext CPUMIPSMVPContext;

struct CPUMIPSMVPContext {
    int32_t CP0_MVPControl;
#define CP0MVPCo_CPA    3
#define CP0MVPCo_STLB   2
#define CP0MVPCo_VPC    1
#define CP0MVPCo_EVP    0
    int32_t CP0_MVPConf0;
#define CP0MVPC0_M      31
#define CP0MVPC0_TLBS   29
#define CP0MVPC0_GS     28
#define CP0MVPC0_PCP    27
#define CP0MVPC0_PTLBE  16
#define CP0MVPC0_TCA    15
#define CP0MVPC0_PVPE   10
#define CP0MVPC0_PTC    0
    int32_t CP0_MVPConf1;
#define CP0MVPC1_CIM    31
#define CP0MVPC1_CIF    30
#define CP0MVPC1_PCX    20
#define CP0MVPC1_PCP2   10
#define CP0MVPC1_PCP1   0
};

#define MIPS_SHADOW_SET_MAX 16

#define MIPS_FPU_MAX 1

#define MIPS_DSP_ACC 4

#define MIPS_KSCRATCH_NUM 6

#define MIPS_MAAR_MAX 16

typedef struct mips_def_t mips_def_t;

typedef struct TCState TCState;

struct TCState {
    target_ulong gpr[32];
#if defined(TARGET_MIPS64)
    /*
     * For CPUs using 128-bit GPR registers, we put the lower halves in gpr[])
     * and the upper halves in gpr_hi[].
     */
    uint64_t gpr_hi[32];
#endif /* TARGET_MIPS64 */
    target_ulong PC;
    target_ulong HI[MIPS_DSP_ACC];
    target_ulong LO[MIPS_DSP_ACC];
    target_ulong ACX[MIPS_DSP_ACC];
    target_ulong DSPControl;
    int32_t CP0_TCStatus;
#define CP0TCSt_TCU3    31
#define CP0TCSt_TCU2    30
#define CP0TCSt_TCU1    29
#define CP0TCSt_TCU0    28
#define CP0TCSt_TMX     27
#define CP0TCSt_RNST    23
#define CP0TCSt_TDS     21
#define CP0TCSt_DT      20
#define CP0TCSt_DA      15
#define CP0TCSt_A       13
#define CP0TCSt_TKSU    11
#define CP0TCSt_IXMT    10
#define CP0TCSt_TASID   0
    int32_t CP0_TCBind;
#define CP0TCBd_CurTC   21
#define CP0TCBd_TBE     17
#define CP0TCBd_CurVPE  0
    target_ulong CP0_TCHalt;
    target_ulong CP0_TCContext;
    target_ulong CP0_TCSchedule;
    target_ulong CP0_TCScheFBack;
    int32_t CP0_Debug_tcstatus;
    target_ulong CP0_UserLocal;

    int32_t msacsr;

#define MSACSR_FS       24
#define MSACSR_FS_MASK  (1 << MSACSR_FS)
#define MSACSR_NX       18
#define MSACSR_NX_MASK  (1 << MSACSR_NX)
#define MSACSR_CEF      2
#define MSACSR_CEF_MASK (0xffff << MSACSR_CEF)
#define MSACSR_RM       0
#define MSACSR_RM_MASK  (0x3 << MSACSR_RM)
#define MSACSR_MASK     (MSACSR_RM_MASK | MSACSR_CEF_MASK | MSACSR_NX_MASK | \
        MSACSR_FS_MASK)

    float_status msa_fp_status;

#define NUMBER_OF_MXU_REGISTERS 16
    target_ulong mxu_gpr[NUMBER_OF_MXU_REGISTERS - 1];
    target_ulong mxu_cr;
#define MXU_CR_LC       31
#define MXU_CR_RC       30
#define MXU_CR_BIAS     2
#define MXU_CR_RD_EN    1
#define MXU_CR_MXU_EN   0

};

typedef struct CPUArchState {
    TCState active_tc;
    CPUMIPSFPUContext active_fpu;

    uint32_t current_tc;
    uint32_t current_fpu;

    uint32_t SEGBITS;
    uint32_t PABITS;
#if defined(TARGET_MIPS64)
# define PABITS_BASE 36
#else
# define PABITS_BASE 32
#endif
    target_ulong SEGMask;
    uint64_t PAMask;
#define PAMASK_BASE ((1ULL << PABITS_BASE) - 1)

    int32_t msair;
#define MSAIR_ProcID    8
#define MSAIR_Rev       0

/*
 * CP0 Register 0
 */
    int32_t CP0_Index;
    /* CP0_MVP* are per MVP registers. */
    int32_t CP0_VPControl;
#define CP0VPCtl_DIS    0
/*
 * CP0 Register 1
 */
    int32_t CP0_Random;
    int32_t CP0_VPEControl;
#define CP0VPECo_YSI    21
#define CP0VPECo_GSI    20
#define CP0VPECo_EXCPT  16
#define CP0VPECo_TE     15
#define CP0VPECo_TargTC 0
    int32_t CP0_VPEConf0;
#define CP0VPEC0_M      31
#define CP0VPEC0_XTC    21
#define CP0VPEC0_TCS    19
#define CP0VPEC0_SCS    18
#define CP0VPEC0_DSC    17
#define CP0VPEC0_ICS    16
#define CP0VPEC0_MVP    1
#define CP0VPEC0_VPA    0
    int32_t CP0_VPEConf1;
#define CP0VPEC1_NCX    20
#define CP0VPEC1_NCP2   10
#define CP0VPEC1_NCP1   0
    target_ulong CP0_YQMask;
    target_ulong CP0_VPESchedule;
    target_ulong CP0_VPEScheFBack;
    int32_t CP0_VPEOpt;
#define CP0VPEOpt_IWX7  15
#define CP0VPEOpt_IWX6  14
#define CP0VPEOpt_IWX5  13
#define CP0VPEOpt_IWX4  12
#define CP0VPEOpt_IWX3  11
#define CP0VPEOpt_IWX2  10
#define CP0VPEOpt_IWX1  9
#define CP0VPEOpt_IWX0  8
#define CP0VPEOpt_DWX7  7
#define CP0VPEOpt_DWX6  6
#define CP0VPEOpt_DWX5  5
#define CP0VPEOpt_DWX4  4
#define CP0VPEOpt_DWX3  3
#define CP0VPEOpt_DWX2  2
#define CP0VPEOpt_DWX1  1
#define CP0VPEOpt_DWX0  0
/*
 * CP0 Register 2
 */
    uint64_t CP0_EntryLo0;
/*
 * CP0 Register 3
 */
    uint64_t CP0_EntryLo1;
#if defined(TARGET_MIPS64)
# define CP0EnLo_RI 63
# define CP0EnLo_XI 62
#else
# define CP0EnLo_RI 31
# define CP0EnLo_XI 30
#endif
    int32_t CP0_GlobalNumber;
#define CP0GN_VPId 0
/*
 * CP0 Register 4
 */
    target_ulong CP0_Context;
    int32_t CP0_MemoryMapID;
/*
 * CP0 Register 5
 */
    int32_t CP0_PageMask;
#define CP0PM_MASK 13
    int32_t CP0_PageGrain_rw_bitmask;
    int32_t CP0_PageGrain;
#define CP0PG_RIE 31
#define CP0PG_XIE 30
#define CP0PG_ELPA 29
#define CP0PG_IEC 27
    target_ulong CP0_SegCtl0;
    target_ulong CP0_SegCtl1;
    target_ulong CP0_SegCtl2;
#define CP0SC_PA        9
#define CP0SC_PA_MASK   (0x7FULL << CP0SC_PA)
#define CP0SC_PA_1GMASK (0x7EULL << CP0SC_PA)
#define CP0SC_AM        4
#define CP0SC_AM_MASK   (0x7ULL << CP0SC_AM)
#define CP0SC_AM_UK     0ULL
#define CP0SC_AM_MK     1ULL
#define CP0SC_AM_MSK    2ULL
#define CP0SC_AM_MUSK   3ULL
#define CP0SC_AM_MUSUK  4ULL
#define CP0SC_AM_USK    5ULL
#define CP0SC_AM_UUSK   7ULL
#define CP0SC_EU        3
#define CP0SC_EU_MASK   (1ULL << CP0SC_EU)
#define CP0SC_C         0
#define CP0SC_C_MASK    (0x7ULL << CP0SC_C)
#define CP0SC_MASK      (CP0SC_C_MASK | CP0SC_EU_MASK | CP0SC_AM_MASK | \
                         CP0SC_PA_MASK)
#define CP0SC_1GMASK    (CP0SC_C_MASK | CP0SC_EU_MASK | CP0SC_AM_MASK | \
                         CP0SC_PA_1GMASK)
#define CP0SC0_MASK     (CP0SC_MASK | (CP0SC_MASK << 16))
#define CP0SC1_XAM      59
#define CP0SC1_XAM_MASK (0x7ULL << CP0SC1_XAM)
#define CP0SC1_MASK     (CP0SC_MASK | (CP0SC_MASK << 16) | CP0SC1_XAM_MASK)
#define CP0SC2_XR       56
#define CP0SC2_XR_MASK  (0xFFULL << CP0SC2_XR)
#define CP0SC2_MASK     (CP0SC_1GMASK | (CP0SC_1GMASK << 16) | CP0SC2_XR_MASK)
    target_ulong CP0_PWBase;
    target_ulong CP0_PWField;
#if defined(TARGET_MIPS64)
#define CP0PF_BDI  32    /* 37..32 */
#define CP0PF_GDI  24    /* 29..24 */
#define CP0PF_UDI  18    /* 23..18 */
#define CP0PF_MDI  12    /* 17..12 */
#define CP0PF_PTI  6     /* 11..6  */
#define CP0PF_PTEI 0     /*  5..0  */
#else
#define CP0PF_GDW  24    /* 29..24 */
#define CP0PF_UDW  18    /* 23..18 */
#define CP0PF_MDW  12    /* 17..12 */
#define CP0PF_PTW  6     /* 11..6  */
#define CP0PF_PTEW 0     /*  5..0  */
#endif
    target_ulong CP0_PWSize;
#if defined(TARGET_MIPS64)
#define CP0PS_BDW  32    /* 37..32 */
#endif
#define CP0PS_PS   30
#define CP0PS_GDW  24    /* 29..24 */
#define CP0PS_UDW  18    /* 23..18 */
#define CP0PS_MDW  12    /* 17..12 */
#define CP0PS_PTW  6     /* 11..6  */
#define CP0PS_PTEW 0     /*  5..0  */
/*
 * CP0 Register 6
 */
    int32_t CP0_Wired;
    int32_t CP0_PWCtl;
#define CP0PC_PWEN      31
#if defined(TARGET_MIPS64)
#define CP0PC_PWDIREXT  30
#define CP0PC_XK        28
#define CP0PC_XS        27
#define CP0PC_XU        26
#endif
#define CP0PC_DPH       7
#define CP0PC_HUGEPG    6
#define CP0PC_PSN       0     /*  5..0  */
    int32_t CP0_SRSConf0_rw_bitmask;
    int32_t CP0_SRSConf0;
#define CP0SRSC0_M      31
#define CP0SRSC0_SRS3   20
#define CP0SRSC0_SRS2   10
#define CP0SRSC0_SRS1   0
    int32_t CP0_SRSConf1_rw_bitmask;
    int32_t CP0_SRSConf1;
#define CP0SRSC1_M      31
#define CP0SRSC1_SRS6   20
#define CP0SRSC1_SRS5   10
#define CP0SRSC1_SRS4   0
    int32_t CP0_SRSConf2_rw_bitmask;
    int32_t CP0_SRSConf2;
#define CP0SRSC2_M      31
#define CP0SRSC2_SRS9   20
#define CP0SRSC2_SRS8   10
#define CP0SRSC2_SRS7   0
    int32_t CP0_SRSConf3_rw_bitmask;
    int32_t CP0_SRSConf3;
#define CP0SRSC3_M      31
#define CP0SRSC3_SRS12  20
#define CP0SRSC3_SRS11  10
#define CP0SRSC3_SRS10  0
    int32_t CP0_SRSConf4_rw_bitmask;
    int32_t CP0_SRSConf4;
#define CP0SRSC4_SRS15  20
#define CP0SRSC4_SRS14  10
#define CP0SRSC4_SRS13  0
/*
 * CP0 Register 7
 */
    int32_t CP0_HWREna;
/*
 * CP0 Register 8
 */
    target_ulong CP0_BadVAddr;
    uint32_t CP0_BadInstr;
    uint32_t CP0_BadInstrP;
    uint32_t CP0_BadInstrX;
/*
 * CP0 Register 9
 */
    int32_t CP0_Count;
    uint32_t CP0_SAARI;
#define CP0SAARI_TARGET 0    /*  5..0  */
    uint64_t CP0_SAAR[2];
#define CP0SAAR_BASE    12   /* 43..12 */
#define CP0SAAR_SIZE    1    /*  5..1  */
#define CP0SAAR_EN      0
/*
 * CP0 Register 10
 */
    target_ulong CP0_EntryHi;
#define CP0EnHi_EHINV 10
    target_ulong CP0_EntryHi_ASID_mask;
/*
 * CP0 Register 11
 */
    int32_t CP0_Compare;
/*
 * CP0 Register 12
 */
    int32_t CP0_Status;
#define CP0St_CU3   31
#define CP0St_CU2   30
#define CP0St_CU1   29
#define CP0St_CU0   28
#define CP0St_RP    27
#define CP0St_FR    26
#define CP0St_RE    25
#define CP0St_MX    24
#define CP0St_PX    23
#define CP0St_BEV   22
#define CP0St_TS    21
#define CP0St_SR    20
#define CP0St_NMI   19
#define CP0St_IM    8
#define CP0St_KX    7
#define CP0St_SX    6
#define CP0St_UX    5
#define CP0St_KSU   3
#define CP0St_ERL   2
#define CP0St_EXL   1
#define CP0St_IE    0
    int32_t CP0_IntCtl;
#define CP0IntCtl_IPTI 29
#define CP0IntCtl_IPPCI 26
#define CP0IntCtl_VS 5
    int32_t CP0_SRSCtl;
#define CP0SRSCtl_HSS 26
#define CP0SRSCtl_EICSS 18
#define CP0SRSCtl_ESS 12
#define CP0SRSCtl_PSS 6
#define CP0SRSCtl_CSS 0
    int32_t CP0_SRSMap;
#define CP0SRSMap_SSV7 28
#define CP0SRSMap_SSV6 24
#define CP0SRSMap_SSV5 20
#define CP0SRSMap_SSV4 16
#define CP0SRSMap_SSV3 12
#define CP0SRSMap_SSV2 8
#define CP0SRSMap_SSV1 4
#define CP0SRSMap_SSV0 0
/*
 * CP0 Register 13
 */
    int32_t CP0_Cause;
#define CP0Ca_BD   31
#define CP0Ca_TI   30
#define CP0Ca_CE   28
#define CP0Ca_DC   27
#define CP0Ca_PCI  26
#define CP0Ca_IV   23
#define CP0Ca_WP   22
#define CP0Ca_IP    8
#define CP0Ca_IP_mask 0x0000FF00
#define CP0Ca_EC    2
/*
 * CP0 Register 14
 */
    target_ulong CP0_EPC;
/*
 * CP0 Register 15
 */
    int32_t CP0_PRid;
    target_ulong CP0_EBase;
    target_ulong CP0_EBaseWG_rw_bitmask;
#define CP0EBase_WG 11
    target_ulong CP0_CMGCRBase;
/*
 * CP0 Register 16 (after Release 1)
 */
    int32_t CP0_Config0;
#define CP0C0_M    31
#define CP0C0_K23  28    /* 30..28 */
#define CP0C0_KU   25    /* 27..25 */
#define CP0C0_MDU  20
#define CP0C0_MM   18
#define CP0C0_BM   16
#define CP0C0_Impl 16    /* 24..16 */
#define CP0C0_BE   15
#define CP0C0_AT   13    /* 14..13 */
#define CP0C0_AR   10    /* 12..10 */
#define CP0C0_MT   7     /*  9..7  */
#define CP0C0_VI   3
#define CP0C0_K0   0     /*  2..0  */
#define CP0C0_AR_LENGTH 3
/*
 * CP0 Register 16 (before Release 1)
 */
#define CP0C0_Impl 16    /* 24..16 */
#define CP0C0_IC   9     /* 11..9 */
#define CP0C0_DC   6     /*  8..6 */
#define CP0C0_IB   5
#define CP0C0_DB   4
    int32_t CP0_Config1;
#define CP0C1_M    31
#define CP0C1_MMU  25    /* 30..25 */
#define CP0C1_IS   22    /* 24..22 */
#define CP0C1_IL   19    /* 21..19 */
#define CP0C1_IA   16    /* 18..16 */
#define CP0C1_DS   13    /* 15..13 */
#define CP0C1_DL   10    /* 12..10 */
#define CP0C1_DA   7     /*  9..7  */
#define CP0C1_C2   6
#define CP0C1_MD   5
#define CP0C1_PC   4
#define CP0C1_WR   3
#define CP0C1_CA   2
#define CP0C1_EP   1
#define CP0C1_FP   0
    int32_t CP0_Config2;
#define CP0C2_M    31
#define CP0C2_TU   28    /* 30..28 */
#define CP0C2_TS   24    /* 27..24 */
#define CP0C2_TL   20    /* 23..20 */
#define CP0C2_TA   16    /* 19..16 */
#define CP0C2_SU   12    /* 15..12 */
#define CP0C2_SS   8     /* 11..8  */
#define CP0C2_SL   4     /*  7..4  */
#define CP0C2_SA   0     /*  3..0  */
    int32_t CP0_Config3;
#define CP0C3_M            31
#define CP0C3_BPG          30
#define CP0C3_CMGCR        29
#define CP0C3_MSAP         28
#define CP0C3_BP           27
#define CP0C3_BI           26
#define CP0C3_SC           25
#define CP0C3_PW           24
#define CP0C3_VZ           23
#define CP0C3_IPLV         21    /* 22..21 */
#define CP0C3_MMAR         18    /* 20..18 */
#define CP0C3_MCU          17
#define CP0C3_ISA_ON_EXC   16
#define CP0C3_ISA          14    /* 15..14 */
#define CP0C3_ULRI         13
#define CP0C3_RXI          12
#define CP0C3_DSP2P        11
#define CP0C3_DSPP         10
#define CP0C3_CTXTC        9
#define CP0C3_ITL          8
#define CP0C3_LPA          7
#define CP0C3_VEIC         6
#define CP0C3_VInt         5
#define CP0C3_SP           4
#define CP0C3_CDMM         3
#define CP0C3_MT           2
#define CP0C3_SM           1
#define CP0C3_TL           0
    int32_t CP0_Config4;
    int32_t CP0_Config4_rw_bitmask;
#define CP0C4_M            31
#define CP0C4_IE           29    /* 30..29 */
#define CP0C4_AE           28
#define CP0C4_VTLBSizeExt  24    /* 27..24 */
#define CP0C4_KScrExist    16
#define CP0C4_MMUExtDef    14
#define CP0C4_FTLBPageSize 8     /* 12..8  */
/* bit layout if MMUExtDef=1 */
#define CP0C4_MMUSizeExt   0     /*  7..0  */
/* bit layout if MMUExtDef=2 */
#define CP0C4_FTLBWays     4     /*  7..4  */
#define CP0C4_FTLBSets     0     /*  3..0  */
    int32_t CP0_Config5;
    int32_t CP0_Config5_rw_bitmask;
#define CP0C5_M            31
#define CP0C5_K            30
#define CP0C5_CV           29
#define CP0C5_EVA          28
#define CP0C5_MSAEn        27
#define CP0C5_PMJ          23    /* 25..23 */
#define CP0C5_WR2          22
#define CP0C5_NMS          21
#define CP0C5_ULS          20
#define CP0C5_XPA          19
#define CP0C5_CRCP         18
#define CP0C5_MI           17
#define CP0C5_GI           15    /* 16..15 */
#define CP0C5_CA2          14
#define CP0C5_XNP          13
#define CP0C5_DEC          11
#define CP0C5_L2C          10
#define CP0C5_UFE          9
#define CP0C5_FRE          8
#define CP0C5_VP           7
#define CP0C5_SBRI         6
#define CP0C5_MVH          5
#define CP0C5_LLB          4
#define CP0C5_MRP          3
#define CP0C5_UFR          2
#define CP0C5_NFExists     0
    int32_t CP0_Config6;
    int32_t CP0_Config6_rw_bitmask;
#define CP0C6_BPPASS          31
#define CP0C6_KPOS            24
#define CP0C6_KE              23
#define CP0C6_VTLBONLY        22
#define CP0C6_LASX            21
#define CP0C6_SSEN            20
#define CP0C6_DISDRTIME       19
#define CP0C6_PIXNUEN         18
#define CP0C6_SCRAND          17
#define CP0C6_LLEXCEN         16
#define CP0C6_DISVC           15
#define CP0C6_VCLRU           14
#define CP0C6_DCLRU           13
#define CP0C6_PIXUEN          12
#define CP0C6_DISBLKLYEN      11
#define CP0C6_UMEMUALEN       10
#define CP0C6_SFBEN           8
#define CP0C6_FLTINT          7
#define CP0C6_VLTINT          6
#define CP0C6_DISBTB          5
#define CP0C6_STPREFCTL       2
#define CP0C6_INSTPREF        1
#define CP0C6_DATAPREF        0
    int32_t CP0_Config7;
    int64_t CP0_Config7_rw_bitmask;
#define CP0C7_WII          31
#define CP0C7_NAPCGEN       2
#define CP0C7_UNIMUEN       1
#define CP0C7_VFPUCGEN      0
    uint64_t CP0_LLAddr;
    uint64_t CP0_MAAR[MIPS_MAAR_MAX];
    int32_t CP0_MAARI;
    /* XXX: Maybe make LLAddr per-TC? */
/*
 * CP0 Register 17
 */
    target_ulong lladdr; /* LL virtual address compared against SC */
    target_ulong llval;
    uint64_t llval_wp;
    uint32_t llnewval_wp;
    uint64_t CP0_LLAddr_rw_bitmask;
    int CP0_LLAddr_shift;
/*
 * CP0 Register 18
 */
    target_ulong CP0_WatchLo[8];
/*
 * CP0 Register 19
 */
    uint64_t CP0_WatchHi[8];
#define CP0WH_ASID 16
#define CP0WH_M    31
/*
 * CP0 Register 20
 */
    target_ulong CP0_XContext;
    int32_t CP0_Framemask;
/*
 * CP0 Register 23
 */
    int32_t CP0_Debug;
#define CP0DB_DBD  31
#define CP0DB_DM   30
#define CP0DB_LSNM 28
#define CP0DB_Doze 27
#define CP0DB_Halt 26
#define CP0DB_CNT  25
#define CP0DB_IBEP 24
#define CP0DB_DBEP 21
#define CP0DB_IEXI 20
#define CP0DB_VER  15
#define CP0DB_DEC  10
#define CP0DB_SSt  8
#define CP0DB_DINT 5
#define CP0DB_DIB  4
#define CP0DB_DDBS 3
#define CP0DB_DDBL 2
#define CP0DB_DBp  1
#define CP0DB_DSS  0
/*
 * CP0 Register 24
 */
    target_ulong CP0_DEPC;
/*
 * CP0 Register 25
 */
    int32_t CP0_Performance0;
/*
 * CP0 Register 26
 */
    int32_t CP0_ErrCtl;
#define CP0EC_WST 29
#define CP0EC_SPR 28
#define CP0EC_ITC 26
/*
 * CP0 Register 28
 */
    uint64_t CP0_TagLo;
    int32_t CP0_DataLo;
/*
 * CP0 Register 29
 */
    int32_t CP0_TagHi;
    int32_t CP0_DataHi;
/*
 * CP0 Register 30
 */
    target_ulong CP0_ErrorEPC;
/*
 * CP0 Register 31
 */
    int32_t CP0_DESAVE;
    target_ulong CP0_KScratch[MIPS_KSCRATCH_NUM];

    /* We waste some space so we can handle shadow registers like TCs. */
    TCState tcs[MIPS_SHADOW_SET_MAX];
    CPUMIPSFPUContext fpus[MIPS_FPU_MAX];
    /* QEMU */
    int error_code;
#define EXCP_TLB_NOMATCH   0x1
#define EXCP_INST_NOTAVAIL 0x2 /* No valid instruction word for BadInstr */
    uint32_t hflags;    /* CPU State */
    /* TMASK defines different execution modes */
#define MIPS_HFLAG_TMASK  0x3F5807FF
#define MIPS_HFLAG_MODE   0x00007 /* execution modes                    */
    /*
     * The KSU flags must be the lowest bits in hflags. The flag order
     * must be the same as defined for CP0 Status. This allows to use
     * the bits as the value of mmu_idx.
     */
#define MIPS_HFLAG_KSU    0x00003 /* kernel/supervisor/user mode mask   */
#define MIPS_HFLAG_UM     0x00002 /* user mode flag                     */
#define MIPS_HFLAG_SM     0x00001 /* supervisor mode flag               */
#define MIPS_HFLAG_KM     0x00000 /* kernel mode flag                   */
#define MIPS_HFLAG_DM     0x00004 /* Debug mode                         */
#define MIPS_HFLAG_64     0x00008 /* 64-bit instructions enabled        */
#define MIPS_HFLAG_CP0    0x00010 /* CP0 enabled                        */
#define MIPS_HFLAG_FPU    0x00020 /* FPU enabled                        */
#define MIPS_HFLAG_F64    0x00040 /* 64-bit FPU enabled                 */
    /*
     * True if the MIPS IV COP1X instructions can be used.  This also
     * controls the non-COP1X instructions RECIP.S, RECIP.D, RSQRT.S
     * and RSQRT.D.
     */
#define MIPS_HFLAG_COP1X  0x00080 /* COP1X instructions enabled         */
#define MIPS_HFLAG_RE     0x00100 /* Reversed endianness                */
#define MIPS_HFLAG_AWRAP  0x00200 /* 32-bit compatibility address wrapping */
#define MIPS_HFLAG_M16    0x00400 /* MIPS16 mode flag                   */
#define MIPS_HFLAG_M16_SHIFT 10
    /*
     * If translation is interrupted between the branch instruction and
     * the delay slot, record what type of branch it is so that we can
     * resume translation properly.  It might be possible to reduce
     * this from three bits to two.
     */
#define MIPS_HFLAG_BMASK_BASE  0x803800
#define MIPS_HFLAG_B      0x00800 /* Unconditional branch               */
#define MIPS_HFLAG_BC     0x01000 /* Conditional branch                 */
#define MIPS_HFLAG_BL     0x01800 /* Likely branch                      */
#define MIPS_HFLAG_BR     0x02000 /* branch to register (can't link TB) */
    /* Extra flags about the current pending branch.  */
#define MIPS_HFLAG_BMASK_EXT 0x7C000
#define MIPS_HFLAG_B16    0x04000 /* branch instruction was 16 bits     */
#define MIPS_HFLAG_BDS16  0x08000 /* branch requires 16-bit delay slot  */
#define MIPS_HFLAG_BDS32  0x10000 /* branch requires 32-bit delay slot  */
#define MIPS_HFLAG_BDS_STRICT  0x20000 /* Strict delay slot size */
#define MIPS_HFLAG_BX     0x40000 /* branch exchanges execution mode    */
#define MIPS_HFLAG_BMASK  (MIPS_HFLAG_BMASK_BASE | MIPS_HFLAG_BMASK_EXT)
    /* MIPS DSP resources access. */
#define MIPS_HFLAG_DSP    0x080000   /* Enable access to DSP resources.    */
#define MIPS_HFLAG_DSP_R2 0x100000   /* Enable access to DSP R2 resources. */
#define MIPS_HFLAG_DSP_R3 0x20000000 /* Enable access to DSP R3 resources. */
    /* Extra flag about HWREna register. */
#define MIPS_HFLAG_HWRENA_ULR 0x200000 /* ULR bit from HWREna is set. */
#define MIPS_HFLAG_SBRI  0x400000 /* R6 SDBBP causes RI excpt. in user mode */
#define MIPS_HFLAG_FBNSLOT 0x800000 /* Forbidden slot                   */
#define MIPS_HFLAG_MSA   0x1000000
#define MIPS_HFLAG_FRE   0x2000000 /* FRE enabled */
#define MIPS_HFLAG_ELPA  0x4000000
#define MIPS_HFLAG_ITC_CACHE  0x8000000 /* CACHE instr. operates on ITC tag */
#define MIPS_HFLAG_ERL   0x10000000 /* error level flag */
    target_ulong btarget;        /* Jump / branch target               */
    target_ulong bcond;          /* Branch condition (if needed)       */

    int SYNCI_Step; /* Address step size for SYNCI */
    int CCRes; /* Cycle count resolution/divisor */
    uint32_t CP0_Status_rw_bitmask; /* Read/write bits in CP0_Status */
    uint32_t CP0_TCStatus_rw_bitmask; /* Read/write bits in CP0_TCStatus */
    uint64_t insn_flags; /* Supported instruction set */
    int saarp;

    /* Fields up to this point are cleared by a CPU reset */
    struct {} end_reset_fields;

    /* Fields from here on are preserved across CPU reset. */
    CPUMIPSMVPContext *mvp;
#if !defined(CONFIG_USER_ONLY)
    CPUMIPSTLBContext *tlb;
    void *irq[8];
    struct MIPSITUState *itu;
    MemoryRegion *itc_tag; /* ITC Configuration Tags */
#endif

    const mips_def_t *cpu_model;
    QEMUTimer *timer; /* Internal timer */
    target_ulong exception_base; /* ExceptionBase input to the core */
    uint64_t cp0_count_ns; /* CP0_Count clock period (in nanoseconds) */
} CPUMIPSState;
#define CONFIG_USER_ONLY 1

#define CONFIG_LINUX 1

#define HOST_BIG_ENDIAN (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)

#include <stddef.h>

#include <stdbool.h>

#include <stdint.h>

#include <sys/types.h>

#include <stdio.h>

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

struct _GArray
{
  gchar *data;
  guint len;
};

GLIB_AVAILABLE_IN_ALL
void     g_list_free_full               (GList            *list,
					 GDestroyNotify    free_func);

GLIB_AVAILABLE_IN_ALL
void     g_slist_free_full               (GSList           *list,
					  GDestroyNotify    free_func);

GLIB_AVAILABLE_IN_ALL
void     g_queue_free_full      (GQueue           *queue,
				GDestroyNotify    free_func);

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

typedef struct QemuSpin QemuSpin;

typedef struct TranslationBlock TranslationBlock;

typedef struct VMStateDescription VMStateDescription;

typedef struct IRQState *qemu_irq;

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

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

#define QTAILQ_FOREACH(var, head, field)                                \
        for ((var) = ((head)->tqh_first);                               \
                (var);                                                  \
                (var) = ((var)->field.tqe_next))

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

struct QemuSpin {
    int value;
};

struct QemuLockCnt {
#ifndef CONFIG_LINUX
    QemuMutex mutex;
#endif
    unsigned count;
};

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

typedef uint64_t vaddr;

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

typedef uint32_t MemOpIdx;

static inline MemOp get_memop(MemOpIdx oi)
{
    return (MemOp)(oi >> 4);
}

#define DECLARE_BITMAP(name,bits)                  \
        unsigned long name[BITS_TO_LONGS(bits)]

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

struct TypeImpl;

typedef struct TypeImpl *Type;

typedef void (ObjectUnparent)(Object *obj);

#define OBJECT_CLASS_CAST_CACHE 4

typedef void (ObjectFree)(void *obj);

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

#define TYPE_DEVICE "device"

typedef void (*DeviceRealize)(DeviceState *dev, Error **errp);

typedef void (*DeviceUnrealize)(DeviceState *dev);

typedef void (*DeviceReset)(DeviceState *dev);

typedef struct Clock Clock;

typedef void *PTR;

typedef uint64_t bfd_vma;

typedef uint8_t bfd_byte;

typedef int (*fprintf_function)(FILE *f, const char *fmt, ...)
    G_GNUC_PRINTF(2, 3);

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

typedef struct CPUClass CPUClass;

typedef struct CPUWatchpoint CPUWatchpoint;

struct TCGCPUOps;

struct AccelCPUClass;

struct SysemuCPUOps;

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

# define TCG_TARGET_REG_BITS 64

#define TCG_TARGET_INTERPRETER 1

#define TCG_TARGET_NB_REGS 16

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

#define TCG_TARGET_NEED_POOL_LABELS

typedef enum {
    TCG_REG_R0 = 0,
    TCG_REG_R1,
    TCG_REG_R2,
    TCG_REG_R3,
    TCG_REG_R4,
    TCG_REG_R5,
    TCG_REG_R6,
    TCG_REG_R7,
    TCG_REG_R8,
    TCG_REG_R9,
    TCG_REG_R10,
    TCG_REG_R11,
    TCG_REG_R12,
    TCG_REG_R13,
    TCG_REG_R14,
    TCG_REG_R15,

    TCG_REG_TMP = TCG_REG_R13,
    TCG_AREG0 = TCG_REG_R14,
    TCG_REG_CALL_STACK = TCG_REG_R15,
} TCGReg;

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

typedef uint64_t tcg_target_ulong;

#define TCG_TARGET_MAYBE_vec            0

typedef uint32_t TCGRegSet;

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

DEF(brcond_i32, 0, 2, 2, TCG_OPF_BB_END | TCG_OPF_COND_BRANCH)

DEF(add2_i32, 2, 4, 0, IMPL(TCG_TARGET_HAS_add2_i32))
DEF(sub2_i32, 2, 4, 0, IMPL(TCG_TARGET_HAS_sub2_i32))
DEF(mulu2_i32, 2, 2, 0, IMPL(TCG_TARGET_HAS_mulu2_i32))
DEF(muls2_i32, 2, 2, 0, IMPL(TCG_TARGET_HAS_muls2_i32))
DEF(muluh_i32, 1, 2, 0, IMPL(TCG_TARGET_HAS_muluh_i32))
DEF(mulsh_i32, 1, 2, 0, IMPL(TCG_TARGET_HAS_mulsh_i32))
DEF(brcond2_i32, 0, 4, 2,
    TCG_OPF_BB_END | TCG_OPF_COND_BRANCH | IMPL(TCG_TARGET_REG_BITS == 32))
DEF(setcond2_i32, 1, 4, 1, IMPL(TCG_TARGET_REG_BITS == 32))

DEF(ext8s_i32, 1, 1, 0, IMPL(TCG_TARGET_HAS_ext8s_i32))
DEF(ext16s_i32, 1, 1, 0, IMPL(TCG_TARGET_HAS_ext16s_i32))
DEF(ext8u_i32, 1, 1, 0, IMPL(TCG_TARGET_HAS_ext8u_i32))
DEF(ext16u_i32, 1, 1, 0, IMPL(TCG_TARGET_HAS_ext16u_i32))
DEF(bswap16_i32, 1, 1, 1, IMPL(TCG_TARGET_HAS_bswap16_i32))
DEF(bswap32_i32, 1, 1, 1, IMPL(TCG_TARGET_HAS_bswap32_i32))
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

DEF(brcond_i64, 0, 2, 2, TCG_OPF_BB_END | TCG_OPF_COND_BRANCH | IMPL64)
DEF(ext8s_i64, 1, 1, 0, IMPL64 | IMPL(TCG_TARGET_HAS_ext8s_i64))
DEF(ext16s_i64, 1, 1, 0, IMPL64 | IMPL(TCG_TARGET_HAS_ext16s_i64))
DEF(ext32s_i64, 1, 1, 0, IMPL64 | IMPL(TCG_TARGET_HAS_ext32s_i64))
DEF(ext8u_i64, 1, 1, 0, IMPL64 | IMPL(TCG_TARGET_HAS_ext8u_i64))
DEF(ext16u_i64, 1, 1, 0, IMPL64 | IMPL(TCG_TARGET_HAS_ext16u_i64))
DEF(ext32u_i64, 1, 1, 0, IMPL64 | IMPL(TCG_TARGET_HAS_ext32u_i64))
DEF(bswap16_i64, 1, 1, 1, IMPL64 | IMPL(TCG_TARGET_HAS_bswap16_i64))
DEF(bswap32_i64, 1, 1, 1, IMPL64 | IMPL(TCG_TARGET_HAS_bswap32_i64))
DEF(bswap64_i64, 1, 1, 1, IMPL64 | IMPL(TCG_TARGET_HAS_bswap64_i64))
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

#define DATA64_ARGS  (TCG_TARGET_REG_BITS == 64 ? 1 : 2)

/* There are tcg_ctx->insn_start_words here, not just one. */
DEF(insn_start, 0, 0, DATA64_ARGS, TCG_OPF_NOT_PRESENT)

DEF(exit_tb, 0, 0, 1, TCG_OPF_BB_EXIT | TCG_OPF_BB_END)
DEF(goto_tb, 0, 0, 1, TCG_OPF_BB_EXIT | TCG_OPF_BB_END)
DEF(goto_ptr, 0, 1, 0, TCG_OPF_BB_EXIT | TCG_OPF_BB_END)

DEF(plugin_cb_start, 0, 0, 3, TCG_OPF_NOT_PRESENT)
DEF(plugin_cb_end, 0, 0, 0, TCG_OPF_NOT_PRESENT)

/* Replicate ld/st ops for 32 and 64-bit guest addresses. */
DEF(qemu_ld_a32_i32, 1, 1, 1,
    TCG_OPF_CALL_CLOBBER | TCG_OPF_SIDE_EFFECTS)
DEF(qemu_st_a32_i32, 0, 1 + 1, 1,
    TCG_OPF_CALL_CLOBBER | TCG_OPF_SIDE_EFFECTS)
DEF(qemu_ld_a32_i64, DATA64_ARGS, 1, 1,
    TCG_OPF_CALL_CLOBBER | TCG_OPF_SIDE_EFFECTS | TCG_OPF_64BIT)
DEF(qemu_st_a32_i64, 0, DATA64_ARGS + 1, 1,
    TCG_OPF_CALL_CLOBBER | TCG_OPF_SIDE_EFFECTS | TCG_OPF_64BIT)

DEF(qemu_ld_a64_i32, 1, DATA64_ARGS, 1,
    TCG_OPF_CALL_CLOBBER | TCG_OPF_SIDE_EFFECTS)
DEF(qemu_st_a64_i32, 0, 1 + DATA64_ARGS, 1,
    TCG_OPF_CALL_CLOBBER | TCG_OPF_SIDE_EFFECTS)
DEF(qemu_ld_a64_i64, DATA64_ARGS, DATA64_ARGS, 1,
    TCG_OPF_CALL_CLOBBER | TCG_OPF_SIDE_EFFECTS | TCG_OPF_64BIT)
DEF(qemu_st_a64_i64, 0, DATA64_ARGS + DATA64_ARGS, 1,
    TCG_OPF_CALL_CLOBBER | TCG_OPF_SIDE_EFFECTS | TCG_OPF_64BIT)

/* Only used by i386 to cope with stupid register constraints. */
DEF(qemu_st8_a32_i32, 0, 1 + 1, 1,
    TCG_OPF_CALL_CLOBBER | TCG_OPF_SIDE_EFFECTS |
    IMPL(TCG_TARGET_HAS_qemu_st8_i32))
DEF(qemu_st8_a64_i32, 0, 1 + DATA64_ARGS, 1,
    TCG_OPF_CALL_CLOBBER | TCG_OPF_SIDE_EFFECTS |
    IMPL(TCG_TARGET_HAS_qemu_st8_i32))

/* Only for 64-bit hosts at the moment. */
DEF(qemu_ld_a32_i128, 2, 1, 1,
    TCG_OPF_CALL_CLOBBER | TCG_OPF_SIDE_EFFECTS | TCG_OPF_64BIT |
    IMPL(TCG_TARGET_HAS_qemu_ldst_i128))
DEF(qemu_ld_a64_i128, 2, 1, 1,
    TCG_OPF_CALL_CLOBBER | TCG_OPF_SIDE_EFFECTS | TCG_OPF_64BIT |
    IMPL(TCG_TARGET_HAS_qemu_ldst_i128))
DEF(qemu_st_a32_i128, 0, 3, 1,
    TCG_OPF_CALL_CLOBBER | TCG_OPF_SIDE_EFFECTS | TCG_OPF_64BIT |
    IMPL(TCG_TARGET_HAS_qemu_ldst_i128))
DEF(qemu_st_a64_i128, 0, 3, 1,
    TCG_OPF_CALL_CLOBBER | TCG_OPF_SIDE_EFFECTS | TCG_OPF_64BIT |
    IMPL(TCG_TARGET_HAS_qemu_ldst_i128))

/* Host vector support.  */

#define IMPLVEC  TCG_OPF_VECTOR | IMPL(TCG_TARGET_MAYBE_vec)

DEF(mov_vec, 1, 1, 0, TCG_OPF_VECTOR | TCG_OPF_NOT_PRESENT)

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
DEF(nand_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_nand_vec))
DEF(nor_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_nor_vec))
DEF(eqv_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_eqv_vec))
DEF(not_vec, 1, 1, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_not_vec))

DEF(shli_vec, 1, 1, 1, IMPLVEC | IMPL(TCG_TARGET_HAS_shi_vec))
DEF(shri_vec, 1, 1, 1, IMPLVEC | IMPL(TCG_TARGET_HAS_shi_vec))
DEF(sari_vec, 1, 1, 1, IMPLVEC | IMPL(TCG_TARGET_HAS_shi_vec))
DEF(rotli_vec, 1, 1, 1, IMPLVEC | IMPL(TCG_TARGET_HAS_roti_vec))

DEF(shls_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_shs_vec))
DEF(shrs_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_shs_vec))
DEF(sars_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_shs_vec))
DEF(rotls_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_rots_vec))

DEF(shlv_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_shv_vec))
DEF(shrv_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_shv_vec))
DEF(sarv_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_shv_vec))
DEF(rotlv_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_rotv_vec))
DEF(rotrv_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_rotv_vec))

DEF(cmp_vec, 1, 2, 1, IMPLVEC)

DEF(bitsel_vec, 1, 3, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_bitsel_vec))
DEF(cmpsel_vec, 1, 4, 1, IMPLVEC | IMPL(TCG_TARGET_HAS_cmpsel_vec))

DEF(last_generic, 0, 0, 0, TCG_OPF_NOT_PRESENT)

#if TCG_TARGET_MAYBE_vec
#include "tcg-target.opc.h"
#endif

#ifdef TCG_TARGET_INTERPRETER
/* These opcodes are only for use between the tci generator and interpreter. */
DEF(tci_movi, 1, 0, 1, TCG_OPF_NOT_PRESENT)
DEF(tci_movl, 1, 0, 1, TCG_OPF_NOT_PRESENT)
#endif

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

typedef struct TCGOp TCGOp;

struct TCGLabelUse {
    QSIMPLEQ_ENTRY(TCGLabelUse) next;
    TCGOp *op;
};

typedef struct TCGLabel TCGLabel;

struct TCGLabel {
    bool present;
    bool has_value;
    uint16_t id;
    union {
        uintptr_t value;
        const tcg_insn_unit *value_ptr;
    } u;
    QSIMPLEQ_HEAD(, TCGLabelUse) branches;
    QSIMPLEQ_HEAD(, TCGRelocation) relocs;
    QSIMPLEQ_ENTRY(TCGLabel) next;
};

#define TCG_MAX_TEMPS 512

#define TCG_MAX_INSNS 512

typedef struct TCGPool {
    struct TCGPool *next;
    int size;
    uint8_t data[] __attribute__ ((aligned));
} TCGPool;

typedef enum TCGType {
    TCG_TYPE_I32,
    TCG_TYPE_I64,
    TCG_TYPE_I128,

    TCG_TYPE_V64,
    TCG_TYPE_V128,
    TCG_TYPE_V256,

    /* Number of different types (integer not enum) */
#define TCG_TYPE_COUNT  (TCG_TYPE_V256 + 1)

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
} TCGType;

typedef tcg_target_ulong TCGArg;

typedef enum TCGTempVal {
    TEMP_VAL_DEAD,
    TEMP_VAL_REG,
    TEMP_VAL_MEM,
    TEMP_VAL_CONST,
} TCGTempVal;

typedef enum TCGTempKind {
    /*
     * Temp is dead at the end of the extended basic block (EBB),
     * the single-entry multiple-exit region that falls through
     * conditional branches.
     */
    TEMP_EBB,
    /* Temp is live across the entire translation block, but dead at end. */
    TEMP_TB,
    /* Temp is live across the entire translation block, and between them. */
    TEMP_GLOBAL,
    /* Temp is in a fixed register. */
    TEMP_FIXED,
    /* Temp is a fixed constant. */
    TEMP_CONST,
} TCGTempKind;

typedef struct TCGTemp {
    TCGReg reg:8;
    TCGTempVal val_type:8;
    TCGType base_type:8;
    TCGType type:8;
    TCGTempKind kind:3;
    unsigned int indirect_reg:1;
    unsigned int indirect_base:1;
    unsigned int mem_coherent:1;
    unsigned int mem_allocated:1;
    unsigned int temp_allocated:1;
    unsigned int temp_subindex:1;

    int64_t val;
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

typedef uint32_t TCGLifeData;

#define TCGOP_CALLI(X)    (X)->param1

#define TCGOP_CALLO(X)    (X)->param2

struct TCGOp {
    TCGOpcode opc   : 8;
    unsigned nargs  : 8;

    /* Parameters for this opcode.  See below.  */
    unsigned param1 : 8;
    unsigned param2 : 8;

    /* Lifetime data of the operands.  */
    TCGLifeData life;

    /* Next and previous opcodes.  */
    QTAILQ_ENTRY(TCGOp) link;

    /* Register preferences for the output(s).  */
    TCGRegSet output_pref[2];

    /* Arguments for the opcode.  */
    TCGArg args[];
};

struct TCGContext {
    uint8_t *pool_cur, *pool_end;
    TCGPool *pool_first, *pool_current, *pool_first_large;
    int nb_labels;
    int nb_globals;
    int nb_temps;
    int nb_indirects;
    int nb_ops;
    TCGType addr_type;            /* TCG_TYPE_I32 or TCG_TYPE_I64 */

#ifdef CONFIG_SOFTMMU
    int tlb_fast_offset;
    int page_mask;
    uint8_t page_bits;
    uint8_t tlb_dyn_max_bits;
#endif
    uint8_t insn_start_words;
    TCGBar guest_mo;

    TCGRegSet reserved_regs;
    intptr_t current_frame_offset;
    intptr_t frame_start;
    intptr_t frame_end;
    TCGTemp *frame_temp;

    TranslationBlock *gen_tb;     /* tb for which code is being generated */
    tcg_insn_unit *code_buf;      /* pointer for start of tb */
    tcg_insn_unit *code_ptr;      /* pointer for running end of tb */

#ifdef CONFIG_PROFILER
    TCGProfile prof;
#endif

#ifdef CONFIG_DEBUG_TCG
    int goto_tb_issue_mask;
    const TCGOpcode *vecop_list;
#endif

    /* Code generation.  Note that we specifically do not use tcg_insn_unit
       here, because there's too much arithmetic throughout that relies
       on addition and subtraction working on bytes.  Rely on the GCC
       extension that allows arithmetic on void*.  */
    void *code_gen_buffer;
    size_t code_gen_buffer_size;
    void *code_gen_ptr;
    void *data_gen_ptr;

    /* Threshold to flush the translated code buffer.  */
    void *code_gen_highwater;

    /* Track which vCPU triggers events */
    CPUState *cpu;                      /* *_trans */

    /* These structures are private to tcg-target.c.inc.  */
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
#endif

    GHashTable *const_table[TCG_TYPE_COUNT];
    TCGTempSet free_temps[TCG_TYPE_COUNT];
    TCGTemp temps[TCG_MAX_TEMPS]; /* globals first, temps after */

    QTAILQ_HEAD(, TCGOp) ops, free_ops;
    QSIMPLEQ_HEAD(, TCGLabel) labels;

    /* Tells which temporary holds a given register.
       It does not take into account fixed registers */
    TCGTemp *reg_to_temp[TCG_TARGET_NB_REGS];

    uint16_t gen_insn_end_off[TCG_MAX_INSNS];
    uint64_t *gen_insn_data;

    /* Exit to translator on overflow. */
    sigjmp_buf jmp_trans;
};

extern __thread TCGContext *tcg_ctx;

static inline TCGArg temp_arg(TCGTemp *ts)
{
    return (uintptr_t)ts;
}

static inline TCGTemp *arg_temp(TCGArg a)
{
    return (TCGTemp *)(uintptr_t)a;
}

static inline size_t temp_idx(TCGTemp *ts)
{
    return ts - tcg_ctx->temps;
}

static inline TCGLabel *arg_label(TCGArg i)
{
    return (TCGLabel *)(uintptr_t)i;
}
