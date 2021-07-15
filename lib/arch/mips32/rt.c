#define _LARGEFILE64_SOURCE /* for O_LARGEFILE */
#define _GNU_SOURCE         /* for what? TODO */

#define CONFIG_USER_ONLY 1

#  define GCC_FMT_ATTR(n, m) __attribute__((format(printf, n, m)))

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

typedef struct Error Error;

typedef struct MemoryMappingList MemoryMappingList;

typedef struct MemoryRegion MemoryRegion;

typedef struct ObjectClass ObjectClass;

typedef struct Property Property;

typedef struct QemuMutex QemuMutex;

typedef struct QemuOpts QemuOpts;

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

#define BITS_PER_BYTE           CHAR_BIT

#define BITS_TO_LONGS(nr)       DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))

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
    DEVICE_CATEGORY_MAX
} DeviceCategory;

typedef void (*DeviceRealize)(DeviceState *dev, Error **errp);

typedef void (*DeviceUnrealize)(DeviceState *dev, Error **errp);

typedef void (*DeviceReset)(DeviceState *dev);

typedef struct DeviceClass {
    /*< private >*/
    ObjectClass parent_class;
    /*< public >*/

    DECLARE_BITMAP(categories, DEVICE_CATEGORY_MAX);
    const char *fw_name;
    const char *desc;
    Property *props;

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
    DeviceReset reset;
    DeviceRealize realize;
    DeviceUnrealize unrealize;

    /* device state */
    const VMStateDescription *vmsd;

    /* Private to qdev / bus.  */
    const char *bus_type;
} DeviceClass;

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
#define bfd_mach_arm_unknown	0
#define bfd_mach_arm_2		1
#define bfd_mach_arm_2a		2
#define bfd_mach_arm_3		3
#define bfd_mach_arm_3M 	4
#define bfd_mach_arm_4 		5
#define bfd_mach_arm_4T 	6
#define bfd_mach_arm_5 		7
#define bfd_mach_arm_5T		8
#define bfd_mach_arm_5TE	9
#define bfd_mach_arm_XScale	10
#define bfd_mach_arm_ep9312	11
#define bfd_mach_arm_iWMMXt	12
#define bfd_mach_arm_iWMMXt2	13
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
  bfd_arch_cris,       /* Axis CRIS */
#define bfd_mach_cris_v0_v10   255
#define bfd_mach_cris_v32      32
#define bfd_mach_cris_v10_v32  1032
  bfd_arch_microblaze, /* Xilinx MicroBlaze.  */
  bfd_arch_moxie,      /* The Moxie core.  */
  bfd_arch_ia64,      /* HP/Intel ia64 */
#define bfd_mach_ia64_elf64    64
#define bfd_mach_ia64_elf32    32
  bfd_arch_nios2,	/* Nios II */
#define bfd_mach_nios2          0
#define bfd_mach_nios2r1        1
#define bfd_mach_nios2r2        2
  bfd_arch_lm32,       /* Lattice Mico32 */
#define bfd_mach_lm32 1
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
    GCC_FMT_ATTR(2, 3);

enum dis_insn_type {
  dis_noninsn,			/* Not a valid instruction */
  dis_nonbranch,		/* Not a branch instruction */
  dis_branch,			/* Unconditional branch */
  dis_condbranch,		/* Conditional branch */
  dis_jsr,			/* Jump to subroutine */
  dis_condjsr,			/* Conditional jump to subroutine */
  dis_dref,			/* Data reference instruction */
  dis_dref2			/* Two data references in instruction */
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
#define INSN_HAS_RELOC	0x80000000
#define INSN_ARM_BE32	0x00010000
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
  bfd_byte *buffer;
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

  char insn_info_valid;		/* Branch info has been set. */
  char branch_delay_insns;	/* How many sequential insn's will run before
				   a branch takes effect.  (0 = normal) */
  char data_size;		/* Size of data reference in insn, in bytes */
  enum dis_insn_type insn_type;	/* Type of instruction */
  bfd_vma target;		/* Target address of branch or dref, if known;
				   zero if unknown.  */
  bfd_vma target2;		/* Second target address for dref2 */

  /* Command line options specific to the target disassembler.  */
  char * disassembler_options;

  /* Options for Capstone disassembly.  */
  int cap_arch;
  int cap_mode;
  int cap_insn_unit;
  int cap_insn_split;

} disassemble_info;

typedef uint64_t hwaddr;

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

typedef uint32_t MemTxResult;

typedef enum GuestPanicInformationType {
    GUEST_PANIC_INFORMATION_TYPE_HYPER_V,
    GUEST_PANIC_INFORMATION_TYPE_S390,
    GUEST_PANIC_INFORMATION_TYPE__MAX,
} GuestPanicInformationType;

typedef struct GuestPanicInformation GuestPanicInformation;

typedef struct GuestPanicInformationHyperV GuestPanicInformationHyperV;

typedef enum S390CrashReason {
    S390_CRASH_REASON_UNKNOWN,
    S390_CRASH_REASON_DISABLED_WAIT,
    S390_CRASH_REASON_EXTINT_LOOP,
    S390_CRASH_REASON_PGMINT_LOOP,
    S390_CRASH_REASON_OPINT_LOOP,
    S390_CRASH_REASON__MAX,
} S390CrashReason;

typedef struct GuestPanicInformationS390 GuestPanicInformationS390;

struct GuestPanicInformationHyperV {
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
    uint64_t arg4;
    uint64_t arg5;
};

struct GuestPanicInformationS390 {
    uint32_t core;
    uint64_t psw_mask;
    uint64_t psw_addr;
    S390CrashReason reason;
};

struct GuestPanicInformation {
    GuestPanicInformationType type;
    union { /* union tag is @type */
        GuestPanicInformationHyperV hyper_v;
        GuestPanicInformationS390 s390;
    } u;
};

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

typedef int (*WriteCoreDumpFunction)(const void *buf, size_t size,
                                     void *opaque);

typedef uint64_t vaddr;

typedef enum MMUAccessType {
    MMU_DATA_LOAD  = 0,
    MMU_DATA_STORE = 1,
    MMU_INST_FETCH = 2
} MMUAccessType;

typedef struct CPUWatchpoint CPUWatchpoint;

struct TranslationBlock;

typedef struct CPUClass {
    /*< private >*/
    DeviceClass parent_class;
    /*< public >*/

    ObjectClass *(*class_by_name)(const char *cpu_model);
    void (*parse_features)(const char *typename, char *str, Error **errp);

    void (*reset)(CPUState *cpu);
    int reset_dump_flags;
    bool (*has_work)(CPUState *cpu);
    void (*do_interrupt)(CPUState *cpu);
    void (*do_unaligned_access)(CPUState *cpu, vaddr addr,
                                MMUAccessType access_type,
                                int mmu_idx, uintptr_t retaddr);
    void (*do_transaction_failed)(CPUState *cpu, hwaddr physaddr, vaddr addr,
                                  unsigned size, MMUAccessType access_type,
                                  int mmu_idx, MemTxAttrs attrs,
                                  MemTxResult response, uintptr_t retaddr);
    bool (*virtio_is_big_endian)(CPUState *cpu);
    int (*memory_rw_debug)(CPUState *cpu, vaddr addr,
                           uint8_t *buf, int len, bool is_write);
    void (*dump_state)(CPUState *cpu, FILE *, int flags);
    GuestPanicInformation* (*get_crash_info)(CPUState *cpu);
    void (*dump_statistics)(CPUState *cpu, int flags);
    int64_t (*get_arch_id)(CPUState *cpu);
    bool (*get_paging_enabled)(const CPUState *cpu);
    void (*get_memory_mapping)(CPUState *cpu, MemoryMappingList *list,
                               Error **errp);
    void (*set_pc)(CPUState *cpu, vaddr value);
    void (*synchronize_from_tb)(CPUState *cpu, struct TranslationBlock *tb);
    bool (*tlb_fill)(CPUState *cpu, vaddr address, int size,
                     MMUAccessType access_type, int mmu_idx,
                     bool probe, uintptr_t retaddr);
    hwaddr (*get_phys_page_debug)(CPUState *cpu, vaddr addr);
    hwaddr (*get_phys_page_attrs_debug)(CPUState *cpu, vaddr addr,
                                        MemTxAttrs *attrs);
    int (*asidx_from_attrs)(CPUState *cpu, MemTxAttrs attrs);
    int (*gdb_read_register)(CPUState *cpu, uint8_t *buf, int reg);
    int (*gdb_write_register)(CPUState *cpu, uint8_t *buf, int reg);
    bool (*debug_check_watchpoint)(CPUState *cpu, CPUWatchpoint *wp);
    void (*debug_excp_handler)(CPUState *cpu);

    int (*write_elf64_note)(WriteCoreDumpFunction f, CPUState *cpu,
                            int cpuid, void *opaque);
    int (*write_elf64_qemunote)(WriteCoreDumpFunction f, CPUState *cpu,
                                void *opaque);
    int (*write_elf32_note)(WriteCoreDumpFunction f, CPUState *cpu,
                            int cpuid, void *opaque);
    int (*write_elf32_qemunote)(WriteCoreDumpFunction f, CPUState *cpu,
                                void *opaque);

    const VMStateDescription *vmsd;
    const char *gdb_core_xml_file;
    gchar * (*gdb_arch_name)(CPUState *cpu);
    const char * (*gdb_get_dynamic_xml)(CPUState *cpu, const char *xmlname);
    void (*cpu_exec_enter)(CPUState *cpu);
    void (*cpu_exec_exit)(CPUState *cpu);
    bool (*cpu_exec_interrupt)(CPUState *cpu, int interrupt_request);

    void (*disas_set_info)(CPUState *cpu, disassemble_info *info);
    vaddr (*adjust_watchpoint_address)(CPUState *cpu, vaddr addr, int len);
    void (*tcg_initialize)(void);

    /* Keep non-pointer data at the end to minimize holes.  */
    int gdb_num_core_regs;
    bool gdb_stop_before_watchpoint;
} CPUClass;

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

typedef struct MIPSCPUClass {
    /*< private >*/
    CPUClass parent_class;
    /*< public >*/

    DeviceRealize parent_realize;
    void (*parent_reset)(CPUState *cpu);
    const struct mips_def_t *cpu_def;
} MIPSCPUClass;

typedef uint32_t target_ulong;

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

    /* Upper 64-bit MMRs (multimedia registers); the lower 64-bit are GPRs */
    uint64_t mmr[32];

#define NUMBER_OF_MXU_REGISTERS 16
    target_ulong mxu_gpr[NUMBER_OF_MXU_REGISTERS - 1];
    target_ulong mxu_cr;
#define MXU_CR_LC       31
#define MXU_CR_RC       30
#define MXU_CR_BIAS     2
#define MXU_CR_RD_EN    1
#define MXU_CR_MXU_EN   0

};

struct MIPSITUState;

typedef struct CPUMIPSState CPUMIPSState;

struct CPUMIPSState {
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
 * CP0 Register 16
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
    int32_t CP0_Config7;
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
    int32_t CP0_WatchHi[8];
#define CP0WH_ASID 16
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
#define MIPS_HFLAG_TMASK  0x1F5807FF
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
#endif

    const mips_def_t *cpu_model;
    void *irq[8];
    QEMUTimer *timer; /* Internal timer */
    struct MIPSITUState *itu;
    MemoryRegion *itc_tag; /* ITC Configuration Tags */
    target_ulong exception_base; /* ExceptionBase input to the core */
};

#include <stddef.h>

/* __thread */ struct CPUMIPSState __jove_env;

/* __thread */ uint64_t *__jove_trace       = NULL;
/* __thread */ uint64_t *__jove_trace_begin = NULL;

/* __thread */ uint64_t *__jove_callstack       = NULL;
/* __thread */ uint64_t *__jove_callstack_begin = NULL;

#define _JOVE_MAX_BINARIES 512

uintptr_t *__jove_function_tables[_JOVE_MAX_BINARIES] = {
    [0 ... _JOVE_MAX_BINARIES - 1] = NULL
};

int    __jove_startup_info_argc = 0;
char **__jove_startup_info_argv = NULL;
char **__jove_startup_info_environ = NULL;

//
// struct sigaction
//
#  define __user

#define _NSIG		128

#define _NSIG_BPW	(sizeof(unsigned long) * 8)

#define _NSIG_WORDS	(_NSIG / _NSIG_BPW)

typedef struct {
	unsigned long sig[_NSIG_WORDS];
} kernel_sigset_t;

typedef void __signalfn_t(int);

typedef __signalfn_t __user *__sighandler_t;

#define __ARCH_HAS_IRIX_SIGACTION

struct kernel_sigaction {
#ifndef __ARCH_HAS_IRIX_SIGACTION
	__sighandler_t	sa_handler;
	unsigned long	sa_flags;
#else
	unsigned int	sa_flags;
	__sighandler_t	sa_handler;
#endif
#ifdef __ARCH_HAS_SA_RESTORER
	__sigrestore_t sa_restorer;
#endif
	kernel_sigset_t	sa_mask;	/* mask last for extensibility */
};

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <signal.h>
#include <ucontext.h>

#define __LOG_COLOR_PREFIX "\033["
#define __LOG_COLOR_SUFFIX "m"

#define __LOG_GREEN          __LOG_COLOR_PREFIX "32" __LOG_COLOR_SUFFIX
#define __LOG_RED            __LOG_COLOR_PREFIX "31" __LOG_COLOR_SUFFIX
#define __LOG_BOLD_GREEN     __LOG_COLOR_PREFIX "1;32" __LOG_COLOR_SUFFIX
#define __LOG_BOLD_BLUE      __LOG_COLOR_PREFIX "1;34" __LOG_COLOR_SUFFIX
#define __LOG_BOLD_RED       __LOG_COLOR_PREFIX "1;31" __LOG_COLOR_SUFFIX "CS-ERROR: "
#define __LOG_MAGENTA        __LOG_COLOR_PREFIX "35" __LOG_COLOR_SUFFIX
#define __LOG_CYAN           __LOG_COLOR_PREFIX "36" __LOG_COLOR_SUFFIX
#define __LOG_YELLOW         __LOG_COLOR_PREFIX "33" __LOG_COLOR_SUFFIX
#define __LOG_BOLD_YELLOW    __LOG_COLOR_PREFIX "1;33" __LOG_COLOR_SUFFIX
#define __LOG_NORMAL_COLOR   __LOG_COLOR_PREFIX "0" __LOG_COLOR_SUFFIX

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define _CTOR   __attribute__((constructor(0)))
#define _INL    __attribute__((always_inline))
#define _UNUSED __attribute__((unused))
#define _NAKED  __attribute__((naked))
#define _NOINL  __attribute__((noinline))
#define _NORET  __attribute__((noreturn))
#define _HIDDEN __attribute__((visibility("hidden")))

#define JOVE_SYS_ATTR _HIDDEN _UNUSED
#include "jove_sys.h"

static void _jove_rt_signal_handler(int, siginfo_t *, ucontext_t *);
_NAKED static void _jove_inverse_thunk(void);

static void _jove_callstack_init(void);
static void _jove_trace_init(void);
static void _jove_flush_trace(void);
static void _jove_init_cpu_state(void);

#define _UNREACHABLE(...)                                                      \
  do {                                                                         \
    char line_str[65];                                                         \
    uint_to_string(__LINE__, line_str, 10);                                    \
                                                                               \
    char buff[256];                                                            \
    buff[0] = '\0';                                                            \
                                                                               \
    _strcat(buff, "JOVE UNREACHABLE: " __VA_ARGS__);                           \
    _strcat(buff, " (");                                                       \
    _strcat(buff, __FILE__);                                                   \
    _strcat(buff, ":");                                                        \
    _strcat(buff, line_str);                                                   \
    _strcat(buff, ")\n");                                                      \
    _robust_write(2 /* stderr */, buff, _strlen(buff));                        \
                                                                               \
    _jove_sys_exit_group(1);                                                   \
                                                                               \
    __builtin_unreachable();                                                   \
  } while (false)

#define JOVE_PAGE_SIZE 4096
#define JOVE_STACK_SIZE (256 * JOVE_PAGE_SIZE)
#define JOVE_TRACE_BUFF_SIZE (64 * JOVE_PAGE_SIZE)

static target_ulong _jove_alloc_callstack(void);
_HIDDEN void _jove_free_callstack(target_ulong);

static target_ulong _jove_alloc_stack(void);
_HIDDEN void _jove_free_stack(target_ulong);

_HIDDEN void _jove_free_stack_later(target_ulong);
_HIDDEN uintptr_t _jove_handle_signal_delivery(target_ulong SignalDelivery,
                                               struct CPUMIPSState *SavedState);

#define JOVE_CALLSTACK_SIZE (32 * JOVE_PAGE_SIZE)

//
// utility functions
//
static _INL void *_memchr(const void *s, int c, size_t n);
static _INL void *_memset(void *dst, int c, size_t n);
static _INL void *_memcpy(void *dest, const void *src, size_t n);
static _INL char *_strcat(char *s, const char *append);
static _INL size_t _strlen(const char *s);
static _INL void uint_to_string(uint32_t x, char *Str, unsigned Radix);
static _INL unsigned _read_pseudo_file(const char *path, char *out, size_t len);
static _INL void _description_of_address_for_maps(char *out, uintptr_t Addr, char *maps, const unsigned n);
static _INL unsigned _getHexDigit(char cdigit);
static _INL uint32_t _u32ofhexstr(char *str_begin, char *str_end);
static _INL ssize_t _robust_write(int fd, void *const buf, const size_t count);

void _jove_inverse_thunk(void) {
  asm volatile("sw $v0,48($sp)" "\n"
               "sw $v1,52($sp)" "\n" /* preserve return registers */

               //
               // free the callstack we allocated in sighandler
               //
               "lw $a0,32($sp)" "\n"
               "lw $a0,0($a0)"  "\n"
               "lw $t9,44($sp)" "\n"
               ".set noreorder" "\n"
               "jalr $t9"       "\n" // _jove_free_callstack(__jove_callstack_begin)
               "nop"            "\n"
               ".set reorder"   "\n"

               //
               // restore __jove_callstack
               //
               "lw $a0,60($sp)" "\n"
               "lw $a1,16($sp)" "\n"
               "sw $a1,0($a0)"  "\n" // __jove_callstack = saved_callstack

               //
               // restore __jove_callstack_begin
               //
               "lw $a0,56($sp)" "\n"
               "lw $a1,20($sp)" "\n"
               "sw $a1,0($a0)"  "\n" // __jove_callstack_begin = saved_callstack_begin

               //
               // mark newstack as to be freed
               //
               "lw $a0,24($sp)" "\n"
               "lw $t9,40($sp)" "\n"
               ".set noreorder" "\n"
               "jalr $t9"       "\n" // _jove_free_stack_later(newstack)
               "nop"            "\n"
               ".set reorder"   "\n"

               //
               // signal handling
               //
               "lw $a0,64($sp)" "\n"
               "lw $a1,72($sp)" "\n"
               "lw $t9,68($sp)" "\n"
               ".set noreorder" "\n"
               "jalr $t9"       "\n" // _jove_handle_signal_delivery(...)
               "nop"            "\n"
               ".set reorder"   "\n"

               "move $a3, $v0"  "\n"

               "lw $v0,48($sp)" "\n"
               "lw $v1,52($sp)" "\n" /* preserve return registers */

               //
               // restore emulated stack pointer
               //
               "lw $a0,28($sp)" "\n" // a0 = &emusp
               //"lw $a3,0($a0)"  "\n" // a3 = emusp

               "lw $a1,12($sp)" "\n" // saved_emusp in $a1
               "sw $a1,0($a0)"  "\n" // restore emusp

               "lw $a2,4($sp)"  "\n" // saved_retaddr in $a2

               ".set noreorder" "\n"
               "jr $a2"         "\n" // pc = saved_retaddr
               "move $sp, $a3"  "\n" // [delay slot] sp = emusp
               ".set reorder"   "\n"

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

void _jove_rt_init(void) {
  static bool __has_inited = false;
  if (__has_inited)
    return;
  __has_inited = true;

  struct kernel_sigaction sa;
  _memset(&sa, 0, sizeof(sa));

#undef sa_handler
#undef sa_restorer
#undef sa_flags

  sa.sa_handler = _jove_rt_signal_handler;
  sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
  //sa.sa_restorer = _jove_do_rt_sigreturn;

  {
    long ret =
        _jove_sys_rt_sigaction(SIGSEGV, &sa, NULL, sizeof(kernel_sigset_t));
    if (ret < 0) {
      _UNREACHABLE();
    }
  }

  target_ulong newstack = _jove_alloc_stack();

  stack_t uss = {.ss_sp = newstack + JOVE_PAGE_SIZE,
                 .ss_flags = 0,
                 .ss_size = JOVE_STACK_SIZE - 2 * JOVE_PAGE_SIZE};
  {
    long ret = _jove_sys_sigaltstack(&uss, NULL);
    if (ret < 0) {
      _UNREACHABLE();
    }
  }

  _jove_callstack_init();
  _jove_trace_init();
  _jove_init_cpu_state();
}

ssize_t _robust_write(int fd, void *const buf, const size_t count) {
  uint8_t *const _buf = (uint8_t *)buf;

  unsigned n = 0;
  do {
    unsigned left = count - n;

    ssize_t ret = _jove_sys_write(fd, &_buf[n], left);

    if (ret == 0)
      return -EIO;

    if (ret < 0) {
      if (ret == -EINTR)
        continue;

      return ret;
    }

    n += ret;
  } while (n != count);

  return n;
}

typedef int32_t	old_time32_t;

struct old_timespec32 {
	old_time32_t	tv_sec;
	int32_t		tv_nsec;
};

static target_ulong to_free[16];

void _jove_rt_signal_handler(int sig, siginfo_t *si, ucontext_t *uctx) {
  if (sig != SIGSEGV)
    _UNREACHABLE();

  //
  // if we are in trace mode, we may have hit a guard page. check for this
  // possbility first.
  //
  void *TraceBegin = __jove_trace_begin;

  if (si && TraceBegin) {
    uintptr_t FaultAddr = (uintptr_t)si->si_addr;

#if 0
    {
      char s[4096];
      s[0] = '\0';

      _strcat(s, "_jove_rt_signal_handler: si_addr=0x");
      {
        char buff[65];
        uint_to_string(FaultAddr, buff, 0x10);

        _strcat(s, buff);
      }
      _strcat(s, "\n");

      _robust_write(2 /* stderr */, s, _strlen(s));
    }
#endif

    if (FaultAddr) {
      uintptr_t TraceGuardPageBeg = (uintptr_t)TraceBegin + JOVE_TRACE_BUFF_SIZE - JOVE_PAGE_SIZE;
      uintptr_t TraceGuardPageEnd = TraceGuardPageBeg + JOVE_PAGE_SIZE;

#if 0
      {
        char s[4096];
        s[0] = '\0';

        _strcat(s, "_jove_rt_signal_handler: TraceGuardPageBeg=0x");
        {
          char buff[65];
          uint_to_string(TraceGuardPageBeg, buff, 0x10);

          _strcat(s, buff);
        }
        _strcat(s, " TraceGuardPageEnd=0x");
        {
          char buff[65];
          uint_to_string(TraceGuardPageEnd, buff, 0x10);

          _strcat(s, buff);
        }
        _strcat(s, " FaultAddr=0x");
        {
          char buff[65];
          uint_to_string(FaultAddr, buff, 0x10);

          _strcat(s, buff);
        }

        _strcat(s, "\n");

        _robust_write(2 /* stderr */, s, _strlen(s));
      }
#endif

      if (FaultAddr >= TraceGuardPageBeg &&
          FaultAddr <= TraceGuardPageEnd) {
        void *Trace = __jove_trace;

        if (Trace != TraceBegin)
          _jove_flush_trace();

        uctx->uc_mcontext.pc += 4; /* skip faulting instruction */
        return;
      }
    }
  }

#define pc    uctx->uc_mcontext.pc
#define sp    uctx->uc_mcontext.gregs[29]
#define ra    uctx->uc_mcontext.gregs[31]
#define t9    uctx->uc_mcontext.gregs[25]
#define emusp __jove_env.active_tc.gpr[29]
#define emut9 __jove_env.active_tc.gpr[25]

  //
  // no time like the present
  //
  for (unsigned i = 0; i < ARRAY_SIZE(to_free); ++i) {
    if (to_free[i] == 0)
      continue;

    _jove_free_stack(to_free[i]);
    to_free[i] = 0;
  }

  uintptr_t saved_pc = pc;

  for (unsigned BIdx = 0; BIdx < _JOVE_MAX_BINARIES; ++BIdx) {
    if (BIdx == 1 ||
        BIdx == 2)
      continue; /* rtld or vdso */

    uintptr_t *fns = __jove_function_tables[BIdx];

    if (!fns)
      continue;

    for (unsigned FIdx = 0; fns[2 * FIdx]; ++FIdx) {
      if (saved_pc != fns[2 * FIdx + 0])
        continue;

      uintptr_t saved_sp = sp;
      uintptr_t saved_emusp = emusp;
      uintptr_t saved_retaddr = ra;
      uintptr_t saved_callstack       = (uintptr_t)__jove_callstack;
      uintptr_t saved_callstack_begin = (uintptr_t)__jove_callstack_begin;

#if 0
      {
        char buff[256];
        buff[0] = '\0';


        _strcat(buff, __LOG_BOLD_BLUE "saved_emusp: 0x");

        {
          char buf[65];
          uint_to_string(saved_emusp, buf, 0x10);

          _strcat(buff, buf);
        }

        _strcat(buff, __LOG_NORMAL_COLOR "\n");

        _jove_sys_write(2 /* stderr */, buff, _strlen(buff));
      }
#endif

      //
      // if the kernel just delivered a signal, then $ra should point to the
      // code that calls sigreturn. this turns out in most cases to reside in
      // [vdso]
      //
      bool SignalDelivery = false;

      if ((((uint32_t *)saved_retaddr)[0] == 0x24021017 ||
           ((uint32_t *)saved_retaddr)[0] == 0x24021061) &&
           ((uint32_t *)saved_retaddr)[1] == 0x0000000c) {
        SignalDelivery = true;

#if 0
        char buff[256];
        buff[0] = '\0';

        _strcat(buff, __LOG_BOLD_BLUE "SignalDelivered\n" __LOG_NORMAL_COLOR);

        _jove_sys_write(2 /* stderr */, buff, _strlen(buff));
#endif
      }

      {
        const uintptr_t newstack = _jove_alloc_stack();

        uintptr_t _newsp =
            newstack + JOVE_STACK_SIZE - JOVE_PAGE_SIZE - 19 * sizeof(uintptr_t);

        if (SignalDelivery)
          _newsp -= sizeof(struct CPUMIPSState);

        _newsp &= 0xfffffff0; // align the stack

        uintptr_t *const newsp = (uintptr_t *)_newsp;

        newsp[0] = 0xdeadbeef;
        newsp[1] = saved_retaddr;
        newsp[2] = saved_sp;
        newsp[3] = saved_emusp;
        newsp[4] = saved_callstack;
        newsp[5] = saved_callstack_begin;
        newsp[6] = newstack;
        newsp[7] = &emusp;
        newsp[8] = &__jove_callstack_begin;
        newsp[9] = saved_callstack;
        newsp[10] = _jove_free_stack_later;
        newsp[11] = _jove_free_callstack;
        newsp[12] = 0; /* saved v0 */
        newsp[13] = 0; /* saved v1 */
        newsp[14] = &__jove_callstack_begin;
        newsp[15] = &__jove_callstack;
        newsp[16] = SignalDelivery;
        newsp[17] = _jove_handle_signal_delivery;
        newsp[18] = &newsp[19];

        if (SignalDelivery)
          _memcpy(&newsp[19], &__jove_env, sizeof(struct CPUMIPSState));

        sp = _newsp;
        ra = _jove_inverse_thunk;
      }

      //
      // native stack becomes emulated stack
      //
      emusp = saved_sp;

      {
        const uintptr_t new_callsp = _jove_alloc_callstack();

        __jove_callstack_begin = __jove_callstack = new_callsp + JOVE_PAGE_SIZE;
      }

      /* TODO consider warning if t9 does not equal expected section pointer */
#if 0
      if (t9 != fns[2 * FIdx + 0]) {
        _UNREACHABLE();
      }
#endif

      if (fns[2 * FIdx + 1] == NULL) {
        _UNREACHABLE("called recompiled function is not ABI");
      }

      emut9 = fns[2 * FIdx + 0];

      pc = t9 = fns[2 * FIdx + 1];

      return;
    }
  }

#undef pc
#undef sp
#undef ra
#undef t9
#undef emusp
#undef emut9

  //
  // if we get here, this is most likely a real crash.
  //
  char maps[4096 * 8];
  const unsigned n = _read_pseudo_file("/proc/self/maps", maps, sizeof(maps));
  maps[n] = '\0';

  char s[4096 * 16];
  s[0] = '\0';

  _strcat(s, "*** crash (jove) *** [");
  {
    char buff[65];
    uint_to_string(_jove_sys_gettid(), buff, 10);

    _strcat(s, buff);
  }
  _strcat(s, "]\n");

#define _FIELD(name, init)                                                     \
  do {                                                                         \
    _strcat(s, name " 0x");                                                    \
                                                                               \
    {                                                                          \
      char _buff[65];                                                          \
      uint_to_string(init, _buff, 0x10);                                       \
                                                                               \
      _strcat(s, _buff);                                                       \
    }                                                                          \
    {                                                                          \
      char _buff[256];                                                         \
      _description_of_address_for_maps(_buff, init, maps, n);                  \
      if (_strlen(_buff) != 0) {                                               \
        _strcat(s, " <");                                                      \
        _strcat(s, _buff);                                                     \
        _strcat(s, ">");                                                       \
      }                                                                        \
    }                                                                          \
                                                                               \
    _strcat(s, "\n");                                                          \
  } while (false)

  _FIELD("pc", saved_pc);
  _FIELD("r0", uctx->uc_mcontext.gregs[0]);
  _FIELD("at", uctx->uc_mcontext.gregs[1]);
  _FIELD("v0", uctx->uc_mcontext.gregs[2]);
  _FIELD("v1", uctx->uc_mcontext.gregs[3]);
  _FIELD("a0", uctx->uc_mcontext.gregs[4]);
  _FIELD("a1", uctx->uc_mcontext.gregs[5]);
  _FIELD("a2", uctx->uc_mcontext.gregs[6]);
  _FIELD("a3", uctx->uc_mcontext.gregs[7]);
  _FIELD("t0", uctx->uc_mcontext.gregs[8]);
  _FIELD("t1", uctx->uc_mcontext.gregs[9]);
  _FIELD("t2", uctx->uc_mcontext.gregs[10]);
  _FIELD("t3", uctx->uc_mcontext.gregs[11]);
  _FIELD("t4", uctx->uc_mcontext.gregs[12]);
  _FIELD("t5", uctx->uc_mcontext.gregs[13]);
  _FIELD("t6", uctx->uc_mcontext.gregs[14]);
  _FIELD("t7", uctx->uc_mcontext.gregs[15]);
  _FIELD("s0", uctx->uc_mcontext.gregs[16]);
  _FIELD("s1", uctx->uc_mcontext.gregs[17]);
  _FIELD("s2", uctx->uc_mcontext.gregs[18]);
  _FIELD("s3", uctx->uc_mcontext.gregs[19]);
  _FIELD("s4", uctx->uc_mcontext.gregs[20]);
  _FIELD("s5", uctx->uc_mcontext.gregs[21]);
  _FIELD("s6", uctx->uc_mcontext.gregs[22]);
  _FIELD("s7", uctx->uc_mcontext.gregs[23]);
  _FIELD("t8", uctx->uc_mcontext.gregs[24]);
  _FIELD("t9", uctx->uc_mcontext.gregs[25]);
  _FIELD("k0", uctx->uc_mcontext.gregs[26]);
  _FIELD("k1", uctx->uc_mcontext.gregs[27]);
  _FIELD("gp", uctx->uc_mcontext.gregs[28]);
  _FIELD("sp", uctx->uc_mcontext.gregs[29]);
  _FIELD("s8", uctx->uc_mcontext.gregs[30]);
  _FIELD("ra", uctx->uc_mcontext.gregs[31]);

#undef _FIELD

  _strcat(s, "\n");
  _strcat(s, maps);

  //
  // dump message for user
  //
  _robust_write(2 /* stderr */, s, _strlen(s));

#if 0
  {
    int fd = _jove_sys_open("/tmp/hack.tmp", O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU);
    _jove_sys_write(fd, buff, _strlen(buff));
    _jove_sys_close(fd);
  }
#endif

  for (;;) {
    struct old_timespec32 t;
    t.tv_sec = 10;
    t.tv_nsec = 0;

    _jove_sys_nanosleep_time32(&t, NULL);
  }

  __builtin_trap();
  __builtin_unreachable();
}

target_ulong _jove_alloc_stack(void) {
  long ret = _jove_sys_mips_mmap(0x0, JOVE_STACK_SIZE, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1L, 0);
  if (ret < 0 && ret > -4096) {
    _UNREACHABLE();
  }

  //
  // create guard pages on both sides
  //
  unsigned long beg = (unsigned long)ret;
  unsigned long end = beg + JOVE_STACK_SIZE;

  if (_jove_sys_mprotect(beg, JOVE_PAGE_SIZE, PROT_NONE) < 0) {
    _UNREACHABLE();
  }

  if (_jove_sys_mprotect(end - JOVE_PAGE_SIZE, JOVE_PAGE_SIZE, PROT_NONE) < 0) {
    _UNREACHABLE();
  }

  return beg;
}

void _jove_free_stack(target_ulong beg) {
  if (_jove_sys_munmap(beg, JOVE_STACK_SIZE) < 0) {
    _UNREACHABLE();
  }
}

target_ulong _jove_alloc_callstack(void) {
  long ret =
      _jove_sys_mips_mmap(0x0, JOVE_CALLSTACK_SIZE, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1L, 0);
  if (ret < 0 && ret > -4096) {
    _UNREACHABLE();
  }

  unsigned long uret = (unsigned long)ret;

  //
  // create guard pages on both sides
  //
  unsigned long beg = uret;
  unsigned long end = beg + JOVE_CALLSTACK_SIZE;

  if (_jove_sys_mprotect(beg, JOVE_PAGE_SIZE, PROT_NONE) < 0) {
    _UNREACHABLE();
  }

  if (_jove_sys_mprotect(end - JOVE_PAGE_SIZE, JOVE_PAGE_SIZE, PROT_NONE) < 0) {
    _UNREACHABLE();
  }

  return beg;
}

void _jove_free_callstack(target_ulong start) {
  if (_jove_sys_munmap(start - JOVE_PAGE_SIZE /* XXX */, JOVE_CALLSTACK_SIZE) < 0) {
    _UNREACHABLE();
  }
}

void _jove_callstack_init(void) {
  target_ulong ptr = _jove_alloc_callstack();

  __jove_callstack_begin = __jove_callstack = ptr + JOVE_PAGE_SIZE;
}

void _jove_trace_init(void) {
  long ret = _jove_sys_mips_mmap(0x0, JOVE_TRACE_BUFF_SIZE,
                                 PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1L, 0);
  if (ret < 0 && ret > -4096)
    _UNREACHABLE("failed to allocate trace buffer");

  unsigned long beg = (unsigned long)ret;
  unsigned long end = beg + JOVE_TRACE_BUFF_SIZE;

  //
  // create guard page
  //
  if (_jove_sys_mprotect(end - JOVE_PAGE_SIZE, JOVE_PAGE_SIZE, PROT_NONE) < 0)
    _UNREACHABLE("failed to create guard page for trace");

  //
  // install
  //
  __jove_trace_begin = __jove_trace = (void *)ret;
}

void _jove_flush_trace(void) {
  void *TraceBegin = __jove_trace_begin;

  int fd;
  {
    char path[4096];
    path[0] = '\0';

    _strcat(path, "/mnt/jove.");
    {
      char buff[65];
      uint_to_string(_jove_sys_gettid(), buff, 10);

      _strcat(path, buff);
    }
    _strcat(path, ".trace.bin");

    fd = _jove_sys_open(path, O_WRONLY | O_APPEND | O_CREAT | O_LARGEFILE, 0666);

    if (fd < 0)
      _UNREACHABLE("_jove_flush_trace: failed to open trace file");
  }

  unsigned n = JOVE_TRACE_BUFF_SIZE - JOVE_PAGE_SIZE /* guard page */;
  ssize_t ret = _robust_write(fd, TraceBegin, n);

  if (ret != n)
    _UNREACHABLE("_jove_flush_trace: could not flush trace file");

  if (_jove_sys_close(fd) < 0)
    _UNREACHABLE("_jove_flush_trace: failed to close trace file");

  //
  // reset
  //
  __jove_trace = TraceBegin;
}

void _jove_init_cpu_state(void) {
  __jove_env.hflags = 226;
}

void *_memset(void *dst, int c, size_t n) {
  if (n != 0) {
    unsigned char *d = dst;

    do
      *d++ = (unsigned char)c;
    while (--n != 0);
  }
  return (dst);
}

void *_memcpy(void *dest, const void *src, size_t n) {
  unsigned char *d = dest;
  const unsigned char *s = src;

  for (; n; n--)
    *d++ = *s++;

  return dest;
}

char *_strcat(char *s, const char *append) {
  char *save = s;

  for (; *s; ++s)
    ;
  while ((*s++ = *append++) != '\0')
    ;
  return (save);
}

size_t _strlen(const char *str) {
  const char *s;

  for (s = str; *s; ++s)
    ;
  return (s - str);
}

void uint_to_string(uint32_t x, char *Str, unsigned Radix) {
  // First, check for a zero value and just short circuit the logic below.
  if (x == 0) {
    *Str++ = '0';

    // null-terminate
    *Str = '\0';
    return;
  }

  static const char Digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";

  char Buffer[65];
  char *BufPtr = &Buffer[sizeof(Buffer)];

  uint32_t N = x;

  while (N) {
    *--BufPtr = Digits[N % Radix];
    N /= Radix;
  }

  for (char *p = BufPtr; p != &Buffer[sizeof(Buffer)]; ++p)
    *Str++ = *p;

  // null-terminate
  *Str = '\0';
  return;
}

unsigned _getHexDigit(char cdigit) {
  unsigned radix = 0x10;

  unsigned r;

  if (radix == 16 || radix == 36) {
    r = cdigit - '0';
    if (r <= 9)
      return r;

    r = cdigit - 'A';
    if (r <= radix - 11U)
      return r + 10;

    r = cdigit - 'a';
    if (r <= radix - 11U)
      return r + 10;

    radix = 10;
  }

  r = cdigit - '0';
  if (r < radix)
    return r;

  return -1U;
}

uint32_t _u32ofhexstr(char *str_begin, char *str_end) {
  const unsigned radix = 0x10;

  uint32_t res = 0;

  char *p = str_begin;
  size_t slen = str_end - str_begin;

  // Figure out if we can shift instead of multiply
  unsigned shift = (radix == 16 ? 4 : radix == 8 ? 3 : radix == 2 ? 1 : 0);

  // Enter digit traversal loop
  for (char *e = str_end; p != e; ++p) {
    unsigned digit = _getHexDigit(*p);

    if (!(digit < radix))
      return 0;

    // Shift or multiply the value by the radix
    if (slen > 1) {
      if (shift)
        res <<= shift;
      else
        res *= radix;
    }

    // Add in the digit we just interpreted
    res += digit;
  }

  return res;
}

void _jove_free_stack_later(target_ulong stack) {
  for (unsigned i = 0; i < ARRAY_SIZE(to_free); ++i) {
    if (to_free[i] != 0)
      continue;

    to_free[i] = stack;
    return;
  }

  _UNREACHABLE();
}

uintptr_t _jove_handle_signal_delivery(target_ulong SignalDelivery,
                                       struct CPUMIPSState *SavedState) {
  //
  // save the emusp *before* we restore env
  //
  uintptr_t res = __jove_env.active_tc.gpr[29];

  if (SignalDelivery) {
#if 0
    {
      char buff[256];
      buff[0] = '\0';

      _strcat(buff, __LOG_BOLD_BLUE "copying cpu state..." __LOG_NORMAL_COLOR "\n");

      _jove_sys_write(2 /* stderr */, buff, _strlen(buff));
    }
#endif

    _memcpy(&__jove_env, SavedState, sizeof(struct CPUMIPSState));

#if 0
    {
      char buff[256];
      buff[0] = '\0';

      _strcat(buff, __LOG_BOLD_BLUE "done copying cpu state" __LOG_NORMAL_COLOR "\n");

      _jove_sys_write(2 /* stderr */, buff, _strlen(buff));
    }
#endif
  }

  return res;
}

unsigned _read_pseudo_file(const char *path, char *out, size_t len) {
  unsigned n;

  {
    int fd = _jove_sys_open(path, O_RDONLY, S_IRWXU);
    if (fd < 0) {
      __builtin_trap();
      __builtin_unreachable();
    }

    // let n denote the number of characters read
    n = 0;

    for (;;) {
      ssize_t ret = _jove_sys_read(fd, &out[n], len - n);

      if (ret == 0)
        break;

      if (ret < 0) {
        if (ret == -EINTR)
          continue;

        __builtin_trap();
        __builtin_unreachable();
      }

      n += ret;
    }

    if (_jove_sys_close(fd) < 0) {
      __builtin_trap();
      __builtin_unreachable();
    }
  }

  return n;
}

void *_memchr(const void *s, int c, size_t n) {
  if (n != 0) {
    const unsigned char *p = s;

    do {
      if (*p++ == (unsigned char)c)
        return ((void *)(p - 1));
    } while (--n != 0);
  }
  return (NULL);
}

void _description_of_address_for_maps(char *out, uintptr_t Addr, char *maps, const unsigned n) {
  out[0] = '\0'; /* empty */

  char *const beg = &maps[0];
  char *const end = &maps[n];

  char *eol;
  for (char *line = beg; line != end; line = eol + 1) {
    {
      unsigned left = n - (line - beg);

      //
      // find the end of the current line
      //
      eol = _memchr(line, '\n', left);
    }

    unsigned left = eol - line;

    struct {
      uint64_t min, max;
    } vm;

    {
      char *dash = _memchr(line, '-', left);
      vm.min = _u32ofhexstr(line, dash);

      char *space = _memchr(line, ' ', left);
      vm.max = _u32ofhexstr(dash + 1, space);
    }

    //
    // does the given address exist within this mapping?
    //
    if (Addr >= vm.min && Addr < vm.max) {
      //
      // we have a match. If this mapping has a file path, we'll make it the
      // description
      //
      char *fwdslash = _memchr(line, '/', left);
      char *leftsqbr = _memchr(line, '[', left);

      if (fwdslash) {
        *eol = '\0';
        _strcat(out, fwdslash);
        *eol = '\n';
      } else if (leftsqbr) {
        *eol = '\0';
        _strcat(out, leftsqbr);
        *eol = '\n';
      } else {
        *out = '\0';
        return;
      }

      _strcat(out, "+0x");

      ssize_t Offset = Addr - vm.min;
      char offsetStr[65];
      uint_to_string(Offset, offsetStr, 0x10);

      _strcat(out, offsetStr);

      return;
    }
  }
}
