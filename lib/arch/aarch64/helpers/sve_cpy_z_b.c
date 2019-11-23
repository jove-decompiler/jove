#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdbool.h>

#include <stdint.h>

#include <limits.h>

#include <assert.h>

#define G_GNUC_EXTENSION __extension__

#define G_GNUC_MALLOC __attribute__((__malloc__))

#define G_GNUC_ALLOC_SIZE(x) __attribute__((__alloc_size__(x)))

#define G_GNUC_ALLOC_SIZE2(x,y) __attribute__((__alloc_size__(x,y)))

#define _GLIB_EXTERN extern

#define G_MAXULONG	ULONG_MAX

typedef unsigned char guint8;

#define G_MAXSIZE	G_MAXULONG

typedef unsigned long gsize;

#define GLIB_AVAILABLE_IN_ALL                   _GLIB_EXTERN

typedef char   gchar;

typedef int    gint;

typedef gint   gboolean;

typedef unsigned int    guint;

typedef void* gpointer;

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

GLIB_AVAILABLE_IN_ALL
GArray* g_array_new               (gboolean          zero_terminated,
				   gboolean          clear_,
				   guint             element_size);

GLIB_AVAILABLE_IN_ALL
GByteArray* g_byte_array_sized_new         (guint             reserved_size);

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

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

typedef uint64_t qemu_plugin_id_t;

typedef void (*qemu_plugin_simple_cb_t)(qemu_plugin_id_t id);

typedef void (*qemu_plugin_udata_cb_t)(qemu_plugin_id_t id, void *userdata);

typedef void (*qemu_plugin_vcpu_simple_cb_t)(qemu_plugin_id_t id,
                                             unsigned int vcpu_index);

typedef void (*qemu_plugin_vcpu_udata_cb_t)(unsigned int vcpu_index,
                                            void *userdata);

struct qemu_plugin_tb;

enum qemu_plugin_mem_rw {
    QEMU_PLUGIN_MEM_R = 1,
    QEMU_PLUGIN_MEM_W,
    QEMU_PLUGIN_MEM_RW,
};

typedef void (*qemu_plugin_vcpu_tb_trans_cb_t)(qemu_plugin_id_t id,
                                               struct qemu_plugin_tb *tb);

enum qemu_plugin_op {
    QEMU_PLUGIN_INLINE_ADD_U64,
};

typedef uint32_t qemu_plugin_meminfo_t;

typedef void
(*qemu_plugin_vcpu_mem_cb_t)(unsigned int vcpu_index,
                             qemu_plugin_meminfo_t info, uint64_t vaddr,
                             void *userdata);

typedef void
(*qemu_plugin_vcpu_syscall_cb_t)(qemu_plugin_id_t id, unsigned int vcpu_index,
                                 int64_t num, uint64_t a1, uint64_t a2,
                                 uint64_t a3, uint64_t a4, uint64_t a5,
                                 uint64_t a6, uint64_t a7, uint64_t a8);

typedef void
(*qemu_plugin_vcpu_syscall_ret_cb_t)(qemu_plugin_id_t id, unsigned int vcpu_idx,
                                     int64_t num, int64_t ret);

union qemu_plugin_cb_sig {
    qemu_plugin_simple_cb_t          simple;
    qemu_plugin_udata_cb_t           udata;
    qemu_plugin_vcpu_simple_cb_t     vcpu_simple;
    qemu_plugin_vcpu_udata_cb_t      vcpu_udata;
    qemu_plugin_vcpu_tb_trans_cb_t   vcpu_tb_trans;
    qemu_plugin_vcpu_mem_cb_t        vcpu_mem;
    qemu_plugin_vcpu_syscall_cb_t    vcpu_syscall;
    qemu_plugin_vcpu_syscall_ret_cb_t vcpu_syscall_ret;
    void *generic;
};

enum plugin_dyn_cb_type {
    PLUGIN_CB_INSN,
    PLUGIN_CB_MEM,
    PLUGIN_N_CB_TYPES,
};

enum plugin_dyn_cb_subtype {
    PLUGIN_CB_REGULAR,
    PLUGIN_CB_INLINE,
    PLUGIN_N_CB_SUBTYPES,
};

struct qemu_plugin_dyn_cb {
    union qemu_plugin_cb_sig f;
    void *userp;
    unsigned tcg_flags;
    enum plugin_dyn_cb_subtype type;
    /* @rw applies to mem callbacks only (both regular and inline) */
    enum qemu_plugin_mem_rw rw;
    /* fields specific to each dyn_cb type go here */
    union {
        struct {
            enum qemu_plugin_op op;
            uint64_t imm;
        } inline_insn;
    };
};

struct qemu_plugin_insn {
    GByteArray *data;
    uint64_t vaddr;
    void *haddr;
    GArray *cbs[PLUGIN_N_CB_TYPES][PLUGIN_N_CB_SUBTYPES];
    bool calls_helpers;
    bool mem_helper;
};

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

uint64_t dup_const(unsigned vece, uint64_t c);

#define dup_const(VECE, C)                                         \
    (__builtin_constant_p(VECE)                                    \
     ? (  (VECE) == MO_8  ? 0x0101010101010101ull * (uint8_t)(C)   \
        : (VECE) == MO_16 ? 0x0001000100010001ull * (uint16_t)(C)  \
        : (VECE) == MO_32 ? 0x0000000100000001ull * (uint32_t)(C)  \
        : dup_const(VECE, C))                                      \
     : dup_const(VECE, C))

#define HELPER(name) glue(helper_, name)

#define SIMD_OPRSZ_SHIFT   0

#define SIMD_OPRSZ_BITS    5

static inline intptr_t simd_oprsz(uint32_t desc)
{
    return (extract32(desc, SIMD_OPRSZ_SHIFT, SIMD_OPRSZ_BITS) + 1) * 8;
}

#define H1(x)   (x)

static inline uint64_t expand_pred_b(uint8_t byte)
{
    static const uint64_t word[256] = {
        0x0000000000000000, 0x00000000000000ff, 0x000000000000ff00,
        0x000000000000ffff, 0x0000000000ff0000, 0x0000000000ff00ff,
        0x0000000000ffff00, 0x0000000000ffffff, 0x00000000ff000000,
        0x00000000ff0000ff, 0x00000000ff00ff00, 0x00000000ff00ffff,
        0x00000000ffff0000, 0x00000000ffff00ff, 0x00000000ffffff00,
        0x00000000ffffffff, 0x000000ff00000000, 0x000000ff000000ff,
        0x000000ff0000ff00, 0x000000ff0000ffff, 0x000000ff00ff0000,
        0x000000ff00ff00ff, 0x000000ff00ffff00, 0x000000ff00ffffff,
        0x000000ffff000000, 0x000000ffff0000ff, 0x000000ffff00ff00,
        0x000000ffff00ffff, 0x000000ffffff0000, 0x000000ffffff00ff,
        0x000000ffffffff00, 0x000000ffffffffff, 0x0000ff0000000000,
        0x0000ff00000000ff, 0x0000ff000000ff00, 0x0000ff000000ffff,
        0x0000ff0000ff0000, 0x0000ff0000ff00ff, 0x0000ff0000ffff00,
        0x0000ff0000ffffff, 0x0000ff00ff000000, 0x0000ff00ff0000ff,
        0x0000ff00ff00ff00, 0x0000ff00ff00ffff, 0x0000ff00ffff0000,
        0x0000ff00ffff00ff, 0x0000ff00ffffff00, 0x0000ff00ffffffff,
        0x0000ffff00000000, 0x0000ffff000000ff, 0x0000ffff0000ff00,
        0x0000ffff0000ffff, 0x0000ffff00ff0000, 0x0000ffff00ff00ff,
        0x0000ffff00ffff00, 0x0000ffff00ffffff, 0x0000ffffff000000,
        0x0000ffffff0000ff, 0x0000ffffff00ff00, 0x0000ffffff00ffff,
        0x0000ffffffff0000, 0x0000ffffffff00ff, 0x0000ffffffffff00,
        0x0000ffffffffffff, 0x00ff000000000000, 0x00ff0000000000ff,
        0x00ff00000000ff00, 0x00ff00000000ffff, 0x00ff000000ff0000,
        0x00ff000000ff00ff, 0x00ff000000ffff00, 0x00ff000000ffffff,
        0x00ff0000ff000000, 0x00ff0000ff0000ff, 0x00ff0000ff00ff00,
        0x00ff0000ff00ffff, 0x00ff0000ffff0000, 0x00ff0000ffff00ff,
        0x00ff0000ffffff00, 0x00ff0000ffffffff, 0x00ff00ff00000000,
        0x00ff00ff000000ff, 0x00ff00ff0000ff00, 0x00ff00ff0000ffff,
        0x00ff00ff00ff0000, 0x00ff00ff00ff00ff, 0x00ff00ff00ffff00,
        0x00ff00ff00ffffff, 0x00ff00ffff000000, 0x00ff00ffff0000ff,
        0x00ff00ffff00ff00, 0x00ff00ffff00ffff, 0x00ff00ffffff0000,
        0x00ff00ffffff00ff, 0x00ff00ffffffff00, 0x00ff00ffffffffff,
        0x00ffff0000000000, 0x00ffff00000000ff, 0x00ffff000000ff00,
        0x00ffff000000ffff, 0x00ffff0000ff0000, 0x00ffff0000ff00ff,
        0x00ffff0000ffff00, 0x00ffff0000ffffff, 0x00ffff00ff000000,
        0x00ffff00ff0000ff, 0x00ffff00ff00ff00, 0x00ffff00ff00ffff,
        0x00ffff00ffff0000, 0x00ffff00ffff00ff, 0x00ffff00ffffff00,
        0x00ffff00ffffffff, 0x00ffffff00000000, 0x00ffffff000000ff,
        0x00ffffff0000ff00, 0x00ffffff0000ffff, 0x00ffffff00ff0000,
        0x00ffffff00ff00ff, 0x00ffffff00ffff00, 0x00ffffff00ffffff,
        0x00ffffffff000000, 0x00ffffffff0000ff, 0x00ffffffff00ff00,
        0x00ffffffff00ffff, 0x00ffffffffff0000, 0x00ffffffffff00ff,
        0x00ffffffffffff00, 0x00ffffffffffffff, 0xff00000000000000,
        0xff000000000000ff, 0xff0000000000ff00, 0xff0000000000ffff,
        0xff00000000ff0000, 0xff00000000ff00ff, 0xff00000000ffff00,
        0xff00000000ffffff, 0xff000000ff000000, 0xff000000ff0000ff,
        0xff000000ff00ff00, 0xff000000ff00ffff, 0xff000000ffff0000,
        0xff000000ffff00ff, 0xff000000ffffff00, 0xff000000ffffffff,
        0xff0000ff00000000, 0xff0000ff000000ff, 0xff0000ff0000ff00,
        0xff0000ff0000ffff, 0xff0000ff00ff0000, 0xff0000ff00ff00ff,
        0xff0000ff00ffff00, 0xff0000ff00ffffff, 0xff0000ffff000000,
        0xff0000ffff0000ff, 0xff0000ffff00ff00, 0xff0000ffff00ffff,
        0xff0000ffffff0000, 0xff0000ffffff00ff, 0xff0000ffffffff00,
        0xff0000ffffffffff, 0xff00ff0000000000, 0xff00ff00000000ff,
        0xff00ff000000ff00, 0xff00ff000000ffff, 0xff00ff0000ff0000,
        0xff00ff0000ff00ff, 0xff00ff0000ffff00, 0xff00ff0000ffffff,
        0xff00ff00ff000000, 0xff00ff00ff0000ff, 0xff00ff00ff00ff00,
        0xff00ff00ff00ffff, 0xff00ff00ffff0000, 0xff00ff00ffff00ff,
        0xff00ff00ffffff00, 0xff00ff00ffffffff, 0xff00ffff00000000,
        0xff00ffff000000ff, 0xff00ffff0000ff00, 0xff00ffff0000ffff,
        0xff00ffff00ff0000, 0xff00ffff00ff00ff, 0xff00ffff00ffff00,
        0xff00ffff00ffffff, 0xff00ffffff000000, 0xff00ffffff0000ff,
        0xff00ffffff00ff00, 0xff00ffffff00ffff, 0xff00ffffffff0000,
        0xff00ffffffff00ff, 0xff00ffffffffff00, 0xff00ffffffffffff,
        0xffff000000000000, 0xffff0000000000ff, 0xffff00000000ff00,
        0xffff00000000ffff, 0xffff000000ff0000, 0xffff000000ff00ff,
        0xffff000000ffff00, 0xffff000000ffffff, 0xffff0000ff000000,
        0xffff0000ff0000ff, 0xffff0000ff00ff00, 0xffff0000ff00ffff,
        0xffff0000ffff0000, 0xffff0000ffff00ff, 0xffff0000ffffff00,
        0xffff0000ffffffff, 0xffff00ff00000000, 0xffff00ff000000ff,
        0xffff00ff0000ff00, 0xffff00ff0000ffff, 0xffff00ff00ff0000,
        0xffff00ff00ff00ff, 0xffff00ff00ffff00, 0xffff00ff00ffffff,
        0xffff00ffff000000, 0xffff00ffff0000ff, 0xffff00ffff00ff00,
        0xffff00ffff00ffff, 0xffff00ffffff0000, 0xffff00ffffff00ff,
        0xffff00ffffffff00, 0xffff00ffffffffff, 0xffffff0000000000,
        0xffffff00000000ff, 0xffffff000000ff00, 0xffffff000000ffff,
        0xffffff0000ff0000, 0xffffff0000ff00ff, 0xffffff0000ffff00,
        0xffffff0000ffffff, 0xffffff00ff000000, 0xffffff00ff0000ff,
        0xffffff00ff00ff00, 0xffffff00ff00ffff, 0xffffff00ffff0000,
        0xffffff00ffff00ff, 0xffffff00ffffff00, 0xffffff00ffffffff,
        0xffffffff00000000, 0xffffffff000000ff, 0xffffffff0000ff00,
        0xffffffff0000ffff, 0xffffffff00ff0000, 0xffffffff00ff00ff,
        0xffffffff00ffff00, 0xffffffff00ffffff, 0xffffffffff000000,
        0xffffffffff0000ff, 0xffffffffff00ff00, 0xffffffffff00ffff,
        0xffffffffffff0000, 0xffffffffffff00ff, 0xffffffffffffff00,
        0xffffffffffffffff,
    };
    return word[byte];
}

void HELPER(sve_cpy_z_b)(void *vd, void *vg, uint64_t val, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;
    uint64_t *d = vd;
    uint8_t *pg = vg;

    val = dup_const(MO_8, val);
    for (i = 0; i < opr_sz; i += 1) {
        d[i] = val & expand_pred_b(pg[H1(i)]);
    }
}

