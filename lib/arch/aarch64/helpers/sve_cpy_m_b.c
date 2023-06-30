#define TARGET_BIG_ENDIAN 0

#define HOST_BIG_ENDIAN (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)

#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

# define QEMU_ERROR(X) __attribute__((error(X)))

#include <stdbool.h>

#include <stdint.h>

#include <assert.h>

# define G_NORETURN __attribute__ ((__noreturn__))

# define MIN_CONST(a, b)                                        \
    __builtin_choose_expr(                                      \
        __builtin_constant_p(a) && __builtin_constant_p(b),     \
        (a) < (b) ? (a) : (b),                                  \
        ((void)0))

G_NORETURN extern
void QEMU_ERROR("code path is reachable")
    qemu_build_not_reached_always(void);

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

# define TARGET_LONG_BITS             64

# define TARGET_VIRT_ADDR_SPACE_BITS  52

typedef uint64_t target_ulong;

#define TARGET_ABI_BITS TARGET_LONG_BITS

#define ABI_LONG_ALIGNMENT (TARGET_ABI_BITS / 8)

typedef target_ulong abi_ulong __attribute__((aligned(ABI_LONG_ALIGNMENT)));

#define GUEST_ADDR_MAX_                                                 \
    ((MIN_CONST(TARGET_VIRT_ADDR_SPACE_BITS, TARGET_ABI_BITS) <= 32) ?  \
     UINT32_MAX : ~0ul)

#define GUEST_ADDR_MAX    (reserved_va ? : GUEST_ADDR_MAX_)

extern unsigned long reserved_va;

#define SIMD_MAXSZ_SHIFT   0

#define SIMD_MAXSZ_BITS    8

#define SIMD_OPRSZ_SHIFT   (SIMD_MAXSZ_SHIFT + SIMD_MAXSZ_BITS)

#define SIMD_OPRSZ_BITS    2

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

static inline bool guest_addr_valid_untagged(abi_ulong x)
{
    return x <= GUEST_ADDR_MAX;
}

#define HELPER(name) glue(helper_, name)

uint64_t dup_const(unsigned vece, uint64_t c);

#define dup_const(VECE, C)                                         \
    (__builtin_constant_p(VECE)                                    \
     ? (  (VECE) == MO_8  ? 0x0101010101010101ull * (uint8_t)(C)   \
        : (VECE) == MO_16 ? 0x0001000100010001ull * (uint16_t)(C)  \
        : (VECE) == MO_32 ? 0x0000000100000001ull * (uint32_t)(C)  \
        : (VECE) == MO_64 ? (uint64_t)(C)                          \
        : (qemu_build_not_reached_always(), 0))                    \
     : dup_const(VECE, C))

#define H1(x)   (x)

extern const uint64_t expand_pred_b_data[256];

static inline uint64_t expand_pred_b(uint8_t byte)
{
    return expand_pred_b_data[byte];
}

void HELPER(sve_cpy_m_b)(void *vd, void *vn, void *vg,
                         uint64_t mm, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;
    uint64_t *d = vd, *n = vn;
    uint8_t *pg = vg;

    mm = dup_const(MO_8, mm);
    for (i = 0; i < opr_sz; i += 1) {
        uint64_t nn = n[i];
        uint64_t pp = expand_pred_b(pg[H1(i)]);
        d[i] = (mm & pp) | (nn & ~pp);
    }
}

