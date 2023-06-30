#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

# define QEMU_ERROR(X) __attribute__((error(X)))

#define QEMU_ALWAYS_INLINE  __attribute__((always_inline))

#include <stdint.h>

#include <assert.h>

# define G_NORETURN __attribute__ ((__noreturn__))

#define qemu_build_not_reached()  qemu_build_not_reached_always()

G_NORETURN extern
void QEMU_ERROR("code path is reachable")
    qemu_build_not_reached_always(void);

static inline uint32_t rol32(uint32_t word, unsigned int shift)
{
    return (word << (shift & 31)) | (word >> (-shift & 31));
}

static inline uint32_t ror32(uint32_t word, unsigned int shift)
{
    return (word >> (shift & 31)) | (word << (-shift & 31));
}

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

static inline int32_t sextract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    /* Note that this implementation relies on right shift of signed
     * integers being an arithmetic shift.
     */
    return ((int32_t)(value << (32 - length - start))) >> (32 - length);
}

#define HELPER(name) glue(helper_, name)

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

static inline void clear_tail(void *vd, uintptr_t opr_sz, uintptr_t max_sz)
{
    uint64_t *d = vd + opr_sz;
    uintptr_t i;

    for (i = opr_sz; i < max_sz; i += 8) {
        *d++ = 0;
    }
}

#define CR_ST_WORD(state, i)   ((state).words[i])

union CRYPTO_STATE {
    uint8_t    bytes[16];
    uint32_t   words[4];
    uint64_t   l[2];
};

static void clear_tail_16(void *vd, uint32_t desc)
{
    int opr_sz = simd_oprsz(desc);
    int max_sz = simd_maxsz(desc);

    assert(opr_sz == 16);
    clear_tail(vd, opr_sz, max_sz);
}

static uint32_t cho(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & (y ^ z)) ^ z;
}

static uint32_t par(uint32_t x, uint32_t y, uint32_t z)
{
    return x ^ y ^ z;
}

static uint32_t maj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) | ((x | y) & z);
}

#define DO_SM3TT(NAME, OPCODE) \
    void HELPER(NAME)(void *vd, void *vn, void *vm, uint32_t desc) \
    { crypto_sm3tt(vd, vn, vm, desc, OPCODE); }

static inline void QEMU_ALWAYS_INLINE
crypto_sm3tt(uint64_t *rd, uint64_t *rn, uint64_t *rm,
             uint32_t desc, uint32_t opcode)
{
    union CRYPTO_STATE d = { .l = { rd[0], rd[1] } };
    union CRYPTO_STATE n = { .l = { rn[0], rn[1] } };
    union CRYPTO_STATE m = { .l = { rm[0], rm[1] } };
    uint32_t imm2 = simd_data(desc);
    uint32_t t;

    assert(imm2 < 4);

    if (opcode == 0 || opcode == 2) {
        /* SM3TT1A, SM3TT2A */
        t = par(CR_ST_WORD(d, 3), CR_ST_WORD(d, 2), CR_ST_WORD(d, 1));
    } else if (opcode == 1) {
        /* SM3TT1B */
        t = maj(CR_ST_WORD(d, 3), CR_ST_WORD(d, 2), CR_ST_WORD(d, 1));
    } else if (opcode == 3) {
        /* SM3TT2B */
        t = cho(CR_ST_WORD(d, 3), CR_ST_WORD(d, 2), CR_ST_WORD(d, 1));
    } else {
        qemu_build_not_reached();
    }

    t += CR_ST_WORD(d, 0) + CR_ST_WORD(m, imm2);

    CR_ST_WORD(d, 0) = CR_ST_WORD(d, 1);

    if (opcode < 2) {
        /* SM3TT1A, SM3TT1B */
        t += CR_ST_WORD(n, 3) ^ ror32(CR_ST_WORD(d, 3), 20);

        CR_ST_WORD(d, 1) = ror32(CR_ST_WORD(d, 2), 23);
    } else {
        /* SM3TT2A, SM3TT2B */
        t += CR_ST_WORD(n, 3);
        t ^= rol32(t, 9) ^ rol32(t, 17);

        CR_ST_WORD(d, 1) = ror32(CR_ST_WORD(d, 2), 13);
    }

    CR_ST_WORD(d, 2) = CR_ST_WORD(d, 3);
    CR_ST_WORD(d, 3) = t;

    rd[0] = d.l[0];
    rd[1] = d.l[1];

    clear_tail_16(rd, desc);
}

DO_SM3TT(crypto_sm3tt1a, 0)

