#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdbool.h>

#include <stdint.h>

#include <assert.h>

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

extern const uint8_t AES_sbox[256];

extern const uint8_t AES_isbox[256];

extern const uint8_t AES_shifts[16];

extern const uint8_t AES_ishifts[16];

static inline void clear_tail(void *vd, uintptr_t opr_sz, uintptr_t max_sz)
{
    uint64_t *d = vd + opr_sz;
    uintptr_t i;

    for (i = opr_sz; i < max_sz; i += 8) {
        *d++ = 0;
    }
}

#define CR_ST_BYTE(state, i)   ((state).bytes[i])

union CRYPTO_STATE {
    uint8_t    bytes[16];
    uint32_t   words[4];
    uint64_t   l[2];
};

static void do_crypto_aese(uint64_t *rd, uint64_t *rn,
                           uint64_t *rm, bool decrypt)
{
    static uint8_t const * const sbox[2] = { AES_sbox, AES_isbox };
    static uint8_t const * const shift[2] = { AES_shifts, AES_ishifts };
    union CRYPTO_STATE rk = { .l = { rm[0], rm[1] } };
    union CRYPTO_STATE st = { .l = { rn[0], rn[1] } };
    int i;

    /* xor state vector with round key */
    rk.l[0] ^= st.l[0];
    rk.l[1] ^= st.l[1];

    /* combine ShiftRows operation and sbox substitution */
    for (i = 0; i < 16; i++) {
        CR_ST_BYTE(st, i) = sbox[decrypt][CR_ST_BYTE(rk, shift[decrypt][i])];
    }

    rd[0] = st.l[0];
    rd[1] = st.l[1];
}

void HELPER(crypto_aese)(void *vd, void *vn, void *vm, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc);
    bool decrypt = simd_data(desc);

    for (i = 0; i < opr_sz; i += 16) {
        do_crypto_aese(vd + i, vn + i, vm + i, decrypt);
    }
    clear_tail(vd, opr_sz, simd_maxsz(desc));
}

