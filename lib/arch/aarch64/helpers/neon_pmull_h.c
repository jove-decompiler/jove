#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

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

static uint64_t expand_byte_to_half(uint64_t x)
{
    return  (x & 0x000000ff)
         | ((x & 0x0000ff00) << 8)
         | ((x & 0x00ff0000) << 16)
         | ((x & 0xff000000) << 24);
}

uint64_t pmull_h(uint64_t op1, uint64_t op2)
{
    uint64_t result = 0;
    int i;
    for (i = 0; i < 8; ++i) {
        uint64_t mask = (op1 & 0x0001000100010001ull) * 0xffff;
        result ^= op2 & mask;
        op1 >>= 1;
        op2 <<= 1;
    }
    return result;
}

void HELPER(neon_pmull_h)(void *vd, void *vn, void *vm, uint32_t desc)
{
    int hi = simd_data(desc);
    uint64_t *d = vd, *n = vn, *m = vm;
    uint64_t nn = n[hi], mm = m[hi];

    d[0] = pmull_h(expand_byte_to_half(nn), expand_byte_to_half(mm));
    nn >>= 32;
    mm >>= 32;
    d[1] = pmull_h(expand_byte_to_half(nn), expand_byte_to_half(mm));

    clear_tail(d, 16, simd_maxsz(desc));
}

