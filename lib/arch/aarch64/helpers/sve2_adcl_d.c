#define HOST_BIG_ENDIAN (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)

#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <assert.h>

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

static inline Int128 int128_make64(uint64_t a)
{
    return (Int128) { .lo = a, .hi = 0 };
}

static inline Int128 int128_make128(uint64_t lo, uint64_t hi)
{
    return (Int128) { .lo = lo, .hi = hi };
}

static inline uint64_t int128_getlo(Int128 a)
{
    return a.lo;
}

static inline int64_t int128_gethi(Int128 a)
{
    return a.hi;
}

static inline Int128 int128_add(Int128 a, Int128 b)
{
    uint64_t lo = a.lo + b.lo;

    /* a.lo <= a.lo + b.lo < a.lo + k (k is the base, 2^64).  Hence,
     * a.lo + b.lo >= k implies 0 <= lo = a.lo + b.lo - k < a.lo.
     * Similarly, a.lo + b.lo < k implies a.lo <= lo = a.lo + b.lo < k.
     *
     * So the carry is lo < a.lo.
     */
    return int128_make128(lo, (uint64_t)a.hi + b.hi + (lo < a.lo));
}

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

#define SIMD_MAXSZ_SHIFT   0

#define SIMD_MAXSZ_BITS    8

#define SIMD_OPRSZ_SHIFT   (SIMD_MAXSZ_SHIFT + SIMD_MAXSZ_BITS)

#define SIMD_OPRSZ_BITS    2

#define SIMD_DATA_SHIFT    (SIMD_OPRSZ_SHIFT + SIMD_OPRSZ_BITS)

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

#define HELPER(name) glue(helper_, name)

void HELPER(sve2_adcl_d)(void *vd, void *vn, void *vm, void *va, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc);
    int sel = extract32(desc, SIMD_DATA_SHIFT, 1);
    uint64_t inv = -(uint64_t)extract32(desc, SIMD_DATA_SHIFT + 1, 1);
    uint64_t *d = vd, *a = va, *n = vn, *m = vm;

    for (i = 0; i < opr_sz / 8; i += 2) {
        Int128 e1 = int128_make64(a[i]);
        Int128 e2 = int128_make64(n[i + sel] ^ inv);
        Int128 c = int128_make64(m[i + 1] & 1);
        Int128 r = int128_add(int128_add(e1, e2), c);
        d[i + 0] = int128_getlo(r);
        d[i + 1] = int128_gethi(r);
    }
}

