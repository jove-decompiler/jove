#define HOST_BIG_ENDIAN (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)

#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#define unlikely(x)   __builtin_expect(!!(x), 0)

#include <stddef.h>

#include <stdbool.h>

#include <stdint.h>

#include <stdio.h>

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

static inline Int128 int128_exts64(int64_t a)
{
    return int128_make128(a, (a < 0) ? -1 : 0);
}

static inline Int128 int128_rshift(Int128 a, int n)
{
    int64_t h;
    if (!n) {
        return a;
    }
    h = a.hi >> (n & 63);
    if (n >= 64) {
        return int128_make128(h, h >> 63);
    } else {
        return int128_make128((a.lo >> n) | ((uint64_t)a.hi << (64 - n)), h);
    }
}

static inline Int128 int128_lshift(Int128 a, int n)
{
    uint64_t l = a.lo << (n & 63);
    if (n >= 64) {
        return int128_make128(0, l);
    } else if (n > 0) {
        return int128_make128(l, (a.hi << n) | (a.lo >> (64 - n)));
    }
    return a;
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

static inline Int128 int128_neg(Int128 a)
{
    uint64_t lo = -a.lo;
    return int128_make128(lo, ~(uint64_t)a.hi + !lo);
}

static inline void muls64(uint64_t *plow, uint64_t *phigh,
                          int64_t a, int64_t b)
{
    __int128_t r = (__int128_t)a * b;
    *plow = r;
    *phigh = r >> 64;
}

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

#define HELPER(name) glue(helper_, name)

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

static int64_t do_sat128_d(Int128 r)
{
    int64_t ls = int128_getlo(r);
    int64_t hs = int128_gethi(r);

    if (unlikely(hs != (ls >> 63))) {
        return hs < 0 ? INT64_MIN : INT64_MAX;
    }
    return ls;
}

int64_t do_sqrdmlah_d(int64_t n, int64_t m, int64_t a, bool neg, bool round)
{
    uint64_t l, h;
    Int128 r, t;

    /* As in do_sqrdmlah_b, but with 128-bit arithmetic. */
    muls64(&l, &h, m, n);
    r = int128_make128(l, h);
    if (neg) {
        r = int128_neg(r);
    }
    if (a) {
        t = int128_exts64(a);
        t = int128_lshift(t, 63);
        r = int128_add(r, t);
    }
    if (round) {
        t = int128_exts64(1ll << 62);
        r = int128_add(r, t);
    }
    r = int128_rshift(r, 63);

    return do_sat128_d(r);
}

void HELPER(sve2_sqrdmulh_d)(void *vd, void *vn, void *vm, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc);
    int64_t *d = vd, *n = vn, *m = vm;

    for (i = 0; i < opr_sz / 8; ++i) {
        d[i] = do_sqrdmlah_d(n[i], m[i], 0, false, true);
    }
}

