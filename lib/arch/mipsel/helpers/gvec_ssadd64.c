#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#define unlikely(x)   __builtin_expect(!!(x), 0)

#include <stddef.h>

#include <stdbool.h>

#include <stdint.h>

#include <stdio.h>

#include <assert.h>

static inline bool sadd32_overflow(int32_t x, int32_t y, int32_t *ret)
{
    return __builtin_add_overflow(x, y, ret);
}

static inline bool sadd64_overflow(int64_t x, int64_t y, int64_t *ret)
{
    return __builtin_add_overflow(x, y, ret);
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

static inline void clear_high(void *d, intptr_t oprsz, uint32_t desc)
{
    intptr_t maxsz = simd_maxsz(desc);
    intptr_t i;

    if (unlikely(maxsz > oprsz)) {
        for (i = oprsz; i < maxsz; i += sizeof(uint64_t)) {
            *(uint64_t *)(d + i) = 0;
        }
    }
}

void HELPER(gvec_ssadd64)(void *d, void *a, void *b, uint32_t desc)
{
    intptr_t oprsz = simd_oprsz(desc);
    intptr_t i;

    for (i = 0; i < oprsz; i += sizeof(int64_t)) {
        int64_t ai = *(int64_t *)(a + i);
        int64_t bi = *(int64_t *)(b + i);
        int64_t di;
        if (sadd64_overflow(ai, bi, &di)) {
            di = (di < 0 ? INT64_MAX : INT64_MIN);
        }
        *(int64_t *)(d + i) = di;
    }
    clear_high(d, oprsz, desc);
}

