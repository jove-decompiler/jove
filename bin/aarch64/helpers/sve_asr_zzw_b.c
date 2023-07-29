#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <assert.h>

#define MIN(a, b)                                       \
    ({                                                  \
        typeof(1 ? (a) : (b)) _a = (a), _b = (b);       \
        _a < _b ? _a : _b;                              \
    })

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

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

#define HELPER(name) glue(helper_, name)

#define H1(x)   (x)

#define DO_ASR(N, M)  (N >> MIN(M, sizeof(N) * 8 - 1))

#define DO_ZZW(NAME, TYPE, TYPEW, H, OP)                       \
void HELPER(NAME)(void *vd, void *vn, void *vm, uint32_t desc) \
{                                                              \
    intptr_t i, opr_sz = simd_oprsz(desc);                     \
    for (i = 0; i < opr_sz; ) {                                \
        TYPEW mm = *(TYPEW *)(vm + i);                         \
        do {                                                   \
            TYPE nn = *(TYPE *)(vn + H(i));                    \
            *(TYPE *)(vd + H(i)) = OP(nn, mm);                 \
            i += sizeof(TYPE);                                 \
        } while (i & 7);                                       \
    }                                                          \
}

DO_ZZW(sve_asr_zzw_b, int8_t, uint64_t, H1, DO_ASR)

