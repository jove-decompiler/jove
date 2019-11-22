#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <assert.h>

typedef uint32_t float32;

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

#define HELPER(name) glue(helper_, name)

#define dh_ctype_f32 float32

#define dh_ctype_ptr void *

#define dh_ctype(t) dh_ctype_##t

#define DEF_HELPER_FLAGS_2(name, flags, ret, t1, t2) \
dh_ctype(ret) HELPER(name) (dh_ctype(t1), dh_ctype(t2));

DEF_HELPER_FLAGS_2(recpe_f32, TCG_CALL_NO_RWG, f32, f32, ptr)

#define SIMD_OPRSZ_SHIFT   0

#define SIMD_OPRSZ_BITS    5

#define SIMD_MAXSZ_SHIFT   (SIMD_OPRSZ_SHIFT + SIMD_OPRSZ_BITS)

#define SIMD_MAXSZ_BITS    5

static inline intptr_t simd_oprsz(uint32_t desc)
{
    return (extract32(desc, SIMD_OPRSZ_SHIFT, SIMD_OPRSZ_BITS) + 1) * 8;
}

static inline intptr_t simd_maxsz(uint32_t desc)
{
    return (extract32(desc, SIMD_MAXSZ_SHIFT, SIMD_MAXSZ_BITS) + 1) * 8;
}

static void clear_tail(void *vd, uintptr_t opr_sz, uintptr_t max_sz)
{
    uint64_t *d = vd + opr_sz;
    uintptr_t i;

    for (i = opr_sz; i < max_sz; i += 8) {
        *d++ = 0;
    }
}

#define DO_2OP(NAME, FUNC, TYPE) \
void HELPER(NAME)(void *vd, void *vn, void *stat, uint32_t desc)  \
{                                                                 \
    intptr_t i, oprsz = simd_oprsz(desc);                         \
    TYPE *d = vd, *n = vn;                                        \
    for (i = 0; i < oprsz / sizeof(TYPE); i++) {                  \
        d[i] = FUNC(n[i], stat);                                  \
    }                                                             \
    clear_tail(d, oprsz, simd_maxsz(desc));                       \
}

DO_2OP(gvec_frecpe_s, helper_recpe_f32, float32)

