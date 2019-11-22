#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#define likely(x)   __builtin_expect(!!(x), 1)

#include <stddef.h>

#include <stdint.h>

#include <stdio.h>

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

#define DEF_HELPER_FLAGS_3(name, flags, ret, t1, t2, t3) \
dh_ctype(ret) HELPER(name) (dh_ctype(t1), dh_ctype(t2), dh_ctype(t3));

DEF_HELPER_FLAGS_3(vfp_mulxs, TCG_CALL_NO_RWG, f32, f32, f32, ptr)

#define SIMD_OPRSZ_SHIFT   0

#define SIMD_OPRSZ_BITS    5

static inline intptr_t simd_oprsz(uint32_t desc)
{
    return (extract32(desc, SIMD_OPRSZ_SHIFT, SIMD_OPRSZ_BITS) + 1) * 8;
}

#define H1_4(x) (x)

#define DO_ZPZZ_FP(NAME, TYPE, H, OP)                           \
void HELPER(NAME)(void *vd, void *vn, void *vm, void *vg,       \
                  void *status, uint32_t desc)                  \
{                                                               \
    intptr_t i = simd_oprsz(desc);                              \
    uint64_t *g = vg;                                           \
    do {                                                        \
        uint64_t pg = g[(i - 1) >> 6];                          \
        do {                                                    \
            i -= sizeof(TYPE);                                  \
            if (likely((pg >> (i & 63)) & 1)) {                 \
                TYPE nn = *(TYPE *)(vn + H(i));                 \
                TYPE mm = *(TYPE *)(vm + H(i));                 \
                *(TYPE *)(vd + H(i)) = OP(nn, mm, status);      \
            }                                                   \
        } while (i & 63);                                       \
    } while (i != 0);                                           \
}

DO_ZPZZ_FP(sve_fmulx_s, uint32_t, H1_4, helper_vfp_mulxs)

