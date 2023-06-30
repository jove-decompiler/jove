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

#define HELPER(name) glue(helper_, name)

#define H1_8(x) (x)

static inline int64_t do_sqadd_d(int64_t n, int64_t m)
{
    int64_t r = n + m;
    if (((r ^ n) & ~(n ^ m)) < 0) {
        /* Signed overflow.  */
        return r < 0 ? INT64_MAX : INT64_MIN;
    }
    return r;
}

static inline int64_t do_sqsub_d(int64_t n, int64_t m)
{
    int64_t r = n - m;
    if (((r ^ n) & (n ^ m)) < 0) {
        /* Signed overflow.  */
        return r < 0 ? INT64_MAX : INT64_MIN;
    }
    return r;
}

#define DO_CADD(NAME, TYPE, H, ADD_OP, SUB_OP)                  \
void HELPER(NAME)(void *vd, void *vn, void *vm, uint32_t desc)  \
{                                                               \
    intptr_t i, opr_sz = simd_oprsz(desc);                      \
    int sub_r = simd_data(desc);                                \
    if (sub_r) {                                                \
        for (i = 0; i < opr_sz; i += 2 * sizeof(TYPE)) {        \
            TYPE acc_r = *(TYPE *)(vn + H(i));                  \
            TYPE acc_i = *(TYPE *)(vn + H(i + sizeof(TYPE)));   \
            TYPE el2_r = *(TYPE *)(vm + H(i));                  \
            TYPE el2_i = *(TYPE *)(vm + H(i + sizeof(TYPE)));   \
            acc_r = ADD_OP(acc_r, el2_i);                       \
            acc_i = SUB_OP(acc_i, el2_r);                       \
            *(TYPE *)(vd + H(i)) = acc_r;                       \
            *(TYPE *)(vd + H(i + sizeof(TYPE))) = acc_i;        \
        }                                                       \
    } else {                                                    \
        for (i = 0; i < opr_sz; i += 2 * sizeof(TYPE)) {        \
            TYPE acc_r = *(TYPE *)(vn + H(i));                  \
            TYPE acc_i = *(TYPE *)(vn + H(i + sizeof(TYPE)));   \
            TYPE el2_r = *(TYPE *)(vm + H(i));                  \
            TYPE el2_i = *(TYPE *)(vm + H(i + sizeof(TYPE)));   \
            acc_r = SUB_OP(acc_r, el2_i);                       \
            acc_i = ADD_OP(acc_i, el2_r);                       \
            *(TYPE *)(vd + H(i)) = acc_r;                       \
            *(TYPE *)(vd + H(i + sizeof(TYPE))) = acc_i;        \
        }                                                       \
    }                                                           \
}

DO_CADD(sve2_sqcadd_d, int64_t, H1_8, do_sqadd_d, do_sqsub_d)

