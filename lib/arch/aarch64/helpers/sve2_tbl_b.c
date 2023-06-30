#define QEMU_ALIGNED(X) __attribute__((aligned(X)))

#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#define unlikely(x)   __builtin_expect(!!(x), 0)

#include <stddef.h>

#include <stdbool.h>

#include <stdint.h>

#include <stdio.h>

#include <string.h>

#include <assert.h>

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

# define ARM_MAX_VQ    16

typedef struct ARMVectorReg {
    uint64_t d[2 * ARM_MAX_VQ] QEMU_ALIGNED(16);
} ARMVectorReg;

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

typedef void tb_impl_fn(void *, void *, void *, void *, uintptr_t, bool);

static inline void do_tbl1(void *vd, void *vn, void *vm, uint32_t desc,
                           bool is_tbx, tb_impl_fn *fn)
{
    ARMVectorReg scratch;
    uintptr_t oprsz = simd_oprsz(desc);

    if (unlikely(vd == vn)) {
        vn = memcpy(&scratch, vn, oprsz);
    }

    fn(vd, vn, NULL, vm, oprsz, is_tbx);
}

#define DO_TB(SUFF, TYPE, H)                                            \
static inline void do_tb_##SUFF(void *vd, void *vt0, void *vt1,         \
                                void *vm, uintptr_t oprsz, bool is_tbx) \
{                                                                       \
    TYPE *d = vd, *tbl0 = vt0, *tbl1 = vt1, *indexes = vm;              \
    uintptr_t i, nelem = oprsz / sizeof(TYPE);                          \
    for (i = 0; i < nelem; ++i) {                                       \
        TYPE index = indexes[H1(i)], val = 0;                           \
        if (index < nelem) {                                            \
            val = tbl0[H(index)];                                       \
        } else {                                                        \
            index -= nelem;                                             \
            if (tbl1 && index < nelem) {                                \
                val = tbl1[H(index)];                                   \
            } else if (is_tbx) {                                        \
                continue;                                               \
            }                                                           \
        }                                                               \
        d[H(i)] = val;                                                  \
    }                                                                   \
}                                                                       \
void HELPER(sve_tbl_##SUFF)(void *vd, void *vn, void *vm, uint32_t desc) \
{                                                                       \
    do_tbl1(vd, vn, vm, desc, false, do_tb_##SUFF);                     \
}                                                                       \
void HELPER(sve2_tbl_##SUFF)(void *vd, void *vn0, void *vn1,            \
                             void *vm, uint32_t desc)                   \
{                                                                       \
    do_tbl2(vd, vn0, vn1, vm, desc, false, do_tb_##SUFF);               \
}                                                                       \
void HELPER(sve2_tbx_##SUFF)(void *vd, void *vn, void *vm, uint32_t desc) \
{                                                                       \
    do_tbl1(vd, vn, vm, desc, true, do_tb_##SUFF);                      \
}

static inline void do_tbl2(void *vd, void *vn0, void *vn1, void *vm,
                           uint32_t desc, bool is_tbx, tb_impl_fn *fn)
{
    ARMVectorReg scratch;
    uintptr_t oprsz = simd_oprsz(desc);

    if (unlikely(vd == vn0)) {
        vn0 = memcpy(&scratch, vn0, oprsz);
        if (vd == vn1) {
            vn1 = vn0;
        }
    } else if (unlikely(vd == vn1)) {
        vn1 = memcpy(&scratch, vn1, oprsz);
    }

    fn(vd, vn0, vn1, vm, oprsz, is_tbx);
}

DO_TB(b, uint8_t, H1)

