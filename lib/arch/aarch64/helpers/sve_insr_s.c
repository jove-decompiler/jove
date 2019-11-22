#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stddef.h>

#include <stdint.h>

#include <string.h>

#include <assert.h>

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

#define HELPER(name) glue(helper_, name)

#define SIMD_OPRSZ_SHIFT   0

#define SIMD_OPRSZ_BITS    5

static inline intptr_t simd_oprsz(uint32_t desc)
{
    return (extract32(desc, SIMD_OPRSZ_SHIFT, SIMD_OPRSZ_BITS) + 1) * 8;
}

#define H1(x)   (x)

#define H1_2(x) (x)

#define H1_4(x) (x)

static void swap_memmove(void *vd, void *vs, size_t n)
{
    uintptr_t d = (uintptr_t)vd;
    uintptr_t s = (uintptr_t)vs;
    uintptr_t o = (d | s | n) & 7;
    size_t i;

#ifndef HOST_WORDS_BIGENDIAN
    o = 0;
#endif
    switch (o) {
    case 0:
        memmove(vd, vs, n);
        break;

    case 4:
        if (d < s || d >= s + n) {
            for (i = 0; i < n; i += 4) {
                *(uint32_t *)H1_4(d + i) = *(uint32_t *)H1_4(s + i);
            }
        } else {
            for (i = n; i > 0; ) {
                i -= 4;
                *(uint32_t *)H1_4(d + i) = *(uint32_t *)H1_4(s + i);
            }
        }
        break;

    case 2:
    case 6:
        if (d < s || d >= s + n) {
            for (i = 0; i < n; i += 2) {
                *(uint16_t *)H1_2(d + i) = *(uint16_t *)H1_2(s + i);
            }
        } else {
            for (i = n; i > 0; ) {
                i -= 2;
                *(uint16_t *)H1_2(d + i) = *(uint16_t *)H1_2(s + i);
            }
        }
        break;

    default:
        if (d < s || d >= s + n) {
            for (i = 0; i < n; i++) {
                *(uint8_t *)H1(d + i) = *(uint8_t *)H1(s + i);
            }
        } else {
            for (i = n; i > 0; ) {
                i -= 1;
                *(uint8_t *)H1(d + i) = *(uint8_t *)H1(s + i);
            }
        }
        break;
    }
}

#define DO_INSR(NAME, TYPE, H) \
void HELPER(NAME)(void *vd, void *vn, uint64_t val, uint32_t desc) \
{                                                                  \
    intptr_t opr_sz = simd_oprsz(desc);                            \
    swap_memmove(vd + sizeof(TYPE), vn, opr_sz - sizeof(TYPE));    \
    *(TYPE *)(vd + H(0)) = val;                                    \
}

DO_INSR(sve_insr_s, uint32_t, H1_4)

