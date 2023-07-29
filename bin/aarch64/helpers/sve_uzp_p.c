#define HOST_BIG_ENDIAN (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)

#define QEMU_ALIGNED(X) __attribute__((aligned(X)))

#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stddef.h>

#include <stdint.h>

#include <string.h>

#include <assert.h>

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

#define MAKE_64BIT_MASK(shift, length) \
    (((~0ULL) >> (64 - (length))) << (shift))

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

#define FIELD(reg, field, shift, length)                                  \
    enum { R_ ## reg ## _ ## field ## _SHIFT = (shift)};                  \
    enum { R_ ## reg ## _ ## field ## _LENGTH = (length)};                \
    enum { R_ ## reg ## _ ## field ## _MASK =                             \
                                        MAKE_64BIT_MASK(shift, length)};

#define FIELD_EX32(storage, reg, field)                                   \
    extract32((storage), R_ ## reg ## _ ## field ## _SHIFT,               \
              R_ ## reg ## _ ## field ## _LENGTH)

# define ARM_MAX_VQ    16

typedef struct ARMPredicateReg {
    uint64_t p[DIV_ROUND_UP(2 * ARM_MAX_VQ, 8)] QEMU_ALIGNED(16);
} ARMPredicateReg;

FIELD(PREDDESC, OPRSZ, 0, 6)

FIELD(PREDDESC, ESZ, 6, 2)

FIELD(PREDDESC, DATA, 8, 24)

#define HELPER(name) glue(helper_, name)

#define H1(x)   (x)

#define H1_2(x) (x)

#define H1_4(x) (x)

static void swap_memmove(void *vd, void *vs, size_t n)
{
    uintptr_t d = (uintptr_t)vd;
    uintptr_t s = (uintptr_t)vs;
    uintptr_t o = (d | s | n) & 7;
    size_t i;

#if !HOST_BIG_ENDIAN
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

static const uint64_t even_bit_esz_masks[5] = {
    0x5555555555555555ull,
    0x3333333333333333ull,
    0x0f0f0f0f0f0f0f0full,
    0x00ff00ff00ff00ffull,
    0x0000ffff0000ffffull,
};

static uint64_t compress_bits(uint64_t x, int n)
{
    int i;

    for (i = n; i <= 4; i++) {
        int sh = 1 << i;
        x &= even_bit_esz_masks[i];
        x = (x >> sh) | x;
    }
    return x & 0xffffffffu;
}

void HELPER(sve_uzp_p)(void *vd, void *vn, void *vm, uint32_t pred_desc)
{
    intptr_t oprsz = FIELD_EX32(pred_desc, PREDDESC, OPRSZ);
    int esz = FIELD_EX32(pred_desc, PREDDESC, ESZ);
    int odd = FIELD_EX32(pred_desc, PREDDESC, DATA) << esz;
    uint64_t *d = vd, *n = vn, *m = vm;
    uint64_t l, h;
    intptr_t i;

    if (oprsz <= 8) {
        l = compress_bits(n[0] >> odd, esz);
        h = compress_bits(m[0] >> odd, esz);
        d[0] = l | (h << (4 * oprsz));
    } else {
        ARMPredicateReg tmp_m;
        intptr_t oprsz_16 = oprsz / 16;

        if ((vm - vd) < (uintptr_t)oprsz) {
            m = memcpy(&tmp_m, vm, oprsz);
        }

        for (i = 0; i < oprsz_16; i++) {
            l = n[2 * i + 0];
            h = n[2 * i + 1];
            l = compress_bits(l >> odd, esz);
            h = compress_bits(h >> odd, esz);
            d[i] = l | (h << 32);
        }

        /*
         * For VL which is not a multiple of 512, the results from M do not
         * align nicely with the uint64_t for D.  Put the aligned results
         * from M into TMP_M and then copy it into place afterward.
         */
        if (oprsz & 15) {
            int final_shift = (oprsz & 15) * 2;

            l = n[2 * i + 0];
            h = n[2 * i + 1];
            l = compress_bits(l >> odd, esz);
            h = compress_bits(h >> odd, esz);
            d[i] = l | (h << final_shift);

            for (i = 0; i < oprsz_16; i++) {
                l = m[2 * i + 0];
                h = m[2 * i + 1];
                l = compress_bits(l >> odd, esz);
                h = compress_bits(h >> odd, esz);
                tmp_m.p[i] = l | (h << 32);
            }
            l = m[2 * i + 0];
            h = m[2 * i + 1];
            l = compress_bits(l >> odd, esz);
            h = compress_bits(h >> odd, esz);
            tmp_m.p[i] = l | (h << final_shift);

            swap_memmove(vd + oprsz / 2, &tmp_m, oprsz / 2);
        } else {
            for (i = 0; i < oprsz_16; i++) {
                l = m[2 * i + 0];
                h = m[2 * i + 1];
                l = compress_bits(l >> odd, esz);
                h = compress_bits(h >> odd, esz);
                d[oprsz_16 + i] = l | (h << 32);
            }
        }
    }
}

