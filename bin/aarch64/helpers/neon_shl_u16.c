#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdbool.h>

#include <stdint.h>

#include <assert.h>

#include <stddef.h>

#define MAKE_64BIT_MASK(shift, length) \
    (((~0ULL) >> (64 - (length))) << (shift))

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

#define HELPER(name) glue(helper_, name)

static inline uint32_t do_uqrshl_bhs(uint32_t src, int32_t shift, int bits,
                                     bool round, uint32_t *sat)
{
    if (shift <= -(bits + round)) {
        return 0;
    } else if (shift < 0) {
        if (round) {
            src >>= -shift - 1;
            return (src >> 1) + (src & 1);
        }
        return src >> -shift;
    } else if (shift < bits) {
        uint32_t val = src << shift;
        if (bits == 32) {
            if (!sat || val >> shift == src) {
                return val;
            }
        } else {
            uint32_t extval = extract32(val, 0, bits);
            if (!sat || val == extval) {
                return extval;
            }
        }
    } else if (!sat || src == 0) {
        return 0;
    }

    *sat = 1;
    return MAKE_64BIT_MASK(0, bits);
}

#define NEON_TYPE2(name, type) \
typedef struct \
{ \
    type v1; \
    type v2; \
} neon_##name;

NEON_TYPE2(u16, uint16_t)

#define NEON_UNPACK(vtype, dest, val) do { \
    union { \
        vtype v; \
        uint32_t i; \
    } conv_u; \
    conv_u.i = (val); \
    dest = conv_u.v; \
    } while(0)

#define NEON_PACK(vtype, dest, val) do { \
    union { \
        vtype v; \
        uint32_t i; \
    } conv_u; \
    conv_u.v = (val); \
    dest = conv_u.i; \
    } while(0)

#define NEON_DO2 \
    NEON_FN(vdest.v1, vsrc1.v1, vsrc2.v1); \
    NEON_FN(vdest.v2, vsrc1.v2, vsrc2.v2);

#define NEON_VOP_BODY(vtype, n) \
{ \
    uint32_t res; \
    vtype vsrc1; \
    vtype vsrc2; \
    vtype vdest; \
    NEON_UNPACK(vtype, vsrc1, arg1); \
    NEON_UNPACK(vtype, vsrc2, arg2); \
    NEON_DO##n; \
    NEON_PACK(vtype, res, vdest); \
    return res; \
}

#define NEON_VOP(name, vtype, n) \
uint32_t HELPER(glue(neon_,name))(uint32_t arg1, uint32_t arg2) \
NEON_VOP_BODY(vtype, n)

#define NEON_FN(dest, src1, src2) \
    (dest = do_uqrshl_bhs(src1, (int8_t)src2, 16, false, NULL))

NEON_VOP(shl_u16, neon_u16, 2)

