#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

typedef uint32_t float32;

typedef uint64_t float64;

#define MMREG_UNION(n, bits)        \
    union n {                       \
        uint8_t  _b_##n[(bits)/8];  \
        uint16_t _w_##n[(bits)/16]; \
        uint32_t _l_##n[(bits)/32]; \
        uint64_t _q_##n[(bits)/64]; \
        float32  _s_##n[(bits)/32]; \
        float64  _d_##n[(bits)/64]; \
    }

typedef MMREG_UNION(MMXReg, 64)  MMXReg;

#define MMX_L(n) _l_MMXReg[n]

#define SHIFT 0

#define Reg MMXReg

#define L(n) MMX_L(n)

#define SUFFIX _mmx

void glue(helper_movl_mm_T0, SUFFIX)(Reg *d, uint32_t val)
{
    d->L(0) = val;
    d->L(1) = 0;
#if SHIFT == 1
    d->Q(1) = 0;
#endif
}

