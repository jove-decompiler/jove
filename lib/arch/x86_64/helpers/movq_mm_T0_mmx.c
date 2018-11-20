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

#define MMX_Q(n) _q_MMXReg[n]

#define SHIFT 0

#define Reg MMXReg

#define Q(n) MMX_Q(n)

#define SUFFIX _mmx

void glue(helper_movq_mm_T0, SUFFIX)(Reg *d, uint64_t val)
{
    d->Q(0) = val;
#if SHIFT == 1
    d->Q(1) = 0;
#endif
}

