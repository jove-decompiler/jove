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

#define MMX_W(n) _w_MMXReg[n]

#define Reg MMXReg

#define W(n) MMX_W(n)

#define SUFFIX _mmx

void glue(helper_pshufw, SUFFIX)(Reg *d, Reg *s, int order)
{
    Reg r;

    r.W(0) = s->W(order & 3);
    r.W(1) = s->W((order >> 2) & 3);
    r.W(2) = s->W((order >> 4) & 3);
    r.W(3) = s->W((order >> 6) & 3);
    *d = r;
}

