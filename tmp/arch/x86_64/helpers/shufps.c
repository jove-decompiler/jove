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

typedef MMREG_UNION(ZMMReg, 512) ZMMReg;

#define ZMM_L(n) _l_ZMMReg[n]

#define Reg ZMMReg

#define L(n) ZMM_L(n)

void helper_shufps(Reg *d, Reg *s, int order)
{
    Reg r;

    r.L(0) = d->L(order & 3);
    r.L(1) = d->L((order >> 2) & 3);
    r.L(2) = s->L((order >> 4) & 3);
    r.L(3) = s->L((order >> 6) & 3);
    *d = r;
}

