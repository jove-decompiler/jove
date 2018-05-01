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

#define ZMM_Q(n) _q_ZMMReg[n]

#define Reg ZMMReg

#define Q(n) ZMM_Q(n)

void helper_shufpd(Reg *d, Reg *s, int order)
{
    Reg r;

    r.Q(0) = d->Q(order & 1);
    r.Q(1) = s->Q((order >> 1) & 1);
    *d = r;
}

