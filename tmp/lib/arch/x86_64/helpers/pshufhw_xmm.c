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

typedef MMREG_UNION(ZMMReg, 512) ZMMReg;

#define ZMM_W(n) _w_ZMMReg[n]

#define ZMM_Q(n) _q_ZMMReg[n]

#define Reg ZMMReg

#define W(n) ZMM_W(n)

#define Q(n) ZMM_Q(n)

#define SUFFIX _xmm

void glue(helper_pshufhw, SUFFIX)(Reg *d, Reg *s, int order)
{
    Reg r;

    r.Q(0) = s->Q(0);
    r.W(4) = s->W(4 + (order & 3));
    r.W(5) = s->W(4 + ((order >> 2) & 3));
    r.W(6) = s->W(4 + ((order >> 4) & 3));
    r.W(7) = s->W(4 + ((order >> 6) & 3));
    *d = r;
}

