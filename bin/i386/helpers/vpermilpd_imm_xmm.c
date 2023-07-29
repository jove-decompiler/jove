#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

typedef uint16_t float16;

typedef uint32_t float32;

typedef uint64_t float64;

typedef union XMMReg {
    uint64_t _q_XMMReg[128 / 64];
} XMMReg;

typedef union YMMReg {
    uint64_t _q_YMMReg[256 / 64];
    XMMReg   _x_YMMReg[256 / 128];
} YMMReg;

typedef union ZMMReg {
    uint8_t  _b_ZMMReg[512 / 8];
    uint16_t _w_ZMMReg[512 / 16];
    uint32_t _l_ZMMReg[512 / 32];
    uint64_t _q_ZMMReg[512 / 64];
    float16  _h_ZMMReg[512 / 16];
    float32  _s_ZMMReg[512 / 32];
    float64  _d_ZMMReg[512 / 64];
    XMMReg   _x_ZMMReg[512 / 128];
    YMMReg   _y_ZMMReg[512 / 256];
} ZMMReg;

#define ZMM_Q(n) _q_ZMMReg[n]

#define SHIFT 1

#define Reg ZMMReg

#define Q(n) ZMM_Q(n)

#define SUFFIX _xmm

void glue(helper_vpermilpd_imm, SUFFIX)(Reg *d, Reg *s, uint32_t order)
{
    uint64_t r0, r1;
    int i;

    for (i = 0; i < 1 << SHIFT; i += 2) {
        r0 = s->Q(i + ((order >> 0) & 1));
        r1 = s->Q(i + ((order >> 1) & 1));
        d->Q(i) = r0;
        d->Q(i+1) = r1;

        order >>= 2;
    }
}

