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

#define Reg ZMMReg

#define Q(n) ZMM_Q(n)

void helper_vpermq_ymm(Reg *d, Reg *s, uint32_t order)
{
    uint64_t r0, r1, r2, r3;
    r0 = s->Q(order & 3);
    r1 = s->Q((order >> 2) & 3);
    r2 = s->Q((order >> 4) & 3);
    r3 = s->Q((order >> 6) & 3);
    d->Q(0) = r0;
    d->Q(1) = r1;
    d->Q(2) = r2;
    d->Q(3) = r3;
}

