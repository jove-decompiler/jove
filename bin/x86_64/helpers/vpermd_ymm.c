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

#define ZMM_L(n) _l_ZMMReg[n]

#define Reg ZMMReg

#define L(n) ZMM_L(n)

void helper_vpermd_ymm(Reg *d, Reg *v, Reg *s)
{
    uint32_t r[8];
    int i;

    for (i = 0; i < 8; i++) {
        r[i] = s->L(v->L(i) & 7);
    }
    for (i = 0; i < 8; i++) {
        d->L(i) = r[i];
    }
}

