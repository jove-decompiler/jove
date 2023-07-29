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

#define ZMM_W(n) _w_ZMMReg[n]

#define ZMM_Q(n) _q_ZMMReg[n]

#define SHIFT 1

#define Reg ZMMReg

#define W(n) ZMM_W(n)

#define Q(n) ZMM_Q(n)

#define SUFFIX _xmm

#define SHUFFLE4(F, a, b, offset) do {      \
    r0 = a->F((order & 3) + offset);        \
    r1 = a->F(((order >> 2) & 3) + offset); \
    r2 = b->F(((order >> 4) & 3) + offset); \
    r3 = b->F(((order >> 6) & 3) + offset); \
    d->F(offset) = r0;                      \
    d->F(offset + 1) = r1;                  \
    d->F(offset + 2) = r2;                  \
    d->F(offset + 3) = r3;                  \
    } while (0)

void glue(helper_pshuflw, SUFFIX)(Reg *d, Reg *s, int order)
{
    uint16_t r0, r1, r2, r3;
    int i, j;

    for (i = 0, j = 1; j < 1 << SHIFT; i += 8, j += 2) {
        SHUFFLE4(W, s, s, i);
        d->Q(j) = s->Q(j);
    }
}

