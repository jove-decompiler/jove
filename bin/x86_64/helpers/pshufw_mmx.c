#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

typedef uint32_t float32;

typedef uint64_t float64;

typedef union MMXReg {
    uint8_t  _b_MMXReg[64 / 8];
    uint16_t _w_MMXReg[64 / 16];
    uint32_t _l_MMXReg[64 / 32];
    uint64_t _q_MMXReg[64 / 64];
    float32  _s_MMXReg[64 / 32];
    float64  _d_MMXReg[64 / 64];
} MMXReg;

#define MMX_W(n) _w_MMXReg[n]

#define Reg MMXReg

#define W(n) MMX_W(n)

#define SUFFIX _mmx

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

void glue(helper_pshufw, SUFFIX)(Reg *d, Reg *s, int order)
{
    uint16_t r0, r1, r2, r3;

    SHUFFLE4(W, s, s, 0);
}

