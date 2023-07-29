#include <stdint.h>

#define SATSB(x)  (x < -0x80 ? -0x80 : x > 0x7f ? 0x7f : x)

typedef union {
    uint8_t  ub[8];
    int8_t   sb[8];
    uint16_t uh[4];
    int16_t  sh[4];
    uint32_t uw[2];
    int32_t  sw[2];
    uint64_t d;
} LMIValue;

uint64_t helper_psubsb(uint64_t fs, uint64_t ft)
{
    LMIValue vs, vt;
    unsigned int i;

    vs.d = fs;
    vt.d = ft;
    for (i = 0; i < 8; ++i) {
        int r = vs.sb[i] - vt.sb[i];
        vs.sb[i] = SATSB(r);
    }
    return vs.d;
}

