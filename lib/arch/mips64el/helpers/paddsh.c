#include <stdint.h>

#define SATSH(x)  (x < -0x8000 ? -0x8000 : x > 0x7fff ? 0x7fff : x)

typedef union {
    uint8_t  ub[8];
    int8_t   sb[8];
    uint16_t uh[4];
    int16_t  sh[4];
    uint32_t uw[2];
    int32_t  sw[2];
    uint64_t d;
} LMIValue;

uint64_t helper_paddsh(uint64_t fs, uint64_t ft)
{
    LMIValue vs, vt;
    unsigned int i;

    vs.d = fs;
    vt.d = ft;
    for (i = 0; i < 4; ++i) {
        int r = vs.sh[i] + vt.sh[i];
        vs.sh[i] = SATSH(r);
    }
    return vs.d;
}

