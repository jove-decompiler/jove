#include <stdint.h>

typedef union {
    uint8_t  ub[8];
    int8_t   sb[8];
    uint16_t uh[4];
    int16_t  sh[4];
    uint32_t uw[2];
    int32_t  sw[2];
    uint64_t d;
} LMIValue;

uint64_t helper_pcmpgtw(uint64_t fs, uint64_t ft)
{
    LMIValue vs, vt;
    unsigned i;

    vs.d = fs;
    vt.d = ft;
    for (i = 0; i < 2; i++) {
        vs.uw[i] = -(vs.uw[i] > vt.uw[i]);
    }
    return vs.d;
}

