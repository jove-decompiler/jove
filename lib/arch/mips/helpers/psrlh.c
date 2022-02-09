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

uint64_t helper_psrlh(uint64_t fs, uint64_t ft)
{
    LMIValue vs;
    unsigned i;

    ft &= 0x7f;
    if (ft > 15) {
        return 0;
    }
    vs.d = fs;
    for (i = 0; i < 4; ++i) {
        vs.uh[i] >>= ft;
    }
    return vs.d;
}

