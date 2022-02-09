#include <stdint.h>

# define BYTE_ORDER_XOR(N) N

typedef union {
    uint8_t  ub[8];
    int8_t   sb[8];
    uint16_t uh[4];
    int16_t  sh[4];
    uint32_t uw[2];
    int32_t  sw[2];
    uint64_t d;
} LMIValue;

uint64_t helper_punpckhhw(uint64_t fs, uint64_t ft)
{
    unsigned host = BYTE_ORDER_XOR(3);
    LMIValue vd, vs, vt;

    vs.d = fs;
    vt.d = ft;
    vd.uh[0 ^ host] = vs.uh[2 ^ host];
    vd.uh[1 ^ host] = vt.uh[2 ^ host];
    vd.uh[2 ^ host] = vs.uh[3 ^ host];
    vd.uh[3 ^ host] = vt.uh[3 ^ host];

    return vd.d;
}

