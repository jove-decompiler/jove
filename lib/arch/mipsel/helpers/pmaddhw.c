#include <stdint.h>

# define BYTE_ORDER_XOR(N) 0

typedef union {
    uint8_t  ub[8];
    int8_t   sb[8];
    uint16_t uh[4];
    int16_t  sh[4];
    uint32_t uw[2];
    int32_t  sw[2];
    uint64_t d;
} LMIValue;

uint64_t helper_pmaddhw(uint64_t fs, uint64_t ft)
{
    unsigned host = BYTE_ORDER_XOR(3);
    LMIValue vs, vt;
    uint32_t p0, p1;

    vs.d = fs;
    vt.d = ft;
    p0  = vs.sh[0 ^ host] * vt.sh[0 ^ host];
    p0 += vs.sh[1 ^ host] * vt.sh[1 ^ host];
    p1  = vs.sh[2 ^ host] * vt.sh[2 ^ host];
    p1 += vs.sh[3 ^ host] * vt.sh[3 ^ host];

    return ((uint64_t)p1 << 32) | p0;
}

