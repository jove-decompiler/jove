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

uint64_t helper_punpckhbh(uint64_t fs, uint64_t ft)
{
    unsigned host = BYTE_ORDER_XOR(7);
    LMIValue vd, vs, vt;

    vs.d = fs;
    vt.d = ft;
    vd.ub[0 ^ host] = vs.ub[4 ^ host];
    vd.ub[1 ^ host] = vt.ub[4 ^ host];
    vd.ub[2 ^ host] = vs.ub[5 ^ host];
    vd.ub[3 ^ host] = vt.ub[5 ^ host];
    vd.ub[4 ^ host] = vs.ub[6 ^ host];
    vd.ub[5 ^ host] = vt.ub[6 ^ host];
    vd.ub[6 ^ host] = vs.ub[7 ^ host];
    vd.ub[7 ^ host] = vt.ub[7 ^ host];

    return vd.d;
}

