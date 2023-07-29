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

uint64_t helper_pshufh(uint64_t fs, uint64_t ft)
{
    unsigned host = BYTE_ORDER_XOR(3);
    LMIValue vd, vs;
    unsigned i;

    vs.d = fs;
    vd.d = 0;
    for (i = 0; i < 4; i++, ft >>= 2) {
        vd.uh[i ^ host] = vs.uh[(ft & 3) ^ host];
    }
    return vd.d;
}

