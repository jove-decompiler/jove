#include <stdint.h>

typedef uint64_t target_ulong;

typedef union {
    uint8_t  ub[4];
    int8_t   sb[4];
    uint16_t uh[2];
    int16_t  sh[2];
    uint32_t uw[1];
    int32_t  sw[1];
} DSP32Value;

target_ulong helper_raddu_w_qb(target_ulong rs)
{
    target_ulong ret = 0;
    DSP32Value ds;
    unsigned int i;

    ds.uw[0] = rs;
    for (i = 0; i < 4; i++) {
        ret += ds.ub[i];
    }
    return ret;
}

