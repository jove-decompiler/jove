#include <stdint.h>

typedef uint64_t target_ulong;

typedef union {
    uint8_t  ub[8];
    int8_t   sb[8];
    uint16_t uh[4];
    int16_t  sh[4];
    uint32_t uw[2];
    int32_t  sw[2];
    uint64_t ul[1];
    int64_t  sl[1];
} DSP64Value;

target_ulong helper_raddu_l_ob(target_ulong rs)
{
    target_ulong ret = 0;
    DSP64Value ds;
    unsigned int i;

    ds.ul[0] = rs;
    for (i = 0; i < 8; i++) {
        ret += ds.ub[i];
    }
    return ret;
}

