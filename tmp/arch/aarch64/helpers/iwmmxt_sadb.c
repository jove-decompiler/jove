#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint64_t HELPER(iwmmxt_sadb)(uint64_t a, uint64_t b)
{
#define abs(x) (((x) >= 0) ? x : -x)
#define SADB(SHR) abs((int) ((a >> SHR) & 0xff) - (int) ((b >> SHR) & 0xff))
    return
        SADB(0) + SADB(8) + SADB(16) + SADB(24) +
        SADB(32) + SADB(40) + SADB(48) + SADB(56);
#undef SADB
}

