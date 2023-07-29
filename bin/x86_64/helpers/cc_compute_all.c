#define TARGET_X86_64 1

#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

typedef int64_t target_long;

typedef uint64_t target_ulong;

#define CC_C    0x0001

#define CC_P    0x0004

#define CC_A    0x0010

#define CC_Z    0x0040

#define CC_S    0x0080

#define CC_O    0x0800

typedef enum {
    CC_OP_DYNAMIC, /* must use dynamic code to get cc_op */
    CC_OP_EFLAGS,  /* all cc are explicitly computed, CC_SRC = flags */

    CC_OP_MULB, /* modify all flags, C, O = (CC_SRC != 0) */
    CC_OP_MULW,
    CC_OP_MULL,
    CC_OP_MULQ,

    CC_OP_ADDB, /* modify all flags, CC_DST = res, CC_SRC = src1 */
    CC_OP_ADDW,
    CC_OP_ADDL,
    CC_OP_ADDQ,

    CC_OP_ADCB, /* modify all flags, CC_DST = res, CC_SRC = src1 */
    CC_OP_ADCW,
    CC_OP_ADCL,
    CC_OP_ADCQ,

    CC_OP_SUBB, /* modify all flags, CC_DST = res, CC_SRC = src1 */
    CC_OP_SUBW,
    CC_OP_SUBL,
    CC_OP_SUBQ,

    CC_OP_SBBB, /* modify all flags, CC_DST = res, CC_SRC = src1 */
    CC_OP_SBBW,
    CC_OP_SBBL,
    CC_OP_SBBQ,

    CC_OP_LOGICB, /* modify all flags, CC_DST = res */
    CC_OP_LOGICW,
    CC_OP_LOGICL,
    CC_OP_LOGICQ,

    CC_OP_INCB, /* modify all flags except, CC_DST = res, CC_SRC = C */
    CC_OP_INCW,
    CC_OP_INCL,
    CC_OP_INCQ,

    CC_OP_DECB, /* modify all flags except, CC_DST = res, CC_SRC = C  */
    CC_OP_DECW,
    CC_OP_DECL,
    CC_OP_DECQ,

    CC_OP_SHLB, /* modify all flags, CC_DST = res, CC_SRC.msb = C */
    CC_OP_SHLW,
    CC_OP_SHLL,
    CC_OP_SHLQ,

    CC_OP_SARB, /* modify all flags, CC_DST = res, CC_SRC.lsb = C */
    CC_OP_SARW,
    CC_OP_SARL,
    CC_OP_SARQ,

    CC_OP_BMILGB, /* Z,S via CC_DST, C = SRC==0; O=0; P,A undefined */
    CC_OP_BMILGW,
    CC_OP_BMILGL,
    CC_OP_BMILGQ,

    CC_OP_ADCX, /* CC_DST = C, CC_SRC = rest.  */
    CC_OP_ADOX, /* CC_DST = O, CC_SRC = rest.  */
    CC_OP_ADCOX, /* CC_DST = C, CC_SRC2 = O, CC_SRC = rest.  */

    CC_OP_CLR, /* Z set, all other flags clear.  */
    CC_OP_POPCNT, /* Z via CC_SRC, all other flags clear.  */

    CC_OP_NB,
} CCOp;

static inline target_long lshift(target_long x, int n)
{
    if (n >= 0) {
        return x << n;
    } else {
        return x >> (-n);
    }
}

#define SHIFT 0

#define DATA_BITS (1 << (3 + SHIFT))

#define SUFFIX b

#define DATA_TYPE uint8_t

#define SIGN_MASK (((DATA_TYPE)1) << (DATA_BITS - 1))

const uint8_t parity_table[256] = {
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
};

static int glue(compute_all_add, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src2 = dst - src1;

    cf = dst < src1;
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & CC_A;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = lshift((src1 ^ src2 ^ -1) & (src1 ^ dst), 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_adc, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1,
                                         DATA_TYPE src3)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src2 = dst - src1 - src3;

    cf = (src3 ? dst <= src1 : dst < src1);
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & 0x10;
    zf = (dst == 0) << 6;
    sf = lshift(dst, 8 - DATA_BITS) & 0x80;
    of = lshift((src1 ^ src2 ^ -1) & (src1 ^ dst), 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_sub, SUFFIX)(DATA_TYPE dst, DATA_TYPE src2)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src1 = dst + src2;

    cf = src1 < src2;
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & CC_A;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = lshift((src1 ^ src2) & (src1 ^ dst), 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_sbb, SUFFIX)(DATA_TYPE dst, DATA_TYPE src2,
                                         DATA_TYPE src3)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src1 = dst + src2 + src3;

    cf = (src3 ? src1 <= src2 : src1 < src2);
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & 0x10;
    zf = (dst == 0) << 6;
    sf = lshift(dst, 8 - DATA_BITS) & 0x80;
    of = lshift((src1 ^ src2) & (src1 ^ dst), 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_logic, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    cf = 0;
    pf = parity_table[(uint8_t)dst];
    af = 0;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = 0;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_inc, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src2;

    cf = src1;
    src1 = dst - 1;
    src2 = 1;
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & CC_A;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = (dst == SIGN_MASK) * CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_dec, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src2;

    cf = src1;
    src1 = dst + 1;
    src2 = 1;
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & CC_A;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = (dst == SIGN_MASK - 1) * CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_shl, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    cf = (src1 >> (DATA_BITS - 1)) & CC_C;
    pf = parity_table[(uint8_t)dst];
    af = 0; /* undefined */
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    /* of is defined iff shift count == 1 */
    of = lshift(src1 ^ dst, 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_sar, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    cf = src1 & 1;
    pf = parity_table[(uint8_t)dst];
    af = 0; /* undefined */
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    /* of is defined iff shift count == 1 */
    of = lshift(src1 ^ dst, 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_mul, SUFFIX)(DATA_TYPE dst, target_long src1)
{
    int cf, pf, af, zf, sf, of;

    cf = (src1 != 0);
    pf = parity_table[(uint8_t)dst];
    af = 0; /* undefined */
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = cf * CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_bmilg, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    cf = (src1 == 0);
    pf = 0; /* undefined */
    af = 0; /* undefined */
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = 0;
    return cf | pf | af | zf | sf | of;
}

#define SHIFT 1

#define DATA_BITS (1 << (3 + SHIFT))

#define SUFFIX w

#define DATA_TYPE uint16_t

#define SIGN_MASK (((DATA_TYPE)1) << (DATA_BITS - 1))

static int glue(compute_all_add, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src2 = dst - src1;

    cf = dst < src1;
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & CC_A;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = lshift((src1 ^ src2 ^ -1) & (src1 ^ dst), 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_adc, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1,
                                         DATA_TYPE src3)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src2 = dst - src1 - src3;

    cf = (src3 ? dst <= src1 : dst < src1);
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & 0x10;
    zf = (dst == 0) << 6;
    sf = lshift(dst, 8 - DATA_BITS) & 0x80;
    of = lshift((src1 ^ src2 ^ -1) & (src1 ^ dst), 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_sub, SUFFIX)(DATA_TYPE dst, DATA_TYPE src2)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src1 = dst + src2;

    cf = src1 < src2;
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & CC_A;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = lshift((src1 ^ src2) & (src1 ^ dst), 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_sbb, SUFFIX)(DATA_TYPE dst, DATA_TYPE src2,
                                         DATA_TYPE src3)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src1 = dst + src2 + src3;

    cf = (src3 ? src1 <= src2 : src1 < src2);
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & 0x10;
    zf = (dst == 0) << 6;
    sf = lshift(dst, 8 - DATA_BITS) & 0x80;
    of = lshift((src1 ^ src2) & (src1 ^ dst), 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_logic, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    cf = 0;
    pf = parity_table[(uint8_t)dst];
    af = 0;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = 0;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_inc, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src2;

    cf = src1;
    src1 = dst - 1;
    src2 = 1;
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & CC_A;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = (dst == SIGN_MASK) * CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_dec, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src2;

    cf = src1;
    src1 = dst + 1;
    src2 = 1;
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & CC_A;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = (dst == SIGN_MASK - 1) * CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_shl, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    cf = (src1 >> (DATA_BITS - 1)) & CC_C;
    pf = parity_table[(uint8_t)dst];
    af = 0; /* undefined */
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    /* of is defined iff shift count == 1 */
    of = lshift(src1 ^ dst, 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_sar, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    cf = src1 & 1;
    pf = parity_table[(uint8_t)dst];
    af = 0; /* undefined */
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    /* of is defined iff shift count == 1 */
    of = lshift(src1 ^ dst, 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_mul, SUFFIX)(DATA_TYPE dst, target_long src1)
{
    int cf, pf, af, zf, sf, of;

    cf = (src1 != 0);
    pf = parity_table[(uint8_t)dst];
    af = 0; /* undefined */
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = cf * CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_bmilg, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    cf = (src1 == 0);
    pf = 0; /* undefined */
    af = 0; /* undefined */
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = 0;
    return cf | pf | af | zf | sf | of;
}

#define SHIFT 2

#define DATA_BITS (1 << (3 + SHIFT))

#define SUFFIX l

#define DATA_TYPE uint32_t

#define SIGN_MASK (((DATA_TYPE)1) << (DATA_BITS - 1))

static int glue(compute_all_add, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src2 = dst - src1;

    cf = dst < src1;
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & CC_A;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = lshift((src1 ^ src2 ^ -1) & (src1 ^ dst), 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_adc, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1,
                                         DATA_TYPE src3)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src2 = dst - src1 - src3;

    cf = (src3 ? dst <= src1 : dst < src1);
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & 0x10;
    zf = (dst == 0) << 6;
    sf = lshift(dst, 8 - DATA_BITS) & 0x80;
    of = lshift((src1 ^ src2 ^ -1) & (src1 ^ dst), 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_sub, SUFFIX)(DATA_TYPE dst, DATA_TYPE src2)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src1 = dst + src2;

    cf = src1 < src2;
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & CC_A;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = lshift((src1 ^ src2) & (src1 ^ dst), 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_sbb, SUFFIX)(DATA_TYPE dst, DATA_TYPE src2,
                                         DATA_TYPE src3)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src1 = dst + src2 + src3;

    cf = (src3 ? src1 <= src2 : src1 < src2);
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & 0x10;
    zf = (dst == 0) << 6;
    sf = lshift(dst, 8 - DATA_BITS) & 0x80;
    of = lshift((src1 ^ src2) & (src1 ^ dst), 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_logic, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    cf = 0;
    pf = parity_table[(uint8_t)dst];
    af = 0;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = 0;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_inc, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src2;

    cf = src1;
    src1 = dst - 1;
    src2 = 1;
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & CC_A;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = (dst == SIGN_MASK) * CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_dec, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src2;

    cf = src1;
    src1 = dst + 1;
    src2 = 1;
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & CC_A;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = (dst == SIGN_MASK - 1) * CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_shl, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    cf = (src1 >> (DATA_BITS - 1)) & CC_C;
    pf = parity_table[(uint8_t)dst];
    af = 0; /* undefined */
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    /* of is defined iff shift count == 1 */
    of = lshift(src1 ^ dst, 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_sar, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    cf = src1 & 1;
    pf = parity_table[(uint8_t)dst];
    af = 0; /* undefined */
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    /* of is defined iff shift count == 1 */
    of = lshift(src1 ^ dst, 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_mul, SUFFIX)(DATA_TYPE dst, target_long src1)
{
    int cf, pf, af, zf, sf, of;

    cf = (src1 != 0);
    pf = parity_table[(uint8_t)dst];
    af = 0; /* undefined */
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = cf * CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_bmilg, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    cf = (src1 == 0);
    pf = 0; /* undefined */
    af = 0; /* undefined */
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = 0;
    return cf | pf | af | zf | sf | of;
}

#define SHIFT 3

#define DATA_BITS (1 << (3 + SHIFT))

#define SUFFIX q

#define DATA_TYPE uint64_t

#define SIGN_MASK (((DATA_TYPE)1) << (DATA_BITS - 1))

static int glue(compute_all_add, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src2 = dst - src1;

    cf = dst < src1;
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & CC_A;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = lshift((src1 ^ src2 ^ -1) & (src1 ^ dst), 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_adc, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1,
                                         DATA_TYPE src3)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src2 = dst - src1 - src3;

    cf = (src3 ? dst <= src1 : dst < src1);
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & 0x10;
    zf = (dst == 0) << 6;
    sf = lshift(dst, 8 - DATA_BITS) & 0x80;
    of = lshift((src1 ^ src2 ^ -1) & (src1 ^ dst), 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_sub, SUFFIX)(DATA_TYPE dst, DATA_TYPE src2)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src1 = dst + src2;

    cf = src1 < src2;
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & CC_A;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = lshift((src1 ^ src2) & (src1 ^ dst), 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_sbb, SUFFIX)(DATA_TYPE dst, DATA_TYPE src2,
                                         DATA_TYPE src3)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src1 = dst + src2 + src3;

    cf = (src3 ? src1 <= src2 : src1 < src2);
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & 0x10;
    zf = (dst == 0) << 6;
    sf = lshift(dst, 8 - DATA_BITS) & 0x80;
    of = lshift((src1 ^ src2) & (src1 ^ dst), 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_logic, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    cf = 0;
    pf = parity_table[(uint8_t)dst];
    af = 0;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = 0;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_inc, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src2;

    cf = src1;
    src1 = dst - 1;
    src2 = 1;
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & CC_A;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = (dst == SIGN_MASK) * CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_dec, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;
    DATA_TYPE src2;

    cf = src1;
    src1 = dst + 1;
    src2 = 1;
    pf = parity_table[(uint8_t)dst];
    af = (dst ^ src1 ^ src2) & CC_A;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = (dst == SIGN_MASK - 1) * CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_shl, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    cf = (src1 >> (DATA_BITS - 1)) & CC_C;
    pf = parity_table[(uint8_t)dst];
    af = 0; /* undefined */
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    /* of is defined iff shift count == 1 */
    of = lshift(src1 ^ dst, 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_sar, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    cf = src1 & 1;
    pf = parity_table[(uint8_t)dst];
    af = 0; /* undefined */
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    /* of is defined iff shift count == 1 */
    of = lshift(src1 ^ dst, 12 - DATA_BITS) & CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_mul, SUFFIX)(DATA_TYPE dst, target_long src1)
{
    int cf, pf, af, zf, sf, of;

    cf = (src1 != 0);
    pf = parity_table[(uint8_t)dst];
    af = 0; /* undefined */
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = cf * CC_O;
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_bmilg, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    cf = (src1 == 0);
    pf = 0; /* undefined */
    af = 0; /* undefined */
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    of = 0;
    return cf | pf | af | zf | sf | of;
}

static target_ulong compute_all_adcx(target_ulong dst, target_ulong src1,
                                     target_ulong src2)
{
    return (src1 & ~CC_C) | (dst * CC_C);
}

static target_ulong compute_all_adox(target_ulong dst, target_ulong src1,
                                     target_ulong src2)
{
    return (src1 & ~CC_O) | (src2 * CC_O);
}

static target_ulong compute_all_adcox(target_ulong dst, target_ulong src1,
                                      target_ulong src2)
{
    return (src1 & ~(CC_C | CC_O)) | (dst * CC_C) | (src2 * CC_O);
}

target_ulong helper_cc_compute_all(target_ulong dst, target_ulong src1,
                                   target_ulong src2, int op)
{
    switch (op) {
    default: /* should never happen */
        return 0;

    case CC_OP_EFLAGS:
        return src1;
    case CC_OP_CLR:
        return CC_Z | CC_P;
    case CC_OP_POPCNT:
        return src1 ? 0 : CC_Z;

    case CC_OP_MULB:
        return compute_all_mulb(dst, src1);
    case CC_OP_MULW:
        return compute_all_mulw(dst, src1);
    case CC_OP_MULL:
        return compute_all_mull(dst, src1);

    case CC_OP_ADDB:
        return compute_all_addb(dst, src1);
    case CC_OP_ADDW:
        return compute_all_addw(dst, src1);
    case CC_OP_ADDL:
        return compute_all_addl(dst, src1);

    case CC_OP_ADCB:
        return compute_all_adcb(dst, src1, src2);
    case CC_OP_ADCW:
        return compute_all_adcw(dst, src1, src2);
    case CC_OP_ADCL:
        return compute_all_adcl(dst, src1, src2);

    case CC_OP_SUBB:
        return compute_all_subb(dst, src1);
    case CC_OP_SUBW:
        return compute_all_subw(dst, src1);
    case CC_OP_SUBL:
        return compute_all_subl(dst, src1);

    case CC_OP_SBBB:
        return compute_all_sbbb(dst, src1, src2);
    case CC_OP_SBBW:
        return compute_all_sbbw(dst, src1, src2);
    case CC_OP_SBBL:
        return compute_all_sbbl(dst, src1, src2);

    case CC_OP_LOGICB:
        return compute_all_logicb(dst, src1);
    case CC_OP_LOGICW:
        return compute_all_logicw(dst, src1);
    case CC_OP_LOGICL:
        return compute_all_logicl(dst, src1);

    case CC_OP_INCB:
        return compute_all_incb(dst, src1);
    case CC_OP_INCW:
        return compute_all_incw(dst, src1);
    case CC_OP_INCL:
        return compute_all_incl(dst, src1);

    case CC_OP_DECB:
        return compute_all_decb(dst, src1);
    case CC_OP_DECW:
        return compute_all_decw(dst, src1);
    case CC_OP_DECL:
        return compute_all_decl(dst, src1);

    case CC_OP_SHLB:
        return compute_all_shlb(dst, src1);
    case CC_OP_SHLW:
        return compute_all_shlw(dst, src1);
    case CC_OP_SHLL:
        return compute_all_shll(dst, src1);

    case CC_OP_SARB:
        return compute_all_sarb(dst, src1);
    case CC_OP_SARW:
        return compute_all_sarw(dst, src1);
    case CC_OP_SARL:
        return compute_all_sarl(dst, src1);

    case CC_OP_BMILGB:
        return compute_all_bmilgb(dst, src1);
    case CC_OP_BMILGW:
        return compute_all_bmilgw(dst, src1);
    case CC_OP_BMILGL:
        return compute_all_bmilgl(dst, src1);

    case CC_OP_ADCX:
        return compute_all_adcx(dst, src1, src2);
    case CC_OP_ADOX:
        return compute_all_adox(dst, src1, src2);
    case CC_OP_ADCOX:
        return compute_all_adcox(dst, src1, src2);

#ifdef TARGET_X86_64
    case CC_OP_MULQ:
        return compute_all_mulq(dst, src1);
    case CC_OP_ADDQ:
        return compute_all_addq(dst, src1);
    case CC_OP_ADCQ:
        return compute_all_adcq(dst, src1, src2);
    case CC_OP_SUBQ:
        return compute_all_subq(dst, src1);
    case CC_OP_SBBQ:
        return compute_all_sbbq(dst, src1, src2);
    case CC_OP_LOGICQ:
        return compute_all_logicq(dst, src1);
    case CC_OP_INCQ:
        return compute_all_incq(dst, src1);
    case CC_OP_DECQ:
        return compute_all_decq(dst, src1);
    case CC_OP_SHLQ:
        return compute_all_shlq(dst, src1);
    case CC_OP_SARQ:
        return compute_all_sarq(dst, src1);
    case CC_OP_BMILGQ:
        return compute_all_bmilgq(dst, src1);
#endif
    }
}

