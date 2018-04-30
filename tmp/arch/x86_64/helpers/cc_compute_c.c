#define TARGET_X86_64 1

#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

typedef uint64_t target_ulong;

#define CC_C    0x0001

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

#define SHIFT 0

#define DATA_BITS (1 << (3 + SHIFT))

#define SUFFIX b

#define DATA_TYPE uint8_t

static int glue(compute_c_add, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    return dst < src1;
}

static int glue(compute_c_adc, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1,
                                       DATA_TYPE src3)
{
    return src3 ? dst <= src1 : dst < src1;
}

static int glue(compute_c_sub, SUFFIX)(DATA_TYPE dst, DATA_TYPE src2)
{
    DATA_TYPE src1 = dst + src2;

    return src1 < src2;
}

static int glue(compute_c_sbb, SUFFIX)(DATA_TYPE dst, DATA_TYPE src2,
                                       DATA_TYPE src3)
{
    DATA_TYPE src1 = dst + src2 + src3;

    return (src3 ? src1 <= src2 : src1 < src2);
}

static int glue(compute_c_shl, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    return (src1 >> (DATA_BITS - 1)) & CC_C;
}

#define SHIFT 1

#define DATA_BITS (1 << (3 + SHIFT))

static int glue(compute_c_bmilg, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    return src1 == 0;
}

#define SUFFIX w

#define DATA_TYPE uint16_t

static int glue(compute_c_add, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    return dst < src1;
}

static int glue(compute_c_adc, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1,
                                       DATA_TYPE src3)
{
    return src3 ? dst <= src1 : dst < src1;
}

static int glue(compute_c_sub, SUFFIX)(DATA_TYPE dst, DATA_TYPE src2)
{
    DATA_TYPE src1 = dst + src2;

    return src1 < src2;
}

static int glue(compute_c_sbb, SUFFIX)(DATA_TYPE dst, DATA_TYPE src2,
                                       DATA_TYPE src3)
{
    DATA_TYPE src1 = dst + src2 + src3;

    return (src3 ? src1 <= src2 : src1 < src2);
}

static int glue(compute_c_shl, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    return (src1 >> (DATA_BITS - 1)) & CC_C;
}

#define SHIFT 2

#define DATA_BITS (1 << (3 + SHIFT))

static int glue(compute_c_bmilg, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    return src1 == 0;
}

#define SUFFIX l

#define DATA_TYPE uint32_t

static int glue(compute_c_add, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    return dst < src1;
}

static int glue(compute_c_adc, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1,
                                       DATA_TYPE src3)
{
    return src3 ? dst <= src1 : dst < src1;
}

static int glue(compute_c_sub, SUFFIX)(DATA_TYPE dst, DATA_TYPE src2)
{
    DATA_TYPE src1 = dst + src2;

    return src1 < src2;
}

static int glue(compute_c_sbb, SUFFIX)(DATA_TYPE dst, DATA_TYPE src2,
                                       DATA_TYPE src3)
{
    DATA_TYPE src1 = dst + src2 + src3;

    return (src3 ? src1 <= src2 : src1 < src2);
}

static int glue(compute_c_shl, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    return (src1 >> (DATA_BITS - 1)) & CC_C;
}

#define SHIFT 3

#define DATA_BITS (1 << (3 + SHIFT))

static int glue(compute_c_bmilg, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    return src1 == 0;
}

#define SUFFIX q

#define DATA_TYPE uint64_t

static int glue(compute_c_add, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    return dst < src1;
}

static int glue(compute_c_adc, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1,
                                       DATA_TYPE src3)
{
    return src3 ? dst <= src1 : dst < src1;
}

static int glue(compute_c_sub, SUFFIX)(DATA_TYPE dst, DATA_TYPE src2)
{
    DATA_TYPE src1 = dst + src2;

    return src1 < src2;
}

static int glue(compute_c_sbb, SUFFIX)(DATA_TYPE dst, DATA_TYPE src2,
                                       DATA_TYPE src3)
{
    DATA_TYPE src1 = dst + src2 + src3;

    return (src3 ? src1 <= src2 : src1 < src2);
}

static int glue(compute_c_shl, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    return (src1 >> (DATA_BITS - 1)) & CC_C;
}

static int glue(compute_c_bmilg, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    return src1 == 0;
}

target_ulong helper_cc_compute_c(target_ulong dst, target_ulong src1,
                                 target_ulong src2, int op)
{
    switch (op) {
    default: /* should never happen */
    case CC_OP_LOGICB:
    case CC_OP_LOGICW:
    case CC_OP_LOGICL:
    case CC_OP_LOGICQ:
    case CC_OP_CLR:
    case CC_OP_POPCNT:
        return 0;

    case CC_OP_EFLAGS:
    case CC_OP_SARB:
    case CC_OP_SARW:
    case CC_OP_SARL:
    case CC_OP_SARQ:
    case CC_OP_ADOX:
        return src1 & 1;

    case CC_OP_INCB:
    case CC_OP_INCW:
    case CC_OP_INCL:
    case CC_OP_INCQ:
    case CC_OP_DECB:
    case CC_OP_DECW:
    case CC_OP_DECL:
    case CC_OP_DECQ:
        return src1;

    case CC_OP_MULB:
    case CC_OP_MULW:
    case CC_OP_MULL:
    case CC_OP_MULQ:
        return src1 != 0;

    case CC_OP_ADCX:
    case CC_OP_ADCOX:
        return dst;

    case CC_OP_ADDB:
        return compute_c_addb(dst, src1);
    case CC_OP_ADDW:
        return compute_c_addw(dst, src1);
    case CC_OP_ADDL:
        return compute_c_addl(dst, src1);

    case CC_OP_ADCB:
        return compute_c_adcb(dst, src1, src2);
    case CC_OP_ADCW:
        return compute_c_adcw(dst, src1, src2);
    case CC_OP_ADCL:
        return compute_c_adcl(dst, src1, src2);

    case CC_OP_SUBB:
        return compute_c_subb(dst, src1);
    case CC_OP_SUBW:
        return compute_c_subw(dst, src1);
    case CC_OP_SUBL:
        return compute_c_subl(dst, src1);

    case CC_OP_SBBB:
        return compute_c_sbbb(dst, src1, src2);
    case CC_OP_SBBW:
        return compute_c_sbbw(dst, src1, src2);
    case CC_OP_SBBL:
        return compute_c_sbbl(dst, src1, src2);

    case CC_OP_SHLB:
        return compute_c_shlb(dst, src1);
    case CC_OP_SHLW:
        return compute_c_shlw(dst, src1);
    case CC_OP_SHLL:
        return compute_c_shll(dst, src1);

    case CC_OP_BMILGB:
        return compute_c_bmilgb(dst, src1);
    case CC_OP_BMILGW:
        return compute_c_bmilgw(dst, src1);
    case CC_OP_BMILGL:
        return compute_c_bmilgl(dst, src1);

#ifdef TARGET_X86_64
    case CC_OP_ADDQ:
        return compute_c_addq(dst, src1);
    case CC_OP_ADCQ:
        return compute_c_adcq(dst, src1, src2);
    case CC_OP_SUBQ:
        return compute_c_subq(dst, src1);
    case CC_OP_SBBQ:
        return compute_c_sbbq(dst, src1, src2);
    case CC_OP_SHLQ:
        return compute_c_shlq(dst, src1);
    case CC_OP_BMILGQ:
        return compute_c_bmilgq(dst, src1);
#endif
    }
}

